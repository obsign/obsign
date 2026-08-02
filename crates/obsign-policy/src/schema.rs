//! The Cedar schema of the model a rule actually sees.
//!
//! Until now the model was only ever *implied*: entity types, actions and
//! context attributes were built by hand in `engine.rs` and described in
//! prose in `docs/policies-cedar.md`, and the engine evaluated with no
//! schema at all. A rule reading `principal.permissions` or
//! `context.enviroment` therefore parsed fine, compiled fine, shipped fine
//! — and then raised an evaluation error on the first live call, where it
//! falls to the fail mode. That is the worst place to discover a typo.
//!
//! This module writes that model down, derived from the same catalogue the
//! engine loads, so the type checker can run at compile time (`Engine::
//! validate`) and so an editor can type-check while the rule is being
//! written. One source of truth: what the schema says is what
//! `Engine::authorize` builds, and the two are asserted equal in the tests.
//!
//! The schema is *not* handed to the authorizer at runtime. Evaluation
//! stays schema-free deliberately: a gateway must decide from the bundle it
//! verified, and adding a second artifact that could disagree with it would
//! create a way for a call to be refused for a reason the bundle does not
//! contain.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::str::FromStr as _;

use crate::bundle::{ArgKind, ToolDef};
use crate::engine::WRAPPED_SERVER;
use crate::Error;

/// Conventional file name, in `policies/` next to the rules it types — where
/// the Cedar VS Code extension auto-detects it.
pub const SCHEMA_FILE: &str = "obsign.cedarschema";

/// What every arbitration puts in the context, whatever the action.
///
/// Mirrors `Engine::context_pairs`. The unit test
/// `engine::tests::the_schema_and_the_engine_agree_on_the_context` asserts
/// the two carry the same attribute *names*, in both directions — a schema
/// that drifts from the engine is worse than no schema, because it would
/// reject rules that work and accept rules that do not, and the second kind
/// falls to the fail mode on a live gateway.
///
/// The test pins names, not types: `RestrictedExpression` does not report
/// its own type, so a `Long` here against a string built there would still
/// slip through. Adding an attribute is the drift that actually happens;
/// changing one's type is a deliberate edit to both sides.
pub(crate) const COMMON_CONTEXT: &[(&str, &str)] = &[
    ("actor_chain", "Set<String>"),
    ("delegation_depth", "Long"),
    ("env", "String"),
    ("has_human_delegation", "Bool"),
    ("principal_kind", "String"),
    ("scopes", "Set<String>"),
    ("server", "String"),
    ("session", "String"),
];

impl ArgKind {
    /// Cedar type this kind is coerced to. Mirrors `engine::coerce`.
    pub(crate) fn cedar_type(&self) -> &'static str {
        match self {
            ArgKind::String => "String",
            ArgKind::Long => "Long",
            ArgKind::Bool => "Bool",
            ArgKind::StringSet => "Set<String>",
        }
    }
}

/// The schema for one catalogue, as Cedar schema source.
///
/// Deterministic: same catalogue, same bytes. It is a derived artifact that
/// customers commit, so it must diff cleanly.
pub fn schema_source(tools: &[ToolDef]) -> Result<String, Error> {
    let args = declared_args(tools)?;

    let mut s = String::new();
    s.push_str(
        "// The Obsign authorization model, as Cedar sees it.\n\
         //\n\
         // GENERATED — do not edit. Regenerate after any change to tools.json:\n\
         //\n\
         //     obsign-control schema --source .\n\
         //\n\
         // `obsign-control compile` type-checks the rules against this model\n\
         // and refuses to sign a rule that reads something the gateway does\n\
         // not expose. Point your editor at this file to get the same check\n\
         // while you type — see docs/policies-cedar.md.\n\n",
    );

    s.push_str(
        "// Principals carry no attributes: permissions are expressed by group\n\
         // membership or by scopes, never by `principal.<something>`.\n\
         entity Group;\n\
         entity User in [Group];\n\n",
    );

    s.push_str(
        "// Only Tool carries attributes, and only because the signed catalogue\n\
         // describes it. `required_scope` is the empty string when none.\n\
         entity Tool = {\n  \
             \"destructive\": Bool,\n  \
             \"required_scope\": String,\n  \
             \"server\": String\n\
         };\n\n",
    );

    s.push_str(
        "// Resource URIs and prompt names are minted by the MCP server at\n\
         // runtime: nothing signed to attach, so no attributes. Decide on the\n\
         // identifier through `context.target`.\n\
         entity Resource;\n\
         entity Prompt;\n\n",
    );

    // Enumerated: the server-initiated channels are granted per server, and
    // the resource key is a fixed literal, not the deployment's `--server-id`.
    // Spelling it as an enum turns "I keyed a rule on my server name" from a
    // rule that silently never matches into an editor error.
    writeln!(
        s,
        "// Server-initiated channels are keyed on a fixed literal, not on the\n\
         // operator's --server-id. Match `context.server` to scope a rule to\n\
         // one deployment.\n\
         entity Server enum [{}];\n",
        cedar_string(WRAPPED_SERVER)
    )
    .expect("writing to a String cannot fail");

    let common = COMMON_CONTEXT
        .iter()
        .map(|(name, ty)| format!("    {}: {ty}", cedar_string(name)))
        .collect::<Vec<_>>();

    // `tool_call` sees the declared arguments; nothing else does.
    let mut tool_ctx = common.clone();
    tool_ctx.push(format!("    \"args\": {}", args_record(&args)));
    writeln!(
        s,
        "action \"tool_call\" appliesTo {{\n  \
             principal: [User],\n  \
             resource: [Tool],\n  \
             context: {{\n{}\n  }}\n\
         }};\n",
        tool_ctx.join(",\n")
    )
    .expect("writing to a String cannot fail");

    // Capability actions see the target instead: entity equality only matches
    // exactly, `context.target like "docs/*"` is how a family is granted.
    let mut cap_ctx = common;
    cap_ctx.push("    \"target\": String".to_string());
    let cap_ctx = cap_ctx.join(",\n");

    for (actions, resource) in [
        ("\"resource_read\"", "Resource"),
        ("\"prompt_get\"", "Prompt"),
        ("\"sampling\", \"elicitation\", \"notify\"", "Server"),
    ] {
        writeln!(
            s,
            "action {actions} appliesTo {{\n  \
                 principal: [User],\n  \
                 resource: [{resource}],\n  \
                 context: {{\n{cap_ctx}\n  }}\n\
             }};\n"
        )
        .expect("writing to a String cannot fail");
    }

    // Parse what we just printed, and refuse to return it otherwise. Every
    // caller either writes this text to a file an editor will trust or feeds
    // it to the validator, and neither can tell a generator bug from a bad
    // catalogue afterwards. Cheap — the callers are one-shot CLI paths — and
    // it makes "the schema on disk is parseable Cedar" true by construction
    // rather than by review of the string building above.
    cedar_policy::Schema::from_str(&s).map_err(|e| {
        Error::Cedar(format!(
            "the generated schema does not parse ({e}) — this is an Obsign \
             bug, please report it with your tools.json"
        ))
    })?;

    Ok(s)
}

/// `context.args` as a Cedar record type.
///
/// Every attribute is **required**, never optional, even though a given call
/// only ever carries the arguments its own tool declares. Optional attributes
/// would force every rule to write `context.args has channel &&` before
/// reading it — noise, and false comfort: extraction already guarantees that
/// a declared argument is present or the call was refused (`extract_args` is
/// total by construction). What the union buys is the typo check, and rules
/// are scoped to a resource, so a rule reading another tool's argument never
/// evaluates on that tool's calls.
fn args_record(args: &BTreeMap<&str, (ArgKind, &str)>) -> String {
    if args.is_empty() {
        // No tool declares arguments: reading `context.args.<anything>` is a
        // mistake, and an empty record type says so precisely.
        return "{}".to_string();
    }
    // The provenance comment goes on its own line *above* the field, and the
    // fields are joined rather than terminated. Both details are load-bearing:
    // Cedar's grammar has no trailing comma, and an earlier version put the
    // comment after it and then deleted the last comma by searching the
    // rendered text for ", //" — which a tool named `a, //b` defeats.
    let fields: Vec<String> = args
        .iter()
        .map(|(name, (kind, tool))| {
            format!(
                "      // {}\n      {}: {}",
                comment_text(tool),
                cedar_string(name),
                kind.cedar_type()
            )
        })
        .collect();
    format!("{{\n{}\n    }}", fields.join(",\n"))
}

/// The union of every `policy_args` declaration, keyed by name.
///
/// `context.args` is one namespace across the whole catalogue — Cedar types
/// the context per *action*, and every tool call is the same `tool_call`
/// action — so two tools cannot give one name two types. Caught here, in a
/// diff, rather than as a type error pointing at a rule that is not wrong.
fn declared_args(tools: &[ToolDef]) -> Result<BTreeMap<&str, (ArgKind, &str)>, Error> {
    let mut sorted: Vec<&ToolDef> = tools.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));

    let mut out: BTreeMap<&str, (ArgKind, &str)> = BTreeMap::new();
    for t in sorted {
        for spec in &t.policy_args {
            match out.get(spec.name.as_str()).copied() {
                Some((kind, first)) if kind != spec.kind => {
                    return Err(Error::Bundle(format!(
                        "argument \"{}\" is declared {} by tool \"{first}\" and {} by \
                         tool \"{}\": `context.args` is one namespace for the whole \
                         catalogue, so a name cannot carry two types. Rename one of \
                         them (`at` keeps the wire name unchanged).",
                        spec.name,
                        kind.as_str(),
                        spec.kind.as_str(),
                        t.name
                    )));
                }
                Some(_) => {}
                None => {
                    out.insert(&spec.name, (spec.kind, &t.name));
                }
            }
        }
    }
    Ok(out)
}

/// Text safe to drop into a `//` comment.
///
/// A tool name reaches here straight from `tools.json`, where the only
/// checks are non-empty and unique — and the names in that file are copied
/// from what a remote MCP server advertises. A newline in one would end the
/// comment and leave its tail as a bare token inside a record type, so the
/// generated schema would not parse and `compile` would blame Obsign for the
/// operator's catalogue. Every control character becomes a space; nothing
/// else about the name is altered, because the point is to identify it.
fn comment_text(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// A Cedar string literal. Attribute names go through it unconditionally:
/// an argument may legitimately be named `if` or `path/glob`, and quoting
/// everything avoids having to know which identifiers Cedar reserves.
fn cedar_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}
