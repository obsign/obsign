//! Argument-aware rules: `context.args`.
//!
//! The catalogue declares which arguments the policy may see; the engine
//! exposes exactly those, typed, total. Two properties carry the design
//! (docs/design/argument-policy-v1.md):
//!
//! * a policy can refuse a call *on its arguments* — "`send_message`, but
//!   only to `#support`" — which is where real-world refusals live;
//! * malformed input is a denial, never the fail mode: an agent that
//!   controls argument shape must not be able to steer a fail-open tool
//!   into its open path.

use obsign_audit_core::record::Outcome;
use obsign_policy::bundle::{
    ArgKind, ArgSpec, Bundle, FailBehaviour, FailMode, ToolDef, FORMAT_V2,
};
use obsign_policy::{Engine, ToolRequest};
use serde_json::json;

const CEDAR: &str = r##"
// The rule every prospect asks for first.
@id("support_channel_only")
forbid (principal, action == Action::"tool_call", resource == Tool::"send_message")
when { context.args.channel != "#support" };

@id("allow_all")
permit (principal, action == Action::"tool_call", resource);
"##;

fn arg(name: &str, kind: ArgKind) -> ArgSpec {
    ArgSpec {
        name: name.into(),
        at: None,
        kind,
        default: None,
    }
}

fn tool_with_args(name: &str, policy_args: Vec<ArgSpec>) -> ToolDef {
    ToolDef {
        name: name.into(),
        server: "mcp://t".into(),
        destructive: false,
        required_scope: None,
        policy_args,
    }
}

fn bundle_v2(cedar: &str, tools: Vec<ToolDef>) -> Bundle {
    Bundle {
        format: FORMAT_V2.to_string(),
        version: "policies@test".into(),
        cedar: cedar.into(),
        tools,
        fail_mode: FailMode {
            default: FailBehaviour::Closed,
            tools: Default::default(),
        },
    }
}

fn engine() -> Engine {
    Engine::load(&bundle_v2(
        CEDAR,
        vec![tool_with_args(
            "send_message",
            vec![arg("channel", ArgKind::String)],
        )],
    ))
    .unwrap()
}

fn call(args: serde_json::Value) -> ToolRequest {
    let mut r = ToolRequest::new("u:marie", "send_message");
    r.args = args;
    r
}

#[test]
fn allowed_channel_passes() {
    let v = engine().evaluate(&call(json!({"channel": "#support"})));
    assert_eq!(v.outcome, Outcome::Allow, "{:?}", v.reason);
}

#[test]
fn forbidden_channel_is_refused_by_the_rule() {
    let v = engine().evaluate(&call(json!({"channel": "#annonces-direction"})));
    assert_eq!(v.outcome, Outcome::Deny);
    assert_eq!(v.policy_id.as_deref(), Some("support_channel_only"));
}

#[test]
fn missing_required_arg_is_refused_before_cedar() {
    let v = engine().evaluate(&call(json!({})));
    assert_eq!(v.outcome, Outcome::Deny);
    // No rule decided: the gate itself did, like an out-of-catalogue tool.
    assert_eq!(v.policy_id, None);
    assert!(v.reason.as_deref().unwrap().contains("args: channel"));
}

#[test]
fn type_confusion_is_refused_not_evaluated() {
    // The classic shape attack: an object where a string is expected would
    // turn `!=` into an evaluation error, and evaluation errors fall to the
    // fail mode. It must die at extraction instead.
    let v = engine().evaluate(&call(json!({"channel": {"id": "C0123"}})));
    assert_eq!(v.outcome, Outcome::Deny);
    assert_eq!(v.policy_id, None);
    assert!(v.reason.as_deref().unwrap().contains("expected a string"));
}

#[test]
fn malformed_args_never_reach_a_fail_open_tool() {
    // Input malformation is denied before Cedar, whatever the fail mode:
    // a crafted shape cannot reach a fail-open tool's open path.
    let mut b = bundle_v2(
        CEDAR,
        vec![tool_with_args(
            "send_message",
            vec![arg("channel", ArgKind::String)],
        )],
    );
    b.fail_mode.tools.insert("send_message".into(), FailBehaviour::Open);
    let e = Engine::load(&b).unwrap();

    let v = e.evaluate(&call(json!({"channel": 42})));
    assert_eq!(v.outcome, Outcome::Deny);
}

#[test]
fn an_eval_error_over_arguments_denies_even_fail_open() {
    // The deeper property: fail-open is only safe for input-INDEPENDENT
    // failures. Once a verdict depends on arguments, an evaluation error is
    // attacker-triggerable (a well-typed value that overflows an i64
    // arithmetic expression), so it must deny rather than reach the open
    // path — the extension of §3.3 from malformed input to in-policy errors
    // a crafted-but-well-typed value can raise.
    let cedar = r##"
    @id("cap_amount")
    forbid (principal, action == Action::"tool_call", resource)
    when { context.args.amount_cents * 100 > 1000000 };

    @id("allow_all")
    permit (principal, action == Action::"tool_call", resource);
    "##;
    let mut b = bundle_v2(
        cedar,
        vec![tool_with_args("transfer", vec![arg("amount_cents", ArgKind::Long)])],
    );
    b.fail_mode.tools.insert("transfer".into(), FailBehaviour::Open);
    let e = Engine::load(&b).unwrap();

    // A benign amount: allowed.
    let mut r = ToolRequest::new("u:marie", "transfer");
    r.args = json!({"amount_cents": 500});
    assert_eq!(e.evaluate(&r).outcome, Outcome::Allow);

    // A value that overflows `* 100`: Cedar errors. Despite fail-open, the
    // call is DENIED (not AllowFailOpen) because the error is driven by the
    // argument.
    r.args = json!({"amount_cents": i64::MAX});
    let v = e.evaluate(&r);
    assert_eq!(v.outcome, Outcome::Deny, "{:?}", v.reason);
    assert_eq!(v.policy_id, None);
    assert!(v.reason.as_deref().unwrap().contains("over arguments"));
}

#[test]
fn a_policy_bug_on_an_argumentless_tool_still_follows_the_fail_mode() {
    // The customer's fail-open choice survives for tools that declare no
    // arguments: their evaluation errors are input-independent (the same for
    // every request), which is exactly what makes fail-open defensible.
    let cedar_typo = r##"
    @id("typo")
    forbid (principal, action == Action::"tool_call", resource)
    when { context.scopse.contains("x") };

    @id("allow_all")
    permit (principal, action == Action::"tool_call", resource);
    "##;
    let mut b = bundle_v2(cedar_typo, vec![tool_with_args("search", vec![])]);
    b.fail_mode.tools.insert("search".into(), FailBehaviour::Open);
    let e = Engine::load(&b).unwrap();

    let mut r = ToolRequest::new("u:marie", "search");
    r.args = json!({});
    assert_eq!(e.evaluate(&r).outcome, Outcome::AllowFailOpen, "{:?}", e.evaluate(&r).reason);
}

#[test]
fn default_makes_an_absent_arg_total() {
    let cedar = r#"
    @id("no_thread_hijack")
    forbid (principal, action == Action::"tool_call", resource)
    when { context.args.thread != "" };

    @id("allow_all")
    permit (principal, action == Action::"tool_call", resource);
    "#;
    let mut spec = arg("thread", ArgKind::String);
    spec.default = Some(json!(""));
    let e = Engine::load(&bundle_v2(
        cedar,
        vec![tool_with_args("send_message", vec![spec])],
    ))
    .unwrap();

    // Absent: the default ("") satisfies the rule.
    let v = e.evaluate(&call(json!({})));
    assert_eq!(v.outcome, Outcome::Allow, "{:?}", v.reason);

    // Present: the sent value decides.
    let v = e.evaluate(&call(json!({"thread": "1234.5678"})));
    assert_eq!(v.outcome, Outcome::Deny);
    assert_eq!(v.policy_id.as_deref(), Some("no_thread_hijack"));

    // Explicit JSON null counts as absent, not as a value: MCP client SDKs
    // routinely serialize an omitted optional field as null, and treating it
    // as present would coerce-fail and deny a call that omitting the key
    // entirely would have allowed via the default.
    let v = e.evaluate(&call(json!({"thread": null})));
    assert_eq!(v.outcome, Outcome::Allow, "{:?}", v.reason);
}

#[test]
fn explicit_null_without_a_default_is_still_required_absent() {
    // Null is absent, so a required (no-default) arg is refused exactly as a
    // missing key would be — not as a type error.
    let v = engine().evaluate(&call(json!({"channel": null})));
    assert_eq!(v.outcome, Outcome::Deny);
    assert_eq!(v.policy_id, None);
    assert!(v.reason.as_deref().unwrap().contains("absent from the call"));
}

#[test]
fn arg_names_with_pointer_metacharacters_read_the_literal_key() {
    // A name containing '/' or '~' must resolve to the literal argument key,
    // not be interpreted as a JSON-pointer nesting path (RFC 6901). Without
    // escaping, an arg named "path/glob" would read args["path"]["glob"] and
    // the real "path/glob" key would go unchecked — a silent restriction
    // bypass.
    let cedar = r##"
    @id("only_safe_path")
    forbid (principal, action == Action::"tool_call", resource)
    when { context.args["path/glob"] != "/tmp/safe" };

    @id("allow_all")
    permit (principal, action == Action::"tool_call", resource);
    "##;
    let e = Engine::load(&bundle_v2(
        cedar,
        vec![tool_with_args("run", vec![arg("path/glob", ArgKind::String)])],
    ))
    .unwrap();
    let run = |args: serde_json::Value| {
        let mut r = ToolRequest::new("u:marie", "run");
        r.args = args;
        r
    };

    // The literal key "path/glob" is what gets read. A nested {"path":{"glob"}}
    // decoy must NOT satisfy the rule.
    let v = e.evaluate(&run(json!({"path": {"glob": "/tmp/safe"}, "path/glob": "/etc/shadow"})));
    assert_eq!(v.outcome, Outcome::Deny, "the literal key must be read, not the nested decoy");
    assert_eq!(v.policy_id.as_deref(), Some("only_safe_path"));

    // The conforming literal key passes.
    let v = e.evaluate(&run(json!({"path/glob": "/tmp/safe"})));
    assert_eq!(v.outcome, Outcome::Allow, "{:?}", v.reason);
}

#[test]
fn permit_only_argument_rules_hide_the_tool_from_listings() {
    // Documented limitation (design §3.8): the "argument-restricted tools
    // stay listed" guarantee holds for a forbid paired with a broad permit,
    // NOT for a tool whose only permit is argument-conditional — that permit
    // is dropped on the listing path (context.args absent) and the tool
    // falls to default-deny. This test pins the current behavior so the
    // constraint is a conscious choice, not a silent surprise.
    let cedar = r##"
    @id("support_only")
    permit (principal, action == Action::"tool_call", resource == Tool::"send_message")
    when { context.args.channel == "#support" };
    "##;
    let e = Engine::load(&bundle_v2(
        cedar,
        vec![tool_with_args("send_message", vec![arg("channel", ArgKind::String)])],
    ))
    .unwrap();

    // Call path: a conforming channel is allowed (enforcement is correct).
    assert_eq!(
        e.evaluate(&call(json!({"channel": "#support"}))).outcome,
        Outcome::Allow
    );
    // Listing path: the permit is dropped, so the tool is hidden. This is
    // the documented gap — prefer a forbid + blanket permit.
    assert_eq!(
        e.evaluate_listing(&ToolRequest::new("u:marie", "send_message")).outcome,
        Outcome::Deny
    );
}

#[test]
fn float_amounts_are_refused_not_rounded() {
    let cedar = r#"
    @id("cap_amount")
    forbid (principal, action == Action::"tool_call", resource)
    when { context.args.amount_cents > 1000000 };

    @id("allow_all")
    permit (principal, action == Action::"tool_call", resource);
    "#;
    let e = Engine::load(&bundle_v2(
        cedar,
        vec![tool_with_args(
            "transfer",
            vec![arg("amount_cents", ArgKind::Long)],
        )],
    ))
    .unwrap();

    let mut r = ToolRequest::new("u:marie", "transfer");
    r.args = json!({"amount_cents": 999999.9});
    let v = e.evaluate(&r);
    assert_eq!(v.outcome, Outcome::Deny);
    assert_eq!(v.policy_id, None);
    assert!(v.reason.as_deref().unwrap().contains("floats refused"));

    // Out of i64 range: same refusal, no silent wrap.
    r.args = json!({"amount_cents": u64::MAX});
    let v = e.evaluate(&r);
    assert_eq!(v.outcome, Outcome::Deny);
    assert_eq!(v.policy_id, None);

    r.args = json!({"amount_cents": 500});
    assert_eq!(e.evaluate(&r).outcome, Outcome::Allow);
}

#[test]
fn string_set_supports_contains() {
    let cedar = r#"
    @id("no_external_recipients")
    forbid (principal, action == Action::"tool_call", resource)
    when { context.args.recipients.contains("all@company.com") };

    @id("allow_all")
    permit (principal, action == Action::"tool_call", resource);
    "#;
    let e = Engine::load(&bundle_v2(
        cedar,
        vec![tool_with_args(
            "send_mail",
            vec![arg("recipients", ArgKind::StringSet)],
        )],
    ))
    .unwrap();

    let mut r = ToolRequest::new("u:marie", "send_mail");
    r.args = json!({"recipients": ["bob@company.com", "all@company.com"]});
    let v = e.evaluate(&r);
    assert_eq!(v.outcome, Outcome::Deny);
    assert_eq!(v.policy_id.as_deref(), Some("no_external_recipients"));

    r.args = json!({"recipients": ["bob@company.com"]});
    assert_eq!(e.evaluate(&r).outcome, Outcome::Allow);
}

#[test]
fn oversize_input_is_refused() {
    let e = engine();

    let v = e.evaluate(&call(json!({"channel": "x".repeat(5000)})));
    assert_eq!(v.outcome, Outcome::Deny);
    assert_eq!(v.policy_id, None);
    assert!(v.reason.as_deref().unwrap().contains("4096"));

    let e = Engine::load(&bundle_v2(
        CEDAR,
        vec![tool_with_args(
            "send_message",
            vec![
                arg("channel", ArgKind::String),
                arg("cc", ArgKind::StringSet),
            ],
        )],
    ))
    .unwrap();
    let big: Vec<String> = (0..65).map(|i| format!("u{i}")).collect();
    let v = e.evaluate(&call(json!({"channel": "#support", "cc": big})));
    assert_eq!(v.outcome, Outcome::Deny);
    assert!(v.reason.as_deref().unwrap().contains("maximum is 64"));
}

#[test]
fn pointer_reaches_into_nesting() {
    let mut spec = arg("channel", ArgKind::String);
    spec.at = Some("/message/channel".into());
    let e = Engine::load(&bundle_v2(
        CEDAR,
        vec![tool_with_args("send_message", vec![spec])],
    ))
    .unwrap();

    let v = e.evaluate(&call(json!({"message": {"channel": "#support", "text": "hi"}})));
    assert_eq!(v.outcome, Outcome::Allow, "{:?}", v.reason);

    let v = e.evaluate(&call(json!({"message": {"channel": "#general"}})));
    assert_eq!(v.outcome, Outcome::Deny);
    assert_eq!(v.policy_id.as_deref(), Some("support_channel_only"));
}

#[test]
fn undeclared_arguments_stay_invisible() {
    // Extra fields the catalogue does not declare are never read: the call
    // evaluates exactly as if they were not there.
    let v = engine().evaluate(&call(json!({
        "channel": "#support",
        "internal_flag": {"deeply": ["weird", {"shape": 1.5}]}
    })));
    assert_eq!(v.outcome, Outcome::Allow, "{:?}", v.reason);
}

#[test]
fn tools_without_declarations_are_untouched() {
    // Empty policy_args: `context.args` is an empty record, existing rules
    // and calls behave exactly as before the feature.
    let e = Engine::load(&bundle_v2(
        r#"@id("allow_all") permit (principal, action, resource);"#,
        vec![tool_with_args("search", vec![])],
    ))
    .unwrap();
    let mut r = ToolRequest::new("u:marie", "search");
    r.args = json!({"anything": ["at", "all"]});
    assert_eq!(e.evaluate(&r).outcome, Outcome::Allow);
}

#[test]
fn argument_restricted_tools_stay_listed() {
    // A listing carries no arguments, and `send_message` restricted to
    // #support is still a tool the agent may legitimately call: hiding it
    // would hide every argument-restricted tool from every agent. The call
    // path stays the enforcement point.
    let e = engine();
    let r = ToolRequest::new("u:marie", "send_message");
    assert!(e.evaluate_listing(&r).is_allowed());

    // The same request through the call path (no arguments) is refused:
    // visibility and permission are two different questions.
    assert_eq!(e.evaluate(&r).outcome, Outcome::Deny);
}

#[test]
fn listing_still_applies_tool_level_rules() {
    // Leniency is scoped to what cannot be evaluated without arguments.
    // A rule that needs none — destructive without a human — still hides.
    let cedar = r#"
    @id("destructive_requires_human")
    forbid (principal, action == Action::"tool_call", resource)
    when { resource.destructive && !context.has_human_delegation };

    @id("allow_all")
    permit (principal, action == Action::"tool_call", resource);
    "#;
    let mut tool = tool_with_args("drop_db", vec![arg("table", ArgKind::String)]);
    tool.destructive = true;
    let e = Engine::load(&bundle_v2(cedar, vec![tool])).unwrap();

    let mut r = ToolRequest::new("batch-agent", "drop_db");
    r.has_human_delegation = false;
    r.principal_kind = "machine".into();
    assert_eq!(e.evaluate_listing(&r).outcome, Outcome::Deny);

    let human = ToolRequest::new("u:marie", "drop_db");
    assert!(e.evaluate_listing(&human).is_allowed());
}

#[test]
fn listing_refuses_out_of_catalogue_tools() {
    let v = engine().evaluate_listing(&ToolRequest::new("u:marie", "not_in_catalogue"));
    assert_eq!(v.outcome, Outcome::Deny);
    assert!(v.reason.as_deref().unwrap().contains("absent from signed catalogue"));
}
