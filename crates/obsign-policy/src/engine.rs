use obsign_audit_core::record::Outcome;
use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicyId, PolicySet, Request, RestrictedExpression,
};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use crate::bundle::{ArgKind, Bundle, FailBehaviour, ToolDef, FORMAT_V2};
use crate::Error;

/// Caps on what one call may put in front of Cedar. Policy-relevant
/// arguments are identifiers — channels, tables, paths, amounts — not
/// payloads; the caps state that, and bound what a hostile agent can make
/// a `like` pattern chew on.
const MAX_DECLARED_ARGS: usize = 16;
const MAX_STRING_BYTES: usize = 4096;
const MAX_SET_ELEMENTS: usize = 64;

/// An authorization request for a tool call.
#[derive(Debug, Clone)]
pub struct ToolRequest {
    /// Human subject carried by the delegation, already verified.
    pub principal: String,
    /// Groups of the principal (RBAC).
    pub groups: Vec<String>,
    /// Scopes granted by the delegation.
    pub scopes: Vec<String>,
    pub server: String,
    pub tool: String,
    /// Environment declared to the gateway (`prod`, `staging`, ...).
    pub env: String,
    pub session_id: String,

    /// Attested actor chain, outermost first.
    pub actor_chain: Vec<String>,
    /// True when an identifiable human sits at the root of the chain.
    ///
    /// False for a `client_credentials` token: nobody behind it. This is the
    /// distinction that lets you write "nothing destructive without a human
    /// at the end of the chain", a rule no MCP gateway expresses today.
    pub has_human_delegation: bool,
    /// Number of delegation hops. 0 for a token without an `act` claim.
    pub delegation_depth: u32,
    /// `human`, `delegated_human` or `machine`.
    pub principal_kind: String,

    /// The call's `arguments` object, as received. Only the fields the
    /// tool's `policy_args` declare are extracted; the rest is never read.
    /// Anything that is not a JSON object behaves as an empty one.
    pub args: serde_json::Value,
}

impl ToolRequest {
    /// Minimal request, for tests and internal calls.
    pub fn new(principal: impl Into<String>, tool: impl Into<String>) -> Self {
        let principal = principal.into();
        ToolRequest {
            actor_chain: vec![principal.clone()],
            principal,
            groups: Vec::new(),
            scopes: Vec::new(),
            server: String::new(),
            tool: tool.into(),
            env: "prod".into(),
            session_id: String::new(),
            has_human_delegation: true,
            delegation_depth: 0,
            principal_kind: "human".into(),
            args: serde_json::Value::Null,
        }
    }
}

/// Non-tool MCP capabilities the gateway arbitrates.
///
/// Unlike tools there is no signed catalogue to check against — resource
/// URIs and prompt names are minted by the MCP server at runtime — so
/// Cedar's default deny is the whole gate: absent an explicit permit for the
/// action, the access is refused. Policies match the target either exactly
/// (`resource == Resource::"file:///etc/motd"`) or by pattern
/// (`context.target like "docs/*"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// `resources/read`, `resources/subscribe`, `resources/unsubscribe`,
    /// and `completion/complete` against a resource template: one
    /// permission for all — a subscription is only ever a promise of
    /// reads, a completion enumerates the very URIs a read would fetch,
    /// and denying the read must deny both.
    ResourceRead,
    /// `prompts/get`, and `completion/complete` against a prompt.
    PromptGet,
    /// `sampling/createMessage`, initiated by the *server*: it borrows the
    /// agent's model, so data crosses the boundary in both directions. The
    /// resource is the server itself — there is no finer-grained target.
    Sampling,
    /// `elicitation/create`, initiated by the *server*: it puts a question
    /// to the human and carries the answer back. Same shape as sampling.
    Elicitation,
    /// `notifications/message`, initiated by the *server*: a log message at
    /// any level, carrying arbitrary `data` straight into the agent's
    /// context. Unlike progress and cancellation notifications — genuine
    /// liveness machinery — this one can spell out the very resource and
    /// prompt names the listing filter hides, so it is arbitrated per
    /// server like sampling. A notification carries no response, so its
    /// effect closes the instant it is delivered or refused.
    Notify,
}

impl Capability {
    /// Cedar action name. Also the key under which `fail_mode.tools` may
    /// override the fail behaviour for this capability.
    pub fn action(&self) -> &'static str {
        match self {
            Capability::ResourceRead => "resource_read",
            Capability::PromptGet => "prompt_get",
            Capability::Sampling => "sampling",
            Capability::Elicitation => "elicitation",
            Capability::Notify => "notify",
        }
    }

    /// Cedar entity type of the resource.
    pub fn entity_type(&self) -> &'static str {
        match self {
            Capability::ResourceRead => "Resource",
            Capability::PromptGet => "Prompt",
            // Server-initiated channels are granted per server, not per
            // target: the request names no stable object to key on.
            Capability::Sampling | Capability::Elicitation | Capability::Notify => "Server",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub outcome: Outcome,
    pub policy_id: Option<String>,
    pub reason: Option<String>,
}

impl Verdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self.outcome, Outcome::Allow | Outcome::AllowFailOpen)
    }
}

/// Decision engine loaded in memory.
pub struct Engine {
    policies: PolicySet,
    tools: HashMap<String, ToolDef>,
    version: String,
    fail_mode: crate::bundle::FailMode,
    authorizer: Authorizer,
}

impl Engine {
    /// Loads an **already verified** bundle.
    ///
    /// The signature is not revalidated here: it is up to the caller never to
    /// pass an unverified bundle. See `SignedBundle::verify`.
    pub fn load(bundle: &Bundle) -> Result<Self, Error> {
        let parsed = PolicySet::from_str(&bundle.cedar)
            .map_err(|e| Error::Cedar(format!("unreadable policies: {e}")))?;

        // Cedar numbers rules `policy0`, `policy1`... by their order in the
        // file. Unusable here: that identifier is engraved in the audit log,
        // and inserting a rule at the top would silently rename every
        // following one. A record saying "denied by policy3" would stop
        // meaning anything.
        //
        // We therefore require an `@id("...")` annotation on every rule, and
        // rebuild the PolicySet with those stable identifiers.
        let mut renamed = Vec::new();
        for p in parsed.policies() {
            let Some(stable) = p.annotation("id") else {
                return Err(Error::Cedar(format!(
                    "rule \"{}\" has no @id annotation: a stable identifier is \
                     mandatory for the audit log to stay usable",
                    p.id()
                )));
            };
            let id = PolicyId::from_str(stable)
                .map_err(|e| Error::Cedar(format!("invalid @id(\"{stable}\"): {e}")))?;
            renamed.push(p.clone().new_id(id));
        }

        let policies = PolicySet::from_policies(renamed)
            .map_err(|e| Error::Cedar(format!("conflicting or invalid @id values: {e}")))?;

        for t in &bundle.tools {
            validate_arg_specs(t, &bundle.format)?;
        }

        let tools = bundle
            .tools
            .iter()
            .map(|t| (t.name.clone(), t.clone()))
            .collect();

        Ok(Engine {
            policies,
            tools,
            version: bundle.version.clone(),
            fail_mode: bundle.fail_mode.clone(),
            authorizer: Authorizer::new(),
        })
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    /// Tools known to the catalogue, used to filter `tools/list`.
    pub fn known_tools(&self) -> impl Iterator<Item = &ToolDef> {
        self.tools.values()
    }

    /// Tool outside the catalogue: refused, without even consulting Cedar.
    ///
    /// An MCP server can advertise new tools at any time (update,
    /// compromise). If the signed catalogue does not describe it, nobody
    /// approved its use: we refuse by construction. Shared by `evaluate` and
    /// `evaluate_listing` so the deny wording — which the audit log and the
    /// tests key on — cannot drift between the call and listing paths.
    fn lookup(&self, tool: &str) -> Result<&ToolDef, Verdict> {
        self.tools.get(tool).ok_or_else(|| Verdict {
            outcome: Outcome::Deny,
            policy_id: None,
            reason: Some(format!(
                "tool \"{tool}\" absent from signed catalogue {}",
                self.version
            )),
        })
    }

    pub fn evaluate(&self, req: &ToolRequest) -> Verdict {
        let def = match self.lookup(&req.tool) {
            Ok(d) => d,
            Err(v) => return v,
        };

        // Malformed *input* is a denial, never the fail mode: extraction
        // catches an argument that is absent-and-required, the wrong JSON
        // type, or over the caps, before Cedar runs, so a crafted argument
        // shape cannot reach a fail-open tool's open path.
        let args = match extract_args(def, &req.args) {
            Ok(a) => a,
            Err(reason) => {
                return Verdict {
                    outcome: Outcome::Deny,
                    policy_id: None,
                    reason: Some(reason),
                }
            }
        };

        match self.authorize(req, def, Some(args)) {
            Ok(v) => v,
            // Fail-open is only defensible for *input-independent* failures.
            // A broken bundle or a policy typo fails the same way for every
            // request, so the customer can knowingly trade caution for
            // availability on a read-only tool. But once a tool's verdict
            // depends on arguments, an evaluation error becomes
            // input-*dependent* and attacker-triggerable — a well-typed value
            // that overflows an i64 arithmetic expression, or fails an
            // `ip()`/`decimal()` constructor — and must not reach the open
            // path. Extraction already denies malformed input before Cedar
            // (§3.3); this extends the same rule one layer, to the errors a
            // crafted-but-well-typed value can raise *inside* Cedar. Tools
            // that declare no arguments keep the customer's fail mode: their
            // eval errors cannot be steered by a request.
            Err(e) if !def.policy_args.is_empty() => Verdict {
                outcome: Outcome::Deny,
                policy_id: None,
                reason: Some(format!(
                    "policy evaluation failed over arguments, denied: {e}"
                )),
            },
            Err(e) => self.on_failure(&req.tool, &e),
        }
    }

    /// Visibility for `tools/list`.
    ///
    /// Argument-dependent rules cannot be decided without a call's
    /// arguments, and a listing has none. Cedar treats a rule whose
    /// condition fails to evaluate as not applying, so this decision is
    /// taken *as if the argument rules did not exist*: `context.args` is
    /// deliberately absent, and evaluation errors do not fall to the fail
    /// mode. Permissive on purpose — hiding `send_message` because its
    /// channel restriction cannot be checked without a channel would hide
    /// every argument-restricted tool from every agent. The listing is
    /// hygiene; `evaluate` on the call path is the enforcement point.
    ///
    /// Two consequences of "drop the unevaluable rule", both documented in
    /// the design doc §3.8:
    /// - the leniency is not scoped to argument errors — *any* evaluation
    ///   error (a typo'd non-argument attribute, a type mismatch) is
    ///   likewise dropped rather than escalated; visibility is best-effort,
    ///   the call path is what enforces;
    /// - it keeps a tool listed when an argument *forbid* is dropped, but
    ///   hides one whose *only* permit is argument-conditional (the permit
    ///   is dropped, nothing grants, default-deny). Pair an argument
    ///   `forbid` with a broad `permit`, rather than gating visibility on a
    ///   permit that reads `context.args`.
    pub fn evaluate_listing(&self, req: &ToolRequest) -> Verdict {
        let def = match self.lookup(&req.tool) {
            Ok(d) => d,
            Err(v) => return v,
        };
        match self.authorize(req, def, None) {
            Ok(v) => v,
            Err(e) => self.on_failure(&req.tool, &e),
        }
    }

    /// Arbitrates a non-tool capability access. The `tool` field of the
    /// request carries the target — the resource URI or the prompt name.
    pub fn evaluate_capability(&self, cap: Capability, req: &ToolRequest) -> Verdict {
        match self.authorize_capability(cap, req) {
            Ok(v) => v,
            Err(e) => self.on_failure(cap.action(), &e),
        }
    }

    /// `args` is `Some` on the call path — strict: an evaluation error is a
    /// broken policy and falls to the fail mode — and `None` on the listing
    /// path, where `context.args` is absent by design and a rule that
    /// cannot evaluate is dropped rather than escalated. The coupling is
    /// semantic, not incidental: absent args is exactly what makes an
    /// argument rule unevaluable.
    fn authorize(
        &self,
        req: &ToolRequest,
        def: &ToolDef,
        args: Option<Vec<(String, RestrictedExpression)>>,
    ) -> Result<Verdict, Error> {
        let principal = uid("User", &req.principal)?;
        let action = uid("Action", "tool_call")?;
        let resource = uid("Tool", &def.name)?;

        let (principal_entity, group_entities) = self.principal_entities(req, &principal)?;

        let mut tool_attrs = HashMap::new();
        tool_attrs.insert(
            "destructive".to_string(),
            RestrictedExpression::new_bool(def.destructive),
        );
        tool_attrs.insert(
            "server".to_string(),
            RestrictedExpression::new_string(def.server.clone()),
        );
        // Cedar has no ergonomic optional to manipulate in a policy, so "no
        // scope required" is represented by the empty string, which keeps
        // rules readable (`resource.required_scope == ""`).
        tool_attrs.insert(
            "required_scope".to_string(),
            RestrictedExpression::new_string(
                def.required_scope.clone().unwrap_or_default(),
            ),
        );
        let tool_entity = Entity::new(resource.clone(), tool_attrs, HashSet::new())
            .map_err(|e| Error::Cedar(e.to_string()))?;

        let mut all = vec![principal_entity, tool_entity];
        all.extend(group_entities);
        let entities =
            Entities::from_entities(all, None).map_err(|e| Error::Cedar(e.to_string()))?;

        let mut pairs = self.context_pairs(req);
        let strict = args.is_some();
        // Total by construction: every declared arg is present — extracted,
        // or defaulted, or the call was refused before reaching this point.
        // A policy reading `context.args.<name>` can therefore never hit a
        // missing attribute because of anything the agent did; the only
        // remaining source of evaluation errors is a policy authoring bug,
        // which legitimately falls to the fail mode.
        if let Some(args) = args {
            pairs.push((
                "args".to_string(),
                RestrictedExpression::new_record(args).map_err(|e| Error::Cedar(e.to_string()))?,
            ));
        }
        let context = Context::from_pairs(pairs).map_err(|e| Error::Cedar(e.to_string()))?;

        let request = Request::new(principal, action, resource, context, None)
            .map_err(|e| Error::Cedar(e.to_string()))?;

        self.decide(&request, &entities, strict)
    }

    fn authorize_capability(&self, cap: Capability, req: &ToolRequest) -> Result<Verdict, Error> {
        let principal = uid("User", &req.principal)?;
        let action = uid("Action", cap.action())?;
        let resource = uid(cap.entity_type(), &req.tool)?;

        let (principal_entity, group_entities) = self.principal_entities(req, &principal)?;

        // No attributes: a resource URI carries no signed metadata the way a
        // catalogued tool does. Policies decide on the identifier alone.
        let resource_entity = Entity::new(resource.clone(), HashMap::new(), HashSet::new())
            .map_err(|e| Error::Cedar(e.to_string()))?;

        let mut all = vec![principal_entity, resource_entity];
        all.extend(group_entities);
        let entities =
            Entities::from_entities(all, None).map_err(|e| Error::Cedar(e.to_string()))?;

        // The target also goes into the context as a plain string: entity
        // equality only matches exactly, `context.target like "docs/*"` is
        // how a policy grants a family of resources.
        let mut pairs = self.context_pairs(req);
        pairs.push((
            "target".to_string(),
            RestrictedExpression::new_string(req.tool.clone()),
        ));
        let context =
            Context::from_pairs(pairs).map_err(|e| Error::Cedar(e.to_string()))?;

        let request = Request::new(principal, action, resource, context, None)
            .map_err(|e| Error::Cedar(e.to_string()))?;

        self.decide(&request, &entities, true)
    }

    /// Principal and group entities: groups become parents, so
    /// `principal in Group::"dba"` works inside policies.
    fn principal_entities(
        &self,
        req: &ToolRequest,
        principal: &EntityUid,
    ) -> Result<(Entity, Vec<Entity>), Error> {
        let mut group_uids = HashSet::new();
        let mut group_entities = Vec::new();
        for g in &req.groups {
            let g_uid = uid("Group", g)?;
            group_entities.push(
                Entity::new(g_uid.clone(), HashMap::new(), HashSet::new())
                    .map_err(|e| Error::Cedar(e.to_string()))?,
            );
            group_uids.insert(g_uid);
        }

        let principal_entity = Entity::new(principal.clone(), HashMap::new(), group_uids)
            .map_err(|e| Error::Cedar(e.to_string()))?;
        Ok((principal_entity, group_entities))
    }

    /// Context shared by every arbitration, whatever the action.
    fn context_pairs(&self, req: &ToolRequest) -> Vec<(String, RestrictedExpression)> {
        vec![
            (
                "env".to_string(),
                RestrictedExpression::new_string(req.env.clone()),
            ),
            (
                "server".to_string(),
                RestrictedExpression::new_string(req.server.clone()),
            ),
            (
                "session".to_string(),
                RestrictedExpression::new_string(req.session_id.clone()),
            ),
            (
                "scopes".to_string(),
                RestrictedExpression::new_set(
                    req.scopes
                        .iter()
                        .map(|s| RestrictedExpression::new_string(s.clone())),
                ),
            ),
            // Attributes derived from the RFC 8693 actor chain.
            (
                "has_human_delegation".to_string(),
                RestrictedExpression::new_bool(req.has_human_delegation),
            ),
            (
                "delegation_depth".to_string(),
                RestrictedExpression::new_long(req.delegation_depth as i64),
            ),
            (
                "principal_kind".to_string(),
                RestrictedExpression::new_string(req.principal_kind.clone()),
            ),
            (
                "actor_chain".to_string(),
                RestrictedExpression::new_set(
                    req.actor_chain
                        .iter()
                        .map(|s| RestrictedExpression::new_string(s.clone())),
                ),
            ),
        ]
    }

    fn decide(
        &self,
        request: &Request,
        entities: &Entities,
        strict: bool,
    ) -> Result<Verdict, Error> {
        let response = self
            .authorizer
            .is_authorized(request, &self.policies, entities);

        // An evaluation error (missing attribute, type mismatch) must never
        // be confused with a clean denial: it means the policy is broken, and
        // it falls under the fail mode. Except on the listing path (`strict`
        // false), where `context.args` is absent by design: Cedar has
        // already dropped the rules that could not evaluate, and its
        // decision over the remaining ones is exactly the visibility answer.
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();
        if strict && !errors.is_empty() {
            return Err(Error::Cedar(errors.join(" ; ")));
        }

        let policy_id = response
            .diagnostics()
            .reason()
            .next()
            .map(|p| p.to_string());

        Ok(match response.decision() {
            Decision::Allow => Verdict {
                outcome: Outcome::Allow,
                policy_id,
                reason: None,
            },
            Decision::Deny => Verdict {
                outcome: Outcome::Deny,
                policy_id: policy_id.clone(),
                reason: Some(match policy_id {
                    Some(_) => "forbidden by an explicit rule".to_string(),
                    // Cedar denies by default: the absence of a permit is a
                    // denial, and the log must say so plainly.
                    None => "no rule authorizes this call".to_string(),
                }),
            },
        })
    }

    /// Compile-time companion to `load`: evaluates every catalogued tool
    /// once, with every declared arg at its default or its kind's zero
    /// value, against the real policies. An evaluation error here is
    /// almost always a typo'd `context.args.<name>` — Cedar's message
    /// names the offending rule — and it must fail in CI, not surface
    /// months later as a fail-mode event on a live gateway.
    ///
    /// Not exhaustive, and deliberately not part of `load`: a rule guarded
    /// by conditions the synthetic context does not satisfy stays
    /// unexercised, and at runtime a broken rule falls under the fail mode
    /// the customer chose — refusing to start the gateway would override
    /// that choice.
    pub fn smoke_check(&self) -> Result<(), Error> {
        // Sorted: two runs over the same bundle must report the same tool
        // first, or compile errors would flap.
        let mut defs: Vec<&ToolDef> = self.tools.values().collect();
        defs.sort_by(|a, b| a.name.cmp(&b.name));

        for def in defs {
            // The synthetic principal exercises rules, it does not grant:
            // the verdict is discarded, only evaluation errors count.
            let req = ToolRequest::new("smoke-check", &def.name);
            let args = def
                .policy_args
                .iter()
                .map(|spec| {
                    let v = spec.default.clone().unwrap_or_else(|| zero_value(spec.kind));
                    // Defaults were validated at load; zero values coerce
                    // by construction.
                    coerce(spec.kind, &v)
                        .map(|e| (spec.name.clone(), e))
                        .map_err(Error::Bundle)
                })
                .collect::<Result<Vec<_>, _>>()?;
            self.authorize(&req, def, Some(args)).map_err(|e| {
                Error::Bundle(format!("tool \"{}\": smoke evaluation: {e}", def.name))
            })?;
        }
        Ok(())
    }

    /// `key` is the tool name for a tool call, the Cedar action name
    /// (`resource_read`, `prompt_get`) for a capability access.
    fn on_failure(&self, key: &str, err: &Error) -> Verdict {
        match self.fail_mode.for_tool(key) {
            FailBehaviour::Closed => Verdict {
                outcome: Outcome::Deny,
                policy_id: None,
                reason: Some(format!("evaluation failed, fail-closed: {err}")),
            },
            FailBehaviour::Open => Verdict {
                // Definitely not `Allow`: this is a degradation, and it must
                // stay distinguishable from a proper authorization when the
                // log is read back two years later.
                outcome: Outcome::AllowFailOpen,
                policy_id: None,
                reason: Some(format!("evaluation failed, fail-open: {err}")),
            },
        }
    }
}

/// Catalogue-time validation of `policy_args`. Runs at `Engine::load`,
/// which the control plane also calls at compile time — a bad declaration
/// fails in CI, not at gateway startup across the fleet.
fn validate_arg_specs(def: &ToolDef, format: &str) -> Result<(), Error> {
    if def.policy_args.is_empty() {
        return Ok(());
    }
    let complain = |why: String| {
        Err(Error::Bundle(format!(
            "tool \"{}\": policy_args: {why}",
            def.name
        )))
    };
    if format != FORMAT_V2 {
        return complain(format!("requires {FORMAT_V2}, bundle is {format}"));
    }
    if def.policy_args.len() > MAX_DECLARED_ARGS {
        return complain(format!(
            "{} declared args, maximum is {MAX_DECLARED_ARGS}",
            def.policy_args.len()
        ));
    }
    let mut seen = HashSet::new();
    for spec in &def.policy_args {
        if spec.name.is_empty() {
            return complain("an arg has an empty name".into());
        }
        if !seen.insert(spec.name.as_str()) {
            return complain(format!("duplicate arg \"{}\"", spec.name));
        }
        if let Some(at) = &spec.at {
            if !at.starts_with('/') {
                return complain(format!(
                    "arg \"{}\": \"{at}\" is not a JSON pointer (must start with '/')",
                    spec.name
                ));
            }
        }
        if let Some(d) = &spec.default {
            if let Err(why) = coerce(spec.kind, d) {
                return complain(format!("arg \"{}\": default: {why}", spec.name));
            }
        }
    }
    Ok(())
}

/// Extracts the declared arguments of one call. Total by construction:
/// every declared arg comes back — extracted, or defaulted, or the whole
/// call is refused with the returned reason. The allowlist is also the
/// privacy boundary: fields the catalogue does not declare are never read.
fn extract_args(
    def: &ToolDef,
    args: &serde_json::Value,
) -> Result<Vec<(String, RestrictedExpression)>, String> {
    let mut out = Vec::with_capacity(def.policy_args.len());
    for spec in &def.policy_args {
        // An explicit JSON `null` counts as absent, not as a value: MCP
        // client SDKs routinely serialize an omitted optional field as
        // `null`, and treating that as present would coerce-fail and deny a
        // call that omitting the key entirely would have allowed via the
        // default. Absent-or-null then follows the same two branches.
        let present = args.pointer(&spec.pointer()).filter(|v| !v.is_null());
        let expr = match (present, &spec.default) {
            (Some(v), _) => coerce(spec.kind, v)
                .map_err(|why| format!("args: {}: {why}", spec.name))?,
            (None, Some(d)) => coerce(spec.kind, d)
                .map_err(|why| format!("args: {}: default: {why}", spec.name))?,
            (None, None) => {
                return Err(format!(
                    "args: {}: required by policy, absent from the call",
                    spec.name
                ))
            }
        };
        out.push((spec.name.clone(), expr));
    }
    Ok(out)
}

/// The neutral value of a kind, for the smoke evaluation: the point is to
/// force every argument rule to *evaluate*, not to make it pass.
fn zero_value(kind: ArgKind) -> serde_json::Value {
    match kind {
        ArgKind::String => serde_json::Value::String(String::new()),
        ArgKind::Long => serde_json::Value::from(0i64),
        ArgKind::Bool => serde_json::Value::Bool(false),
        ArgKind::StringSet => serde_json::Value::Array(Vec::new()),
    }
}

/// One JSON value becomes one typed Cedar value, or a reason for refusing.
fn coerce(kind: ArgKind, v: &serde_json::Value) -> Result<RestrictedExpression, String> {
    use serde_json::Value;
    match kind {
        ArgKind::String => match v {
            Value::String(s) if s.len() > MAX_STRING_BYTES => Err(format!(
                "string exceeds {MAX_STRING_BYTES} bytes — policy-relevant \
                 arguments are identifiers, not payloads"
            )),
            Value::String(s) => Ok(RestrictedExpression::new_string(s.clone())),
            _ => Err("expected a string".to_string()),
        },
        // `as_i64` is exactly the contract: integral JSON numbers in i64
        // range. A float — even 2.0 — comes back None and is refused, not
        // rounded: an amount check that rounds is an amount check with a
        // hole.
        ArgKind::Long => match v.as_i64() {
            Some(n) => Ok(RestrictedExpression::new_long(n)),
            None => Err("expected an integer (i64 range, floats refused)".to_string()),
        },
        ArgKind::Bool => match v {
            Value::Bool(b) => Ok(RestrictedExpression::new_bool(*b)),
            _ => Err("expected a boolean".to_string()),
        },
        ArgKind::StringSet => match v {
            Value::Array(items) => {
                if items.len() > MAX_SET_ELEMENTS {
                    return Err(format!(
                        "{} elements, maximum is {MAX_SET_ELEMENTS}",
                        items.len()
                    ));
                }
                let mut set = Vec::with_capacity(items.len());
                for it in items {
                    match it {
                        Value::String(s) if s.len() > MAX_STRING_BYTES => {
                            return Err(format!(
                                "an element exceeds {MAX_STRING_BYTES} bytes"
                            ))
                        }
                        Value::String(s) => set.push(RestrictedExpression::new_string(s.clone())),
                        _ => return Err("expected an array of strings".to_string()),
                    }
                }
                Ok(RestrictedExpression::new_set(set))
            }
            _ => Err("expected an array of strings".to_string()),
        },
    }
}

/// Builds a Cedar identifier through the typed constructor.
///
/// Never by string interpolation: a tool name containing a quote would let an
/// attacker craft an arbitrary identifier, and tool names come from a remote
/// MCP server.
fn uid(kind: &str, id: &str) -> Result<EntityUid, Error> {
    let type_name =
        EntityTypeName::from_str(kind).map_err(|e| Error::Cedar(e.to_string()))?;
    let entity_id = EntityId::from_str(id).map_err(|e| Error::Cedar(e.to_string()))?;
    Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
}
