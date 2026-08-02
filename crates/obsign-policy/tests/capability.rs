//! Arbitration of non-tool MCP capabilities: resource reads, prompt fetches.
//!
//! The gap this pins down: `resources/*` and `prompts/*` used to traverse
//! the gateway with neither policy nor record — a read channel invisible to
//! the proof. There is no signed catalogue of resource URIs (the server
//! mints them at runtime), so Cedar's default deny is the whole gate: a
//! capability nobody explicitly permitted is refused.

use obsign_audit_core::record::Outcome;
use obsign_policy::bundle::{Bundle, FailBehaviour, FailMode, FORMAT};
use obsign_policy::{Capability, Engine, ToolRequest};

fn engine_with(cedar: &str, fail_mode: FailMode) -> Engine {
    Engine::load(&Bundle {
        format: FORMAT.to_string(),
        version: "policies@test".into(),
        cedar: cedar.into(),
        tools: vec![],
        fail_mode,
    })
    .unwrap()
}

fn engine(cedar: &str) -> Engine {
    engine_with(
        cedar,
        FailMode {
            default: FailBehaviour::Closed,
            tools: Default::default(),
        },
    )
}

#[test]
fn a_resource_nobody_permitted_is_refused_by_default() {
    // An empty policy set allows tools nothing — and capabilities nothing.
    let e = engine("");
    let v = e.evaluate_capability(
        Capability::ResourceRead,
        &ToolRequest::new("u:marie", "db://prod/customers"),
    );
    assert_eq!(v.outcome, Outcome::Deny);
    assert_eq!(v.reason.as_deref(), Some("no rule authorizes this call"));
}

#[test]
fn a_permit_on_tool_call_grants_no_resource_access() {
    // The action namespaces are watertight: "everything for tools" must not
    // silently open the resource channel.
    let e = engine(
        r#"@id("allow_tools")
           permit (principal, action == Action::"tool_call", resource);"#,
    );
    let v = e.evaluate_capability(
        Capability::ResourceRead,
        &ToolRequest::new("u:marie", "db://prod/customers"),
    );
    assert_eq!(v.outcome, Outcome::Deny);
}

#[test]
fn an_exact_resource_permit_matches_the_entity() {
    let e = engine(
        r#"@id("allow_runbook")
           permit (principal, action == Action::"resource_read",
                   resource == Resource::"docs://runbook");"#,
    );
    let allowed = e.evaluate_capability(
        Capability::ResourceRead,
        &ToolRequest::new("u:marie", "docs://runbook"),
    );
    assert_eq!(allowed.outcome, Outcome::Allow);
    assert_eq!(allowed.policy_id.as_deref(), Some("allow_runbook"));

    let denied = e.evaluate_capability(
        Capability::ResourceRead,
        &ToolRequest::new("u:marie", "db://prod/customers"),
    );
    assert_eq!(denied.outcome, Outcome::Deny);
}

#[test]
fn a_pattern_permit_grants_a_family_through_the_context() {
    let e = engine(
        r#"@id("allow_docs")
           permit (principal, action == Action::"resource_read", resource)
           when { context.target like "docs://*" };"#,
    );
    assert_eq!(
        e.evaluate_capability(
            Capability::ResourceRead,
            &ToolRequest::new("u:marie", "docs://runbook"),
        )
        .outcome,
        Outcome::Allow
    );
    assert_eq!(
        e.evaluate_capability(
            Capability::ResourceRead,
            &ToolRequest::new("u:marie", "db://prod/customers"),
        )
        .outcome,
        Outcome::Deny
    );
}

#[test]
fn prompts_are_their_own_action_and_entity_type() {
    let e = engine(
        r#"@id("allow_summarize")
           permit (principal, action == Action::"prompt_get",
                   resource == Prompt::"summarize");"#,
    );
    assert_eq!(
        e.evaluate_capability(
            Capability::PromptGet,
            &ToolRequest::new("u:marie", "summarize"),
        )
        .outcome,
        Outcome::Allow
    );
    // The same name under the resource action stays refused: entity types
    // do not bleed into one another.
    assert_eq!(
        e.evaluate_capability(
            Capability::ResourceRead,
            &ToolRequest::new("u:marie", "summarize"),
        )
        .outcome,
        Outcome::Deny
    );
}

#[test]
fn capability_evaluation_failures_follow_the_fail_mode_under_their_action_key() {
    // A policy that evaluates with an error (unknown context attribute on
    // this request shape) falls under the fail mode, keyed by the Cedar
    // action name — the same identifier the customer writes in rules.
    let broken = r#"@id("broken")
        permit (principal, action == Action::"resource_read", resource)
        when { context.no_such_attribute == "x" };"#;

    let closed = engine(broken);
    let v = closed.evaluate_capability(
        Capability::ResourceRead,
        &ToolRequest::new("u:marie", "docs://runbook"),
    );
    assert_eq!(v.outcome, Outcome::Deny);
    assert!(v.reason.unwrap().contains("fail-closed"));

    let open = engine_with(
        broken,
        FailMode {
            default: FailBehaviour::Closed,
            tools: [("resource_read".to_string(), FailBehaviour::Open)]
                .into_iter()
                .collect(),
        },
    );
    let v = open.evaluate_capability(
        Capability::ResourceRead,
        &ToolRequest::new("u:marie", "docs://runbook"),
    );
    assert_eq!(v.outcome, Outcome::AllowFailOpen);
}

#[test]
fn server_initiated_channels_are_keyed_on_the_literal_whatever_the_caller_says() {
    // `Server` is an enumerated entity type in the generated schema: it holds
    // exactly one id. Minting `Server::<caller text>` would put a runtime
    // entity outside that set, and a rule written against the literal — the
    // only form the docs describe — would then silently never match: the
    // `permit` stops permitting, with no evaluation error and nothing in the
    // log to tell it apart from a clean default deny.
    let e = engine(&format!(
        r#"@id("allow_sampling")
           permit (principal, action == Action::"sampling",
                   resource == Server::"{}");"#,
        obsign_policy::WRAPPED_SERVER
    ));

    // The gateway's own call: the literal, which must be permitted.
    let v = e.evaluate_capability(
        Capability::Sampling,
        &ToolRequest::new("u:marie", obsign_policy::WRAPPED_SERVER),
    );
    assert_eq!(v.outcome, Outcome::Allow);
    assert_eq!(v.policy_id.as_deref(), Some("allow_sampling"));

    // A caller naming the deployment instead — an embedder passing
    // `--server-id`, or a future server-initiated path. The rule must still
    // decide, because the resource is the model's literal either way.
    let v = e.evaluate_capability(
        Capability::Sampling,
        &ToolRequest::new("u:marie", "mcp://crm.internal"),
    );
    assert_eq!(
        v.policy_id.as_deref(),
        Some("allow_sampling"),
        "the resource must be the literal, not the caller's string"
    );

    // What the caller named is not lost: it reaches rules as context.target,
    // which is where a per-deployment distinction belongs.
    let e = engine(
        r#"@id("not_the_crm")
           forbid (principal, action == Action::"sampling", resource)
           when { context.target == "mcp://crm.internal" };
           @id("allow_sampling")
           permit (principal, action == Action::"sampling", resource);"#,
    );
    let v = e.evaluate_capability(
        Capability::Sampling,
        &ToolRequest::new("u:marie", "mcp://crm.internal"),
    );
    assert_eq!(v.outcome, Outcome::Deny);
    assert_eq!(v.policy_id.as_deref(), Some("not_the_crm"));
}

#[test]
fn target_keyed_capabilities_still_key_on_the_request() {
    // The other side of `keyed_on_server`: resource reads and prompt fetches
    // must keep naming what the request asked for, or every exact-match rule
    // in the docs would stop working.
    let e = engine(
        r#"@id("one_doc")
           permit (principal, action == Action::"resource_read",
                   resource == Resource::"docs://runbook");"#,
    );
    let v = e.evaluate_capability(
        Capability::ResourceRead,
        &ToolRequest::new("u:marie", "docs://runbook"),
    );
    assert_eq!(v.outcome, Outcome::Allow);
    let v = e.evaluate_capability(
        Capability::ResourceRead,
        &ToolRequest::new("u:marie", "docs://other"),
    );
    assert_eq!(v.outcome, Outcome::Deny);
}
