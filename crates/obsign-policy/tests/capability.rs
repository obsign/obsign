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
