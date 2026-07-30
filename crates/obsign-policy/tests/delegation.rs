//! Rules about the delegation chain.
//!
//! This is the product differentiator: expressing "no agent destroys anything
//! without an identifiable human at the end of the chain" is a sentence a
//! CISO understands in five seconds, and that no MCP gateway can write
//! today.

use obsign_audit_core::record::Outcome;
use obsign_policy::bundle::{Bundle, FailBehaviour, FailMode, ToolDef, FORMAT};
use obsign_policy::{Engine, ToolRequest};

const CEDAR: &str = r#"
// Nothing destructive without an identifiable human at the root of the
// delegation. This blocks agents running under client_credentials.
@id("destructive_requires_human")
forbid (principal, action == Action::"tool_call", resource)
when { resource.destructive && !context.has_human_delegation };

// Bounds delegation depth: an agent calling an agent calling an agent
// eventually dilutes accountability to the point where it no longer exists.
@id("chain_too_long")
forbid (principal, action == Action::"tool_call", resource)
when { context.delegation_depth > 2 };

@id("allow_all")
permit (principal, action == Action::"tool_call", resource);
"#;

fn bundle_with(cedar: &str, tools: Vec<ToolDef>) -> Bundle {
    Bundle {
        format: FORMAT.to_string(),
        version: "policies@test".into(),
        cedar: cedar.into(),
        tools,
        fail_mode: FailMode {
            default: FailBehaviour::Closed,
            tools: Default::default(),
        },
    }
}

fn tool_def(name: &str, destructive: bool) -> ToolDef {
    ToolDef {
        name: name.into(),
        server: "mcp://t".into(),
        destructive,
        required_scope: None,
        policy_args: Vec::new(),
    }
}

fn engine() -> Engine {
    Engine::load(&bundle_with(
        CEDAR,
        vec![tool_def("drop_db", true), tool_def("search", false)],
    ))
    .unwrap()
}

#[test]
fn direct_human_may_destroy() {
    let v = engine().evaluate(&ToolRequest::new("u:marie", "drop_db"));
    assert_eq!(v.outcome, Outcome::Allow, "{:?}", v.reason);
}

#[test]
fn agent_delegated_by_a_human_may_destroy() {
    let mut r = ToolRequest::new("u:marie", "drop_db");
    r.actor_chain = vec!["support-copilot".into(), "u:marie".into()];
    r.delegation_depth = 1;
    r.principal_kind = "delegated_human".into();

    let v = engine().evaluate(&r);
    assert_eq!(v.outcome, Outcome::Allow, "{:?}", v.reason);
}

#[test]
fn service_account_may_not_destroy() {
    // The scenario nobody covers: a batch agent under client_credentials,
    // with no human behind it, deleting in production.
    let mut r = ToolRequest::new("batch-agent", "drop_db");
    r.has_human_delegation = false;
    r.principal_kind = "machine".into();

    let v = engine().evaluate(&r);
    assert_eq!(v.outcome, Outcome::Deny);
    assert_eq!(v.policy_id.as_deref(), Some("destructive_requires_human"));
}

#[test]
fn service_account_keeps_non_destructive_tools() {
    // The rule targets irreversible acts, not the agent as such: forbidding
    // everything to a machine would make the product unusable.
    let mut r = ToolRequest::new("batch-agent", "search");
    r.has_human_delegation = false;
    r.principal_kind = "machine".into();

    assert_eq!(engine().evaluate(&r).outcome, Outcome::Allow);
}

#[test]
fn delegation_chain_too_deep_is_refused() {
    let mut r = ToolRequest::new("u:marie", "search");
    r.actor_chain = vec!["a".into(), "b".into(), "c".into(), "u:marie".into()];
    r.delegation_depth = 3;
    r.principal_kind = "delegated_human".into();

    let v = engine().evaluate(&r);
    assert_eq!(v.outcome, Outcome::Deny);
    assert_eq!(v.policy_id.as_deref(), Some("chain_too_long"));
}

#[test]
fn depth_within_limit_is_accepted() {
    let mut r = ToolRequest::new("u:marie", "search");
    r.delegation_depth = 2;
    r.principal_kind = "delegated_human".into();
    assert_eq!(engine().evaluate(&r).outcome, Outcome::Allow);
}

#[test]
fn a_rule_can_target_a_specific_actor() {
    // `actor_chain` is a Cedar set: you can forbid a named agent, or require
    // one, without touching the engine.
    let cedar = r#"
    @id("forbid_experimental_agent")
    forbid (principal, action == Action::"tool_call", resource)
    when { context.actor_chain.contains("agent-experimental") };

    @id("allow_all")
    permit (principal, action == Action::"tool_call", resource);
    "#;

    let e = Engine::load(&bundle_with(cedar, vec![tool_def("search", false)])).unwrap();

    let mut forbidden = ToolRequest::new("u:marie", "search");
    forbidden.actor_chain = vec!["agent-experimental".into(), "u:marie".into()];
    assert_eq!(e.evaluate(&forbidden).outcome, Outcome::Deny);

    let mut allowed = ToolRequest::new("u:marie", "search");
    allowed.actor_chain = vec!["support-copilot".into(), "u:marie".into()];
    assert_eq!(e.evaluate(&allowed).outcome, Outcome::Allow);
}
