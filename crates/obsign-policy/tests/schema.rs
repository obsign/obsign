//! The generated Cedar schema, and the compile-time type check it enables.
//!
//! The schema is only worth having if it describes the model the engine
//! *actually* builds. These tests pin both directions: what the schema
//! declares must be readable at runtime, and what a rule may not read must
//! fail the validator.

use obsign_policy::bundle::{ArgKind, ArgSpec, Bundle, FailMode, ToolDef, FORMAT, FORMAT_V2};
use obsign_policy::{schema_source, Engine, ToolRequest, WRAPPED_SERVER};

fn tool(name: &str) -> ToolDef {
    ToolDef {
        name: name.into(),
        server: "mcp://demo".into(),
        destructive: false,
        required_scope: None,
        policy_args: Vec::new(),
    }
}

fn arg(name: &str, kind: ArgKind) -> ArgSpec {
    ArgSpec {
        name: name.into(),
        at: None,
        kind,
        default: None,
    }
}

fn bundle(cedar: &str, tools: Vec<ToolDef>) -> Bundle {
    let uses_args = tools.iter().any(|t| !t.policy_args.is_empty());
    Bundle {
        format: if uses_args { FORMAT_V2 } else { FORMAT }.to_string(),
        version: "policies@test".into(),
        cedar: cedar.into(),
        tools,
        fail_mode: FailMode::default(),
    }
}

fn validate(cedar: &str, tools: Vec<ToolDef>) -> Result<Vec<String>, String> {
    Engine::load(&bundle(cedar, tools))
        .expect("the rules should parse")
        .validate()
        .map_err(|e| e.to_string())
}

/// The reference policy from the docs and from `examples/mkbundle.rs`: every
/// idiom Obsign tells customers to write must type-check.
const REFERENCE: &str = r##"
@id("forbid_destructive_prod")
forbid (principal, action == Action::"tool_call", resource)
when { resource.destructive && context.env == "prod" };

@id("allow_scoped")
permit (principal, action == Action::"tool_call", resource)
when {
  resource.required_scope != "" &&
  context.scopes.contains(resource.required_scope)
};

@id("allow_unscoped")
permit (principal, action == Action::"tool_call", resource)
when { resource.required_scope == "" };

@id("allow_dba_nonprod")
permit (principal in Group::"dba", action == Action::"tool_call", resource)
when { context.env != "prod" };

@id("forbid_robot_destructive")
forbid (principal, action == Action::"tool_call", resource)
when { resource.destructive && !context.has_human_delegation };

@id("allow_public_docs")
permit (principal, action == Action::"resource_read", resource)
when { context.target like "docs://public/*" };

@id("allow_sampling_for_support")
permit (principal in Group::"support", action == Action::"sampling", resource);

@id("support_channel_only")
forbid (principal, action == Action::"tool_call", resource == Tool::"send_message")
when { context.args.channel != "#support" };
"##;

#[test]
fn the_documented_idioms_type_check() {
    let mut send = tool("send_message");
    send.policy_args = vec![arg("channel", ArgKind::String)];
    let warnings = validate(REFERENCE, vec![tool("search_docs"), send]).expect("should validate");
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
}

#[test]
fn an_attribute_the_model_does_not_expose_fails_at_compile_time() {
    // The exact mistake docs/policies-cedar.md lists as a *runtime* symptom
    // ("evaluation failed, fail-closed: ... does not have the attribute").
    // It is a compile error now.
    let err = validate(
        r#"@id("rbac") permit (principal, action == Action::"tool_call", resource)
           when { principal.permissions.contains("admin") };"#,
        vec![tool("search_docs")],
    )
    .expect_err("principal carries no attributes");
    assert!(err.contains("rbac"), "the rule must be named: {err}");
}

#[test]
fn a_typo_in_a_context_attribute_fails_at_compile_time() {
    let err = validate(
        r#"@id("prod_only") forbid (principal, action == Action::"tool_call", resource)
           when { context.enviroment == "prod" };"#,
        vec![tool("search_docs")],
    )
    .expect_err("`enviroment` is not an attribute");
    assert!(err.contains("prod_only"), "the rule must be named: {err}");
}

#[test]
fn a_typo_in_a_declared_argument_fails_at_compile_time() {
    // Caught whatever guards the rule carries — the check is over the rule's
    // text, not over one synthetic evaluation that may never reach it.
    let mut send = tool("send_message");
    send.policy_args = vec![arg("channel", ArgKind::String)];
    let err = validate(
        r##"@id("chan") forbid (principal, action == Action::"tool_call",
                                resource == Tool::"send_message")
            when { context.env == "prod" && context.args.chanel != "#support" };"##,
        vec![send],
    )
    .expect_err("`chanel` is not declared");
    assert!(err.contains("chan"), "the rule must be named: {err}");
}

#[test]
fn reading_arguments_when_no_tool_declares_any_fails() {
    let err = validate(
        r##"@id("chan") forbid (principal, action == Action::"tool_call", resource)
            when { context.args.channel != "#support" };"##,
        vec![tool("send_message")],
    )
    .expect_err("the catalogue declares no policy_args at all");
    assert!(err.contains("chan"), "the rule must be named: {err}");
}

#[test]
fn an_unconstrained_action_reading_a_tool_attribute_fails() {
    // Reads `resource.destructive` for `resource_read` too, where the
    // resource is a `Resource` and has no attributes. At runtime this rule
    // raises an evaluation error on every capability access and falls to the
    // fail mode — silently, on a fail-open deployment.
    let err = validate(
        r#"@id("no_destructive") forbid (principal, action, resource)
           when { resource.destructive };"#,
        vec![tool("search_docs")],
    )
    .expect_err("Resource and Prompt carry no attributes");
    assert!(err.contains("no_destructive"), "the rule must be named: {err}");
}

#[test]
fn a_server_entity_named_after_the_deployment_fails() {
    // docs/policies-cedar.md warns that `Server::"mcp://crm.internal"` is not
    // a thing — the resource key is a literal. The enum makes it an error
    // rather than a rule that never matches.
    let err = validate(
        &format!(
            r#"@id("sampling_crm") permit (principal, action == Action::"sampling",
                                            resource == Server::"mcp://crm.internal");
               @id("sampling_ok") permit (principal, action == Action::"sampling",
                                          resource == Server::"{WRAPPED_SERVER}");"#
        ),
        vec![tool("search_docs")],
    )
    .expect_err("only the fixed literal exists");
    assert!(
        err.contains("sampling_crm") && !err.contains("sampling_ok"),
        "only the deployment-named rule should fail: {err}"
    );
}

#[test]
fn an_ip_test_over_an_argument_compiles_and_is_reported() {
    // Strict validation refuses `ip()` on a non-literal, but the rule
    // evaluates perfectly and is exactly what the argument feature was
    // designed for. Refusing it would delete a working capability as a side
    // effect of adding a type checker — and `like "10.*"`, the obvious
    // substitute, cannot express a /12 or a /24.
    let mut connect = tool("connect");
    connect.policy_args = vec![arg("src", ArgKind::String)];

    let warnings = validate(
        r#"@id("private_ranges_only")
           forbid (principal, action == Action::"tool_call", resource == Tool::"connect")
           when { !ip(context.args.src).isInRange(ip("10.0.0.0/8")) };"#,
        vec![connect.clone()],
    )
    .expect("a well-typed ip() rule must still compile");

    // Accepted, but never silently: it is surfaced so the author knows a
    // Cedar editor will underline it.
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("private_ranges_only"), "{warnings:?}");
    assert!(warnings[0].contains("accepted"), "{warnings:?}");

    // And it really does evaluate — the whole justification for tolerating it.
    let engine = Engine::load(&bundle(
        r#"@id("private_ranges_only")
           forbid (principal, action == Action::"tool_call", resource == Tool::"connect")
           when { !ip(context.args.src).isInRange(ip("10.0.0.0/8")) };
           @id("allow_all")
           permit (principal, action == Action::"tool_call", resource);"#,
        vec![connect],
    ))
    .unwrap();
    let mut req = ToolRequest::new("alice", "connect");
    req.args = serde_json::json!({"src": "10.1.2.3"});
    assert!(engine.evaluate(&req).is_allowed(), "inside the range");
    req.args = serde_json::json!({"src": "8.8.8.8"});
    assert!(!engine.evaluate(&req).is_allowed(), "outside the range");

}

#[test]
fn a_broken_rule_is_still_refused_and_the_message_says_it_enforces_nothing() {
    // The other side of the same line: tolerating the strict *form*
    // restrictions must not soften anything about rules that cannot work.
    let err = validate(
        r#"@id("dept_gate") forbid (principal, action == Action::"tool_call", resource)
           when { principal.department == "eng" };"#,
        vec![tool("search_docs")],
    )
    .expect_err("principal carries no attributes");
    assert!(err.contains("dept_gate"), "{err}");
    // The remedy has to be obvious, or an operator blocked mid-incident
    // reads the refusal as "my policy repository is bricked".
    assert!(
        err.contains("changes no enforcement"),
        "the message must say the rule does nothing today: {err}"
    );
}

#[test]
fn one_argument_name_cannot_carry_two_types() {
    let mut a = tool("transfer");
    a.policy_args = vec![arg("amount", ArgKind::Long)];
    let mut b = tool("annotate");
    b.policy_args = vec![arg("amount", ArgKind::String)];

    let err = schema_source(&[a, b]).expect_err("conflicting kinds");
    let err = err.to_string();
    assert!(err.contains("annotate") && err.contains("transfer"), "{err}");
    assert!(err.contains("amount"), "{err}");
}

#[test]
fn the_schema_is_deterministic_whatever_the_catalogue_order() {
    let mut a = tool("a");
    a.policy_args = vec![arg("channel", ArgKind::String)];
    let mut b = tool("b");
    b.policy_args = vec![arg("amount", ArgKind::Long)];

    let one = schema_source(&[a.clone(), b.clone()]).unwrap();
    let two = schema_source(&[b, a]).unwrap();
    assert_eq!(one, two);
}

/// The load-bearing test: a rule that reads *every* attribute the schema
/// declares must both type-check and evaluate without error against the
/// entities the engine really builds. An attribute added to the schema but
/// not to `Engine::context_pairs` fails here, in this repository, instead of
/// on a customer's gateway as a fail-mode event.
#[test]
fn everything_the_schema_declares_is_actually_built_at_runtime() {
    let mut send = tool("send_message");
    send.policy_args = vec![
        arg("channel", ArgKind::String),
        arg("amount", ArgKind::Long),
        arg("urgent", ArgKind::Bool),
        arg("tags", ArgKind::StringSet),
    ];

    let cedar = r#"
@id("touch_everything_tool")
permit (principal, action == Action::"tool_call", resource)
when {
  resource.destructive == false &&
  resource.server != "" &&
  resource.required_scope == "" &&
  context.env != "" &&
  context.server != "" &&
  context.session != "" &&
  context.scopes.contains("s") &&
  context.has_human_delegation &&
  context.delegation_depth >= 0 &&
  context.principal_kind != "" &&
  context.actor_chain.contains("a") &&
  context.args.channel != "" &&
  context.args.amount > 0 &&
  context.args.urgent &&
  context.args.tags.contains("t")
};

@id("touch_everything_capability")
permit (principal, action == Action::"resource_read", resource)
when {
  context.target != "" &&
  context.env != "" &&
  context.server != "" &&
  context.session != "" &&
  context.scopes.contains("s") &&
  context.has_human_delegation &&
  context.delegation_depth >= 0 &&
  context.principal_kind != "" &&
  context.actor_chain.contains("a")
};
"#;

    let engine = Engine::load(&bundle(cedar, vec![send])).expect("should load");
    engine.validate().expect("should type-check");

    // Now prove the runtime agrees. Asserting on the `policy_id` rather than
    // on the outcome is what makes this a drift test: a rule Cedar dropped
    // because an attribute was missing would leave the decision to the
    // default deny, and naming it is the only way to know it really ran.
    let mut req = ToolRequest::new("alice", "send_message");
    req.groups = vec!["dba".into()];
    req.scopes = vec!["s".into()];
    req.server = "mcp://demo".into();
    req.session_id = "sess-1".into();
    req.actor_chain = vec!["a".into()];
    req.args = serde_json::json!({
        "channel": "#support", "amount": 1, "urgent": true, "tags": ["t"]
    });
    let v = engine.evaluate(&req);
    assert_eq!(
        v.policy_id.as_deref(),
        Some("touch_everything_tool"),
        "the tool rule must evaluate, not error: {:?}",
        v.reason
    );

    let mut cap = ToolRequest::new("alice", "docs://public/readme");
    cap.scopes = vec!["s".into()];
    cap.server = "mcp://demo".into();
    cap.session_id = "sess-1".into();
    cap.actor_chain = vec!["a".into()];
    let v = engine.evaluate_capability(obsign_policy::Capability::ResourceRead, &cap);
    assert_eq!(
        v.policy_id.as_deref(),
        Some("touch_everything_capability"),
        "the capability rule must evaluate, not error: {:?}",
        v.reason
    );
}
