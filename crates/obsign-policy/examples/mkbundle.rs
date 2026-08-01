//! Compiles and signs a demo policy bundle.
//!
//!     cargo run -p obsign-policy --example mkbundle -- /tmp/demo
//!
//! In production this is the control plane's job: it reads a git repository,
//! compiles, signs with a KMS key, and publishes. The version carries the
//! commit sha — that is what makes a decision replayable months later.

use obsign_audit_core::checkpoint::PublicKeyEntry;
use ed25519_dalek::SigningKey;
use obsign_policy::bundle::{ArgKind, ArgSpec, Bundle, FailBehaviour, FailMode, ToolDef, FORMAT_V2};
use std::collections::BTreeMap;
use std::path::PathBuf;

const CEDAR: &str = r##"
// Reference policy for the support copilot.
//
// Cedar denies by default: without an explicit permit, a call is rejected.
// `forbid` always wins over `permit`, which lets you express an absolute
// prohibition without having to audit every permit.

// 1. Absolute prohibition: nothing destructive in production.
//    No delegation and no group can lift this one.
@id("forbid_destructive_prod")
forbid (
  principal,
  action == Action::"tool_call",
  resource
) when {
  resource.destructive && context.env == "prod"
};

// 2. Nominal authorization: the tool must be covered by a scope the
//    delegation actually carries.
@id("allow_scoped")
permit (
  principal,
  action == Action::"tool_call",
  resource
) when {
  resource.required_scope != "" &&
  context.scopes.contains(resource.required_scope)
};

// 3. Tools requiring no scope are open to everyone (public read).
@id("allow_unscoped")
permit (
  principal,
  action == Action::"tool_call",
  resource
) when {
  resource.required_scope == ""
};

// 4. DBAs keep access to database tools outside production.
@id("allow_dba_nonprod")
permit (
  principal in Group::"dba",
  action == Action::"tool_call",
  resource
) when {
  context.env != "prod"
};

// 5. Argument-level restriction: the tool is allowed, this channel is not.
//    The catalogue declares which arguments the policy may read
//    (`policy_args` on the tool), the gateway extracts exactly those, and
//    the rule decides on the value. A call with a malformed or missing
//    `channel` is refused before this rule even runs.
@id("support_channel_only")
forbid (
  principal,
  action == Action::"tool_call",
  resource == Tool::"send_message"
) when {
  context.args.channel != "#support"
};
"##;

fn main() {
    let out: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/demo".into())
        .into();
    std::fs::create_dir_all(&out).expect("creating the output directory");

    // Policy signing key, distinct from the log sealing key: compromising one
    // must not yield the other.
    let key = SigningKey::from_bytes(&[0x11; 32]);
    let key_id = "policy-key-2026";

    let mut fail_tools = BTreeMap::new();
    // A read-only tool that breaks production because of an evaluation error
    // would be worse than the disease: that one goes fail-open.
    fail_tools.insert("search_docs".to_string(), FailBehaviour::Open);

    let bundle = Bundle {
        // v2: the catalogue below declares argument policy.
        format: FORMAT_V2.to_string(),
        version: "policies@a3f19c2".to_string(),
        cedar: CEDAR.to_string(),
        // Every tool declares the one server the demo gateway wraps, and the
        // demo passes the same string as `--server-id`. A catalogue naming
        // servers the gateway does not front would make its own evidence
        // pack contradict its own bundle — the first thing anyone reads.
        tools: vec![
            ToolDef {
                name: "delete_production_db".into(),
                server: "mcp://mock.demo".into(),
                destructive: true,
                required_scope: Some("db:admin".into()),
                policy_args: Vec::new(),
            },
            ToolDef {
                name: "ticket_update".into(),
                server: "mcp://mock.demo".into(),
                destructive: false,
                required_scope: Some("support:ticket_update".into()),
                policy_args: Vec::new(),
            },
            ToolDef {
                name: "search_docs".into(),
                server: "mcp://mock.demo".into(),
                destructive: false,
                required_scope: None,
                policy_args: Vec::new(),
            },
            ToolDef {
                name: "export_customer_data".into(),
                server: "mcp://mock.demo".into(),
                destructive: false,
                required_scope: Some("data:export".into()),
                policy_args: Vec::new(),
            },
            // Argument-restricted: callable by everyone (rule 3), but rule 5
            // pins the channel. `policy_args` is the allowlist of what the
            // policy may read — the message text is never extracted.
            ToolDef {
                name: "send_message".into(),
                server: "mcp://mock.demo".into(),
                destructive: false,
                required_scope: None,
                policy_args: vec![ArgSpec {
                    name: "channel".into(),
                    at: None,
                    kind: ArgKind::String,
                    default: None,
                }],
            },
        ],
        fail_mode: FailMode {
            default: FailBehaviour::Closed,
            tools: fail_tools,
        },
    };

    let signed = bundle.sign(key_id, &key);
    let keys = vec![PublicKeyEntry {
        key_id: key_id.to_string(),
        algo: "ed25519".to_string(),
        public_key: hex::encode(key.verifying_key().to_bytes()),
        role: Default::default(),
    }];

    let bundle_path = out.join("policy-bundle.json");
    let keys_path = out.join("trusted-keys.json");
    std::fs::write(&bundle_path, serde_json::to_string_pretty(&signed).unwrap()).unwrap();
    std::fs::write(&keys_path, serde_json::to_string_pretty(&keys).unwrap()).unwrap();

    println!("signed bundle : {}", bundle_path.display());
    println!("trusted keys  : {}", keys_path.display());
}
