use obsign_audit_core::record::PrincipalKind;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Where to find each piece of information inside the token.
///
/// No two providers put the same things in the same place:
///
/// * Keycloak puts realm roles under `realm_access.roles` (nested) and client
///   roles under `resource_access.<client>.roles`;
/// * Entra ID emits `scp` as an array and `groups` flat;
/// * Okta and Ping each have their own variant.
///
/// Hard-coding a special case per provider is the debt not to take on. So we
/// describe the paths in configuration, and the product stays vendor-neutral,
/// which is also what lets you tell a customer "we speak the standard" rather
/// than "we support your IdP".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClaimMap {
    pub subject: String,
    /// Paths tried in order; the first one that answers wins.
    pub scopes: Vec<String>,
    /// All paths are walked and the results merged: a user can legitimately
    /// carry both directory groups and application roles.
    pub groups: Vec<String>,
    /// Used to recognise a service token (`sub` == `client_id`).
    pub client_id: Vec<String>,
    /// Claims a human-readable name may be read from, tried in order; the
    /// first that answers wins. Never replaces `subject`. The label is
    /// recorded *beside* it, because a display name can be renamed and an
    /// audit trail needs the identifier that cannot.
    ///
    /// Defaulted so an `obsign-identity/1` or `/2` bundle deserializes
    /// unchanged; neither signature covers this field, so [`crate::bundle`]
    /// refuses either format carrying anything but the defaults.
    #[serde(default = "default_labels")]
    pub labels: Vec<String>,
    /// What marks a token as a machine's. `#[serde(default)]` so a
    /// `obsign-identity/1` bundle deserializes unchanged, but for that
    /// format the signature does not cover this field, so [`crate::bundle`]
    /// refuses a v1 bundle carrying anything but the defaults.
    #[serde(default)]
    pub machine: MachineMarkers,
}

impl Default for ClaimMap {
    /// Defaults covering Keycloak, Entra ID and Okta with no configuration.
    fn default() -> Self {
        ClaimMap {
            subject: "/sub".into(),
            scopes: vec!["/scope".into(), "/scp".into()],
            groups: vec![
                "/groups".into(),
                "/roles".into(),
                // Keycloak: realm roles.
                "/realm_access/roles".into(),
                // Keycloak: client roles, whichever the client.
                "/resource_access/*/roles".into(),
            ],
            client_id: vec!["/client_id".into(), "/azp".into()],
            labels: default_labels(),
            machine: MachineMarkers::default(),
        }
    }
}

/// Display claims every mainstream IdP populates, most trustworthy first.
///
/// `preferred_username` first because it is what an operator types and what a
/// Keycloak service account carries; `email` before `name` because an IdP
/// usually verifies the former and rarely the latter.
pub fn default_labels() -> Vec<String> {
    vec![
        "/preferred_username".into(),
        "/email".into(),
        "/name".into(),
    ]
}

/// Resolves a JSON-pointer-like path, with `*` meaning "every child".
///
/// The wildcard is not a luxury: Keycloak's `resource_access.<client>.roles`
/// has a segment whose name depends on the client, impossible to hard-code in
/// a configuration shared across several applications.
fn resolve<'a>(root: &'a Value, path: &str) -> Vec<&'a Value> {
    let mut current: Vec<&Value> = vec![root];

    for segment in path.split('/').filter(|s| !s.is_empty()) {
        let mut next = Vec::new();
        for v in current {
            if segment == "*" {
                match v {
                    Value::Object(m) => next.extend(m.values()),
                    Value::Array(a) => next.extend(a.iter()),
                    _ => {}
                }
            } else if let Some(child) = v.get(segment) {
                next.push(child);
            }
        }
        current = next;
        if current.is_empty() {
            break;
        }
    }

    current
}

/// Flattens a value into a list of strings.
///
/// Accepts both shapes seen in practice: a space-separated string (`scope` in
/// Keycloak) or an array (`scp` in Entra ID).
fn flatten(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.extend(s.split_whitespace().map(String::from)),
        Value::Array(a) => {
            for item in a {
                flatten(item, out);
            }
        }
        _ => {}
    }
}

impl ClaimMap {
    pub fn subject(&self, claims: &Value) -> Option<String> {
        resolve(claims, &self.subject)
            .first()
            .and_then(|v| v.as_str())
            .map(String::from)
    }

    /// A display name for this token, with the claim it came from.
    ///
    /// First path that answers wins, and an empty string does not count as an
    /// answer: an IdP that sends `"email": ""` should fall through to the
    /// next claim rather than label the principal with nothing.
    ///
    /// Returns the claim path alongside the value because a label's authority
    /// is the authority of the claim behind it, and only the reader can weigh
    /// that.
    pub fn label(&self, claims: &Value) -> Option<(String, String)> {
        for path in &self.labels {
            if let Some(v) = resolve(claims, path)
                .first()
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            {
                return Some((v.to_string(), path.clone()));
            }
        }
        None
    }

    /// First path that answers. Scopes do not accumulate across
    /// representations: `scope` and `scp` are two spellings of the same
    /// thing, merging them would produce misleading duplicates.
    pub fn scopes(&self, claims: &Value) -> Vec<String> {
        for path in &self.scopes {
            let mut out = Vec::new();
            for v in resolve(claims, path) {
                flatten(v, &mut out);
            }
            if !out.is_empty() {
                out.sort();
                out.dedup();
                return out;
            }
        }
        Vec::new()
    }

    /// Union of every path: directory groups and application roles coexist
    /// legitimately.
    pub fn groups(&self, claims: &Value) -> Vec<String> {
        let mut out = Vec::new();
        for path in &self.groups {
            for v in resolve(claims, path) {
                flatten(v, &mut out);
            }
        }
        out.sort();
        out.dedup();
        out
    }

    pub fn client_id(&self, claims: &Value) -> Option<String> {
        for path in &self.client_id {
            if let Some(s) = resolve(claims, path).first().and_then(|v| v.as_str()) {
                return Some(s.to_string());
            }
        }
        None
    }
}

/// Maximum accepted delegation depth.
///
/// Defensive bound: a token whose `act` claim is nested thousands of times has
/// no legitimate use.
const MAX_ACT_DEPTH: usize = 8;

/// One marker: a claim path (same syntax as [`ClaimMap`], wildcard included)
/// matched against a value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MarkerMatch {
    pub path: String,
    pub value: String,
}

/// Markers identifying a machine token (no human at the root of the chain).
///
/// The old test (`sub` == `client_id`) is only one of the shapes a service
/// token takes, and it is not the one the IdPs this product targets actually
/// emit: a Keycloak or Entra `client_credentials` token has `sub` set to the
/// service principal's own id, distinct from the client id, so that test
/// alone let a keyless robot classify as `Human` and satisfy a "requires a
/// human" Cedar rule. Detection is therefore the union of the markers each
/// target IdP does emit. Every marker only ever *adds* a Machine verdict; a
/// genuine user token matches none of them, so broadening this can never
/// downgrade a real human to a robot, only the reverse, which is the safe
/// direction.
///
/// These are configuration, not code, for the same reason the claim paths
/// are: no two providers mark their service tokens the same way, and a
/// hard-coded list means "we support your IdP" instead of "we speak the
/// standard". But they decide `PrincipalKind`, hence which Cedar rules apply,
/// so they travel inside the signed identity bundle (`obsign-identity/2`),
/// never as a plain file option. A verifier that removes a marker widens what
/// counts as human; that change must be signed like any other authorization
/// change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MachineMarkers {
    /// `sub` == `client_id`: the textbook client_credentials shape, and what
    /// a Keycloak "sub == clientId" protocol mapper produces when configured.
    pub subject_is_client: bool,
    /// A claim equals a value exactly. Default: Entra ID's `idtyp` is `"app"`
    /// for an application acting as itself and `"user"` (or absent) for a
    /// delegated user token; a user token never carries `"app"`.
    pub equals: Vec<MarkerMatch>,
    /// A claim starts with a prefix. Default: a Keycloak service account's
    /// backing user has `preferred_username` = `service-account-<client>`, a
    /// reserved prefix no human login carries.
    pub prefixes: Vec<MarkerMatch>,
}

impl Default for MachineMarkers {
    fn default() -> Self {
        MachineMarkers {
            subject_is_client: true,
            equals: vec![MarkerMatch {
                path: "/idtyp".into(),
                value: "app".into(),
            }],
            prefixes: vec![MarkerMatch {
                path: "/preferred_username".into(),
                value: "service-account-".into(),
            }],
        }
    }
}

impl MachineMarkers {
    /// Whether the token belongs to a machine. Any one marker is enough.
    pub fn is_machine(&self, claims: &Value, subject: &str, client_id: Option<&str>) -> bool {
        if self.subject_is_client && client_id.is_some_and(|c| c == subject) {
            return true;
        }
        for m in &self.equals {
            if resolve(claims, &m.path)
                .iter()
                .any(|v| v.as_str() == Some(m.value.as_str()))
            {
                return true;
            }
        }
        for m in &self.prefixes {
            if resolve(claims, &m.path)
                .iter()
                .any(|v| v.as_str().is_some_and(|s| s.starts_with(m.value.as_str())))
            {
                return true;
            }
        }
        false
    }
}

/// Actor chain and principal nature, derived from the `act` claim.
///
/// RFC 8693 semantics: `sub` names the principal on whose behalf we act, `act`
/// names the actor actually acting, and nesting `act` describes multi-hop
/// delegation. The returned chain runs from outermost (the agent acting now)
/// to innermost (the original principal).
pub fn actor_chain(
    claims: &Value,
    subject: &str,
    client_id: Option<&str>,
    markers: &MachineMarkers,
) -> (Vec<String>, PrincipalKind) {
    let mut chain = Vec::new();
    let mut node = claims.get("act");
    let mut depth = 0;

    while let Some(act) = node {
        if depth >= MAX_ACT_DEPTH {
            break;
        }
        if let Some(s) = act.get("sub").and_then(Value::as_str) {
            chain.push(s.to_string());
        }
        node = act.get("act");
        depth += 1;
    }

    chain.push(subject.to_string());

    // Is there a human at the end of the chain, or is this a keyless robot?
    // The distinction is the reason `PrincipalKind` exists — a destructive
    // action with no identifiable human behind it is defensible to no auditor,
    // and Cedar rules gate on it. Getting it wrong in the machine→human
    // direction is a bypass, so detection is additive and fail-safe: any one
    // marker is enough, and none of them ever fires on a genuine user token.
    let machine = markers.is_machine(claims, subject, client_id);

    let kind = match (chain.len() > 1, machine) {
        (_, true) => PrincipalKind::Machine,
        (true, false) => PrincipalKind::DelegatedHuman,
        (false, false) => PrincipalKind::Human,
    };

    (chain, kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Default markers (what every deployment gets without configuration).
    fn chain(c: &Value, sub: &str, cid: Option<&str>) -> (Vec<String>, PrincipalKind) {
        actor_chain(c, sub, cid, &MachineMarkers::default())
    }

    #[test]
    fn nested_keycloak_roles_are_read() {
        // The case that was broken: Keycloak produces no flat `roles` array,
        // everything sits under `realm_access` and `resource_access`.
        let claims = json!({
            "sub": "u:marie",
            "realm_access": { "roles": ["support-n2", "offline_access"] },
            "resource_access": {
                "obsign-proxy": { "roles": ["dba"] },
                "account": { "roles": ["view-profile"] }
            }
        });

        let g = ClaimMap::default().groups(&claims);
        assert!(g.contains(&"support-n2".to_string()));
        assert!(g.contains(&"dba".to_string()), "client roles not read: {g:?}");
        assert!(g.contains(&"view-profile".to_string()));
    }

    #[test]
    fn scopes_as_string_or_array() {
        let m = ClaimMap::default();
        assert_eq!(m.scopes(&json!({ "scope": "a b c" })), vec!["a", "b", "c"]);
        assert_eq!(m.scopes(&json!({ "scp": ["b", "a"] })), vec!["a", "b"]);
    }

    #[test]
    fn absent_paths_do_not_fail() {
        let m = ClaimMap::default();
        assert!(m.groups(&json!({ "sub": "x" })).is_empty());
        assert!(m.scopes(&json!({ "sub": "x" })).is_empty());
    }

    #[test]
    fn plain_user_token() {
        let c = json!({ "sub": "u:marie", "azp": "obsign-proxy" });
        let (chain, kind) = chain(&c, "u:marie", Some("obsign-proxy"));
        assert_eq!(chain, vec!["u:marie"]);
        assert_eq!(kind, PrincipalKind::Human);
        assert!(kind.has_human());
    }

    #[test]
    fn service_token_is_recognised_as_machine() {
        // client_credentials: `sub` == `client_id`, no human behind it.
        let c = json!({ "sub": "batch-agent", "client_id": "batch-agent" });
        let (chain, kind) = chain(&c, "batch-agent", Some("batch-agent"));
        assert_eq!(chain, vec!["batch-agent"]);
        assert_eq!(kind, PrincipalKind::Machine);
        assert!(!kind.has_human(), "no human may be assumed");
    }

    #[test]
    fn keycloak_service_account_is_machine_despite_sub_ne_client_id() {
        // The gap the `sub == client_id` test missed: a real Keycloak
        // client_credentials token has `sub` = the service-account user id,
        // distinct from `azp`. Only `preferred_username` betrays the robot.
        let c = json!({
            "sub": "b8f3c0a1-service-uuid",
            "azp": "batch-agent",
            "preferred_username": "service-account-batch-agent"
        });
        let (_, kind) = chain(&c, "b8f3c0a1-service-uuid", Some("batch-agent"));
        assert_eq!(kind, PrincipalKind::Machine);
        assert!(!kind.has_human(), "a keyless robot must not pass as a human");
    }

    #[test]
    fn entra_app_only_token_is_machine() {
        // Entra ID app-only token: `sub` is the service principal object id,
        // `appid`/`azp` the client id, and `idtyp` == "app" marks it.
        let c = json!({
            "sub": "sp-object-id",
            "azp": "00000000-client",
            "idtyp": "app"
        });
        let (_, kind) = chain(&c, "sp-object-id", Some("00000000-client"));
        assert_eq!(kind, PrincipalKind::Machine);
        assert!(!kind.has_human());
    }

    #[test]
    fn human_token_with_username_is_not_misclassified() {
        // Counter-check: the new markers must never fire on a genuine user.
        // A normal `preferred_username` and no `idtyp` stays Human.
        let c = json!({
            "sub": "u:marie",
            "azp": "obsign-proxy",
            "preferred_username": "marie",
            "idtyp": "user"
        });
        let (_, kind) = chain(&c, "u:marie", Some("obsign-proxy"));
        assert_eq!(kind, PrincipalKind::Human);
        assert!(kind.has_human());
    }

    #[test]
    fn single_hop_delegation_via_token_exchange() {
        let c = json!({ "sub": "u:marie", "act": { "sub": "support-copilot" } });
        let (chain, kind) = chain(&c, "u:marie", Some("obsign-proxy"));
        assert_eq!(chain, vec!["support-copilot", "u:marie"]);
        assert_eq!(kind, PrincipalKind::DelegatedHuman);
    }

    #[test]
    fn multi_hop_delegation() {
        // Multi-agent topology: an agent calls another one, each still acting
        // on Marie's behalf.
        let c = json!({
            "sub": "u:marie",
            "act": { "sub": "agent-b", "act": { "sub": "agent-a" } }
        });
        let (chain, kind) = chain(&c, "u:marie", None);
        assert_eq!(chain, vec!["agent-b", "agent-a", "u:marie"]);
        assert_eq!(kind, PrincipalKind::DelegatedHuman);
    }

    #[test]
    fn custom_equals_marker_adds_a_machine_verdict() {
        // An IdP marking its service tokens with `token_use: "m2m"` — none of
        // the built-in markers fire, the configured one must.
        let c = json!({ "sub": "svc-42", "azp": "some-client", "token_use": "m2m" });
        assert_eq!(chain(&c, "svc-42", Some("some-client")).1, PrincipalKind::Human);

        let mut m = MachineMarkers::default();
        m.equals.push(MarkerMatch {
            path: "/token_use".into(),
            value: "m2m".into(),
        });
        let (_, kind) = actor_chain(&c, "svc-42", Some("some-client"), &m);
        assert_eq!(kind, PrincipalKind::Machine);
    }

    #[test]
    fn custom_prefix_marker_uses_claim_paths() {
        // Marker paths speak the same language as the claim map, wildcard
        // included: a robot naming convention buried under a provider-specific
        // segment stays expressible.
        let c = json!({ "sub": "x1", "ext": { "corp": { "login": "robot-batch" } } });
        let mut m = MachineMarkers::default();
        m.prefixes.push(MarkerMatch {
            path: "/ext/*/login".into(),
            value: "robot-".into(),
        });
        let (_, kind) = actor_chain(&c, "x1", None, &m);
        assert_eq!(kind, PrincipalKind::Machine);
    }

    #[test]
    fn subject_is_client_can_be_disabled() {
        // Some IdPs reuse `azp` == `sub` for first-party human logins; the
        // signed bundle may turn that single marker off without losing the
        // other two.
        let c = json!({ "sub": "portal", "client_id": "portal" });
        let m = MachineMarkers {
            subject_is_client: false,
            ..MachineMarkers::default()
        };
        let (_, kind) = actor_chain(&c, "portal", Some("portal"), &m);
        assert_eq!(kind, PrincipalKind::Human);
    }

    #[test]
    fn act_nesting_is_bounded() {
        let mut act = json!({ "sub": "a0" });
        for i in 1..50 {
            act = json!({ "sub": format!("a{i}"), "act": act });
        }
        let c = json!({ "sub": "u:marie", "act": act });
        let (chain, _) = chain(&c, "u:marie", None);
        assert!(chain.len() <= MAX_ACT_DEPTH + 1, "nesting is not bounded");
    }
}
