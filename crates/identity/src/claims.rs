use audit_core::record::PrincipalKind;
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
/// describe the paths in configuration, and the product stays vendor-neutral —
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
        }
    }
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

/// Whether the token belongs to a machine (no human at the root of the chain).
///
/// The old test — `sub` == `client_id` — is only one of the shapes a service
/// token takes, and NOT the one the IdPs this product targets actually emit: a
/// Keycloak or Entra `client_credentials` token has `sub` set to the service
/// principal's own id, distinct from the client id, so that test alone let a
/// keyless robot classify as `Human` and satisfy a "requires a human" Cedar
/// rule. Detection is therefore the union of the markers each target IdP does
/// emit. Every branch only ever *adds* a Machine verdict — a genuine user
/// token matches none of them — so broadening this can never downgrade a real
/// human to a robot, only the reverse, which is the safe direction.
///
/// These live as built-in defaults (like `MAX_ACT_DEPTH` and the Keycloak
/// paths in `ClaimMap::default`). Making them overridable belongs to a future
/// signed-bundle revision: the claim map is part of the signed identity bundle
/// because it changes authorization outcomes, and so would this.
fn is_machine(claims: &Value, subject: &str, client_id: Option<&str>) -> bool {
    // 1. `sub` == `client_id`: the textbook client_credentials shape, and what
    //    a Keycloak "sub == clientId" protocol mapper produces when configured.
    if client_id.is_some_and(|c| c == subject) {
        return true;
    }
    // 2. Entra ID app-only token. `idtyp` is "app" for an application acting as
    //    itself and "user" (or absent) for a delegated user token; a user token
    //    never carries "app".
    if claims.get("idtyp").and_then(Value::as_str) == Some("app") {
        return true;
    }
    // 3. Keycloak service account: the backing user's `preferred_username` is
    //    `service-account-<client>`. A human's `preferred_username` is their own
    //    login, never this reserved prefix.
    if claims
        .get("preferred_username")
        .and_then(Value::as_str)
        .is_some_and(|u| u.starts_with("service-account-"))
    {
        return true;
    }
    false
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
    let machine = is_machine(claims, subject, client_id);

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

    #[test]
    fn nested_keycloak_roles_are_read() {
        // The case that was broken: Keycloak produces no flat `roles` array,
        // everything sits under `realm_access` and `resource_access`.
        let claims = json!({
            "sub": "u:marie",
            "realm_access": { "roles": ["support-n2", "offline_access"] },
            "resource_access": {
                "probant-proxy": { "roles": ["dba"] },
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
        let c = json!({ "sub": "u:marie", "azp": "probant-proxy" });
        let (chain, kind) = actor_chain(&c, "u:marie", Some("probant-proxy"));
        assert_eq!(chain, vec!["u:marie"]);
        assert_eq!(kind, PrincipalKind::Human);
        assert!(kind.has_human());
    }

    #[test]
    fn service_token_is_recognised_as_machine() {
        // client_credentials: `sub` == `client_id`, no human behind it.
        let c = json!({ "sub": "batch-agent", "client_id": "batch-agent" });
        let (chain, kind) = actor_chain(&c, "batch-agent", Some("batch-agent"));
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
        let (_, kind) = actor_chain(&c, "b8f3c0a1-service-uuid", Some("batch-agent"));
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
        let (_, kind) = actor_chain(&c, "sp-object-id", Some("00000000-client"));
        assert_eq!(kind, PrincipalKind::Machine);
        assert!(!kind.has_human());
    }

    #[test]
    fn human_token_with_username_is_not_misclassified() {
        // Counter-check: the new markers must never fire on a genuine user.
        // A normal `preferred_username` and no `idtyp` stays Human.
        let c = json!({
            "sub": "u:marie",
            "azp": "probant-proxy",
            "preferred_username": "marie",
            "idtyp": "user"
        });
        let (_, kind) = actor_chain(&c, "u:marie", Some("probant-proxy"));
        assert_eq!(kind, PrincipalKind::Human);
        assert!(kind.has_human());
    }

    #[test]
    fn single_hop_delegation_via_token_exchange() {
        let c = json!({ "sub": "u:marie", "act": { "sub": "support-copilot" } });
        let (chain, kind) = actor_chain(&c, "u:marie", Some("probant-proxy"));
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
        let (chain, kind) = actor_chain(&c, "u:marie", None);
        assert_eq!(chain, vec!["agent-b", "agent-a", "u:marie"]);
        assert_eq!(kind, PrincipalKind::DelegatedHuman);
    }

    #[test]
    fn act_nesting_is_bounded() {
        let mut act = json!({ "sub": "a0" });
        for i in 1..50 {
            act = json!({ "sub": format!("a{i}"), "act": act });
        }
        let c = json!({ "sub": "u:marie", "act": act });
        let (chain, _) = actor_chain(&c, "u:marie", None);
        assert!(chain.len() <= MAX_ACT_DEPTH + 1, "nesting is not bounded");
    }
}
