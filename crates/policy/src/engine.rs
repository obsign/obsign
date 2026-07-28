use audit_core::record::Outcome;
use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicyId, PolicySet, Request, RestrictedExpression,
};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use crate::bundle::{Bundle, FailBehaviour, ToolDef};
use crate::Error;

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

    pub fn evaluate(&self, req: &ToolRequest) -> Verdict {
        // Tool outside the catalogue: refused, without even consulting Cedar.
        //
        // An MCP server can advertise new tools at any time (update,
        // compromise). If the signed catalogue does not describe it, nobody
        // approved its use: we refuse by construction.
        let Some(def) = self.tools.get(&req.tool) else {
            return Verdict {
                outcome: Outcome::Deny,
                policy_id: None,
                reason: Some(format!(
                    "tool \"{}\" absent from signed catalogue {}",
                    req.tool, self.version
                )),
            };
        };

        match self.authorize(req, def) {
            Ok(v) => v,
            Err(e) => self.on_failure(req, &e),
        }
    }

    fn authorize(&self, req: &ToolRequest, def: &ToolDef) -> Result<Verdict, Error> {
        let principal = uid("User", &req.principal)?;
        let action = uid("Action", "tool_call")?;
        let resource = uid("Tool", &def.name)?;

        // Principal entity: groups become parents, so
        // `principal in Group::"dba"` works inside policies.
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

        let context = Context::from_pairs([
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
        ])
        .map_err(|e| Error::Cedar(e.to_string()))?;

        let request = Request::new(principal, action, resource, context, None)
            .map_err(|e| Error::Cedar(e.to_string()))?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &entities);

        // An evaluation error (missing attribute, type mismatch) must never
        // be confused with a clean denial: it means the policy is broken, and
        // it falls under the fail mode.
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();
        if !errors.is_empty() {
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

    fn on_failure(&self, req: &ToolRequest, err: &Error) -> Verdict {
        match self.fail_mode.for_tool(&req.tool) {
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
