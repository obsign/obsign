use crate::canonical::Encoder;
use crate::hash::{digest, domain, Hash};
use serde::{Deserialize, Serialize};

/// One link of the audit log.
///
/// Two structures are layered in the same object and must not be confused:
///
/// * the **integrity chain** (`seq` + `prev_hash`): total order, proves that
///   no record was removed, inserted or modified;
/// * the **attribution chain** (`id` + `parent_id`): the business tree, ties
///   an act back to the human who delegated it.
///
/// The first one serves the auditor, the second one serves the investigation.
/// They are independent: a record can be intact and orphaned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// Position in the chain, strictly increasing, no gaps.
    pub seq: u64,
    /// Wall clock at write time (ms since epoch).
    /// Informational: never order by it, only `seq` is authoritative.
    pub ts_ms: i64,
    /// Hash of the previous record (GENESIS when seq == 0).
    pub prev_hash: Hash,

    /// Identifier of this node in the attribution chain.
    pub id: String,
    /// Parent node (None only for a root delegation).
    pub parent_id: Option<String>,
    /// End-to-end correlation, from the human login down to the effect.
    pub session_id: String,

    pub payload: Payload,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
    /// A human delegates authority to an agent, for a bounded time.
    Delegation(Delegation),
    /// Actor chain attested by the identity provider (`act` claim, RFC 8693).
    Actor(Actor),
    /// An agent instance starts under that delegation.
    AgentSession(AgentSession),
    /// A model turn: the *context* that led to the act.
    LlmTurn(LlmTurn),
    /// An attempted tool call: the act itself.
    ToolCall(ToolCall),
    /// An attempted MCP capability access outside tool calls: a resource
    /// read or subscription, a prompt fetch. Data leaves the server on this
    /// channel exactly as it does on `tools/call`, so it is recorded — and
    /// arbitrated — the same way.
    McpAccess(McpAccess),
    /// A human-readable name for a subject the log names elsewhere.
    ///
    /// Real OIDC subjects are opaque — Keycloak issues UUIDs — so a pack
    /// naming only `sub` is unreadable to the auditor it is written for,
    /// who by construction cannot query the issuer's directory. Recording
    /// the label *beside* the subject rather than instead of it keeps both
    /// properties: `sub` stays the stable identifier a rename cannot move,
    /// the label stays the string a human can act on.
    PrincipalLabel(PrincipalLabel),
    /// A payload type this build does not know, kept verbatim.
    ///
    /// The alternative — refusing the whole log — was the behaviour, and it
    /// is wrong for the reader this product is written for: an auditor
    /// building the verifier from source, months after the log was written,
    /// against a gateway that has since gained a payload type. Refusing gave
    /// them "unreadable record at line 3", which reads as corruption and
    /// says nothing about the remedy.
    ///
    /// Keeping the record readable is *not* the same as accepting it. A
    /// payload this build cannot re-encode is a payload whose hash it cannot
    /// recompute, so it cannot attest to that record at all — the verifier
    /// reports `unknown_payload_type` as an **error** and the pack does not
    /// come out valid. What changes is the diagnosis: an operator learns
    /// which type, on which record, and that the fix is a newer verifier.
    Unknown(UnknownPayload),
    /// The policy decision applied to that call.
    Decision(Decision),
    /// What actually happened.
    Effect(Effect),
    /// A configuration reload observed by the gateway (key rotation,
    /// republished bundle), applied or rejected.
    ConfigReload(ConfigReload),
    /// The gateway identity key's certificate over this chain's ephemeral
    /// session signing key. The first record of a chain, so every later
    /// record's origin signature resolves to a key the identity key vouched
    /// for.
    SessionCert(SessionCert),
}

/// Canonical encoding of an arbitrary JSON value, for payloads with no
/// schema.
///
/// Type-tagged so a string and a number can never encode alike, and object
/// keys are sorted so insertion order cannot move the result. Deliberately
/// not `serde_json::to_string`: that is JSON as a computation format, and it
/// inherits whatever key order the input file happened to carry.
fn encode_json(e: &mut Encoder, v: &serde_json::Value) {
    use serde_json::Value;
    match v {
        Value::Null => {
            e.u8(0);
        }
        Value::Bool(b) => {
            e.u8(1).u8(*b as u8);
        }
        // Numbers keep their textual form: JSON has no integer/float
        // distinction we can rely on, and re-deriving one here would be the
        // "two serializers, two hashes" problem the encoder exists to avoid.
        Value::Number(n) => {
            e.u8(2).str(&n.to_string());
        }
        Value::String(s) => {
            e.u8(3).str(s);
        }
        Value::Array(items) => {
            e.u8(4).u64(items.len() as u64);
            for item in items {
                encode_json(e, item);
            }
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            e.u8(5).u64(keys.len() as u64);
            for k in keys {
                e.str(k);
                encode_json(e, &map[k]);
            }
        }
    }
}

/// A payload kept verbatim because this build has no schema for it.
#[derive(Debug, Clone, PartialEq)]
pub struct UnknownPayload {
    /// The `kind` discriminant as it appeared, so a report can name it.
    pub kind: String,
    /// The payload object exactly as read, `kind` included. Kept whole so
    /// re-serializing a pack is byte-faithful: a verifier that rewrote a
    /// record it did not understand would be destroying the evidence it was
    /// asked to check.
    pub raw: serde_json::Map<String, serde_json::Value>,
}

// Hand-written so an unknown `kind` yields `Unknown` instead of failing the
// whole record, and so `Unknown` serializes back to what it came from. The
// macro keeps the variant list to one line each: a mirror enum would be the
// same list twice, and the day the two drifted, a payload would silently
// change shape on disk.
macro_rules! payload_kinds {
    ($( $kind:literal => $variant:ident($ty:ty) ),* $(,)?) => {
        impl Payload {
            /// The `kind` discriminant as it appears in JSON.
            pub fn kind_str(&self) -> &str {
                match self {
                    $( Payload::$variant(_) => $kind, )*
                    Payload::Unknown(u) => &u.kind,
                }
            }

            /// False when this build has no schema for the payload, and so
            /// cannot recompute the record's hash or attest to it.
            pub fn is_understood(&self) -> bool {
                !matches!(self, Payload::Unknown(_))
            }
        }

        impl Serialize for Payload {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                use serde::ser::Error as _;
                // Verbatim: a verifier that rewrote a record it did not
                // understand would be destroying the evidence it was asked
                // to check.
                if let Payload::Unknown(u) = self {
                    return u.raw.serialize(s);
                }
                let mut obj = match self {
                    $( Payload::$variant(v) => serde_json::to_value(v).map_err(S::Error::custom)?, )*
                    Payload::Unknown(_) => unreachable!("handled above"),
                };
                obj.as_object_mut()
                    .ok_or_else(|| S::Error::custom("payload did not serialize to an object"))?
                    .insert("kind".into(), serde_json::Value::String(self.kind_str().into()));
                obj.serialize(s)
            }
        }

        impl<'de> Deserialize<'de> for Payload {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                use serde::de::Error as _;
                let mut map = serde_json::Map::deserialize(d)?;
                // Removed, not cloned-around: `kind` belongs to the envelope
                // and the inner structs are `deny_unknown_fields`, so it has
                // to go before they see the object either way. Taking it out
                // once lets the map be *moved* into whichever arm wins.
                let kind = match map.remove("kind") {
                    Some(serde_json::Value::String(k)) => k,
                    Some(_) => return Err(D::Error::custom("`kind` must be a string")),
                    None => return Err(D::Error::missing_field("kind")),
                };

                match kind.as_str() {
                    $(
                        $kind => serde_json::from_value::<$ty>(serde_json::Value::Object(map))
                            .map(Payload::$variant)
                            .map_err(D::Error::custom),
                    )*
                    // Only an unrecognised discriminant becomes `Unknown`. A
                    // payload whose kind we *do* know but whose fields are
                    // malformed stays an error above: that is corruption, not
                    // a version gap, and treating it as "unknown type" would
                    // let a tampered record pass as a newer one.
                    _ => {
                        // Put `kind` back: `raw` is what gets written out
                        // again, and a payload that lost its discriminant
                        // would not round-trip.
                        map.insert("kind".into(), serde_json::Value::String(kind.clone()));
                        Ok(Payload::Unknown(UnknownPayload { kind, raw: map }))
                    }
                }
            }
        }
    };
}

payload_kinds! {
    "delegation" => Delegation(Delegation),
    "actor" => Actor(Actor),
    "agent_session" => AgentSession(AgentSession),
    "llm_turn" => LlmTurn(LlmTurn),
    "tool_call" => ToolCall(ToolCall),
    "mcp_access" => McpAccess(McpAccess),
    "principal_label" => PrincipalLabel(PrincipalLabel),
    "decision" => Decision(Decision),
    "effect" => Effect(Effect),
    "config_reload" => ConfigReload(ConfigReload),
    "session_cert" => SessionCert(SessionCert),
}

impl Payload {
    /// Stable discriminant, frozen once and for all.
    ///
    /// NEVER renumber: these values feed the hash computation, changing them
    /// would invalidate every existing log. A new payload type takes the next
    /// free integer.
    fn tag(&self) -> u8 {
        match self {
            Payload::Delegation(_) => 1,
            Payload::AgentSession(_) => 2,
            Payload::LlmTurn(_) => 3,
            Payload::ToolCall(_) => 4,
            Payload::Decision(_) => 5,
            Payload::Effect(_) => 6,
            // Added later, to record the RFC 8693 actor chain.
            //
            // Deliberately a *new* type rather than a field added to
            // `Delegation`: changing the encoding of an existing payload would
            // change its hash and invalidate every already-sealed log. An
            // additional type touches nothing.
            Payload::Actor(_) => 7,
            // Added later, same rule: configuration reloads used to be
            // traceable only through the `config_hash` of the next
            // `agent_session` record, i.e. only if a delegation happened to be
            // recorded after the reload.
            Payload::ConfigReload(_) => 8,
            // Added later, same rule: the two-tier key architecture. Records
            // are signed by an ephemeral session key; this certificate, signed
            // by the gateway's hardware identity key, is what a verifier
            // resolves that session key against.
            Payload::SessionCert(_) => 9,
            // Added later, same rule: resource and prompt accesses used to
            // traverse the gateway with no record at all — a read channel
            // invisible to the proof.
            Payload::McpAccess(_) => 10,
            // Added later, same rule: a display name for an opaque subject.
            // A field on `Delegation` would have been the obvious place and
            // is exactly what the rule forbids — it would rewrite the hash of
            // every delegation ever sealed.
            Payload::PrincipalLabel(_) => 11,
            // Zero, never allocated to a real payload — tags start at 1 — so
            // this encoding cannot collide with any type, present or future.
            // It is deliberately *not* the producer's encoding: nothing here
            // knows the schema, so the hash it yields is this build's opinion
            // of an opaque blob, never a re-derivation of the original. The
            // verifier must therefore refuse to attest to such a record
            // rather than compare hashes — see `is_understood`.
            Payload::Unknown(_) => 0,
        }
    }

    fn encode(&self, e: &mut Encoder) {
        e.u8(self.tag());
        match self {
            Payload::Delegation(d) => {
                e.str(&d.principal_sub)
                    .str(&d.principal_issuer)
                    .str_seq(&d.scopes)
                    .i64(d.expires_at_ms)
                    .opt_str(d.approved_by.as_deref())
                    .str(d.approval_mode.as_str());
            }
            Payload::Actor(a) => {
                e.str_seq(&a.chain).str(a.principal_kind.as_str());
            }
            Payload::AgentSession(a) => {
                e.str(&a.agent_id)
                    .str(&a.agent_version)
                    .hash(&a.config_hash);
            }
            Payload::LlmTurn(t) => {
                e.str(&t.provider)
                    .str(&t.model)
                    .hash(&t.prompt_hash)
                    .hash(&t.response_hash)
                    .opt_u64(t.input_tokens)
                    .opt_u64(t.output_tokens)
                    .opt_u64(t.cost_micros);
            }
            Payload::ToolCall(c) => {
                e.str(&c.server).str(&c.tool).hash(&c.args_hash);
                match &c.args_sealed {
                    None => {
                        e.u8(0);
                    }
                    Some(s) => {
                        e.u8(1).str(&s.key_id).str(&s.blob_ref);
                    }
                }
            }
            Payload::Decision(d) => {
                e.str(d.outcome.as_str())
                    .opt_str(d.policy_id.as_deref())
                    .str(&d.bundle_version)
                    .opt_str(d.reason.as_deref());
            }
            Payload::Effect(x) => {
                e.str(x.status.as_str())
                    .opt_hash(x.result_hash.as_ref())
                    .u64(x.latency_ms);
            }
            Payload::ConfigReload(c) => {
                e.str(c.config_kind.as_str())
                    .str(c.status.as_str())
                    .str(&c.bundle_version)
                    .opt_hash(c.bundle_hash.as_ref())
                    .opt_str(c.reason.as_deref());
            }
            Payload::SessionCert(c) => {
                e.str(&c.session_pubkey)
                    .str(&c.identity_key_id)
                    .str(&c.gateway_id)
                    .i64(c.not_before_ms)
                    .i64(c.not_after_ms)
                    .str(&c.identity_sig);
            }
            Payload::McpAccess(a) => {
                e.str(&a.server)
                    .str(&a.method)
                    .str(&a.target)
                    .hash(&a.params_hash);
            }
            Payload::PrincipalLabel(p) => {
                e.str(&p.issuer).str(&p.subject).str(&p.label).str(&p.claim);
            }
            Payload::Unknown(u) => {
                // Through the canonical encoder, with object keys sorted at
                // every level — not `to_string()`. The workspace enables
                // serde_json's `preserve_order` (cedar-policy pulls it in via
                // serde_with), so a `Map` iterates in *insertion* order and
                // the JSON text of one logical payload depends on the key
                // order of the file it was read from. Hashing that text would
                // make two honest verifiers disagree about the same record,
                // and would put JSON where the README says it must never be:
                // "no JSON for hashes ... JSON stays the transport and reading
                // format, never the computation one".
                //
                // This hash is still not the producer's — nothing here knows
                // the schema. It only has to be total and stable.
                e.str(&u.kind);
                encode_json(e, &serde_json::Value::Object(u.raw.clone()));
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    /// `sub` of the OIDC token, after signature verification.
    pub principal_sub: String,
    /// Token issuer: without it, `sub` is not unique.
    pub principal_issuer: String,
    pub scopes: Vec<String>,
    pub expires_at_ms: i64,
    /// Set when a second human approved (four-eyes).
    pub approved_by: Option<String>,
    pub approval_mode: ApprovalMode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// Follows from the bearer's standing permissions.
    Implicit,
    /// A human approved explicitly, in the moment.
    Interactive,
    /// Approved by a third party (four-eyes).
    FourEyes,
}

impl ApprovalMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalMode::Implicit => "implicit",
            ApprovalMode::Interactive => "interactive",
            ApprovalMode::FourEyes => "four_eyes",
        }
    }
}

/// Actor chain as attested by the identity provider.
///
/// Built on the `act` claim of RFC 8693 (OAuth 2.0 Token Exchange): `sub`
/// names the principal on whose behalf we act, `act` names the actor doing
/// the acting, and nesting `act` describes multi-hop delegation.
///
/// Without it, the log records "marie.dupont" with no way to substantiate
/// that an agent was acting in her name: the attribution chain is inferred
/// rather than attested.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    /// From outermost (the one acting) to innermost (the original
    /// principal). A single element means there is no delegation.
    pub chain: Vec<String>,
    /// Deliberately verbose name: `Payload` is serialized with
    /// `#[serde(tag = "kind")]`, so a field called `kind` would collide with
    /// the discriminant serde injects — the value would be written twice and
    /// reading it back would fail.
    pub principal_kind: PrincipalKind,
}

/// Nature of the principal at the root of the chain.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// User token, no attested delegation.
    Human,
    /// Attested delegation: an actor acts on behalf of a human.
    DelegatedHuman,
    /// Service token (`sub` == `client_id`): no human at the end of the
    /// chain. The distinction is essential — a destructive action with no
    /// identifiable human behind it is defensible to no one.
    Machine,
}

impl PrincipalKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PrincipalKind::Human => "human",
            PrincipalKind::DelegatedHuman => "delegated_human",
            PrincipalKind::Machine => "machine",
        }
    }

    /// True when an identifiable human sits at the root.
    pub fn has_human(&self) -> bool {
        matches!(self, PrincipalKind::Human | PrincipalKind::DelegatedHuman)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentSession {
    pub agent_id: String,
    pub agent_version: String,
    /// Hash of the effective configuration (system prompt, declared tools,
    /// parameters). Lets you prove after the fact exactly which configuration
    /// the agent was running that day.
    pub config_hash: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LlmTurn {
    pub provider: String,
    pub model: String,
    /// The hash, not the content: prompts almost always carry personal data
    /// or business secrets. Nothing here retains the cleartext — same rule,
    /// and same absence of a retention path, as `ToolCall::args_sealed`.
    pub prompt_hash: Hash,
    pub response_hash: Hash,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    /// Cost in millionths of a currency unit: an integer, so no float ever
    /// enters a hash (an f64 has no portable canonical representation).
    pub cost_micros: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ToolCall {
    pub server: String,
    pub tool: String,
    pub args_hash: Hash,
    /// Reserved for retained content. **Nothing in this repository writes
    /// it**: the gateway hashes the arguments and drops the values, so this
    /// is `None` in every log written today. It sits in the format — and in
    /// the record hash, see the encoding below — so that turning retention
    /// on later does not change how existing records hash.
    ///
    /// The constraint on any implementation is already settled: the content
    /// must be encrypted to a key the customer holds, and the gateway must
    /// not hold its private half. A gateway that can read back the arguments
    /// it stored is a gateway worth compromising for the arguments.
    pub args_sealed: Option<SealedRef>,
}

/// A display name for a subject, recorded beside it rather than instead of it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PrincipalLabel {
    /// Issuer of the subject below, byte-for-byte as the `Delegation`
    /// recorded it.
    ///
    /// Half of the join key, and not optional: an OIDC subject is only
    /// unique *within* an issuer. The gateway hot-reloads identity bundles,
    /// so one chain can hold delegations from two providers, and a `sub` as
    /// ordinary as `1000` collides across realms. A label joined on the
    /// subject alone would then name the wrong human — the one failure this
    /// payload exists to prevent.
    pub issuer: String,
    /// The subject this names, byte-for-byte as the `Delegation` recorded it.
    /// The other half of the join key: a reader that does not understand this
    /// payload loses the label and keeps a log that still says who acted.
    pub subject: String,
    /// What a human reads — `guillaume`, `service-account-n8n-agent`.
    pub label: String,
    /// The claim it came from (`/preferred_username`, `/email`, ...).
    ///
    /// Recorded because a label's authority is exactly the authority of the
    /// claim behind it: an `email` an IdP verified and a `name` a user typed
    /// deserve different trust, and an auditor cannot weigh them without
    /// knowing which is which.
    pub claim: String,
}

/// An MCP capability access outside tool calls.
///
/// The investigation needs to know *what* was touched, so the target — a
/// resource URI or a prompt name — is recorded verbatim: it is an
/// identifier, like a tool name, not a payload. The content that came back
/// only ever appears as the effect's `result_hash`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpAccess {
    pub server: String,
    /// JSON-RPC method: `resources/read`, `resources/subscribe`,
    /// `resources/unsubscribe`, `prompts/get`.
    pub method: String,
    /// Resource URI or prompt name, as sent by the agent.
    pub target: String,
    /// Hash of the full request params.
    pub params_hash: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SealedRef {
    pub key_id: String,
    pub blob_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub outcome: Outcome,
    /// The Cedar rule that decided. None when no rule matched (we then fell
    /// through to the implicit default).
    pub policy_id: Option<String>,
    /// Version of the signed bundle loaded by the gateway at that instant.
    /// Without it, replaying the decision later is impossible.
    pub bundle_version: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allow,
    Deny,
    /// The engine could not decide and the policy is fail-open.
    /// Distinct from Allow: this is a degradation, and it must be visible.
    AllowFailOpen,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Allow => "allow",
            Outcome::Deny => "deny",
            Outcome::AllowFailOpen => "allow_fail_open",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Effect {
    pub status: EffectStatus,
    pub result_hash: Option<Hash>,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EffectStatus {
    Ok,
    Error,
    /// The call never reached the tool: blocked upstream.
    Blocked,
    Timeout,
}

impl EffectStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            EffectStatus::Ok => "ok",
            EffectStatus::Error => "error",
            EffectStatus::Blocked => "blocked",
            EffectStatus::Timeout => "timeout",
        }
    }
}

/// A configuration reload observed by the gateway.
///
/// The bundles the gateway trusts — JWKS, claim mapping, policies — are
/// reloaded from disk when the control plane republishes them, typically on a
/// key rotation. That changes what the log means: the same token is refused
/// before the reload and accepted after. So the reload itself goes into the
/// log, and "which keys were trusted when this act happened?" has a direct
/// answer: the last applied `config_reload` (or the opening `agent_session`)
/// before the act.
///
/// Rejected attempts are recorded too. A bundle refused at reload — bad
/// signature, truncated file — leaves the previous configuration in force,
/// but the attempt itself is exactly what an investigation wants to see:
/// dropping a rogue JWKS on disk is an attack, not noise.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConfigReload {
    /// Same serde constraint as `Actor::principal_kind`: `Payload` is tagged
    /// with `kind`, so no field here may bear that name.
    pub config_kind: ConfigKind,
    pub status: ReloadStatus,
    /// Version in force AFTER the attempt: the new version when applied, the
    /// previous one — kept — when rejected.
    pub bundle_version: String,
    /// Content hash of the file that was read: the applied bundle, or the
    /// rejected bytes. None when the file could not be read at all.
    pub bundle_hash: Option<Hash>,
    /// Why the file was rejected (status = rejected).
    pub reason: Option<String>,
}

/// The gateway identity key's certificate over an ephemeral session key.
///
/// The two-tier key architecture: a long-lived identity key (in hardware)
/// certifies a session key generated in memory at chain open, and the session
/// key signs every record. This certificate is what lets a verifier trust the
/// session key — it is the chain's first record, sealed like any other, so it
/// cannot be stripped. The `identity_sig` binds the session key to this exact
/// `chain_id` (carried by the record) and this `gateway_id`, so a leaked
/// session key cannot be replayed onto another chain or another gateway.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionCert {
    /// The ephemeral session public key (32-byte ed25519, hex) that signs
    /// every record of this chain in the envelope.
    pub session_pubkey: String,
    /// The identity key that certified it, resolved in the deployment
    /// bundle's active set.
    pub identity_key_id: String,
    /// Gateway identity, bound into the signature.
    pub gateway_id: String,
    pub not_before_ms: i64,
    pub not_after_ms: i64,
    /// Ed25519 signature by the identity key, 64 bytes in hex, over the
    /// canonical encoding of the fields above plus the chain id (see
    /// `crate::origin::session_cert_signing_bytes`).
    pub identity_sig: String,
}

/// Which configuration the reload concerned.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfigKind {
    /// Signed identity bundle: issuer, audience, JWKS, claim mapping.
    IdentityBundle,
    /// Signed policy bundle: Cedar rules and tool catalogue.
    PolicyBundle,
    /// Signed deployment bundle: the active gateway origin keys. Recorded so
    /// "which origin keys did the gateway trust when this chain was written?"
    /// reads from the log, exactly like the JWKS question. Added later, same
    /// rule as the tags above: `config_kind` is encoded as a string, so a new
    /// variant touches no existing hash.
    DeploymentBundle,
}

impl ConfigKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConfigKind::IdentityBundle => "identity_bundle",
            ConfigKind::PolicyBundle => "policy_bundle",
            ConfigKind::DeploymentBundle => "deployment_bundle",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReloadStatus {
    /// New configuration verified and in force.
    Applied,
    /// File refused — bad signature, unreadable — the previous configuration
    /// stays in force.
    Rejected,
}

impl ReloadStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReloadStatus::Applied => "applied",
            ReloadStatus::Rejected => "rejected",
        }
    }
}

impl Record {
    /// Canonical hash of the record.
    ///
    /// This is the only function that defines a record's identity. Any change
    /// to its encoding is a format break: it invalidates already-sealed logs
    /// and requires an explicit migration.
    pub fn hash(&self) -> Hash {
        let mut e = Encoder::new();
        e.u64(self.seq)
            .i64(self.ts_ms)
            .hash(&self.prev_hash)
            .str(&self.id)
            .opt_str(self.parent_id.as_deref())
            .str(&self.session_id);
        self.payload.encode(&mut e);
        digest(domain::RECORD, e.finish())
    }
}
