use crate::origin::OriginSigner;
use obsign_audit_core::record::*;
use obsign_audit_core::{content_hash, origin_signing_bytes, ChainWriter, SignedRecord};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use obsign_wal::Wal;

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A tool call forwarded to the server, awaiting its response.
pub struct Pending {
    pub decision_record_id: String,
    /// Identifier reserved for the effect record, frozen *at call time*.
    ///
    /// It cannot be computed when the response arrives: MCP responses are
    /// asynchronous and come back out of order, so a counter read at that
    /// point has already moved on and two effects get the same identifier.
    /// The integrity chain is unaffected, but the attribution graph becomes
    /// ambiguous — and that is the one an investigation relies on.
    pub effect_record_id: String,
    pub started: Instant,
}

/// Mutable gateway state, shared between the upstream direction (agent to
/// server) and the downstream one (server to agent).
pub struct Session {
    pub chain: ChainWriter,
    pub wal: Wal,
    /// Origin key of this gateway. `None` runs unsigned (legacy, and the
    /// rollout window before every deployment carries a key): the records
    /// are still durable and chained, they just prove consistency, not
    /// authorship.
    pub origin: Option<Arc<dyn OriginSigner>>,
    pub session_id: String,
    pub agent_record_id: String,
    pub pending: HashMap<String, Pending>,
    /// Server-initiated requests (sampling, elicitation) forwarded to the
    /// agent, awaiting the agent's response. A separate map from `pending`:
    /// the two directions use independent JSON-RPC id spaces, and a server
    /// id colliding with an agent id must not close the wrong effect.
    pub pending_to_agent: HashMap<String, Pending>,
    /// Ids of server-initiated machinery requests (`ping`, `roots/list`)
    /// relayed to the agent without arbitration. The agent's reply to one of
    /// these passes like the request did; a "response" matching neither this
    /// set nor `pending_to_agent` is unsolicited — an arbitrary payload
    /// aimed at the server — and is refused. Bounded: past the cap, new
    /// machinery requests still relay but their replies will be refused,
    /// which fails toward refusal, never toward an unarbitrated channel.
    pub relayed_to_agent: HashSet<String>,
    /// Call counter, used to build readable identifiers.
    pub counter: u64,
    /// Separate counter for `reload-N` identifiers: reloads are rarer than
    /// calls and sharing the call counter would leave holes in the dec-N /
    /// eff-N pairing an investigator reads by.
    pub reload_counter: u64,
}

impl Session {
    /// Writes a record: chain it, sign it, then make it durable in the WAL.
    ///
    /// Order matters. We make it durable **before** the caller forwards the
    /// call to the tool. If the process dies in between, we have a trace of an
    /// act that did not happen — awkward but defensible. The other way round
    /// we would have an act with no trace, which ruins the product.
    ///
    /// The origin signature sits between the chain append and the fsync: it
    /// covers the record's final form (`seq` and `prev_hash` are set by the
    /// chain), and a record must never become durable unsigned when the
    /// gateway has a key — the sealer would refuse it later, far from the
    /// cause.
    pub fn write(
        &mut self,
        id: impl Into<String>,
        parent: Option<String>,
        payload: Payload,
    ) -> Result<Record, obsign_wal::Error> {
        let sid = self.session_id.clone();
        let rec = self.chain.append(now_ms(), id, parent, sid, payload);
        let sr = match &self.origin {
            None => SignedRecord::unsigned(rec),
            Some(signer) => {
                let msg = origin_signing_bytes(self.chain.chain_id(), &rec.hash());
                let sig = signer.sign(&msg)?;
                SignedRecord::signed(rec, signer.key_id(), sig)
            }
        };
        self.wal.append(&sr)?;
        Ok(sr.record)
    }

    pub fn next_call_id(&mut self) -> String {
        self.counter += 1;
        format!("call-{}", self.counter)
    }

    /// Closing report, written to stderr on shutdown.
    ///
    /// The gateway does not seal — it must never hold a signing key, or the
    /// key and the log cohabit on one host and the checkpoints certify
    /// whatever that host's attacker rewrites (see the `ledger` crate). Its
    /// job ends when every record is durable in the WAL; the message says
    /// where to point the sealer.
    pub fn closing_report(&self) -> String {
        format!(
            "{} record(s) durable in {} — seal with: obsign-ledger seal \
             --wal <dir> --chain-id {}",
            self.chain.next_seq(),
            self.wal.path().display(),
            self.chain.chain_id(),
        )
    }
}

/// Engraves configuration reloads drained from `Auth::take_reloads`.
///
/// Chain-level events, deliberately outside the attribution tree (no
/// parent): a reload changes what the gateway trusts, whoever the principal
/// of the moment is. Written before the act that triggered them, so "which
/// keys were trusted when this act happened?" reads directly: the last
/// applied `config_reload` — or the opening `agent_session` — above the act.
pub fn record_config_reloads(
    s: &mut Session,
    reloads: Vec<ConfigReload>,
) -> Result<(), obsign_wal::Error> {
    for reload in reloads {
        s.reload_counter += 1;
        let id = format!("reload-{}", s.reload_counter);
        s.write(id, None, Payload::ConfigReload(reload))?;
    }
    Ok(())
}

/// Records the session certificate as the chain's first record.
///
/// Written before anything else, and origin-signed by the very session key it
/// certifies: the envelope signature proves the session key wrote the record,
/// the `identity_sig` inside proves the identity key blessed that session key.
/// From here every record resolves to a key the identity key vouched for.
pub fn record_session_cert(
    s: &mut Session,
    cert: obsign_audit_core::record::SessionCert,
) -> Result<(), obsign_wal::Error> {
    s.write("session-cert", None, Payload::SessionCert(cert))?;
    Ok(())
}

/// Records the deployment bundle in force at the top of the chain.
///
/// A chain-level event with no attribution parent, like a config reload: it
/// says which origin keys the gateway trusted while writing this chain,
/// independent of any principal. Recorded as `Applied` at session open so
/// every pack is self-contained about its origin trust — the in-chain answer
/// to "who could have written these records?".
pub fn record_deployment_bundle(
    s: &mut Session,
    trust: &crate::origin::DeploymentTrust,
) -> Result<(), obsign_wal::Error> {
    s.reload_counter += 1;
    let id = format!("deployment-{}", s.reload_counter);
    s.write(
        id,
        None,
        Payload::ConfigReload(ConfigReload {
            config_kind: ConfigKind::DeploymentBundle,
            status: ReloadStatus::Applied,
            bundle_version: trust.version.clone(),
            bundle_hash: Some(trust.content),
            reason: None,
        }),
    )?;
    Ok(())
}

/// Records a delegation and the opening (or resumption) of an agent session.
///
/// Called at startup, then on every token renewal. Renewing emits a new
/// delegation/agent pair: the authority the agent operates under has changed,
/// and subsequent calls must attach to the new one, not the old. Without
/// this, an act performed under a renewed token would appear authorized by an
/// already-expired delegation.
pub fn record_delegation(
    s: &mut Session,
    generation: u64,
    deleg: &obsign_identity::Delegation,
    agent_id: &str,
    bundle_version: &str,
) -> Result<(), obsign_wal::Error> {
    let deleg_id = format!("deleg-{generation}");
    let agent_rec_id = format!("agent-{generation}");

    s.write(
        deleg_id.clone(),
        None,
        Payload::Delegation(Delegation {
            principal_sub: deleg.subject.clone(),
            principal_issuer: deleg.issuer.clone(),
            scopes: deleg.scopes.clone(),
            expires_at_ms: deleg.expires_at_ms,
            approved_by: None,
            approval_mode: ApprovalMode::Implicit,
        }),
    )?;

    // The actor chain is a separate record, inserted between the delegation
    // and the agent session. An additional type rather than a field added to
    // `Delegation`: changing the encoding of an existing payload would
    // invalidate every already-sealed log.
    let actor_id = format!("actor-{generation}");
    s.write(
        actor_id.clone(),
        Some(deleg_id),
        Payload::Actor(Actor {
            chain: deleg.actor_chain.clone(),
            principal_kind: deleg.kind,
        }),
    )?;

    s.write(
        agent_rec_id.clone(),
        Some(actor_id),
        Payload::AgentSession(AgentSession {
            agent_id: agent_id.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            config_hash: content_hash(bundle_version.as_bytes()),
        }),
    )?;

    s.agent_record_id = agent_rec_id;
    Ok(())
}

/// Opens the session on a given log.
pub fn open(
    chain: ChainWriter,
    wal: Wal,
    session_id: String,
    origin: Option<Arc<dyn OriginSigner>>,
) -> Session {
    Session {
        chain,
        wal,
        origin,
        session_id,
        agent_record_id: String::new(),
        pending: HashMap::new(),
        pending_to_agent: HashMap::new(),
        relayed_to_agent: HashSet::new(),
        counter: 0,
        reload_counter: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_write_is_signed_when_the_session_holds_an_origin_key() {
        let dir = std::env::temp_dir()
            .join(format!("obsign-session-origin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let signer = std::sync::Arc::new(crate::origin::FileOriginSigner::from_seed([3u8; 32]));
        let vk = signer.verifying_key();

        let (wal, chain) = Wal::open(&dir, "t").unwrap();
        let mut s = open(chain, wal, "sess".into(), Some(signer));
        let deleg = obsign_identity::Delegation {
            subject: "u:test".into(),
            issuer: "cli://declared".into(),
            scopes: vec![],
            groups: vec![],
            expires_at_ms: i64::MAX,
            issued_at_ms: None,
            actor_chain: vec!["u:test".into()],
            kind: PrincipalKind::Machine,
        };
        record_delegation(&mut s, 1, &deleg, "agent", "policies@test").unwrap();

        let records = s.wal.read_all().unwrap();
        assert!(!records.is_empty());
        for r in &records {
            r.verify_origin("t", &vk)
                .unwrap_or_else(|e| panic!("record {} unsigned or invalid: {e}", r.id));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reload_records_chain_outside_the_attribution_tree() {
        let dir = std::env::temp_dir()
            .join(format!("obsign-session-reload-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (wal, chain) = Wal::open(&dir, "t").unwrap();
        let mut s = open(chain, wal, "sess".into(), None);

        record_config_reloads(
            &mut s,
            vec![
                ConfigReload {
                    config_kind: ConfigKind::IdentityBundle,
                    status: ReloadStatus::Applied,
                    bundle_version: "identity@2".into(),
                    bundle_hash: Some(content_hash(b"new bundle")),
                    reason: None,
                },
                ConfigReload {
                    config_kind: ConfigKind::IdentityBundle,
                    status: ReloadStatus::Rejected,
                    bundle_version: "identity@2".into(),
                    bundle_hash: None,
                    reason: Some("reading: gone".into()),
                },
            ],
        )
        .unwrap();

        let recs = s.wal.read_all().unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].id, "reload-1");
        assert_eq!(recs[1].id, "reload-2");
        for r in &recs {
            // A reload belongs to the whole chain, not to any principal's
            // attribution tree.
            assert!(r.parent_id.is_none());
            assert!(matches!(r.payload, Payload::ConfigReload(_)));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
