use audit_core::checkpoint::{PublicKeyEntry, SignedCheckpoint};
use audit_core::evidence::{Evidence, FORMAT as EVIDENCE_FORMAT};
use audit_core::record::*;
use audit_core::{content_hash, ChainWriter};
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use wal::Wal;

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
    pub session_id: String,
    pub agent_record_id: String,
    pub pending: HashMap<String, Pending>,
    /// Call counter, used to build readable identifiers.
    pub counter: u64,
    /// Separate counter for `reload-N` identifiers: reloads are rarer than
    /// calls and sharing the call counter would leave holes in the dec-N /
    /// eff-N pairing an investigator reads by.
    pub reload_counter: u64,
}

impl Session {
    /// Writes a record: chain it, then make it durable in the WAL.
    ///
    /// Order matters. We make it durable **before** the caller forwards the
    /// call to the tool. If the process dies in between, we have a trace of an
    /// act that did not happen — awkward but defensible. The other way round
    /// we would have an act with no trace, which ruins the product.
    pub fn write(
        &mut self,
        id: impl Into<String>,
        parent: Option<String>,
        payload: Payload,
    ) -> Result<Record, wal::Error> {
        let sid = self.session_id.clone();
        let rec = self.chain.append(now_ms(), id, parent, sid, payload);
        self.wal.append(&rec)?;
        Ok(rec)
    }

    pub fn next_call_id(&mut self) -> String {
        self.counter += 1;
        format!("call-{}", self.counter)
    }

    /// Seals whatever is still pending and produces the evidence pack.
    pub fn finish(
        &mut self,
        key_id: &str,
        key: &SigningKey,
    ) -> Result<Evidence, wal::Error> {
        let mut checkpoints: Vec<SignedCheckpoint> = Vec::new();
        if let Some(cp) = self.chain.seal(now_ms(), key_id) {
            checkpoints.push(cp.sign(key));
        }

        Ok(Evidence {
            format: EVIDENCE_FORMAT.to_string(),
            chain_id: self.chain.chain_id().to_string(),
            records: self.wal.read_all()?,
            checkpoints,
            keys: vec![PublicKeyEntry {
                key_id: key_id.to_string(),
                algo: "ed25519".to_string(),
                public_key: hex::encode(key.verifying_key().to_bytes()),
            }],
            anchors: Vec::new(),
        })
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
) -> Result<(), wal::Error> {
    for reload in reloads {
        s.reload_counter += 1;
        let id = format!("reload-{}", s.reload_counter);
        s.write(id, None, Payload::ConfigReload(reload))?;
    }
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
    deleg: &identity::Delegation,
    agent_id: &str,
    bundle_version: &str,
) -> Result<(), wal::Error> {
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
pub fn open(chain: ChainWriter, wal: Wal, session_id: String) -> Session {
    Session {
        chain,
        wal,
        session_id,
        agent_record_id: String::new(),
        pending: HashMap::new(),
        counter: 0,
        reload_counter: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reload_records_chain_outside_the_attribution_tree() {
        let dir = std::env::temp_dir()
            .join(format!("probant-session-reload-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (wal, chain) = Wal::open(&dir, "t").unwrap();
        let mut s = open(chain, wal, "sess".into());

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
