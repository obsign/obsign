use crate::sealer::{sign_checkpoint, Sealer};
use crate::store::Store;
use crate::Error;
use audit_core::checkpoint::{seal_interval, KeyRole, PublicKeyEntry, SignedCheckpoint};
use audit_core::deployment::SignedDeploymentBundle;
use audit_core::evidence::{Evidence, FORMAT};
use audit_core::origin::SignedRecord;
use audit_core::record::Record;
use ed25519_dalek::VerifyingKey;
use std::collections::BTreeMap;

/// Which origin keys this ledger accepts, and how strictly.
///
/// This is the sealer-side half of origin authentication: sealing a record
/// lends it the checkpoint key's authority, so the decision "is this record
/// the gateway's" has to be made *here*, before the signature — afterwards
/// the forgery is indistinguishable from history.
#[derive(Debug)]
pub struct OriginPolicy {
    trusted: BTreeMap<String, VerifyingKey>,
    /// A record without a verifiable signature is refused, not tolerated.
    /// Off during rollout (pre-origin gateways still seal, with a warning
    /// left to the caller); on once every gateway of the deployment signs.
    require: bool,
    /// The ops-signed bundle the trust came from (v1), embedded in the pack
    /// by `export`. `None` for the v0 flat-file path.
    bundle: Option<SignedDeploymentBundle>,
}

impl OriginPolicy {
    /// No origin checking at all: the pre-origin-auth behaviour.
    pub fn permissive() -> Self {
        OriginPolicy {
            trusted: BTreeMap::new(),
            require: false,
            bundle: None,
        }
    }

    /// Builds the trusted set from key entries; non-origin roles are
    /// refused rather than skipped — a sealing key in an origin trust file
    /// is a configuration error worth stopping on, not working around.
    ///
    /// This is the v0 flat-file path, kept for one transition. The v1 entry
    /// point is [`OriginPolicy::from_bundle`].
    pub fn new(entries: &[PublicKeyEntry], require: bool) -> Result<Self, Error> {
        let mut trusted = BTreeMap::new();
        for e in entries {
            if e.role != KeyRole::Origin {
                return Err(Error::StoreBroken(format!(
                    "key \"{}\" has role {} in the trusted origin keys: only \
                     role \"origin\" belongs there",
                    e.key_id,
                    e.role.as_str()
                )));
            }
            trusted.insert(e.key_id.clone(), e.to_verifying_key()?);
        }
        if require && trusted.is_empty() {
            return Err(Error::StoreBroken(
                "origin required but no trusted origin key supplied: every \
                 record would be refused"
                    .to_string(),
            ));
        }
        Ok(OriginPolicy {
            trusted,
            require,
            bundle: None,
        })
    }

    /// v1: resolve the trusted origin set from an ops-signed deployment
    /// bundle. The bundle is verified under `ops_key` — the same root that
    /// signs policy and identity bundles — before any of its keys are
    /// trusted; whoever could forge it could already forge rules. The bundle
    /// is retained so `export` can embed it in the pack, making the pack
    /// self-describing about which origin keys were trusted at seal time.
    pub fn from_bundle(
        signed: &SignedDeploymentBundle,
        ops_key: &VerifyingKey,
        require: bool,
    ) -> Result<Self, Error> {
        let bundle = signed.verify(ops_key)?;
        let trusted = bundle.active_origin_keys()?;
        if require && trusted.is_empty() {
            return Err(Error::StoreBroken(format!(
                "deployment bundle \"{}\" enrolls no gateway but origin is \
                 required: every record would be refused",
                bundle.version
            )));
        }
        Ok(OriginPolicy {
            trusted,
            require,
            bundle: Some(signed.clone()),
        })
    }

    /// The deployment bundle backing this policy, if any — embedded in the
    /// exported pack.
    pub fn bundle(&self) -> Option<&SignedDeploymentBundle> {
        self.bundle.as_ref()
    }

    /// The session keys this chain's certificates authorize, harvested from
    /// the whole chain (the certificate sits at seq 0, so a later pass sealing
    /// a suffix still needs to see it). Each is validated against a trusted
    /// identity key before its session key is trusted — a v2 record then
    /// resolves to a key the identity key vouched for, a v0/v1 record resolves
    /// to a bundle key directly, and the union covers both.
    fn session_keys(
        &self,
        chain_id: &str,
        records: &[SignedRecord],
    ) -> BTreeMap<String, VerifyingKey> {
        let mut m = BTreeMap::new();
        for sr in records {
            if let audit_core::record::Payload::SessionCert(cert) = &sr.record.payload {
                if let Some(id_vk) = self.trusted.get(&cert.identity_key_id) {
                    if let Ok(vk) = audit_core::verify_session_cert(chain_id, cert, id_vk) {
                        m.insert(audit_core::key_id_for(&vk), vk);
                    }
                }
            }
        }
        m
    }

    /// Why this record may not be sealed, or `None` if it may.
    ///
    /// Severity mirrors the offline verifier: an *invalid* signature under a
    /// trusted key is positive evidence of tampering and always refuses; an
    /// *absent or unresolvable* one is an absence of proof, refused only
    /// under `require`. Anything harsher would break mixed-fleet rollouts;
    /// anything softer would seal forgeries. `session` holds the session keys
    /// certified by this chain (see [`session_keys`]).
    fn refusal(
        &self,
        chain_id: &str,
        sr: &SignedRecord,
        session: &BTreeMap<String, VerifyingKey>,
    ) -> Option<String> {
        match (&sr.origin_sig, &sr.origin_key_id) {
            (None, None) => self
                .require
                .then(|| "no origin signature".to_string()),
            (Some(_), Some(kid)) => match self.trusted.get(kid).or_else(|| session.get(kid)) {
                Some(vk) => sr.verify_origin(chain_id, vk).err().map(|e| e.to_string()),
                None => self
                    .require
                    .then(|| format!("origin key \"{kid}\" is not trusted")),
            },
            _ => Some(
                "origin signature and key id must come together; half of the \
                 pair can only be produced by tampering"
                    .to_string(),
            ),
        }
    }
}

/// One sealing pass: seal everything the log holds beyond sealed history.
///
/// `records` comes from `wal::read`, which already validated the chain's
/// internal consistency. What it cannot validate — and what this function
/// exists to catch — is consistency with *sealed history*: a compromised
/// gateway host can rewrite the WAL and recompute every hash, producing a
/// perfectly self-consistent log that is no longer the one the checkpoints
/// certify. The boundary record is therefore re-hashed and compared to the
/// sealed head before anything new is sealed.
///
/// Origin comes next: consistency proves the records agree with each other,
/// the origin signature proves the gateway wrote them. On the first record
/// `origin` refuses, the pass seals the authentic prefix — refusing the
/// whole pass would let an attacker append garbage to *suppress* sealing of
/// honest records, turning a forgery primitive into an anti-durability
/// primitive — then returns [`Error::UnauthenticatedRecord`]. The error is
/// the alarm: the checkpoint over the prefix is already persisted when it
/// is raised.
///
/// `min_new` batches sealing (a checkpoint per record would bloat the store);
/// it is a floor, not a trigger — call this from `run` or cron. An
/// authentic prefix cut short by a refused record seals regardless of the
/// floor: those records' path to proof must not wait on an attacker.
///
/// Returns `Ok(None)` when there is nothing (or not yet enough) to seal.
pub fn seal_pass(
    records: &[SignedRecord],
    store: &mut Store,
    sealer: &dyn Sealer,
    origin: &OriginPolicy,
    now_ms: i64,
    min_new: usize,
) -> Result<Option<SignedCheckpoint>, Error> {
    let unsealed: &[SignedRecord] = match store.last() {
        None => records,
        Some(last) => {
            let sealed_to = last.checkpoint.to_seq;
            let Ok(idx) = records.binary_search_by_key(&sealed_to, |r| r.seq) else {
                return Err(Error::TruncatedLog {
                    log_last: records.last().map(|r| r.seq),
                    sealed_to,
                });
            };
            if records[idx].hash() != last.checkpoint.head_hash {
                return Err(Error::DivergedLog { seq: sealed_to });
            }
            &records[idx + 1..]
        }
    };

    // Session certificates live at the chain top (already sealed on a later
    // pass), so trust is harvested from the whole chain, not just the suffix.
    let session_keys = origin.session_keys(store.chain_id(), records);
    let refused = unsealed
        .iter()
        .find_map(|sr| origin.refusal(store.chain_id(), sr, &session_keys).map(|r| (sr.seq, r)));

    let authentic = match refused {
        None => unsealed,
        Some((seq, _)) => {
            let cut = unsealed.iter().position(|sr| sr.seq == seq).expect("found above");
            &unsealed[..cut]
        }
    };

    let sealed = if authentic.is_empty()
        || (refused.is_none() && authentic.len() < min_new.max(1))
    {
        None
    } else {
        let plain: Vec<Record> = authentic.iter().map(|sr| sr.record.clone()).collect();
        let cp = seal_interval(
            store.chain_id(),
            &plain,
            store.last_hash(),
            now_ms,
            sealer.key_id(),
        )?;
        let signed = sign_checkpoint(cp, sealer)?;
        store.append_checkpoint(signed.clone(), &sealer.public_key())?;
        Some(signed)
    };

    match refused {
        Some((seq, reason)) => Err(Error::UnauthenticatedRecord {
            seq,
            reason,
            prefix_sealed_to: sealed.map(|sc| sc.checkpoint.to_seq),
        }),
        None => Ok(sealed),
    }
}

/// Assembles the evidence pack an auditor receives.
///
/// Assembly, not judgement: the pack is handed to `obsign verify` (or run
/// through `audit_core::evidence::verify` by the caller) for that. An export
/// that filtered or repaired on the way out would be doing exactly what the
/// product exists to make impossible.
///
/// `origin_keys` are appended to the pack's keys the way the sealing keys
/// are: a reading convenience so the pack self-describes, never a substitute
/// for `--trusted-keys` obtained out of band. `deployment` embeds the
/// ops-signed bundle (v1) so the whole origin chain of trust verifies from
/// the ops key alone.
pub fn export(
    records: Vec<SignedRecord>,
    store: &Store,
    origin_keys: &[PublicKeyEntry],
    deployment: Option<SignedDeploymentBundle>,
) -> Evidence {
    let mut keys = store.keys().to_vec();
    keys.extend(origin_keys.iter().cloned());
    Evidence {
        format: FORMAT.to_string(),
        chain_id: store.chain_id().to_string(),
        records,
        checkpoints: store.checkpoints().to_vec(),
        keys,
        anchors: store.anchors().to_vec(),
        deployment,
    }
}
