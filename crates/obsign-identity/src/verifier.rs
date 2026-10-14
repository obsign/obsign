use obsign_audit_core::record::PrincipalKind;
use jsonwebtoken::{decode, decode_header, Validation};
use serde_json::Value;

use crate::bundle::IdentityBundle;
use crate::claims::{actor_chain, ClaimMap};
use crate::jwks::KeyStore;
use crate::Error;

/// A proven delegation: what a human actually granted to an agent.
#[derive(Debug, Clone, PartialEq)]
pub struct Delegation {
    /// Principal on whose behalf we act.
    pub subject: String,
    /// Verified issuer. This is the field that distinguishes, in the log, a
    /// proven identity from a declared one: a value of `cli://declared`
    /// immediately tells the auditor that nothing was verified.
    pub issuer: String,
    pub scopes: Vec<String>,
    pub groups: Vec<String>,
    pub expires_at_ms: i64,
    pub issued_at_ms: Option<i64>,
    /// From outermost (the one acting) to innermost (the original
    /// principal). Always at least one element.
    pub actor_chain: Vec<String>,
    pub kind: PrincipalKind,
    /// Display name for `subject`, with the claim it was read from. `None`
    /// when the token carries none: a subject with no readable name is
    /// recorded as it is, never invented.
    pub label: Option<(String, String)>,
}

impl Delegation {
    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_at_ms
    }

    /// Remaining lifetime in seconds, negative once expired.
    pub fn remaining_secs(&self, now_ms: i64) -> i64 {
        (self.expires_at_ms - now_ms) / 1000
    }

    /// Number of delegation hops. 0 for a token without `act`.
    pub fn delegation_depth(&self) -> usize {
        self.actor_chain.len().saturating_sub(1)
    }

    /// True when an identifiable human sits at the root of the chain.
    pub fn has_human(&self) -> bool {
        self.kind.has_human()
    }
}

pub struct Verifier {
    keys: KeyStore,
    issuer: String,
    audience: String,
    claims: ClaimMap,
    /// Clock tolerance, in seconds.
    leeway: u64,
}

impl Verifier {
    pub fn new(keys: KeyStore, issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Verifier {
            keys,
            issuer: issuer.into(),
            audience: audience.into(),
            claims: ClaimMap::default(),
            // Clocks drift, especially air-gapped where NTP is often absent.
            // 60 s is the usual tolerance; beyond that we would accept
            // genuinely stale tokens.
            leeway: 60,
        }
    }

    /// Builds the verifier from an **already verified** bundle.
    pub fn from_bundle(bundle: &IdentityBundle) -> Result<Self, Error> {
        Ok(Verifier {
            keys: KeyStore::from_set(&bundle.jwks)?,
            issuer: bundle.issuer.clone(),
            audience: bundle.audience.clone(),
            claims: bundle.claims.clone(),
            leeway: 60,
        })
    }

    pub fn with_claims(mut self, claims: ClaimMap) -> Self {
        self.claims = claims;
        self
    }

    pub fn with_leeway(mut self, secs: u64) -> Self {
        self.leeway = secs;
        self
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Verifies a token and extracts the delegation from it.
    ///
    /// Checks, in this order: presence of `kid`, existence of the key,
    /// signature, issuer, audience, expiry. None of these steps is optional.
    /// Verifying the signature without verifying the audience lets through a
    /// valid token issued for another service.
    ///
    /// Each of `exp`, `iss` and `aud` must be present *and* well typed: a
    /// claim jsonwebtoken cannot parse is indistinguishable from an absent
    /// one, and an absent one skips its own check. See the comment on
    /// `set_required_spec_claims` below -- that line carries the audience
    /// check, it does not restate the two above it.
    pub fn verify(&self, token: &str) -> Result<Delegation, Error> {
        let header = decode_header(token)?;
        let kid = header.kid.ok_or(Error::MissingKid)?;
        let (key, alg) = self.keys.get(&kid)?;

        // The algorithm comes from the JWKS, not from the token header.
        // Trusting `header.alg` is the classic JWT flaw: an attacker declares
        // whichever algorithm suits them.
        let mut validation = Validation::new(*alg);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        // Not redundant with the two lines above, and not decoration.
        // jsonwebtoken ends its `aud` match on a catch-all: an audience that
        // is absent *or carries the wrong JSON type* falls through it and has
        // its check skipped in silence. Naming the claim here is the only
        // thing that turns "absent or unparseable" into a refusal, because
        // the required-claims loop tests for a parsed value and nothing else.
        // Without this line a token minted by the same trusted issuer for
        // another service is accepted -- precisely what the doc comment on
        // this function says must never happen.
        //
        // Still true on 11.1.0, and checked by two tests at the bottom of
        // tests/jwt.rs. CVE-2026-25537 (fixed in 10.3.0) covered the
        // time-based claims; the audience behaviour described above is not
        // part of that fix and did not change with it.
        //
        // `iss` is named for symmetry and for the absent case. A mistyped one
        // would be caught a few lines down anyway, where the issuer is read
        // back as a string -- but relying on that would make the refusal a
        // side effect of needing the value, which is not a property to rest
        // an authorization decision on.
        //
        // `sub` is deliberately absent: the subject path is configurable
        // through the signed `ClaimMap`, and a deployment reading it from
        // `/oid` carries no `sub` to require. `verify` demands a subject of
        // its own accord a few lines down.
        //
        // `nbf` is absent for a different reason: requiring it would reject
        // every provider that does not emit it, which is most of them. A
        // mistyped one is refused by jsonwebtoken itself since 10.3.0
        // (`InvalidClaimFormat`), which is the half of CVE-2026-25537 that
        // the upgrade did close; tests/jwt.rs pins that, so a regression in a
        // future release reopens as a red test rather than as a bypass.
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = self.leeway;

        // Decoded into a `Value` rather than a typed struct: the shape of the
        // claims depends on the provider, and `ClaimMap` is what knows where
        // to look.
        let data = decode::<Value>(token, key, &validation)?;
        let claims = data.claims;

        let subject = self.claims.subject(&claims).ok_or(Error::MissingSubject)?;
        let issuer = claims
            .get("iss")
            .and_then(Value::as_str)
            .ok_or(Error::MissingSubject)?
            .to_string();
        // jsonwebtoken has already validated expiry, but we need the value to
        // re-evaluate it on every act.
        let exp = claims
            .get("exp")
            .and_then(Value::as_i64)
            .ok_or(Error::MissingExpiry)?;

        let scopes = self.claims.scopes(&claims);
        if scopes.is_empty() {
            // A token with no scope would only authorize tools requiring no
            // scope. That is nearly always a configuration mistake, or a
            // claim mapping pointing at the wrong place. Better to fail loudly
            // than to let an agent run with empty permissions.
            return Err(Error::NoScopes);
        }

        let client_id = self.claims.client_id(&claims);
        let (actor_chain, kind) =
            actor_chain(&claims, &subject, client_id.as_deref(), &self.claims.machine);

        let label = self.claims.label(&claims);

        Ok(Delegation {
            subject,
            issuer,
            scopes,
            groups: self.claims.groups(&claims),
            expires_at_ms: exp * 1000,
            issued_at_ms: claims.get("iat").and_then(Value::as_i64).map(|i| i * 1000),
            actor_chain,
            kind,
            label,
        })
    }
}
