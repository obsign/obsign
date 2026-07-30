//! ECDSA P-256 signature *verification*, and nothing else.
//!
//! Exists for exactly one caller: [`crate::attestation`]. A TPM's attestation
//! key signs quotes and certifies with the algorithms the TPM implements, and
//! the software TPM this tree tests against (swtpm/libtpms 0.10) implements
//! no EdDSA at all — its capability list carries neither `TPM_ALG_EDDSA`
//! (0x0060) nor the 25519 curve (0x0040), and an EdDSA `TPM2_CreatePrimary`
//! fails with `TPM_RC_SCHEME`. Real attestations from such a TPM sign
//! ECDSA-P256, so the offline verifier must check that signature or give up
//! on real hardware.
//!
//! Hand-rolled under the same constraint as the DER and TPM parsers: the
//! auditor-facing dependency list stays readable end to end, so no curve
//! crate. What makes that defensible here is that this is **verification
//! only** — every input is public (a public key, a public signature, a public
//! message), so the side-channel discipline a signer needs does not apply;
//! only correctness does, and correctness is what the known-answer tests and
//! the real-TPM fixtures pin down. No signing half exists to get wrong.
//!
//! Scope: uncompressed points only (the form a TPM emits), SHA-256 digests,
//! raw `r || s` signatures. Everything else is a refusal, not a fallback.

/// 256-bit unsigned integer, four little-endian u64 limbs.
#[derive(Clone, Copy, PartialEq, Eq)]
struct U256([u64; 4]);

impl core::fmt::Debug for U256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for i in (0..4).rev() {
            write!(f, "{:016x}", self.0[i])?;
        }
        Ok(())
    }
}

impl U256 {
    const ZERO: U256 = U256([0; 4]);
    const ONE: U256 = U256([1, 0, 0, 0]);

    fn from_be(b: &[u8; 32]) -> U256 {
        let limb = |i: usize| u64::from_be_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        U256([limb(3), limb(2), limb(1), limb(0)])
    }

    fn is_zero(&self) -> bool {
        *self == U256::ZERO
    }

    /// `self >= other`.
    fn ge(&self, other: &U256) -> bool {
        for i in (0..4).rev() {
            if self.0[i] != other.0[i] {
                return self.0[i] > other.0[i];
            }
        }
        true
    }

    fn bit(&self, i: usize) -> bool {
        (self.0[i / 64] >> (i % 64)) & 1 == 1
    }

    fn add(&self, o: &U256) -> (U256, bool) {
        let mut r = [0u64; 4];
        let mut carry = false;
        for (i, out) in r.iter_mut().enumerate() {
            let (v, c1) = self.0[i].overflowing_add(o.0[i]);
            let (v, c2) = v.overflowing_add(carry as u64);
            *out = v;
            carry = c1 || c2;
        }
        (U256(r), carry)
    }

    fn sub(&self, o: &U256) -> (U256, bool) {
        let mut r = [0u64; 4];
        let mut borrow = false;
        for (i, out) in r.iter_mut().enumerate() {
            let (v, b1) = self.0[i].overflowing_sub(o.0[i]);
            let (v, b2) = v.overflowing_sub(borrow as u64);
            *out = v;
            borrow = b1 || b2;
        }
        (U256(r), borrow)
    }
}

/// Modular arithmetic for one modulus, in Montgomery form (R = 2^256).
/// Both P-256 moduli exceed 2^255, which the constructor relies on.
struct Field {
    m: U256,
    /// `-m^-1 mod 2^64`, the Montgomery reduction factor.
    m0: u64,
    /// `R^2 mod m`, for conversion into Montgomery form.
    r2: U256,
    /// `R mod m` — the Montgomery representation of 1.
    one: U256,
}

impl Field {
    fn new(m: U256) -> Field {
        // Newton's iteration doubles correct low bits each round: six rounds
        // pin all 64. Then negate: mont reduction wants -m^-1.
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m.0[0].wrapping_mul(inv)));
        }
        let m0 = inv.wrapping_neg();
        // m > 2^255, so R mod m = 2^256 - m, computable as 0 - m in 256 bits.
        let one = U256::ZERO.sub(&m).0;
        // R^2 mod m by 256 modular doublings of R mod m.
        let mut r2 = one;
        for _ in 0..256 {
            r2 = mod_add(&r2, &r2, &m);
        }
        Field { m, m0, r2, one }
    }

    fn add(&self, a: &U256, b: &U256) -> U256 {
        mod_add(a, b, &self.m)
    }

    fn sub(&self, a: &U256, b: &U256) -> U256 {
        let (r, borrow) = a.sub(b);
        if borrow {
            r.add(&self.m).0
        } else {
            r
        }
    }

    /// Montgomery product `a * b * R^-1 mod m` (CIOS).
    fn mul(&self, a: &U256, b: &U256) -> U256 {
        let mut t = [0u64; 6];
        for i in 0..4 {
            // t += a[i] * b
            let ai = a.0[i] as u128;
            let mut carry: u128 = 0;
            for (j, &bj) in b.0.iter().enumerate() {
                let v = t[j] as u128 + ai * (bj as u128) + carry;
                t[j] = v as u64;
                carry = v >> 64;
            }
            let v = t[4] as u128 + carry;
            t[4] = v as u64;
            t[5] = (v >> 64) as u64;

            // t = (t + mu * m) / 2^64 — mu chosen so the low limb cancels.
            let mu = (t[0].wrapping_mul(self.m0)) as u128;
            let v = t[0] as u128 + mu * (self.m.0[0] as u128);
            let mut carry = v >> 64;
            for j in 1..4 {
                let v = t[j] as u128 + mu * (self.m.0[j] as u128) + carry;
                t[j - 1] = v as u64;
                carry = v >> 64;
            }
            let v = t[4] as u128 + carry;
            t[3] = v as u64;
            t[4] = t[5] + (v >> 64) as u64;
            t[5] = 0;
        }
        let mut r = U256([t[0], t[1], t[2], t[3]]);
        if t[4] != 0 || r.ge(&self.m) {
            r = r.sub(&self.m).0;
        }
        r
    }

    /// Into Montgomery form.
    fn enter(&self, a: &U256) -> U256 {
        self.mul(a, &self.r2)
    }

    /// Out of Montgomery form.
    fn leave(&self, a: &U256) -> U256 {
        self.mul(a, &U256::ONE)
    }

    /// `base^e` (base in Montgomery form, plain exponent), square-and-multiply.
    fn pow(&self, base: &U256, e: &U256) -> U256 {
        let mut acc = self.one;
        for i in (0..256).rev() {
            acc = self.mul(&acc, &acc);
            if e.bit(i) {
                acc = self.mul(&acc, base);
            }
        }
        acc
    }

    /// Multiplicative inverse by Fermat: `a^(m-2)`. The moduli are prime.
    fn inv(&self, a: &U256) -> U256 {
        let e = self.m.sub(&U256([2, 0, 0, 0])).0;
        self.pow(a, &e)
    }
}

fn mod_add(a: &U256, b: &U256, m: &U256) -> U256 {
    let (r, carry) = a.add(b);
    if carry || r.ge(m) {
        r.sub(m).0
    } else {
        r
    }
}

/// Jacobian point, coordinates in Montgomery form. `z == 0` is infinity.
#[derive(Clone, Copy)]
struct Point {
    x: U256,
    y: U256,
    z: U256,
}

const INFINITY: Point = Point {
    x: U256::ZERO,
    y: U256::ZERO,
    z: U256::ZERO,
};

fn double(fp: &Field, p: &Point) -> Point {
    if p.z.is_zero() {
        return *p;
    }
    let zz = fp.mul(&p.z, &p.z);
    let yy = fp.mul(&p.y, &p.y);
    let xyy = fp.mul(&p.x, &yy);
    let s = {
        let t = fp.add(&xyy, &xyy);
        fp.add(&t, &t) // 4·X·Y²
    };
    // a = -3 lets 3(X² − Z⁴) factor as 3(X − Z²)(X + Z²).
    let m = {
        let t = fp.mul(&fp.sub(&p.x, &zz), &fp.add(&p.x, &zz));
        fp.add(&fp.add(&t, &t), &t)
    };
    let x3 = fp.sub(&fp.sub(&fp.mul(&m, &m), &s), &s);
    let yyyy = fp.mul(&yy, &yy);
    let y8 = {
        let t = fp.add(&yyyy, &yyyy);
        let t = fp.add(&t, &t);
        fp.add(&t, &t) // 8·Y⁴
    };
    let y3 = fp.sub(&fp.mul(&m, &fp.sub(&s, &x3)), &y8);
    let z3 = {
        let t = fp.mul(&p.y, &p.z);
        fp.add(&t, &t)
    };
    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

fn add(fp: &Field, p: &Point, q: &Point) -> Point {
    if p.z.is_zero() {
        return *q;
    }
    if q.z.is_zero() {
        return *p;
    }
    let z1z1 = fp.mul(&p.z, &p.z);
    let z2z2 = fp.mul(&q.z, &q.z);
    let u1 = fp.mul(&p.x, &z2z2);
    let u2 = fp.mul(&q.x, &z1z1);
    let s1 = fp.mul(&fp.mul(&p.y, &q.z), &z2z2);
    let s2 = fp.mul(&fp.mul(&q.y, &p.z), &z1z1);
    let h = fp.sub(&u2, &u1);
    let r = fp.sub(&s2, &s1);
    if h.is_zero() {
        return if r.is_zero() { double(fp, p) } else { INFINITY };
    }
    let h2 = fp.mul(&h, &h);
    let h3 = fp.mul(&h, &h2);
    let u1h2 = fp.mul(&u1, &h2);
    let x3 = fp.sub(&fp.sub(&fp.mul(&r, &r), &h3), &fp.add(&u1h2, &u1h2));
    let y3 = fp.sub(&fp.mul(&r, &fp.sub(&u1h2, &x3)), &fp.mul(&s1, &h3));
    let z3 = fp.mul(&fp.mul(&p.z, &q.z), &h);
    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Plain double-and-add. Not constant-time — the scalar derives entirely
/// from public signature material, there is no secret to leak.
fn scalar_mul(fp: &Field, k: &U256, p: &Point) -> Point {
    let mut acc = INFINITY;
    for i in (0..256).rev() {
        acc = double(fp, &acc);
        if k.bit(i) {
            acc = add(fp, &acc, p);
        }
    }
    acc
}

/// Parses a compile-time hex constant. Only called on the fixed curve
/// parameters below; a malformed constant is a programming error, caught by
/// every test in this module.
fn u256(hex64: &str) -> U256 {
    let raw = hex::decode(hex64).expect("curve constant");
    let arr: [u8; 32] = raw.as_slice().try_into().expect("curve constant length");
    U256::from_be(&arr)
}

// NIST P-256 domain parameters (FIPS 186-4, D.1.2.3).
const P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
const N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
const B: &str = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
const GX: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
const GY: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

/// Verifies an ECDSA-P256 signature over a SHA-256 digest.
///
/// * `public` — the uncompressed point, `0x04 || x || y`, 65 bytes: the form
///   a TPM's `TPMS_ECC_POINT` flattens to.
/// * `digest` — SHA-256 of the signed message (a TPM signs the digest of the
///   marshalled `TPMS_ATTEST`).
/// * `sig` — raw `r || s`, each 32 bytes big-endian.
///
/// Returns `true` only for a well-formed key on the curve and a signature
/// that verifies; every malformation is a `false`, never a panic.
pub fn verify_ecdsa_p256(public: &[u8], digest: &[u8; 32], sig: &[u8; 64]) -> bool {
    if public.len() != 65 || public[0] != 0x04 {
        return false;
    }
    let fp = Field::new(u256(P));
    let fx = Field::new(u256(N));
    let p_mod = u256(P);
    let n_mod = u256(N);

    let qx = U256::from_be(public[1..33].try_into().expect("checked length"));
    let qy = U256::from_be(public[33..65].try_into().expect("checked length"));
    if qx.ge(&p_mod) || qy.ge(&p_mod) {
        return false;
    }
    let qxm = fp.enter(&qx);
    let qym = fp.enter(&qy);
    // On-curve check: y² == x³ − 3x + b.
    let rhs = {
        let x3 = fp.mul(&fp.mul(&qxm, &qxm), &qxm);
        let three_x = fp.add(&fp.add(&qxm, &qxm), &qxm);
        fp.add(&fp.sub(&x3, &three_x), &fp.enter(&u256(B)))
    };
    if fp.mul(&qym, &qym) != rhs {
        return false;
    }

    let r = U256::from_be(sig[..32].try_into().expect("checked length"));
    let s = U256::from_be(sig[32..].try_into().expect("checked length"));
    if r.is_zero() || s.is_zero() || r.ge(&n_mod) || s.ge(&n_mod) {
        return false;
    }

    // e = digest as integer, reduced mod n (one subtraction: e < 2n).
    let mut e = U256::from_be(digest);
    if e.ge(&n_mod) {
        e = e.sub(&n_mod).0;
    }

    let w = fx.inv(&fx.enter(&s));
    let u1 = fx.leave(&fx.mul(&fx.enter(&e), &w));
    let u2 = fx.leave(&fx.mul(&fx.enter(&r), &w));

    let g = Point {
        x: fp.enter(&u256(GX)),
        y: fp.enter(&u256(GY)),
        z: fp.one,
    };
    let q = Point {
        x: qxm,
        y: qym,
        z: fp.one,
    };
    let sum = add(&fp, &scalar_mul(&fp, &u1, &g), &scalar_mul(&fp, &u2, &q));
    if sum.z.is_zero() {
        return false;
    }

    // Affine x = X / Z², then compare mod n.
    let zinv = fp.inv(&sum.z);
    let x_aff = fp.leave(&fp.mul(&sum.x, &fp.mul(&zinv, &zinv)));
    let mut v = x_aff;
    if v.ge(&n_mod) {
        v = v.sub(&n_mod).0;
    }
    v == r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;

    /// Known-answer vector produced with OpenSSL (`openssl dgst -sha256
    /// -sign` over the message below, key generated with `openssl ecparam
    /// -name prime256v1`), cross-verified with `openssl dgst -verify` before
    /// being embedded here.
    const KAT_QX: &str = "96701b4243646dd8521884decec66a02f340eb129e1d55ca9e8350c79f21ec6c";
    const KAT_QY: &str = "2fea23acb6e8d354ccaa238b30b4e66ed261e50582e687e2ad4e1d868a8d49e2";
    const KAT_R: &str = "a61d38170e78329d947c6b1e39b4cffb315f80cbf51a3b1790937be909ab6e54";
    const KAT_S: &str = "4278f5bf8517541c9c4590b762086c03de93edd93892ddd6a66a3c0d364a3779";
    const KAT_MSG: &[u8] = b"probant p256 known-answer message";

    fn kat() -> (Vec<u8>, [u8; 32], [u8; 64]) {
        let mut public = vec![0x04];
        public.extend_from_slice(&hex::decode(KAT_QX).unwrap());
        public.extend_from_slice(&hex::decode(KAT_QY).unwrap());
        let digest: [u8; 32] = *sha256(KAT_MSG).as_bytes();
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&hex::decode(KAT_R).unwrap());
        sig[32..].copy_from_slice(&hex::decode(KAT_S).unwrap());
        (public, digest, sig)
    }

    #[test]
    fn openssl_known_answer_verifies() {
        let (public, digest, sig) = kat();
        assert!(verify_ecdsa_p256(&public, &digest, &sig));
    }

    #[test]
    fn every_corrupted_signature_byte_is_rejected() {
        let (public, digest, sig) = kat();
        for i in 0..64 {
            let mut bad = sig;
            bad[i] ^= 0x01;
            assert!(
                !verify_ecdsa_p256(&public, &digest, &bad),
                "corruption at signature byte {i} still verified"
            );
        }
    }

    #[test]
    fn a_different_message_is_rejected() {
        let (public, _, sig) = kat();
        let digest: [u8; 32] = *sha256(b"a different message").as_bytes();
        assert!(!verify_ecdsa_p256(&public, &digest, &sig));
    }

    #[test]
    fn zero_and_out_of_range_scalars_are_rejected() {
        let (public, digest, sig) = kat();
        let mut zero_r = sig;
        zero_r[..32].fill(0);
        assert!(!verify_ecdsa_p256(&public, &digest, &zero_r));
        let mut zero_s = sig;
        zero_s[32..].fill(0);
        assert!(!verify_ecdsa_p256(&public, &digest, &zero_s));
        let mut huge_s = sig;
        huge_s[32..].fill(0xFF); // >= n
        assert!(!verify_ecdsa_p256(&public, &digest, &huge_s));
    }

    #[test]
    fn a_point_off_the_curve_is_rejected() {
        let (mut public, digest, sig) = kat();
        public[64] ^= 0x01; // bend y: no longer a curve point
        assert!(!verify_ecdsa_p256(&public, &digest, &sig));
    }

    #[test]
    fn malformed_key_encodings_are_rejected() {
        let (public, digest, sig) = kat();
        assert!(!verify_ecdsa_p256(&public[..64], &digest, &sig));
        assert!(!verify_ecdsa_p256(&[], &digest, &sig));
        let mut compressed = public.clone();
        compressed[0] = 0x02;
        assert!(!verify_ecdsa_p256(&compressed, &digest, &sig));
    }
}

#[cfg(test)]
mod arithmetic_tests {
    //! Pins the arithmetic core independently of full signatures, so a
    //! future regression names the broken layer, not just "bad signature".

    use super::*;

    #[test]
    fn montgomery_field_arithmetic_holds() {
        let fp = Field::new(u256(P));
        let a = u256(GX);
        assert_eq!(fp.leave(&fp.enter(&a)), a, "mont roundtrip");
        assert_eq!(fp.enter(&U256::ONE), fp.one, "representation of one");
        let am = fp.enter(&a);
        assert_eq!(fp.pow(&am, &U256::ONE), am, "pow by one");
        assert_eq!(
            fp.pow(&am, &U256([2, 0, 0, 0])),
            fp.mul(&am, &am),
            "pow by two"
        );
        // Fermat's little theorem: a^(p-1) == 1, 256 squarings deep — the
        // whole multiplier is exercised, not just its friendly corners.
        let e = fp.m.sub(&U256::ONE).0;
        assert_eq!(fp.pow(&am, &e), fp.one, "fermat");
        assert_eq!(fp.mul(&am, &fp.inv(&am)), fp.one, "inverse");
    }

    #[test]
    fn the_group_law_reproduces_2g() {
        let fp = Field::new(u256(P));
        let g = Point {
            x: fp.enter(&u256(GX)),
            y: fp.enter(&u256(GY)),
            z: fp.one,
        };
        // x(2G), a published curve test value.
        let want = u256("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978");
        let affine_x = |p: &Point| {
            let zinv = fp.inv(&p.z);
            fp.leave(&fp.mul(&p.x, &fp.mul(&zinv, &zinv)))
        };
        assert_eq!(affine_x(&double(&fp, &g)), want, "double");
        assert_eq!(
            affine_x(&scalar_mul(&fp, &U256([2, 0, 0, 0]), &g)),
            want,
            "scalar mul"
        );
        // add(G, G) hits the h == 0, r == 0 branch and must agree.
        assert_eq!(affine_x(&add(&fp, &g, &g)), want, "add of equal points");
        // G + (-G) is infinity.
        let neg_g = Point {
            x: g.x,
            y: fp.sub(&U256::ZERO, &g.y),
            z: fp.one,
        };
        assert!(
            add(&fp, &g, &neg_g).z.is_zero(),
            "opposite points sum to infinity"
        );
    }
}
