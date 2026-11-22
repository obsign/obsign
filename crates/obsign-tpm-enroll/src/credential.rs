//! `TPM2_MakeCredential`, computed in software on the ops side.
//!
//! The ops side holds no TPM of its own: what it needs is to encrypt a
//! credential so that only the TPM holding a given EK, *and* a loaded object
//! with a given Name, can recover it with `TPM2_ActivateCredential`. That is
//! public-key encryption to the EK plus symmetric wrapping keyed on the AK's
//! Name, TPM 2.0 Part 1, §24 (credential protection) and Annex B.10.4 (RSA
//! secret sharing), done here in software exactly as go-tpm's
//! `credactivation.Generate` and tpm2-tools' `makecredential -T none` do.
//!
//! The steps, for an RSA EK with SHA-256 names and AES-128-CFB storage
//! parameters (the TCG default template L-1, the only shape accepted):
//!
//! 1. a random 32-byte `seed`, RSA-OAEP(SHA-256) encrypted to the EK under
//!    the label `"IDENTITY\0"`: the `secret` the TPM decrypts;
//! 2. `symKey = KDFa(seed, "STORAGE", AK Name)`, 128 bits, encrypts the
//!    marshalled `TPM2B_DIGEST(credential)` in CFB mode with a zero IV;
//! 3. `hmacKey = KDFa(seed, "INTEGRITY")`, 256 bits, MACs the ciphertext
//!    and the AK Name: the TPM recomputes it with the Name of the object it
//!    was handed, so a credential made for another AK fails its integrity
//!    check (`TPM_RC_INTEGRITY`) rather than decrypting.
//!
//! Hand-rolled, like the TPM marshalling and the audit-core P-256: the
//! primitives needed are small (AES-128 encryption only, HMAC over the
//! workspace's SHA-256, one RSA public-exponent operation) and adding a
//! crypto stack for them would put more in the tree than it removes. The
//! one secret here is the seed, used once and never stored; the RSA
//! operation is on public values plus that seed, on the ops host, and the
//! credential it protects is released after the exchange anyway (see
//! `obsign_audit_core::attestation::Activation::secret`). Correctness is
//! pinned by FIPS-197, SP 800-38A and RFC 4231 known answers below, and end
//! to end by a real `TPM2_ActivateCredential` in the swtpm test.

use sha2::{Digest, Sha256};

/// `TPM2_MakeCredential`'s two outputs, as the TPM expects them in
/// `TPM2_ActivateCredential`: the contents of `TPM2B_ID_OBJECT` and of
/// `TPM2B_ENCRYPTED_SECRET` (each without its own size prefix).
pub struct MadeCredential {
    pub credential_blob: Vec<u8>,
    pub encrypted_secret: Vec<u8>,
}

/// Makes a credential for the object named `ak_name` (`alg || digest`),
/// encrypted to the RSA-2048 EK whose modulus is `ek_modulus` (exponent
/// 65537). `credential` must fit a `TPM2B_DIGEST` (at most 32 bytes here).
pub fn make_credential(
    ek_modulus: &[u8],
    ak_name: &[u8],
    credential: &[u8],
) -> Result<MadeCredential, crate::Error> {
    let seed = random32()?;
    let oaep_seed = random32()?;
    make_credential_with(ek_modulus, ak_name, credential, &seed, &oaep_seed)
}

/// 32 bytes from the OS RNG.
pub fn random32() -> Result<[u8; 32], crate::Error> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| crate::Error::Unsupported(format!("no randomness: {e}")))?;
    Ok(b)
}

/// [`make_credential`] with the randomness supplied, for known-answer tests.
fn make_credential_with(
    ek_modulus: &[u8],
    ak_name: &[u8],
    credential: &[u8],
    seed: &[u8; 32],
    oaep_seed: &[u8; 32],
) -> Result<MadeCredential, crate::Error> {
    if ek_modulus.len() != 256 || ek_modulus[0] & 0x80 == 0 {
        return Err(crate::Error::Unsupported(
            "the EK modulus is not a 2048-bit RSA modulus".into(),
        ));
    }
    if credential.len() > 32 {
        return Err(crate::Error::Unsupported(
            "a credential is at most one SHA-256 digest long".into(),
        ));
    }
    let em = oaep_encode(seed, b"IDENTITY\0", oaep_seed);
    let encrypted_secret = rsa_public(ek_modulus, &em);

    let sym_key = kdfa(seed, b"STORAGE", ak_name, &[], 16);
    let mut plain = (credential.len() as u16).to_be_bytes().to_vec(); // TPM2B_DIGEST
    plain.extend_from_slice(credential);
    let enc_identity = aes128_cfb_encrypt(&sym_key.try_into().expect("16 bytes"), &plain);

    let hmac_key = kdfa(seed, b"INTEGRITY", &[], &[], 32);
    let integrity = hmac_sha256(&hmac_key, &[&enc_identity[..], ak_name].concat());

    let mut credential_blob = (integrity.len() as u16).to_be_bytes().to_vec(); // TPM2B_DIGEST
    credential_blob.extend_from_slice(&integrity);
    credential_blob.extend_from_slice(&enc_identity);
    Ok(MadeCredential {
        credential_blob,
        encrypted_secret,
    })
}

/// HMAC-SHA-256 (RFC 2104).
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5C));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// KDFa with SHA-256 (TPM 2.0 Part 1, §11.4.10.2), `len` bytes: counter
/// mode over HMAC, `[i] || label || 0x00 || contextU || contextV || [bits]`.
fn kdfa(key: &[u8], label: &[u8], context_u: &[u8], context_v: &[u8], len: usize) -> Vec<u8> {
    let bits = (len as u32 * 8).to_be_bytes();
    let mut out = Vec::new();
    let mut i = 1u32;
    while out.len() < len {
        let mut m = i.to_be_bytes().to_vec();
        m.extend_from_slice(label);
        m.push(0);
        m.extend_from_slice(context_u);
        m.extend_from_slice(context_v);
        m.extend_from_slice(&bits);
        out.extend_from_slice(&hmac_sha256(key, &m));
        i += 1;
    }
    out.truncate(len);
    out
}

/// MGF1 with SHA-256 (RFC 8017, B.2.1).
fn mgf1(seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter = 0u32;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(seed);
        h.update(counter.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

/// EME-OAEP encoding for a 2048-bit modulus with SHA-256 (RFC 8017,
/// 7.1.1 step 2): `0x00 || maskedSeed || maskedDB`.
fn oaep_encode(msg: &[u8], label: &[u8], seed: &[u8; 32]) -> [u8; 256] {
    const K: usize = 256;
    const H: usize = 32;
    let mut db = vec![0u8; K - H - 1];
    db[..H].copy_from_slice(&Sha256::digest(label));
    let one = K - H - 1 - msg.len() - 1;
    db[one] = 0x01;
    db[one + 1..].copy_from_slice(msg);
    for (d, m) in db.iter_mut().zip(mgf1(seed, K - H - 1)) {
        *d ^= m;
    }
    let mut masked_seed = *seed;
    for (s, m) in masked_seed.iter_mut().zip(mgf1(&db, H)) {
        *s ^= m;
    }
    let mut em = [0u8; K];
    em[1..1 + H].copy_from_slice(&masked_seed);
    em[1 + H..].copy_from_slice(&db);
    em
}

/// `m^65537 mod n`, big-endian in and out, output padded to the modulus
/// length. The one RSA operation the credential needs; schoolbook
/// arithmetic on 32-bit limbs, which is plenty for one call per enrollment.
fn rsa_public(n_be: &[u8], m: &[u8]) -> Vec<u8> {
    let n = Big::from_be(n_be);
    let m = Big::from_be(m);
    let mut r = m.clone();
    for _ in 0..16 {
        r = r.mul_mod(&r, &n);
    }
    r.mul_mod(&m, &n).to_be(n_be.len())
}

/// Little-endian 32-bit limbs.
#[derive(Clone)]
struct Big(Vec<u32>);

impl Big {
    fn from_be(b: &[u8]) -> Big {
        let mut limbs = vec![0u32; b.len().div_ceil(4)];
        for (i, byte) in b.iter().rev().enumerate() {
            limbs[i / 4] |= (*byte as u32) << (8 * (i % 4));
        }
        Big(limbs)
    }

    fn to_be(&self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        for (i, o) in out.iter_mut().rev().enumerate() {
            let limb = self.0.get(i / 4).copied().unwrap_or(0);
            *o = (limb >> (8 * (i % 4))) as u8;
        }
        out
    }

    /// `self * other mod n`: the full product, then a bit-serial long
    /// division keeping only the remainder.
    fn mul_mod(&self, other: &Big, n: &Big) -> Big {
        let mut prod = vec![0u32; self.0.len() + other.0.len()];
        for (i, &a) in self.0.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &b) in other.0.iter().enumerate() {
                let t = prod[i + j] as u64 + a as u64 * b as u64 + carry;
                prod[i + j] = t as u32;
                carry = t >> 32;
            }
            prod[i + other.0.len()] = carry as u32;
        }
        // r stays below 2n, so one extra limb holds it.
        let mut r = vec![0u32; n.0.len() + 1];
        for bit in (0..prod.len() * 32).rev() {
            let mut carry = (prod[bit / 32] >> (bit % 32)) & 1;
            for limb in r.iter_mut() {
                let next = *limb >> 31;
                *limb = (*limb << 1) | carry;
                carry = next;
            }
            if !less_than(&r, &n.0) {
                let mut borrow = 0i64;
                for (i, limb) in r.iter_mut().enumerate() {
                    let t = *limb as i64 - n.0.get(i).copied().unwrap_or(0) as i64 - borrow;
                    *limb = t as u32;
                    borrow = (t < 0) as i64;
                }
            }
        }
        r.truncate(n.0.len());
        Big(r)
    }
}

/// `a < b` over little-endian limbs of possibly different lengths.
fn less_than(a: &[u32], b: &[u32]) -> bool {
    for i in (0..a.len().max(b.len())).rev() {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x < y;
        }
    }
    false
}

/// AES-128 in CFB-128 mode with a zero IV, encryption (SP 800-38A, 6.3),
/// the mode the EK's storage parameters name. A short final block uses a
/// truncated keystream.
fn aes128_cfb_encrypt(key: &[u8; 16], plain: &[u8]) -> Vec<u8> {
    let round_keys = aes128_expand(key);
    let mut feedback = [0u8; 16];
    let mut out = Vec::with_capacity(plain.len());
    for chunk in plain.chunks(16) {
        let ks = aes128_encrypt_block(&round_keys, &feedback);
        let c: Vec<u8> = chunk.iter().zip(ks).map(|(p, k)| p ^ k).collect();
        feedback[..c.len()].copy_from_slice(&c);
        out.extend_from_slice(&c);
    }
    out
}

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// FIPS-197 §5.2 key expansion for a 128-bit key: 11 round keys.
fn aes128_expand(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut w = [[0u8; 4]; 44];
    for i in 0..4 {
        w[i].copy_from_slice(&key[4 * i..4 * i + 4]);
    }
    let mut rcon = 1u8;
    for i in 4..44 {
        let mut t = w[i - 1];
        if i % 4 == 0 {
            t = [SBOX[t[1] as usize] ^ rcon, SBOX[t[2] as usize], SBOX[t[3] as usize], SBOX[t[0] as usize]];
            rcon = xtime(rcon);
        }
        for j in 0..4 {
            w[i][j] = w[i - 4][j] ^ t[j];
        }
    }
    let mut rk = [[0u8; 16]; 11];
    for (r, k) in rk.iter_mut().enumerate() {
        for c in 0..4 {
            k[4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
        }
    }
    rk
}

fn xtime(b: u8) -> u8 {
    (b << 1) ^ if b & 0x80 != 0 { 0x1B } else { 0 }
}

/// One AES-128 block encryption (FIPS-197 §5.1). The state is column-major,
/// byte `4c + r` at row r, column c, as the input bytes arrive.
fn aes128_encrypt_block(rk: &[[u8; 16]; 11], block: &[u8; 16]) -> [u8; 16] {
    let mut s = *block;
    let add = |s: &mut [u8; 16], k: &[u8; 16]| s.iter_mut().zip(k).for_each(|(a, b)| *a ^= b);
    add(&mut s, &rk[0]);
    for (round, key) in rk.iter().enumerate().skip(1) {
        for b in s.iter_mut() {
            *b = SBOX[*b as usize];
        }
        // ShiftRows: row r rotates left by r columns.
        let t = s;
        for c in 0..4 {
            for r in 0..4 {
                s[4 * c + r] = t[4 * ((c + r) % 4) + r];
            }
        }
        if round != 10 {
            // MixColumns, as 2a ^ 3b ^ c ^ d per output byte.
            for c in 0..4 {
                let col = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
                let all = col[0] ^ col[1] ^ col[2] ^ col[3];
                for r in 0..4 {
                    s[4 * c + r] = col[r] ^ all ^ xtime(col[r] ^ col[(r + 1) % 4]);
                }
            }
        }
        add(&mut s, key);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn aes128_matches_fips_197() {
        // FIPS-197, Appendix C.1.
        let key: [u8; 16] = h("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let pt: [u8; 16] = h("00112233445566778899aabbccddeeff").try_into().unwrap();
        let ct = aes128_encrypt_block(&aes128_expand(&key), &pt);
        assert_eq!(hex::encode(ct), "69c4e0d86a7b0430d8cdb78070b4c55a");
    }

    #[test]
    fn cfb128_matches_sp_800_38a() {
        // SP 800-38A, F.3.13 (CFB128-AES128.Encrypt), run block by block
        // with the vector's IV: keystream 1 = E(IV), keystream 2 = E(C1).
        let key: [u8; 16] = h("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
        let rk = aes128_expand(&key);
        let iv: [u8; 16] = h("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let p1 = h("6bc1bee22e409f96e93d7e117393172a");
        let ks1 = aes128_encrypt_block(&rk, &iv);
        let c1: Vec<u8> = p1.iter().zip(ks1).map(|(p, k)| p ^ k).collect();
        assert_eq!(hex::encode(&c1), "3b3fd92eb72dad20333449f8e83cfb4a");
        let p2 = h("ae2d8a571e03ac9c9eb76fac45af8e51");
        let ks2 = aes128_encrypt_block(&rk, &c1.clone().try_into().unwrap());
        let c2: Vec<u8> = p2.iter().zip(ks2).map(|(p, k)| p ^ k).collect();
        assert_eq!(hex::encode(&c2), "c8a64537a0b3a93fcde3cdad9f1ce58b");

        // The mode function (whose IV is always zero, as the credential
        // protocol fixes it) follows the same chain, short final block
        // included.
        let plain = [p1.clone(), p2.clone(), vec![0xAB; 5]].concat();
        let out = aes128_cfb_encrypt(&key, &plain);
        let z1 = aes128_encrypt_block(&rk, &[0u8; 16]);
        let e1: Vec<u8> = p1.iter().zip(z1).map(|(p, k)| p ^ k).collect();
        assert_eq!(&out[..16], &e1[..]);
        let z2 = aes128_encrypt_block(&rk, &e1.clone().try_into().unwrap());
        let e2: Vec<u8> = p2.iter().zip(z2).map(|(p, k)| p ^ k).collect();
        assert_eq!(&out[16..32], &e2[..]);
        assert_eq!(out.len(), 37);
    }

    #[test]
    fn hmac_matches_rfc_4231() {
        // RFC 4231, test cases 2 and 6 (key longer than the block).
        assert_eq!(
            hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex::encode(hmac_sha256(
                &[0xAA; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn kdfa_is_counter_mode_hmac() {
        // One block, by the definition: HMAC(key, [1] || label || 0 || u || v || [bits]).
        let k = kdfa(b"key", b"STORAGE", b"name", &[], 16);
        let mut m = 1u32.to_be_bytes().to_vec();
        m.extend_from_slice(b"STORAGE\0name");
        m.extend_from_slice(&128u32.to_be_bytes());
        assert_eq!(k, hmac_sha256(b"key", &m)[..16]);
        // Longer outputs chain counters 1, 2, ...
        let long = kdfa(b"key", b"INTEGRITY", &[], &[], 40);
        let mut m2 = 2u32.to_be_bytes().to_vec();
        m2.extend_from_slice(b"INTEGRITY\0");
        m2.extend_from_slice(&320u32.to_be_bytes());
        assert_eq!(&long[32..], &hmac_sha256(b"key", &m2)[..8]);
    }

    #[test]
    fn rsa_public_matches_small_known_answers() {
        // n = 61 * 53 = 3233, and 65537 = 17 mod lcm(60, 52) = 780, so
        // 65^65537 = 65^17 = 2790 mod 3233.
        let n = 3233u16.to_be_bytes();
        let c = rsa_public(&n, &65u16.to_be_bytes());
        assert_eq!(u16::from_be_bytes(c.try_into().unwrap()), 2790);
        // A full-width modulus: the result is reduced and padded.
        let mut n = vec![0xFFu8; 256];
        n[255] = 0xF1;
        let one = rsa_public(&n, &[1]);
        assert_eq!(one.len(), 256);
        assert_eq!(one[255], 1);
        assert!(one[..255].iter().all(|b| *b == 0));
    }

    #[test]
    fn oaep_encoding_unmasks_to_the_message() {
        // Decoded by hand per RFC 8017 7.1.2 step 3: the encoding is what
        // the TPM's decryption will unwrap.
        let msg = [0x5Au8; 32];
        let em = oaep_encode(&msg, b"IDENTITY\0", &[0x77; 32]);
        assert_eq!(em[0], 0);
        let (masked_seed, masked_db) = em[1..].split_at(32);
        let seed: Vec<u8> = masked_seed.iter().zip(mgf1(masked_db, 32)).map(|(a, b)| a ^ b).collect();
        assert_eq!(seed, [0x77; 32]);
        let db: Vec<u8> = masked_db.iter().zip(mgf1(&seed, 223)).map(|(a, b)| a ^ b).collect();
        assert_eq!(&db[..32], &Sha256::digest(b"IDENTITY\0")[..]);
        assert!(db[32..190].iter().all(|b| *b == 0));
        assert_eq!(db[190], 1);
        assert_eq!(&db[191..], &msg);
    }

    #[test]
    fn a_credential_has_the_tpm2b_id_object_shape() {
        let mut n = vec![0xC3u8; 256];
        n[255] |= 1;
        let name = [&[0x00, 0x0B][..], &[0x99; 32]].concat();
        let made = make_credential_with(&n, &name, &[0x42; 32], &[1; 32], &[2; 32]).unwrap();
        assert_eq!(made.encrypted_secret.len(), 256);
        // integrity TPM2B (2 + 32), then the encrypted TPM2B_DIGEST (2 + 32).
        assert_eq!(made.credential_blob.len(), 2 + 32 + 34);
        assert_eq!(&made.credential_blob[..2], &[0, 32]);
        // The integrity covers the Name: another AK, another MAC.
        let other = [&[0x00, 0x0B][..], &[0x98; 32]].concat();
        let made2 = make_credential_with(&n, &other, &[0x42; 32], &[1; 32], &[2; 32]).unwrap();
        assert_ne!(made.credential_blob[2..34], made2.credential_blob[2..34]);
        // Refusals: not a 2048-bit modulus, an oversized credential.
        assert!(make_credential_with(&n[1..], &name, &[0; 32], &[1; 32], &[2; 32]).is_err());
        assert!(make_credential_with(&n, &name, &[0; 33], &[1; 32], &[2; 32]).is_err());
    }
}
