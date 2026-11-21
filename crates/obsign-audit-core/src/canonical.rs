use crate::hash::Hash;

/// Canonical encoder: length-prefixed, big-endian, unambiguous.
///
/// We deliberately do NOT use `serde_json` to compute hashes. JSON allows too
/// much freedom (key order, whitespace, escaping, number representation): two
/// serializers can produce different bytes for the same data, and therefore
/// different hashes. For a product whose hash *is* the value, that is
/// disqualifying.
///
/// Here every field is written with its length in front, so concatenation is
/// injective: two distinct structures cannot produce the same byte string.
/// JSON is still used for transport and human reading, never for computation.
#[derive(Default)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// String: 4-byte length, then the UTF-8 bytes.
    pub fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(&length_prefix(b.len()).to_be_bytes());
        self.buf.extend_from_slice(b);
        self
    }

    /// Raw digest: fixed size, no length prefix needed.
    pub fn hash(&mut self, h: &Hash) -> &mut Self {
        self.buf.extend_from_slice(h.as_bytes());
        self
    }

    /// Option: one presence byte, then the value if present.
    /// Unambiguously distinguishes `None` from `Some("")`.
    pub fn opt_str(&mut self, v: Option<&str>) -> &mut Self {
        match v {
            None => self.u8(0),
            Some(s) => self.u8(1).str(s),
        }
    }

    pub fn opt_u64(&mut self, v: Option<u64>) -> &mut Self {
        match v {
            None => self.u8(0),
            Some(n) => self.u8(1).u64(n),
        }
    }

    pub fn opt_i64(&mut self, v: Option<i64>) -> &mut Self {
        match v {
            None => self.u8(0),
            Some(n) => self.u8(1).i64(n),
        }
    }

    pub fn opt_hash(&mut self, v: Option<&Hash>) -> &mut Self {
        match v {
            None => self.u8(0),
            Some(h) => self.u8(1).hash(h),
        }
    }

    /// Sequence of strings: count, then the elements in the given order.
    /// The order is significant and part of the proof.
    pub fn str_seq(&mut self, items: &[String]) -> &mut Self {
        self.u64(items.len() as u64);
        for it in items {
            self.str(it);
        }
        self
    }

    pub fn finish(&self) -> &[u8] {
        &self.buf
    }
}

/// The 4-byte length prefix, refusing what it cannot represent.
///
/// `as u32` would wrap a field of 4 GiB + n bytes to n, and two different
/// byte strings would then share an encoding: the one property this format
/// exists for. Every caller returns a bare digest, so the refusal is a
/// panic, not an error to thread through; no honest record or checkpoint
/// comes near the limit, and `obsign verify` caps the pack it reads well
/// below it.
fn length_prefix(len: usize) -> u32 {
    u32::try_from(len).unwrap_or_else(|_| {
        panic!("canonical encoding: a {len}-byte field exceeds the 4 GiB length prefix")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "exceeds the 4 GiB length prefix")]
    fn a_field_over_4_gib_is_refused_not_wrapped() {
        // Allocating 4 GiB in a test is not an option; the prefix is what
        // `bytes` writes, and it used to be `len as u32`, i.e. 0 here.
        length_prefix(u32::MAX as usize + 1);
    }

    #[test]
    fn the_largest_representable_length_still_encodes() {
        assert_eq!(length_prefix(u32::MAX as usize), u32::MAX);
    }

    #[test]
    fn length_prefix_prevents_concatenation_collisions() {
        // Without a length prefix, ("ab", "c") and ("a", "bc") would produce
        // the same bytes. That is exactly the hole we close.
        let mut a = Encoder::new();
        a.str("ab").str("c");
        let mut b = Encoder::new();
        b.str("a").str("bc");
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn none_and_empty_string_are_distinct() {
        let mut a = Encoder::new();
        a.opt_str(None);
        let mut b = Encoder::new();
        b.opt_str(Some(""));
        assert_ne!(a.finish(), b.finish());
    }
}
