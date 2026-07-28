use crate::canonical::Encoder;
use crate::hash::{digest, domain, Hash};

/// Merkle root of a batch of records.
///
/// Two precautions that avoid known attacks:
///
/// * leaves and internal nodes use different domain bytes, otherwise an
///   internal node could be passed off as a leaf;
/// * with an odd number of elements the last one is **promoted** as-is to the
///   next level, it is not duplicated. Duplication (Bitcoin's historical bug,
///   CVE-2012-2459) lets you build two different batches with the same root.
///
/// Returns `None` on an empty batch: a seal with no content is meaningless and
/// must be rejected by the caller, not silently accepted.
pub fn merkle_root(leaves: &[Hash]) -> Option<Hash> {
    if leaves.is_empty() {
        return None;
    }

    let mut level: Vec<Hash> = leaves.iter().map(leaf_hash).collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            next.push(node_hash(&level[i], &level[i + 1]));
            i += 2;
        }
        if i < level.len() {
            // Odd count: promotion, not duplication.
            next.push(level[i]);
        }
        level = next;
    }

    Some(level[0])
}

fn leaf_hash(record_hash: &Hash) -> Hash {
    let mut e = Encoder::new();
    e.hash(record_hash);
    digest(domain::MERKLE_LEAF, e.finish())
}

fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut e = Encoder::new();
    e.hash(left).hash(right);
    digest(domain::MERKLE_NODE, e.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> Hash {
        Hash([n; 32])
    }

    #[test]
    fn empty_batch_rejected() {
        assert!(merkle_root(&[]).is_none());
    }

    #[test]
    fn root_is_stable_and_order_sensitive() {
        let a = merkle_root(&[h(1), h(2), h(3)]).unwrap();
        let b = merkle_root(&[h(1), h(2), h(3)]).unwrap();
        assert_eq!(a, b);

        let permuted = merkle_root(&[h(1), h(3), h(2)]).unwrap();
        assert_ne!(a, permuted, "order is part of the proof");
    }

    #[test]
    fn a_leaf_is_not_its_own_hash() {
        // Otherwise a record could be presented as a batch root, and vice
        // versa.
        let r = merkle_root(&[h(7)]).unwrap();
        assert_ne!(r, h(7));
    }

    #[test]
    fn odd_promotion_avoids_collision() {
        // The classic trap: [a, b, c] duplicated into [a, b, c, c] must stay
        // distinguishable from [a, b, c, c] actually supplied.
        let three = merkle_root(&[h(1), h(2), h(3)]).unwrap();
        let four = merkle_root(&[h(1), h(2), h(3), h(3)]).unwrap();
        assert_ne!(three, four);
    }

    #[test]
    fn any_tampering_changes_the_root() {
        let base = merkle_root(&[h(1), h(2), h(3), h(4), h(5)]).unwrap();
        let tampered = merkle_root(&[h(1), h(2), h(9), h(4), h(5)]).unwrap();
        assert_ne!(base, tampered);
    }
}
