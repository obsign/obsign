use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid hex string: {0}")]
    BadHex(String),

    #[error("invalid signature length (64 bytes expected)")]
    BadSignatureLength,

    #[error("invalid key length (32 bytes expected)")]
    BadKeyLength,

    #[error("invalid public key: {0}")]
    BadKey(String),

    #[error("unsupported signature algorithm: {0}")]
    UnsupportedAlgo(String),

    #[error("invalid signature on checkpoint [{from_seq}..{to_seq}] (key {key_id})")]
    BadSignature {
        key_id: String,
        from_seq: u64,
        to_seq: u64,
    },

    #[error("unknown format version: {0}")]
    UnknownFormat(String),

    #[error("empty interval: a seal with no content has no probative value")]
    EmptySeal,

    #[error("broken interval: {0}")]
    BrokenInterval(String),

    #[error("unreadable DER structure: {0}")]
    BadDer(String),

    #[error("timestamp request rejected by the TSA (status {0})")]
    TimestampRejected(u64),

    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),
}
