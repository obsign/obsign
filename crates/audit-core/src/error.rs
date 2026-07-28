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

    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),
}
