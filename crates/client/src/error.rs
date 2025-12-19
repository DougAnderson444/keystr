//! Error type for the client crate

use provenance_log::Key;

/// type alias for Result with our Error type
pub type Result<T> = std::result::Result<T, Error>;

/// Client Errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Multikey error: {0}")]
    Multikey(#[from] multikey::Error),

    #[error("Multihash error: {0}")]
    Multihash(#[from] multihash::Error),

    #[error("Multicid error: {0}")]
    Multicid(#[from] multicid::Error),

    #[error("No key present at path: {0}")]
    NoKeyPresent(Key),

    #[error("BetterSign error: {0}")]
    BetterSign(#[from] bs::Error),

    #[error("Open error: {0}")]
    Open(#[from] bs::error::OpenError),

    #[error("Update error: {0}")]
    Update(#[from] bs::error::UpdateError),

    #[error("Provenance log error: {0}")]
    ProvenanceLog(#[from] provenance_log::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[cfg(feature = "web")]
    #[error("Passkey error: {0}")]
    Passkey(#[from] crate::web::passkey_wallet::PasskeyError),

    /// From [getrandom::Error]
    #[error(transparent)]
    GetRandom(#[from] getrandom::Error),
}
