//! Error type for the client crate

/// type alias for Result with our Error type
pub type Result<T> = std::result::Result<T, Error>;

/// Client Errors
#[derive(Debug, thiserror::Error)]
pub enum Error {}
