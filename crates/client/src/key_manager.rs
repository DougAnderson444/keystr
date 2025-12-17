//! Implements the [bs::KeyManager] trait for managing keys in the Keystr client.
use bs::config::asynchronous::{AsyncSigner, MultiSigner};
use bs::prelude::{multihash, multikey};
use bs_traits::Signer;
use std::fmt::Debug;

/// The Key Manager for Keystr client.
pub struct Wallet<E = crate::Error> {
    // Add any fields needed for key management, e.g., storage backend
    _phantom: std::marker::PhantomData<E>,
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}

impl Wallet {
    /// Creates a new KeyManager instance.
    pub fn new() -> Self {
        Ok(Wallet {
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<E> Signer for Wallet<E>
where
    E: From<multikey::Error> + From<multihash::Error> + Debug,
{
    type KeyPath = String;
    type Signature = Signature;
    type Error = E;
}

impl MultiSigner for Wallet {
    fn get_signer(
        &self,
        key_params: &ValidatedKeyParams,
    ) -> Result<Box<dyn bs::signer::Signer>, crate::Error> {
        todo!()
    }
}

impl<E> AsyncSigner for Wallet<E>
where
    E: From<multikey::Error> + From<multihash::Error> + Debug,
{
    fn try_sign(
        &self,
        key_path: &Self::KeyPath,
        data: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        // Get the secret key corresponding to the provided path
        let secret_key = self
            .get_secret_key(key_path)?
            .ok_or(crate::Error::NoKeyPresent(key_path.clone()))?;

        let msg = data;
        let combined = false;
        let scheme = None;

        let signmk = secret_key.sign_view()?;
        let signature = signmk.sign(msg, combined, scheme)?;

        let sig_bytes_raw: Vec<u8> = signature.clone().into();
        tracing::debug!(
            "try_sign Signature created with {} bytes, first 4 bytes: {:02x?} ({:?} dec)",
            sig_bytes_raw.len(),
            &sig_bytes_raw[..4],
            &sig_bytes_raw[..4]
        );

        Ok(signature)
    }
}
