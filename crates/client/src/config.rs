use std::ops::Deref;

use bs::{
    config::{Codec, Key},
    open::{
        self,
        config::{Field, Script, ValidatedKeyParams, format_with_fields},
    },
    params::{
        anykey::PubkeyParams,
        vlad::{FirstEntryKeyParams, VladParams},
    },
};

/// Configuration for plog generation
pub struct GenerationConfig(open::Config);

impl Deref for GenerationConfig {
    type Target = open::Config;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for GenerationConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl GenerationConfig {
    /// Creates a new Plog with opinionated configuration:
    ///
    /// - Ed25519 private key for pubkey and entry key
    /// - Unlock script that pushes entry and proof fields
    /// - Lock script that checks recovery key, pubkey, or pre-image proof
    pub fn new() -> Self {
        let pubkey_params = PubkeyParams::builder().codec(Codec::Ed25519Priv).build();

        let pubkey_key_path = pubkey_params.key_path().as_str();
        assert_eq!(pubkey_key_path, "/pubkey");

        // or we could use the asoc const from which it is derived
        let pubkey_ket_path = &*PubkeyParams::KEY_PATH;
        assert_eq!(pubkey_ket_path, "/pubkey");

        let entry_key = Field::ENTRY;
        assert_eq!(entry_key, "/entry/");

        let proof_key = Field::PROOF;
        assert_eq!(proof_key, "/entry/proof");

        let unlock_old_school = format!(
            r#"
               // push the serialized Entry as the message
               push("{entry_key}");

               // push the proof data
               push("{proof_key}");
          "#
        );

        // If we have just Fields, we can use format_with_fields! macro
        let unlock = format_with_fields!(
            r#"
               // push the serialized Entry as the message
               push("{Field::ENTRY}");

               // push the proof data
               push("{Field::PROOF}");
          "#
        );

        assert_eq!(unlock_old_school, unlock);

        // Note: The First Lock script is embedded in VladParams,
        // since it's tightly coupled to the first entry key,
        // first entry key_path, and the Vlad Cid,
        // so we don't need to define it here.

        // for now, if we have a mix of Fields and Strings, we can use format! macro
        let lock = format!(
            r#"
                  // check a possible threshold sig...
                  check_signature("/recoverykey", "{entry_key}") ||

                  // then check a possible pubkey sig...
                  check_signature("{pubkey_key_path}", "{entry_key}") ||

                  // then the pre-image proof...
                  check_preimage("/hash")
              "#
        );

        // The Type on VladParams ensures we use the same type for the first entry key
        // which is used to generate the first lock script in the VladParams.
        let vlad_params = VladParams::<FirstEntryKeyParams>::default();

        let entry_key_params = FirstEntryKeyParams::builder()
            .codec(Codec::Ed25519Priv)
            .build();

        let config = open::Config::builder() // Uses default type parameter FirstEntryKeyParams
            .vlad(vlad_params)
            .pubkey(pubkey_params.into())
            .entrykey(entry_key_params.into())
            .lock(Script::Code(Key::default(), lock))
            .unlock(Script::Code(Key::default(), unlock))
            .build();
        Self(config)
    }
}
