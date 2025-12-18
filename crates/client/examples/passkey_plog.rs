//! Example demonstrating how to use PasskeyWallet with BetterSign for provenance logs
//!
//! This example shows:
//! 1. Creating a PasskeyWallet instance
//! 2. Setting up a BetterSign instance with P256 keys from passkeys
//! 3. Creating a provenance log with an ephemeral Ed25519 first entry
//! 4. Adding subsequent entries signed with the user's passkey

use bs::better_sign::BetterSign;
use bs::open;
use bs::params::{anykey::PubkeyParams, vlad::FirstEntryKeyParams, vlad::VladParams};
use bs::update;
use keystr_client::PasskeyWallet;
use multicodec::Codec;
use provenance_log::{Key, Script};

/// This example must be run in a browser environment with WASM support
#[cfg(target_arch = "wasm32")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for debugging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    tracing::info!("Starting passkey provenance log example");

    // Step 1: Create a PasskeyWallet
    // In a real application, you would:
    // - Generate a random user_id and store it persistently
    // - Get the rp_id from window.location.hostname
    // - Get user_name from your application's user management

    let user_id = {
        let mut buf = [0u8; 16];
        getrandom::getrandom(&mut buf)?;
        buf.to_vec()
    };

    let wallet = PasskeyWallet::new(
        "localhost".to_string(),      // rp_id - should be your actual domain
        "Keystr Example".to_string(), // rp_name
        "user@example.com".to_string(), // user_name
        user_id,
    );

    tracing::info!("Created PasskeyWallet for {}", wallet.user_name());

    // Step 2: Configure the provenance log to use P256 for pubkey
    // The first entry will still use Ed25519 (ephemeral), but subsequent entries use P256

    let open_config = open::Config::builder()
        .vlad(VladParams::default())
        .pubkey(
            PubkeyParams::builder()
                .codec(Codec::P256Pub) // Use P256 instead of Ed25519
                .build()
                .into(),
        )
        .entrykey(
            FirstEntryKeyParams::builder()
                .codec(Codec::Ed25519Priv) // First entry remains Ed25519 (ephemeral)
                .build()
                .into(),
        )
        .lock(Script::Code(
            Key::default(),
            "check_signature(\"/pubkey\", \"/entry/\")".to_string(),
        ))
        .unlock(Script::Code(
            Key::default(),
            "push(\"/entry/\"); push(\"/entry/proof\")".to_string(),
        ))
        .build();

    tracing::info!("Created provenance log configuration");

    // Step 3: Create BetterSign instance
    // This will:
    // - Generate an ephemeral Ed25519 key for the first entry
    // - Create a passkey (prompting the user) for the P256 public key
    // - Initialize the provenance log

    tracing::info!("Creating BetterSign instance (this will prompt for passkey creation)...");

    let mut bs = BetterSign::new(open_config, wallet.clone(), wallet.clone())
        .await
        .map_err(|e| format!("Failed to create BetterSign: {:?}", e))?;

    tracing::info!("Successfully created provenance log!");
    tracing::info!("Initial entries: {}", bs.plog().entries.len());

    // Step 4: Add a new entry to the log
    // This will use the user's passkey to sign

    let update_config = update::Config::builder()
        .unlock(Script::Code(
            Key::default(),
            "push(\"/entry/\"); push(\"/entry/proof\")".to_string(),
        ))
        .entry_signing_key(PubkeyParams::KEY_PATH.into())
        .build();

    tracing::info!("Adding new entry (this will prompt for passkey authentication)...");

    let new_entry = bs
        .update(update_config)
        .await
        .map_err(|e| format!("Failed to update plog: {:?}", e))?;

    tracing::info!("Successfully added new entry!");
    tracing::info!("New entry CID: {}", new_entry.cid());
    tracing::info!("Total entries: {}", bs.plog().entries.len());

    // Step 5: Verify the provenance log
    let verification_results: Vec<_> = bs.plog().verify().collect();
    let all_valid = verification_results.iter().all(|r| r.is_ok());

    tracing::info!("Verification results:");
    for (idx, result) in verification_results.iter().enumerate() {
        match result {
            Ok(_) => tracing::info!("  Entry {}: ✓ Valid", idx),
            Err(e) => tracing::error!("  Entry {}: ✗ Invalid - {:?}", idx, e),
        }
    }

    if all_valid {
        tracing::info!("✓ All entries verified successfully!");
    } else {
        tracing::error!("✗ Some entries failed verification");
    }

    // Step 6: Demonstrate adding multiple entries
    tracing::info!("Adding a few more entries...");

    for i in 0..3 {
        let config = update::Config::builder()
            .unlock(Script::Code(
                Key::default(),
                "push(\"/entry/\"); push(\"/entry/proof\")".to_string(),
            ))
            .entry_signing_key(PubkeyParams::KEY_PATH.into())
            .build();

        let entry = bs
            .update(config)
            .await
            .map_err(|e| format!("Failed to add entry {}: {:?}", i, e))?;

        tracing::info!("  Added entry {} - CID: {}", i + 1, entry.cid());
    }

    tracing::info!("Final entry count: {}", bs.plog().entries.len());

    // Step 7: Export the provenance log
    // In a real application, you would serialize this and store it
    let plog = bs.into_plog();
    let plog_json = serde_json::to_string_pretty(&plog)?;

    tracing::info!("Provenance log JSON (truncated):");
    tracing::info!("{}", &plog_json[..std::cmp::min(500, plog_json.len())]);

    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    eprintln!("This example must be run in a browser with WASM support");
    eprintln!("Build with: wasm-pack build --target web");
    std::process::exit(1);
}
