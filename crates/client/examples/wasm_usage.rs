//! Practical example for integrating PasskeyWallet into a web application
//!
//! This shows the typical workflow for a static site hosted on GitHub Pages or similar:
//! 1. Initialize the wallet on first visit
//! 2. Create a passkey for the user
//! 3. Store the provenance log in localStorage
//! 4. Load and update the log on subsequent visits

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use bs::better_sign::BetterSign;
#[cfg(target_arch = "wasm32")]
use bs::{open, update};
#[cfg(target_arch = "wasm32")]
use bs::params::{anykey::PubkeyParams, vlad::FirstEntryKeyParams, vlad::VladParams};
#[cfg(target_arch = "wasm32")]
use keystr_client::PasskeyWallet;
#[cfg(target_arch = "wasm32")]
use multicodec::Codec;
#[cfg(target_arch = "wasm32")]
use provenance_log::{Key, Script, Log};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::spawn_local;

/// JavaScript-callable function to initialize a new provenance log with passkey
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn init_plog(user_name: String) -> Result<JsValue, JsValue> {
    // Set up panic hook for better error messages
    console_error_panic_hook::set_once();

    // Get the current domain
    let window = web_sys::window().ok_or("No window object")?;
    let location = window.location();
    let hostname = location
        .hostname()
        .map_err(|_| "Failed to get hostname")?;

    // Generate a random user ID
    let user_id = {
        let mut buf = [0u8; 16];
        getrandom::getrandom(&mut buf).map_err(|e| format!("Failed to generate user ID: {}", e))?;
        buf.to_vec()
    };

    // Create wallet
    let wallet = PasskeyWallet::new(
        hostname.clone(),
        format!("Keystr on {}", hostname),
        user_name.clone(),
        user_id,
    );

    // Configure provenance log
    let open_config = open::Config::builder()
        .vlad(VladParams::default())
        .pubkey(
            PubkeyParams::builder()
                .codec(Codec::P256Pub)
                .build()
                .into(),
        )
        .entrykey(
            FirstEntryKeyParams::builder()
                .codec(Codec::Ed25519Priv)
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

    // Create BetterSign instance (this will prompt user to create passkey)
    let bs = BetterSign::new(open_config, wallet.clone(), wallet.clone())
        .await
        .map_err(|e| format!("Failed to create provenance log: {:?}", e))?;

    // Serialize the provenance log
    let plog = bs.into_plog();
    let plog_json = serde_json::to_string(&plog)
        .map_err(|e| format!("Failed to serialize plog: {}", e))?;

    // Store in localStorage
    let storage = window
        .local_storage()
        .map_err(|_| "Failed to access localStorage")?
        .ok_or("localStorage not available")?;

    storage
        .set_item("keystr_plog", &plog_json)
        .map_err(|_| "Failed to store plog")?;

    Ok(JsValue::from_str(&format!(
        "Provenance log initialized with {} entries",
        plog.entries.len()
    )))
}

/// JavaScript-callable function to add an entry to an existing provenance log
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn add_entry(user_name: String, entry_data: String) -> Result<JsValue, JsValue> {
    let window = web_sys::window().ok_or("No window object")?;
    let location = window.location();
    let hostname = location
        .hostname()
        .map_err(|_| "Failed to get hostname")?;

    // Load existing plog from localStorage
    let storage = window
        .local_storage()
        .map_err(|_| "Failed to access localStorage")?
        .ok_or("localStorage not available")?;

    let plog_json = storage
        .get_item("keystr_plog")
        .map_err(|_| "Failed to read plog")?
        .ok_or("No provenance log found. Please initialize first.")?;

    let plog: Log = serde_json::from_str(&plog_json)
        .map_err(|e| format!("Failed to parse plog: {}", e))?;

    // Recreate wallet (in production, you'd want to persist user_id too)
    let user_id = {
        let mut buf = [0u8; 16];
        getrandom::getrandom(&mut buf).map_err(|e| format!("Failed to generate user ID: {}", e))?;
        buf.to_vec()
    };

    let wallet = PasskeyWallet::new(
        hostname.clone(),
        format!("Keystr on {}", hostname),
        user_name.clone(),
        user_id,
    );

    // TODO: We need to restore the passkey credential info to the wallet
    // This is a limitation of the current design - we need to store credential IDs
    // and public keys in localStorage as well, or use discoverable credentials

    // Reconstruct BetterSign from existing plog
    let mut bs = BetterSign::from_parts(plog, wallet.clone(), wallet.clone());

    // Add new entry
    let update_config = update::Config::builder()
        .unlock(Script::Code(
            Key::default(),
            "push(\"/entry/\"); push(\"/entry/proof\")".to_string(),
        ))
        .entry_signing_key(PubkeyParams::KEY_PATH.into())
        .build();

    let new_entry = bs
        .update(update_config)
        .await
        .map_err(|e| format!("Failed to add entry: {:?}", e))?;

    // Save updated plog
    let plog = bs.into_plog();
    let plog_json = serde_json::to_string(&plog)
        .map_err(|e| format!("Failed to serialize plog: {}", e))?;

    storage
        .set_item("keystr_plog", &plog_json)
        .map_err(|_| "Failed to store updated plog")?;

    Ok(JsValue::from_str(&format!(
        "Added entry with CID: {}",
        new_entry.cid()
    )))
}

/// JavaScript-callable function to verify the provenance log
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn verify_plog() -> Result<JsValue, JsValue> {
    let window = web_sys::window().ok_or("No window object")?;
    let storage = window
        .local_storage()
        .map_err(|_| "Failed to access localStorage")?
        .ok_or("localStorage not available")?;

    let plog_json = storage
        .get_item("keystr_plog")
        .map_err(|_| "Failed to read plog")?
        .ok_or("No provenance log found")?;

    let plog: Log = serde_json::from_str(&plog_json)
        .map_err(|e| format!("Failed to parse plog: {}", e))?;

    let results: Vec<_> = plog.verify().collect();
    let valid_count = results.iter().filter(|r| r.is_ok()).count();
    let total_count = results.len();

    Ok(JsValue::from_str(&format!(
        "Verified {}/{} entries successfully",
        valid_count, total_count
    )))
}

/// JavaScript-callable function to export the provenance log as JSON
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn export_plog() -> Result<String, JsValue> {
    let window = web_sys::window().ok_or("No window object")?;
    let storage = window
        .local_storage()
        .map_err(|_| "Failed to access localStorage")?
        .ok_or("localStorage not available")?;

    let plog_json = storage
        .get_item("keystr_plog")
        .map_err(|_| "Failed to read plog")?
        .ok_or("No provenance log found")?;

    Ok(plog_json)
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    eprintln!("This example is designed to be compiled to WASM");
    eprintln!("Build with: wasm-pack build --target web");
}
