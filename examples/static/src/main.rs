//! Static website which allows users to create and use plogs.
use bs::open;
use bs::open::config::ValidatedKeyParams;
use bs::params::anykey::PubkeyParams;
use bs::params::vlad::FirstEntryKeyParams;
use bs::params::vlad::VladParams;
use bs::BetterSign;
use dioxus::{logger::tracing, prelude::*};

#[cfg(not(all(feature = "web", target_arch = "wasm32")))]
use keystr_client::key_manager::Wallet;

#[cfg(all(feature = "web"))]
use keystr_client::passkey_wallet::{PasskeyKeyManager, PasskeyP256Signer, PasskeyStore};

use multicodec::Codec;
use provenance_log::{Key, Script};

const FAVICON: Asset = asset!("/assets/favicon.ico");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

fn main() {
    // Initialize tracing
    dioxus::logger::init(tracing::Level::INFO).expect("failed to init logger");
    tracing::info!("Starting Keystr application");
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        Hero {}
    }
}

#[component]
pub fn Hero() -> Element {
    rsx! {
        div { class: "container mx-auto p-4",
            h1 { class: "text-4xl font-bold mb-8", "Keystr - Provenance Log Creator" }
            NewPlog {}
        }
    }
}

/// New user create Plog component
#[component]
pub fn NewPlog() -> Element {
    let mut status = use_signal(|| "Ready to create plog".to_string());
    let mut plog_created = use_signal(|| false);
    let mut plog_info = use_signal(String::new);

    let create_plog = move |_| {
        tracing::info!("Create Plog button clicked");
        status.set("Creating provenance log...".to_string());

        // Spawn async task to create plog
        spawn(async move {
            match create_plog_async().await {
                Ok(info) => {
                    tracing::info!("Plog created successfully");
                    status.set("Plog created successfully!".to_string());
                    plog_created.set(true);
                    plog_info.set(info);
                }
                Err(e) => {
                    tracing::error!("Failed to create plog: {:?}", e);
                    status.set(format!("Error: {}", e));
                }
            }
        });
    };

    rsx! {
        div { class: "space-y-4",
            button {
                class: "bg-blue-500 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg shadow-md transition duration-200",
                onclick: create_plog,
                disabled: plog_created(),
                "Create New Plog"
            }

            div { class: "mt-4 p-4 bg-gray-100 rounded",
                p { class: "font-medium", "Status: " }
                p { class: "text-sm", "{status}" }
            }

            if plog_created() {
                div { class: "mt-4 p-4 bg-green-100 border border-green-400 rounded",
                    h3 { class: "font-bold text-lg mb-2", "Plog Details:" }
                    pre { class: "text-xs overflow-auto", "{plog_info}" }
                }
            }
        }
    }
}

async fn create_plog_async() -> Result<String, Box<dyn std::error::Error>> {
    tracing::info!("Creating wallet components...");

    // Use Passkey-based managers in browser, regular Wallet otherwise
    #[cfg(all(feature = "web"))]
    let (key_manager, signer) = {
        tracing::info!("Creating Passkey managers for browser...");

        let user_id = {
            let mut buf = [0u8; 16];
            getrandom::getrandom(&mut buf)?;
            buf.to_vec()
        };
        tracing::debug!("Generated initial user_id: {} bytes", user_id.len());

        // The user_name is a display string, and user_id is the persistent identifier.
        // preprocess_vlad will overwrite user_id with the vlad string.
        let store = PasskeyStore::<bs::Error>::new(
            web_sys::window()
                .and_then(|w| w.location().hostname().ok())
                .unwrap_or_else(|| "localhost".to_string()),
            "Keystr Provenance Log".to_string(),
            "keystr-user".to_string(), // Will be overwritten by vlad when plog i created and
            // preprocess_vlad is called.
            user_id,
        );
        tracing::info!("PasskeyStore created with rp_id: {}", store.rp_id());

        let key_manager = PasskeyKeyManager::new(store.clone());
        let signer = PasskeyP256Signer::new(store);

        (key_manager, signer)
    };

    #[cfg(not(all(feature = "web", target_arch = "wasm32")))]
    let (key_manager, signer) = {
        tracing::info!("Creating standard Wallet (non-browser)...");
        let wallet = Wallet::new();
        (wallet.clone(), wallet)
    };
    let pubkey_codec = Codec::P256Pub;

    tracing::info!("Building plog configuration...");
    tracing::debug!("Using pubkey_codec: {:?}", pubkey_codec);
    let config = open::Config::builder()
        .vlad(VladParams::default())
        .pubkey(PubkeyParams::builder().codec(pubkey_codec).build().into())
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
    tracing::debug!("Configuration built successfully");

    tracing::info!("Creating BetterSign instance...");
    let bs = BetterSign::new(config, key_manager, signer).await?;
    tracing::info!("BetterSign instance created successfully");

    tracing::info!("Plog created successfully");
    let plog = bs.plog();

    // Create summary info
    let info = format!(
        "Plog Head: {}\nEntries: {}\nVerification: {}",
        plog.head,
        plog.entries.len(),
        if plog.verify().count() > 0 {
            "Passed"
        } else {
            "Failed"
        }
    );

    Ok(info)
}
