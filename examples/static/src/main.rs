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
use keystr_client::passkey_wallet::PasskeyWallet;

#[cfg(all(feature = "web"))]
use multicid::{cid, Vlad};
#[cfg(all(feature = "web"))]
use multihash::mh;

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
    tracing::info!("Creating wallet...");

    // Use PasskeyWallet in browser, regular Wallet otherwise
    #[cfg(all(feature = "web"))]
    let (wallet, pubkey_codec) = {
        tracing::info!("Creating PasskeyWallet for browser...");

        // Generate vlad first to use as passkey identifier
        let vlad = {
            // Create a random cid for vlad generation
            let random_bytes = {
                let mut buf = [0u8; 32];
                getrandom::getrandom(&mut buf)?;
                buf
            };

            let cid = cid::Builder::new(Codec::Cidv1)
                .with_target_codec(Codec::DagCbor)
                .with_hash(
                    &mh::Builder::new_from_bytes(Codec::Sha3512, &random_bytes)?.try_build()?,
                )
                .try_build()?;

            // Generate vlad from ephemeral signature
            Vlad::generate(&cid, |cid| {
                let v: Vec<u8> = cid.clone().into();
                Ok(v)
            })?
        };

        let user_id = {
            let mut buf = [0u8; 16];
            getrandom::getrandom(&mut buf)?;
            buf.to_vec()
        };
        tracing::debug!("Generated user_id: {} bytes", user_id.len());

        // Use vlad's Display implementation for the username
        let vlad_string = vlad.to_string();
        tracing::info!("Using vlad as passkey username: {}", vlad_string);

        let wallet: PasskeyWallet<bs::Error> = PasskeyWallet::new(
            web_sys::window()
                .and_then(|w| w.location().hostname().ok())
                .unwrap_or_else(|| "localhost".to_string()),
            "Keystr Provenance Log".to_string(),
            vlad_string,
            user_id,
        );
        tracing::info!("PasskeyWallet created with rp_id: {}", wallet.rp_id());
        (wallet, Codec::P256Pub)
    };

    #[cfg(not(all(feature = "web", target_arch = "wasm32")))]
    let (wallet, pubkey_codec) = {
        tracing::info!("Creating standard Wallet (non-browser)...");
        (Wallet::new(), Codec::Ed25519Priv)
    };

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
    tracing::debug!("Calling BetterSign::new with PasskeyWallet...");
    let bs = BetterSign::new(config, wallet.clone(), wallet).await?;
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
