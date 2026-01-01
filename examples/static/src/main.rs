//! Static website which allows users to create and use plogs.
use dioxus::{logger::tracing, prelude::*};
use gloo_storage::{LocalStorage, Storage};
use keystr_client::web::Keystr;

const FAVICON: Asset = asset!("/assets/favicon.ico");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");
const VLAD_STORAGE_KEY: &str = "keystr_vlad";

fn main() {
    // Initialize tracing
    dioxus::logger::init(tracing::Level::INFO).expect("failed to init logger");
    tracing::info!("Starting Keystr application");
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    let mut cached_vlad = use_signal::<Option<String>>(|| None);
    let mut is_checking_storage = use_signal(|| true);

    // On component mount, check for a cached vlad in local storage
    use_effect(move || {
        cached_vlad.set(LocalStorage::get(VLAD_STORAGE_KEY).ok());
        is_checking_storage.set(false);
    });

    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        div { class: "container mx-auto p-4",
            h1 { class: "text-4xl font-bold mb-8", "Keystr - Passkey Demo" }
            if is_checking_storage() {
                p { "Checking for existing passkey identity..." }
            } else {
                if let Some(vlad) = cached_vlad() {
                    Signer { vlad: vlad.clone(), on_forget: move |_| cached_vlad.set(None) }
                } else {
                    PlogCreator { on_create: move |vlad| cached_vlad.set(Some(vlad)) }
                }
            }
        }
    }
}

/// A component for signing data with an existing passkey.
#[component]
fn Signer(vlad: String, on_forget: EventHandler<()>) -> Element {
    let mut status = use_signal(|| format!("Found existing identity (vlad): {}", vlad));
    let mut data_to_sign = use_signal(|| "Hello, world!".to_string());
    let mut signature_info = use_signal(String::new);
    let mut is_busy = use_signal(|| false);

    let sign_data = move |_| {
        is_busy.set(true);
        status.set("Requesting signature from passkey...".to_string());
        signature_info.set("".to_string());
        let vlad = vlad.clone();
        let data = data_to_sign();

        spawn(async move {
            match Keystr::sign(&vlad, data.as_bytes()).await {
                Ok(info) => {
                    tracing::info!("Signing successful");
                    status.set("Successfully signed data with passkey!".to_string());
                    signature_info.set(info);
                }
                Err(e) => {
                    tracing::error!("Failed to sign: {:?}", e);
                    status.set(format!("Error: {}", e));
                }
            }
            is_busy.set(false);
        });
    };

    let forget_identity = move |_| {
        tracing::info!("Forget Identity button clicked");
        LocalStorage::delete(VLAD_STORAGE_KEY);
        on_forget.call(());
    };

    rsx! {
        div { class: "space-y-4 p-4 border rounded-lg shadow-sm",
            div { class: "p-4 bg-gray-100 rounded",
                p { class: "font-medium", "Status: " }
                p { class: "text-sm break-all", "{status}" }
            }

            div { class: "space-y-2",
                label { class: "block font-medium", "Data to Sign:" }
                input {
                    class: "w-full p-2 border rounded",
                    value: "{data_to_sign}",
                    oninput: move |e| data_to_sign.set(e.value())
                }
            }

            div { class: "flex space-x-4",
                button {
                    class: "bg-green-500 hover:bg-green-700 text-white font-semibold py-3 px-6 rounded-lg shadow-md transition duration-200 disabled:bg-gray-400",
                    onclick: sign_data,
                    disabled: is_busy(),
                    "Sign with Passkey"
                }
                button {
                    class: "bg-red-500 hover:bg-red-700 text-white font-semibold py-3 px-6 rounded-lg shadow-md transition duration-200",
                    onclick: forget_identity,
                    "Forget Identity"
                }
            }

            if !signature_info().is_empty() {
                div { class: "mt-4 p-4 bg-green-100 border border-green-400 rounded",
                    h3 { class: "font-bold text-lg mb-2", "Result:" }
                    pre { class: "text-xs overflow-auto", "{signature_info}" }
                }
            }
        }
    }
}

/// A component for creating a new Plog and passkey identity.
#[component]
pub fn PlogCreator(on_create: EventHandler<String>) -> Element {
    let mut status = use_signal(|| "No passkey identity found. Ready to create one.".to_string());
    let mut plog_info = use_signal(String::new);
    let mut is_busy = use_signal(|| false);

    let create_plog = move |_| {
        is_busy.set(true);
        status.set("Creating new provenance log and passkey...".to_string());
        plog_info.set("".to_string());

        spawn(async move {
            match create_plog_async().await {
                Ok((info, vlad)) => {
                    tracing::info!("New plog created successfully");
                    if let Err(e) = LocalStorage::set(VLAD_STORAGE_KEY, &vlad) {
                        tracing::error!("Failed to cache vlad: {:?}", e);
                        status.set(format!("Error caching plog: {}", e));
                    } else {
                        status.set("New identity created and cached successfully!".to_string());
                        on_create.call(vlad);
                    }
                    plog_info.set(info);
                }
                Err(e) => {
                    tracing::error!("Failed to create new plog: {:?}", e);
                    status.set(format!("Error: {}", e));
                }
            }
            is_busy.set(false);
        });
    };

    rsx! {
        div { class: "space-y-4 p-4 border rounded-lg shadow-sm",
            div { class: "p-4 bg-gray-100 rounded",
                p { class: "font-medium", "Status: " }
                p { class: "text-sm", "{status}" }
            }

            button {
                class: "bg-blue-500 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg shadow-md transition duration-200 disabled:bg-gray-400",
                onclick: create_plog,
                disabled: is_busy(),
                "Create New Passkey Identity"
            }

            if !plog_info().is_empty() {
                div { class: "mt-4 p-4 bg-green-100 border border-green-400 rounded",
                    h3 { class: "font-bold text-lg mb-2", "New Plog Details:" }
                    pre { class: "text-xs overflow-auto", "{plog_info}" }
                }
            }
        }
    }
}

/// Creates a new plog and returns its info and vlad.
async fn create_plog_async() -> Result<(String, String), Box<dyn std::error::Error>> {
    tracing::info!("Creating new Keystr client and plog...");

    let keystr = Keystr::new().await?;
    let bs = keystr.bs;
    let plog = bs.plog();

    let info = format!(
        "Plog Head: {}\nVlad: {}\nEntries: {}\nVerification: {}",
        plog.head,
        plog.vlad,
        plog.entries.len(),
        if plog.verify().count() > 0 {
            "Passed"
        } else {
            "Failed"
        }
    );

    Ok((info, plog.vlad.to_string()))
}
