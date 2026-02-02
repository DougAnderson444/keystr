//! Static website which allows users to create and use plogs.
use dioxus::{logger::tracing, prelude::*};
use gloo_storage::{LocalStorage, Storage};
use keystr_client::web::Keystr;
use wasm_bindgen::JsCast;

const FAVICON: Asset = asset!("/assets/favicon.ico");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");
const VLAD_STORAGE_KEY: &str = "keystr_vlad";
const PLOG_STORAGE_KEY: &str = "keystr_plog_export";

fn main() {
    // Initialize tracing
    dioxus::logger::init(tracing::Level::INFO).expect("failed to init logger");
    tracing::info!("Starting Keystr application");
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    let mut cached_vlad = use_signal::<Option<String>>(|| None);
    let mut cached_plog_export = use_signal::<Option<String>>(|| None);
    let mut is_checking_storage = use_signal(|| true);

    // On component mount, check for a cached vlad and plog in local storage
    use_effect(move || {
        cached_vlad.set(LocalStorage::get(VLAD_STORAGE_KEY).ok());
        cached_plog_export.set(LocalStorage::get(PLOG_STORAGE_KEY).ok());
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
                    Signer { 
                        vlad: vlad.clone(), 
                        plog_export: cached_plog_export().clone(),
                        on_forget: move |_| {
                            cached_vlad.set(None);
                            cached_plog_export.set(None);
                            LocalStorage::delete(VLAD_STORAGE_KEY);
                            LocalStorage::delete(PLOG_STORAGE_KEY);
                        }
                    }
                } else {
                    PlogCreator { 
                        on_create: move |(vlad, plog_export)| {
                            if let Err(e) = LocalStorage::set(PLOG_STORAGE_KEY, &plog_export) {
                                tracing::error!("Failed to cache plog export: {:?}", e);
                            }
                            cached_vlad.set(Some(vlad));
                            cached_plog_export.set(Some(plog_export));
                        }
                    }
                }
            }
        }
    }
}

/// A component for signing data with an existing passkey.
#[component]
fn Signer(vlad: String, plog_export: Option<String>, on_forget: EventHandler<()>) -> Element {
    let vlad_signal = use_signal(|| vlad);
    let mut status = use_signal(|| format!("Found existing identity (vlad): {}", vlad_signal()));
    let mut data_to_sign = use_signal(|| "Hello, world!".to_string());
    let mut signature_info = use_signal(String::new);
    let mut is_busy = use_signal(|| false);
    let mut plog_export_signal = use_signal(String::new);
    let mut show_export = use_signal(|| false);

    let sign_data = move |_| {
        is_busy.set(true);
        status.set("Requesting signature from passkey...".to_string());
        signature_info.set("".to_string());
        let vlad = vlad_signal();
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

    let export_plog = move |_| {
        if let Some(export) = plog_export.clone() {
            plog_export_signal.set(export);
            show_export.set(true);
            status.set(
                "Plog exported! Copy the text below to import on another device."
                    .to_string(),
            );
        } else {
            status.set(
                "Export not available. The plog was created before this session. Try importing on the new device using the vlad."
                    .to_string(),
            );
        }
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
                    class: "bg-blue-500 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg shadow-md transition duration-200 disabled:bg-gray-400",
                    onclick: export_plog,
                    disabled: is_busy(),
                    "Export Plog"
                }
                button {
                    class: "bg-red-500 hover:bg-red-700 text-white font-semibold py-3 px-6 rounded-lg shadow-md transition duration-200",
                    onclick: forget_identity,
                    "Forget Identity"
                }
            }

            if !signature_info().is_empty() {
                div { class: "mt-4 p-4 bg-green-100 border border-green-400 rounded",
                    h3 { class: "font-bold text-lg mb-2", "Signature Result:" }
                    pre { class: "text-xs overflow-auto", "{signature_info}" }
                }
            }

            if show_export() && !plog_export_signal().is_empty() {
                div { class: "mt-4 p-4 bg-blue-100 border border-blue-400 rounded",
                    h3 { class: "font-bold text-lg mb-2", "Exported Plog (Base64):" }
                    p { class: "text-sm mb-2", "Copy this text and use \"Import Plog\" on another device:" }
                    textarea {
                        class: "w-full p-2 border rounded font-mono text-xs",
                        rows: 10,
                        readonly: true,
                        value: "{plog_export_signal}",
                        onclick: move |_| {
                            // Auto-select text on click for easy copying
                            if let Some(window) = web_sys::window() {
                                if let Some(document) = window.document() {
                                    if let Some(element) = document.query_selector("textarea").ok().flatten() {
                                        if let Ok(textarea) = element.dyn_into::<web_sys::HtmlTextAreaElement>() {
                                            textarea.select();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// A component for creating a new Plog and passkey identity.
#[component]
pub fn PlogCreator(on_create: EventHandler<(String, String)>) -> Element {
    let mut status = use_signal(|| "No passkey identity found. Ready to create one.".to_string());
    let mut plog_info = use_signal(String::new);
    let mut is_busy = use_signal(|| false);
    let mut show_import = use_signal(|| false);
    let mut import_text = use_signal(String::new);

    let create_plog = move |_| {
        is_busy.set(true);
        status.set("Creating new provenance log and passkey...".to_string());
        plog_info.set("".to_string());

        spawn(async move {
            match create_plog_async().await {
                Ok((info, vlad, plog_export)) => {
                    tracing::info!("New plog created successfully");
                    if let Err(e) = LocalStorage::set(VLAD_STORAGE_KEY, &vlad) {
                        tracing::error!("Failed to cache vlad: {:?}", e);
                        status.set(format!("Error caching plog: {}", e));
                    } else {
                        status.set("New identity created and cached successfully!".to_string());
                        on_create.call((vlad, plog_export));
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

    let toggle_import = move |_| {
        show_import.set(!show_import());
    };

    let import_plog = move |_| {
        is_busy.set(true);
        status.set("Importing plog...".to_string());
        plog_info.set("".to_string());
        let import_data = import_text();

        spawn(async move {
            match Keystr::import_plog(&import_data).await {
                Ok(keystr) => {
                    let plog = keystr.bs.plog();
                    let vlad = plog.vlad.to_string();
                    let plog_export = keystr.export_plog();

                    tracing::info!("Plog imported successfully");
                    let info = format!(
                        "Imported Plog:\nVlad: {}\nEntries: {}\nHead: {}",
                        vlad,
                        plog.entries.len(),
                        plog.head
                    );
                    plog_info.set(info);
                    status.set("Plog imported successfully! Ready to sign.".to_string());
                    on_create.call((vlad, plog_export));
                }
                Err(e) => {
                    tracing::error!("Failed to import plog: {:?}", e);
                    status.set(format!("Import error: {}", e));
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

            div { class: "flex space-x-4",
                button {
                    class: "bg-blue-500 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg shadow-md transition duration-200 disabled:bg-gray-400",
                    onclick: create_plog,
                    disabled: is_busy(),
                    "Create New Passkey Identity"
                }
                button {
                    class: "bg-purple-500 hover:bg-purple-700 text-white font-semibold py-3 px-6 rounded-lg shadow-md transition duration-200 disabled:bg-gray-400",
                    onclick: toggle_import,
                    disabled: is_busy(),
                    if show_import() { "Hide Import" } else { "Import Existing Plog" }
                }
            }

            if show_import() {
                div { class: "mt-4 p-4 bg-purple-100 border border-purple-400 rounded",
                    h3 { class: "font-bold text-lg mb-2", "Import Plog from Base64:" }
                    p { class: "text-sm mb-2", "Paste the exported plog text below:" }
                    textarea {
                        class: "w-full p-2 border rounded font-mono text-xs",
                        rows: 10,
                        placeholder: "Paste base64-encoded plog here...",
                        value: "{import_text}",
                        oninput: move |e| import_text.set(e.value())
                    }
                    button {
                        class: "mt-2 bg-purple-600 hover:bg-purple-800 text-white font-semibold py-2 px-4 rounded disabled:bg-gray-400",
                        onclick: import_plog,
                        disabled: is_busy() || import_text().trim().is_empty(),
                        "Import and Verify"
                    }
                }
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

/// Creates a new plog and returns its info, vlad, and base64 export.
async fn create_plog_async() -> Result<(String, String, String), Box<dyn std::error::Error>> {
    tracing::info!("Creating new Keystr client and plog...");

    let keystr = Keystr::new().await?;
    let plog = keystr.bs.plog();
    let plog_export = keystr.export_plog();

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

    Ok((info, plog.vlad.to_string(), plog_export))
}
