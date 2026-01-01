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
            PlogManager {}
        }
    }
}

/// Component to manage plog creation and loading
#[component]
pub fn PlogManager() -> Element {
    let mut status = use_signal(|| "Initializing...".to_string());
    let mut plog_info = use_signal(String::new);
    let mut cached_vlad = use_signal::<Option<String>>(|| None);
    let mut is_busy = use_signal(|| true);

    // On component mount, check for a cached vlad in local storage
    use_effect(move || {
        match LocalStorage::get(VLAD_STORAGE_KEY) {
            Ok(vlad) => {
                tracing::info!("Found cached vlad");
                cached_vlad.set(Some(vlad));
                status.set("Found cached plog. Ready to load.".to_string());
            }
            Err(_) => {
                tracing::info!("No cached vlad found");
                status.set("No cached plog found. Ready to create a new one.".to_string());
            }
        }
        is_busy.set(false);
    });

    let create_new_plog = move |_| {
        tracing::info!("Create New Plog button clicked");
        is_busy.set(true);
        status.set("Creating new provenance log...".to_string());
        plog_info.set("".to_string());

        spawn(async move {
            match process_plog(None).await {
                Ok((info, vlad)) => {
                    tracing::info!("New plog created successfully");
                    if let Err(e) = LocalStorage::set(VLAD_STORAGE_KEY, &vlad) {
                        tracing::error!("Failed to cache vlad: {:?}", e);
                        status.set(format!("Error caching plog: {}", e));
                    } else {
                        status.set("New plog created and cached successfully!".to_string());
                        cached_vlad.set(Some(vlad));
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

    let use_existing_plog = move |_| {
        if let Some(vlad) = cached_vlad() {
            tracing::info!("Use Existing Plog button clicked");
            is_busy.set(true);
            status.set("Loading from existing provenance log...".to_string());
            plog_info.set("".to_string());

            spawn(async move {
                match process_plog(Some(vlad)).await {
                    Ok((info, _)) => {
                        tracing::info!("Existing plog loaded successfully");
                        status.set("Existing plog loaded successfully!".to_string());
                        plog_info.set(info);
                    }
                    Err(e) => {
                        tracing::error!("Failed to use existing plog: {:?}", e);
                        status.set(format!("Error: {}", e));
                    }
                }
                is_busy.set(false);
            });
        }
    };

    let forget_plog = move |_| {
        tracing::info!("Forget Plog button clicked");
        // The compiler insists this returns (), so we can't handle errors.
        // If it fails, it will likely panic.
        LocalStorage::delete(VLAD_STORAGE_KEY);
        tracing::info!("Deleted vlad from storage (or it didn't exist).");
        cached_vlad.set(None);
        plog_info.set("".to_string());
        status.set("Cleared cached plog. Ready to create a new one.".to_string());
    };

    rsx! {
        div { class: "space-y-4",
            if is_busy() {
                div { class: "font-medium", "Please wait..." }
            } else {
                div { class: "flex space-x-4",
                    button {
                        class: "bg-blue-500 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg shadow-md transition duration-200 disabled:bg-gray-400",
                        onclick: create_new_plog,
                        disabled: is_busy(),
                        "Create New Plog"
                    }
                    if let Some(_) = cached_vlad() {
                        button {
                            class: "bg-green-500 hover:bg-green-700 text-white font-semibold py-3 px-6 rounded-lg shadow-md transition duration-200 disabled:bg-gray-400",
                            onclick: use_existing_plog,
                            disabled: is_busy(),
                            "Use Existing Plog"
                        }
                        button {
                            class: "bg-red-500 hover:bg-red-700 text-white font-semibold py-3 px-6 rounded-lg shadow-md transition duration-200 disabled:bg-gray-400",
                            onclick: forget_plog,
                            disabled: is_busy(),
                            "Forget Plog"
                        }
                    }
                }
            }


            div { class: "mt-4 p-4 bg-gray-100 rounded",
                p { class: "font-medium", "Status: " }
                p { class: "text-sm", "{status}" }
            }

            if !plog_info().is_empty() {
                div { class: "mt-4 p-4 bg-green-100 border border-green-400 rounded",
                    h3 { class: "font-bold text-lg mb-2", "Plog Details:" }
                    pre { class: "text-xs overflow-auto", "{plog_info}" }
                }
            }
        }
    }
}

/// Creates or loads a plog and returns its info and vlad.
async fn process_plog(
    vlad: Option<String>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    tracing::info!("Processing plog...");

    let keystr = if let Some(vlad_str) = &vlad {
        Keystr::from_vlad(vlad_str).await?
    } else {
        Keystr::new().await?
    };
    let bs = keystr.bs;
    let plog = bs.plog();

    let info = format!(
        "Plog Head: {}
Vlad: {}
Entries: {}
Verification: {}",
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