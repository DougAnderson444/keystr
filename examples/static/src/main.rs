//! Static website which allows users to create and use plogs.
use dioxus::{logger::tracing, prelude::*};
use keystr_client::Keystr;

const FAVICON: Asset = asset!("/assets/favicon.ico");
const MAIN_CSS: Asset = asset!("/assets/main.css");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

fn main() {
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
        NewPlog {}
    }
}

/// New user create Plog component
/// Just a button that calls the client side plog creation function
#[component]
pub fn NewPlog() -> Element {
    let create_plog = |_| {
        // Call client side plog creation function
        // This is just a placeholder
        tracing::info!("Create Plog button clicked");
        let keystr = Keystr::new();
    };

    rsx! {
        button {
            class: "bg-blue-500 hover:bg-blue-700 text-white font-semi-bold py-2 px-4 rounded",
            onclick: create_plog,
            "Create New Plog"
        }
    }
}
