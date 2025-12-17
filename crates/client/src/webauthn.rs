//! Some references to webauthn functionality
//! This module provides WebAuthn functionality for WASM applications.
use js_sys::{JSON, Object, Reflect, Uint8Array};
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, CredentialCreationOptions,
    CredentialRequestOptions, CredentialsContainer, PublicKeyCredential,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
};

// Helper to get the `credentials` object from the `navigator`.
fn credentials() -> Result<CredentialsContainer, JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
    Ok(window.navigator().credentials())
}

/// Creates a JsValue from a serde_json::Value, converting base64url strings
/// to ArrayBuffers where required by the WebAuthn API.
fn build_credential_options(options: &serde_json::Value) -> Result<JsValue, JsValue> {
    let obj = Object::new();

    if let Some(challenge_str) = options["challenge"].as_str() {
        let buffer: JsValue = base64_to_array_buffer(challenge_str)?.into();
        Reflect::set(&obj, &"challenge".into(), &buffer)?;
    }
    if let Some(user) = options["user"].as_object() {
        let user_obj = Object::new();
        if let Some(id_str) = user["id"].as_str() {
            let buffer: JsValue = base64_to_array_buffer(id_str)?.into();
            Reflect::set(&user_obj, &"id".into(), &buffer)?;
        }
        if let Some(name) = user["name"].as_str() {
            Reflect::set(&user_obj, &"name".into(), &name.into())?;
        }
        if let Some(display_name) = user["displayName"].as_str() {
            Reflect::set(&user_obj, &"displayName".into(), &display_name.into())?;
        }
        Reflect::set(&obj, &"user".into(), &user_obj)?;
    }

    if let Some(allow_credentials) = options["allowCredentials"].as_array() {
        let creds_array = js_sys::Array::new();
        for cred_val in allow_credentials {
            let cred_obj = Object::new();
            if let Some(id_str) = cred_val["id"].as_str() {
                let buffer: JsValue = base64_to_array_buffer(id_str)?.into();
                Reflect::set(&cred_obj, &"id".into(), &buffer)?;
            }
            if let Some(cred_type) = cred_val["type"].as_str() {
                Reflect::set(&cred_obj, &"type".into(), &cred_type.into())?;
            }
            creds_array.push(&cred_obj);
        }
        Reflect::set(&obj, &"allowCredentials".into(), &creds_array)?;
    }

    // Copy other properties directly
    if let Some(options_obj) = options.as_object() {
        for (key, value) in options_obj {
            if obj.has_own_property(&key.as_str().into()) {
                continue;
            }
            Reflect::set(&obj, &key.as_str().into(), &json_to_js_value(value)?)?;
        }
    }

    Ok(obj.into())
}

fn json_to_js_value(json: &serde_json::Value) -> Result<JsValue, JsValue> {
    JSON::parse(&json.to_string())
}

/// Wraps navigator.credentials.create()
pub async fn create_credential(options_str: &str) -> Result<String, JsValue> {
    tracing::info!("Starting create_credential");
    let options: serde_json::Value =
        serde_json::from_str(options_str).map_err(|e| e.to_string())?;

    let pub_key_opts_js = build_credential_options(&options["publicKey"])?;
    let pub_key_opts: PublicKeyCredentialCreationOptions = pub_key_opts_js.into();

    let creation_options = CredentialCreationOptions::new();
    creation_options.set_public_key(&pub_key_opts);

    let promise = credentials()?.create_with_options(&creation_options)?;
    let result = JsFuture::from(promise).await?;
    tracing::info!("Credential created");

    let cred: PublicKeyCredential = result.dyn_into()?;
    let attestation_response: AuthenticatorAttestationResponse = cred.response().dyn_into()?;

    let json_result = serde_json::json!({
        "id": cred.id(),
        "rawId": buffer_to_base64_url(&cred.raw_id()),
        "type": cred.type_(),
        "response": {
            "clientDataJSON": buffer_to_base64_url(&attestation_response.client_data_json()),
            "attestationObject": buffer_to_base64_url(&attestation_response.attestation_object()),
        }
    });

    Ok(json_result.to_string())
}

/// Wraps navigator.credentials.get()
pub async fn get_credential(options_str: &str) -> Result<String, JsValue> {
    tracing::info!("Starting get_credential");
    let options: serde_json::Value =
        serde_json::from_str(options_str).map_err(|e| e.to_string())?;

    let pub_key_opts_js = build_credential_options(&options["publicKey"])?;
    let pub_key_opts: PublicKeyCredentialRequestOptions = pub_key_opts_js.into();

    let request_options = CredentialRequestOptions::new();
    request_options.set_public_key(&pub_key_opts);

    let promise = credentials()?.get_with_options(&request_options)?;
    let result = JsFuture::from(promise).await?;
    tracing::info!("Credential retrieved");

    let cred: PublicKeyCredential = result.dyn_into()?;
    let assertion_response: AuthenticatorAssertionResponse = cred.response().dyn_into()?;

    let user_handle = assertion_response
        .user_handle()
        .map(|uh| buffer_to_base64_url(&uh));

    let json_result = serde_json::json!({
        "id": cred.id(),
        "rawId": buffer_to_base64_url(&cred.raw_id()),
        "type": cred.type_(),
        "response": {
            "clientDataJSON": buffer_to_base64_url(&assertion_response.client_data_json()),
            "authenticatorData": buffer_to_base64_url(&assertion_response.authenticator_data()),
            "signature": buffer_to_base64_url(&assertion_response.signature()),
            "userHandle": user_handle,
        }
    });

    Ok(json_result.to_string())
}

// Convert ArrayBuffer to base64_url string
fn buffer_to_base64_url(buffer: &js_sys::ArrayBuffer) -> String {
    let bytes = Uint8Array::new(buffer).to_vec();
    base64_url::encode(&bytes)
}

// Convert base64_url string to ArrayBuffer
fn base64_to_array_buffer(base64_url_str: &str) -> Result<js_sys::ArrayBuffer, JsValue> {
    let bytes = base64_url::decode(base64_url_str).map_err(|e| e.to_string())?;
    let uint8_array = Uint8Array::from(&bytes[..]);
    Ok(uint8_array.buffer())
}

/// Check if the browser supports conditional mediation (autofill UI)
/// This allows passkeys to be displayed in password autofill fields
pub async fn is_conditional_mediation_available() -> Result<bool, JsValue> {
    let creds = credentials()?;

    // Check if the method exists
    let has_method = js_sys::Reflect::has(&creds, &"isConditionalMediationAvailable".into())?;
    if !has_method {
        return Ok(false);
    }

    // Call the method
    let method = js_sys::Reflect::get(&creds, &"isConditionalMediationAvailable".into())?;
    let func = method.dyn_into::<js_sys::Function>()?;
    let promise = func.call0(&creds)?;
    let result = JsFuture::from(js_sys::Promise::from(promise)).await?;

    Ok(result.as_bool().unwrap_or(false))
}

/// Try to authenticate using discoverable credentials (resident keys)
/// This allows authentication without knowing the credential ID in advance.
/// If allowCredentials is empty, the browser will show all available credentials
/// for this domain (if they are resident/discoverable keys).
pub async fn get_credential_discoverable(challenge_b64: &str) -> Result<String, JsValue> {
    tracing::info!("Starting discoverable credential authentication");

    let challenge_buffer = base64_to_array_buffer(challenge_b64)?;

    // Create minimal request options with empty allowCredentials
    // This tells the browser to show ALL available credentials for this RP
    let pub_key_opts = PublicKeyCredentialRequestOptions::new(&challenge_buffer);

    // Set user verification to preferred (will use biometrics if available)
    pub_key_opts.set_user_verification(web_sys::UserVerificationRequirement::Preferred);

    let request_options = CredentialRequestOptions::new();
    request_options.set_public_key(&pub_key_opts);

    // Optionally enable conditional mediation for autofill UI
    // request_options.set_mediation(web_sys::CredentialMediationRequirement::Conditional);

    let promise = credentials()?.get_with_options(&request_options)?;
    let result = JsFuture::from(promise).await?;
    tracing::info!("Discoverable credential retrieved");

    let cred: PublicKeyCredential = result.dyn_into()?;
    let assertion_response: AuthenticatorAssertionResponse = cred.response().dyn_into()?;

    let user_handle = assertion_response
        .user_handle()
        .map(|uh| buffer_to_base64_url(&uh));

    let json_result = serde_json::json!({
        "id": cred.id(),
        "rawId": buffer_to_base64_url(&cred.raw_id()),
        "type": cred.type_(),
        "response": {
            "clientDataJSON": buffer_to_base64_url(&assertion_response.client_data_json()),
            "authenticatorData": buffer_to_base64_url(&assertion_response.authenticator_data()),
            "signature": buffer_to_base64_url(&assertion_response.signature()),
            "userHandle": user_handle,
        }
    });

    Ok(json_result.to_string())
}

/// Start a conditional mediation request for passkey autofill integration.
/// This enables passkeys to appear in the browser's autofill dropdown when
/// a user interacts with an input field that has autocomplete="username webauthn".
///
/// This should be called when the page loads to set up the autofill listener.
/// The returned future will resolve when the user selects a passkey from the
/// autofill dropdown.
///
/// # Arguments
/// * `options_str` - JSON string containing the publicKey credential request options
///
/// # Returns
/// A JSON string containing the selected credential and authentication response
pub async fn start_conditional_autofill(options_str: &str) -> Result<String, JsValue> {
    tracing::info!("Starting conditional mediation for autofill UI");

    let options: serde_json::Value =
        serde_json::from_str(options_str).map_err(|e| e.to_string())?;

    let pub_key_opts_js = build_credential_options(&options["publicKey"])?;
    let pub_key_opts: PublicKeyCredentialRequestOptions = pub_key_opts_js.into();

    let request_options = CredentialRequestOptions::new();
    request_options.set_public_key(&pub_key_opts);

    // Enable conditional mediation using Reflect since web-sys doesn't expose the enum yet
    // This makes the credential request integrate with the browser's autofill UI
    Reflect::set(&request_options, &"mediation".into(), &"conditional".into())?;

    // This promise will resolve when user selects a passkey from autofill dropdown
    let promise = credentials()?.get_with_options(&request_options)?;
    let result = JsFuture::from(promise).await?;
    tracing::info!("Conditional credential retrieved from autofill");

    let cred: PublicKeyCredential = result.dyn_into()?;
    let assertion_response: AuthenticatorAssertionResponse = cred.response().dyn_into()?;

    let user_handle = assertion_response
        .user_handle()
        .map(|uh| buffer_to_base64_url(&uh));

    let json_result = serde_json::json!({
        "id": cred.id(),
        "rawId": buffer_to_base64_url(&cred.raw_id()),
        "type": cred.type_(),
        "response": {
            "clientDataJSON": buffer_to_base64_url(&assertion_response.client_data_json()),
            "authenticatorData": buffer_to_base64_url(&assertion_response.authenticator_data()),
            "signature": buffer_to_base64_url(&assertion_response.signature()),
            "userHandle": user_handle,
        }
    });

    Ok(json_result.to_string())
}
