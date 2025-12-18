//! CBOR parsing utilities for WebAuthn attestation objects
//! 
//! This module provides functionality to extract P256 public keys from WebAuthn
//! attestation objects, which are CBOR-encoded according to the WebAuthn spec.

use serde_cbor::Value as CborValue;

/// Extract P256 public key from WebAuthn attestation object
/// 
/// The attestation object contains an authenticator data section which includes
/// the COSE key (public key) in CBOR format.
/// 
/// For P256 (ES256), the COSE key structure is:
/// - kty (1): 2 (EC2 key type)
/// - alg (3): -7 (ES256 algorithm)
/// - crv (-1): 1 (P-256 curve)
/// - x (-2): x-coordinate (32 bytes)
/// - y (-3): y-coordinate (32 bytes)
pub fn extract_p256_public_key_from_attestation(attestation_object: &[u8]) -> Result<Vec<u8>, String> {
    // Parse CBOR attestation object
    let attestation: CborValue = 
        serde_cbor::from_slice(attestation_object)
            .map_err(|e| format!("Failed to parse attestation object: {}", e))?;
    
    // Get authData field from the map
    let auth_data = match &attestation {
        CborValue::Map(map) => {
            let auth_data_key = CborValue::Text("authData".to_string());
            match map.get(&auth_data_key) {
                Some(CborValue::Bytes(data)) => data,
                _ => return Err("Missing or invalid authData in attestation object".to_string()),
            }
        }
        _ => return Err("Attestation object is not a map".to_string()),
    };
    
    // Parse authenticator data to extract the credential public key
    extract_public_key_from_auth_data(auth_data)
}

/// Extract public key from authenticator data
/// 
/// Authenticator data structure:
/// - rpIdHash: 32 bytes
/// - flags: 1 byte
/// - signCount: 4 bytes
/// - attestedCredentialData (if AT flag is set):
///   - aaguid: 16 bytes
///   - credentialIdLength: 2 bytes (big-endian)
///   - credentialId: credentialIdLength bytes
///   - credentialPublicKey: CBOR-encoded COSE_Key
fn extract_public_key_from_auth_data(auth_data: &[u8]) -> Result<Vec<u8>, String> {
    if auth_data.len() < 37 {
        return Err("Authenticator data too short".to_string());
    }
    
    // Check if AT (Attested credential data) flag is set
    let flags = auth_data[32];
    let at_flag = (flags & 0x40) != 0;
    
    if !at_flag {
        return Err("Attested credential data flag not set".to_string());
    }
    
    // Skip rpIdHash (32 bytes), flags (1 byte), signCount (4 bytes), aaguid (16 bytes)
    let mut offset = 32 + 1 + 4 + 16;
    
    if auth_data.len() < offset + 2 {
        return Err("Authenticator data too short for credential ID length".to_string());
    }
    
    // Read credential ID length (2 bytes, big-endian)
    let cred_id_len = u16::from_be_bytes([auth_data[offset], auth_data[offset + 1]]) as usize;
    offset += 2;
    
    if auth_data.len() < offset + cred_id_len {
        return Err("Authenticator data too short for credential ID".to_string());
    }
    
    // Skip credential ID
    offset += cred_id_len;
    
    // The rest is the CBOR-encoded COSE_Key (public key)
    let cose_key_bytes = &auth_data[offset..];
    
    // Parse COSE key
    let cose_key: CborValue = 
        serde_cbor::from_slice(cose_key_bytes)
            .map_err(|e| format!("Failed to parse COSE key: {}", e))?;
    
    // Extract P256 coordinates
    extract_p256_from_cose_key(&cose_key)
}

/// Extract P256 public key bytes from COSE key structure
/// 
/// Returns the uncompressed public key format (0x04 || x || y)
fn extract_p256_from_cose_key(cose_key: &CborValue) -> Result<Vec<u8>, String> {
    // Get the map from the COSE key
    let map = match cose_key {
        CborValue::Map(m) => m,
        _ => return Err("COSE key is not a map".to_string()),
    };
    
    // Check key type (kty = 1, should be 2 for EC2)
    let kty_key = CborValue::Integer(1);
    let _kty = match map.get(&kty_key) {
        Some(CborValue::Integer(2)) => 2,
        _ => return Err("Invalid or missing key type (kty)".to_string()),
    };
    
    // Check algorithm (alg = 3, should be -7 for ES256/P-256)
    let alg_key = CborValue::Integer(3);
    let _alg = match map.get(&alg_key) {
        Some(CborValue::Integer(-7)) => -7,
        _ => return Err("Invalid or missing algorithm (alg), expected -7 for ES256".to_string()),
    };
    
    // Check curve (crv = -1, should be 1 for P-256)
    let crv_key = CborValue::Integer(-1);
    let _crv = match map.get(&crv_key) {
        Some(CborValue::Integer(1)) => 1,
        _ => return Err("Invalid or missing curve (crv), expected 1 for P-256".to_string()),
    };
    
    // Extract x coordinate (key = -2)
    let x_key = CborValue::Integer(-2);
    let x = match map.get(&x_key) {
        Some(CborValue::Bytes(bytes)) => {
            if bytes.len() != 32 {
                return Err(format!("Invalid x coordinate length: {}", bytes.len()));
            }
            bytes
        },
        _ => return Err("Missing or invalid x coordinate".to_string()),
    };
    
    // Extract y coordinate (key = -3)
    let y_key = CborValue::Integer(-3);
    let y = match map.get(&y_key) {
        Some(CborValue::Bytes(bytes)) => {
            if bytes.len() != 32 {
                return Err(format!("Invalid y coordinate length: {}", bytes.len()));
            }
            bytes
        },
        _ => return Err("Missing or invalid y coordinate".to_string()),
    };
    
    // Return uncompressed format: 0x04 || x || y (65 bytes total)
    let mut public_key = Vec::with_capacity(65);
    public_key.push(0x04); // Uncompressed point indicator
    public_key.extend_from_slice(x);
    public_key.extend_from_slice(y);
    
    Ok(public_key)
}

/// Parse WebAuthn signature format to extract raw P256 signature
/// 
/// WebAuthn signatures are in ASN.1 DER format, but P256 signatures in multicodec
/// are typically raw (r || s) format (64 bytes).
pub fn extract_p256_signature_from_der(der_sig: &[u8]) -> Result<Vec<u8>, String> {
    // Simple DER parser for ECDSA signatures
    // Format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
    
    if der_sig.len() < 8 {
        return Err("DER signature too short".to_string());
    }
    
    if der_sig[0] != 0x30 {
        return Err("Invalid DER signature format".to_string());
    }
    
    let mut offset = 2; // Skip 0x30 and total length
    
    // Parse r
    if der_sig[offset] != 0x02 {
        return Err("Invalid DER signature: expected INTEGER for r".to_string());
    }
    offset += 1;
    
    let r_len = der_sig[offset] as usize;
    offset += 1;
    
    if offset + r_len > der_sig.len() {
        return Err("DER signature truncated at r".to_string());
    }
    
    let r = &der_sig[offset..offset + r_len];
    offset += r_len;
    
    // Parse s
    if offset >= der_sig.len() || der_sig[offset] != 0x02 {
        return Err("Invalid DER signature: expected INTEGER for s".to_string());
    }
    offset += 1;
    
    let s_len = der_sig[offset] as usize;
    offset += 1;
    
    if offset + s_len > der_sig.len() {
        return Err("DER signature truncated at s".to_string());
    }
    
    let s = &der_sig[offset..offset + s_len];
    
    // Convert to raw format (32 bytes each, padding/trimming as needed)
    let mut raw_sig = Vec::with_capacity(64);
    
    // Handle r (might have leading zeros or 0x00 padding byte)
    if r.len() == 32 {
        raw_sig.extend_from_slice(r);
    } else if r.len() == 33 && r[0] == 0x00 {
        raw_sig.extend_from_slice(&r[1..]);
    } else if r.len() < 32 {
        // Pad with leading zeros
        raw_sig.extend(std::iter::repeat(0).take(32 - r.len()));
        raw_sig.extend_from_slice(r);
    } else {
        return Err(format!("Invalid r length: {}", r.len()));
    }
    
    // Handle s (might have leading zeros or 0x00 padding byte)
    if s.len() == 32 {
        raw_sig.extend_from_slice(s);
    } else if s.len() == 33 && s[0] == 0x00 {
        raw_sig.extend_from_slice(&s[1..]);
    } else if s.len() < 32 {
        // Pad with leading zeros
        raw_sig.extend(std::iter::repeat(0).take(32 - s.len()));
        raw_sig.extend_from_slice(s);
    } else {
        return Err(format!("Invalid s length: {}", s.len()));
    }
    
    Ok(raw_sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_der_signature_parsing() {
        // Example DER signature with both r and s being 32 bytes
        let der_sig = vec![
            0x30, 0x44, // SEQUENCE, 68 bytes total
            0x02, 0x20, // INTEGER, 32 bytes (r)
            // r value (32 bytes of example data)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
            0x02, 0x20, // INTEGER, 32 bytes (s)
            // s value (32 bytes of example data)
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
        ];
        
        let raw_sig = extract_p256_signature_from_der(&der_sig).unwrap();
        assert_eq!(raw_sig.len(), 64);
        assert_eq!(raw_sig[0], 0x01);
        assert_eq!(raw_sig[31], 0x20);
        assert_eq!(raw_sig[32], 0x21);
        assert_eq!(raw_sig[63], 0x40);
    }
}
