use base64ct::{Base64UrlUnpadded, Encoding};
use ciborium::Value as CborValue;

use crate::error::KdfError;

#[cfg(target_arch = "wasm32")]
macro_rules! console_log {
    ($($t:tt)*) => (crate::log(&format_args!($($t)*).to_string()))
}

#[cfg(not(target_arch = "wasm32"))]
macro_rules! console_log {
    ($($t:tt)*) => (eprintln!("[LOG] {}", format_args!($($t)*)))
}

/// Helper function for base64url decoding
fn base64_url_decode(input: &str) -> Result<Vec<u8>, KdfError> {
    Base64UrlUnpadded::decode_vec(input)
        .map_err(|e| KdfError::Base64DecodeError(format!("{:?}", e)))
}

/// Parse WebAuthn attestation object to extract authData
pub fn parse_attestation_object(attestation_object_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let cbor_value: CborValue = ciborium::from_reader(attestation_object_bytes)
        .map_err(|e| format!("Failed to parse CBOR: {}", e))?;

    if let CborValue::Map(map) = cbor_value {
        // Extract authData (required)
        for (key, value) in map.iter() {
            if let CborValue::Text(key_str) = key {
                if key_str == "authData" {
                    if let CborValue::Bytes(auth_data_bytes) = value {
                        return Ok(auth_data_bytes.clone());
                    }
                }
            }
        }
        Err("authData not found in attestation object".to_string())
    } else {
        Err("Attestation object is not a CBOR map".to_string())
    }
}

/// Parse authenticator data to extract COSE public key
pub fn parse_authenticator_data(auth_data_bytes: &[u8]) -> Result<Vec<u8>, String> {
    if auth_data_bytes.len() < 37 {
        return Err("Authenticator data too short".to_string());
    }

    let flags = auth_data_bytes[32];

    // Check if attested credential data is present (AT flag = bit 6)
    if (flags & 0x40) == 0 {
        return Err("No attested credential data present".to_string());
    }

    let mut offset = 37; // Skip rpIdHash(32) + flags(1) + counter(4)

    // Skip AAGUID (16 bytes)
    if auth_data_bytes.len() < offset + 16 {
        return Err("Authenticator data too short for AAGUID".to_string());
    }
    offset += 16;

    // Get credential ID length (2 bytes, big-endian)
    if auth_data_bytes.len() < offset + 2 {
        return Err("Authenticator data too short for credential ID length".to_string());
    }
    let cred_id_length = u16::from_be_bytes([
        auth_data_bytes[offset],
        auth_data_bytes[offset + 1]
    ]) as usize;
    offset += 2;

    // Skip credential ID
    if auth_data_bytes.len() < offset + cred_id_length {
        return Err("Authenticator data too short for credential ID".to_string());
    }
    offset += cred_id_length;

    // The rest is the credential public key (COSE format)
    let credential_public_key = auth_data_bytes[offset..].to_vec();
    Ok(credential_public_key)
}

/// Extract P-256 coordinates from COSE key
pub fn extract_p256_coordinates_from_cose(cose_key_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cbor_value: CborValue = ciborium::from_reader(cose_key_bytes)
        .map_err(|e| format!("Failed to parse COSE key CBOR: {}", e))?;

    if let CborValue::Map(map) = cbor_value {
        let mut kty: Option<i128> = None;
        let mut alg: Option<i128> = None;
        let mut crv: Option<i128> = None;
        let mut x_coord = None;
        let mut y_coord = None;

        // Parse COSE key parameters
        for (key, value) in map.iter() {
            if let CborValue::Integer(key_int) = key {
                let key_val: i128 = (*key_int).into(); // Convert Integer to i128
                match key_val {
                    1 => { // kty (Key Type)
                        if let CborValue::Integer(val) = value {
                            kty = Some((*val).into());
                        }
                    }
                    3 => { // alg (Algorithm)
                        if let CborValue::Integer(val) = value {
                            alg = Some((*val).into());
                        }
                    }
                    -1 => { // crv (Curve) for EC2
                        if let CborValue::Integer(val) = value {
                            crv = Some((*val).into());
                        }
                    }
                    -2 => { // x coordinate for EC2
                        if let CborValue::Bytes(bytes) = value {
                            x_coord = Some(bytes.clone());
                        }
                    }
                    -3 => { // y coordinate for EC2
                        if let CborValue::Bytes(bytes) = value {
                            y_coord = Some(bytes.clone());
                        }
                    }
                    _ => {}
                }
            }
        }

        // Validate this is a P-256 key
        if kty != Some(2) {
            return Err(format!("Unsupported key type: {:?} (expected 2 for EC2)", kty));
        }
        if alg != Some(-7) {
            return Err(format!("Unsupported algorithm: {:?} (expected -7 for ES256)", alg));
        }
        if crv != Some(1) {
            return Err(format!("Unsupported curve: {:?} (expected 1 for P-256)", crv));
        }

        match (x_coord, y_coord) {
            (Some(x), Some(y)) => {
                if x.len() != 32 || y.len() != 32 {
                    return Err(format!("Invalid coordinate length: x={}, y={} (expected 32 each)", x.len(), y.len()));
                }
                Ok((x, y))
            }
            _ => Err("Missing x or y coordinate in COSE key".to_string())
        }
    } else {
        Err("COSE key is not a CBOR map".to_string())
    }
}

/// Extract COSE public key from WebAuthn attestation object
pub fn extract_cose_public_key_from_attestation_core(attestation_object_b64u: &str) -> Result<Vec<u8>, String> {
    console_log!("RUST: Extracting COSE public key from attestation object");

    // Decode the base64url attestation object
    let attestation_object_bytes = base64_url_decode(attestation_object_b64u)
        .map_err(|e| format!("Failed to decode attestation object: {:?}", e))?;

    // Parse the attestation object to get authData
    let auth_data_bytes = parse_attestation_object(&attestation_object_bytes)?;

    // Extract the COSE public key from authenticator data
    let cose_public_key_bytes = parse_authenticator_data(&auth_data_bytes)?;

    console_log!("RUST: Successfully extracted COSE public key ({} bytes)", cose_public_key_bytes.len());
    Ok(cose_public_key_bytes)
}

/// Validate COSE key format and return information
pub fn validate_cose_key_format_core(cose_key_bytes: &[u8]) -> Result<String, String> {
    console_log!("RUST: Validating COSE key format");

    let cbor_value: CborValue = ciborium::from_reader(cose_key_bytes)
        .map_err(|e| format!("Failed to parse COSE key CBOR: {}", e))?;

    if let CborValue::Map(map) = cbor_value {
        let mut kty: Option<i128> = None;
        let mut alg: Option<i128> = None;
        let mut crv: Option<i128> = None;

        // Parse COSE key parameters
        for (key, value) in map.iter() {
            if let CborValue::Integer(key_int) = key {
                let key_val: i128 = (*key_int).into();
                match key_val {
                    1 => { // kty (Key Type)
                        if let CborValue::Integer(val) = value {
                            kty = Some((*val).into());
                        }
                    }
                    3 => { // alg (Algorithm)
                        if let CborValue::Integer(val) = value {
                            alg = Some((*val).into());
                        }
                    }
                    -1 => { // crv (Curve) for EC2
                        if let CborValue::Integer(val) = value {
                            crv = Some((*val).into());
                        }
                    }
                    _ => {}
                }
            }
        }

        let info = format!(
            r#"{{"kty": {:?}, "alg": {:?}, "crv": {:?}, "valid": {}}}"#,
            kty,
            alg,
            crv,
            kty.is_some() && alg.is_some()
        );

        console_log!("RUST: COSE key validation result: {}", info);
        Ok(info)
    } else {
        Err("COSE key is not a CBOR map".to_string())
    }
}