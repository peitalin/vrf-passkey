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

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value as CborValue;

    /// Helper function to create a mock COSE P-256 key
    fn create_mock_cose_p256_key() -> Vec<u8> {
        let mut cose_key_vec = Vec::new();

        // kty: 2 (EC2)
        cose_key_vec.push((CborValue::Integer(1.into()), CborValue::Integer(2.into())));

        // alg: -7 (ES256)
        cose_key_vec.push((CborValue::Integer(3.into()), CborValue::Integer((-7).into())));

        // crv: 1 (P-256)
        cose_key_vec.push((CborValue::Integer((-1).into()), CborValue::Integer(1.into())));

        // x coordinate (32 bytes)
        let x_coord = vec![0x42u8; 32];
        cose_key_vec.push((CborValue::Integer((-2).into()), CborValue::Bytes(x_coord)));

        // y coordinate (32 bytes)
        let y_coord = vec![0x84u8; 32];
        cose_key_vec.push((CborValue::Integer((-3).into()), CborValue::Bytes(y_coord)));

        let cose_key = CborValue::Map(cose_key_vec);

        let mut buffer = Vec::new();
        ciborium::into_writer(&cose_key, &mut buffer).unwrap();
        buffer
    }

    /// Helper function to create a mock WebAuthn attestation object
    fn create_mock_attestation_object() -> Vec<u8> {
        // Create mock authenticator data
        let mut auth_data = Vec::new();

        // rpIdHash (32 bytes)
        auth_data.extend_from_slice(&[0x00u8; 32]);

        // flags (1 byte) - set AT flag (bit 6) to indicate attested credential data
        auth_data.push(0x40);

        // counter (4 bytes)
        auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

        // AAGUID (16 bytes)
        auth_data.extend_from_slice(&[0x11u8; 16]);

        // Credential ID length (2 bytes, big-endian)
        let cred_id = vec![0x22u8; 16];
        auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());

        // Credential ID
        auth_data.extend_from_slice(&cred_id);

        // Credential public key (COSE format)
        let cose_key = create_mock_cose_p256_key();
        auth_data.extend_from_slice(&cose_key);

        // Convert to CBOR map with Vec format
        let mut cbor_vec = Vec::new();
        cbor_vec.push((CborValue::Text("authData".to_string()), CborValue::Bytes(auth_data)));
        cbor_vec.push((CborValue::Text("fmt".to_string()), CborValue::Text("none".to_string())));
        cbor_vec.push((CborValue::Text("attStmt".to_string()), CborValue::Map(Vec::new())));

        let cbor_attestation = CborValue::Map(cbor_vec);

        let mut buffer = Vec::new();
        ciborium::into_writer(&cbor_attestation, &mut buffer).unwrap();
        buffer
    }

    #[test]
    fn test_base64_url_decode() {
        // Test valid base64url strings
        let result = base64_url_decode("SGVsbG8gV29ybGQ").unwrap();
        assert_eq!(result, b"Hello World");

        let result = base64_url_decode("SGVsbG8gV29ybGQh").unwrap();
        assert_eq!(result, b"Hello World!");

        // Test with padding
        let result = base64_url_decode("SGVsbG8").unwrap();
        assert_eq!(result, b"Hello");

        // Test invalid base64 - this should fail gracefully
        let result = base64_url_decode("Invalid!!!Base64");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_p256_coordinates_from_cose() {
        let cose_key_bytes = create_mock_cose_p256_key();
        let (x_coord, y_coord) = extract_p256_coordinates_from_cose(&cose_key_bytes).unwrap();

        assert_eq!(x_coord.len(), 32);
        assert_eq!(y_coord.len(), 32);
        assert_eq!(x_coord, vec![0x42u8; 32]);
        assert_eq!(y_coord, vec![0x84u8; 32]);
    }

    #[test]
    fn test_extract_p256_coordinates_invalid_key_type() {
        // Create COSE key with wrong key type
        let mut cose_key_vec = Vec::new();
        cose_key_vec.push((CborValue::Integer(1.into()), CborValue::Integer(1.into()))); // kty: 1 (OKP, not EC2)
        cose_key_vec.push((CborValue::Integer(3.into()), CborValue::Integer((-7).into()))); // alg: -7 (ES256)

        let cose_key = CborValue::Map(cose_key_vec);
        let mut buffer = Vec::new();
        ciborium::into_writer(&cose_key, &mut buffer).unwrap();

        let result = extract_p256_coordinates_from_cose(&buffer);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported key type"));
    }

    #[test]
    fn test_extract_p256_coordinates_invalid_algorithm() {
        // Create COSE key with wrong algorithm
        let mut cose_key_vec = Vec::new();
        cose_key_vec.push((CborValue::Integer(1.into()), CborValue::Integer(2.into()))); // kty: 2 (EC2)
        cose_key_vec.push((CborValue::Integer(3.into()), CborValue::Integer((-8).into()))); // alg: -8 (EdDSA, not ES256)

        let cose_key = CborValue::Map(cose_key_vec);
        let mut buffer = Vec::new();
        ciborium::into_writer(&cose_key, &mut buffer).unwrap();

        let result = extract_p256_coordinates_from_cose(&buffer);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported algorithm"));
    }

    #[test]
    fn test_extract_p256_coordinates_invalid_curve() {
        // Create COSE key with wrong curve
        let mut cose_key_vec = Vec::new();
        cose_key_vec.push((CborValue::Integer(1.into()), CborValue::Integer(2.into()))); // kty: 2 (EC2)
        cose_key_vec.push((CborValue::Integer(3.into()), CborValue::Integer((-7).into()))); // alg: -7 (ES256)
        cose_key_vec.push((CborValue::Integer((-1).into()), CborValue::Integer(2.into()))); // crv: 2 (P-384, not P-256)

        let cose_key = CborValue::Map(cose_key_vec);
        let mut buffer = Vec::new();
        ciborium::into_writer(&cose_key, &mut buffer).unwrap();

        let result = extract_p256_coordinates_from_cose(&buffer);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported curve"));
    }

    #[test]
    fn test_extract_p256_coordinates_missing_coordinates() {
        // Create COSE key without x,y coordinates
        let mut cose_key_vec = Vec::new();
        cose_key_vec.push((CborValue::Integer(1.into()), CborValue::Integer(2.into()))); // kty: 2 (EC2)
        cose_key_vec.push((CborValue::Integer(3.into()), CborValue::Integer((-7).into()))); // alg: -7 (ES256)
        cose_key_vec.push((CborValue::Integer((-1).into()), CborValue::Integer(1.into()))); // crv: 1 (P-256)
        // Missing x (-2) and y (-3) coordinates

        let cose_key = CborValue::Map(cose_key_vec);
        let mut buffer = Vec::new();
        ciborium::into_writer(&cose_key, &mut buffer).unwrap();

        let result = extract_p256_coordinates_from_cose(&buffer);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing x or y coordinate"));
    }

    #[test]
    fn test_extract_p256_coordinates_invalid_coordinate_length() {
        // Create COSE key with wrong coordinate lengths
        let mut cose_key_vec = Vec::new();
        cose_key_vec.push((CborValue::Integer(1.into()), CborValue::Integer(2.into()))); // kty: 2 (EC2)
        cose_key_vec.push((CborValue::Integer(3.into()), CborValue::Integer((-7).into()))); // alg: -7 (ES256)
        cose_key_vec.push((CborValue::Integer((-1).into()), CborValue::Integer(1.into()))); // crv: 1 (P-256)

        // Wrong coordinate lengths (should be 32 bytes each)
        let x_coord = vec![0x42u8; 31]; // Wrong length
        let y_coord = vec![0x84u8; 33]; // Wrong length
        cose_key_vec.push((CborValue::Integer((-2).into()), CborValue::Bytes(x_coord)));
        cose_key_vec.push((CborValue::Integer((-3).into()), CborValue::Bytes(y_coord)));

        let cose_key = CborValue::Map(cose_key_vec);
        let mut buffer = Vec::new();
        ciborium::into_writer(&cose_key, &mut buffer).unwrap();

        let result = extract_p256_coordinates_from_cose(&buffer);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid coordinate length"));
    }

    #[test]
    fn test_parse_attestation_object() {
        let attestation_object_bytes = create_mock_attestation_object();
        let auth_data = parse_attestation_object(&attestation_object_bytes).unwrap();

        // Verify auth data structure
        assert!(auth_data.len() > 37); // Minimum size for valid auth data

        // Check flags byte (should have AT flag set)
        assert_eq!(auth_data[32] & 0x40, 0x40); // AT flag set
    }

    #[test]
    fn test_parse_attestation_object_invalid_cbor() {
        let invalid_cbor = vec![0xFF, 0xFF, 0xFF]; // Invalid CBOR
        let result = parse_attestation_object(&invalid_cbor);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse CBOR"));
    }

    #[test]
    fn test_parse_attestation_object_missing_auth_data() {
        // Create attestation object without authData
        let mut cbor_vec = Vec::new();
        cbor_vec.push((CborValue::Text("fmt".to_string()), CborValue::Text("none".to_string())));
        cbor_vec.push((CborValue::Text("attStmt".to_string()), CborValue::Map(Vec::new())));
        // Missing authData

        let cbor_attestation = CborValue::Map(cbor_vec);
        let mut buffer = Vec::new();
        ciborium::into_writer(&cbor_attestation, &mut buffer).unwrap();

        let result = parse_attestation_object(&buffer);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("authData not found"));
    }

    #[test]
    fn test_parse_authenticator_data() {
        let attestation_object_bytes = create_mock_attestation_object();
        let auth_data = parse_attestation_object(&attestation_object_bytes).unwrap();

        let cose_public_key = parse_authenticator_data(&auth_data).unwrap();
        assert!(!cose_public_key.is_empty());

        // Verify it's a valid COSE key by extracting coordinates
        let (x_coord, y_coord) = extract_p256_coordinates_from_cose(&cose_public_key).unwrap();
        assert_eq!(x_coord.len(), 32);
        assert_eq!(y_coord.len(), 32);
    }

    #[test]
    fn test_parse_authenticator_data_too_short() {
        let short_auth_data = vec![0x00u8; 36]; // Too short (< 37 bytes)
        let result = parse_authenticator_data(&short_auth_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Authenticator data too short"));
    }

    #[test]
    fn test_parse_authenticator_data_no_attested_credential() {
        // Create auth data without AT flag
        let mut auth_data = vec![0x00u8; 37];
        auth_data[32] = 0x00; // flags byte without AT flag

        let result = parse_authenticator_data(&auth_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No attested credential data present"));
    }

    #[test]
    fn test_validate_cose_key_format_core() {
        let cose_key_bytes = create_mock_cose_p256_key();
        let result = validate_cose_key_format_core(&cose_key_bytes);
        assert!(result.is_ok());

        let validation_info = result.unwrap();
        assert!(validation_info.contains("valid"));
        assert!(validation_info.contains("true"));
    }

    #[test]
    fn test_validate_cose_key_format_invalid() {
        // Create COSE key with missing required fields
        let mut cose_key_vec = Vec::new();
        cose_key_vec.push((CborValue::Integer(1.into()), CborValue::Integer(2.into()))); // kty only
        // Missing alg

        let cose_key = CborValue::Map(cose_key_vec);
        let mut buffer = Vec::new();
        ciborium::into_writer(&cose_key, &mut buffer).unwrap();

        let result = validate_cose_key_format_core(&buffer);
        assert!(result.is_ok());

        let validation_info = result.unwrap();
        assert!(validation_info.contains("valid"));
        assert!(validation_info.contains("false"));
    }

    #[test]
    fn test_validate_cose_key_format_not_cbor_map() {
        // Create CBOR that's not a map
        let cbor_array = CborValue::Array(vec![CborValue::Integer(1.into())]);
        let mut buffer = Vec::new();
        ciborium::into_writer(&cbor_array, &mut buffer).unwrap();

        let result = validate_cose_key_format_core(&buffer);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("COSE key is not a CBOR map"));
    }

    #[test]
    fn test_extract_cose_public_key_from_attestation_core() {
        // Create a mock attestation object and encode to base64url
        let attestation_object_bytes = create_mock_attestation_object();
        let attestation_object_b64u = Base64UrlUnpadded::encode_string(&attestation_object_bytes);

        let cose_key_bytes = extract_cose_public_key_from_attestation_core(&attestation_object_b64u).unwrap();

        // Verify it's a valid COSE key
        let (x_coord, y_coord) = extract_p256_coordinates_from_cose(&cose_key_bytes).unwrap();
        assert_eq!(x_coord, vec![0x42u8; 32]);
        assert_eq!(y_coord, vec![0x84u8; 32]);
    }

    #[test]
    fn test_extract_cose_public_key_invalid_base64() {
        let invalid_b64 = "Invalid@Base64!";
        let result = extract_cose_public_key_from_attestation_core(invalid_b64);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to decode attestation object"));
    }

    #[test]
    fn test_cbor_not_a_map_error() {
        // Test with CBOR that's not a map
        let cbor_array = CborValue::Array(vec![CborValue::Integer(1.into())]);
        let mut buffer = Vec::new();
        ciborium::into_writer(&cbor_array, &mut buffer).unwrap();

        let result = extract_p256_coordinates_from_cose(&buffer);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("COSE key is not a CBOR map"));
    }
}