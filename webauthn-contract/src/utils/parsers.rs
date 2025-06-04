use serde_cbor::Value as CborValue;

#[derive(Debug)]
pub struct AttestedCredentialData {
    pub(crate) aaguid: Vec<u8>,
    pub(crate) credential_id: Vec<u8>,
    pub(crate) credential_public_key: Vec<u8>,
}

#[derive(Debug)]
pub struct AuthenticatorData {
    pub(crate) rp_id_hash: Vec<u8>,
    pub(crate) flags: u8,
    pub(crate) counter: u32,
    pub(crate) attested_credential_data: Option<AttestedCredentialData>,
}

pub fn parse_attestation_object(
    attestation_object: &CborValue
) -> Result<(Vec<u8>, CborValue, String), String> {
    if let CborValue::Map(map) = attestation_object {
        // Extract authData (required)
        let auth_data = map
            .get(&CborValue::Text("authData".to_string()))
            .ok_or("Missing authData in attestation object")?;

        let auth_data_bytes = if let CborValue::Bytes(bytes) = auth_data {
            bytes.clone()
        } else {
            return Err("authData must be bytes".to_string());
        };

        // Extract fmt (required)
        let fmt = map
            .get(&CborValue::Text("fmt".to_string()))
            .ok_or("Missing fmt in attestation object")?;

        let fmt_string = if let CborValue::Text(s) = fmt {
            s.clone()
        } else {
            return Err("fmt must be text".to_string());
        };

        // Extract attStmt (required)
        let att_stmt = map
            .get(&CborValue::Text("attStmt".to_string()))
            .ok_or("Missing attStmt in attestation object")?
            .clone();

        Ok((auth_data_bytes, att_stmt, fmt_string))
    } else {
        Err("Attestation object must be a CBOR map".to_string())
    }
}

pub fn parse_authenticator_data(auth_data_bytes: &[u8]) -> Result<AuthenticatorData, String> {
    if auth_data_bytes.len() < 37 {
        return Err("Authenticator data too short".to_string());
    }

    // Parse fixed-length portion
    let rp_id_hash = auth_data_bytes[0..32].to_vec();
    let flags = auth_data_bytes[32];
    let counter = u32::from_be_bytes([
        auth_data_bytes[33],
        auth_data_bytes[34],
        auth_data_bytes[35],
        auth_data_bytes[36],
    ]);

    let mut offset = 37;
    let mut attested_credential_data = None;

    // Check if attested credential data is present (AT flag = bit 6)
    if (flags & 0x40) != 0 {
        if auth_data_bytes.len() < offset + 18 {
            return Err("Authenticator data too short for attested credential data".to_string());
        }

        // Parse attested credential data
        let aaguid = auth_data_bytes[offset..offset + 16].to_vec();
        offset += 16;

        let credential_id_length =
            u16::from_be_bytes([auth_data_bytes[offset], auth_data_bytes[offset + 1]]) as usize;
        offset += 2;

        if auth_data_bytes.len() < offset + credential_id_length {
            return Err("Authenticator data too short for credential ID".to_string());
        }

        let credential_id = auth_data_bytes[offset..offset + credential_id_length].to_vec();
        offset += credential_id_length;

        // The rest is the credential public key (COSE format)
        let credential_public_key = auth_data_bytes[offset..].to_vec();

        attested_credential_data = Some(AttestedCredentialData {
            aaguid,
            credential_id,
            credential_public_key,
        });
    }

    Ok(AuthenticatorData {
        rp_id_hash,
        flags,
        counter,
        attested_credential_data,
    })
}
