

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)]
pub struct RpEntity {
    pub name: String,
    pub id: String,
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)]
pub struct UserEntity {
    pub id: String, // base64url encoded Vec<u8>
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)]
pub struct PubKeyCredParam {
    pub alg: i32,
    #[serde(rename = "type")]
    pub type_: String,
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)]
pub enum AuthenticatorTransport {
    #[serde(rename = "usb")]
    Usb,
    #[serde(rename = "nfc")]
    Nfc,
    #[serde(rename = "ble")]
    Ble,
    #[serde(rename = "internal")]
    Internal,
    #[serde(rename = "hybrid")]
    Hybrid,
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, Default, PartialEq)] // Added PartialEq
pub struct PublicKeyCredentialDescriptorJSON {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String, // base64url encoded
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)] // Added PartialEq
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "residentKey")]
    pub resident_key: Option<String>,
    #[serde(rename = "requireResidentKey")]
    pub require_resident_key: Option<bool>,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

// Default matches JS `defaultAuthenticatorSelection` + `requireResidentKey` logic
impl Default for AuthenticatorSelectionCriteria {
    fn default() -> Self {
        Self {
            // JS doesn't set this by default unless preferredAuthenticatorType is used
            authenticator_attachment: None,
            resident_key: Some("preferred".to_string()),
            require_resident_key: Some(false),
            // JS default for requireResidentKey is false if residentKey is 'preferred'
            user_verification: Some("preferred".to_string()),
        }
    }
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)] // Added PartialEq
pub struct AuthenticationExtensionsClientInputsJSON {
    #[serde(rename = "credProps")]
    pub cred_props: Option<bool>,
}

impl Default for AuthenticationExtensionsClientInputsJSON {
    fn default() -> Self {
        Self {
            cred_props: Some(true), // JS sets this to true
        }
    }
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)]
pub struct PublicKeyCredentialCreationOptionsJSON {
    pub challenge: String,
    pub rp: RpEntity,
    pub user: UserEntity,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    pub timeout: u64,
    pub attestation: String,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptorJSON>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: AuthenticatorSelectionCriteria,
    pub extensions: AuthenticationExtensionsClientInputsJSON,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hints: Option<Vec<String>>,
}

// Structure to hold yielded registration data
#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone)]
pub struct YieldedRegistrationData {
    pub(crate) commitment_b64url: String,
    pub(crate) original_challenge_b64url: String,
    pub(crate) salt_b64url: String,
    pub(crate) rp_id: String, // Store rp_id to derive origin and for verification
    pub(crate) require_user_verification: bool,
}

#[near_sdk::near(serializers = [json])]
#[derive(Debug)]
pub struct RegistrationOptionsJSON {
    pub options: PublicKeyCredentialCreationOptionsJSON,
    #[serde(rename = "nearAccountId")]
    pub near_account_id: Option<String>,
    #[serde(rename = "commitmentId")]
    pub commitment_id: Option<String>,
}

// Authentication-specific types (equivalent to @simplewebauthn/server types)
#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)]
pub enum UserVerificationRequirement {
    #[serde(rename = "discouraged")]
    Discouraged,
    #[serde(rename = "preferred")]
    Preferred,
    #[serde(rename = "required")]
    Required,
}

impl Default for UserVerificationRequirement {
    fn default() -> Self {
        Self::Preferred
    }
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticationExtensionsClientInputs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appid: Option<String>,
    #[serde(rename = "credProps", skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,
    #[serde(rename = "hmacCreateSecret", skip_serializing_if = "Option::is_none")]
    pub hmac_create_secret: Option<bool>,
    #[serde(rename = "minPinLength", skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<bool>,
}

impl Default for AuthenticationExtensionsClientInputs {
    fn default() -> Self {
        Self {
            appid: None,
            cred_props: None,
            hmac_create_secret: None,
            min_pin_length: None,
        }
    }
}


#[near_sdk::near(serializers = [json])]
#[derive(Debug, Clone, PartialEq)]
pub struct PublicKeyCredentialRequestOptionsJSON {
    pub challenge: String, // Base64URL encoded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(rename = "rpId", skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(rename = "allowCredentials", skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptorJSON>>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

#[near_sdk::near(serializers = [json])]
#[derive(Debug)]
pub struct AuthenticationOptionsJSON {
    pub options: PublicKeyCredentialRequestOptionsJSON,
    #[serde(rename = "commitmentId")]
    pub commitment_id: Option<String>,
}