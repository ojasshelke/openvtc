/*!
*  Secured [crate::config::Config] information that is stored in the OS Secure Storage
*
*  * If using hardware tokens, then the data is encrypted/decrypted using the hardware token
*  * If no hardware token, then may be using a passphrase to protect the data
*  * If no hardware token, and no passphrase, then is in plaintext in the OS Secure Store
*
*  Must intially save bip32_seed first before any keys can be stored
*/

#[cfg(feature = "openpgp-card")]
use crate::config::TokenInteractions;
use crate::{
    config::{Config, KeyBackend, KeyTypes, UnlockCode},
    errors::OpenVTCError,
};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, aead::Aead};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use keyring::Entry;
use rand::rngs::OsRng;
use secrecy::ExposeSecret;
#[cfg(feature = "openpgp-card")]
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use tracing::{error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Constants for storing secure info in the OS Secure Store
const SERVICE: &str = "openvtc";

/// Methods of protecting [SecuredConfig]
#[derive(Clone, Debug, Default)]
pub enum ProtectionMethod {
    TokenEncrypted,
    PasswordEncrypted,
    PlainText,
    #[default]
    Unknown,
}

impl From<SecuredConfigFormat> for ProtectionMethod {
    fn from(format: SecuredConfigFormat) -> Self {
        match format {
            SecuredConfigFormat::TokenEncrypted { .. } => ProtectionMethod::TokenEncrypted,
            SecuredConfigFormat::PasswordEncrypted { .. } => ProtectionMethod::PasswordEncrypted,
            SecuredConfigFormat::PlainText { .. } => ProtectionMethod::PlainText,
        }
    }
}

/// Three possible formats to store [SecuredConfig].
///
/// # Security: Internally-Tagged Format — Downgrade Attack Prevention
///
/// ## Threat Model
/// An adversary with write access to the OS keychain (compromised keychain daemon,
/// local privilege escalation, or a malicious app granted keychain access) could
/// previously substitute a `PasswordEncrypted` or `TokenEncrypted` blob with a
/// crafted `PlainText` blob containing the victim's raw identity material.
///
/// With the old `#[serde(untagged)]` design serde tries variants in declaration
/// order with **no discriminator field in the JSON**.  A blob like:
/// ```json
/// {"text": "<base64-of-real-identity-material>"}
/// ```
/// would silently deserialize as `PlainText` even when `PublicConfig.protection`
/// demanded `PasswordEncrypted` — bypassing AES-256-GCM entirely and delivering
/// the BIP32 seed, VRCs, and relationship keys in cleartext.
///
/// ## Fix — Layer 1: Explicit Discriminator
/// `#[serde(tag = "format")]` writes a mandatory `"format"` key into every stored
/// blob, e.g. `{"format":"PasswordEncrypted","data":"..."}`.  Any blob that lacks
/// the `"format"` key — including every blob written by the old code — produces a
/// hard `serde_json` error rather than silently matching a weaker variant.
///
/// ## Fix — Layer 2: Caller-Intent Cross-Validation
/// See [`assert_format_matches_intent`].  Even if an attacker replaces the blob
/// with a validly-tagged but weaker format, the second check refuses to proceed
/// if the stored format does not match what the caller's supplied credentials imply.
///
/// ## Breaking Change
/// All configs stored by the previous untagged format are **no longer loadable**
/// without migration.  To migrate an existing installation:
/// 1. Export the config before upgrading (`openvtc export`).
/// 2. After upgrade, re-import and re-save (`openvtc import`).
///
/// The `format_version` convention is `"format": "<Variant>"` itself; future
/// variants can carry a `v` suffix (e.g. `TokenEncryptedV2`) for graceful migration.
///
/// NOTE: All string payloads are BASE64URL (no-pad) encoded.
#[derive(Serialize, Deserialize, Debug, Zeroize)]
#[serde(tag = "format")]
enum SecuredConfigFormat {
    /// Hardware token encrypted data
    TokenEncrypted {
        /// Encrypted Session Key (BASE64URL)
        esk: String,
        /// Encrypted data using esk (BASE64URL)
        data: String,
    },

    /// Password/PIN Protected data
    PasswordEncrypted {
        /// AES-256-GCM ciphertext derived from unlock code via HKDF (BASE64URL)
        data: String,
    },

    /// Plaintext data — USE AT YOUR OWN RISK.
    /// Only valid when `PublicConfig.protection == ConfigProtectionType::Plaintext`.
    PlainText {
        /// BASE64URL-encoded raw JSON of [SecuredConfig]
        text: String,
    },
}

/// Cross-validates the stored [`SecuredConfigFormat`] variant against the
/// protection level the caller's supplied credentials imply.
///
/// # Security rationale
/// This is **Layer 2** of the downgrade-attack defence (Layer 1 is the
/// internally-tagged serde format).  Even if an attacker manages to write a
/// syntactically valid but weaker format into the OS keychain — e.g. a
/// correctly-tagged `PlainText` blob where a `PasswordEncrypted` blob is
/// expected — this function refuses to proceed, turning a silent data
/// exfiltration into a loud, logged error.
///
/// The mapping from caller intent to expected format is:
/// - `has_token == true`               → must be [`SecuredConfigFormat::TokenEncrypted`]
/// - `has_unlock == true`              → must be [`SecuredConfigFormat::PasswordEncrypted`]
/// - neither token nor unlock present  → must be [`SecuredConfigFormat::PlainText`]
///
/// Any other combination is treated as evidence of tampering.
fn assert_format_matches_intent(
    format: &SecuredConfigFormat,
    has_token: bool,
    has_unlock: bool,
) -> Result<(), OpenVTCError> {
    if matches!(
        (format, has_token, has_unlock),
        (SecuredConfigFormat::TokenEncrypted { .. }, true, _)
            | (SecuredConfigFormat::PasswordEncrypted { .. }, false, true)
            | (SecuredConfigFormat::PlainText { .. }, false, false)
    ) {
        return Ok(());
    }

    let stored = match format {
        SecuredConfigFormat::TokenEncrypted { .. } => "token-encrypted",
        SecuredConfigFormat::PasswordEncrypted { .. } => "password-encrypted",
        SecuredConfigFormat::PlainText { .. } => "plaintext",
    };
    let expected = if has_token {
        "token-encrypted"
    } else if has_unlock {
        "password-encrypted"
    } else {
        "plaintext"
    };

    error!(
        "SECURITY ALERT: stored config format ({stored}) does not match expected \
         protection level ({expected}). Possible downgrade attack or config corruption."
    );
    Err(OpenVTCError::Config(format!(
        "Security violation: stored config format '{stored}' does not match \
         expected protection level '{expected}'. Refusing to load. \
         If this is a legitimate format migration, re-save your config with the \
         correct protection method first."
    )))
}

/// Legacy untagged format — used **only** during one-time migration.
///
/// Configs written before the `#[serde(tag = "format")]` change have no
/// `"format"` key, so serde tries variants in declaration order (untagged).
/// After a successful migration load the config is immediately re-saved in
/// the new tagged format; this type is never written to the OS Secure Store.
#[derive(Deserialize)]
#[serde(untagged)]
enum LegacySecuredConfigFormat {
    TokenEncrypted { esk: String, data: String },
    PasswordEncrypted { data: String },
    PlainText { text: String },
}

impl From<LegacySecuredConfigFormat> for SecuredConfigFormat {
    fn from(legacy: LegacySecuredConfigFormat) -> Self {
        match legacy {
            LegacySecuredConfigFormat::TokenEncrypted { esk, data } => {
                SecuredConfigFormat::TokenEncrypted { esk, data }
            }
            LegacySecuredConfigFormat::PasswordEncrypted { data } => {
                SecuredConfigFormat::PasswordEncrypted { data }
            }
            LegacySecuredConfigFormat::PlainText { text } => {
                SecuredConfigFormat::PlainText { text }
            }
        }
    }
}

impl SecuredConfigFormat {
    /// Loads secret info from the OS Secure Store
    pub fn unlock(
        &self,
        #[cfg(feature = "openpgp-card")] user_pin: &SecretString,
        token: Option<&String>,
        unlock: Option<&UnlockCode>,
        #[cfg(feature = "openpgp-card")] touch_prompt: &impl TokenInteractions,
    ) -> Result<SecuredConfig, OpenVTCError> {
        let raw_bytes = match self {
            SecuredConfigFormat::TokenEncrypted { esk, data } => {
                // Token Encrypted format
                if let Some(token) = token {
                    #[cfg(feature = "openpgp-card")]
                    {
                        use crate::openpgp_card::crypt::token_decrypt;

                        token_decrypt(
                            #[cfg(feature = "openpgp-card")]
                            user_pin,
                            token,
                            &BASE64_URL_SAFE_NO_PAD.decode(esk)?,
                            &BASE64_URL_SAFE_NO_PAD.decode(data)?,
                            touch_prompt,
                        )?
                    }
                    #[cfg(not(feature = "openpgp-card"))]
                    {
                        warn!(
                            "Token has been configured, but no openpgp-card feature-flag has been enabled! exiting..."
                        );
                        return Err(OpenVTCError::Config("Token has been configured, but no openpgp-card feature-flag has been enabled! exiting.".to_string()));
                    }
                } else {
                    warn!(
                        "Secured Config is Token Encrypted, but no token identifier has been provided!"
                    );
                    return Err(OpenVTCError::Config("Secured Config is Token Encrypted, but no token identifier has been provided!".to_string()));
                }
            }
            SecuredConfigFormat::PasswordEncrypted { data } => {
                // Password Encrypted format
                if let Some(unlock) = unlock {
                    let decoded = BASE64_URL_SAFE_NO_PAD.decode(data)?;
                    let key = unlock
                        .0
                        .expose_secret()
                        .first_chunk::<32>()
                        .ok_or_else(|| {
                            OpenVTCError::Decrypt("Unlock code is not 32 bytes".to_string())
                        })?;

                    unlock_code_decrypt(key, &decoded).map_err(|e| {
                        OpenVTCError::Decrypt(format!(
                            "Couldn't decrypt password encrypted SecuredConfig. Reason: {e}"
                        ))
                    })?
                } else {
                    return Err(OpenVTCError::Config(
                        "Secured Config is Password Encrypted, but no unlock code has been provided!".to_string()
                    ));
                }
            }
            SecuredConfigFormat::PlainText { text } => {
                // Plaintext format - no checks needed

                BASE64_URL_SAFE_NO_PAD.decode(text)?
            }
        };

        Ok(serde_json::from_slice(raw_bytes.as_slice())?)
    }
}

/// Secured Configuration information for openvtc tool
/// Try to keep this as small as possible for ease of secure storage
#[derive(Serialize, Deserialize, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecuredConfig {
    /// base64 encoded BIP32 private seed (legacy - present only for BIP32-based configs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bip32_seed: Option<String>,

    /// base64-encoded CredentialBundle for VTA auth
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_bundle: Option<String>,

    /// VTA service URL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_url: Option<String>,

    /// VTA's DID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_did: Option<String>,

    /// Key information containing path info
    /// key is the DID VerificationMethod ID
    #[zeroize(skip)] // chrono doesn't support zeroize
    pub key_info: HashMap<String, KeyInfoConfig>,

    #[serde(skip, default)]
    #[zeroize(skip)]
    pub protection_method: ProtectionMethod,
}

impl From<&Config> for SecuredConfig {
    /// Extracts secured/private information from the full Config
    fn from(cfg: &Config) -> Self {
        match &cfg.key_backend {
            KeyBackend::Bip32 { seed, .. } => SecuredConfig {
                bip32_seed: Some(seed.expose_secret().to_owned()),
                credential_bundle: None,
                vta_url: None,
                vta_did: None,
                key_info: cfg.key_info.clone(),
                protection_method: cfg.protection_method.clone(),
            },
            KeyBackend::Vta {
                credential_bundle,
                vta_did,
                vta_url,
                ..
            } => SecuredConfig {
                bip32_seed: None,
                credential_bundle: Some(credential_bundle.expose_secret().to_owned()),
                vta_url: Some(vta_url.clone()),
                vta_did: Some(vta_did.clone()),
                key_info: cfg.key_info.clone(),
                protection_method: cfg.protection_method.clone(),
            },
        }
    }
}

impl SecuredConfig {
    /// Internal private function that saves a SecuredConfig to the OS Secure Store
    /// Encrypts the secret info as needed based on token/unlock parameters
    /// Converts to BASE64 then saves to OS Secure Store
    pub fn save(
        &self,
        profile: &str,
        token: Option<&String>,
        unlock: Option<&Vec<u8>>,
        #[cfg(feature = "openpgp-card")] touch_prompt: &(dyn Fn() + Send + Sync),
    ) -> Result<(), OpenVTCError> {
        let entry = Entry::new(SERVICE, profile).map_err(|e| {
            OpenVTCError::Config(format!(
                "Couldn't open OS Secure Store for profile ({profile}). Reason: {e}"
            ))
        })?;

        // Serialize SecuredConfig to byte array
        let input = serde_json::to_vec(&self)?;

        let formatted = if let Some(token) = token {
            #[cfg(feature = "openpgp-card")]
            {
                use crate::openpgp_card::crypt::token_encrypt;

                let (esk, data) = token_encrypt(token, &input, touch_prompt)?;
                SecuredConfigFormat::TokenEncrypted {
                    esk: BASE64_URL_SAFE_NO_PAD.encode(&esk),
                    data: BASE64_URL_SAFE_NO_PAD.encode(&data),
                }
            }
            #[cfg(not(feature = "openpgp-card"))]
            return Err(OpenVTCError::Config( "Token has been configured, but no openpgp-card feature-flag has been enabled! exiting...".to_string()));
        } else if let Some(unlock) = unlock {
            SecuredConfigFormat::PasswordEncrypted {
                data: BASE64_URL_SAFE_NO_PAD.encode(unlock_code_encrypt(
                    unlock.first_chunk::<32>().ok_or_else(|| {
                        OpenVTCError::Encrypt("Unlock code is not 32 bytes".to_string())
                    })?,
                    &input,
                )?),
            }
        } else {
            // Plain-text
            SecuredConfigFormat::PlainText {
                text: BASE64_URL_SAFE_NO_PAD.encode(input),
            }
        };

        // Save this to the OS Secure Store
        entry
            .set_secret(serde_json::to_string_pretty(&formatted)?.as_bytes())
            .map_err(|e| {
                OpenVTCError::Config(format!(
                    "Couldn't save encrypted config to the OS Secure Store. Reason: {e}"
                ))
            })?;
        Ok(())
    }

    /// Loads secret info from the OS Secure Store
    /// token: Hardware token identifier if being used
    /// unlock: Use a Password/PIN to unlock secret storage if no hardware token
    /// If token is None and unlock is false, assumes no protection apart from the OS Secure Store
    /// itself
    pub fn load(
        profile: &str,
        #[cfg(feature = "openpgp-card")] user_pin: &SecretString,
        token: Option<&String>,
        unlock: Option<&UnlockCode>,
        #[cfg(feature = "openpgp-card")] touch_prompt: &impl TokenInteractions,
    ) -> Result<Self, OpenVTCError> {
        let entry = Entry::new(SERVICE, profile).map_err(|e| {
            OpenVTCError::Config(format!(
                "Couldn't access OS Secure Store for profile ({profile}). Reason: {e}",
            ))
        })?;

        let raw_secured_config: SecuredConfigFormat = match entry.get_secret() {
            Ok(secret) => match serde_json::from_slice(secret.as_slice()) {
                // ── Fast path: new tagged format ──────────────────────────────
                Ok(format) => format,
                // ── Slow path: try legacy untagged format and migrate ─────────
                Err(tagged_err) => {
                    warn!(
                        "Tagged config deserialization failed ({tagged_err}); \
                         attempting legacy untagged migration"
                    );
                    match serde_json::from_slice::<LegacySecuredConfigFormat>(secret.as_slice()) {
                        Ok(legacy) => {
                            let migrated = SecuredConfigFormat::from(legacy);
                            // Re-save immediately so future loads use the new format.
                            let new_json =
                                serde_json::to_string_pretty(&migrated).map_err(|e| {
                                    OpenVTCError::Config(format!(
                                        "Couldn't serialize migrated config: {e}"
                                    ))
                                })?;
                            entry.set_secret(new_json.as_bytes()).map_err(|e| {
                                OpenVTCError::Config(format!(
                                    "Couldn't re-save migrated config to OS Secure Store: {e}"
                                ))
                            })?;
                            info!("Migrated legacy config to new tagged format");
                            migrated
                        }
                        Err(legacy_err) => {
                            error!(
                                "ERROR: Format of SecuredConfig in OS Secure Store is invalid! \
                                 Tagged error: {tagged_err}, Legacy error: {legacy_err}"
                            );
                            return Err(OpenVTCError::Config(format!(
                                "Couldn't load openvtc secured configuration. Reason: {tagged_err}"
                            )));
                        }
                    }
                }
            },
            Err(e) => {
                error!("Couldn't find Secure Config in the OS Secret Store. Fatal Error: {e}");
                return Err(OpenVTCError::Config(format!(
                    "Couldn't find openvtc secured configuration. Reason: {e}"
                )));
            }
        };

        // ── Security Gate ─────────────────────────────────────────────────────
        // Cross-validate the stored format against the caller's supplied
        // credentials *before* attempting decryption.  This is the second
        // defence layer against silent encryption-downgrade attacks: even a
        // correctly-tagged-but-weaker blob (e.g. PlainText where
        // PasswordEncrypted is expected) is rejected here with a hard error.
        assert_format_matches_intent(&raw_secured_config, token.is_some(), unlock.is_some())?;

        raw_secured_config.unlock(
            #[cfg(feature = "openpgp-card")]
            user_pin,
            token,
            unlock,
            #[cfg(feature = "openpgp-card")]
            touch_prompt,
        )
    }
}

/// Information that is required for each key stored
#[derive(Clone, Serialize, Deserialize, Debug, Zeroize, ZeroizeOnDrop)]
pub struct KeyInfoConfig {
    /// Where did the keys being used come from?
    /// key: #key-id
    /// value: Derived Path (BIP32 or Imported)
    pub path: KeySourceMaterial,

    /// When wss this key first created?
    #[zeroize(skip)] // chrono doesn't support zeroize
    pub create_time: DateTime<Utc>,

    #[zeroize(skip)]
    #[serde(default)]
    pub purpose: KeyTypes,
}
/// Where did the source for the Key Material come from?
#[derive(Clone, Serialize, Deserialize, Debug, Zeroize, ZeroizeOnDrop)]
pub enum KeySourceMaterial {
    /// Sourced from BIP32 derivative, Path for this key
    Derived { path: String },

    /// Sourced from an external Key Import
    /// multiencoded private key
    /// Key Material will be stored in the OS Secure Store
    Imported { seed: String },

    /// Managed by VTA service - key_id is VTA's opaque identifier
    /// No derivation paths are stored in openvtc for VTA-managed keys
    VtaManaged { key_id: String },
}

/// AES-256-GCM nonce size in bytes
const NONCE_SIZE: usize = 12;
/// HKDF info label for key derivation (v2 format)
const HKDF_INFO: &[u8] = b"openvtc-key-v2";
/// Fixed domain-separation salt for HKDF (RFC 5869 §3.1).
///
/// The unlock code already carries 32 bytes of entropy, so a fixed, labelled
/// salt is correct here.  Crucially the salt is **not** the AES-GCM nonce —
/// key derivation and per-message randomness must be kept independent.
const HKDF_SALT: &[u8] = b"openvtc-unlock-v2-salt";

/// Derives a stable AES-256-GCM key from the unlock code using HKDF-SHA256.
///
/// Key derivation uses a fixed domain salt; the per-message nonce is passed
/// separately to AES-GCM, following standard AEAD practice.
fn derive_key(unlock: &[u8; 32]) -> Result<Aes256Gcm, OpenVTCError> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), unlock);
    let mut key_bytes = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key_bytes)
        .map_err(|e| OpenVTCError::Encrypt(format!("HKDF key derivation failed: {e}")))?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| OpenVTCError::Encrypt(format!("Invalid AES key: {e}")))?;
    key_bytes.zeroize();
    Ok(cipher)
}

/// Encrypts data using AES-256-GCM with an HKDF-derived key and a fresh random nonce.
///
/// Key derivation (HKDF) uses a fixed salt; the AES-GCM nonce is independent
/// and used solely for per-message randomness — the two roles are not mixed.
///
/// Output format: `[12-byte nonce | ciphertext + auth tag]`
pub fn unlock_code_encrypt(unlock: &[u8; 32], input: &[u8]) -> Result<Vec<u8>, OpenVTCError> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher = derive_key(unlock)?;

    match cipher.encrypt(&nonce, input) {
        Ok(ciphertext) => {
            let mut result = nonce.to_vec();
            result.extend_from_slice(&ciphertext);
            Ok(result)
        }
        Err(e) => {
            error!("Couldn't encrypt data. Reason: {e}");
            Err(OpenVTCError::Encrypt(format!(
                "Couldn't encrypt data. Reason: {e}"
            )))
        }
    }
}

/// Decrypts data using AES-256-GCM with an HKDF-derived key.
///
/// Expected input format: `[12-byte nonce | ciphertext + auth tag]`
pub fn unlock_code_decrypt(unlock: &[u8; 32], input: &[u8]) -> Result<Vec<u8>, OpenVTCError> {
    if input.len() <= NONCE_SIZE {
        return Err(OpenVTCError::Decrypt(
            "Ciphertext too short (missing nonce)".to_string(),
        ));
    }

    let (nonce_bytes, ciphertext) = input.split_at(NONCE_SIZE);
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    let cipher = derive_key(unlock)?;

    cipher.decrypt(nonce, ciphertext).map_err(|e| {
        error!("Couldn't decrypt data. Likely due to incorrect unlock code! Reason: {e}");
        OpenVTCError::Decrypt(format!(
            "Couldn't decrypt data, likely due to incorrect unlock code! Reason: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let unlock = [42u8; 32];
        let plaintext = b"hello world - this is sensitive config data";
        let encrypted = unlock_code_encrypt(&unlock, plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        let decrypted = unlock_code_decrypt(&unlock, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encryption_is_non_deterministic() {
        let unlock = [42u8; 32];
        let plaintext = b"same data";

        let cipher1 = unlock_code_encrypt(&unlock, plaintext).unwrap();
        let cipher2 = unlock_code_encrypt(&unlock, plaintext).unwrap();

        assert_ne!(cipher1, cipher2, "Encryption must be non-deterministic");
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let unlock = [42u8; 32];
        let wrong_unlock = [99u8; 32];
        let plaintext = b"secret data";
        let encrypted = unlock_code_encrypt(&unlock, plaintext).unwrap();
        assert!(unlock_code_decrypt(&wrong_unlock, &encrypted).is_err());
    }

    #[test]
    fn test_encrypt_empty_data() {
        let unlock = [42u8; 32];
        let encrypted = unlock_code_encrypt(&unlock, b"").unwrap();
        let decrypted = unlock_code_decrypt(&unlock, &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encrypt_large_data() {
        let unlock = [42u8; 32];
        let plaintext = vec![0xABu8; 10_000];
        let encrypted = unlock_code_encrypt(&unlock, &plaintext).unwrap();
        let decrypted = unlock_code_decrypt(&unlock, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_too_short_input_fails() {
        let unlock = [42u8; 32];
        // Input shorter than nonce size should fail
        assert!(unlock_code_decrypt(&unlock, &[0u8; 5]).is_err());
        assert!(unlock_code_decrypt(&unlock, &[]).is_err());
    }

    #[test]
    fn test_different_unlocks_produce_different_ciphertext() {
        let plaintext = b"same data";
        let encrypted1 = unlock_code_encrypt(&[1u8; 32], plaintext).unwrap();
        let encrypted2 = unlock_code_encrypt(&[2u8; 32], plaintext).unwrap();
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_output_contains_nonce_prefix() {
        let unlock = [42u8; 32];
        let plaintext = b"test";

        let encrypted = unlock_code_encrypt(&unlock, plaintext).unwrap();
        // Output should be: 12 bytes nonce + ciphertext (plaintext len + 16 byte auth tag)
        assert_eq!(encrypted.len(), NONCE_SIZE + plaintext.len() + 16);
    }

    #[test]
    fn test_decrypt_corrupted_data_fails() {
        let unlock = [42u8; 32];
        let plaintext = b"important data";
        let mut encrypted = unlock_code_encrypt(&unlock, plaintext).unwrap();
        if let Some(byte) = encrypted.last_mut() {
            *byte ^= 0xFF;
        }
        assert!(unlock_code_decrypt(&unlock, &encrypted).is_err());
    }

    #[test]
    fn test_key_source_material_zeroize() {
        let mut source = KeySourceMaterial::Imported {
            seed: "z6MkTestSeed123456789".to_string(),
        };
        source.zeroize();
        match &source {
            KeySourceMaterial::Imported { seed } => assert!(seed.is_empty()),
            _ => panic!("expected Imported variant"),
        }
    }

    // ── Security Tests ────────────────────────────────────────────────────────

    /// Verifies that every serialized variant carries the explicit `"format"`
    /// discriminator required to prevent silent downgrade via field-guessing.
    #[test]
    fn test_tagged_format_discriminator_present_in_json() {
        let token_enc = SecuredConfigFormat::TokenEncrypted {
            esk: "abc".into(),
            data: "xyz".into(),
        };
        let pass_enc = SecuredConfigFormat::PasswordEncrypted { data: "xyz".into() };
        let plain = SecuredConfigFormat::PlainText { text: "xyz".into() };

        let j1 = serde_json::to_string(&token_enc).unwrap();
        let j2 = serde_json::to_string(&pass_enc).unwrap();
        let j3 = serde_json::to_string(&plain).unwrap();

        assert!(
            j1.contains(r#""format":"TokenEncrypted""#),
            "missing tag: {j1}"
        );
        assert!(
            j2.contains(r#""format":"PasswordEncrypted""#),
            "missing tag: {j2}"
        );
        assert!(j3.contains(r#""format":"PlainText""#), "missing tag: {j3}");
    }

    /// An attacker-supplied blob that looks like the old untagged `PlainText`
    /// format — `{"text":"..."}` without a `"format"` key — must be rejected
    /// at the deserialization stage, never reaching unlock logic.
    #[test]
    fn test_legacy_untagged_blob_rejected_at_parse() {
        let legacy_plain = r#"{"text":"dGVzdA"}"#;
        let legacy_pass = r#"{"data":"dGVzdA"}"#;
        let legacy_token = r#"{"esk":"dGVzdA","data":"dGVzdA"}"#;

        assert!(
            serde_json::from_str::<SecuredConfigFormat>(legacy_plain).is_err(),
            "untagged PlainText blob must be rejected"
        );
        assert!(
            serde_json::from_str::<SecuredConfigFormat>(legacy_pass).is_err(),
            "untagged PasswordEncrypted blob must be rejected"
        );
        assert!(
            serde_json::from_str::<SecuredConfigFormat>(legacy_token).is_err(),
            "untagged TokenEncrypted blob must be rejected"
        );
    }

    /// Caller supplies an unlock code (expects PasswordEncrypted) but the
    /// stored blob is tagged PlainText → downgrade check must fire.
    #[test]
    fn test_downgrade_plaintext_rejected_when_password_expected() {
        let plain = SecuredConfigFormat::PlainText {
            text: BASE64_URL_SAFE_NO_PAD.encode(b"{}"),
        };
        // has_token=false, has_unlock=true → expects PasswordEncrypted
        let result = assert_format_matches_intent(&plain, false, true);
        assert!(
            result.is_err(),
            "PlainText must be rejected when PasswordEncrypted is expected"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Security violation"),
            "error must mention security violation: {msg}"
        );
        assert!(
            msg.contains("plaintext"),
            "error must name the stored format: {msg}"
        );
        assert!(
            msg.contains("password-encrypted"),
            "error must name the expected format: {msg}"
        );
    }

    /// Caller supplies no credentials (expects PlainText) but the stored blob
    /// is tagged PasswordEncrypted → downgrade check (in reverse) must fire,
    /// preventing an attacker from forcing unnecessary decryption attempts.
    #[test]
    fn test_downgrade_encrypted_rejected_when_plaintext_expected() {
        let pass_enc = SecuredConfigFormat::PasswordEncrypted {
            data: BASE64_URL_SAFE_NO_PAD.encode(b"garbage"),
        };
        // has_token=false, has_unlock=false → expects PlainText
        let result = assert_format_matches_intent(&pass_enc, false, false);
        assert!(
            result.is_err(),
            "PasswordEncrypted must be rejected when PlainText is expected"
        );
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Security violation"), "{msg}");
        assert!(msg.contains("password-encrypted"), "{msg}");
        assert!(msg.contains("plaintext"), "{msg}");
    }

    /// Happy-path: each format variant is accepted when caller intent matches.
    #[test]
    fn test_format_intent_happy_paths() {
        let plain = SecuredConfigFormat::PlainText { text: "x".into() };
        let pass_enc = SecuredConfigFormat::PasswordEncrypted { data: "x".into() };
        let token_enc = SecuredConfigFormat::TokenEncrypted {
            esk: "x".into(),
            data: "x".into(),
        };

        assert!(assert_format_matches_intent(&plain, false, false).is_ok());
        assert!(assert_format_matches_intent(&pass_enc, false, true).is_ok());
        assert!(assert_format_matches_intent(&token_enc, true, false).is_ok());
        // token takes precedence: token_enc + both credentials still valid
        assert!(assert_format_matches_intent(&token_enc, true, true).is_ok());
    }
}
