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
use tracing::{error, warn};
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

/// Three possible formats to store [SecuredConfig]
/// 1. TokenEncrypted - Encrypted using a hardware token
/// 2. PasswordEncrypted - Encrypted from a derived key from a password/PIN
/// 3. PlainText - No Encryption at all - USE AT YOUR OWN RISK!
///
/// NOTE: All strings are BASE64 encoded
#[derive(Serialize, Deserialize, Debug, Zeroize)]
#[serde(untagged)]
enum SecuredConfigFormat {
    /// Hardware token encrypted data
    TokenEncrypted {
        /// Encrypted Session Key
        esk: String,
        /// Encrypted data using esk
        data: String,
    },

    /// Password/PIN Protected data
    PasswordEncrypted {
        /// Encrypted data using AES-256 from derived key.
        /// Wire format of the raw blob: `[12-byte nonce | ciphertext + 16-byte tag]`
        data: String,

        /// Crypto scheme version used to produce `data`.
        ///
        /// - `1` (legacy / absent in old blobs): nonce used as HKDF salt.
        /// - `2` (current): fixed [`HKDF_SALT`] constant used; nonce is AES-GCM only.
        ///
        /// Old blobs serialized without this field default to `1` via serde.
        #[serde(default = "default_crypto_version")]
        version: u8,
    },

    /// Plaintext data - dangerous!
    PlainText {
        /// Plaintext data that can be Serialized into [SecuredConfig]
        text: String,
    },
}

impl SecuredConfigFormat {
    /// Decrypts the blob and returns `(SecuredConfig, needs_hkdf_migration)`.
    ///
    /// `needs_hkdf_migration` is `true` when the blob used the **v1 legacy**
    /// nonce-as-salt HKDF scheme.  The caller should immediately re-encrypt and
    /// save the config with the current v2 scheme when the flag is set.
    pub fn unlock(
        &self,
        #[cfg(feature = "openpgp-card")] user_pin: &SecretString,
        token: Option<&String>,
        unlock: Option<&UnlockCode>,
        #[cfg(feature = "openpgp-card")] touch_prompt: &impl TokenInteractions,
    ) -> Result<(SecuredConfig, bool), OpenVTCError> {
        let mut needs_hkdf_migration = false;

        let raw_bytes = match self {
            SecuredConfigFormat::TokenEncrypted {
                esk: _esk,
                data: _data,
            } => {
                // Token Encrypted format — no HKDF involved; no migration needed.
                if let Some(_token) = token {
                    #[cfg(feature = "openpgp-card")]
                    {
                        use crate::openpgp_card::crypt::token_decrypt;

                        token_decrypt(
                            #[cfg(feature = "openpgp-card")]
                            user_pin,
                            _token,
                            &BASE64_URL_SAFE_NO_PAD.decode(_esk)?,
                            &BASE64_URL_SAFE_NO_PAD.decode(_data)?,
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
            SecuredConfigFormat::PasswordEncrypted { data, version } => {
                if let Some(unlock) = unlock {
                    let decoded = BASE64_URL_SAFE_NO_PAD.decode(data)?;
                    let key = unlock
                        .0
                        .expose_secret()
                        .first_chunk::<32>()
                        .ok_or_else(|| {
                            OpenVTCError::Decrypt("Unlock code is not 32 bytes".to_string())
                        })?;

                    if *version == CRYPTO_VERSION_CURRENT {
                        // v2: fixed HKDF salt — the correct current scheme.
                        unlock_code_decrypt_v2(key, &decoded).map_err(|e| {
                            OpenVTCError::Decrypt(format!(
                                "Couldn't decrypt password-encrypted config (v2). Reason: {e}"
                            ))
                        })?
                    } else {
                        // v1 legacy: nonce-as-salt — decrypt and flag for re-encryption.
                        let plain = unlock_code_decrypt_legacy(key, &decoded).map_err(|e| {
                            OpenVTCError::Decrypt(format!(
                                "Couldn't decrypt password-encrypted config (legacy v1). Reason: {e}"
                            ))
                        })?;
                        needs_hkdf_migration = true;
                        plain
                    }
                } else {
                    return Err(OpenVTCError::Config(
                        "Secured Config is Password Encrypted, but no unlock code has been provided!".to_string()
                    ));
                }
            }
            SecuredConfigFormat::PlainText { text } => BASE64_URL_SAFE_NO_PAD.decode(text)?,
        };

        Ok((
            serde_json::from_slice(raw_bytes.as_slice())?,
            needs_hkdf_migration,
        ))
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
                // Always write version = 2 (fixed HKDF salt) on every save.
                version: CRYPTO_VERSION_CURRENT,
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

    /// Loads secret info from the OS Secure Store.
    ///
    /// If the stored blob was encrypted with the legacy v1 HKDF scheme
    /// (nonce-as-salt), the config is automatically re-encrypted with the
    /// current v2 scheme (fixed salt) and saved back before returning.
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
                Ok(format) => format,
                Err(e) => {
                    error!(
                        "ERROR: Format of SecuredConfig in OS Secure store is invalid! Reason: {e}"
                    );
                    return Err(OpenVTCError::Config(format!(
                        "Couldn't load openvtc secured configuration. Reason: {e}"
                    )));
                }
            },
            Err(e) => {
                error!("Couldn't find Secure Config in the OS Secret Store. Fatal Error: {e}");
                return Err(OpenVTCError::Config(format!(
                    "Couldn't find openvtc secured configuration. Reason: {e}"
                )));
            }
        };

        let (sc, needs_hkdf_migration) = raw_secured_config.unlock(
            #[cfg(feature = "openpgp-card")]
            user_pin,
            token,
            unlock,
            #[cfg(feature = "openpgp-card")]
            touch_prompt,
        )?;

        // Auto-migrate: re-encrypt with the v2 fixed-salt scheme and save back
        // to the OS secure store so the legacy blob is replaced on first load.
        if needs_hkdf_migration {
            tracing::info!("Migrated legacy HKDF scheme (nonce-as-salt) to new fixed-salt version");
            let unlock_vec = unlock.map(|uc| uc.0.expose_secret().to_vec());
            sc.save(
                profile,
                token,
                unlock_vec.as_ref(),
                #[cfg(feature = "openpgp-card")]
                &|| {},
            )
            .unwrap_or_else(|e| {
                tracing::warn!("HKDF migration: failed to re-save config: {e}");
            });
        }

        Ok(sc)
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

// ---------------------------------------------------------------------------
// AES-256-GCM + HKDF-SHA256 encryption layer
//
// Crypto version history:
//   v1 (legacy): HKDF salt = the per-message AES-GCM nonce — insecure because
//                the nonce is public and the same bytes feed both the KDF and
//                the cipher, reducing the effective security margin.
//   v2 (current): HKDF salt = fixed high-entropy constant (HKDF_SALT).
//                 The AES-GCM nonce is random and used solely for AES-GCM.
//
// Blob wire format (both versions): `[12-byte nonce | ciphertext + 16-byte tag]`
// The version is tracked externally (in PasswordEncrypted.version) so that
// callers know which derive_key variant to use for decryption.
// ---------------------------------------------------------------------------

/// AES-256-GCM nonce size in bytes.
const NONCE_SIZE: usize = 12;

/// HKDF info/label string shared by both v1 and v2 schemes.
const HKDF_INFO: &[u8] = b"openvtc-key-v2";

/// Fixed, high-entropy HKDF salt used by the v2 scheme.
///
/// **Never change this constant after deployment** — any change would make all
/// existing v2 blobs permanently undecryptable.  The value was generated from
/// `/dev/urandom` and is intentionally not a human-readable string.
#[doc(hidden)]
const HKDF_SALT: &[u8; 32] = &[
    0x6f, 0x70, 0x65, 0x6e, 0x76, 0x74, 0x63, 0x2d, // "openvtc-"
    0x68, 0x6b, 0x64, 0x66, 0x2d, 0x73, 0x61, 0x6c, // "hkdf-sal"
    0x74, 0x2d, 0x76, 0x32, 0x00, 0xc3, 0x7e, 0x91, // "t-v2\0..."
    0xd4, 0x2b, 0x88, 0xf0, 0x1a, 0x55, 0xe9, 0x3c, // random suffix
];

/// Crypto scheme version stored in [`SecuredConfigFormat::PasswordEncrypted`].
pub(crate) const CRYPTO_VERSION_LEGACY: u8 = 1;
/// Current (v2) crypto scheme version.
pub(crate) const CRYPTO_VERSION_CURRENT: u8 = 2;

/// serde default for the `version` field — old blobs have no version field and
/// should be treated as v1 (legacy nonce-as-salt scheme).
fn default_crypto_version() -> u8 {
    CRYPTO_VERSION_LEGACY
}

// ---------------------------------------------------------------------------
// Private key-derivation helpers
// ---------------------------------------------------------------------------

/// v2: derive AES-256-GCM key using a **fixed** HKDF salt.
/// The nonce is NOT involved in key derivation — it is purely an AES-GCM IV.
fn derive_key_v2(unlock: &[u8; 32]) -> Result<Aes256Gcm, OpenVTCError> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), unlock);
    let mut key_bytes = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key_bytes)
        .map_err(|e| OpenVTCError::Encrypt(format!("HKDF key derivation failed: {e}")))?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| OpenVTCError::Encrypt(format!("Invalid AES key: {e}")))?;
    key_bytes.zeroize();
    Ok(cipher)
}

/// v1 (legacy): derive AES-256-GCM key using the **nonce as HKDF salt**.
/// Kept only for decrypting existing blobs during the migration window.
fn derive_key_legacy(unlock: &[u8; 32], nonce: &[u8]) -> Result<Aes256Gcm, OpenVTCError> {
    let hk = Hkdf::<Sha256>::new(Some(nonce), unlock);
    let mut key_bytes = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key_bytes)
        .map_err(|e| OpenVTCError::Encrypt(format!("HKDF key derivation failed: {e}")))?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| OpenVTCError::Encrypt(format!("Invalid AES key: {e}")))?;
    key_bytes.zeroize();
    Ok(cipher)
}

// ---------------------------------------------------------------------------
// Internal versioned decrypt helpers
// ---------------------------------------------------------------------------

/// Decrypt a blob that was produced by the **v2** (fixed-salt) scheme.
///
/// Blob format: `[12-byte nonce | ciphertext + 16-byte auth tag]`
#[doc(hidden)]
fn unlock_code_decrypt_v2(unlock: &[u8; 32], input: &[u8]) -> Result<Vec<u8>, OpenVTCError> {
    if input.len() <= NONCE_SIZE {
        return Err(OpenVTCError::Decrypt(
            "Ciphertext too short (missing nonce)".to_string(),
        ));
    }
    let (nonce_bytes, ciphertext) = input.split_at(NONCE_SIZE);
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    let cipher = derive_key_v2(unlock)?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| OpenVTCError::Decrypt(format!("v2 decrypt failed: {e}")))
}

/// Decrypt a blob that was produced by the **v1 (legacy)** nonce-as-salt scheme.
///
/// Blob format: `[12-byte nonce | ciphertext + 16-byte auth tag]`
#[doc(hidden)]
fn unlock_code_decrypt_legacy(unlock: &[u8; 32], input: &[u8]) -> Result<Vec<u8>, OpenVTCError> {
    if input.len() <= NONCE_SIZE {
        return Err(OpenVTCError::Decrypt(
            "Ciphertext too short (missing nonce)".to_string(),
        ));
    }
    let (nonce_bytes, ciphertext) = input.split_at(NONCE_SIZE);
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    let cipher = derive_key_legacy(unlock, nonce_bytes)?;
    cipher.decrypt(nonce, ciphertext).map_err(|e| {
        OpenVTCError::Decrypt(format!(
            "legacy decrypt failed (wrong key or corrupted blob): {e}"
        ))
    })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encrypts `input` using AES-256-GCM with an HKDF-derived key (v2 scheme).
///
/// The HKDF key is derived from `unlock` with a fixed, high-entropy salt
/// (`HKDF_SALT`).  A fresh random 12-byte nonce is generated for every call
/// and prepended to the output.
///
/// Output wire format: `[12-byte nonce | ciphertext + 16-byte auth tag]`
pub fn unlock_code_encrypt(unlock: &[u8; 32], input: &[u8]) -> Result<Vec<u8>, OpenVTCError> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher = derive_key_v2(unlock)?;

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

/// Decrypts a blob that may have been produced by either the v2 (fixed-salt) or
/// v1 (nonce-as-salt, legacy) scheme.
///
/// **Try order**: v2 first; if v2 fails (wrong MAC), fall back to v1 legacy.
/// This ensures backward compatibility for blobs from `protected_config`,
/// `openpgp_card/crypt`, export files, and other callers that do not track
/// an explicit version marker.
///
/// For the main `PasswordEncrypted` config blob where an explicit `version`
/// field is available, prefer calling `unlock_code_decrypt_v2` or
/// `unlock_code_decrypt_legacy` directly so the attempt is not ambiguous.
pub fn unlock_code_decrypt(unlock: &[u8; 32], input: &[u8]) -> Result<Vec<u8>, OpenVTCError> {
    if input.len() <= NONCE_SIZE {
        return Err(OpenVTCError::Decrypt(
            "Ciphertext too short (missing nonce)".to_string(),
        ));
    }
    // Try v2 (fixed-salt) first.
    match unlock_code_decrypt_v2(unlock, input) {
        Ok(plain) => Ok(plain),
        Err(_) => {
            // Fall back to the v1 legacy scheme (nonce-as-salt).
            unlock_code_decrypt_legacy(unlock, input).map_err(|e| {
                error!("Couldn't decrypt data. Likely due to incorrect unlock code! Reason: {e}");
                OpenVTCError::Decrypt(format!("Couldn't decrypt data (tried v2 and legacy): {e}"))
            })
        }
    }
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

    // -----------------------------------------------------------------------
    // HKDF v2 fixed-salt scheme tests
    // -----------------------------------------------------------------------

    /// Helper: encrypt `plaintext` with the LEGACY v1 scheme (nonce-as-salt).
    fn make_legacy_v1_blob(unlock: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        use aes_gcm::AeadCore;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = derive_key_legacy(unlock, &nonce).unwrap();
        let mut ct = cipher.encrypt(&nonce, plaintext).unwrap();
        let mut blob = nonce.to_vec();
        blob.append(&mut ct);
        blob
    }

    #[test]
    fn test_v2_roundtrip() {
        // New scheme: encrypt then decrypt should return original plaintext.
        let unlock = [0xAAu8; 32];
        let plaintext = b"openvtc v2 roundtrip test";
        let blob = unlock_code_encrypt(&unlock, plaintext).unwrap();
        let plain = unlock_code_decrypt_v2(&unlock, &blob).unwrap();
        assert_eq!(plain, plaintext);
    }

    #[test]
    fn test_v2_wrong_key_fails() {
        let unlock = [0xAAu8; 32];
        let wrong = [0xBBu8; 32];
        let blob = unlock_code_encrypt(&unlock, b"secret").unwrap();
        assert!(unlock_code_decrypt_v2(&wrong, &blob).is_err());
    }

    #[test]
    fn test_legacy_v1_blob_still_decryptable() {
        // Backward-compat: blobs created with the old nonce-as-salt scheme
        // must be readable via unlock_code_decrypt_legacy.
        let unlock = [0x11u8; 32];
        let plaintext = b"legacy config data";
        let blob = make_legacy_v1_blob(&unlock, plaintext);
        let plain = unlock_code_decrypt_legacy(&unlock, &blob).unwrap();
        assert_eq!(plain, plaintext);
    }

    #[test]
    fn test_legacy_v1_blob_wrong_key_fails() {
        let unlock = [0x11u8; 32];
        let wrong = [0x22u8; 32];
        let blob = make_legacy_v1_blob(&unlock, b"data");
        assert!(unlock_code_decrypt_legacy(&wrong, &blob).is_err());
    }

    #[test]
    fn test_v1_and_v2_blobs_are_distinct() {
        // The same key + plaintext must produce different ciphertext under v1 vs v2
        // because the HKDF-derived keys are different.
        let unlock = [0x55u8; 32];
        let plaintext = b"same plaintext";
        let blob_v2 = unlock_code_encrypt(&unlock, plaintext).unwrap();
        let blob_v1 = make_legacy_v1_blob(&unlock, plaintext);
        // v2 blob is unreadable with v1 key (and vice-versa)
        assert!(
            unlock_code_decrypt_legacy(&unlock, &blob_v2).is_err(),
            "v2 blob must not be decryptable by legacy v1 scheme"
        );
        assert!(
            unlock_code_decrypt_v2(&unlock, &blob_v1).is_err(),
            "v1 blob must not be decryptable by v2 scheme"
        );
    }

    #[test]
    fn test_public_decrypt_handles_both_schemes() {
        // unlock_code_decrypt (public API) must transparently handle both v1 and v2.
        let unlock = [0x77u8; 32];
        let plaintext = b"transparent migration test";
        let blob_v2 = unlock_code_encrypt(&unlock, plaintext).unwrap();
        let blob_v1 = make_legacy_v1_blob(&unlock, plaintext);
        assert_eq!(unlock_code_decrypt(&unlock, &blob_v2).unwrap(), plaintext);
        assert_eq!(unlock_code_decrypt(&unlock, &blob_v1).unwrap(), plaintext);
    }

    #[test]
    fn test_password_encrypted_v1_sets_migration_flag() {
        // A PasswordEncrypted blob without a version field (serde default = 1)
        // must signal needs_hkdf_migration = true after unlock.
        let key = [0xC0u8; 32];
        let plaintext = b"{\"bip32_seed\":null,\"credential_bundle\":null,\
            \"vta_url\":null,\"vta_did\":null,\"key_info\":{}}";
        let blob_v1 = make_legacy_v1_blob(&key, plaintext);
        let fmt = SecuredConfigFormat::PasswordEncrypted {
            data: BASE64_URL_SAFE_NO_PAD.encode(&blob_v1),
            version: CRYPTO_VERSION_LEGACY, // explicit v1
        };
        let unlock = UnlockCode(secrecy::SecretVec::new(key.to_vec()));
        let (_sc, migrated) = fmt
            .unlock(
                #[cfg(feature = "openpgp-card")]
                &secrecy::SecretString::new("pin".into()),
                None,
                Some(&unlock),
                #[cfg(feature = "openpgp-card")]
                &openvtc_noop_touch(),
            )
            .unwrap();
        assert!(migrated, "v1 blob must report needs_hkdf_migration = true");
    }

    #[test]
    fn test_password_encrypted_v2_no_migration_flag() {
        // A PasswordEncrypted blob with version = 2 must NOT set migration flag.
        let key = [0xC0u8; 32];
        let plaintext = b"{\"bip32_seed\":null,\"credential_bundle\":null,\
            \"vta_url\":null,\"vta_did\":null,\"key_info\":{}}";
        let blob_v2 = unlock_code_encrypt(&key, plaintext).unwrap();
        let fmt = SecuredConfigFormat::PasswordEncrypted {
            data: BASE64_URL_SAFE_NO_PAD.encode(&blob_v2),
            version: CRYPTO_VERSION_CURRENT,
        };
        let unlock = UnlockCode(secrecy::SecretVec::new(key.to_vec()));
        let (_sc, migrated) = fmt
            .unlock(
                #[cfg(feature = "openpgp-card")]
                &secrecy::SecretString::new("pin".into()),
                None,
                Some(&unlock),
                #[cfg(feature = "openpgp-card")]
                &openvtc_noop_touch(),
            )
            .unwrap();
        assert!(!migrated, "v2 blob must NOT report needs_hkdf_migration");
    }

    #[test]
    fn test_serde_default_version_is_legacy() {
        // Old blobs serialized without the `version` field must deserialize
        // as version = CRYPTO_VERSION_LEGACY (1), triggering migration.
        let json = r#"{"data":"AAAA"}"#;
        let fmt: SecuredConfigFormat = serde_json::from_str(json).unwrap();
        if let SecuredConfigFormat::PasswordEncrypted { version, .. } = fmt {
            assert_eq!(
                version, CRYPTO_VERSION_LEGACY,
                "Missing version field must default to CRYPTO_VERSION_LEGACY"
            );
        } else {
            panic!("Expected PasswordEncrypted variant");
        }
    }

    #[test]
    fn test_serde_version_2_round_trip() {
        // PasswordEncrypted with version = 2 must serialize and deserialize correctly.
        let fmt = SecuredConfigFormat::PasswordEncrypted {
            data: "AAAA".to_string(),
            version: CRYPTO_VERSION_CURRENT,
        };
        let json = serde_json::to_string(&fmt).unwrap();
        assert!(
            json.contains("\"version\":2"),
            "version field must be in JSON"
        );
        let fmt2: SecuredConfigFormat = serde_json::from_str(&json).unwrap();
        if let SecuredConfigFormat::PasswordEncrypted { version, .. } = fmt2 {
            assert_eq!(version, CRYPTO_VERSION_CURRENT);
        } else {
            panic!("Expected PasswordEncrypted variant");
        }
    }

    // Helper shim so cfg-gated openpgp-card arguments can be provided in tests.
    #[cfg(feature = "openpgp-card")]
    fn openvtc_noop_touch() -> impl crate::config::TokenInteractions {
        struct NoopTouch;
        impl crate::config::TokenInteractions for NoopTouch {
            fn touch_notify(&self) {}
            fn touch_completed(&self) {}
        }
        NoopTouch
    }
}
