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
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use tracing::{debug, error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Constants for storing secure info in the OS Secure Store
const SERVICE: &str = "openvtc";

// ---------------------------------------------------------------------------
// Serde helpers for SecretString
//
// `Secret<String>` does not implement `SerializableSecret`, so the standard
// `#[serde(with = "secrecy")]` attribute won't compile.  These narrow modules
// expose the inner value only at the serde boundary and nowhere else.
// ---------------------------------------------------------------------------
mod serde_secret_str {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &SecretString, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(v.expose_secret())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SecretString, D::Error> {
        // secrecy 0.10: SecretString::new() takes Box<str>, not String
        Ok(SecretString::new(String::deserialize(d)?.into()))
    }
}
mod serde_opt_secret_str {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Option<SecretString>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(secret) => s.serialize_some(secret.expose_secret()),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SecretString>, D::Error> {
        // secrecy 0.10: SecretString::new() takes Box<str>, not String
        Ok(Option::<String>::deserialize(d)?.map(|s| SecretString::new(s.into())))
    }
}

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
/// ## Auto-Migration (no manual steps needed)
/// Blobs written by the old untagged code are automatically detected and
/// re-saved in the new tagged format on the first successful load.
/// Similarly, `PasswordEncrypted` blobs that used the v1 nonce-as-salt HKDF
/// scheme are re-encrypted with the v2 fixed-salt scheme on the first load.
/// Both migrations happen in a single re-save after the security gate passes.
///
/// ## Breaking Change (HKDF salt)
/// The HKDF salt constant changed between v1 and v2.  If automatic migration
/// fails (e.g. keychain write permission denied), users may need to re-create
/// their config manually.
///
/// ## Breaking Change (serde tag)
/// All configs stored by the previous untagged format are **no longer loadable**
/// without migration.  Auto-migration handles this transparently; if you need to
/// bypass it, export before upgrading and re-import after.
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
        /// AES-256-GCM ciphertext derived from unlock code via HKDF (BASE64URL).
        ///
        /// Wire format: `[12-byte nonce | ciphertext + 16-byte auth tag]`
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
#[derive(Deserialize, Zeroize)]
#[serde(untagged)]
enum LegacySecuredConfigFormat {
    TokenEncrypted {
        esk: String,
        data: String,
    },
    /// Old blobs may lack the `version` field; serde defaults to 1 (legacy HKDF).
    PasswordEncrypted {
        data: String,
        #[serde(default = "default_crypto_version")]
        version: u8,
    },
    PlainText {
        text: String,
    },
}

impl From<LegacySecuredConfigFormat> for SecuredConfigFormat {
    fn from(legacy: LegacySecuredConfigFormat) -> Self {
        match legacy {
            LegacySecuredConfigFormat::TokenEncrypted { esk, data } => {
                SecuredConfigFormat::TokenEncrypted { esk, data }
            }
            LegacySecuredConfigFormat::PasswordEncrypted { data, version } => {
                SecuredConfigFormat::PasswordEncrypted { data, version }
            }
            LegacySecuredConfigFormat::PlainText { text } => {
                SecuredConfigFormat::PlainText { text }
            }
        }
    }
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
            // `_esk` / `_data` suppress unused-variable warnings when compiled
            // without the `openpgp-card` feature flag.
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
            SecuredConfigFormat::PlainText { text } => {
                // Plaintext format - no checks needed
                BASE64_URL_SAFE_NO_PAD.decode(text)?
            }
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
    /// base64 encoded BIP32 private seed (legacy - present only for BIP32-based configs).
    ///
    /// `SecretString` ensures the value is zeroed on drop via `Secret<T>`'s `ZeroizeOnDrop`
    /// implementation.  We set `#[zeroize(skip)]` so the outer `Zeroize` derive does not
    /// try to call `.zeroize()` on `Secret<String>` directly (it doesn't implement `Zeroize`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serde_opt_secret_str::serialize",
        deserialize_with = "serde_opt_secret_str::deserialize"
    )]
    #[zeroize(skip)]
    pub bip32_seed: Option<SecretString>,

    /// base64-encoded CredentialBundle for VTA auth.
    ///
    /// Same `#[zeroize(skip)]` rationale as `bip32_seed` above.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serde_opt_secret_str::serialize",
        deserialize_with = "serde_opt_secret_str::deserialize"
    )]
    #[zeroize(skip)]
    pub credential_bundle: Option<SecretString>,

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
                bip32_seed: Some(seed.clone()),
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
                credential_bundle: Some(credential_bundle.clone()),
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

        let formatted = if let Some(_token) = token {
            #[cfg(feature = "openpgp-card")]
            {
                use crate::openpgp_card::crypt::token_encrypt;

                let (esk, data) = token_encrypt(_token, &input, touch_prompt)?;
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
    /// Handles two independent migration axes in a single pass:
    ///
    /// 1. **Serde format migration**: blobs written without a `"format"` tag
    ///    (old untagged format) are transparently promoted to the new tagged
    ///    format on first load.
    /// 2. **HKDF scheme migration**: `PasswordEncrypted` blobs written with the
    ///    v1 nonce-as-salt scheme (`version` absent or `1`) are re-encrypted
    ///    with the current v2 fixed-salt scheme on first load.
    ///
    /// The security gate ([`assert_format_matches_intent`]) always runs **before**
    /// any re-save so that a downgrade attack cannot be laundered through the
    /// migration path.  A single re-save is performed when either (or both)
    /// migrations are needed.
    ///
    /// # Parameters
    /// - `token`: Hardware token identifier if being used
    /// - `unlock`: Password/PIN to unlock secret storage if no hardware token
    ///
    /// If both `token` and `unlock` are `None`, assumes no protection apart from
    /// the OS Secure Store itself.
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

        let secret = match entry.get_secret() {
            Ok(s) => s,
            Err(e) => {
                error!("Couldn't find Secure Config in the OS Secret Store. Fatal Error: {e}");
                return Err(OpenVTCError::Config(format!(
                    "Couldn't find openvtc secured configuration. Reason: {e}"
                )));
            }
        };

        // ── Step 1: Deserialize — try tagged format, fall back to legacy untagged ──
        let (raw_secured_config, serde_migration_needed) =
            match serde_json::from_slice::<SecuredConfigFormat>(secret.as_slice()) {
                // Fast path: new tagged format — no serde migration needed.
                Ok(format) => (format, false),
                // Slow path: try legacy untagged format.
                Err(tagged_err) => {
                    warn!(
                        "Tagged config deserialization failed ({tagged_err}); \
                         attempting legacy untagged migration"
                    );
                    match serde_json::from_slice::<LegacySecuredConfigFormat>(secret.as_slice()) {
                        Ok(legacy) => (SecuredConfigFormat::from(legacy), true),
                        Err(legacy_err) => {
                            error!(
                                "Format of SecuredConfig in OS Secure Store is invalid! \
                                 Tagged error: {tagged_err}, Legacy error: {legacy_err}"
                            );
                            return Err(OpenVTCError::Config(format!(
                                "Couldn't load openvtc secured configuration. Reason: {tagged_err}"
                            )));
                        }
                    }
                }
            };

        // ── Step 2: Security gate — MUST run before any re-save ──────────────────
        // Cross-validate the stored format against the caller's supplied
        // credentials *before* attempting decryption or writing anything back.
        // This is the second defence layer against silent encryption-downgrade
        // attacks: even a correctly-tagged-but-weaker blob (e.g. PlainText where
        // PasswordEncrypted is expected) is rejected here with a hard error.
        assert_format_matches_intent(&raw_secured_config, token.is_some(), unlock.is_some())?;

        // ── Step 3: Decrypt — version field drives v1 vs v2 HKDF ─────────────────
        let (sc, needs_hkdf_migration) = raw_secured_config.unlock(
            #[cfg(feature = "openpgp-card")]
            user_pin,
            token,
            unlock,
            #[cfg(feature = "openpgp-card")]
            touch_prompt,
        )?;

        // ── Step 4: Auto-migrate — single re-save if either migration is needed ──
        // Both migrations (serde format and HKDF scheme) are collapsed into one
        // keychain write to minimise I/O and reduce the window for partial updates.
        if serde_migration_needed || needs_hkdf_migration {
            if needs_hkdf_migration {
                info!("Migrated legacy HKDF scheme (nonce-as-salt) to new fixed-salt version");
            }
            if serde_migration_needed {
                info!("Migrated legacy config to new tagged format");
            }

            let unlock_vec = unlock.map(|uc| uc.0.expose_secret().to_vec());
            sc.save(
                profile,
                token,
                unlock_vec.as_ref(),
                #[cfg(feature = "openpgp-card")]
                &|| {},
            )
            .unwrap_or_else(|e| {
                warn!("Auto-migration: failed to re-save config: {e}");
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
    /// Key Material will be stored in the OS Secure Store.
    ///
    /// `#[zeroize(skip)]`: `Secret<String>` zeroes itself on drop; the outer
    /// `Zeroize` derive cannot call `.zeroize()` on it directly.
    Imported {
        #[serde(with = "serde_secret_str")]
        #[zeroize(skip)]
        seed: SecretString,
    },

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

/// Fixed domain-separation constant for HKDF key derivation (v2 scheme).
///
/// This value serves as the HKDF salt (RFC 5869 §3.1) and provides
/// domain separation between different uses of the same unlock code.
/// The unlock code already carries 32 bytes of entropy, so a fixed,
/// labelled salt is correct here — the salt's role is domain separation,
/// not additional entropy.
///
/// **Never change this constant after deployment** — any change would make all
/// existing v2 blobs permanently undecryptable.  The value was generated from
/// `/dev/urandom` and is intentionally not a human-readable string.
///
/// Crucially, the salt is **not** the AES-GCM nonce — key derivation and
/// per-message randomness must be kept independent (contrast with v1 legacy).
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

/// v2: derive AES-256-GCM key using a **fixed** HKDF salt (domain-separation constant).
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

/// Decrypt a blob produced by the **v2** (fixed-salt) scheme.
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

/// Decrypt a blob produced by the **v1 (legacy)** nonce-as-salt scheme.
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
/// The HKDF key is derived from `unlock` with a fixed, high-entropy
/// domain-separation salt (`HKDF_SALT`).  A fresh random 12-byte nonce is
/// generated for every call and prepended to the output.
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
        Err(v2_err) => {
            // v2 failed; log at debug before trying the legacy fallback.
            debug!("v2 decrypt failed ({v2_err}); trying legacy v1 nonce-as-salt fallback");
            // TODO: remove this legacy fallback after v0.3.0 once all blobs have migrated.
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
        // SecretString zeroes itself via ZeroizeOnDrop when dropped.
        // We just verify the variant is constructed and accessible correctly.
        let source = KeySourceMaterial::Imported {
            seed: SecretString::new("z6MkTestSeed123456789".into()),
        };
        match &source {
            KeySourceMaterial::Imported { seed } => {
                assert!(!seed.expose_secret().is_empty())
            }
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
        let pass_enc = SecuredConfigFormat::PasswordEncrypted {
            data: "xyz".into(),
            version: CRYPTO_VERSION_CURRENT,
        };
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
            version: CRYPTO_VERSION_CURRENT,
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
        let pass_enc = SecuredConfigFormat::PasswordEncrypted {
            data: "x".into(),
            version: CRYPTO_VERSION_CURRENT,
        };
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

    // ── HKDF v2 fixed-salt scheme tests ──────────────────────────────────────

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
        let unlock = [0x55u8; 32];
        let plaintext = b"same plaintext";
        let blob_v2 = unlock_code_encrypt(&unlock, plaintext).unwrap();
        let blob_v1 = make_legacy_v1_blob(&unlock, plaintext);
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
        let unlock = [0x77u8; 32];
        let plaintext = b"transparent migration test";
        let blob_v2 = unlock_code_encrypt(&unlock, plaintext).unwrap();
        let blob_v1 = make_legacy_v1_blob(&unlock, plaintext);
        assert_eq!(unlock_code_decrypt(&unlock, &blob_v2).unwrap(), plaintext);
        assert_eq!(unlock_code_decrypt(&unlock, &blob_v1).unwrap(), plaintext);
    }

    #[test]
    fn test_password_encrypted_v1_sets_migration_flag() {
        let key = [0xC0u8; 32];
        let plaintext = b"{\"bip32_seed\":null,\"credential_bundle\":null,\
            \"vta_url\":null,\"vta_did\":null,\"key_info\":{}}";
        let blob_v1 = make_legacy_v1_blob(&key, plaintext);
        let fmt = SecuredConfigFormat::PasswordEncrypted {
            data: BASE64_URL_SAFE_NO_PAD.encode(&blob_v1),
            version: CRYPTO_VERSION_LEGACY,
        };
        let unlock = UnlockCode(secrecy::SecretBox::new(Box::new(key.to_vec())));
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
        let key = [0xC0u8; 32];
        let plaintext = b"{\"bip32_seed\":null,\"credential_bundle\":null,\
            \"vta_url\":null,\"vta_did\":null,\"key_info\":{}}";
        let blob_v2 = unlock_code_encrypt(&key, plaintext).unwrap();
        let fmt = SecuredConfigFormat::PasswordEncrypted {
            data: BASE64_URL_SAFE_NO_PAD.encode(&blob_v2),
            version: CRYPTO_VERSION_CURRENT,
        };
        let unlock = UnlockCode(secrecy::SecretBox::new(Box::new(key.to_vec())));
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
        // as CRYPTO_VERSION_LEGACY (1), triggering migration.
        // Note: this only works with the untagged legacy deserializer; the
        // tagged format requires the "format" key.
        let json = r#"{"data":"AAAA"}"#;
        let fmt: LegacySecuredConfigFormat = serde_json::from_str(json).unwrap();
        if let LegacySecuredConfigFormat::PasswordEncrypted { version, .. } = fmt {
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

    // ── SecretString tests (from upstream PR #41) ────────────────────────────

    #[test]
    fn test_bip32_seed_is_secret_string() {
        let config = SecuredConfig {
            bip32_seed: Some(SecretString::new("super-secret-seed-value".into())),
            credential_bundle: None,
            vta_url: None,
            vta_did: None,
            key_info: std::collections::HashMap::new(),
            protection_method: ProtectionMethod::default(),
        };
        let debug = format!("{:?}", config);
        assert!(
            !debug.contains("super-secret-seed-value"),
            "SecretString must not leak through Debug formatting"
        );
    }

    #[test]
    fn test_imported_seed_requires_expose() {
        let material = KeySourceMaterial::Imported {
            seed: SecretString::new("z6MkSensitiveKeyData".into()),
        };
        let json = serde_json::to_string(&material).unwrap();
        assert!(json.contains("z6MkSensitiveKeyData"));
        if let KeySourceMaterial::Imported { seed } = &material {
            assert_eq!(seed.expose_secret(), "z6MkSensitiveKeyData");
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
