//! Unlocking the vault with the device's own biometrics (Settings → Security).
//!
//! Windows Hello follows Bitwarden's desktop client
//! (`desktop_native/biometric/src/windows.rs`): a Hello key credential signs a
//! fixed random challenge, and the SHA-256 of that signature is the key that
//! seals the vault identity's secret key. Hello's keys are RSA with PKCS#1
//! v1.5 signatures, which are deterministic, so the same challenge always
//! yields the same key, and only a Hello check (face, fingerprint or PIN) on
//! this Windows account can produce it. The sealed key lives in
//! `vault_biometric.json` next to the identity; nothing stored on disk opens
//! it without Hello.
//!
//! Turning it on never takes away another way in: a master password must be
//! set first, and the plain copy of the key in the OS keychain is only
//! removed after Hello has actually opened the vault once
//! ([`Sealed::proven`]). Turning it off puts that copy back.

use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const FILE: &str = "vault_biometric.json";

/// What protects the key, as stored and as shown in Settings.
pub const WINDOWS_HELLO: &str = "windows_hello";

/// The identity's secret key, sealed by a biometric check.
#[derive(Serialize, Deserialize, Clone)]
pub struct Sealed {
    pub user_uuid: String,
    pub method: String,
    challenge: String,
    nonce: String,
    ciphertext: String,
    /// Set once the biometric check has opened the vault for real. Until
    /// then the plain keychain copy stays, in case the seal cannot be opened.
    #[serde(default)]
    pub proven: bool,
}

/// Which method this build offers on this platform, or `None`.
pub fn method() -> Option<&'static str> {
    if cfg!(windows) { Some(WINDOWS_HELLO) } else { None }
}

/// Whether the method can be used now (a Hello PIN or better is set up).
/// Blocking.
pub fn available() -> bool {
    platform::available()
}

pub fn load(app_dir: &Path) -> Option<Sealed> {
    let data = std::fs::read(app_dir.join(FILE)).ok()?;
    match serde_json::from_slice(&data) {
        Ok(sealed) => Some(sealed),
        Err(e) => {
            tracing::warn!("Ignoring an unreadable {}: {}", FILE, e);
            None
        }
    }
}

pub fn save(app_dir: &Path, sealed: &Sealed) -> std::io::Result<()> {
    let tmp = app_dir.join(format!("{FILE}.tmp"));
    std::fs::write(&tmp, serde_json::to_vec_pretty(sealed)?)?;
    std::fs::rename(&tmp, app_dir.join(FILE))
}

pub fn remove(app_dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(app_dir.join(FILE)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

fn aad(user_uuid: &str) -> Vec<u8> {
    [b"reach-biometric-v1:".as_slice(), user_uuid.as_bytes()].concat()
}

/// Seal `secret` behind a biometric check. Blocking; shows the system prompt.
pub fn seal(user_uuid: &str, secret: &[u8]) -> Result<Sealed, String> {
    let challenge: [u8; 32] = rand::random();
    let key = platform::key_for(&challenge, true)?;
    let nonce: [u8; 24] = rand::random();
    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(&XNonce::from(nonce), Payload { msg: secret, aad: &aad(user_uuid) })
        .map_err(|e| e.to_string())?;
    Ok(Sealed {
        user_uuid: user_uuid.to_string(),
        method: WINDOWS_HELLO.to_string(),
        challenge: BASE64.encode(challenge),
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(ciphertext),
        proven: false,
    })
}

/// Open a seal made by [`seal`]. Blocking; shows the system prompt.
pub fn open(sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>, String> {
    let decode = |s: &str| BASE64.decode(s).map_err(|e| e.to_string());
    let challenge = decode(&sealed.challenge)?;
    let nonce: [u8; 24] = decode(&sealed.nonce)?.try_into().map_err(|_| "bad nonce".to_string())?;
    let ciphertext = decode(&sealed.ciphertext)?;
    let key = platform::key_for(&challenge, false)?;
    XChaCha20Poly1305::new((&*key).into())
        .decrypt(&XNonce::from(nonce), Payload { msg: &ciphertext, aad: &aad(&sealed.user_uuid) })
        .map(Zeroizing::new)
        .map_err(|_| "The biometric key did not open the vault key".to_string())
}

/// Delete the platform credential. Best-effort; blocking.
pub fn forget() {
    platform::forget();
}

#[cfg(windows)]
mod platform {
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use windows::core::{s, Array, HSTRING};
    use windows::Security::Credentials::{
        KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
    };
    use windows::Security::Cryptography::CryptographicBuffer;
    use windows::Win32::System::Threading::{AttachThreadInput, GetCurrentThreadId};
    use windows::Win32::UI::WindowsAndMessaging::{
        BringWindowToTop, FindWindowA, GetForegroundWindow, GetWindowThreadProcessId, SetForegroundWindow,
    };
    use zeroize::Zeroizing;

    const CREDENTIAL_NAME: &str = "Reach vault";

    pub fn available() -> bool {
        KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| op.join())
            .unwrap_or(false)
    }

    fn status_error(status: KeyCredentialStatus) -> String {
        match status {
            KeyCredentialStatus::UserCanceled => "Windows Hello was cancelled".into(),
            KeyCredentialStatus::UserPrefersPassword => "Windows Hello was declined".into(),
            KeyCredentialStatus::NotFound => "Windows Hello has no key for Reach".into(),
            KeyCredentialStatus::SecurityDeviceLocked => "Windows Hello is locked after too many attempts".into(),
            other => format!("Windows Hello failed (status {})", other.0),
        }
    }

    fn credential(create: bool) -> Result<KeyCredential, String> {
        let name = HSTRING::from(CREDENTIAL_NAME);
        let result = if create {
            with_prompt_in_front(|| {
                KeyCredentialManager::RequestCreateAsync(&name, KeyCredentialCreationOption::FailIfExists)?.join()
            })
        } else {
            KeyCredentialManager::OpenAsync(&name).and_then(|op| op.join())
        }
        .map_err(|e| e.to_string())?;
        match result.Status().map_err(|e| e.to_string())? {
            KeyCredentialStatus::Success => result.Credential().map_err(|e| e.to_string()),
            KeyCredentialStatus::CredentialAlreadyExists if create => credential(false),
            status => Err(status_error(status)),
        }
    }

    /// SHA-256 of Hello's signature over `challenge`.
    pub fn key_for(challenge: &[u8], create: bool) -> Result<Zeroizing<[u8; 32]>, String> {
        let credential = credential(create)?;
        let data = CryptographicBuffer::CreateFromByteArray(challenge).map_err(|e| e.to_string())?;
        let result = with_prompt_in_front(|| credential.RequestSignAsync(&data)?.join()).map_err(|e| e.to_string())?;
        let status = result.Status().map_err(|e| e.to_string())?;
        if status != KeyCredentialStatus::Success {
            return Err(status_error(status));
        }
        let signature = result.Result().map_err(|e| e.to_string())?;
        let mut bytes = Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&signature, &mut bytes).map_err(|e| e.to_string())?;
        let digest = Sha256::digest(&bytes[..]);
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&digest);
        Ok(key)
    }

    pub fn forget() {
        let name = HSTRING::from(CREDENTIAL_NAME);
        if let Err(e) = KeyCredentialManager::DeleteAsync(&name).and_then(|op| op.join()) {
            tracing::debug!("Removing the Windows Hello key: {}", e);
        }
    }

    /// Hello's prompt, asked for by a desktop app, tends to open behind that
    /// app's window. While `f` waits on it, keep bringing it to the front, as
    /// Bitwarden does (`windows_focus.rs`).
    fn with_prompt_in_front<T>(f: impl FnOnce() -> windows::core::Result<T>) -> windows::core::Result<T> {
        let waiting = Arc::new(AtomicBool::new(true));
        let flag = waiting.clone();
        let _ = std::thread::Builder::new().name("hello-focus".into()).spawn(move || {
            while flag.load(Ordering::Relaxed) {
                // SAFETY: plain window lookups and focus calls on handles the
                // system gave us; failures only mean the prompt keeps its place.
                unsafe {
                    if let Ok(prompt) = FindWindowA(s!("Credential Dialog Xaml Host"), None) {
                        if GetForegroundWindow() != prompt {
                            let front = GetWindowThreadProcessId(GetForegroundWindow(), None);
                            let me = GetCurrentThreadId();
                            let attached = front != 0 && front != me && AttachThreadInput(me, front, true).as_bool();
                            let _ = BringWindowToTop(prompt);
                            let _ = SetForegroundWindow(prompt);
                            if attached {
                                let _ = AttachThreadInput(me, front, false);
                            }
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        });
        let result = f();
        waiting.store(false, Ordering::Relaxed);
        result
    }
}

#[cfg(not(windows))]
mod platform {
    use zeroize::Zeroizing;

    pub fn available() -> bool {
        false
    }

    pub fn key_for(_: &[u8], _: bool) -> Result<Zeroizing<[u8; 32]>, String> {
        Err("Biometric unlock is not available on this platform".into())
    }

    pub fn forget() {}
}

#[cfg(test)]
impl Sealed {
    /// A seal for tests: the fields a Hello prompt would fill are dummies.
    pub fn for_test(user_uuid: &str) -> Self {
        Sealed {
            user_uuid: user_uuid.into(),
            method: WINDOWS_HELLO.into(),
            challenge: String::new(),
            nonce: String::new(),
            ciphertext: String::new(),
            proven: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seal_file_survives_a_round_trip_and_removal() {
        let dir = std::env::temp_dir().join(format!("reach-bio-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(load(&dir).is_none());
        let sealed = Sealed {
            user_uuid: "u".into(),
            method: WINDOWS_HELLO.into(),
            challenge: BASE64.encode([1u8; 32]),
            nonce: BASE64.encode([2u8; 24]),
            ciphertext: BASE64.encode([3u8; 48]),
            proven: false,
        };
        save(&dir, &sealed).unwrap();
        let back = load(&dir).unwrap();
        assert_eq!(back.user_uuid, "u");
        assert!(!back.proven);
        remove(&dir).unwrap();
        remove(&dir).unwrap();
        assert!(load(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Asks the real platform; run by hand: `cargo test hello_probe -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn hello_probe() {
        let t = std::time::Instant::now();
        println!("method={:?} available={} in {:?}", method(), available(), t.elapsed());
    }

    #[test]
    fn a_seal_is_bound_to_its_user() {
        // The cipher half of seal/open, without the Hello prompt.
        let key = [7u8; 32];
        let nonce = [9u8; 24];
        let cipher = XChaCha20Poly1305::new((&key).into());
        let ct = cipher.encrypt(&XNonce::from(nonce), Payload { msg: b"secret", aad: &aad("alice") }).unwrap();
        assert!(cipher.decrypt(&XNonce::from(nonce), Payload { msg: &ct, aad: &aad("bob") }).is_err());
        assert_eq!(cipher.decrypt(&XNonce::from(nonce), Payload { msg: &ct, aad: &aad("alice") }).unwrap(), b"secret");
    }
}
