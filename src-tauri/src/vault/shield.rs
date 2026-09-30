//! Keys kept encrypted in memory, and never swapped to disk.
//!
//! The vault's long-lived keys (the key that unlocks the vault, each vault's
//! master key, the identity key) are in memory for as long as the vault is
//! unlocked. Held as plain bytes, any read of this process's memory, a dump,
//! a scraper or a side channel such as Spectre or Rowhammer, would hand them
//! over whole.
//!
//! So they are held encrypted, the way OpenSSH shields private keys since
//! 8.1 and Sequoia PGP's `mem::Encrypted` does after it. Once per process a
//! 16 KiB random prekey is made. Each secret gets its own random salt, is
//! sealed with XChaCha20-Poly1305 under SHA-512(salt ‖ prekey), and is opened
//! only for the length of a call ([`Shielded::with`]), into a buffer that is
//! wiped as the call returns. To read a key an attacker needs all 16 KiB of
//! the prekey without a single wrong bit, which is what makes partial and
//! noisy reads useless.
//!
//! The prekey and every opened buffer are locked into RAM (`memsec::mlock`:
//! `VirtualLock` on Windows, `mlock` elsewhere, and on Linux left out of core
//! dumps), so neither reaches the swap file. Locking is best-effort: a system
//! that refuses it (Linux caps how much a process may lock) is logged once,
//! and the keys stay encrypted regardless.

use std::sync::OnceLock;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

/// OpenSSH and Sequoia both use four 4 KiB pages.
const PREKEY_LEN: usize = 4 * 4096;

struct Prekey {
    bytes: Box<[u8; PREKEY_LEN]>,
    locked: bool,
}

/// Made on first use and kept for the life of the process: every shielded
/// secret depends on it.
fn prekey() -> &'static Prekey {
    static PREKEY: OnceLock<Prekey> = OnceLock::new();
    PREKEY.get_or_init(|| {
        let mut bytes = Box::new([0u8; PREKEY_LEN]);
        rand::fill(&mut bytes[..]);
        let locked = lock(bytes.as_mut_ptr(), PREKEY_LEN);
        if !locked {
            tracing::warn!("Could not lock the key-shielding prekey into RAM; keys stay encrypted in memory");
        }
        Prekey { bytes, locked }
    })
}

/// Whether the prekey is locked into RAM. For the tests.
pub(crate) fn prekey_locked() -> bool {
    prekey().locked
}

fn lock(ptr: *mut u8, len: usize) -> bool {
    // SAFETY: `ptr` points at `len` bytes this module owns and keeps alive
    // until the matching `unlock`.
    unsafe { memsec::mlock(ptr, len) }
}

fn unlock(ptr: *mut u8, len: usize) {
    // SAFETY: as for `lock`; munlock also wipes the bytes first.
    unsafe {
        memsec::munlock(ptr, len);
    }
}

fn sealing_key(salt: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hash = Sha512::new();
    hash.update(salt);
    hash.update(&prekey().bytes[..]);
    let mut digest = hash.finalize();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest[..32]);
    digest.as_mut_slice().zeroize();
    key
}

/// Every salt is fresh and so is the key it makes, so a nonce of zero is
/// never used twice under one key (the same reasoning as Sequoia's).
const NONCE: [u8; 24] = [0u8; 24];

/// `N` secret bytes, held only encrypted.
pub struct Shielded<const N: usize> {
    salt: [u8; 32],
    sealed: Vec<u8>,
}

/// A secret opened for one call: locked into RAM, wiped and unlocked on drop.
struct Opened<const N: usize>(Box<[u8; N]>);

impl<const N: usize> Opened<N> {
    fn new() -> Self {
        let mut buf = Box::new([0u8; N]);
        lock(buf.as_mut_ptr(), N);
        Self(buf)
    }
}

impl<const N: usize> Drop for Opened<N> {
    fn drop(&mut self) {
        unlock(self.0.as_mut_ptr(), N);
        self.0.zeroize();
    }
}

impl<const N: usize> Shielded<N> {
    /// Shield a secret written straight into a locked buffer by `fill`, so
    /// no unshielded copy is left behind by the caller.
    pub fn from_fn(fill: impl FnOnce(&mut [u8; N])) -> Self {
        let mut opened = Opened::<N>::new();
        fill(&mut opened.0);
        Self::seal(&opened.0)
    }

    /// As [`Shielded::from_fn`], for a `fill` that can fail (a key
    /// derivation, say). Nothing is kept if it does.
    pub fn try_from_fn<E>(fill: impl FnOnce(&mut [u8; N]) -> Result<(), E>) -> Result<Self, E> {
        let mut opened = Opened::<N>::new();
        fill(&mut opened.0)?;
        Ok(Self::seal(&opened.0))
    }

    /// Shield a secret the caller already holds, and wipe the caller's copy.
    pub fn new(mut secret: [u8; N]) -> Self {
        let shielded = Self::seal(&secret);
        secret.zeroize();
        shielded
    }

    fn seal(secret: &[u8; N]) -> Self {
        let mut salt = [0u8; 32];
        rand::fill(&mut salt[..]);
        let cipher = XChaCha20Poly1305::new((&*sealing_key(&salt)).into());
        let sealed = cipher
            .encrypt(&XNonce::from(NONCE), secret.as_slice())
            .expect("XChaCha20-Poly1305 encryption of a fixed-size buffer cannot fail");
        Self { salt, sealed }
    }

    /// Open the secret for the length of `use_it`. The opened copy is locked
    /// into RAM and wiped as soon as `use_it` returns.
    pub fn with<T>(&self, use_it: impl FnOnce(&[u8; N]) -> T) -> T {
        let cipher = XChaCha20Poly1305::new((&*sealing_key(&self.salt)).into());
        let mut plain = Zeroizing::new(
            cipher
                .decrypt(&XNonce::from(NONCE), self.sealed.as_slice())
                .expect("a shielded secret always opens under the process prekey"),
        );
        let mut opened = Opened::<N>::new();
        opened.0.copy_from_slice(&plain);
        plain.zeroize();
        use_it(&opened.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_opens_to_what_it_was() {
        let shielded = Shielded::new([7u8; 32]);
        shielded.with(|k| assert_eq!(k, &[7u8; 32]));
        shielded.with(|k| assert_eq!(k, &[7u8; 32]));
    }

    #[test]
    fn the_same_secret_is_sealed_differently_every_time() {
        let a = Shielded::new([7u8; 32]);
        let b = Shielded::new([7u8; 32]);
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.sealed, b.sealed);
    }

    #[test]
    fn the_prekey_is_locked_into_ram() {
        assert!(prekey_locked(), "the prekey could be swapped to disk");
    }

    /// The attack itself: a key is made, and the whole of this process's
    /// readable memory is searched for its bytes. They must not be there.
    /// The key is never held in the clear by the test either: it is
    /// generated inside the shield and compared through a transform.
    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn the_key_cannot_be_found_anywhere_in_memory() {
        // Recognise the key by its bytes XORed with 0xA5, so the search
        // pattern in memory is not itself the key.
        let mut masked = [0u8; 32];
        let shielded = Shielded::<32>::from_fn(|k| {
            rand::fill(&mut k[..]);
            for (m, b) in masked.iter_mut().zip(k.iter()) {
                *m = b ^ 0xA5;
            }
        });
        // The key is usable...
        shielded.with(|k| assert!(k.iter().zip(masked.iter()).all(|(b, m)| b ^ 0xA5 == *m)));
        // ...and, outside that call, nowhere in memory.
        let hits = memory_scan::count(&masked, 0xA5);
        assert_eq!(hits, 0, "the key's bytes were found in process memory {hits} time(s)");
    }

    /// The same attack on a real vault key: derived from a password with
    /// Argon2id, as unlocking does, and then looked for everywhere. Argon2's
    /// working memory, the derivation's output and any copy on the way would
    /// all show up here.
    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn a_password_derived_vault_key_is_nowhere_in_memory() {
        let salt = [3u8; 32];
        let kek = crate::vault::kdf::derive_kek(b"a vault password", &salt).unwrap();
        let mut masked = [0u8; 32];
        kek.with_key(|k| {
            for (m, b) in masked.iter_mut().zip(k.iter()) {
                *m = b ^ 0x3C;
            }
        });
        let hits = memory_scan::count(&masked, 0x3C);
        assert_eq!(hits, 0, "the derived key was found in process memory {hits} time(s)");
    }

    /// The control for the test above: a key held the ordinary way is found.
    /// Without it a scan that finds nothing would prove nothing.
    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn a_key_held_in_the_clear_is_found() {
        let mut masked = [0u8; 32];
        rand::fill(&mut masked[..]);
        let plain: Box<[u8; 32]> = Box::new(std::array::from_fn(|i| masked[i] ^ 0x5A));
        assert!(memory_scan::count(&masked, 0x5A) >= 1, "the scan cannot see a key in plain memory");
        drop(plain);
    }

    #[cfg(any(windows, target_os = "linux"))]
    mod memory_scan {
        /// How many times `masked ^ mask` appears in this process's readable
        /// memory.
        pub fn count(masked: &[u8; 32], mask: u8) -> usize {
            let mut hits = 0;
            for (start, len) in regions() {
                let mut buf = vec![0u8; len];
                if !read(start, &mut buf) {
                    continue;
                }
                let first = masked[0] ^ mask;
                let mut i = 0;
                while i + 32 <= buf.len() {
                    if buf[i] == first && buf[i..i + 32].iter().zip(masked).all(|(b, m)| b ^ mask == *m) {
                        hits += 1;
                    }
                    i += 1;
                }
            }
            hits
        }

        #[cfg(windows)]
        fn regions() -> Vec<(usize, usize)> {
            use windows::Win32::System::Memory::{
                VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
            };
            let mut out = Vec::new();
            let mut addr = 0usize;
            loop {
                let mut info = MEMORY_BASIC_INFORMATION::default();
                // SAFETY: VirtualQuery only reads the address space map.
                let n = unsafe {
                    VirtualQuery(Some(addr as *const _), &mut info, std::mem::size_of::<MEMORY_BASIC_INFORMATION>())
                };
                if n == 0 {
                    break;
                }
                let readable = info.State == MEM_COMMIT
                    && (info.Protect.0 & PAGE_NOACCESS.0) == 0
                    && (info.Protect.0 & PAGE_GUARD.0) == 0;
                if readable {
                    out.push((info.BaseAddress as usize, info.RegionSize));
                }
                addr = info.BaseAddress as usize + info.RegionSize;
            }
            out
        }

        #[cfg(windows)]
        fn read(start: usize, buf: &mut [u8]) -> bool {
            use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
            use windows::Win32::System::Threading::GetCurrentProcess;
            // SAFETY: ReadProcessMemory copies into `buf` and fails rather
            // than faulting on memory that changed under it.
            unsafe {
                ReadProcessMemory(GetCurrentProcess(), start as *const _, buf.as_mut_ptr().cast(), buf.len(), None)
                    .is_ok()
            }
        }

        #[cfg(target_os = "linux")]
        fn regions() -> Vec<(usize, usize)> {
            std::fs::read_to_string("/proc/self/maps")
                .unwrap_or_default()
                .lines()
                .filter_map(|line| {
                    let mut parts = line.split_whitespace();
                    let range = parts.next()?;
                    let perms = parts.next()?;
                    if !perms.starts_with('r') {
                        return None;
                    }
                    let (a, b) = range.split_once('-')?;
                    let (a, b) = (usize::from_str_radix(a, 16).ok()?, usize::from_str_radix(b, 16).ok()?);
                    // Skip the vsyscall page and huge reservations.
                    (b > a && b - a < (1 << 30)).then_some((a, b - a))
                })
                .collect()
        }

        #[cfg(target_os = "linux")]
        fn read(start: usize, buf: &mut [u8]) -> bool {
            use std::io::{Read, Seek, SeekFrom};
            let Ok(mut mem) = std::fs::File::open("/proc/self/mem") else { return false };
            mem.seek(SeekFrom::Start(start as u64)).is_ok() && mem.read_exact(buf).is_ok()
        }
    }
}
