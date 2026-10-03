//! An X server for X11 forwarding on Windows, the way MobaXterm brings its
//! own: when nothing has set DISPLAY, Reach uses an X server already
//! running on this machine, or starts VcXsrv. VcXsrv is downloaded the
//! first time it is needed (the installer stays small), checked against a
//! SHA-256 pinned here, and kept under the tools folder.
//!
//! The server is started with a random MIT-MAGIC-COOKIE-1 of Reach's own
//! (`-auth`), never with access control off: nothing on this machine or
//! the network can draw on it without the cookie, and the cookie stays
//! with Reach (the SSH server gets a fake one, see `x11`).

use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

/// The files of the official VcXsrv 21.1.16.1 release (unpacked from
/// vcxsrv-64.21.1.16.1.installer.noadmin.exe, SHA-256 dea6c7d6…d620,
/// without uninstall.exe and plink.exe), with its licence and a note on
/// where the source is.
const VERSION: &str = "21.1.16.1";
const URL: &str = "https://github.com/alexandrosnt/Reach/releases/download/vcxsrv-21.1.16.1/vcxsrv-21.1.16.1-x64.zip";
const SHA256: &str = "2f272a234108595fbe91b0b537fad881c4d11ad52879e1634c844cb9c908ded8";

/// A display Reach can forward to.
#[derive(Debug, Clone)]
pub struct Display {
    /// "localhost:N".
    pub name: String,
    /// The server's cookie, when Reach started it; `None` for a server
    /// someone else runs (its own access control applies).
    pub cookie: Option<Vec<u8>>,
    /// The authority file holding `cookie`, for xauth.
    pub auth_file: Option<PathBuf>,
    /// The xauth that comes with the server.
    pub xauth: Option<PathBuf>,
}

struct Running {
    display: Display,
    child: std::process::Child,
    /// Closing it ends the server: Reach's X server lives as long as Reach.
    _job: Job,
}

fn state() -> &'static tokio::sync::Mutex<Option<Running>> {
    static S: std::sync::OnceLock<tokio::sync::Mutex<Option<Running>>> = std::sync::OnceLock::new();
    S.get_or_init(Default::default)
}

fn root() -> PathBuf {
    crate::app_data_dir().join("tools").join("vcxsrv").join(VERSION)
}

fn port_open(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_millis(300)).is_ok()
}

/// The display to forward to: an X server already running here, Reach's
/// own if it started one, or a new one.
pub async fn ensure(progress: impl Fn(&str)) -> Result<Display, String> {
    let mut st = state().lock().await;
    if let Some(r) = st.as_mut() {
        if r.child.try_wait().ok().flatten().is_none() {
            return Ok(r.display.clone());
        }
        *st = None;
    }
    // Someone else's X server (MobaXterm, VcXsrv, X410, Xming) on :0.
    if port_open(6000) {
        return Ok(Display { name: "localhost:0".into(), cookie: None, auth_file: None, xauth: None });
    }
    let dir = root();
    let exe = dir.join("vcxsrv.exe");
    if !exe.is_file() {
        install(&dir, &progress).await?;
    }
    let running = start(&dir).await?;
    let display = running.display.clone();
    *st = Some(running);
    Ok(display)
}

async fn install(dir: &Path, progress: &impl Fn(&str)) -> Result<(), String> {
    progress(&format!("X11: downloading the X server (VcXsrv {VERSION}, about 48 MB), once…"));
    let bytes = fetch().await?;
    let got: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    if got != SHA256 {
        return Err(format!("the X server download does not match its pinned SHA-256 (got {got}); nothing was installed"));
    }
    progress("X11: unpacking the X server…");
    let staging = dir.with_extension("partial");
    let _ = std::fs::remove_dir_all(&staging);
    let staged = staging.clone();
    tokio::task::spawn_blocking(move || unpack(&bytes, &staged))
        .await
        .map_err(|e| e.to_string())??;
    let _ = std::fs::remove_dir_all(dir);
    // Only a complete, verified tree takes the final name.
    std::fs::rename(staging.join("vcxsrv"), dir).map_err(|e| format!("X server: {e}"))?;
    let _ = std::fs::remove_dir_all(&staging);
    Ok(())
}

async fn fetch() -> Result<Vec<u8>, String> {
    // A development build can use a local copy of the zip.
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os("REACH_DEV_VCXSRV_ZIP") {
        return std::fs::read(p).map_err(|e| e.to_string());
    }
    let client = crate::http::client_builder()
        .user_agent("Reach (https://github.com/alexandrosnt/Reach)")
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(URL).send().await.map_err(|e| format!("X server download failed: {e}"))?;
    let resp = resp.error_for_status().map_err(|e| format!("X server download failed: {e}"))?;
    resp.bytes().await.map(|b| b.to_vec()).map_err(|e| format!("X server download failed: {e}"))
}

/// Unpacks the zip under `into`, refusing any entry that would land
/// outside it.
fn unpack(bytes: &[u8], into: &Path) -> Result<(), String> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|e| e.to_string())?;
    for i in 0..zip.len() {
        let mut f = zip.by_index(i).map_err(|e| e.to_string())?;
        let Some(rel) = f.enclosed_name() else { return Err(format!("unsafe path in the X server zip: {}", f.name())) };
        let out = into.join(rel);
        if f.is_dir() {
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut w = std::fs::File::create(&out).map_err(|e| e.to_string())?;
        std::io::copy(&mut f, &mut w).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// An Xauthority entry for display `n` (any address: the server checks
/// the cookie, not where it is presented from).
fn authority(n: u16, cookie: &[u8]) -> Vec<u8> {
    // FamilyWild (0xffff) with an empty address matches any address.
    let mut out = vec![0xff, 0xff, 0, 0];
    for field in [n.to_string().as_bytes(), b"MIT-MAGIC-COOKIE-1".as_slice(), cookie] {
        out.extend((field.len() as u16).to_be_bytes());
        out.extend(field);
    }
    out
}

async fn start(dir: &Path) -> Result<Running, String> {
    // The first free display from 10 up: below that MobaXterm and the like
    // usually sit. A display with an X<n>.hosts file is skipped: hosts
    // listed there get in without the cookie.
    let n = (10u16..64)
        .find(|n| !port_open(6000 + n) && !dir.join(format!("X{n}.hosts")).exists())
        .ok_or("no free X display number")?;
    let cookie: [u8; 16] = rand::random();
    // VcXsrv takes relative paths from its own folder and refuses any
    // argument over 128 characters, so the files live there under short
    // names (the folder is the user's own, under the app data).
    let auth_name = format!("reach-auth.{n}");
    let auth_file = dir.join(&auth_name);
    std::fs::write(&auth_file, authority(n, &cookie)).map_err(|e| format!("X server: {e}"))?;
    let log = dir.join("reach-vcxsrv.log");

    let mut cmd = std::process::Command::new(dir.join("vcxsrv.exe"));
    cmd.arg(format!(":{n}"))
        .args(["-multiwindow", "-clipboard", "-wgl", "-silent-dup-error", "-notrayicon", "-auth", &auth_name, "-logfile", "reach-vcxsrv.log"])
        .current_dir(dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = cmd.spawn().map_err(|e| format!("could not start the X server: {e}"))?;
    let job = Job::new().map_err(|e| format!("X server: {e}"))?;
    job.assign(&child);

    // OpenGL setup alone takes seconds on a first start.
    for _ in 0..300 {
        if port_open(6000 + n) {
            // A server that lets a client in without the cookie (it could
            // not read the file) is not one to forward to.
            if !refuses_without_cookie(6000 + n) {
                let _ = child.kill();
                return Err(format!("the X server accepts connections without its cookie; not using it (see {})", log.display()));
            }
            let display = Display {
                name: format!("localhost:{n}"),
                cookie: Some(cookie.to_vec()),
                auth_file: Some(auth_file),
                xauth: Some(dir.join("xauth.exe")).filter(|p| p.is_file()),
            };
            tracing::info!("X11: started VcXsrv {VERSION} on display :{n}");
            return Ok(Running { display, child, _job: job });
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("the X server exited ({status}); see {}", log.display()));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = child.kill();
    Err(format!("the X server did not start listening; see {}", log.display()))
}

/// Connects with no authorization and reads the answer: 0 is "Failed".
fn refuses_without_cookie(port: u16) -> bool {
    use std::io::{Read, Write};
    let Ok(mut s) = std::net::TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_secs(2)) else { return false };
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    // Little-endian setup, protocol 11.0, no authorization.
    if s.write_all(&[0x6c, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err() {
        return false;
    }
    let mut first = [0u8; 1];
    matches!(s.read_exact(&mut first), Ok(()) if first[0] == 0)
}

/// A Windows job that kills its processes when Reach closes it or exits.
struct Job(windows::Win32::Foundation::HANDLE);

// SAFETY: a job handle may be used from any thread.
unsafe impl Send for Job {}

impl Job {
    fn new() -> windows::core::Result<Self> {
        use windows::Win32::System::JobObjects::{
            CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };
        // SAFETY: plain Win32 calls with valid arguments; the handle is
        // owned by the returned Job and closed in Drop.
        unsafe {
            let h = CreateJobObjectW(None, None)?;
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                h,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )?;
            Ok(Job(h))
        }
    }

    fn assign(&self, child: &std::process::Child) {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::System::JobObjects::AssignProcessToJobObject;
        let ph = windows::Win32::Foundation::HANDLE(child.as_raw_handle());
        // SAFETY: both handles are valid for the call.
        if let Err(e) = unsafe { AssignProcessToJobObject(self.0, ph) } {
            tracing::warn!("X11: the X server is not tied to Reach's lifetime: {e}");
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: the handle came from CreateJobObjectW and is closed once.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_entry_is_xauth_format() {
        let a = authority(12, &[7; 16]);
        assert_eq!(&a[..4], &[0xff, 0xff, 0, 0]);
        assert_eq!(&a[4..6], &[0, 2]);
        assert_eq!(&a[6..8], b"12");
        assert_eq!(&a[8..10], &[0, 18]);
        assert_eq!(&a[10..28], b"MIT-MAGIC-COOKIE-1");
        assert_eq!(&a[28..30], &[0, 16]);
        assert_eq!(&a[30..], &[7; 16]);
    }

    #[test]
    fn unpack_refuses_paths_outside() {
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            w.start_file("../evil.txt", zip::write::SimpleFileOptions::default()).unwrap();
            std::io::Write::write_all(&mut w, b"x").unwrap();
            w.finish().unwrap();
        }
        let dir = std::env::temp_dir().join(format!("reach-xs-{}", std::process::id()));
        assert!(unpack(&buf, &dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
