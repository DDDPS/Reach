//! The VNC surface the webview calls. Shaped like the RDP one, so the same
//! desktop panel drives either; see [`crate::vnc`].

use tauri::ipc::Channel;
use tauri::State;

use crate::db::types::Route;
use crate::state::AppState;
use crate::vnc::{Input, MouseAction, VncConnectParams};

/// Open a desktop. Frames arrive on `on_frame`; lifecycle arrives as
/// `vnc-status-{id}` events. Through an SSH session, that login happens
/// here, so a failed one is this command's error.
#[tauri::command]
pub async fn vnc_connect(
    app_handle: tauri::AppHandle,
    state: State<'_, AppState>,
    params: VncConnectParams,
    on_frame: Channel,
) -> Result<(), String> {
    let id = params.id.clone();
    // A panel re-created over a running session only re-attaches; no new
    // SSH login for that.
    let running = state.vnc_manager.lock().await.running(&id);
    let forward = match params.via_session_id.clone().filter(|s| !s.is_empty() && !running) {
        Some(session_id) => {
            let route = Route::Session { session_id };
            crate::ipc::db_commands::forward_route(&app_handle, &state, &route, params.host.clone(), params.port)
                .await
                .inspect_err(|e| tracing::warn!("VNC {id}: SSH leg failed: {e}"))?
        }
        None => None,
    };
    state.vnc_manager.lock().await.connect(app_handle, params, forward, on_frame);
    Ok(())
}

#[tauri::command]
pub async fn vnc_disconnect(state: State<'_, AppState>, id: String) -> Result<(), String> {
    state.vnc_manager.lock().await.disconnect(&id)
}

#[tauri::command]
pub async fn vnc_disconnect_all(state: State<'_, AppState>) -> Result<(), String> {
    state.vnc_manager.lock().await.disconnect_all();
    Ok(())
}

/// The webview painted one frame message; see [`crate::rdp::Flow`].
#[tauri::command]
pub async fn vnc_ack(state: State<'_, AppState>, id: String) -> Result<(), String> {
    state.vnc_manager.lock().await.ack(&id)
}

/// As `rdp_mouse`: `action` is `move`, `down`, `up` or `wheel`; `button` is
/// 0 left, 1 middle, 2 right; `delta` is positive for a notch away.
#[tauri::command]
pub async fn vnc_mouse(
    state: State<'_, AppState>,
    id: String,
    x: u16,
    y: u16,
    action: String,
    button: u8,
    delta: i16,
) -> Result<(), String> {
    let action = MouseAction::parse(&action)?;
    if button > 2 {
        return Err(format!("unknown mouse button {button}"));
    }
    state.vnc_manager.lock().await.send(&id, Input::Mouse { x, y, action, button, delta })
}

/// An X11 keysym going down or up.
#[tauri::command]
pub async fn vnc_key(state: State<'_, AppState>, id: String, keysym: u32, down: bool) -> Result<(), String> {
    state.vnc_manager.lock().await.send(&id, Input::Key { keysym, down })
}

#[tauri::command]
pub async fn vnc_resize(state: State<'_, AppState>, id: String, width: u16, height: u16) -> Result<(), String> {
    state.vnc_manager.lock().await.send(&id, Input::Resize { width, height })
}

/// The desktop gained focus: offer the local clipboard's text to the server.
#[tauri::command]
pub async fn vnc_clipboard_sync(app_handle: tauri::AppHandle, state: State<'_, AppState>, id: String) -> Result<(), String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    // Nothing, or not text, is nothing to offer.
    let Ok(text) = app_handle.clipboard().read_text() else { return Ok(()) };
    state.vnc_manager.lock().await.send(&id, Input::Clipboard(text))
}
