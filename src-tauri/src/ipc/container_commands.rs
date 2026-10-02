//! The Containers workspace: Docker and Podman engines and Compose projects,
//! on a server reached through SSH or on this computer. Every command checks
//! the DevOps switch first, so a workspace that is off does nothing.

use serde::Serialize;
use tauri::ipc::Channel;
use tauri::State;

use crate::container::compose::{ComposeAction, Project};
use crate::container::{self, Action, ContainerRow, Engine, HostInfo, ImageRow, NetworkRow, VolumeRow};
use crate::db::types::Route;
use crate::devops::{self, Tool};
use crate::state::AppState;

fn host_key(route: &Route, engine: Engine) -> String {
    format!("{}:{}", engine.cli(), serde_json::to_string(route).unwrap_or_default())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Opened {
    pub key: String,
    pub info: HostInfo,
}

/// Connect to `engine` on the host `route` leads to. Reconnecting replaces
/// the previous connection to the same host.
#[tauri::command]
pub async fn ctr_open(app: tauri::AppHandle, state: State<'_, AppState>, route: Route, engine: Engine) -> Result<Opened, String> {
    devops::require(Tool::Containers)?;
    let ssh = crate::ipc::db_commands::ssh_for_route(&app, &state, &route).await?;
    let host = container::open(engine, ssh).await?;
    let key = host_key(&route, engine);
    let info = state.containers.lock().await.insert(key.clone(), host);
    Ok(Opened { key, info })
}

#[tauri::command]
pub async fn ctr_close(state: State<'_, AppState>, key: String) -> Result<(), String> {
    state.containers.lock().await.close(&key);
    Ok(())
}

async fn host(state: &State<'_, AppState>, key: &str) -> Result<std::sync::Arc<container::Host>, String> {
    devops::require(Tool::Containers)?;
    state.containers.lock().await.get(key)
}

#[tauri::command]
pub async fn ctr_containers(state: State<'_, AppState>, key: String) -> Result<Vec<ContainerRow>, String> {
    host(&state, &key).await?.containers().await
}

#[tauri::command]
pub async fn ctr_images(state: State<'_, AppState>, key: String) -> Result<Vec<ImageRow>, String> {
    host(&state, &key).await?.images().await
}

#[tauri::command]
pub async fn ctr_volumes(state: State<'_, AppState>, key: String) -> Result<Vec<VolumeRow>, String> {
    host(&state, &key).await?.volumes().await
}

#[tauri::command]
pub async fn ctr_networks(state: State<'_, AppState>, key: String) -> Result<Vec<NetworkRow>, String> {
    host(&state, &key).await?.networks().await
}

#[tauri::command]
pub async fn ctr_projects(state: State<'_, AppState>, key: String) -> Result<Vec<Project>, String> {
    host(&state, &key).await?.projects().await
}

#[tauri::command]
pub async fn ctr_act(state: State<'_, AppState>, key: String, id: String, action: Action) -> Result<(), String> {
    host(&state, &key).await?.act(&id, action).await
}

#[tauri::command]
pub async fn ctr_remove(state: State<'_, AppState>, key: String, kind: String, id: String) -> Result<(), String> {
    let h = host(&state, &key).await?;
    match kind.as_str() {
        "image" => h.remove_image(&id).await,
        "volume" => h.remove_volume(&id).await,
        "network" => h.remove_network(&id).await,
        other => Err(format!("Unknown kind {other}")),
    }
}

#[tauri::command]
pub async fn ctr_inspect(state: State<'_, AppState>, key: String, kind: String, id: String) -> Result<String, String> {
    host(&state, &key).await?.inspect(&kind, &id).await
}

#[tauri::command]
pub async fn ctr_compose(state: State<'_, AppState>, key: String, project: String, action: ComposeAction) -> Result<String, String> {
    host(&state, &key).await?.compose(&project, action).await
}

/// Follow a container's log into `on_data` until [`ctr_logs_stop`].
#[tauri::command]
pub async fn ctr_logs(
    state: State<'_, AppState>,
    key: String,
    id: String,
    stream_id: String,
    tail: Option<u32>,
    on_data: Channel<String>,
) -> Result<(), String> {
    let h = host(&state, &key).await?;
    state.containers.lock().await.follow_logs(stream_id, h, id, tail.unwrap_or(500), on_data);
    Ok(())
}

#[tauri::command]
pub async fn ctr_logs_stop(state: State<'_, AppState>, stream_id: String) -> Result<(), String> {
    state.containers.lock().await.stop_stream(&stream_id);
    Ok(())
}

/// The shell command that opens a terminal inside a container: bash if the
/// image has it, sh otherwise. The terminal tab runs it on the same host.
#[tauri::command]
pub fn ctr_shell_command(engine: Engine, id: String) -> Result<String, String> {
    devops::require(Tool::Containers)?;
    Ok(format!(
        "{} exec -it {} sh -c 'if command -v bash >/dev/null 2>&1; then exec bash; else exec sh; fi'",
        engine.cli(),
        container::sh_quote(&id)
    ))
}
