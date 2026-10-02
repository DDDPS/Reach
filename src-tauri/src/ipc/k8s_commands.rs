//! The Kubernetes workspace: clusters from a kubeconfig, directly or through
//! an SSH session, and their Helm releases. Every command checks the DevOps
//! switch first.

use serde::Serialize;
use tauri::ipc::Channel;
use tauri::State;

use crate::db::types::Route;
use crate::devops::{self, Tool};
use crate::k8s::helm::{self, Detail, HelmAction, Revision};
use crate::k8s::{self, ContextInfo, EventRow, Kind, ObjectRow, PodRow, WorkloadRow};
use crate::state::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Contexts {
    pub contexts: Vec<ContextInfo>,
    pub current: Option<String>,
}

/// The contexts in a kubeconfig, without connecting to anything.
#[tauri::command]
pub fn k8s_contexts(yaml: String) -> Result<Contexts, String> {
    devops::require(Tool::Kubernetes)?;
    let (contexts, current) = k8s::contexts(&yaml)?;
    Ok(Contexts { contexts, current })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenedCluster {
    pub key: String,
    pub version: String,
    pub namespace: String,
}

/// Connect to `context` of `yaml`. With an SSH route, the API server is
/// reached through it, and its certificate is still checked by name.
#[tauri::command]
pub async fn k8s_open(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    yaml: String,
    context: Option<String>,
    route: Route,
) -> Result<OpenedCluster, String> {
    devops::require(Tool::Kubernetes)?;
    let (list, current) = k8s::contexts(&yaml)?;
    let name = context.clone().or(current).ok_or("The kubeconfig names no context")?;
    let ctx = list.iter().find(|c| c.name == name).ok_or_else(|| format!("No context called {name}"))?;
    let forward = match route {
        Route::Direct => None,
        ref r => {
            let (host, port) = k8s::server_addr(&ctx.server)?;
            crate::ipc::db_commands::forward_route(&app, &state, r, host, port).await?
        }
    };
    let cluster = k8s::connect(&yaml, Some(&name), forward).await?;
    let key = format!("{name}:{}", serde_json::to_string(&route).unwrap_or_default());
    let opened = OpenedCluster { key: key.clone(), version: cluster.version.clone(), namespace: cluster.namespace.clone() };
    state.k8s.lock().await.insert(key, cluster);
    Ok(opened)
}

#[tauri::command]
pub async fn k8s_close(state: State<'_, AppState>, key: String) -> Result<(), String> {
    state.k8s.lock().await.close(&key);
    Ok(())
}

async fn cluster(state: &State<'_, AppState>, key: &str) -> Result<std::sync::Arc<k8s::Cluster>, String> {
    devops::require(Tool::Kubernetes)?;
    state.k8s.lock().await.get(key)
}

/// An empty namespace means all of them.
fn ns(namespace: &Option<String>) -> Option<&str> {
    namespace.as_deref().filter(|n| !n.is_empty())
}

#[tauri::command]
pub async fn k8s_namespaces(state: State<'_, AppState>, key: String) -> Result<Vec<String>, String> {
    cluster(&state, &key).await?.namespaces().await
}

#[tauri::command]
pub async fn k8s_pods(state: State<'_, AppState>, key: String, namespace: Option<String>) -> Result<Vec<PodRow>, String> {
    cluster(&state, &key).await?.pods(ns(&namespace)).await
}

#[tauri::command]
pub async fn k8s_workloads(state: State<'_, AppState>, key: String, namespace: Option<String>) -> Result<Vec<WorkloadRow>, String> {
    cluster(&state, &key).await?.workloads(ns(&namespace)).await
}

#[tauri::command]
pub async fn k8s_objects(state: State<'_, AppState>, key: String, kind: Kind, namespace: Option<String>) -> Result<Vec<ObjectRow>, String> {
    cluster(&state, &key).await?.objects(kind, ns(&namespace)).await
}

#[tauri::command]
pub async fn k8s_events(state: State<'_, AppState>, key: String, namespace: Option<String>) -> Result<Vec<EventRow>, String> {
    cluster(&state, &key).await?.events(ns(&namespace)).await
}

#[tauri::command]
pub async fn k8s_get_yaml(state: State<'_, AppState>, key: String, kind: Kind, namespace: Option<String>, name: String) -> Result<String, String> {
    cluster(&state, &key).await?.get_yaml(kind, ns(&namespace), &name).await
}

#[tauri::command]
pub async fn k8s_replace_yaml(
    state: State<'_, AppState>,
    key: String,
    kind: Kind,
    namespace: Option<String>,
    name: String,
    yaml: String,
) -> Result<(), String> {
    cluster(&state, &key).await?.replace_yaml(kind, ns(&namespace), &name, &yaml).await
}

#[tauri::command]
pub async fn k8s_delete(state: State<'_, AppState>, key: String, kind: Kind, namespace: Option<String>, name: String) -> Result<(), String> {
    cluster(&state, &key).await?.delete(kind, ns(&namespace), &name).await
}

#[tauri::command]
pub async fn k8s_scale(state: State<'_, AppState>, key: String, kind: Kind, namespace: String, name: String, replicas: i32) -> Result<(), String> {
    cluster(&state, &key).await?.scale(kind, &namespace, &name, replicas).await
}

#[tauri::command]
pub async fn k8s_restart(state: State<'_, AppState>, key: String, kind: Kind, namespace: String, name: String) -> Result<(), String> {
    cluster(&state, &key).await?.restart(kind, &namespace, &name).await
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn k8s_logs(
    state: State<'_, AppState>,
    key: String,
    namespace: String,
    pod: String,
    container: Option<String>,
    stream_id: String,
    tail: Option<i64>,
    on_data: Channel<String>,
) -> Result<(), String> {
    let c = cluster(&state, &key).await?;
    state.k8s.lock().await.follow_logs(stream_id, c, namespace, pod, container, tail.unwrap_or(500), on_data);
    Ok(())
}

#[tauri::command]
pub async fn k8s_logs_stop(state: State<'_, AppState>, stream_id: String) -> Result<(), String> {
    state.k8s.lock().await.stop_stream(&stream_id);
    Ok(())
}

#[tauri::command]
pub async fn k8s_helm_releases(state: State<'_, AppState>, key: String, namespace: Option<String>) -> Result<Vec<Revision>, String> {
    cluster(&state, &key).await?.releases(ns(&namespace)).await
}

#[tauri::command]
pub async fn k8s_helm_history(state: State<'_, AppState>, key: String, namespace: String, name: String) -> Result<Vec<Revision>, String> {
    cluster(&state, &key).await?.release_history(&namespace, &name).await
}

#[tauri::command]
pub async fn k8s_helm_detail(state: State<'_, AppState>, key: String, namespace: String, name: String, revision: i32) -> Result<Detail, String> {
    cluster(&state, &key).await?.release_detail(&namespace, &name, revision).await
}

/// Roll back or uninstall a release with `helm` on the host `route` leads
/// to (or this computer), using the kubeconfig `yaml` Reach connected with,
/// so it acts as the same identity on the same cluster. From that host the
/// kubeconfig's server address must be reachable, as it is when the route is
/// the one the cluster was opened through.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn k8s_helm_run(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    route: Route,
    yaml: String,
    action: HelmAction,
    namespace: String,
    name: String,
    revision: Option<i32>,
    kube_context: Option<String>,
) -> Result<String, String> {
    devops::require(Tool::Kubernetes)?;
    k8s::contexts(&yaml)?;
    let cmd = helm::command(action, &namespace, &name, revision, kube_context.as_deref())?;
    let o = match crate::ipc::db_commands::ssh_for_route(&app, &state, &route).await? {
        Some((h, _keep)) => {
            crate::container::Shell::Ssh(h)
                .run_with_input(&helm::with_stdin_kubeconfig(&cmd), Some(yaml.as_bytes()), 900)
                .await?
        }
        None => run_helm_here(&cmd, &yaml).await?,
    };
    if !o.ok() {
        return Err(o.failure("helm"));
    }
    Ok(format!("{}{}", o.stdout, o.stderr))
}

/// Helm on this computer: the kubeconfig in a file of Reach's own, readable
/// by the user only, removed afterwards.
async fn run_helm_here(cmd: &str, yaml: &str) -> Result<crate::container::Output, String> {
    let dir = crate::app_data_dir().join("tmp");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("kubeconfig-{}", uuid::Uuid::new_v4()));
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    {
        use std::io::Write;
        let mut f = o.open(&path).map_err(|e| e.to_string())?;
        f.write_all(yaml.as_bytes()).map_err(|e| e.to_string())?;
    }
    let quoted = if cfg!(windows) { format!("\"{}\"", path.display()) } else { crate::container::sh_quote(&path.display().to_string()) };
    let result = crate::container::Shell::Local.run(&format!("{cmd} --kubeconfig {quoted}"), 900).await;
    let _ = std::fs::remove_file(&path);
    result
}
