// src-tauri/src/main.rs
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

struct DaemonState(Arc<Mutex<Option<Child>>>);

#[tauri::command]
fn greet(name: String) -> String {
    format!("Hello, {}!", name)
}

#[tauri::command]
async fn daemon_start(state: tauri::State<'_, DaemonState>) -> Result<String, String> {
    let mut slot = state.0.lock().map_err(|_| "mutex poisoned")?;
    if slot.is_some() {
        return Ok("already running".into());
    }
    let bin = if cfg!(target_os = "windows") { "safenet-daemon.exe" } else { "safenet-daemon" };
    let child = Command::new(bin)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to start daemon: {e}"))?;
    *slot = Some(child);
    Ok("started".into())
}

#[tauri::command]
async fn daemon_stop(state: tauri::State<'_, DaemonState>) -> Result<String, String> {
    let mut slot = state.0.lock().map_err(|_| "mutex poisoned")?;
    if let Some(mut child) = slot.take() {
        child.kill().map_err(|e| format!("failed to kill: {e}"))?;
        let _ = child.wait();
        return Ok("stopped".into());
    }
    Ok("not running".into())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(DaemonState(Arc::new(Mutex::new(None))))
        .invoke_handler(tauri::generate_handler![greet, daemon_start, daemon_stop])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
