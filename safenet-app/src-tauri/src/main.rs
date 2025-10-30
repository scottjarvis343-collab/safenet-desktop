// SafeNet Desktop – daemon control + DNS bridge (Tauri v2.9.x, Windows)

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    net::{SocketAddr, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::Duration,
};

use std::os::windows::process::CommandExt; // creation_flags()
use tauri::{AppHandle, Emitter, Manager, State};

/// Simple blocking HTTP helper using reqwest (blocking)
fn http_post_json(url: &str, body: serde_json::Value) -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let res = client
        .post(url)
        .json(&body)
        .send()
        .map_err(|e| e.to_string())?;
    let status = res.status();
    let text = res.text().unwrap_or_default();
    if !status.is_success() {
        return Err(format!("HTTP {} • {}", status.as_u16(), text));
    }
    Ok(text)
}

fn http_get_text(url: &str) -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let res = client.get(url).send().map_err(|e| e.to_string())?;
    let status = res.status();
    let text = res.text().unwrap_or_default();
    if !status.is_success() {
        return Err(format!("HTTP {} • {}", status.as_u16(), text));
    }
    Ok(text)
}

// ---------------------------------------------------------------------------
// Global daemon state
struct DaemonState(Mutex<Option<Child>>);

// ---------------------------------------------------------------------------
// Small helpers

fn daemon_health_addr() -> SocketAddr {
    "127.0.0.1:8765".parse().expect("valid loopback socket")
}

fn daemon_is_up() -> bool {
    TcpStream::connect_timeout(&daemon_health_addr(), Duration::from_millis(150)).is_ok()
}

fn pick_daemon_exe() -> Option<&'static str> {
    // Search common dev/build locations
    const CANDIDATES: [&str; 3] = [
        r"C:\safenet-desktop\safenet-app\src-tauri\target\debug\safenet-daemon.exe",
        r"C:\safenet-desktop\safenet-app\safenet-daemon.exe",
        r"C:\safenet-desktop\daemon\safenet-daemon.exe",
    ];
    for p in CANDIDATES {
        if Path::new(p).exists() {
            return Some(p);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Commands

#[tauri::command]
fn daemon_start(app: AppHandle, state: State<DaemonState>) -> Result<(), String> {
    // If already answering on 127.0.0.1:8765, just notify UI.
    if daemon_is_up() {
        let _ = app.emit("daemon://status", "running");
        return Ok(());
    }

    let exe = pick_daemon_exe()
        .ok_or_else(|| "safenet-daemon.exe not found in expected locations".to_string())?;

    let _ = app.emit("daemon://status", "starting");

    // Hidden console window
    let mut cmd = Command::new(exe);
    cmd.creation_flags(0x08000000) // CREATE_NO_WINDOW
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = cmd.spawn().map_err(|e| e.to_string())?;
    *state.0.lock().unwrap() = Some(child);

    // Small delay, then announce "running"
    let handle = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(600));
        let _ = handle.emit("daemon://status", "running");
    });

    Ok(())
}

#[tauri::command]
fn daemon_stop(app: AppHandle, state: State<DaemonState>) -> Result<(), String> {
    let mut guard = state.0.lock().unwrap();
    if let Some(mut child) = guard.take() {
        let _ = child.kill();
    }
    let _ = app.emit("daemon://status", "stopped");
    Ok(())
}

// NEW: Apply Windows DNS (via daemon)
#[tauri::command]
fn apply_dns(primary: String, secondary: String) -> Result<String, String> {
    let url = "http://127.0.0.1:8765/apply_dns";
    let body = serde_json::json!({
        "primary": primary,
        "secondary": secondary
    });
    http_post_json(url, body)
}

// NEW: Reset DNS back to DHCP
#[tauri::command]
fn reset_dns() -> Result<String, String> {
    let url = "http://127.0.0.1:8765/reset_dns";
    let body = serde_json::json!({});
    http_post_json(url, body)
}

// NEW: Read current DNS status
#[tauri::command]
fn dns_status() -> Result<String, String> {
    let url = "http://127.0.0.1:8765/dns_status";
    http_get_text(url)
}

// ---------------------------------------------------------------------------
// Main entry

fn main() {
    tauri::Builder::default()
        .manage(DaemonState(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![daemon_start, daemon_stop, apply_dns, reset_dns, dns_status])
        // Auto-start daemon on app launch (dev convenience),
        // avoiding lifetimes by only moving an owned AppHandle.
        .setup(|app| {
            // Clone an owned AppHandle ONLY. Do NOT grab State here.
            let handle: AppHandle = app.handle().clone();

            std::thread::spawn(move || {
                // give the webview a moment to mount
                std::thread::sleep(Duration::from_millis(300));

                // Re-acquire State inside the thread via the handle (no borrow of `app` escapes).
                let state: State<DaemonState> = handle.state::<DaemonState>();

                // Call with owned AppHandle (clone) + fresh State
                let _ = daemon_start(handle.clone(), state);
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
