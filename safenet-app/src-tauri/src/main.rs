// C:\safenet-desktop\safenet-app\src-tauri\src\main.rs
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::Duration,
};
use std::os::windows::process::CommandExt; // creation_flags()

use tauri::{AppHandle, Emitter, Manager, State};
use tauri::tray::TrayIconBuilder;
use tauri::menu::{MenuBuilder, MenuItemBuilder, MenuEvent};

/// -------------------------------
/// Simple blocking HTTP helpers
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

/// -------------------------------
/// Global daemon state
struct DaemonState(Mutex<Option<Child>>);

/// -------------------------------
/// Small helpers
fn daemon_health_addr() -> SocketAddr {
    "127.0.0.1:8765".parse().expect("valid loopback socket")
}

fn daemon_is_up() -> bool {
    TcpStream::connect_timeout(&daemon_health_addr(), Duration::from_millis(180)).is_ok()
}

/// Resolve the directory of the running UI exe
fn ui_exe_dir() -> Option<PathBuf> {
    std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf()))
}

/// Pick the daemon exe (universal first: beside the UI exe; then dev fallbacks)
fn pick_daemon_exe() -> Option<PathBuf> {
    // 1) Beside the UI exe (universal install)
    if let Some(dir) = ui_exe_dir() {
        let cand = dir.join("safenet-daemon.exe");
        if cand.exists() { return Some(cand); }
    }
    // 2) Known dev/build locations
    const CANDIDATES: [&str; 3] = [
        r"C:\safenet-desktop\safenet-app\safenet-daemon.exe",
        r"C:\safenet-desktop\safenet-app\src-tauri\target\debug\safenet-daemon.exe",
        r"C:\safenet-desktop\daemon\safenet-daemon.exe",
    ];
    for p in CANDIDATES {
        let pb = Path::new(p);
        if pb.exists() { return Some(pb.to_path_buf()); }
    }
    None
}

/// Wait (briefly) for the daemon to open its port
fn wait_for_daemon(max_ms: u64) {
    let mut waited = 0u64;
    let mut backoff = 150u64;
    while waited < max_ms {
        if daemon_is_up() { break; }
        std::thread::sleep(Duration::from_millis(backoff));
        waited += backoff;
        backoff = std::cmp::min(backoff * 2, 600);
    }
}

/// -------------------------------
/// Commands (existing)

#[tauri::command]
fn daemon_start(app: AppHandle, state: State<DaemonState>) -> Result<(), String> {
    if daemon_is_up() {
        let _ = app.emit("daemon://status", "running");
        return Ok(());
    }

    let exe = pick_daemon_exe()
        .ok_or_else(|| "safenet-daemon.exe not found beside app or in known paths".to_string())?;

    let _ = app.emit("daemon://status", "starting");

    let mut cmd = Command::new(exe);
    cmd.creation_flags(0x08000000) // CREATE_NO_WINDOW
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = cmd.spawn().map_err(|e| e.to_string())?;
    *state.0.lock().unwrap() = Some(child);

    // Proactively wait a moment so first UI fetches don't race the socket start
    wait_for_daemon(2500);

    let handle = app.clone();
    std::thread::spawn(move || {
        // Emit final status (in case UI listens)
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

// Apply via daemon (simple sync path kept for compatibility)
#[tauri::command]
fn apply_dns(primary: String, secondary: String) -> Result<String, String> {
    let url = "http://127.0.0.1:8765/apply_dns";
    let body = serde_json::json!({
        "primary": primary,
        "secondary": secondary
    });
    http_post_json(url, body)
}

// NOTE: keep implemented but DO NOT register in invoke_handler (parental-control hardening)
// #[tauri::command]
// fn reset_dns() -> Result<String, String> {
//     let url = "http://127.0.0.1:8765/reset_dns";
//     let body = serde_json::json!({});
//     http_post_json(url, body)
// }

#[tauri::command]
fn dns_status() -> Result<String, String> {
    let url = "http://127.0.0.1:8765/dns_status";
    http_get_text(url)
}

/// -------------------------------
/// NEW: Async commands (kept & improved)
#[tauri::command]
async fn sn_enforce_dns(
    enable: bool,
    cid: Option<String>,
    interfaces: Vec<String>,
) -> Result<String, String> {
    let client = reqwest::Client::new();

    if enable {
        // 1) Ensure we have CID from daemon if not provided
        let got_cid = if let Some(c) = cid { c } else {
            let h = client.get("http://127.0.0.1:8765/health")
                .send().await.map_err(|e| e.to_string())?
                .json::<serde_json::Value>().await.map_err(|e| e.to_string())?;
            h.get("cid").and_then(|v| v.as_str()).unwrap_or_default().to_string()
        };

        // 2) Ask daemon to apply with hostname (daemon will resolve to IPv4)
        let body = serde_json::json!({
            "primary": "dns.safenettechnology.com",
            "secondary": "",
            "interfaces": interfaces,
            "cid": got_cid
        });
        let res = client
            .post("http://127.0.0.1:8765/apply_dns")
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let text = res.text().await.map_err(|e| e.to_string())?;
        Ok(text)
    } else {
        let body = serde_json::json!({ "interfaces": interfaces });
        let res = client
            .post("http://127.0.0.1:8765/reset_dns")
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let text = res.text().await.map_err(|e| e.to_string())?;
        Ok(text)
    }
}

#[tauri::command]
async fn sn_dns_status() -> Result<serde_json::Value, String> {
    let res = reqwest::get("http://127.0.0.1:8765/dns_status")
        .await
        .map_err(|e| e.to_string())?;
    let json = res.json::<serde_json::Value>().await.map_err(|e| e.to_string())?;
    Ok(json)
}

/// -------------------------------
/// MAIN ENTRY (tray + daemon autostart)
fn main() {
    tauri::Builder::default()
        .manage(DaemonState(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            daemon_start,
            daemon_stop,
            apply_dns,
            // reset_dns,  // <-- NOT registered on purpose
            dns_status,
            sn_enforce_dns,
            sn_dns_status
        ])
        .setup(|app| {
            // ---- Build the tray (Tauri v2 API) ----
            let item_on  = MenuItemBuilder::with_id("sn_on",  "Enable Filtering").build(app)?;
            let item_off = MenuItemBuilder::with_id("sn_off", "Disable Filtering").build(app)?;
            let menu     = MenuBuilder::new(app).items(&[&item_on, &item_off]).build()?;

            TrayIconBuilder::new()
                .menu(&menu)
                .on_menu_event(|_app, event: MenuEvent| {
                    let id = event.id().as_ref();
                    let client = reqwest::blocking::Client::new();
                    match id {
                        "sn_on" => {
                            // Send hostname; daemon resolves & uses stored CID
                            let _ = client
                                .post("http://127.0.0.1:8765/apply_dns")
                                .json(&serde_json::json!({
                                    "primary": "dns.safenettechnology.com",
                                    "secondary": "",
                                    "interfaces": ["Wi-Fi"]
                                }))
                                .send();
                        }
                        "sn_off" => {
                            let _ = client
                                .post("http://127.0.0.1:8765/reset_dns")
                                .json(&serde_json::json!({
                                    "interfaces": ["Wi-Fi"]
                                }))
                                .send();
                        }
                        _ => {}
                    }
                })
                .build(app)?;

            // ---- Auto-start daemon (universal) ----
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                let state: State<DaemonState> = handle.state::<DaemonState>();
                let _ = daemon_start(handle.clone(), state);
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
