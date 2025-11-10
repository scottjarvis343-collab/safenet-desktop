// SafeNet Desktop – daemon control + DNS bridge + startup task (Tauri v2.x, Windows)

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    fs,
    path::Path,
    process::{Child, Command},
    sync::Mutex,
    time::Duration,
    net::{SocketAddr, TcpStream},
    os::windows::process::CommandExt, // creation_flags()
};

use tauri::{AppHandle, Emitter, Manager, State};

struct DaemonState(Mutex<Option<Child>>);

fn health_addr() -> SocketAddr { "127.0.0.1:8765".parse().unwrap() }

fn http_post_json(url: &str, body: serde_json::Value) -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| e.to_string())?;
    let res = client.post(url).json(&body).send().map_err(|e| e.to_string())?;
    let status = res.status();
    let text = res.text().unwrap_or_default();
    if !status.is_success() { return Err(format!("HTTP {} • {}", status.as_u16(), text)); }
    Ok(text)
}
fn http_get(url: &str) -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| e.to_string())?;
    let res = client.get(url).send().map_err(|e| e.to_string())?;
    let status = res.status();
    let text = res.text().unwrap_or_default();
    if !status.is_success() { return Err(format!("HTTP {} • {}", status.as_u16(), text)); }
    Ok(text)
}

fn bundled_daemon_path(app: &AppHandle) -> Option<String> {
    if let Ok(res_dir) = app.path().resource_dir() {
        let p = res_dir.join("bin").join("safenet-daemon.exe");
        if p.exists() { return Some(p.to_string_lossy().to_string()); }
    }
    for c in [
        r"C:\safenet-desktop\safenet-app\src-tauri\target\debug\safenet-daemon.exe",
        r"C:\safenet-desktop\safenet-app\safenet-daemon.exe",
        r"C:\safenet-desktop\daemon\safenet-daemon.exe",
    ] {
        if Path::new(c).exists() { return Some(c.to_string()); }
    }
    None
}

fn ensure_startup_task(app: &AppHandle) -> Result<(), String> {
    let Some(exe) = bundled_daemon_path(app) else { return Err("Bundled safenet-daemon.exe not found".into()); };
    if !Path::new(&exe).exists() { return Err(format!("Daemon missing at {}", exe)); }

    let tr_arg = format!(r#""{}""#, exe);
    let out = Command::new("schtasks")
        .args(["/Create","/TN","SafeNet Daemon","/TR",&tr_arg,"/SC","ONLOGON","/RL","HIGHEST","/F"])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output();

    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr).to_string();
            let ps_script = format!(r#"
$action    = New-ScheduledTaskAction -Execute "{exe}"
$trigger   = New-ScheduledTaskTrigger -AtLogOn
$trigger.Delay = "PT5S"
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName "SafeNet Daemon" -Action $action -Trigger $trigger -Principal $principal -Force
"#, exe = exe.replace('\\', r"\\"));
            let ps = Command::new("powershell.exe")
                .args(["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command",&ps_script])
                .creation_flags(0x08000000)
                .output()
                .map_err(|e| format!("schtasks failed ({err}); PS error: {e}"))?;
            if !ps.status.success() {
                return Err(format!("Could not create startup task. schtasks err: {err}; PS out: {}", String::from_utf8_lossy(&ps.stderr)));
            }
            Ok(())
        }
        Err(e) => Err(format!("schtasks spawn error: {e}"))
    }
}

#[tauri::command]
fn daemon_start(app: AppHandle, state: State<DaemonState>) -> Result<(), String> {
    ensure_startup_task(&app)?;
    let out = std::process::Command::new("schtasks")
        .args(["/Run","/TN","SafeNet Daemon"])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| format!("schtasks /Run error: {e}"))?;
    if !out.status.success() {
        return Err(format!("schtasks /Run failed: {}", String::from_utf8_lossy(&out.stderr)));
    }

    for _ in 0..40 {
        if TcpStream::connect_timeout(&health_addr(), Duration::from_millis(250)).is_ok() {
            let _ = app.emit("daemon://status", "running");
            *state.0.lock().unwrap() = None;
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    Err("daemon did not come up (health timeout)".into())
}

#[tauri::command]
fn daemon_stop(app: AppHandle, state: State<DaemonState>) -> Result<(), String> {
    if let Some(mut child) = state.0.lock().unwrap().take() { let _ = child.kill(); }
    let _ = app.emit("daemon://status", "stopped");
    Ok(())
}

#[tauri::command]
fn apply_dns(primary: String, secondary: String) -> Result<String, String> {
    http_post_json("http://127.0.0.1:8765/apply_dns", serde_json::json!({ "primary": primary, "secondary": secondary }))
}
#[tauri::command]
fn reset_dns() -> Result<String, String> {
    http_post_json("http://127.0.0.1:8765/reset_dns", serde_json::json!({}))
}
#[tauri::command]
fn dns_status() -> Result<String, String> {
    http_get("http://127.0.0.1:8765/dns_status")
}
#[tauri::command]
fn ensure_startup_task_cmd(app: AppHandle) -> Result<(), String> {
    ensure_startup_task(&app)
}

/// Return list of UP IPv4 InterfaceAlias values (Wi-Fi/Ethernet/etc).
fn up_ipv4_aliases() -> Vec<String> {
    let ps = r#"$ifs = Get-DnsClient | ? { $_.InterfaceOperationalStatus -eq 'Up' -and $_.AddressFamily -eq 2 }
$ifs | Select-Object -ExpandProperty InterfaceAlias | ConvertTo-Json -Compress"#;

    let out = Command::new("powershell.exe")
        .args(["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command", ps])
        .creation_flags(0x08000000)
        .output();

    if let Ok(o) = out {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s.is_empty() { return vec![]; }
        // Can be ["Wi-Fi","Ethernet"] or "Wi-Fi"
        if s.starts_with('[') {
            serde_json::from_str::<Vec<String>>(&s).unwrap_or_default()
        } else {
            vec![s.trim_matches('"').to_string()]
        }
    } else {
        vec![]
    }
}

fn contains_127(status_json: &str, aliases: &[String]) -> bool {
    // cheap check: look for 127.0.0.1 lines for any of the aliases we applied to
    let want = "127.0.0.1";
    if !status_json.contains(want) { return false; }
    if aliases.is_empty() { return status_json.contains(want); }
    for a in aliases {
        if status_json.contains(a) && status_json.contains(want) { return true; }
    }
    false
}

/// One-click protection: start elevated daemon, force netsh to Wi-Fi/Ethernet (or all UP adapters),
/// and verify 127.0.0.1 is active.
#[tauri::command]
fn protect_enable(app: AppHandle, state: State<DaemonState>) -> Result<String, String> {
    daemon_start(app.clone(), state)?;

    //  Check pairing status first
    let cfg = http_get("http://127.0.0.1:8765/config")?;
    if !cfg.contains("\"cid\"") || cfg.contains("\"cid\":\"\"") {
        return Err("Device not paired: pair this device before enabling protection.".into());
    }

    // Prefer explicit interfaces so daemon uses netsh path
    let mut aliases = up_ipv4_aliases();
    if aliases.is_empty() {
        aliases = vec!["Wi-Fi".into(), "Ethernet".into()];
    }

    // Apply 127.0.0.1 only after verified CID
    let res = http_post_json(
        "http://127.0.0.1:8765/apply_dns",
        serde_json::json!({ "primary": "127.0.0.1", "secondary": "", "interfaces": aliases })
    )?;

    // Optional hydrate (CID/proxy)
    let _ = http_get("http://127.0.0.1:8765/refresh");

    // Verify 127 applied
    let s = http_get("http://127.0.0.1:8765/dns_status")?;
    if !contains_127(&s, &aliases) {
        return Err(format!("Protection not active yet (adapters still not 127.0.0.1). DNS status:\n{}", s));
    }
    Ok(res)
}







fn copy_daemon_to_resources_on_dev(app: &AppHandle) {
    if let Ok(res_dir) = app.path().resource_dir() {
        let target = res_dir.join("bin").join("safenet-daemon.exe");
        if target.exists() { return; }
        for s in [
            r"C:\safenet-desktop\daemon\safenet-daemon.exe",
            r"C:\safenet-desktop\safenet-app\safenet-daemon.exe",
        ] {
            if Path::new(s).exists() {
                let _ = fs::create_dir_all(target.parent().unwrap());
                let _ = fs::copy(s, &target);
                break;
            }
        }
    }
}

fn main() {
    tauri::Builder::default()
        .manage(DaemonState(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            daemon_start,
            daemon_stop,
            apply_dns,
            reset_dns,
            dns_status,
            ensure_startup_task_cmd,
            protect_enable
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            copy_daemon_to_resources_on_dev(&handle);
            // (optional) try to bring daemon up on app launch; ignore errors
            let h2 = handle.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                let state: State<DaemonState> = h2.state::<DaemonState>();
                let _ = daemon_start(h2.clone(), state);
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
