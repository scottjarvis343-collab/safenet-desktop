// SafeNet Desktop – front-end glue (Tauri v2)  [DROP-IN COMPLETE WITH PERSISTENT PROTECTED UI]
import { invoke } from "@tauri-apps/api/core";

// ---------- Types ----------
type PairStatus = "paired" | "not paired" | "pairing" | "error";

// ---------- Local daemon endpoints ----------
const ROOT    = "http://127.0.0.1:8765";
const HEALTH  = `${ROOT}/health`;
const PAIR    = `${ROOT}/pair`;
const CONFIG  = `${ROOT}/config`;
const REFRESH = `${ROOT}/refresh`;
const APPLY_DNS_HTTP = `${ROOT}/apply_dns`; // HTTP path to daemon

// ---------- SafeNet DNS (edit if needed) ----------
const PRIMARY_DNS_HOST = "dns.safenettechnology.com"; // informational (not used in enforce)
const SECONDARY_DNS    = ""; // optional

// Primary to ENFORCE when protection is enabled (local DoH proxy)
const ENFORCE_PRIMARY = "127.0.0.1";
// interfaces to pass for apply; [] = all "Up" IPv4 adapters (recommended)
const ENFORCE_INTERFACES: string[] = [];

// ---------- DOM helpers ----------
const el = <T extends HTMLElement>(id: string) => document.getElementById(id) as T | null;

const $pairCode     = () => el<HTMLInputElement>("pairCode");
const $pairBtn      = () => el<HTMLButtonElement>("pairBtn");
const $refreshBtn   = () => el<HTMLButtonElement>("refreshBtn");
const $startBtn     = () => el<HTMLButtonElement>("startDaemon");
const $stopBtn      = () => el<HTMLButtonElement>("stopDaemon");
const $daemonA      = () => el<HTMLAnchorElement>("healthLink");
const $pairBadge    = () => el<HTMLSpanElement>("pairBadge");
const $daemonBadge  = () => el<HTMLSpanElement>("daemonBadge");
const $pairOut      = () => el<HTMLPreElement>("pairOut");

// Will be created dynamically if absent:
let $applyDNSBtnEl: HTMLButtonElement | null = null;
let $resetDNSBtnEl: HTMLButtonElement | null = null;
let $dnsStatusBtnEl: HTMLButtonElement | null = null;

// === NEW: flow state / persistence ===
let $enableProtectionBtn: HTMLButtonElement | null = null;
let _isProtected = false;

// ---------- Small UI setters ----------
function setDaemonBadge(s: "starting..." | "running") {
  const b = $daemonBadge(); if (!b) return;
  b.textContent = s;
  b.className = `badge ${s.replace(" ", "-")}`;
}
function setPairStatus(s: PairStatus) {
  const b = $pairBadge(); if (!b) return;
  b.textContent = s;
  b.className = `badge ${s.replace(" ", "-")}`;
}
function showPairMessage(msg: string) {
  const out = $pairOut(); if (!out) return;
  out.textContent = msg || "";
}
const textln = (...parts: (string | number | undefined)[]) => parts.filter(Boolean).join("") + "\n";

// ---------- NEW: protected banner (separate from device info so it doesn't get overwritten) ----------
function ensureBanner() {
  if (document.getElementById("sn-protect-banner")) return;
  const b = document.createElement("div");
  b.id = "sn-protect-banner";
  b.style.margin = "12px 16px";
  b.style.display = "none";
  b.style.fontWeight = "600";
  b.style.color = "#166534";
  b.style.background = "#ecfdf5";
  b.style.border = "1px solid #86efac";
  b.style.borderRadius = "8px";
  b.style.padding = "10px 12px";
  b.innerText = "";
  const title = document.querySelector(".title");
  if (title?.parentElement) title.parentElement.insertBefore(b, title.nextSibling);
  else document.body.prepend(b);
}
function showBanner(msg: string) {
  ensureBanner();
  const b = document.getElementById("sn-protect-banner") as HTMLDivElement;
  b.innerText = msg;
  b.style.display = "";
}
function hideBanner() {
  const b = document.getElementById("sn-protect-banner") as HTMLDivElement | null;
  if (b) b.style.display = "none";
}

// ---------- Persistence helpers ----------
function setProtectedFlag(on: boolean) {
  _isProtected = on;
  try { localStorage.setItem("sn_protected", on ? "1" : "0"); } catch {}
}
function getProtectedFlag(): boolean {
  try { return localStorage.getItem("sn_protected") === "1"; } catch { return false; }
}

// ---------- Device info renderer ----------
function updateDeviceInfo(data: any) {
  const out = $pairOut(); if (!out) return;
  const lines: string[] = [];

  const cid        = data?.cid ?? data?.device?.cid ?? data?.user?.cid ?? data?.dns?.clientId;
  const deviceId   = data?.deviceId ?? data?.device?.id;
  const deviceName = data?.deviceName ?? data?.device?.deviceName ?? data?.device?.name;
  const uniqueId   = data?.uniqueId ?? data?.device?.uniqueId;

  if (cid)        lines.push(textln("CID: ", cid));
  if (deviceId)   lines.push(textln("DeviceID: ", deviceId));
  if (deviceName) lines.push(textln("DeviceName: ", deviceName));
  if (uniqueId)   lines.push(textln("UniqueID: ", uniqueId));

  if (!lines.length) {
    try { lines.push(JSON.stringify(data, null, 2)); } catch {}
  }
  out.textContent = lines.join("");

  if (_isProtected) showBanner("This device is protected by SafeNet.");
}

// ---------- fetch helpers ----------
async function safeJson(res: Response) {
  const text = await res.text();
  try { return { body: JSON.parse(text), raw: text }; }
  catch { return { body: null as any, raw: text }; }
}

// ---------- actions ----------
async function pingHealth() {
  try {
    const r = await fetch(HEALTH, { cache: "no-store" });
    const { body, raw } = await safeJson(r);
    if (!r.ok) throw new Error(`HTTP ${r.status}${raw ? " • " + raw : ""}`);
    setDaemonBadge("running");
    if (body) updateDeviceInfo(body);
    const a = $daemonA(); if (a) a.href = HEALTH;
    return true;
  } catch (e: any) {
    setDaemonBadge("starting...");
    setPairStatus("error");
    showPairMessage(`Health error: ${e?.message || e}`);
    return false;
  }
}

async function doPair() {
  const code = $pairCode()?.value.trim();
  if (!code) { showPairMessage("Enter pairing code"); return; }
  setPairStatus("pairing");
  showPairMessage("");

  try {
    const r = await fetch(PAIR, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code })
    });
    const { body, raw } = await safeJson(r);

    if (!r.ok) {
      setPairStatus("error");
      showPairMessage(`Pairing failed: HTTP ${r.status} • ${raw}`);
      return;
    }
    if (body) updateDeviceInfo(body);
    setPairStatus("paired");
    await doRefresh(); // verify + hydrate

    renderEnableProtection();
  } catch (e: any) {
    setPairStatus("error");
    showPairMessage(`Network error: ${e?.message || e}`);
  }
}

async function doRefresh() {
  try {
    const r = await fetch(CONFIG, { cache: "no-store" });
    const { body, raw } = await safeJson(r);
    if (!r.ok) throw new Error(`HTTP ${r.status}${raw ? " • " + raw : ""}`);
    if (body) updateDeviceInfo(body);
    await pingHealth();
  } catch (e: any) {
    setPairStatus("error");
    showPairMessage(`Refresh error: ${e?.message || e}`);
  }
}

async function startDaemon() {
  try {
    await invoke?.("daemon_start");
    setDaemonBadge("starting...");
    setTimeout(() => { void pingHealth(); }, 700);
  } catch (e: any) {
    showPairMessage(`Start error: ${e?.toString()}`);
  }
}
async function stopDaemon() {
  try {
    await invoke?.("daemon_stop");
    setDaemonBadge("starting...");
  } catch (e: any) {
    showPairMessage(`Stop error: ${e?.toString()}`);
  }
}

// ---------- DNS controls via Tauri commands (kept for advanced section) ----------
async function applyDNS() {
  try {
    const res = await invoke?.("apply_dns", { primary: PRIMARY_DNS_HOST, secondary: SECONDARY_DNS });
    showPairMessage(`DNS applied • ${String(res)}`);
  } catch (e: any) {
    showPairMessage(`Apply DNS error: ${e?.toString()}\nTip: run daemon/app as Administrator.`);
  }
}

async function resetDNS() {
  try {
    const res = await invoke?.("reset_dns");
    showPairMessage(`DNS reset • ${String(res)}`);
  } catch (e: any) {
    showPairMessage(`Reset DNS error: ${e?.toString()}\nTip: run daemon/app as Administrator.`);
  }
}

async function dnsStatus(opts?: { silent?: boolean }) {
  try {
    const res = await invoke?.("dns_status");
    if (!opts?.silent) showPairMessage(`DNS status:\n${String(res)}`);
    return String(res);
  } catch (e: any) {
    if (!opts?.silent) showPairMessage(`DNS status error: ${e?.toString()}`);
    return "";
  }
}

// ---------- NEW: HTTP apply (enforce 127.0.0.1 with watchdog & proxy) ----------
async function applyDNS127Local(interfaces: string[] = ENFORCE_INTERFACES) {
  const body = {
    primary: ENFORCE_PRIMARY,  // 127.0.0.1
    secondary: "",
    interfaces,
  };
  const r = await fetch(APPLY_DNS_HTTP, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const { body: resp, raw } = await safeJson(r);
  if (!r.ok) throw new Error(`HTTP ${r.status}${raw ? " • " + raw : ""}`);
  showPairMessage(`Protection enforced • ${JSON.stringify(resp)}`);
}

// ---------- dynamic DNS block (renders if missing in HTML) ----------
function ensureDNSControls() {
  const pairingBox = document.querySelector('[data-section="pairing"]') || document.body;

  const card = document.createElement("div");
  card.className = "card";
  card.style.marginTop = "16px";
  card.setAttribute("data-dns-card", "1");
  card.innerHTML = `
    <h3 style="margin:0 0 12px 0;">DNS Controls</h3>
    <div style="display:flex; gap:8px; flex-wrap:wrap;">
      <button id="applyDNS" class="btn">Apply SafeNet DNS</button>
      <button id="resetDNS" class="btn">Reset to DHCP</button>
      <button id="dnsStatus" class="btn btn-outline">Show DNS Status</button>
    </div>
  `;
  pairingBox.parentElement?.insertBefore(card, pairingBox.nextSibling);

  $applyDNSBtnEl = document.getElementById("applyDNS") as HTMLButtonElement;
  $resetDNSBtnEl = document.getElementById("resetDNS") as HTMLButtonElement;
  $dnsStatusBtnEl = document.getElementById("dnsStatus") as HTMLButtonElement;

  $applyDNSBtnEl?.addEventListener("click", () => void applyDNS());
  $resetDNSBtnEl?.addEventListener("click", () => void resetDNS());
  $dnsStatusBtnEl?.addEventListener("click", () => void dnsStatus());
}

// ---------- NEW: tiny CSS injector so .hidden actually hides ----------
function ensureHiddenCss() {
  if (document.getElementById("sn-hidden-css")) return;
  const style = document.createElement("style");
  style.id = "sn-hidden-css";
  style.textContent = `.hidden{display:none !important}`;
  document.head.appendChild(style);
}

// ---------- NEW: stronger visual hider for advanced controls ----------
function hideAdvancedControls() {
  ensureHiddenCss();

  const hideEl = (node: HTMLElement | null) => {
    if (!node) return;
    node.style.display = "none";
    node.classList.add("hidden");
  };

  hideEl($startBtn());
  hideEl($stopBtn());
  hideEl($daemonA());

  const upToCard = (n: HTMLElement | null): HTMLElement | null => {
    let cur: HTMLElement | null = n;
    for (let i = 0; i < 6 && cur; i++) {
      if (cur.classList?.contains("card")) return cur;
      if (cur.tagName === "SECTION") return cur;
      cur = cur.parentElement as HTMLElement | null;
    }
    return null;
  };

  const stop = $stopBtn();
  const maybeCard = upToCard(stop);
  if (maybeCard) {
    maybeCard.style.display = "none";
    maybeCard.classList.add("hidden");
  }

  const dnsCard = document.querySelector('[data-dns-card="1"]') as HTMLElement | null;
  if (dnsCard) {
    dnsCard.style.display = "none";
    dnsCard.classList.add("hidden");
  }
}

// ---------- NEW: post-pair Enable Protection button ----------
function renderEnableProtection() {
  hideAdvancedControls();

  if (!$enableProtectionBtn) {
    const pairingBox = document.querySelector('[data-section="pairing"]') || document.body;
    const wrap = document.createElement("div");
    wrap.style.marginTop = "12px";

    $enableProtectionBtn = document.createElement("button");
    $enableProtectionBtn.className = "btn";
    $enableProtectionBtn.textContent = "Enable Protection";

    $enableProtectionBtn.addEventListener("click", async () => {
      try {
        $enableProtectionBtn!.disabled = true;
        $enableProtectionBtn!.textContent = "Enabling…";
        await startDaemon();                 // ensure daemon (RunAs via scheduler)
        await applyDNS127Local(ENFORCE_INTERFACES); // enforce 127.0.0.1 via daemon HTTP
        await fetch(REFRESH).catch(() => {});       // hydrate CID if needed
        markProtected();
      } catch (e: any) {
        alert("Failed to enable protection: " + (e?.message || e));
      } finally {
        $enableProtectionBtn!.disabled = false;
        $enableProtectionBtn!.textContent = "Enable Protection";
      }
    });

    wrap.appendChild($enableProtectionBtn);
    pairingBox.parentElement?.insertBefore(wrap, pairingBox.nextSibling);
  } else {
    $enableProtectionBtn.style.display = "";
  }
}

// ---------- NEW: final protected state ----------
function markProtected() {
  setProtectedFlag(true);
  hideAdvancedControls();
  showBanner("This device is protected by SafeNet.");
  setPairStatus("paired");
  setDaemonBadge("running");
}

// ---------- NEW: on-boot check to restore UI if already protected ----------
async function rehydrateProtection() {
  try {
    const statusStr = await dnsStatus({ silent: true });
    if (statusStr) {
      try {
        const maybe = JSON.parse(statusStr);
        if (maybe && (maybe.enforced === true || maybe.protected === true)) {
          setProtectedFlag(true);
        }
      } catch {
        if (/enforced.+true/i.test(statusStr) || /protected.+true/i.test(statusStr)) {
          setProtectedFlag(true);
        }
      }
    } else if (getProtectedFlag()) {
      setProtectedFlag(true);
    }
  } catch {
    if (getProtectedFlag()) setProtectedFlag(true);
  }

  if (_isProtected) {
    showBanner("This device is protected by SafeNet.");
    if ($enableProtectionBtn) $enableProtectionBtn.style.display = "none";
  }
}

// ---------- One-click top buttons ----------
async function onEnableProtectionClick() {
  try {
    const res = await invoke<string>("protect_enable");
    console.log("Protection enabled:", res);
    // update banner/UI as you already do
  } catch (e: any) {
    alert("Enable protection failed: " + (e?.message || e?.toString() || "unknown error"));
  }
}

async function onRepairStartupClick() {
  try {
    await invoke("ensure_startup_task_cmd");
    alert("Startup entry repaired.");
  } catch (e) {
    alert("Repair failed: " + ((e as any)?.message ?? String(e)));
  }
}

// ---------- wire up ----------
function wire() {
  // Top global buttons
  document.getElementById("enable-protection")?.addEventListener("click", onEnableProtectionClick);
  document.getElementById("repair-startup")?.addEventListener("click", onRepairStartupClick);

  // Pairing + daemon
  $pairBtn()?.addEventListener("click", () => void doPair());
  $refreshBtn()?.addEventListener("click", () => void doRefresh());
  $startBtn()?.addEventListener("click", () => void startDaemon());
  $stopBtn()?.addEventListener("click", () => void stopDaemon());

  // Create the advanced DNS controls card (then we hide it for end-users)
  ensureDNSControls();
  ensureBanner();
  hideAdvancedControls();

  setDaemonBadge("starting...");
  setPairStatus("not paired");
  const a = $daemonA(); if (a) a.href = HEALTH;

  void pingHealth();
  void rehydrateProtection();

  // Cache a handle to the top button for later show/hide
  $enableProtectionBtn = document.getElementById("enable-protection") as HTMLButtonElement | null;
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", wire);
} else {
  wire();
}
