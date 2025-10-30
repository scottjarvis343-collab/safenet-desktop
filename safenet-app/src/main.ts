// SafeNet Desktop – front-end glue (Tauri v2)

type PairStatus = "paired" | "not paired" | "pairing" | "error";

// Tauri bridge (optional during dev if invoke is undefined)
const invoke = (window as any).__TAURI__?.invoke as (cmd: string, args?: any) => Promise<any>;

// Local daemon endpoints
const ROOT    = "http://127.0.0.1:8765";
const HEALTH  = `${ROOT}/health`;
const PAIR    = `${ROOT}/pair`;
const CONFIG  = `${ROOT}/config`;
const REFRESH = `${ROOT}/refresh`;

// ---- SafeNet DNS to apply (EDIT if needed) -------------------------------
// Hostnames are OK: the daemon resolves them to IPv4.
const PRIMARY_DNS   = "dns.safenettechnology.com";
const SECONDARY_DNS = ""; // optional

// ---- DOM helpers -----------------------------------------------------------
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

function updateDeviceInfo(data: any) {
  const out = $pairOut(); if (!out) return;
  const lines: string[] = [];

  // normalize common fields
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
}

// ---- fetch helpers ---------------------------------------------------------
async function safeJson(res: Response) {
  const text = await res.text();
  try { return { body: JSON.parse(text), raw: text }; }
  catch { return { body: null as any, raw: text }; }
}

// ---- actions ---------------------------------------------------------------
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

    // Auto-apply SafeNet DNS once paired
    await applyDNS();
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

// ---- DNS controls via Tauri commands --------------------------------------
async function applyDNS() {
  try {
    const res = await invoke?.("apply_dns", { primary: PRIMARY_DNS, secondary: SECONDARY_DNS });
    showPairMessage(`DNS applied • ${String(res)}`);
  } catch (e: any) {
    // Common case: not elevated → Set-DnsClientServerAddress access denied.
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

async function dnsStatus() {
  try {
    const res = await invoke?.("dns_status");
    showPairMessage(`DNS status:\n${String(res)}`);
  } catch (e: any) {
    showPairMessage(`DNS status error: ${e?.toString()}`);
  }
}

// ---- dynamic DNS block (renders if missing in HTML) -----------------------
function ensureDNSControls() {
  // Insert after the "Pairing" section if possible
  const pairingBox = document.querySelector('[data-section="pairing"]') || document.body;

  const card = document.createElement("div");
  card.className = "card";
  card.style.marginTop = "16px";
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

// ---- wire up ---------------------------------------------------------------
function wire() {
  $pairBtn()?.addEventListener("click", () => void doPair());
  $refreshBtn()?.addEventListener("click", () => void doRefresh());
  $startBtn()?.addEventListener("click", () => void startDaemon());
  $stopBtn()?.addEventListener("click", () => void stopDaemon());

  // Build DNS controls dynamically so no HTML edits are needed
  ensureDNSControls();

  setDaemonBadge("starting...");
  setPairStatus("not paired");
  const a = $daemonA(); if (a) a.href = HEALTH;

  void pingHealth();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", wire);
} else {
  wire();
}
