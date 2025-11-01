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
const CHILD_MODE = true;
const POLL_MS = 10000;

// ---- SafeNet DNS to apply (EDIT if needed) -------------------------------
const PRIMARY_DNS   = "dns.safenettechnology.com";
const SECONDARY_DNS = "";

// ---- pairing state (NEW) --------------------------------------------------
let isPaired = false;
let currentCid = "";

// small show/hide helpers
function hide(el?: HTMLElement | null) { if (el) el.style.display = "none"; }
function show(el?: HTMLElement | null) { if (el) el.style.display = ""; }

// ---- NEW: fetch helpers with timeout & wait-for-daemon --------------------
async function fetchWithTimeout(input: RequestInfo, init: RequestInit = {}, timeoutMs = 1500) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(input, { ...init, signal: controller.signal, cache: "no-store" });
    clearTimeout(id);
    return res;
  } catch (e) {
    clearTimeout(id);
    throw e;
  }
}

async function waitForDaemon(maxAttempts = 25, delayMs = 350): Promise<boolean> {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const r = await fetchWithTimeout(HEALTH, {}, 1000);
      if (r.ok) return true;
    } catch {}
    await new Promise(res => setTimeout(res, delayMs));
  }
  return false;
}

// ---- Safe Tauri invoke with HTTP fallback ----------------------------------
async function i<T = any>(cmd: string, args?: any): Promise<T> {
  const tauriInvoke = (window as any).__TAURI__?.invoke as
    | ((cmd: string, args?: any) => Promise<any>)
    | undefined;

  if (tauriInvoke) return await tauriInvoke(cmd, args);

  // HTTP fallback to daemon
  switch (cmd) {
    case "apply_dns": {
      const r = await fetch(`${ROOT}/apply_dns`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          primary: args?.primary ?? PRIMARY_DNS,
          secondary: args?.secondary ?? "",
        }),
      });
      return (await r.text()) as any;
    }
    case "dns_status": {
      const r = await fetch(`${ROOT}/dns_status`, { cache: "no-store" });
      return (await r.text()) as any;
    }
    case "daemon_start":
    case "daemon_stop":
      return "ok" as any;
    default:
      throw new Error(`invoke unavailable for ${cmd}`);
  }
}

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

let $applyDNSBtnEl: HTMLButtonElement | null = null;
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

// ---- UI gating (NEW) -------------------------------------------------------
function renderUI() {
  // banner/status in your existing device-details box
  const out = $pairOut();
  if (out) {
    out.textContent = isPaired
      ? `This device is protected by SafeNet\nCID: ${currentCid || "(unknown)"}\nFiltering is enforced at the system level.`
      : `Not paired. Enter pairing code to enable protection.`;
  }

  // enable/disable buttons
  $applyDNSBtnEl?.toggleAttribute("disabled", !isPaired);
  $dnsStatusBtnEl?.toggleAttribute("disabled", false);

  // show/hide pairing section
  const pairingSection = document.querySelector('[data-section="pairing"]') as HTMLElement | null;
  if (pairingSection) {
    if (isPaired) hide(pairingSection); else show(pairingSection);
  }

  // badge
  setPairStatus(isPaired ? "paired" : "not paired");
}

// ---- actions ---------------------------------------------------------------
async function pingHealth() {
  try {
    const r = await fetchWithTimeout(HEALTH, {}, 1200);
    const { body, raw } = await safeJson(r);
    if (!r.ok) throw new Error(`HTTP ${r.status}${raw ? " • " + raw : ""}`);

    // reflect daemon state (NEW)
    isPaired   = !!(body?.paired);
    currentCid = body?.cid || "";

    setDaemonBadge("running");
    if (body) updateDeviceInfo(body);
    const a = $daemonA(); if (a) a.href = HEALTH;

    renderUI(); // NEW
    return true;
  } catch (e: any) {
    setDaemonBadge("starting...");
    isPaired = false;                    // NEW
    renderUI();                          // NEW
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

    // update local state (NEW)
    isPaired   = true;
    currentCid = body?.cid || currentCid;

    if (body) updateDeviceInfo(body);
    setPairStatus("paired");
    renderUI();               // NEW

    await doRefresh();        // verify + hydrate

    // Auto-apply exactly once after successful pair (kept as requested)
    await applyDNS();
  } catch (e: any) {
    setPairStatus("error");
    showPairMessage(`Network error: ${e?.message || e}`);
  }
}

async function doRefresh() {
  try {
    const r = await fetchWithTimeout(CONFIG, {}, 1500);
    const { body, raw } = await safeJson(r);
    if (!r.ok) throw new Error(`HTTP ${r.status}${raw ? " • " + raw : ""}`);

    // also sync state from /config if it exposes paired/cid (safe no-op otherwise)
    if (body) {
      isPaired   = !!(body?.paired ?? isPaired);
      currentCid = body?.cid || currentCid;
      updateDeviceInfo(body);
    }

    renderUI(); // NEW
    await pingHealth();
  } catch (e: any) {
    setPairStatus("error");
    showPairMessage(`Refresh error: ${e?.message || e}`);
  }
}

async function startDaemon() {
  try {
    await i("daemon_start");
    setDaemonBadge("starting...");
    await waitForDaemon();
    await pingHealth();
  } catch (e: any) {
    showPairMessage(`Start error: ${e?.toString()}`);
  }
}
async function stopDaemon() {
  try {
    await i("daemon_stop");
    setDaemonBadge("starting...");
    isPaired = false;         // NEW: reflect unknown state after stop
    renderUI();               // NEW
  } catch (e: any) {
    showPairMessage(`Stop error: ${e?.toString()}`);
  }
}

// ---- DNS controls via Tauri commands --------------------------------------
async function applyDNS() {
  try {
    const res = await i<string>("apply_dns", { primary: PRIMARY_DNS, secondary: SECONDARY_DNS });
    let out = String(res); try { out = JSON.stringify(JSON.parse(out), null, 2); } catch {}
    showPairMessage(`DNS applied • ${out}`);
  } catch (e: any) {
    showPairMessage(`Apply DNS error: ${e?.toString()}\nTip: run as Administrator.`);
  }
}

async function resetDNS() {
  try {
    const res = await i<string>("reset_dns");
    let out = String(res);
    try { out = JSON.stringify(JSON.parse(out), null, 2); } catch {}
    showPairMessage(`DNS reset • ${out}`);
  } catch (e: any) {
    showPairMessage(`Reset DNS error: ${e?.toString()}\nTip: run as Administrator.`);
  }
}

async function dnsStatus() {
  try {
    const res = await i<string>("dns_status");
    let out = String(res); try { out = JSON.stringify(JSON.parse(out), null, 2); } catch {}
    showPairMessage(`DNS status:\n${out}`);
    return out;
  } catch (e: any) {
    showPairMessage(`DNS status error: ${e?.toString()}`);
    return null;
  }
}

function renderProtectedView(cid?: string) {
  const root = document.querySelector('[data-section="pairing"]')?.parentElement || document.body;

  const box = document.createElement("div");
  box.className = "card";
  box.innerHTML = `
    <h3 style="margin:0 0 12px 0;">This device is protected by SafeNet</h3>
    <div style="font-size:14px;opacity:.85">
      ${cid ? `CID: <code>${cid}</code><br/>` : ""}
      Filtering is enforced at the system level.
    </div>

    <div class="card" style="margin-top:16px">
      <h3 style="margin:0 0 12px 0;">DNS Controls</h3>
      <div style="display:flex; gap:8px; flex-wrap:wrap;">
        <button id="applyDNS" class="btn">Apply SafeNet DNS</button>
        <button id="dnsStatus" class="btn btn-outline">Show DNS Status</button>
      </div>
    </div>
  `;
  root.replaceChildren(box);

  // attach the event listeners again after re-render
  const applyBtn = document.getElementById("applyDNS");
  const statusBtn = document.getElementById("dnsStatus");
  applyBtn?.addEventListener("click", () => void applyDNS());
  statusBtn?.addEventListener("click", () => void dnsStatus());
}


async function reEnforceLoop() {
  setInterval(async () => {
    try {
      await pingHealth();
      const statusText = await dnsStatus();
      if (statusText) {
        if (!statusText.includes("3.129.187.175") && !statusText.includes(PRIMARY_DNS)) {
          if (isPaired) await applyDNS(); // only enforce if paired
        }
      }
    } catch {}
  }, POLL_MS);
}

// ---- dynamic DNS block (renders if missing in HTML) -----------------------
function ensureDNSControls() {
  const pairingBox = document.querySelector('[data-section="pairing"]') || document.body;

  const card = document.createElement("div");
  card.className = "card";
  card.style.marginTop = "16px";
  card.innerHTML = `
    <h3 style="margin:0 0 12px 0;">DNS Controls</h3>
    <div style="display:flex; gap:8px; flex-wrap:wrap;">
      <button id="applyDNS" class="btn" disabled>Apply SafeNet DNS</button>
      <button id="dnsStatus" class="btn btn-outline">Show DNS Status</button>
    </div>
  `;
  pairingBox.parentElement?.insertBefore(card, (pairingBox as any).nextSibling);

  $applyDNSBtnEl = document.getElementById("applyDNS") as HTMLButtonElement;
  $dnsStatusBtnEl = document.getElementById("dnsStatus") as HTMLButtonElement;

  $applyDNSBtnEl?.addEventListener("click", () => void applyDNS());
  $dnsStatusBtnEl?.addEventListener("click", () => void dnsStatus());

  renderUI(); // NEW: set initial disabled/enabled
}

// ---- wire up ---------------------------------------------------------------
function wire() {
  ensureDNSControls();

  if (CHILD_MODE) {
    hide($startBtn());
    hide($stopBtn());

    // In child mode, show pairing when unpaired.
    const pairingSection = document.querySelector('[data-section="pairing"]') as HTMLElement | null;

    setDaemonBadge("starting...");
    const a = $daemonA(); if (a) a.href = HEALTH;

    i("daemon_start").catch(() => { /* ignore */ });

    (async () => {
      const ok = await waitForDaemon();
      if (!ok) {
        setPairStatus("error");
        showPairMessage("Could not reach the SafeNet service. Close and reopen as Administrator.");
        if (pairingSection) show(pairingSection);
        return;
      }

      try {
        await pingHealth();

        // Read config to hydrate CID if present (optional)
        const r = await fetchWithTimeout(CONFIG, {}, 1500);
        const { body } = await safeJson(r);
        if (body?.cid && !currentCid) currentCid = body.cid;
        renderUI();

        if (!isPaired) {
          if (pairingSection) show(pairingSection);
          $pairBtn()?.addEventListener("click", async () => {
            await doPair();              // will set isPaired + renderUI + auto-apply once
            reEnforceLoop();
          });
        } else {
          // already paired, no auto-apply; user (or policy) can apply explicitly
          if (pairingSection) hide(pairingSection);
          reEnforceLoop();
        }
      } catch {
        if (pairingSection) show(pairingSection);
      }
    })();

    // no Reset button exposed in child mode
    const resetBtn = document.getElementById("resetDNS");
    if (resetBtn) resetBtn.remove();
  } else {
    $pairBtn()?.addEventListener("click", () => void doPair());
    $refreshBtn()?.addEventListener("click", () => void doRefresh());
    $startBtn()?.addEventListener("click", () => void i("daemon_start"));
    $stopBtn()?.addEventListener("click", () => void i("daemon_stop"));

    setDaemonBadge("starting...");
    const a = $daemonA(); if (a) a.href = HEALTH;

    (async () => {
      await waitForDaemon();
      await pingHealth();
    })();
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", wire);
} else {
  wire();
}

/* --------------------------------------------------------------------------
   APPENDED HELPERS (kept) – now call the safe wrapper `i(...)`
-------------------------------------------------------------------------- */
async function _invoke<T>(cmd: string, args?: any): Promise<T> {
  return await i<T>(cmd, args);
}

async function filteringOn(cid: string, interfaces = ["Wi-Fi"]) {
  return await _invoke<string>("sn_enforce_dns", { enable: true, cid, interfaces });
}

async function filteringOff(interfaces = ["Wi-Fi"]) {
  return await _invoke<string>("sn_enforce_dns", { enable: false, interfaces });
}

async function showDnsStatus() {
  const json = await _invoke<any>("sn_dns_status");
  console.log("DNS status:", json);
  const elx = document.getElementById("dns-status");
  if (elx) elx.textContent = JSON.stringify(json, null, 2);
}
