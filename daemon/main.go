// C:\safenet-desktop\daemon\main.go
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const (
	addr          = "127.0.0.1:8765"
	appVersion    = "0.1.0"
	apiBase       = "https://api.safenettechnology.com"
	pairEndpoint  = "/devices/pair"
	configDirName = "SafeNet"
	configName    = "config.json"
)

type Config struct {
	Token        string   `json:"token"`
	DeviceID     string   `json:"deviceId"`
	CID          string   `json:"cid"`
	DeviceName   string   `json:"deviceName"`
	UniqueID     string   `json:"uniqueId"`
	UpdatedAt    string   `json:"updatedAt"`
	EnforceDNS   bool     `json:"enforceDns,omitempty"`
	DNSPrimary   string   `json:"dnsPrimary,omitempty"`
	DNSSecondary string   `json:"dnsSecondary,omitempty"`
	Interfaces   []string `json:"interfaces,omitempty"`
}

var lastPairRaw []byte
var lastPairReq []byte

/* ---------- storage ---------- */

func programDataDir() (string, error) {
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			return "", errors.New("%ProgramData% not set")
		}
		return filepath.Join(base, configDirName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "."+strings.ToLower(configDirName)), nil
}

func configPath() (string, error) {
	dir, err := programDataDir()
	if err != nil {
		return "", err
	}
	_ = os.MkdirAll(dir, 0o755)
	return filepath.Join(dir, configName), nil
}

func readConfig() (*Config, error) {
	p, err := configPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func writeConfig(c *Config) error {
	p, err := configPath()
	if err != nil {
		return err
	}
	c.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(p, b, 0o644)
}

/* ---------- uniqueId ---------- */

func uuidV4NoDeps() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	hexStr := hex.EncodeToString(b[:])
	return hexStr[0:8] + "-" + hexStr[8:12] + "-" + hexStr[12:16] + "-" + hexStr[16:20] + "-" + hexStr[20:32], nil
}

func ensureUniqueID() (string, error) {
	c, _ := readConfig()
	if c == nil {
		c = &Config{}
	}
	if strings.TrimSpace(c.UniqueID) == "" {
		u, err := uuidV4NoDeps()
		if err != nil {
			return "", err
		}
		c.UniqueID = u
		if err := writeConfig(c); err != nil {
			return "", err
		}
	}
	return c.UniqueID, nil
}

/* ---------- http helpers ---------- */

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

/* ---------- generic pickers ---------- */

func normalizeString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func pickCID(m map[string]any) string {
	if m == nil {
		return ""
	}
	keys := []string{
		"cid", "CID", "clientId", "client_id", "clientID",
		"uniqueTag", "tag", "cidTag",
	}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return normalizeString(v)
		}
	}
	for _, subKey := range []string{"data", "user", "device", "result", "payload"} {
		if v, ok := m[subKey]; ok {
			if subMap, ok := v.(map[string]any); ok {
				if c := pickCID(subMap); c != "" {
					return c
				}
			}
		}
	}
	for _, v := range m {
		switch vv := v.(type) {
		case map[string]any:
			if c := pickCID(vv); c != "" {
				return c
			}
		case []any:
			for _, item := range vv {
				if sub, ok := item.(map[string]any); ok {
					if c := pickCID(sub); c != "" {
						return c
					}
				}
			}
		}
	}
	return ""
}

func pickDeviceID(m map[string]any) string {
	keys := []string{"deviceId", "device_id", "id", "deviceID"}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return normalizeString(v)
		}
	}
	if v, ok := m["device"]; ok {
		if sub, ok := v.(map[string]any); ok {
			return pickDeviceID(sub)
		}
	}
	if v, ok := m["data"]; ok {
		if sub, ok := v.(map[string]any); ok {
			return pickDeviceID(sub)
		}
	}
	return ""
}

func pickToken(m map[string]any) string {
	keys := []string{"token", "accessToken", "jwt", "access_token"}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return normalizeString(v)
		}
	}
	if v, ok := m["data"]; ok {
		if sub, ok := v.(map[string]any); ok {
			return pickToken(sub)
		}
	}
	return ""
}

/* ---------- API calls ---------- */

func apiGET(ctx context.Context, token, pathWithQuery string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+pathWithQuery, nil)
	if err != nil {
		return nil, 0, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode, nil
}

func tryResolveCID(ctx context.Context, token, deviceID, uniqueID string) (cid string, updatedDeviceID string) {
	if deviceID != "" {
		if b, code, err := apiGET(ctx, token, "/devices/"+url.PathEscape(deviceID)); err == nil && code == 200 {
			var m map[string]any
			if json.Unmarshal(b, &m) == nil {
				if c := pickCID(m); c != "" {
					return c, pickDeviceID(m)
				}
			}
		}
	}
	if b, code, err := apiGET(ctx, token, "/devices/me"); err == nil && code == 200 {
		var m map[string]any
		if json.Unmarshal(b, &m) == nil {
			if c := pickCID(m); c != "" {
				return c, pickDeviceID(m)
			}
		}
	}
	if uniqueID != "" {
		q := "/devices/by-unique?uniqueId=" + url.QueryEscape(uniqueID)
		if b, code, err := apiGET(ctx, token, q); err == nil && code == 200 {
			var m map[string]any
			if json.Unmarshal(b, &m) == nil {
				if c := pickCID(m); c != "" {
					return c, pickDeviceID(m)
				}
			}
		}
	}
	if b, code, err := apiGET(ctx, token, "/policy"); err == nil && code == 200 {
		var m map[string]any
		if json.Unmarshal(b, &m) == nil {
			if c := pickCID(m); c != "" {
				return c, pickDeviceID(m)
			}
		}
	}
	return "", deviceID
}

/* ---------- DNS (Windows) ---------- */

type dnsApplyReq struct {
	Primary    string   `json:"primary"`
	Secondary  string   `json:"secondary"`
	Interfaces []string `json:"interfaces,omitempty"`
	CID        string   `json:"cid,omitempty"`
}

func firstIPv4(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
		return "", fmt.Errorf("only IPv4 supported: %s", host)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", errors.New("no IPv4 resolved for host: " + host)
}

func psExec(args ...string) ([]byte, []byte, error) {
	cmd := exec.Command("powershell.exe", append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// --- netsh helpers (preferred on Windows) ---

func runNetsh(args ...string) error {
	cmd := exec.Command("netsh", args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("netsh %v -> %v (%s)", args, err, buf.String())
	}
	return nil
}

// applyDNSNetsh sets per-interface DNS and optional DoH mapping to the CID template.
func applyDNSNetsh(interfaces []string, primaryHost, secondaryHost, cid string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("netsh path is windows-only")
	}
	pIP, err := firstIPv4(primaryHost)
	if err != nil {
		return fmt.Errorf("resolve primary: %w", err)
	}
	if strings.TrimSpace(cid) != "" {
		_ = runNetsh("dns", "delete", "encryption", fmt.Sprintf("server=%s", pIP))
		tmpl := fmt.Sprintf("https://dns.safenettechnology.com/dns-query/%s", cid)
		log.Printf("[DEBUG] Applying DoH mapping → %s", tmpl)
		if err := runNetsh("dns", "add", "encryption",
			fmt.Sprintf("server=%s", pIP),
			fmt.Sprintf("dohtemplate=%s", tmpl),
			"autoupgrade=yes", // ensure permanent Auto-DoH
			"udpfallback=no",
		); err != nil {
			return fmt.Errorf("add DoH mapping: %w", err)
		}
	}
	secIP := ""
	if strings.TrimSpace(secondaryHost) != "" {
		if v, e := firstIPv4(secondaryHost); e == nil && v != "" {
			secIP = v
		}
	}
	for _, alias := range interfaces {
		alias = strings.TrimSpace(alias)
		if alias == "" {
			continue
		}
		nameArg := fmt.Sprintf(`name="%s"`, alias)
		if err := runNetsh("interface", "ipv4", "set", "dnsservers",
			nameArg, "static", pIP, "primary", "validate=no",
		); err != nil {
			return fmt.Errorf("set dns for %q: %w", alias, err)
		}
		if secIP != "" {
			_ = runNetsh("interface", "ipv4", "add", "dnsservers",
				nameArg, fmt.Sprintf("address=%s", secIP), "index=2", "validate=no",
			)
		}
	}
	return nil
}

// windowsApplyDNS (existing PowerShell path) retained as fallback.
func windowsApplyDNS(primary, secondary string, interfaces []string) error {
	pIP, err := firstIPv4(primary)
	if err != nil {
		return err
	}
	sIP := ""
	if strings.TrimSpace(secondary) != "" {
		if v, e := firstIPv4(secondary); e == nil {
			sIP = v
		}
	}
	if len(interfaces) > 0 {
		script := `
param($Primary, $Secondary, $Ifs)
$servers = @($Primary)
if ($Secondary -and $Secondary.Trim() -ne "") { $servers += $Secondary }
foreach ($alias in $Ifs.Split(',')) {
  try {
    $a = Get-DnsClient | Where-Object { $_.InterfaceAlias -eq $alias -and $_.AddressFamily -eq 2 }
    if ($a) {
      Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -ServerAddresses $servers -ErrorAction Stop
    }
  } catch {}
}
`
		_, _, err = psExec(script, "-args", pIP, sIP, strings.Join(interfaces, ","))
		return err
	}
	script := `
param($Primary, $Secondary)
$servers = @($Primary)
if ($Secondary -and $Secondary.Trim() -ne "") { $servers += $Secondary }
$ifs = Get-DnsClient | Where-Object { $_.InterfaceOperationalStatus -eq "Up" -and $_.AddressFamily -eq 2 }
foreach ($i in $ifs) {
  try {
    Set-DnsClientServerAddress -InterfaceIndex $i.InterfaceIndex -ServerAddresses $servers -ErrorAction Stop
  } catch {}
}
`
	_, _, err = psExec(script, "-args", pIP, sIP)
	return err
}

func windowsResetDNS(interfaces []string) error {
	if len(interfaces) > 0 {
		script := `
param($Ifs)
foreach ($alias in $Ifs.Split(',')) {
  try {
    $a = Get-DnsClient | Where-Object { $_.InterfaceAlias -eq $alias -and $_.AddressFamily -eq 2 }
    if ($a) {
      Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -ResetServerAddresses -ErrorAction Stop
    }
  } catch {}
}
`
		_, _, err := psExec(script, "-args", strings.Join(interfaces, ","))
		return err
	}
	script := `
$ifs = Get-DnsClient | Where-Object { $_.InterfaceOperationalStatus -eq "Up" -and $_.AddressFamily -eq 2 }
foreach ($i in $ifs) {
  try {
    Set-DnsClientServerAddress -InterfaceIndex $i.InterfaceIndex -ResetServerAddresses -ErrorAction Stop
  } catch {}
}
`
	_, _, err := psExec(script)
	return err
}

func windowsDNSStatusJSON() (string, error) {
	script := `Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,InterfaceIndex,ServerAddresses | ConvertTo-Json -Compress`
	out, _, err := psExec(script)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func netshEncryptionShow() (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("unsupported on non-windows")
	}
	cmd := exec.Command("netsh", "dns", "show", "encryption")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("netsh dns show encryption: %v (%s)", err, buf.String())
	}
	return buf.String(), nil
}

// blockIPv6DNS creates firewall rules to block all outbound IPv6 DNS (UDP/TCP 53)
func blockIPv6DNS() {
	if runtime.GOOS != "windows" {
		return
	}
	log.Printf("[DEBUG] Applying IPv6 DNS firewall block rules...")
	_ = runNetsh("advfirewall", "firewall", "add", "rule",
		"name=SafeNet Block DNS (UDP 53 v6)", "dir=out", "action=block",
		"protocol=UDP", "remoteport=53", "profile=any", "enable=yes")
	_ = runNetsh("advfirewall", "firewall", "add", "rule",
		"name=SafeNet Block DNS (TCP 53 v6)", "dir=out", "action=block",
		"protocol=TCP", "remoteport=53", "profile=any", "enable=yes")
}

// unblockIPv6DNS removes the IPv6 DNS firewall rules created by blockIPv6DNS
func unblockIPv6DNS() {
	if runtime.GOOS != "windows" {
		return
	}
	log.Printf("[DEBUG] Removing IPv6 DNS firewall block rules...")
	_ = runNetsh("advfirewall", "firewall", "delete", "rule",
		"name=SafeNet Block DNS (UDP 53 v6)")
	_ = runNetsh("advfirewall", "firewall", "delete", "rule",
		"name=SafeNet Block DNS (TCP 53 v6)")
}
// --- Auto-DoH registry and PowerShell DoH mapping helpers ---

// Sets HKLM\SYSTEM\...\Dnscache\Parameters\EnableAutoDoh = 2
func windowsEnableAutoDoh() {
	if runtime.GOOS != "windows" {
		return
	}
	_, _, _ = psExec(`reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v EnableAutoDoh /t REG_DWORD /d 2 /f`)
}

// Restarts the DNS Client service so mappings take effect on stubborn builds.
func windowsRestartDnsClient() {
	if runtime.GOOS != "windows" {
		return
	}
	_, _, _ = psExec(`Try { Restart-Service -Name Dnscache -Force -ErrorAction Stop } Catch {}`)
}

// Uses PowerShell API (Win11/late Win10) to add DoH mapping with AutoUpgrade=true and no UDP fallback.
func addDohMappingPowerShell(ip, cid string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("powershell DoH mapping is windows-only")
	}
	if strings.TrimSpace(ip) == "" || strings.TrimSpace(cid) == "" {
		return fmt.Errorf("missing ip or cid")
	}
	tmpl := fmt.Sprintf("https://dns.safenettechnology.com/dns-query/%s", cid)

	script := `
param($Ip, $Tpl)
$cmd = Get-Command Add-DnsClientDohServerAddress -ErrorAction SilentlyContinue
if (-not $cmd) { throw "Add-DnsClientDohServerAddress not available" }
Try { Remove-DnsClientDohServerAddress -ServerAddress $Ip -ErrorAction SilentlyContinue } Catch {}
Add-DnsClientDohServerAddress -ServerAddress $Ip -DohTemplate $Tpl -AutoUpgrade $true -AllowFallbackToUdp $false -ErrorAction Stop
`
	_, stderr, err := psExec(script, "-args", ip, tmpl)
	if err != nil {
		return fmt.Errorf("Add-DnsClientDohServerAddress failed: %v (%s)", err, string(stderr))
	}
	return nil
}

// --- IPv6 + plaintext hardening helpers ---

// Remove all configured IPv6 DNS server addresses on specified interfaces (or all "Up" if none).

// Add outbound firewall rules to block plaintext DNS on v4 and v6 (idempotent).
func windowsBlockPlainDNSAll() {
	if runtime.GOOS != "windows" {
		return
	}
	// v4
	_, _, _ = psExec(`netsh advfirewall firewall add rule name="SafeNet Block DNS (UDP 53)" dir=out action=block protocol=UDP remoteport=53`)
	_, _, _ = psExec(`netsh advfirewall firewall add rule name="SafeNet Block DNS (TCP 53)" dir=out action=block protocol=TCP remoteport=53`)
	// v6
	_, _, _ = psExec(`netsh advfirewall firewall add rule name="SafeNet Block DNS (UDP 53, v6)" dir=out action=block protocol=UDP remoteport=53`)
	_, _, _ = psExec(`netsh advfirewall firewall add rule name="SafeNet Block DNS (TCP 53, v6)" dir=out action=block protocol=TCP remoteport=53`)
}

/* ---------- routes ---------- */

func health(w http.ResponseWriter, r *http.Request) {
	uq, _ := ensureUniqueID()
	c, _ := readConfig()
	resp := map[string]any{
		"ok":       true,
		"service":  "safenet-daemon",
		"version":  appVersion,
		"paired":   c != nil && c.Token != "",
		"cid":      "",
		"deviceId": "",
		"uniqueId": uq,
	}
	if c != nil {
		resp["cid"] = c.CID
		resp["deviceId"] = c.DeviceID
	}
	jsonOK(w, resp)
}

type pairReq struct {
	Code       string `json:"code"`
	DeviceName string `json:"deviceName"`
	Platform   string `json:"platform"`
	UniqueID   string `json:"uniqueId"`
}

func pairHandler(w http.ResponseWriter, r *http.Request) {
	var in pairReq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Code) == "" {
		jsonErr(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if in.DeviceName == "" {
		hostname, _ := os.Hostname()
		in.DeviceName = hostname
	}
	if in.Platform == "" {
		in.Platform = "windows"
	}
	uq, err := ensureUniqueID()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "uniqueId generation failed")
		return
	}
	in.UniqueID = uq

	body, _ := json.Marshal(in)
	lastPairReq = body

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+pairEndpoint, bytes.NewReader(body))
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "request build failed")
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		jsonErr(w, http.StatusBadGateway, "pairing network error")
		return
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	lastPairRaw = raw

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		jsonErr(w, resp.StatusCode, "pairing failed: "+string(raw))
		return
	}

	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		jsonErr(w, http.StatusBadGateway, "invalid response from server")
		return
	}

	token := pickToken(generic)
	cid := pickCID(generic)
	deviceID := pickDeviceID(generic)

	conf, _ := readConfig()
	if conf == nil {
		conf = &Config{}
	}
	if token != "" {
		conf.Token = token
	}
	if cid != "" {
		conf.CID = cid
	}
	if deviceID != "" {
		conf.DeviceID = deviceID
	}
	conf.DeviceName = in.DeviceName
	if strings.TrimSpace(conf.UniqueID) == "" {
		conf.UniqueID = uq
	}
	_ = writeConfig(conf)

	if conf.Token != "" && conf.CID == "" {
		rctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel2()
		if rcid, rid := tryResolveCID(rctx, conf.Token, conf.DeviceID, conf.UniqueID); rcid != "" {
			conf.CID = rcid
			if rid != "" {
				conf.DeviceID = rid
			}
			_ = writeConfig(conf)
		}
	}

	jsonOK(w, map[string]any{
		"paired":     conf.Token != "" && (conf.CID != "" || conf.DeviceID != ""),
		"deviceId":   conf.DeviceID,
		"cid":        conf.CID,
		"deviceName": conf.DeviceName,
		"uniqueId":   conf.UniqueID,
		"raw":        json.RawMessage(raw),
	})
}

func getConfig(w http.ResponseWriter, r *http.Request) {
	uq, _ := ensureUniqueID()
	c, _ := readConfig()
	if c == nil {
		jsonOK(w, map[string]any{"paired": false, "uniqueId": uq})
		return
	}
	m := map[string]any{
		"token":        c.Token,
		"deviceId":     c.DeviceID,
		"cid":          c.CID,
		"deviceName":   c.DeviceName,
		"uniqueId":     uq,
		"updatedAt":    c.UpdatedAt,
		"enforceDns":   c.EnforceDNS,
		"dnsPrimary":   c.DNSPrimary,
		"dnsSecondary": c.DNSSecondary,
		"interfaces":   c.Interfaces,
	}
	jsonOK(w, m)
}

func debugLastPair(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if len(lastPairRaw) == 0 {
		w.Write([]byte(`{"raw":null}`))
		return
	}
	w.Write(lastPairRaw)
}

func debugLastPairReq(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if len(lastPairReq) == 0 {
		w.Write([]byte(`{"raw":null}`))
		return
	}
	w.Write(lastPairReq)
}

func refreshHandler(w http.ResponseWriter, r *http.Request) {
	c, _ := readConfig()
	if c == nil || c.Token == "" {
		jsonErr(w, 400, "not paired")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if rcid, rid := tryResolveCID(ctx, c.Token, c.DeviceID, c.UniqueID); rcid != "" {
		c.CID = rcid
		if rid != "" {
			c.DeviceID = rid
		}
		_ = writeConfig(c)
	}
	jsonOK(w, map[string]any{
		"cid":      c.CID,
		"deviceId": c.DeviceID,
	})
}

/* ---------- DNS routes (updated + new) ---------- */

func normalizeDNSPair(primary, secondary string) (string, string, error) {
	p, err := firstIPv4(primary)
	if err != nil {
		return "", "", err
	}
	s := ""
	if strings.TrimSpace(secondary) != "" {
		if v, e := firstIPv4(secondary); e == nil {
			s = v
		}
	}
	return p, s, nil
}

func applyDNSHandler(w http.ResponseWriter, r *http.Request) {
	if runtime.GOOS != "windows" {
		jsonErr(w, http.StatusNotImplemented, "DNS apply supported on Windows only")
		return
	}
	var req dnsApplyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Primary) == "" {
		jsonErr(w, http.StatusBadRequest, "invalid json (need primary)")
		return
	}
	pIP, sIP, err := normalizeDNSPair(req.Primary, req.Secondary)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "resolve failed: "+err.Error())
		return
	}

	// Pull CID from request or stored config
	cid := strings.TrimSpace(req.CID)
	conf, _ := readConfig()
	if cid == "" && conf != nil {
		cid = conf.CID
	}

	// Prefer netsh path; fall back to PowerShell path
	method := "netsh"
	if err := applyDNSNetsh(req.Interfaces, pIP, sIP, cid); err != nil {
		method = "powershell-fallback"
		if err2 := windowsApplyDNS(pIP, sIP, req.Interfaces); err2 != nil {
			jsonErr(w, http.StatusInternalServerError, "apply failed: "+err.Error()+"; fallback: "+err2.Error())
			return
		}
	}

	if conf == nil {
		conf = &Config{}
	}
	conf.EnforceDNS = true
	conf.DNSPrimary = pIP
	conf.DNSSecondary = sIP
	conf.Interfaces = req.Interfaces
	_ = writeConfig(conf)

	// Sticky + OS auto-upgrade to DoH
	windowsEnableAutoDoh()
	_ = addDohMappingPowerShell(pIP, cid) // ignore if API missing
	windowsRestartDnsClient()

	// Harden: clear IPv6 DNS and block plaintext DNS (v4+v6)
	windowsResetIPv6Servers(req.Interfaces)
	windowsBlockPlainDNSAll()

	jsonOK(w, map[string]any{
		"ok":         true,
		"enforced":   true,
		"primary":    pIP,
		"secondary":  sIP,
		"interfaces": req.Interfaces,
		"method":     method,
	})
}

func resetDNSHandler(w http.ResponseWriter, r *http.Request) {
	if runtime.GOOS != "windows" {
		jsonErr(w, http.StatusNotImplemented, "DNS reset supported on Windows only")
		return
	}
	var req struct {
		Interfaces []string `json:"interfaces,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	unblockIPv6DNS()
	if err := windowsResetDNS(req.Interfaces); err != nil {
		jsonErr(w, http.StatusInternalServerError, "reset failed: "+err.Error())
		return
	}
	conf, _ := readConfig()
	if conf == nil {
		conf = &Config{}
	}
	conf.EnforceDNS = false
	conf.DNSPrimary = ""
	conf.DNSSecondary = ""
	conf.Interfaces = nil
	_ = writeConfig(conf)

	jsonOK(w, map[string]any{"ok": true, "enforced": false})
}

func dnsEnforceHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enable     bool     `json:"enable"`
		Primary    string   `json:"primary,omitempty"`
		Secondary  string   `json:"secondary,omitempty"`
		Interfaces []string `json:"interfaces,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "invalid json")
		return
	}
	conf, _ := readConfig()
	if conf == nil {
		conf = &Config{}
	}
	if !req.Enable {
		conf.EnforceDNS = false
		_ = writeConfig(conf)
		jsonOK(w, map[string]any{"ok": true, "enforced": false})
		return
	}
	if strings.TrimSpace(req.Primary) == "" {
		jsonErr(w, 400, "primary required when enabling")
		return
	}
	p, s, err := normalizeDNSPair(req.Primary, req.Secondary)
	if err != nil {
		jsonErr(w, 400, "resolve failed: "+err.Error())
		return
	}
	conf.EnforceDNS = true
	conf.DNSPrimary = p
	conf.DNSSecondary = s
	conf.Interfaces = req.Interfaces
	_ = writeConfig(conf)
	_ = windowsApplyDNS(p, s, req.Interfaces) // watchdog may re-apply
	jsonOK(w, map[string]any{"ok": true, "enforced": true, "primary": p, "secondary": s})
}

func dnsPolicyHandler(w http.ResponseWriter, r *http.Request) {
	conf, _ := readConfig()
	if conf == nil {
		conf = &Config{}
	}
	jsonOK(w, map[string]any{
		"enforceDns":   conf.EnforceDNS,
		"dnsPrimary":   conf.DNSPrimary,
		"dnsSecondary": conf.DNSSecondary,
		"interfaces":   conf.Interfaces,
	})
}

// NEW: /dns_status – returns current adapter DNS and netsh DoH mappings
func dnsStatusHandler(w http.ResponseWriter, r *http.Request) {
	if runtime.GOOS != "windows" {
		jsonErr(w, http.StatusNotImplemented, "status supported on Windows only")
		return
	}
	serversJSON, err := windowsDNSStatusJSON()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "status failed: "+err.Error())
		return
	}
	enc, _ := netshEncryptionShow()
	var servers any
	_ = json.Unmarshal([]byte(serversJSON), &servers)
	jsonOK(w, map[string]any{
		"servers":    servers,
		"encryption": enc,
	})
}

// NEW: /resolve_ipv4?host=example.com – helper for UI
var ipv4Re = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)

func resolveIPv4Host(host string) (string, error) {
	if ipv4Re.MatchString(host) {
		return host, nil
	}
	return firstIPv4(host)
}

func resolveIPv4Handler(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if host == "" {
		jsonErr(w, 400, "host required")
		return
	}
	ip, err := resolveIPv4Host(host)
	if err != nil {
		jsonErr(w, 400, "resolve failed: "+err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true, "host": host, "ipv4": ip})
}

// NEW: /force_doh – reapply DoH mapping using stored CID + primary
func forceDohHandler(w http.ResponseWriter, r *http.Request) {
	if runtime.GOOS != "windows" {
		jsonErr(w, http.StatusNotImplemented, "windows only")
		return
	}
	conf, _ := readConfig()
	if conf == nil || strings.TrimSpace(conf.CID) == "" || strings.TrimSpace(conf.DNSPrimary) == "" {
		jsonErr(w, 400, "missing CID or DNS primary; call /apply_dns first")
		return
	}
	if err := applyDNSNetsh(conf.Interfaces, conf.DNSPrimary, conf.DNSSecondary, conf.CID); err != nil {
		_ = windowsApplyDNS(conf.DNSPrimary, conf.DNSSecondary, conf.Interfaces)
	}
	windowsEnableAutoDoh()
	_ = addDohMappingPowerShell(conf.DNSPrimary, conf.CID)
	windowsRestartDnsClient()

	enc, _ := netshEncryptionShow()
	jsonOK(w, map[string]any{"ok": true, "encryption": enc, "cid": conf.CID})
}

// OPTIONAL: /harden_dns – re-run IPv6 cleanup + plaintext blocks + Auto-DoH
func hardenDnsHandler(w http.ResponseWriter, r *http.Request) {
	if runtime.GOOS != "windows" {
		jsonErr(w, http.StatusNotImplemented, "windows only")
		return
	}
	conf, _ := readConfig()
	var ifs []string
	if conf != nil {
		ifs = conf.Interfaces
	}
	windowsResetIPv6Servers(ifs)
	windowsBlockPlainDNSAll()
	windowsEnableAutoDoh()
	windowsRestartDnsClient()
	jsonOK(w, map[string]any{"ok": true})
}

/* ---------- watchdog ---------- */

func adaptersConformTo(servers any, want1, want2 string) bool {
	arr, ok := servers.([]any)
	if !ok {
		return false
	}
	set := map[string]struct{}{}
	for _, v := range arr {
		switch t := v.(type) {
		case string:
			if ip := net.ParseIP(t); ip != nil && ip.To4() != nil {
				set[ip.String()] = struct{}{}
			}
		case []any:
			for _, inner := range t {
				if s, ok := inner.(string); ok {
					if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
						set[ip.String()] = struct{}{}
					}
				}
			}
		}
	}
	_, ok1 := set[want1]
	if want2 == "" {
		return ok1 && len(set) == 1
	}
	_, ok2 := set[want2]
	return ok1 && ok2 && len(set) == 2
}

func startDNSWatchdog(ctx context.Context) {
	if runtime.GOOS != "windows" {
		return
	}
	ticker := time.NewTicker(3 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				conf, err := readConfig()
				if err != nil || conf == nil || !conf.EnforceDNS || strings.TrimSpace(conf.DNSPrimary) == "" {
					continue
				}
				jsonStr, err := windowsDNSStatusJSON()
				if err != nil || jsonStr == "" {
					continue
				}
				var data any
				if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
					continue
				}
				needApply := false
				switch t := data.(type) {
				case []any:
					for _, row := range t {
						m, ok := row.(map[string]any)
						if !ok {
							continue
						}
						servers := m["ServerAddresses"]
						if !adaptersConformTo(servers, conf.DNSPrimary, conf.DNSSecondary) {
							needApply = true
							break
						}
					}
				case map[string]any:
					servers := t["ServerAddresses"]
					if !adaptersConformTo(servers, conf.DNSPrimary, conf.DNSSecondary) {
						needApply = true
					}
				}
				if needApply {
					if err := applyDNSNetsh(conf.Interfaces, conf.DNSPrimary, conf.DNSSecondary, conf.CID); err != nil {
						_ = windowsApplyDNS(conf.DNSPrimary, conf.DNSSecondary, conf.Interfaces)
					}
				}
			}
		}
	}()
}

// IPv6 DNS watchdog — periodically clears any re-added IPv6 DNS servers
func startIPv6Watchdog(ctx context.Context) {
	if runtime.GOOS != "windows" {
		return
	}

	// Run once immediately at startup
	go func() {
		conf, _ := readConfig()
		if conf != nil && conf.EnforceDNS {
			log.Printf("[DEBUG] IPv6 watchdog initial cleanup starting...")
			windowsResetIPv6Servers(conf.Interfaces)
			log.Printf("[DEBUG] IPv6 watchdog initial cleanup complete")
		}
	}()

	// Then keep checking every 10 seconds
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				conf, err := readConfig()
				if err != nil {
					continue
				}
				if conf != nil && conf.EnforceDNS {
					windowsResetIPv6Servers(conf.Interfaces)
					log.Printf("[DEBUG] IPv6 watchdog cleared DNS servers on active interfaces")
				}
			}
		}
	}()
}


func windowsResetIPv6Servers(interfaces []string) {
	if runtime.GOOS != "windows" {
		return
	}

	// 1) Try PowerShell first
	if len(interfaces) > 0 {
		script := `
param($Ifs)
foreach ($alias in $Ifs.Split(',')) {
  try {
    $a = Get-DnsClient | Where-Object { $_.InterfaceAlias -eq $alias -and $_.AddressFamily -eq 23 }
    if ($a) {
      Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -ResetServerAddresses -ErrorAction Stop
    }
  } catch {}
}
`
		_, _, _ = psExec(script, "-args", strings.Join(interfaces, ","))
	} else {
		script := `
$ifs = Get-DnsClient | Where-Object { $_.InterfaceOperationalStatus -eq "Up" -and $_.AddressFamily -eq 23 }
foreach ($i in $ifs) {
  try {
    Set-DnsClientServerAddress -InterfaceIndex $i.InterfaceIndex -ResetServerAddresses -ErrorAction Stop
  } catch {}
}
`
		_, _, _ = psExec(script)
	}

	// 2) Fallback: use netsh to forcibly clear IPv6 DNS on all adapters
	out, _, _ := psExec(`(Get-NetAdapter | ? Status -eq 'Up').InterfaceAlias | ConvertTo-Json -Compress`)
	var aliases []string
	_ = json.Unmarshal([]byte(strings.TrimSpace(string(out))), &aliases)
	for _, alias := range aliases {
		if alias == "" {
			continue
		}
		_ = runNetsh("interface", "ipv6", "set", "dnsservers", fmt.Sprintf(`name="%s"`, alias), "none")
	}
}



/* ---------- main ---------- */

func main() {
	l, err := net.Listen("tcp4", addr)
	if err != nil {
		log.Fatalf("safenet-daemon: port %s already in use: %v", addr, err)
	}
	defer l.Close()
	

	_, _ = ensureUniqueID()
	blockIPv6DNS()

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/last_pair_req", debugLastPairReq)
	mux.HandleFunc("/health", health)
	mux.HandleFunc("/config", getConfig)
	mux.HandleFunc("/pair", pairHandler)
	mux.HandleFunc("/debug/last_pair", debugLastPair)
	mux.HandleFunc("/refresh", refreshHandler)
	mux.HandleFunc("/apply_dns", applyDNSHandler)
	mux.HandleFunc("/reset_dns", resetDNSHandler)
	mux.HandleFunc("/dns_status", dnsStatusHandler)
	mux.HandleFunc("/dns_enforce", dnsEnforceHandler)
	mux.HandleFunc("/dns_policy", dnsPolicyHandler)
	mux.HandleFunc("/resolve_ipv4", resolveIPv4Handler) // helper
	mux.HandleFunc("/force_doh", forceDohHandler)       // repair endpoint
	mux.HandleFunc("/harden_dns", hardenDnsHandler)      // optional harden endpoint

	srv := &http.Server{
		Handler:      withCORS(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 20 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	idleConnsClosed := make(chan struct{})

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		cancel()
		_ = srv.Shutdown(context.Background())
		close(idleConnsClosed)
	}()
	startDNSWatchdog(ctx)
	startIPv6Watchdog(ctx)

	log.Printf("safenet-daemon: listening on http://%s", addr)
	go func() {
		if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
			log.Fatalf("safenet-daemon Serve: %v", err)
		}
	}()

	<-idleConnsClosed
	log.Printf("safenet-daemon: stopped")
}
