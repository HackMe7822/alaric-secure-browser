/**
 * networkMonitor.js — Network lockdown during exam
 *
 * Strategy:
 *   Windows: Set DefaultOutboundAction=Block on all profiles, then add explicit
 *            Allow rules for exam server IPs, DNS, DHCP, loopback.
 *            Block rules added AFTER setting default: explicit Allow rules always
 *            win over the default policy, so exam server traffic gets through.
 *
 *   macOS:   Write pfctl anchor rules: pass exam server, DNS, loopback;
 *            block everything else (both directions).
 *
 * On restore: removes all AlaricExam* rules, restores original DefaultOutboundAction.
 */
'use strict';
const { exec }      = require('child_process');
const { promisify } = require('util');
const dns           = require('dns').promises;
const fs            = require('fs');
const path          = require('path');
const execAsync     = promisify(exec);

const RULE_PREFIX  = 'AlaricExam';
const PF_ANCHOR    = '/tmp/alaric_pf.conf';
const ORIG_FW_FILE = path.join(require('os').tmpdir(), 'alaric_fw_orig.json');

let _serverIPs    = new Set();
let _interval     = null;
let _callback     = null;
let _rulesApplied = false;

// ─── DNS resolve ──────────────────────────────────────────────────────────────
async function resolveHost(host) {
  const addAll = (arr) => arr.forEach(ip => _serverIPs.add(ip));
  try { addAll(await dns.resolve4(host)); } catch {}
  try { addAll(await dns.resolve6(host)); } catch {}
  // Also allow the raw host string if resolution fails
  if (_serverIPs.size === 0 && host) _serverIPs.add(host);
  console.log('[network] Exam server IPs:', [..._serverIPs]);
}

// ─── Windows Firewall ─────────────────────────────────────────────────────────
async function applyWindowsRules() {
  if (!_serverIPs.size) return;

  const ps = (cmd) =>
    execAsync(`powershell -NoProfile -NonInteractive -Command "${cmd}"`, { timeout: 12000 });

  try {
    // 1. Save current DefaultOutboundAction for each profile so we can restore it
    const orig = await ps(
      'Get-NetFirewallProfile | Select-Object Name,DefaultOutboundAction | ConvertTo-Json -Compress'
    );
    fs.writeFileSync(ORIG_FW_FILE, orig.stdout.trim());

    // 2. Clean up any leftover Alaric rules from a previous session
    await ps(`Get-NetFirewallRule -DisplayName "${RULE_PREFIX}*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule`).catch(() => {});

    // 3. Set DefaultOutboundAction = Block on ALL profiles
    //    Explicit Allow rules (added next) always override the default → no conflict
    await ps('Set-NetFirewallProfile -All -DefaultOutboundAction Block');

    // 4. Allow exam server (TCP + UDP for WebRTC media)
    const ips = [..._serverIPs].join('","');
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}Server" -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress "${ips}" -ErrorAction Stop`);
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}ServerUDP" -Direction Outbound -Action Allow -Protocol UDP -RemoteAddress "${ips}"`);

    // 5. Allow DNS (UDP + TCP port 53)
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}DNS" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53`);
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}DNSTCP" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 53`);

    // 6. Allow loopback (Electron IPC uses localhost)
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}Loopback" -Direction Outbound -Action Allow -Protocol Any -RemoteAddress "127.0.0.1","::1","0.0.0.0"`);

    // 7. Allow DHCP (UDP 67/68) and NTP (UDP 123) — needed for network stack
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}DHCP" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 67,68,123`);

    // 8. Block all inbound (belt-and-suspenders: prevents remote connections TO this machine)
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}BlockIn" -Direction Inbound -Action Block -Protocol Any`).catch(() => {});
    // Allow inbound from exam server (WebRTC answers, admin commands)
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}AllowIn" -Direction Inbound -Action Allow -Protocol Any -RemoteAddress "${ips}"`).catch(() => {});

    _rulesApplied = true;
    console.log('[network] Windows firewall lockdown applied — only exam server allowed');
  } catch (e) {
    console.error('[network] Windows firewall error:', e.message);
    // On failure try to clean up so machine isn't left broken
    await restoreWindowsRules().catch(() => {});
  }
}

async function restoreWindowsRules() {
  const ps = (cmd) =>
    execAsync(`powershell -NoProfile -NonInteractive -Command "${cmd}"`, { timeout: 12000 });

  // Remove all AlaricExam rules
  await ps(`Get-NetFirewallRule -DisplayName "${RULE_PREFIX}*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule`).catch(() => {});

  // Restore original DefaultOutboundAction
  if (fs.existsSync(ORIG_FW_FILE)) {
    try {
      const orig = JSON.parse(fs.readFileSync(ORIG_FW_FILE, 'utf8'));
      const profiles = Array.isArray(orig) ? orig : [orig];
      for (const p of profiles) {
        await ps(`Set-NetFirewallProfile -Name "${p.Name}" -DefaultOutboundAction ${p.DefaultOutboundAction}`).catch(() => {});
      }
    } catch {}
    fs.unlinkSync(ORIG_FW_FILE);
  }
  console.log('[network] Windows firewall restored');
}

// ─── macOS pfctl ──────────────────────────────────────────────────────────────
async function applyMacRules() {
  if (!_serverIPs.size) return;
  const ips = [..._serverIPs];

  // pfctl: rules are evaluated top-to-bottom; 'quick' stops processing on first match
  const rules = [
    '# Alaric Exam Network Guard',
    'set skip on lo0',           // loopback always passes
    '',
    '# Allow exam server (TCP + UDP for WebRTC)',
    ...ips.map(ip => `pass out quick inet proto tcp to ${ip}/32 keep state`),
    ...ips.map(ip => `pass out quick inet proto udp to ${ip}/32 keep state`),
    ...ips.map(ip => `pass in  quick inet from ${ip}/32 keep state`),
    '',
    '# Allow DNS and DHCP',
    'pass out quick proto udp to port 53  keep state',
    'pass out quick proto udp to port 123 keep state',   // NTP
    'pass out quick proto udp to port 67  keep state',   // DHCP
    '',
    '# Block everything else',
    'block out all',
    'block in  all',
  ].join('\n') + '\n';

  try {
    fs.writeFileSync(PF_ANCHOR, rules, 'utf8');
    // Save original pf state and load our rules
    await execAsync(`pfctl -e -f "${PF_ANCHOR}" 2>/dev/null || sudo pfctl -e -f "${PF_ANCHOR}"`, { timeout: 10000 });
    _rulesApplied = true;
    console.log('[network] macOS pfctl lockdown applied');
  } catch (e) {
    console.warn('[network] pfctl error:', e.message);
  }
}

async function restoreMacRules() {
  try {
    await execAsync('pfctl -d 2>/dev/null || sudo pfctl -d', { timeout: 8000 }).catch(() => {});
    if (fs.existsSync(PF_ANCHOR)) fs.unlinkSync(PF_ANCHOR);
    console.log('[network] macOS pfctl restored');
  } catch (e) {
    console.warn('[network] pfctl restore error:', e.message);
  }
}

// ─── Restore ──────────────────────────────────────────────────────────────────
async function restore() {
  if (process.platform === 'win32')       await restoreWindowsRules();
  else if (process.platform === 'darwin') await restoreMacRules();
  _rulesApplied = false;
}

// ─── Connection scanner ───────────────────────────────────────────────────────
const LOCAL_PREFIXES = ['127.','10.','192.168.','172.','::1','fe80','0.0.0.0'];

async function scanConnections() {
  if (!_callback) return;
  try {
    let lines = [];
    if (process.platform === 'win32') {
      const { stdout } = await execAsync('netstat -n -p TCP 2>nul', { timeout: 8000 });
      lines = stdout.split('\n').filter(l => l.includes('ESTABLISHED'));
    } else {
      const { stdout } = await execAsync('netstat -n -p tcp 2>/dev/null || ss -tn 2>/dev/null', { timeout: 8000 });
      lines = stdout.split('\n').filter(l => l.includes('ESTABLISHED') || l.includes('ESTAB'));
    }

    const suspicious = [];
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      // remote address is column 3 (netstat) or 4 (ss)
      const remote = parts[2] || parts[3] || '';
      const ip = remote.split(':')[0].replace(/[\[\]]/g, '');
      if (!ip || LOCAL_PREFIXES.some(p => ip.startsWith(p))) continue;
      if (_serverIPs.has(ip)) continue;
      suspicious.push(remote);
    }

    if (suspicious.length > 0 && _callback) {
      _callback({
        type:        'suspicious_connection',
        severity:    'critical',
        message:     `Connection to non-exam host detected: ${suspicious.slice(0,3).join(', ')}`,
        connections: suspicious,
        timestamp:   Date.now(),
      });
    }
  } catch {}
}

// ─── Public API ───────────────────────────────────────────────────────────────
async function start(examServerHost, callback) {
  _callback = callback;
  _serverIPs.clear();

  await resolveHost(examServerHost);

  if      (process.platform === 'win32')  await applyWindowsRules();
  else if (process.platform === 'darwin') await applyMacRules();

  // Scan every 5 seconds for unexpected outbound connections
  _interval = setInterval(scanConnections, 5000);
}

function stop() {
  if (_interval) { clearInterval(_interval); _interval = null; }
  _callback = null;
}

module.exports = { start, stop, restore };
