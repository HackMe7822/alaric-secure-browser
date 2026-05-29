/**
 * networkMonitor.js — Total network lockdown during exam
 *
 * Three-layer approach:
 *  1. Disable remote-access protocols at the OS level (RDP, WinRM, SSH, etc.)
 *  2. Firewall: DefaultOutboundAction=Block + Allow exam-server IPs only
 *  3. Kill/close any process/connection that already has a remote TCP session
 *     (catches legitimately-named rootkits — they still need the network)
 *
 * On restore: remove firewall rules, restore original protocol states,
 *             restore original DefaultOutboundAction.
 */
'use strict';
const { exec }      = require('child_process');
const { promisify } = require('util');
const dns           = require('dns').promises;
const fs            = require('fs');
const os            = require('os');
const path          = require('path');
const execAsync     = promisify(exec);

const RULE_PREFIX  = 'AlaricExam';
const PF_ANCHOR    = '/tmp/alaric_pf.conf';
// Use HOME dir (not tmpdir) — tmpdir is cleared on reboot, which would leave the
// machine with DefaultOutboundAction=Block permanently if the file is lost.
const _DATA_DIR    = process.env.APPDATA || process.env.HOME || os.homedir();
const ORIG_FW_FILE = path.join(_DATA_DIR, '.alaric_fw_orig.json');
const ORIG_PR_FILE = path.join(_DATA_DIR, '.alaric_proto_orig.json');

let _serverIPs    = new Set();
let _interval     = null;
let _callback     = null;
let _rulesApplied = false;

// ─── DNS resolve ──────────────────────────────────────────────────────────────
async function resolveHost(host) {
  const add = (arr) => arr.forEach(ip => _serverIPs.add(ip));
  try { add(await dns.resolve4(host)); } catch {}
  try { add(await dns.resolve6(host)); } catch {}
  if (_serverIPs.size === 0 && host) _serverIPs.add(host);
  console.log('[network] Exam server IPs:', [..._serverIPs]);
}

// ─── PowerShell helpers ───────────────────────────────────────────────────────
// Single-line commands only — uses -Command with quote escaping
const ps = (cmd) =>
  execAsync(`powershell -NoProfile -NonInteractive -Command "${cmd.replace(/"/g, '\\"')}"`,
    { timeout: 15000 });

// Multi-line scripts — uses -EncodedCommand (base64 UTF-16LE) to bypass
// cmd.exe newline-splitting which breaks multi-line -Command scripts
function psBig(script) {
  const b64 = Buffer.from(script, 'utf16le').toString('base64');
  return execAsync(`powershell -NoProfile -NonInteractive -EncodedCommand ${b64}`,
    { timeout: 25000 });
}

// Only actual IP addresses (not hostnames) are valid for Windows firewall rules
function isIP(addr) { return /^[\d.:a-fA-F]+$/.test(addr) && addr !== ''; }

// ─── 1. Disable all remote-access protocols (save originals) ─────────────────
async function disableRemoteProtocols() {
  if (process.platform === 'win32') {
    // Save current state of every remote-access protocol
    const orig = {};
    const safe = async (key, cmd) => { try { orig[key] = (await ps(cmd)).stdout.trim(); } catch { orig[key] = ''; } };

    await safe('rdpDeny',       '(Get-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -ErrorAction SilentlyContinue).fDenyTSConnections');
    await safe('winrmStart',    '(Get-Service WinRM          -ErrorAction SilentlyContinue).StartType');
    await safe('remRegStart',   '(Get-Service RemoteRegistry -ErrorAction SilentlyContinue).StartType');
    await safe('sshdStart',     '(Get-Service sshd           -ErrorAction SilentlyContinue).StartType');
    await safe('termSvcStart',  '(Get-Service TermService    -ErrorAction SilentlyContinue).StartType');
    await safe('umRdpStart',    '(Get-Service UmRdpService   -ErrorAction SilentlyContinue).StartType');
    await safe('rdpUdpStart',   '(Get-Service RdpManagerUserModePort -ErrorAction SilentlyContinue).StartType');

    fs.writeFileSync(ORIG_PR_FILE, JSON.stringify(orig));

    // ── Disable RDP (block at registry + stop services) ───────────────────
    await ps('Set-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections -Value 1').catch(() => {});
    await ps('Stop-Service TermService    -Force -ErrorAction SilentlyContinue').catch(() => {});
    await ps('Stop-Service UmRdpService   -Force -ErrorAction SilentlyContinue').catch(() => {});
    await ps('Stop-Service SessionEnv    -Force -ErrorAction SilentlyContinue').catch(() => {});
    await ps('Set-Service TermService    -StartupType Disabled -ErrorAction SilentlyContinue').catch(() => {});
    await ps('Set-Service UmRdpService   -StartupType Disabled -ErrorAction SilentlyContinue').catch(() => {});

    // ── Disable WinRM (PowerShell Remoting) ───────────────────────────────
    await ps('Stop-Service WinRM -Force -ErrorAction SilentlyContinue').catch(() => {});
    await ps('Set-Service WinRM -StartupType Disabled -ErrorAction SilentlyContinue').catch(() => {});

    // ── Disable Remote Registry ───────────────────────────────────────────
    await ps('Stop-Service RemoteRegistry -Force -ErrorAction SilentlyContinue').catch(() => {});
    await ps('Set-Service RemoteRegistry -StartupType Disabled -ErrorAction SilentlyContinue').catch(() => {});

    // ── Disable OpenSSH server (optional — might not exist) ───────────────
    await ps('Stop-Service sshd -Force -ErrorAction SilentlyContinue').catch(() => {});
    await ps('Set-Service sshd -StartupType Disabled -ErrorAction SilentlyContinue').catch(() => {});

    // ── Block RDP port 3389 explicitly (belt-and-suspenders) ─────────────
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}BlockRDP3389" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block -ErrorAction SilentlyContinue`).catch(() => {});
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}BlockVNC5900"  -Direction Inbound -Protocol TCP -LocalPort 5900-5910 -Action Block -ErrorAction SilentlyContinue`).catch(() => {});
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}BlockSSH22"    -Direction Inbound -Protocol TCP -LocalPort 22 -Action Block -ErrorAction SilentlyContinue`).catch(() => {});

    console.log('[network] Remote access protocols disabled');
  } else if (process.platform === 'darwin') {
    const orig = {};
    // Save SSH state
    try { orig.sshEnabled = (await execAsync('systemsetup -getremotelogin 2>/dev/null')).stdout.includes('On'); } catch { orig.sshEnabled = false; }
    // Save Screen Sharing state
    try { orig.screenShare = fs.existsSync('/Library/Preferences/com.apple.ScreenSharing.plist'); } catch { orig.screenShare = false; }
    fs.writeFileSync(ORIG_PR_FILE, JSON.stringify(orig));

    // Disable SSH
    await execAsync('launchctl unload -w /System/Library/LaunchDaemons/ssh.plist 2>/dev/null || true').catch(() => {});
    await execAsync('systemsetup -setremotelogin off 2>/dev/null || true').catch(() => {});
    // Disable Screen Sharing
    await execAsync('launchctl unload -w /System/Library/LaunchDaemons/com.apple.screensharing.plist 2>/dev/null || true').catch(() => {});
    // Disable Apple Remote Desktop
    await execAsync('/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop 2>/dev/null || true').catch(() => {});

    console.log('[network] macOS remote access protocols disabled');
  }
}

async function restoreRemoteProtocols() {
  if (!fs.existsSync(ORIG_PR_FILE)) return;
  try {
    const orig = JSON.parse(fs.readFileSync(ORIG_PR_FILE, 'utf8'));
    if (process.platform === 'win32') {
      // Restore RDP registry key
      if (orig.rdpDeny !== undefined) {
        await ps(`Set-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections -Value ${orig.rdpDeny || 1}`).catch(() => {});
      }
      // Restore each service startup type
      const svcMap = {
        winrmStart:  'WinRM',          remRegStart:  'RemoteRegistry',
        sshdStart:   'sshd',           termSvcStart: 'TermService',
        umRdpStart:  'UmRdpService',   rdpUdpStart:  'RdpManagerUserModePort',
      };
      for (const [key, svcName] of Object.entries(svcMap)) {
        if (orig[key] && orig[key] !== 'Disabled') {
          await ps(`Set-Service ${svcName} -StartupType ${orig[key]} -ErrorAction SilentlyContinue`).catch(() => {});
        }
      }
    } else if (process.platform === 'darwin') {
      if (orig.sshEnabled) {
        await execAsync('launchctl load -w /System/Library/LaunchDaemons/ssh.plist 2>/dev/null || true').catch(() => {});
      }
      if (orig.screenShare) {
        await execAsync('launchctl load -w /System/Library/LaunchDaemons/com.apple.screensharing.plist 2>/dev/null || true').catch(() => {});
      }
    }
    fs.unlinkSync(ORIG_PR_FILE);
    console.log('[network] Remote protocols restored');
  } catch (e) { console.warn('[network] Protocol restore error:', e.message); }
}

// ─── 2. Kill/close existing remote connections ────────────────────────────────
// This catches legitimately-named processes (rootkits, renamed tools) that
// already have an established connection — name-based detection misses these.
const LOCAL_PREFIXES = ['127.','0.0.0.0','::1','fe80','169.254.','[::','[:'];

async function killExistingRemoteConnections() {
  if (process.platform !== 'win32') return;

  // Only valid IPs — hostname strings don't match TCP connection remote addresses
  const validIPs = [..._serverIPs].filter(isIP);
  if (!validIPs.length) {
    console.warn('[network] killExistingRemoteConnections: no valid IPs — skipping to avoid killing exam server connections');
    return;
  }

  const examIPList = validIPs.map(ip => `"${ip}"`).join(',');

  // Use psBig (base64 -EncodedCommand) — avoids cmd.exe newline-splitting bug
  // that made the original ps() multi-line call completely inoperative.
  // $procId used instead of $pid to avoid shadowing PowerShell's read-only $PID built-in.
  const script = `
$examIPs    = @(${examIPList})
$localPre   = @('127.','0.0.0.0','::1','fe80','169.254.')
$systemPIDs = @(0,4,8)

function IsLocal([string]$ip) {
  foreach ($p in $localPre) { if ($ip.StartsWith($p)) { return $true } }
  return $false
}
function IsExam([string]$ip) { return ($examIPs -contains $ip) }

# Step 1: close TCP connections cleanly via Remove-NetTCPConnection
try {
  Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { -not (IsLocal $_.RemoteAddress) -and -not (IsExam $_.RemoteAddress) } |
    ForEach-Object {
      Write-Host "Closing $($_.RemoteAddress):$($_.RemotePort) PID=$($_.OwningProcess)"
      $_ | Remove-NetTCPConnection -ErrorAction SilentlyContinue
    }
} catch {}

Start-Sleep -Milliseconds 800

# Step 2: kill processes that still have remote connections
# Uses $procId (not $pid) to avoid shadowing PowerShell's read-only built-in $PID
try {
  Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { -not (IsLocal $_.RemoteAddress) -and -not (IsExam $_.RemoteAddress) } |
    ForEach-Object {
      $procId = $_.OwningProcess
      if ($systemPIDs -contains $procId) { return }
      $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
      if (-not $proc) { return }
      $procName = $proc.ProcessName.ToLower()
      Write-Host "Killing $procName (PID $procId) -> $($_.RemoteAddress)"
      if ($procName -eq 'svchost') {
        # Stop individual services inside svchost rather than killing the host
        Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
          Where-Object { $_.ProcessId -eq $procId -and $_.State -eq 'Running' } |
          ForEach-Object {
            Write-Host "  Stopping svc: $($_.Name)"
            Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
            Set-Service  -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue
          }
      } else {
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
      }
    }
} catch {}
`;

  try {
    const result = await psBig(script);
    if (result.stdout.trim()) console.log('[network] Kill remote connections:\n', result.stdout.trim());
  } catch (e) { console.warn('[network] Kill connections error:', e.message); }
}

// ─── 3. Windows firewall lockdown ─────────────────────────────────────────────
async function applyWindowsRules() {
  if (!_serverIPs.size) return;
  try {
    // Save original DefaultOutboundAction
    const origRaw = await ps('Get-NetFirewallProfile | Select-Object Name,DefaultOutboundAction | ConvertTo-Json -Compress');
    fs.writeFileSync(ORIG_FW_FILE, origRaw.stdout.trim());

    // Remove any leftover Alaric rules
    await ps(`Get-NetFirewallRule -DisplayName "${RULE_PREFIX}*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule`).catch(() => {});

    // Set default outbound = Block (explicit Allow rules win over this)
    await ps('Set-NetFirewallProfile -All -DefaultOutboundAction Block');

    // Windows -RemoteAddress only accepts IP addresses, not hostnames
    const validIPs = [..._serverIPs].filter(isIP);
    if (!validIPs.length) {
      // DNS failed entirely — do NOT apply DefaultOutboundAction=Block yet:
      // that would permanently block the exam server with no whitelist entry.
      // Restore DefaultOutboundAction to its original value and abort.
      await restoreWindowsRules().catch(() => {});
      console.error('[network] DNS resolution failed — no valid IPs for exam server. Firewall lockdown skipped to prevent bricking network access.');
      return;
    }
    const ips = validIPs.join('","');

    // Allow exam server (TCP + UDP for WebRTC)
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}ServerTCP" -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress "${ips}"`);
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}ServerUDP" -Direction Outbound -Action Allow -Protocol UDP -RemoteAddress "${ips}"`);

    // Allow DNS, DHCP, NTP (needed for network stack)
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}DNS"  -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53`);
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}DHCP" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 67,68,123`);

    // Allow loopback (Electron IPC uses localhost)
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}Loop" -Direction Outbound -Action Allow -Protocol Any -RemoteAddress "127.0.0.1","::1"`);

    // Allow DHCP inbound — DHCP lease renewals are INBOUND (server UDP/67 → client UDP/68).
    // Without this, the lease expires mid-exam and the machine loses its IP.
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}DHCP_IN" -Direction Inbound -Action Allow -Protocol UDP -RemotePort 67 -LocalPort 68`);
    // Allow DNS responses inbound
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}DNS_IN" -Direction Inbound -Action Allow -Protocol UDP -RemotePort 53`);

    // Block all other inbound (prevents remote connections TO this machine).
    // Note: DHCP_IN and DNS_IN rules above are added first so they take precedence.
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}BlockIn" -Direction Inbound -Action Block -Protocol Any`);
    // Allow inbound from exam server (WebRTC answers, WS monitor)
    await ps(`New-NetFirewallRule -DisplayName "${RULE_PREFIX}AllowIn" -Direction Inbound -Action Allow -Protocol Any -RemoteAddress "${ips}"`);

    _rulesApplied = true;
    console.log('[network] Windows firewall lockdown applied');
  } catch (e) {
    console.error('[network] Firewall apply error:', e.message);
    await restoreWindowsRules().catch(() => {});
  }
}

async function restoreWindowsRules() {
  await ps(`Get-NetFirewallRule -DisplayName "${RULE_PREFIX}*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule`).catch(() => {});
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

// ─── 4. macOS pfctl lockdown ──────────────────────────────────────────────────
async function applyMacRules() {
  if (!_serverIPs.size) return;
  const ips = [..._serverIPs].filter(isIP); // pfctl requires IP addresses, not hostnames
  if (!ips.length) { console.warn('[network] No valid IPs for pfctl'); return; }
  const rules = [
    '# Alaric Exam Network Guard',
    'set skip on lo0',
    '',
    '# Allow exam server',
    ...ips.map(ip => `pass out quick inet proto tcp to ${ip}/32 keep state`),
    ...ips.map(ip => `pass out quick inet proto udp to ${ip}/32 keep state`),
    ...ips.map(ip => `pass in  quick inet from ${ip}/32 keep state`),
    '',
    '# Allow DNS, DHCP, NTP',
    'pass out quick proto udp to port 53  keep state',
    'pass out quick proto udp to port 123 keep state',
    'pass out quick proto udp to port 67  keep state',
    '',
    '# Block all else (both directions)',
    'block out all',
    'block in  all',
  ].join('\n') + '\n';

  try {
    fs.writeFileSync(PF_ANCHOR, rules, 'utf8');
    await execAsync(`pfctl -e -f "${PF_ANCHOR}" 2>/dev/null || sudo pfctl -e -f "${PF_ANCHOR}"`, { timeout: 10000 });
    _rulesApplied = true;
    console.log('[network] macOS pfctl lockdown applied');
  } catch (e) { console.warn('[network] pfctl error:', e.message); }
}

// ─── 5. Connection scanner (5-second poll) ────────────────────────────────────
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
      const remote = parts[2] || parts[3] || '';
      const ip = remote.split(':')[0].replace(/[\[\]]/g, '');
      if (!ip || LOCAL_PREFIXES.some(p => ip.startsWith(p))) continue;
      if (_serverIPs.has(ip)) continue;
      suspicious.push(remote);
    }

    if (suspicious.length > 0) {
      // Auto-kill the suspicious connection process too
      await killExistingRemoteConnections();
      _callback({
        type:     'suspicious_connection',
        severity: 'critical',
        message:  `Connection to non-exam host detected and terminated: ${suspicious.slice(0,3).join(', ')}`,
        timestamp: Date.now(),
      });
    }
  } catch {}
}

// ─── Public API ───────────────────────────────────────────────────────────────
async function start(examServerHost, callback) {
  _callback = callback;
  _serverIPs.clear();
  await resolveHost(examServerHost);

  // Layer 1: disable all remote access protocols at OS level
  await disableRemoteProtocols();

  // Layer 2: firewall rules
  if      (process.platform === 'win32')  await applyWindowsRules();
  else if (process.platform === 'darwin') await applyMacRules();

  // Layer 3: kill any already-established remote connections (including rootkits)
  await killExistingRemoteConnections();

  // Poll every 5s — kills anything that re-establishes
  _interval = setInterval(scanConnections, 5000);
}

function stop() {
  if (_interval) { clearInterval(_interval); _interval = null; }
  _callback = null;
}

async function restore() {
  stop();
  if (process.platform === 'win32') {
    await restoreWindowsRules();
  } else if (process.platform === 'darwin') {
    try {
      await execAsync('pfctl -d 2>/dev/null || sudo pfctl -d', { timeout: 8000 }).catch(() => {});
      if (fs.existsSync(PF_ANCHOR)) fs.unlinkSync(PF_ANCHOR);
    } catch {}
  }
  await restoreRemoteProtocols();
  _rulesApplied = false;
}

module.exports = { start, stop, restore };
