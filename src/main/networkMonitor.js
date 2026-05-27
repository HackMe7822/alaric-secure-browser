/**
 * networkMonitor.js
 * 1. Resolves exam server hostname → IP(s)
 * 2. Adds Windows Firewall / macOS pfctl rules to allow ONLY exam server
 * 3. Polls netstat every 5 s, flags connections to unlisted IPs
 * 4. Restores rules on app quit
 */
'use strict';
const { exec }      = require('child_process');
const { promisify } = require('util');
const dns           = require('dns').promises;
const fs            = require('fs');
const path          = require('path');
const execAsync     = promisify(exec);

const RULE_ALLOW = 'AlaricExamAllow';
const RULE_BLOCK = 'AlaricExamBlock';
const PF_ANCHOR  = '/tmp/alaric_pf_anchor.conf';

let _serverIPs    = new Set();
let _interval     = null;
let _callback     = null;
let _rulesApplied = false;
let _platform     = process.platform;

// ─── DNS resolve ──────────────────────────────────────────────────────────────
async function resolveHost(host) {
  try {
    const addrs = await dns.resolve4(host);
    addrs.forEach(ip => _serverIPs.add(ip));
  } catch {}
  // Also try resolve6 for completeness
  try {
    const addrs = await dns.resolve6(host);
    addrs.forEach(ip => _serverIPs.add(ip));
  } catch {}
  console.log('[networkMonitor] Exam server IPs:', [..._serverIPs]);
}

// ─── Windows Firewall rules ───────────────────────────────────────────────────
async function applyWindowsRules() {
  if (_serverIPs.size === 0) return;
  const allowed = [..._serverIPs].join(',');
  try {
    // Clean up any previous rules
    await execAsync(`netsh advfirewall firewall delete rule name="${RULE_ALLOW}"`, { timeout: 6000 }).catch(() => {});
    await execAsync(`netsh advfirewall firewall delete rule name="${RULE_BLOCK}"`, { timeout: 6000 }).catch(() => {});

    // Allow outbound TCP to exam server
    await execAsync(
      `netsh advfirewall firewall add rule name="${RULE_ALLOW}" dir=out action=allow protocol=TCP remoteip="${allowed}"`,
      { timeout: 8000 }
    );
    // Allow DNS (UDP 53) so the exam page can still resolve assets
    await execAsync(
      `netsh advfirewall firewall add rule name="${RULE_ALLOW}_DNS" dir=out action=allow protocol=UDP remoteport=53`,
      { timeout: 8000 }
    );
    // Block all other outbound TCP — allow rules evaluated first by Windows FW
    await execAsync(
      `netsh advfirewall firewall add rule name="${RULE_BLOCK}" dir=out action=block protocol=TCP`,
      { timeout: 8000 }
    );
    _rulesApplied = true;
    console.log('[networkMonitor] Windows firewall rules applied');
  } catch (e) {
    console.warn('[networkMonitor] Firewall rule error:', e.message);
  }
}

// ─── macOS pfctl rules ────────────────────────────────────────────────────────
async function applyMacRules() {
  if (_serverIPs.size === 0) return;
  const rules = [
    '# Alaric Exam Network Guard — auto-generated',
    'set skip on lo0',
    ...[ ..._serverIPs ].map(ip => `pass out quick inet to ${ip}/32`),
    'pass out quick proto udp to port 53',   // DNS
    'block out all',
  ].join('\n') + '\n';

  try {
    fs.writeFileSync(PF_ANCHOR, rules);
    await execAsync(`sudo pfctl -f ${PF_ANCHOR} -e 2>/dev/null || pfctl -f ${PF_ANCHOR} -e`, { timeout: 8000 });
    _rulesApplied = true;
    console.log('[networkMonitor] macOS pfctl rules applied');
  } catch (e) {
    console.warn('[networkMonitor] pfctl error:', e.message);
  }
}

// ─── Restore ──────────────────────────────────────────────────────────────────
async function restore() {
  if (!_rulesApplied) return;
  try {
    if (_platform === 'win32') {
      await execAsync(`netsh advfirewall firewall delete rule name="${RULE_ALLOW}"`,     { timeout: 6000 }).catch(() => {});
      await execAsync(`netsh advfirewall firewall delete rule name="${RULE_ALLOW}_DNS"`, { timeout: 6000 }).catch(() => {});
      await execAsync(`netsh advfirewall firewall delete rule name="${RULE_BLOCK}"`,     { timeout: 6000 }).catch(() => {});
      console.log('[networkMonitor] Windows firewall rules removed');
    } else if (_platform === 'darwin') {
      await execAsync('sudo pfctl -d 2>/dev/null || pfctl -d', { timeout: 6000 }).catch(() => {});
      if (fs.existsSync(PF_ANCHOR)) fs.unlinkSync(PF_ANCHOR);
      console.log('[networkMonitor] macOS pfctl restored');
    }
  } catch (e) {
    console.warn('[networkMonitor] Restore error:', e.message);
  }
  _rulesApplied = false;
}

// ─── Connection scanner ───────────────────────────────────────────────────────
const LOCAL_PREFIXES = ['127.','10.','192.168.','172.','::1','fe80'];

async function scanConnections() {
  if (!_callback || _serverIPs.size === 0) return;
  try {
    let lines = [];
    if (_platform === 'win32') {
      const { stdout } = await execAsync('netstat -n -p TCP 2>nul', { timeout: 8000 });
      lines = stdout.split('\n').filter(l => l.includes('ESTABLISHED'));
    } else {
      const { stdout } = await execAsync('netstat -n -p tcp 2>/dev/null || ss -tn 2>/dev/null', { timeout: 8000 });
      lines = stdout.split('\n').filter(l => l.includes('ESTABLISHED') || l.includes('ESTAB'));
    }

    const suspicious = [];
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      const remote = parts[2] || parts[parts.length - 1] || '';
      const ip = remote.split(':')[0].replace(/[\[\]]/g, '');
      if (!ip || LOCAL_PREFIXES.some(p => ip.startsWith(p))) continue;
      if (_serverIPs.has(ip)) continue;
      suspicious.push(remote);
    }

    if (suspicious.length > 0) {
      _callback({
        type:        'suspicious_connection',
        severity:    'warning',
        message:     `Outbound connection to non-exam host detected`,
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

  if (_platform === 'win32')      await applyWindowsRules();
  else if (_platform === 'darwin') await applyMacRules();

  _interval = setInterval(scanConnections, 5000);
}

function stop() {
  if (_interval) { clearInterval(_interval); _interval = null; }
  _callback = null;
}

module.exports = { start, stop, restore };
