/**
 * machineCheck.js — Pre-exam system security checks
 * Runs both Windows-specific (PowerShell) and macOS-specific (system_profiler / plutil) checks.
 */
'use strict';
const { exec }  = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

// ─── Blacklisted processes ───────────────────────────────────────────────────
const BLACKLISTED = [
  // Remote desktop / control
  'teamviewer','tv_w32','tv_x64','teamviewer_service',
  'anydesk',
  'ammyyadmin','aa_v3',
  'logmein','logmeinremoteaccess',
  'remoting_host',                   // Chrome Remote Desktop
  'vncviewer','vncserver','winvnc','tvnserver','ultravnc',
  'ultraviewer',
  'supremo',
  'screenconnect','connectwisecontrol',
  'dameware',
  'splashtop',
  'parsec',
  'rustdesk',
  'dwagent','dwservice',
  'radmin',
  'getscreen',
  'zoho assist',
  // Screen capture / broadcast
  'obs64','obs32','obs',
  'xsplit',
  'streamlabs obs',
  'bandicam',
  'camtasia',
  'fraps',
  'nvidia shadowplay','nvcontainer',
  // Virtual machines
  'vmware','vmwaretray','vmwareuser','vmware-vmx',
  'virtualbox','vboxservice','vboxtray',
  'parallels','prl_client_app',
  'qemu-system',
  'vmwp','vmms',                     // Hyper-V workers
];

// ─── Helpers ─────────────────────────────────────────────────────────────────
async function ps(cmd) {
  const { stdout } = await execAsync(
    `powershell -NoProfile -NonInteractive -Command "${cmd}"`,
    { timeout: 12000 }
  );
  return stdout.trim();
}

async function sh(cmd) {
  const { stdout } = await execAsync(cmd, { timeout: 10000 });
  return stdout.trim();
}

// ─── Individual checks ────────────────────────────────────────────────────────

async function checkAntivirus() {
  if (process.platform !== 'win32') return { pass: true, msg: 'N/A on this OS', na: true };
  try {
    const raw = await ps('Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json');
    const d = JSON.parse(raw);
    if (!d.AntivirusEnabled)        return { pass: false, msg: 'Windows Defender antivirus is disabled', fix: 'Open Windows Security → Virus & threat protection → turn on' };
    if (!d.AMServiceEnabled)        return { pass: false, msg: 'Antimalware service is stopped', fix: 'Restart Windows Defender service in Services.msc' };
    if (!d.RealTimeProtectionEnabled) return { pass: false, msg: 'Real-time protection is off', fix: 'Open Windows Security → Virus & threat protection → turn on real-time protection' };
    return { pass: true, msg: 'Windows Defender active with real-time protection' };
  } catch(e) {
    return { pass: false, msg: 'Could not verify antivirus status', fix: 'Ensure Windows Defender is enabled and try again' };
  }
}

async function checkFirewall() {
  if (process.platform === 'win32') {
    try {
      const raw = await ps('Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json');
      const profiles = JSON.parse(raw);
      const arr = Array.isArray(profiles) ? profiles : [profiles];
      const disabled = arr.filter(p => !p.Enabled).map(p => p.Name);
      if (disabled.length > 0) return { pass: false, msg: `Firewall OFF on: ${disabled.join(', ')}`, fix: 'Open Windows Security → Firewall & network protection → enable all profiles' };
      return { pass: true, msg: 'Windows Firewall enabled on all profiles' };
    } catch {
      return { pass: false, msg: 'Could not verify firewall', fix: 'Enable Windows Firewall via Windows Security' };
    }
  } else {
    try {
      const out = await sh('/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate');
      if (!out.toLowerCase().includes('enabled')) return { pass: false, msg: 'macOS Firewall is off', fix: 'System Settings → Network → Firewall → Turn On' };
      return { pass: true, msg: 'macOS Firewall enabled' };
    } catch {
      return { pass: true, msg: 'Firewall check skipped', na: true };
    }
  }
}

async function checkProcesses() {
  let list = [];
  try {
    if (process.platform === 'win32') {
      const raw = await execAsync('tasklist /fo csv /nh', { timeout: 10000 });
      list = raw.stdout.split('\n').map(l => l.replace(/"/g,'').toLowerCase().split(',')[0].trim()).filter(Boolean);
    } else {
      const raw = await execAsync('ps -ax -o comm=', { timeout: 10000 });
      list = raw.stdout.split('\n').map(l => require('path').basename(l.trim()).toLowerCase()).filter(Boolean);
    }
  } catch { return { pass: true, msg: 'Process check skipped', na: true }; }

  const found = BLACKLISTED.filter(b => list.some(p => p.replace('.exe','').includes(b)));
  if (found.length > 0) return { pass: false, msg: `Must close: ${[...new Set(found)].join(', ')}`, fix: 'Close the listed applications and retry', violations: found };
  return { pass: true, msg: 'No blacklisted applications running' };
}

async function checkVirtualMachine() {
  try {
    if (process.platform === 'win32') {
      const raw = await ps('Get-WmiObject Win32_ComputerSystem | Select-Object Manufacturer,Model | ConvertTo-Json');
      const d = JSON.parse(raw);
      const s = `${d.Manufacturer} ${d.Model}`.toLowerCase();
      const isVM = ['vmware','virtualbox','innotek','parallels','qemu','xen','bochs'].some(v => s.includes(v))
                || (s.includes('microsoft') && (s.includes('virtual') || s.includes('hyper')));
      if (isVM) return { pass: false, msg: 'Virtual machine detected — exam requires a physical machine', fix: 'Restart on physical hardware' };
    } else {
      const raw = await sh('system_profiler SPHardwareDataType 2>/dev/null | grep "Model Identifier"');
      if (/vmware|parallels|virtual/i.test(raw)) return { pass: false, msg: 'Virtual machine detected', fix: 'Use a physical Mac' };
    }
  } catch {}
  return { pass: true, msg: 'Physical machine confirmed' };
}

async function checkRemoteSession() {
  try {
    if (process.platform === 'win32') {
      // SM_REMOTESESSION = 0x1000
      const raw = await ps("Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class U32{[DllImport(\"user32.dll\")]public static extern int GetSystemMetrics(int n);}' -PassThru 2>$null | Out-Null; [U32]::GetSystemMetrics(0x1000)");
      if (parseInt(raw) !== 0) return { pass: false, msg: 'Active remote desktop session detected', fix: 'Disconnect all remote desktop / VNC sessions' };
    } else {
      const { stdout } = await execAsync("who 2>/dev/null | grep -v 'console' | wc -l", { timeout: 5000 });
      if (parseInt(stdout.trim()) > 0) return { pass: false, msg: 'Remote session detected', fix: 'Disconnect all remote sessions' };
    }
  } catch {}
  return { pass: true, msg: 'No remote desktop session active' };
}

async function checkServices() {
  // Windows only — check for remote services even if process is hidden
  if (process.platform !== 'win32') return { pass: true, msg: 'N/A on this OS', na: true };
  try {
    const raw = await ps('Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object -ExpandProperty Name | ConvertTo-Json');
    const services = JSON.parse(raw || '[]');
    const arr = Array.isArray(services) ? services : [services];
    const lc = arr.map(s => s.toLowerCase());
    const blocked = ['teamviewer','anydesk','ultravnc','ultraviewer','rustdesk'].filter(b => lc.some(s => s.includes(b)));
    if (blocked.length > 0) return { pass: false, msg: `Remote service running: ${blocked.join(', ')}`, fix: 'Stop the service via Services.msc and disable it', violations: blocked };
  } catch {}
  return { pass: true, msg: 'No blacklisted services running' };
}

// ─── Run all ──────────────────────────────────────────────────────────────────
async function runAll() {
  const [av, firewall, procs, vm, remote, services] = await Promise.allSettled([
    checkAntivirus(),
    checkFirewall(),
    checkProcesses(),
    checkVirtualMachine(),
    checkRemoteSession(),
    checkServices(),
  ]);

  const resolve = r => r.status === 'fulfilled' ? r.value : { pass: false, msg: r.reason?.message || 'Check failed' };

  return {
    platform:  process.platform,
    timestamp: Date.now(),
    antivirus:     resolve(av),
    firewall:      resolve(firewall),
    processes:     resolve(procs),
    virtualMachine:resolve(vm),
    remoteSession: resolve(remote),
    services:      resolve(services),
  };
}

module.exports = { runAll, checkProcesses, BLACKLISTED };
