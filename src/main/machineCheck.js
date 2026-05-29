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

// ─── Friendly display names + stop instructions ───────────────────────────────
const PROCESS_INFO = {
  'vmms':           { name: 'Hyper-V Virtual Machine Management', fix: 'Open Services.msc → find "Hyper-V Virtual Machine Management" → right-click → Stop. Or run: net stop vmms' },
  'vmwp':           { name: 'Hyper-V VM Worker Process',          fix: 'Stop the Hyper-V Virtual Machine Management service: net stop vmms' },
  'vboxservice':    { name: 'VirtualBox Guest Additions Service',  fix: 'Open Services.msc → "VirtualBox Guest Additions" → Stop, or uninstall VirtualBox' },
  'vboxtray':       { name: 'VirtualBox System Tray',             fix: 'Close VirtualBox and stop the VBoxService in Services.msc' },
  'vmwaretray':     { name: 'VMware Tray Process',                fix: 'Exit VMware Workstation completely' },
  'vboxservice':    { name: 'VirtualBox Service',                  fix: 'Stop VirtualBox service: net stop VBoxService' },
  'teamviewer':     { name: 'TeamViewer',                          fix: 'Close TeamViewer completely (right-click system tray → Exit)' },
  'anydesk':        { name: 'AnyDesk',                             fix: 'Close AnyDesk completely (right-click system tray → Quit AnyDesk)' },
  'obs64':          { name: 'OBS Studio',                          fix: 'Close OBS Studio before starting the exam' },
  'obs32':          { name: 'OBS Studio',                          fix: 'Close OBS Studio before starting the exam' },
  'obs':            { name: 'OBS Studio',                          fix: 'Close OBS Studio before starting the exam' },
  'parsec':         { name: 'Parsec Remote Desktop',               fix: 'Quit Parsec from the system tray' },
  'rustdesk':       { name: 'RustDesk Remote Desktop',             fix: 'Quit RustDesk from the system tray' },
  'screenconnect':  { name: 'ConnectWise ScreenConnect',           fix: 'Stop the ScreenConnect service in Services.msc' },
};

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
    // Step 1: Check SecurityCenter2 for any registered third-party AV/EDR
    // (SentinelOne, CrowdStrike, Bitdefender, Kaspersky, McAfee, etc.)
    let thirdPartyActive = null;
    try {
      const sc2Raw = await ps(
        'Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct | Select-Object displayName,productState | ConvertTo-Json -Compress'
      );
      const products = JSON.parse(sc2Raw || '[]');
      const arr = Array.isArray(products) ? products : (products && products.displayName ? [products] : []);
      for (const p of arr) {
        const name = (p.displayName || '').toLowerCase();
        if (name.includes('windows defender') || name.includes('microsoft defender')) continue;
        // productState: bits 12-15 = 1 means enabled/active
        const state = parseInt(p.productState) || 0;
        const isEnabled = ((state >> 12) & 0xF) === 1;
        if (isEnabled) { thirdPartyActive = p.displayName; break; }
        // Some EDRs (SentinelOne, CrowdStrike) may report state differently — treat presence as active
        if (p.displayName) { thirdPartyActive = p.displayName; break; }
      }
    } catch {}

    if (thirdPartyActive) {
      return { pass: true, msg: `${thirdPartyActive} is active` };
    }

    // Step 2: No third-party AV found — require Windows Defender real-time protection
    const raw = await ps('Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json');
    const d = JSON.parse(raw);
    if (!d.AntivirusEnabled || !d.AMServiceEnabled) {
      return { pass: false, msg: 'No active antivirus detected', fix: 'Enable Windows Defender: Windows Security → Virus & threat protection → turn on, or install a third-party antivirus' };
    }
    if (!d.RealTimeProtectionEnabled) {
      return { pass: false, msg: 'Windows Defender real-time protection is off', fix: 'Windows Security → Virus & threat protection → Virus & threat protection settings → turn on Real-time protection' };
    }
    return { pass: true, msg: 'Windows Defender active with real-time protection' };
  } catch(e) {
    return { pass: false, msg: 'Could not verify antivirus status', fix: 'Ensure your antivirus is enabled and try again' };
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
  if (found.length > 0) {
    const unique = [...new Set(found)];
    const details = unique.map(b => {
      const info = PROCESS_INFO[b];
      return info ? `${info.name} (${b})` : b;
    });
    // Use fix from first found item with known info, else generic
    const firstInfo = unique.map(b => PROCESS_INFO[b]).find(Boolean);
    const fix = firstInfo ? firstInfo.fix : 'Open Task Manager → find the process → End Task, or stop the service in Services.msc';
    return { pass: false, msg: `Prohibited software running: ${details.join(', ')}`, fix, violations: unique };
  }
  return { pass: true, msg: 'No prohibited software running' };
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

// ─── Run all (config controls which checks are enabled) ───────────────────────
// config: { antivirus, firewall, processes, services, vm, remote } — undefined or true = run
async function runAll(config = {}) {
  const on = key => config[key] !== false; // missing/true/1 = enabled; false/0 = skip

  const NA = { pass: true, msg: 'Skipped by exam settings', na: true, skipped: true };

  const jobs = {
    antivirus:      on('antivirus')  ? checkAntivirus()      : Promise.resolve(NA),
    firewall:       on('firewall')   ? checkFirewall()        : Promise.resolve(NA),
    processes:      on('processes')  ? checkProcesses()       : Promise.resolve(NA),
    virtualMachine: on('vm')         ? checkVirtualMachine()  : Promise.resolve(NA),
    remoteSession:  on('remote')     ? checkRemoteSession()   : Promise.resolve(NA),
    services:       on('services')   ? checkServices()        : Promise.resolve(NA),
  };

  const keys = Object.keys(jobs);
  const settled = await Promise.allSettled(Object.values(jobs));
  const resolve = r => r.status === 'fulfilled' ? r.value : { pass: false, msg: r.reason?.message || 'Check failed' };

  const result = { platform: process.platform, timestamp: Date.now() };
  keys.forEach((k, i) => { result[k] = resolve(settled[i]); });
  return result;
}

module.exports = { runAll, checkProcesses, BLACKLISTED };
