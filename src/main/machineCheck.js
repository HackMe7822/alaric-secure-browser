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

async function checkAntivirus(autoFix = true) {
  if (process.platform !== 'win32') return { pass: true, msg: 'N/A on this OS', na: true };
  try {
    // Step 1: third-party AV/EDR (SentinelOne, CrowdStrike, Bitdefender, etc.)
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
        const state = parseInt(p.productState) || 0;
        if (((state >> 12) & 0xF) === 1 || p.displayName) { thirdPartyActive = p.displayName; break; }
      }
    } catch {}
    if (thirdPartyActive) return { pass: true, msg: `${thirdPartyActive} is active` };

    // Step 2: Windows Defender
    const raw = await ps('Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json');
    const d = JSON.parse(raw);
    const rtOff = !d.RealTimeProtectionEnabled;
    const avOff = !d.AntivirusEnabled || !d.AMServiceEnabled;

    if (!rtOff && !avOff) return { pass: true, msg: 'Windows Defender active with real-time protection' };

    // ── Auto-fix: enable Windows Defender RT protection ─────────────────────
    if (autoFix) {
      // Record original state for rollback
      if (_snap.defenderRtDisabled === null) _snap.defenderRtDisabled = rtOff;
      // Start service + enable RT protection
      await execAsync('net start WinDefend 2>nul || exit 0', { timeout: 10000 }).catch(() => {});
      await ps('Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue').catch(() => {});
      await new Promise(r => setTimeout(r, 2000));
      const recheck = await checkAntivirus(false);
      if (recheck.pass) return { pass: true, msg: 'Windows Defender real-time protection enabled automatically', fixed: true };
      return recheck;
    }

    return avOff
      ? { pass: false, msg: 'No active antivirus detected', fix: 'Enable Windows Defender: Windows Security → Virus & threat protection → turn on' }
      : { pass: false, msg: 'Windows Defender real-time protection is off', fix: 'Windows Security → Virus & threat protection settings → turn on Real-time protection' };
  } catch(e) {
    return { pass: false, msg: 'Could not verify antivirus status', fix: 'Ensure your antivirus is enabled and try again' };
  }
}

async function checkFirewall(autoFix = true) {
  if (process.platform === 'win32') {
    try {
      const raw = await ps('Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json');
      const profiles = JSON.parse(raw);
      const arr = Array.isArray(profiles) ? profiles : [profiles];
      const disabled = arr.filter(p => !p.Enabled).map(p => p.Name);

      if (!disabled.length) return { pass: true, msg: 'Windows Firewall enabled on all profiles' };

      // ── Auto-fix: enable all profiles ──────────────────────────────────────
      if (autoFix) {
        // Save original profile states for rollback
        if (!_snap.firewallProfiles) {
          _snap.firewallProfiles = {};
          arr.forEach(p => { _snap.firewallProfiles[p.Name] = !!p.Enabled; });
        }
        await ps('Set-NetFirewallProfile -All -Enabled True -ErrorAction SilentlyContinue');
        await new Promise(r => setTimeout(r, 600));
        const recheck = await checkFirewall(false);
        if (recheck.pass) return { pass: true, msg: `Firewall enabled on all profiles (was off: ${disabled.join(', ')})`, fixed: true, fixedItems: disabled };
        return recheck;
      }

      return { pass: false, msg: `Firewall OFF on: ${disabled.join(', ')}`, fix: 'Windows Security → Firewall & network protection → enable all profiles' };
    } catch {
      return { pass: false, msg: 'Could not verify firewall', fix: 'Enable Windows Firewall via Windows Security' };
    }
  } else {
    try {
      const out = await sh('/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate');
      if (!out.toLowerCase().includes('enabled')) {
        if (autoFix) {
          await sh('/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on').catch(() => {});
          if (!_snap.firewallProfiles) _snap.firewallProfiles = { macOS: false };
          const recheck = await sh('/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate');
          if (recheck.toLowerCase().includes('enabled'))
            return { pass: true, msg: 'macOS Firewall enabled automatically', fixed: true };
        }
        return { pass: false, msg: 'macOS Firewall is off', fix: 'System Settings → Network → Firewall → Turn On' };
      }
      return { pass: true, msg: 'macOS Firewall enabled' };
    } catch { return { pass: true, msg: 'Firewall check skipped', na: true }; }
  }
}

// ─── Central snapshot — tracks EVERY change so restoreAll() can undo it ──────
const _snap = {
  services:           new Map(),   // svcName → { name, startType }
  firewallProfiles:   null,        // { Domain: bool, Private: bool, Public: bool }
  defenderRtDisabled: null,        // true if we turned RT back ON (so restore = turn OFF)
  displayMode:        null,        // 'extended' if original was multi-monitor
};
// Keep alias so existing _serviceSnapshot refs work
const _serviceSnapshot = _snap.services;

// Map process names → their backing Windows service names (for disabling)
const PROCESS_TO_SERVICE = {
  'vmms':            ['vmms'],
  'vmwp':            ['vmms'],
  'vboxservice':     ['VBoxService'],
  'vboxtray':        ['VBoxService'],
  'vmwaretray':      ['VMware'],
  'teamviewer':      ['TeamViewer'],
  'teamviewer_service': ['TeamViewer'],
  'tv_w32':          ['TeamViewer'],
  'tv_x64':          ['TeamViewer'],
  'anydesk':         ['AnyDesk'],
  'rustdesk':        ['RustDesk'],
  'ultravnc':        ['uvnc_service'],
  'ultraviewer':     ['UltraViewer_service'],
  'screenconnect':   ['ScreenConnect Client'],
  'logmein':         ['LogMeIn'],
  'supremo':         ['SupremoService'],
  'dwagent':         ['dwservice'],
  'parsec':          ['Parsec'],
};

async function _stopAndDisableService(rawName) {
  if (process.platform !== 'win32') return false;
  try {
    // Get current start type before touching anything
    const infoRaw = await ps(
      `$s=Get-Service -Name '${rawName}' -ErrorAction SilentlyContinue;` +
      `if($s){[PSCustomObject]@{Name=$s.Name;StartType=$s.StartType.ToString();Status=$s.Status.ToString()}|ConvertTo-Json -Compress}`
    );
    const info = infoRaw ? JSON.parse(infoRaw) : null;
    const key = rawName.toLowerCase();
    if (info && !_serviceSnapshot.has(key)) {
      _serviceSnapshot.set(key, { name: info.Name, startType: info.StartType });
    }
    // Stop it (force, ignore errors)
    await ps(`Stop-Service -Name '${rawName}' -Force -ErrorAction SilentlyContinue`);
    // Disable so Windows can't restart it automatically
    await ps(`Set-Service -Name '${rawName}' -StartupType Disabled -ErrorAction SilentlyContinue`);
    // Belt-and-suspenders: also disable via sc.exe
    await execAsync(`sc.exe config "${rawName}" start= disabled`, { timeout: 5000 }).catch(() => {});
    return true;
  } catch { return false; }
}

async function _killProcess(name) {
  try {
    if (process.platform === 'win32') {
      await execAsync(`taskkill /f /im "${name}.exe" 2>nul`, { timeout: 5000 }).catch(() => {});
      await execAsync(`taskkill /f /im "${name}"     2>nul`, { timeout: 5000 }).catch(() => {});
    } else {
      await execAsync(`pkill -9 -f "${name}" 2>/dev/null || true`, { timeout: 5000 }).catch(() => {});
    }
    // Also disable any backing service
    const svcNames = PROCESS_TO_SERVICE[name.toLowerCase()] || [];
    for (const svc of svcNames) await _stopAndDisableService(svc);
  } catch {}
}

// ─── Restore all changes made during pre-check / exam ────────────────────────
async function restoreAll() {
  const jobs = [];

  // 1. Restore service startup types (Windows + macOS)
  for (const [, info] of _snap.services) {
    jobs.push(
      ps(`Set-Service -Name '${info.name}' -StartupType ${info.startType} -ErrorAction SilentlyContinue`).catch(() => {})
    );
  }
  _snap.services.clear();

  // 2. Restore firewall profiles
  if (_snap.firewallProfiles) {
    if (process.platform === 'win32') {
      for (const [name, wasEnabled] of Object.entries(_snap.firewallProfiles)) {
        jobs.push(
          ps(`Set-NetFirewallProfile -Name '${name}' -Enabled ${wasEnabled ? 'True' : 'False'} -ErrorAction SilentlyContinue`).catch(() => {})
        );
      }
    } else if (_snap.firewallProfiles.macOS === false) {
      // We turned macOS firewall ON — restore to OFF
      jobs.push(sh('/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off').catch(() => {}));
    }
    _snap.firewallProfiles = null;
  }

  // 3. Restore Windows Defender RT (only if we turned it ON from OFF)
  if (_snap.defenderRtDisabled === true && process.platform === 'win32') {
    jobs.push(
      ps('Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue').catch(() => {})
    );
    _snap.defenderRtDisabled = null;
  }

  await Promise.allSettled(jobs);
}

// Legacy alias — keeps existing callers working
const restoreServices = restoreAll;

async function checkProcesses(autoFix = true) {
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

  const found = [...new Set(BLACKLISTED.filter(b => list.some(p => p.replace('.exe','').includes(b))))];

  if (!found.length) return { pass: true, msg: 'No prohibited software running' };

  // ── Auto-fix: kill processes + disable backing services ──────────────────
  if (autoFix) {
    for (const name of found) await _killProcess(name);
    await new Promise(r => setTimeout(r, 1200)); // wait for OS to clean up

    // Re-scan after killing
    const recheck = await checkProcesses(false);
    if (recheck.pass) {
      const labels = found.map(b => PROCESS_INFO[b]?.name || b);
      return { pass: true, msg: `Auto-closed and disabled: ${labels.join(', ')}`, fixed: true, fixedItems: found };
    }
    // Some are still running — report the remainder
    return recheck;
  }

  const details = found.map(b => { const i = PROCESS_INFO[b]; return i ? `${i.name} (${b})` : b; });
  const firstInfo = found.map(b => PROCESS_INFO[b]).find(Boolean);
  const fix = firstInfo ? firstInfo.fix : 'Open Task Manager → End Task, or stop the service in Services.msc';
  return { pass: false, msg: `Prohibited software running: ${details.join(', ')}`, fix, violations: found };
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

async function checkRemoteSession(autoFix = true) {
  try {
    if (process.platform === 'win32') {
      const metricRaw = await ps(
        "Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class U32{[DllImport(\"user32.dll\")]public static extern int GetSystemMetrics(int n);}' -PassThru 2>$null | Out-Null; [U32]::GetSystemMetrics(0x1000)"
      );
      if (parseInt(metricRaw) === 0) return { pass: true, msg: 'No remote desktop session active' };

      // ── Auto-fix: logoff all remote/disconnected sessions ──────────────────
      if (autoFix) {
        await ps(`
          $myId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
          try {
            $lines = (query session 2>$null) -split '\`n' | Select-Object -Skip 1
            foreach ($line in $lines) {
              if ($line -match '\\s+(\\d+)\\s') {
                $id = [int]$Matches[1]
                if ($id -ne $myId -and $id -ne 0) {
                  logoff $id /server:localhost 2>$null | Out-Null
                }
              }
            }
          } catch {}
        `).catch(() => {});
        await new Promise(r => setTimeout(r, 1500));
        const recheck = await checkRemoteSession(false);
        if (recheck.pass) return { pass: true, msg: 'Remote sessions disconnected automatically', fixed: true };
        return recheck;
      }

      return { pass: false, msg: 'Active remote desktop session detected', fix: 'Disconnect all remote desktop / VNC sessions before starting' };
    } else {
      const { stdout } = await execAsync("who 2>/dev/null | grep -v 'console' | wc -l", { timeout: 5000 });
      const count = parseInt(stdout.trim());
      if (count > 0) {
        if (autoFix) {
          await execAsync("who 2>/dev/null | grep -v 'console' | awk '{print $2}' | xargs -I{} bash -c 'pkill -9 -t {} 2>/dev/null || true'", { timeout: 8000 }).catch(() => {});
          await new Promise(r => setTimeout(r, 1000));
          const recheck = await checkRemoteSession(false);
          if (recheck.pass) return { pass: true, msg: 'Remote sessions disconnected', fixed: true };
        }
        return { pass: false, msg: 'Remote session detected', fix: 'Disconnect all remote sessions' };
      }
    }
  } catch {}
  return { pass: true, msg: 'No remote desktop session active' };
}

const SERVICE_BLACKLIST = ['teamviewer','anydesk','ultravnc','ultraviewer','rustdesk','vmms','vboxservice','parsec','dwservice','supremo','screenconnect','logmeinremoteaccess'];

async function _getRunningBlacklistedServices() {
  if (process.platform !== 'win32') return [];
  try {
    const raw = await ps(
      'Get-Service | Where-Object {$_.Status -eq "Running"} | ' +
      'Select-Object Name | ConvertTo-Json -Compress'
    );
    const services = JSON.parse(raw || '[]');
    const arr = (Array.isArray(services) ? services : [services]).map(s => (s.Name || '').toLowerCase());
    return SERVICE_BLACKLIST.filter(b => arr.some(s => s.includes(b)));
  } catch { return []; }
}

async function checkServices(autoFix = true) {
  if (process.platform !== 'win32') return { pass: true, msg: 'N/A on this OS', na: true };

  const blocked = await _getRunningBlacklistedServices();
  if (!blocked.length) return { pass: true, msg: 'No blacklisted services running' };

  // ── Auto-fix: stop each service and disable it so Windows can't restart it ──
  if (autoFix) {
    for (const svcFragment of blocked) {
      // Find the exact service name from the running list
      try {
        const exactRaw = await ps(
          `Get-Service | Where-Object {$_.Status -eq 'Running' -and $_.Name -like '*${svcFragment}*'} | Select-Object -ExpandProperty Name`
        );
        const exact = exactRaw.trim();
        if (exact) await _stopAndDisableService(exact);
      } catch {}
    }

    await new Promise(r => setTimeout(r, 1500)); // wait for stops to complete

    // Re-scan
    const stillBlocked = await _getRunningBlacklistedServices();
    if (!stillBlocked.length) {
      const labels = blocked.map(b => {
        const i = PROCESS_INFO[b] || PROCESS_INFO[b + 'service'];
        return i ? i.name : b;
      });
      return { pass: true, msg: `Auto-stopped and disabled: ${labels.join(', ')}`, fixed: true, fixedItems: blocked };
    }

    return {
      pass: false,
      msg:  `Could not stop services: ${stillBlocked.join(', ')}`,
      fix:  'Run Services.msc as Administrator → find the service → Stop and set Startup Type to Disabled',
      violations: stillBlocked,
    };
  }

  return {
    pass: false,
    msg:  `Remote service running: ${blocked.join(', ')}`,
    fix:  'Stop the service via Services.msc and set Startup Type to Disabled',
    violations: blocked,
  };
}

// ─── Run all ──────────────────────────────────────────────────────────────────
// config: { antivirus, firewall, processes, services, vm, remote } — false = skip
// config.autoFix (default true): attempt to auto-fix each failing check
async function runAll(config = {}) {
  const on      = key => config[key] !== false;
  const autoFix = config.autoFix !== false;
  const NA = { pass: true, msg: 'Skipped by exam settings', na: true, skipped: true };

  // Services + processes first (sequential, services before processes)
  let services = NA, processes = NA;
  if (on('services'))  services  = await checkServices(autoFix).catch(e  => ({ pass: false, msg: e.message }));
  if (on('processes')) processes = await checkProcesses(autoFix).catch(e => ({ pass: false, msg: e.message }));

  // Remaining checks in parallel (each auto-fixes independently)
  const [av, fw, vm, remote] = await Promise.allSettled([
    on('antivirus') ? checkAntivirus(autoFix)      : Promise.resolve(NA),
    on('firewall')  ? checkFirewall(autoFix)       : Promise.resolve(NA),
    on('vm')        ? checkVirtualMachine()        : Promise.resolve(NA),
    on('remote')    ? checkRemoteSession(autoFix)  : Promise.resolve(NA),
  ]);
  const r = x => x.status === 'fulfilled' ? x.value : { pass: false, msg: x.reason?.message || 'Check failed' };

  return {
    platform:       process.platform,
    timestamp:      Date.now(),
    antivirus:      r(av),
    firewall:       r(fw),
    processes,
    virtualMachine: r(vm),
    remoteSession:  r(remote),
    services,
  };
}

// ─── Watchdog: re-run service+process checks during exam ─────────────────────
// Call startWatchdog() after exam starts, stopWatchdog() on exam end
let _watchdogTimer = null;

function startWatchdog(onViolationCb) {
  if (_watchdogTimer) return;
  _watchdogTimer = setInterval(async () => {
    try {
      // Re-check and auto-fix services and processes silently
      const svcResult  = await checkServices(true);
      const procResult = await checkProcesses(true);

      // If something was found (even if auto-fixed), notify the proctor
      if (svcResult.fixed || !svcResult.pass) {
        onViolationCb?.({ type: 'service_violation', severity: 'critical', message: svcResult.msg });
      }
      if (procResult.fixed || !procResult.pass) {
        onViolationCb?.({ type: 'process_violation', severity: 'critical', message: procResult.msg });
      }
    } catch {}
  }, 30000); // every 30 seconds
}

function stopWatchdog() {
  if (_watchdogTimer) { clearInterval(_watchdogTimer); _watchdogTimer = null; }
}

module.exports = { runAll, restoreAll, restoreServices, startWatchdog, stopWatchdog, checkProcesses, BLACKLISTED };
