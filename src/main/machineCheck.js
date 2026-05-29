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
  // ── Remote desktop / control ─────────────────────────────────────────────
  'teamviewer','tv_w32','tv_x64','teamviewer_service',
  'anydesk',
  'ammyyadmin','aa_v3',
  'logmein','logmeinremoteaccess',
  'remoting_host',                          // Chrome Remote Desktop
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

  // ── Video conferencing / screen sharing (screen-share loophole) ───────────
  'teams','ms-teams','msteams',             // Microsoft Teams
  'zoom','zoomautoupdater',                 // Zoom
  'skype','skypeapp',                       // Skype
  'discord',                                // Discord
  'slack',                                  // Slack
  'webex','webexmta','ciscowebexstart',     // Cisco WebEx
  'gotomeeting','g2mcomm','g2mlauncher',   // GoToMeeting
  'lync',                                   // MS Lync (old Teams)
  'whatsapp',                               // WhatsApp Desktop
  'telegram',                               // Telegram Desktop
  // 'signal' → BLACKLISTED_EXACT (would match 'signalr')
  'facetime',                               // macOS FaceTime
  'googlemeet',                             // Google Meet desktop
  'whereby',                                // Whereby
  // 'wire' → BLACKLISTED_EXACT (would match WireGuard VPN)

  // ── Screen capture tools ─────────────────────────────────────────────────
  'obs64','obs32',              // 'obs' alone is in BLACKLISTED_EXACT (exact match only)
  'xsplit','xsplitbroadcaster',
  'streamlabs',
  'bandicam',
  'camtasia',
  'fraps',
  'sharex',
  'snagit32','snagit64','snagiteditor',
  'lightshot',
  'greenshot',
  'screenpresso',

  // Browsers removed from auto-kill list — Edge/Arc are system processes that
  // resist killing. Instead, checkBrowsers() detects them and asks user to close.

  // ── RMM / endpoint management tools (can be used for remote access) ──────
  // NinjaRMM
  'ninjarmm','ninjaone','ninjapsfacade',
  // ConnectWise Automate (LabTech)
  'ltsvc','ltagent','ltservice','labtech',
  // Kaseya VSA
  'agentmon','kawebsvc','kaseyaagent',
  // Datto RMM (Autotask Endpoint Management) — 'datto' → BLACKLISTED_EXACT
  'aemtray','aemcore',
  // N-able (SolarWinds MSP)
  'nableservices','ncentral','takecont',
  // ManageEngine Desktop Central
  'desktopcentral','dcagentservice',
  // Atera
  'atera','ateraagent',
  // Pulseway
  'pulseway',
  // Syncro / RepairShopr
  'syncro','kabuto',
  // PDQ Deploy / Inventory
  'pdqdeploy','pdqinventory',
  // SolarWinds Agent (swi- is a prefix, not a full name — less false-positive risk)
  'solarwinds',
  // Continuum / Barracuda
  'continuum','itsplatform',
  // ITarian / Comodo
  'comodoremotecontrol','crm_service',
  // LogMeIn Central
  'logmeinrescue','rescuedesktop',
  // GoTo Resolve (formerly GoToAssist)
  'goto','gotoassist','gotoresolve',

  // ── Virtual machines ─────────────────────────────────────────────────────
  'vmware','vmwaretray','vmwareuser','vmware-vmx',
  'virtualbox','vboxservice','vboxtray',
  'parallels','prl_client_app',
  'qemu-system',
  'vmwp','vmms',
];

// More precise matching for short/ambiguous names — use exact process-name match
// rather than substring to prevent false positives on legitimate processes:
//   'arc'    would match Intel GPU driver 'arcep.exe'
//   'wire'   would match 'wireguard.exe' (VPN)
//   'goto'   would match unrelated paths containing 'goto'
//   'signal' would match 'signalr' helper processes
//   'obs'    would match 'obshost.exe' (Microsoft OneBackup)
//   'datto'  would match vendor agent names with 'datto' in path
// These short entries use full exact match (checked separately in checkProcesses).
const BLACKLISTED_EXACT = new Set([
  // 'arc' REMOVED — Intel Arc GPU driver installs Arc.exe (Intel Arc Control monitoring tool).
  // This is a legitimate GPU system process, not the Arc browser. Flagging it causes false
  // positives on machines with Intel Arc GPUs and the process can't be killed without
  // breaking GPU functionality.
  'wire', 'obs', 'signal', 'datto', 'goto',
]);

// ─── Friendly display names + stop instructions ───────────────────────────────
const PROCESS_INFO = {
  'vmms':           { name: 'Hyper-V Virtual Machine Management', fix: 'Open Services.msc → find "Hyper-V Virtual Machine Management" → right-click → Stop. Or run: net stop vmms' },
  'vmwp':           { name: 'Hyper-V VM Worker Process',          fix: 'Stop the Hyper-V Virtual Machine Management service: net stop vmms' },
  'vboxservice':    { name: 'VirtualBox Service',                  fix: 'Stop VirtualBox service: net stop VBoxService, or open Services.msc → "VirtualBox Guest Additions" → Stop' },
  'vboxtray':       { name: 'VirtualBox System Tray',             fix: 'Close VirtualBox and stop the VBoxService in Services.msc' },
  'vmwaretray':     { name: 'VMware Tray Process',                fix: 'Exit VMware Workstation completely' },
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
  // Must escape " → \" so cmd.exe doesn't break the outer double-quoted -Command string.
  // Without this, any command containing "Running" or "user32.dll" etc. silently fails.
  const safe = cmd.replace(/"/g, '\\"');
  const { stdout } = await execAsync(
    `powershell -NoProfile -NonInteractive -Command "${safe}"`,
    { timeout: 12000 }
  );
  return stdout.trim();
}

// Multi-line PS scripts: base64 -EncodedCommand bypasses cmd.exe newline-splitting
function psBig(script) {
  const b64 = Buffer.from(script, 'utf16le').toString('base64');
  return execAsync(`powershell -NoProfile -NonInteractive -EncodedCommand ${b64}`, { timeout: 20000 });
}

async function sh(cmd) {
  const { stdout } = await execAsync(cmd, { timeout: 10000 });
  return stdout.trim();
}

// ─── Individual checks ────────────────────────────────────────────────────────

// ─── Admin rights check ───────────────────────────────────────────────────────
async function checkIsAdmin() {
  if (process.platform !== 'win32') return { pass: true, msg: 'N/A on this OS', na: true };
  try {
    // net session requires admin; exits 0 if admin, non-zero if not
    await execAsync('net session >nul 2>&1', { timeout: 5000 });
    return { pass: true, msg: 'Running with administrator privileges' };
  } catch {
    return {
      pass: false,
      msg:  'Not running as Administrator',
      fix:  'Right-click "Alaric Secure Browser" → Run as administrator. Without admin rights the app cannot stop services or disconnect monitors.',
    };
  }
}

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
        // productState bits 12-15 = 1 means enabled/active; only flag if actually active
        if (((state >> 12) & 0xF) === 1) { thirdPartyActive = p.displayName; break; }
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

// ─── Browser detection (detect only — no auto-kill) ─────────────────────────
// Edge is a system-integrated browser on Windows 11 that resists force-kill.
// Arc.exe is the Intel Arc GPU driver. Neither should be auto-killed.
// We just detect and ask the user to close browsers manually.
const BROWSER_NAMES = [
  'msedge','microsoftedge','chrome','googlechrome',
  'firefox','firefoxdeveloperedi','opera','brave',
  'safari','vivaldi','iexplore','arc',
];

async function checkBrowsers() {
  try {
    let list = [];
    if (process.platform === 'win32') {
      const { stdout } = await execAsync('tasklist /fo csv /nh', { timeout: 8000 });
      list = stdout.split('\n')
        .map(l => l.replace(/"/g,'').toLowerCase().split(',')[0].replace('.exe','').trim())
        .filter(Boolean);
    } else {
      const { stdout } = await execAsync('ps -ax -o comm=', { timeout: 8000 });
      list = stdout.split('\n')
        .map(l => require('path').basename(l.trim()).toLowerCase().replace('.exe',''))
        .filter(Boolean);
    }
    const found = [...new Set(BROWSER_NAMES.filter(b => list.some(p => p === b || p.startsWith(b))))];
    if (!found.length) return { pass: true, msg: 'No browsers open' };
    return {
      pass: false,
      msg:  `Browser open: ${found.join(', ')}`,
      fix:  'Close all browser windows, then click Re-run Checks',
    };
  } catch { return { pass: true, msg: 'Browser check skipped', na: true }; }
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
  // Browsers — disable update service so browser can't auto-restart
  'msedge':          ['edgeupdate', 'edgeupdatem'],
  'microsoftedge':   ['edgeupdate', 'edgeupdatem'],
  'chrome':          ['GoogleChromeElevationService'],
  // RMM agents with watchdog services — must disable service or process restarts immediately
  'ninjarmm':        ['NinjaRMMAgent', 'ninjarmm', 'NinjaRMM'],
  'ninjaone':        ['NinjaRMMAgent', 'ninjarmm'],
  'ninjapsfacade':   ['NinjaRMMAgent'],
  'ltsvc':           ['LTService', 'LTSvcMon'],
  'ltagent':         ['LTService', 'LTSvcMon'],
  'agentmon':        ['KaseyaAgent'],
  'aemtray':         ['AEMAgent'],
  'ateraagent':      ['AteraAgent'],
  'pulseway':        ['Pulseway'],
  'splashtop':       ['SplashtopService', 'SplashtopStreamingService'],
};

async function _stopAndDisableService(rawName) {
  if (process.platform !== 'win32') return false;
  try {
    // Save original start type
    const infoRaw = await ps(
      `$s=Get-Service -Name '${rawName}' -ErrorAction SilentlyContinue;` +
      `if($s){[PSCustomObject]@{Name=$s.Name;StartType=$s.StartType.ToString();Status=$s.Status.ToString()}|ConvertTo-Json -Compress}`
    );
    const info = infoRaw ? JSON.parse(infoRaw) : null;
    const key  = rawName.toLowerCase();
    if (info && !_serviceSnapshot.has(key)) {
      _serviceSnapshot.set(key, { name: info.Name, startType: info.StartType });
    }

    // DISABLE first so the service can't auto-restart while we're stopping it
    await execAsync(`sc.exe config "${rawName}" start= disabled 2>nul`, { timeout: 5000 }).catch(() => {});
    await ps(`Set-Service -Name '${rawName}' -StartupType Disabled -ErrorAction SilentlyContinue`).catch(() => {});

    // Now stop via multiple methods — some RMM agents only respond to sc.exe / net stop
    await execAsync(`sc.exe stop "${rawName}" 2>nul`, { timeout: 8000 }).catch(() => {});
    await execAsync(`net stop "${rawName}" /y 2>nul`, { timeout: 8000 }).catch(() => {});
    await ps(`Stop-Service -Name '${rawName}' -Force -ErrorAction SilentlyContinue`).catch(() => {});

    // Kill any process running under this service name as an extra measure
    await execAsync(`taskkill /f /fi "SERVICES eq ${rawName}" 2>nul`, { timeout: 5000 }).catch(() => {});

    return true;
  } catch { return false; }
}

async function _killProcess(name) {
  try {
    if (process.platform === 'win32') {
      // STEP 1: Disable backing service FIRST — cuts the watchdog before we kill the process.
      // If we kill the process first, the service sees it died and restarts it immediately.
      const svcNames = PROCESS_TO_SERVICE[name.toLowerCase()] || [];
      for (const svc of svcNames) {
        await execAsync(`sc.exe config "${svc}" start= disabled 2>nul`, { timeout: 4000 }).catch(() => {});
        await execAsync(`sc.exe stop "${svc}" 2>nul`, { timeout: 6000 }).catch(() => {});
        await ps(`Set-Service -Name '${svc}' -StartupType Disabled -ErrorAction SilentlyContinue; Stop-Service -Name '${svc}' -Force -ErrorAction SilentlyContinue`).catch(() => {});
      }

      // STEP 2: Kill via WMI Terminate() — most forceful, bypasses process protections
      // WMI Win32_Process.Terminate() works even when taskkill and Stop-Process fail
      await psBig(`
$n = '${name}'
# WMI Terminate — calls TerminateProcess() via kernel, most reliable method
Get-WmiObject Win32_Process | Where-Object {
  $_.Name -like "*$n*"
} | ForEach-Object {
  try { $_.Terminate() | Out-Null } catch {}
}
# Also via Stop-Process as secondary
Stop-Process -Name $n -Force -ErrorAction SilentlyContinue
`).catch(() => {});

      // wmic command-line fallback (different execution path from PowerShell WMI)
      await execAsync(`wmic process where "name like '%${name}%'" call terminate 2>nul`, { timeout: 8000 }).catch(() => {});
      // taskkill with /t (tree) as final fallback
      await execAsync(`taskkill /f /t /im ${name}.exe 2>nul`, { timeout: 5000 }).catch(() => {});
    } else {
      await execAsync(`pkill -9 -f "${name}" 2>/dev/null || true`, { timeout: 5000 }).catch(() => {});
    }
  } catch {}
}

// ─── Restore all changes made during pre-check / exam ────────────────────────
async function restoreAll() {
  // Snapshot ALL state and clear BEFORE any awaits — prevents the watchdog
  // from writing to _snap between our awaits and corrupting the restore
  const services          = new Map(_snap.services);   _snap.services.clear();
  const firewallProfiles  = _snap.firewallProfiles;    _snap.firewallProfiles   = null;
  const defenderRtDisabled = _snap.defenderRtDisabled; _snap.defenderRtDisabled = null;

  const jobs = [];

  // 1. Restore service startup types
  for (const [, info] of services) {
    if (info?.name && info?.startType) {
      jobs.push(
        ps(`Set-Service -Name '${info.name}' -StartupType ${info.startType} -ErrorAction SilentlyContinue`).catch(() => {})
      );
    }
  }

  // 2. Restore firewall profiles
  if (firewallProfiles) {
    if (process.platform === 'win32') {
      for (const [name, wasEnabled] of Object.entries(firewallProfiles)) {
        jobs.push(
          ps(`Set-NetFirewallProfile -Name '${name}' -Enabled ${wasEnabled ? 'True' : 'False'} -ErrorAction SilentlyContinue`).catch(() => {})
        );
      }
    } else if (firewallProfiles.macOS === false) {
      jobs.push(sh('/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off').catch(() => {}));
    }
  }

  // 3. Restore Windows Defender RT (only if we turned it ON from OFF)
  if (defenderRtDisabled === true && process.platform === 'win32') {
    jobs.push(
      ps('Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue').catch(() => {})
    );
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

  // Substring match for most entries; exact match for ambiguous short names
  const found = [...new Set([
    ...BLACKLISTED.filter(b => list.some(p => p.replace('.exe','').includes(b))),
    ...([...BLACKLISTED_EXACT].filter(b => list.some(p => p.replace('.exe','') === b))),
  ])];

  if (!found.length) return { pass: true, msg: 'No prohibited software running' };

  // ── Auto-fix: kill processes + disable backing services ──────────────────
  if (autoFix) {
    for (const name of found) await _killProcess(name);
    await new Promise(r => setTimeout(r, 2000));
    // Second kill pass — catches any process that was still starting when first pass ran
    for (const name of found) await _killProcess(name);
    await new Promise(r => setTimeout(r, 2000)); // total 4s wait

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
        // psBig (base64 -EncodedCommand) avoids cmd.exe newline-splitting bug
        // that made the previous ps() multi-line call completely inoperative
        await psBig(`
$mySessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
try {
  $lines = (& query session 2>$null) -split '\`n' | Select-Object -Skip 1
  foreach ($line in $lines) {
    if ($line -match '\\s+(\\d+)\\s') {
      $sessionId = [int]$Matches[1]
      if ($sessionId -ne $mySessionId -and $sessionId -ne 0) {
        logoff $sessionId /server:localhost 2>$null | Out-Null
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

const SERVICE_BLACKLIST = [
  // Remote access / screen share
  'teamviewer','anydesk','ultravnc','ultraviewer','rustdesk','vmms',
  'vboxservice','parsec','dwservice','supremo','screenconnect','logmeinremoteaccess',
  'splashtop','radmin','getscreen','ammyyadmin',
  // RMM tools — caught by name even if process is renamed
  'ltsvc','ltagent','labtech',          // ConnectWise Automate
  'agentmon','kawebsvc',                // Kaseya
  'aemtray','aemcore',                  // Datto RMM
  'nableservices','ncentral',           // N-able
  'desktopcentral','dcagentservice',    // ManageEngine
  'ateraagent',                         // Atera
  'pulseway',                           // Pulseway
  'syncro',                             // Syncro
  // Windows built-in remote services (disabled by disableRemoteProtocols but also checked here)
  'termservice','umrdpservice','winrm','remoteregistry','sshd',
];

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
        // Split by newline — multiple services may match one fragment (e.g. splashtop)
        const names = exactRaw.trim().split(/\r?\n/).map(s => s.trim()).filter(Boolean);
        for (const name of names) await _stopAndDisableService(name);
      } catch {}
    }

    await new Promise(r => setTimeout(r, 3000)); // wait for stops to complete (some services take 2-3s)

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

  // Admin rights check first — determines whether auto-fix can work at all
  const adminResult = await checkIsAdmin().catch(() => ({ pass: false, msg: 'Could not verify admin rights' }));

  // Services + processes first (sequential, services before processes)
  let services = NA, processes = NA;
  if (on('services'))  services  = await checkServices(autoFix).catch(e  => ({ pass: false, msg: e.message }));
  if (on('processes')) processes = await checkProcesses(autoFix).catch(e => ({ pass: false, msg: e.message }));

  // Remaining checks in parallel
  const [av, fw, vm, remote, browsers] = await Promise.allSettled([
    on('antivirus') ? checkAntivirus(autoFix)      : Promise.resolve(NA),
    on('firewall')  ? checkFirewall(autoFix)       : Promise.resolve(NA),
    on('vm')        ? checkVirtualMachine()        : Promise.resolve(NA),
    on('remote')    ? checkRemoteSession(autoFix)  : Promise.resolve(NA),
    checkBrowsers(),                               // always run browser check
  ]);
  const r = x => x.status === 'fulfilled' ? x.value : { pass: false, msg: x.reason?.message || 'Check failed' };

  return {
    platform:       process.platform,
    timestamp:      Date.now(),
    adminRights:    adminResult,
    antivirus:      r(av),
    firewall:       r(fw),
    processes,
    virtualMachine: r(vm),
    remoteSession:  r(remote),
    services,
    browsers:       r(browsers),
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
