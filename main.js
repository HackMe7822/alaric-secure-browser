'use strict';
const { app, BrowserWindow, ipcMain, screen, shell, dialog, systemPreferences } = require('electron');
const path = require('path');
const os   = require('os');
const fs   = require('fs');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const { autoUpdater } = require('electron-updater');

const machineCheck    = require('./src/main/machineCheck');
const processMonitor  = require('./src/main/processMonitor');
const keyboardLock    = require('./src/main/keyboardLock');
const networkMonitor  = require('./src/main/networkMonitor');
const usbMonitor      = require('./src/main/usbMonitor');

// ─── Single instance ──────────────────────────────────────────────────────────
if (!app.requestSingleInstanceLock()) { app.quit(); process.exit(0); }

// Windows: register as default protocol handler for alaricexam://
if (process.platform === 'win32') {
  app.setAsDefaultProtocolClient('alaricexam');
}

let launcherWin = null;
let examWin     = null;
let lockedWin   = null;
let isExamLive  = false;

// ─── Lock file ────────────────────────────────────────────────────────────────
const LOCK_FILE = path.join(app.getPath('userData'), 'exam-lock.json');

function readLockData() {
  try { return JSON.parse(fs.readFileSync(LOCK_FILE, 'utf8')); } catch { return null; }
}
function writeLockData(data) {
  fs.mkdirSync(path.dirname(LOCK_FILE), { recursive: true });
  fs.writeFileSync(LOCK_FILE, JSON.stringify({ ...data, lockedAt: new Date().toISOString() }));
}
function clearLockData() { try { fs.unlinkSync(LOCK_FILE); } catch {} }

// ─── Auto-start (survive reboot) ─────────────────────────────────────────────
async function addAutoStart() {
  const exe = process.execPath;
  if (process.platform === 'win32') {
    await execAsync(
      `reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v AlaricSecureBrowser /t REG_SZ /d "\\"${exe}\\"" /f`,
      { timeout: 6000 }
    ).catch(() => {});
  } else if (process.platform === 'darwin') {
    const plistDir  = path.join(os.homedir(), 'Library', 'LaunchAgents');
    const plistPath = path.join(plistDir, 'com.alaric.securebrowser.locked.plist');
    fs.mkdirSync(plistDir, { recursive: true });
    fs.writeFileSync(plistPath,
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n` +
      `<plist version="1.0"><dict>\n` +
      `  <key>Label</key><string>com.alaric.securebrowser.locked</string>\n` +
      `  <key>ProgramArguments</key><array><string>${exe}</string></array>\n` +
      `  <key>RunAtLoad</key><true/>\n` +
      `  <key>KeepAlive</key><false/>\n` +
      `</dict></plist>`
    );
    await execAsync(`launchctl load "${plistPath}"`, { timeout: 5000 }).catch(() => {});
  }
}

async function clearAutoStart() {
  if (process.platform === 'win32') {
    await execAsync(
      `reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v AlaricSecureBrowser /f`,
      { timeout: 5000 }
    ).catch(() => {});
  } else if (process.platform === 'darwin') {
    const plistPath = path.join(os.homedir(), 'Library', 'LaunchAgents', 'com.alaric.securebrowser.locked.plist');
    await execAsync(`launchctl unload "${plistPath}" 2>/dev/null || true`, { timeout: 5000 }).catch(() => {});
    try { fs.unlinkSync(plistPath); } catch {}
  }
}

// ─── Release machine — cleanup everything ────────────────────────────────────
async function runRelease() {
  await clearAutoStart();
  clearLockData();

  // Restore ALL changes: services startup types, firewall profiles, Windows Defender
  await machineCheck.restoreAll().catch(() => {});
  // Remove Windows Firewall / macOS pfctl rules — must be called here too
  // because if the machine rebooted while locked, networkMonitor was never started
  // in this session so the firewall rules from the exam session still survive
  await networkMonitor.restore().catch(() => {});

  // Restore display mode (if we switched to single-display, restore extend)
  if (_displayWasExtended && process.platform === 'win32') {
    await execAsync('DisplaySwitch.exe /extend', { timeout: 8000 }).catch(() => {});
    _displayWasExtended = false;
  }

  // Delete local Electron user data (cache, logs, etc.)
  const userData = app.getPath('userData');
  for (const sub of ['Cache', 'GPUCache', 'Logs', 'blob_storage', 'Code Cache']) {
    const p = path.join(userData, sub);
    await execAsync(
      process.platform === 'win32'
        ? `if exist "${p}" rd /s /q "${p}" 2>nul`
        : `rm -rf "${p}" 2>/dev/null || true`,
      { timeout: 8000 }
    ).catch(() => {});
  }

  // Platform uninstaller
  if (process.platform === 'win32') {
    const uninstaller = path.join(path.dirname(process.execPath), 'Uninstall AlaricSecureBrowser.exe');
    if (fs.existsSync(uninstaller)) {
      // Launch NSIS /S uninstaller then quit. NSIS terminates running instances
      // before removing files, so we must quit FIRST to release the exe file lock.
      // Do NOT call both exec() and app.quit() simultaneously — that causes a
      // file-lock race where the uninstaller can't delete the exe while Electron
      // is still tearing down.
      app._quitting = true;
      app.quit();
      // Small delay so Electron releases file locks before uninstaller deletes
      setTimeout(() => exec(`"${uninstaller}" /S`), 800);
      return; // don't fall through to app.quit() below
    } else {
      // Fallback: schedule deletion after app exits
      exec(`ping 127.0.0.1 -n 3 > nul && rd /s /q "${path.dirname(process.execPath)}"`);
    }
  } else if (process.platform === 'darwin') {
    const appBundle = path.resolve(process.execPath, '..', '..', '..');
    exec(`sleep 2 && rm -rf "${appBundle}" && rm -rf "${userData}"`);
  }

  app._quitting = true;
  app.quit();
}

// ─── macOS permission prompts ─────────────────────────────────────────────────
async function setupMacPermissions() {
  if (process.platform !== 'darwin') return;

  // Accessibility (keyboard lock, window management)
  const trusted = systemPreferences.isTrustedAccessibilityClient(false);
  if (!trusted) {
    const { response } = await dialog.showMessageBox({
      type:      'warning',
      title:     'Accessibility Permission Required',
      message:   'Alaric Secure Browser needs Accessibility access',
      detail:    'This is required to enforce keyboard security and window focus during exams.\n\n' +
                 'Click "Open Settings" → find "Alaric Secure Browser" → enable the toggle.',
      buttons:   ['Open Settings', 'Later'],
      defaultId: 0,
    });
    if (response === 0) {
      systemPreferences.isTrustedAccessibilityClient(true); // triggers macOS prompt
      shell.openExternal('x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility');
    }
  }

  // Screen Recording
  const screenStatus = systemPreferences.getMediaAccessStatus('screen');
  if (screenStatus !== 'granted') {
    const { response } = await dialog.showMessageBox({
      type:      'info',
      title:     'Screen Recording Permission',
      message:   'Alaric Secure Browser needs Screen Recording access',
      detail:    'Required for proctoring screen capture during exams.\n\n' +
                 'Click "Open Settings" → find "Alaric Secure Browser" → enable the toggle, then restart the app.',
      buttons:   ['Open Settings', 'Later'],
      defaultId: 0,
    });
    if (response === 0) {
      shell.openExternal('x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture');
    }
  }

  // Microphone + Camera (these trigger native macOS prompt automatically)
  if (systemPreferences.getMediaAccessStatus('microphone') !== 'granted')
    await systemPreferences.askForMediaAccess('microphone').catch(() => {});
  if (systemPreferences.getMediaAccessStatus('camera') !== 'granted')
    await systemPreferences.askForMediaAccess('camera').catch(() => {});
}

// ─── Auto-updater ────────────────────────────────────────────────────────────
autoUpdater.autoDownload         = true;   // download automatically when available
autoUpdater.autoInstallOnAppQuit = false;  // we install immediately after download

function sendToLauncher(channel, data) {
  if (launcherWin && !launcherWin.isDestroyed()) {
    launcherWin.webContents.send(channel, data);
  }
}

function setupAutoUpdater() {
  autoUpdater.on('checking-for-update', () => {
    sendToLauncher('update-status', { phase: 'checking', version: app.getVersion() });
  });

  autoUpdater.on('update-available', info => {
    sendToLauncher('update-status', { phase: 'available', version: info.version, current: app.getVersion() });
  });

  autoUpdater.on('update-not-available', () => {
    sendToLauncher('update-status', { phase: 'current', version: app.getVersion() });
  });

  autoUpdater.on('download-progress', p => {
    sendToLauncher('update-status', {
      phase:       'downloading',
      percent:     Math.round(p.percent),
      transferred: p.transferred,
      total:       p.total,
      speed:       p.bytesPerSecond,
      version:     app.getVersion(),
    });
  });

  autoUpdater.on('update-downloaded', info => {
    if (isExamLive) {
      // Never interrupt a running exam — defer update until after exam completes
      sendToLauncher('update-status', { phase: 'pending_restart', version: info.version });
      console.log('[updater] Update deferred — exam in progress');
      return;
    }
    sendToLauncher('update-status', { phase: 'installing', version: info.version });
    // Silent install: isSilent=true, forceRunAfter=true (app relaunches after install)
    setTimeout(() => autoUpdater.quitAndInstall(true, true), 1500);
  });

  autoUpdater.on('error', err => {
    sendToLauncher('update-status', { phase: 'error', message: err.message, version: app.getVersion() });
  });

  // Check immediately — send 'checking' first so launcher can block Step 1 right away
  sendToLauncher('update-status', { phase: 'checking', version: app.getVersion() });
  autoUpdater.checkForUpdates().catch(err => {
    sendToLauncher('update-status', { phase: 'error', message: err.message, version: app.getVersion() });
  });
}

// ─── Deep link helper ─────────────────────────────────────────────────────────
function extractDeepLink(argv) {
  return (argv || []).find(a => a.startsWith('alaricexam://')) || null;
}

function sendDeepLink(url) {
  if (!launcherWin || launcherWin.isDestroyed()) return;
  launcherWin.webContents.send('protocol-url', url);
  launcherWin.show();
  launcherWin.focus();
}

// ─── Display management ───────────────────────────────────────────────────────
let _displayAddedHandler = null;
let _displayWasExtended  = false; // true if machine had multiple monitors before we switched

async function switchToInternalDisplay() {
  if (process.platform !== 'win32') return false;
  if (!_displayWasExtended) {
    _displayWasExtended = screen.getAllDisplays().length > 1;
  }

  // Helper: poll until displayCount drops to 1 or timeout (8s)
  const waitForSingleDisplay = async () => {
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 600));
      if (screen.getAllDisplays().length <= 1) return true;
    }
    return screen.getAllDisplays().length <= 1;
  };

  try {
    // Primary method: DisplaySwitch.exe /internal (built-in on all Windows)
    await execAsync('DisplaySwitch.exe /internal', { timeout: 10000 });
    const ok = await waitForSingleDisplay();
    if (ok) return true;
  } catch {}

  try {
    // Fallback: SetDisplayConfig Win32 API — SDC_TOPOLOGY_INTERNAL(1)|SDC_APPLY(0x80)=0x81
    await execAsync(
      `powershell -NoProfile -NonInteractive -Command "` +
      `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;` +
      `public class D{[DllImport(\\"user32.dll\\")]public static extern int SetDisplayConfig(uint p,IntPtr pa,uint m,IntPtr ma,uint f);}' ` +
      `-PassThru 2>$null | Out-Null; [D]::SetDisplayConfig(0,[IntPtr]::Zero,0,[IntPtr]::Zero,0x81)"`,
      { timeout: 10000 }
    );
    const ok = await waitForSingleDisplay();
    if (ok) return true;
  } catch {}

  return false;
}

function startDisplayWatcher() {
  if (_displayAddedHandler) return; // already watching
  _displayAddedHandler = async () => {
    if (!isExamLive) return;
    // A monitor was connected mid-exam — auto-disconnect it
    const fixed = await switchToInternalDisplay();
    if (examWin && !examWin.isDestroyed()) {
      examWin.webContents.send('security-event', {
        type:     'multi_monitor',
        message:  fixed
          ? 'External display connected mid-exam — auto-disconnected'
          : 'External display detected — please disconnect it to continue',
        severity: 'critical',
      });
    }
  };
  screen.on('display-added', _displayAddedHandler);
}

function stopDisplayWatcher() {
  if (_displayAddedHandler) {
    screen.off('display-added', _displayAddedHandler);
    _displayAddedHandler = null;
  }
}

// ─── Locked window (shown after exam until Release Machine is clicked) ────────
function createLockedWindow(lockData) {
  if (lockedWin && !lockedWin.isDestroyed()) { lockedWin.focus(); return; }
  lockedWin = new BrowserWindow({
    width:      900,
    height:     580,
    frame:      false,
    resizable:  false,
    maximizable:false,
    alwaysOnTop:true,
    skipTaskbar:false,
    backgroundColor: '#0f172a',
    webPreferences: {
      preload:          path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration:  false,
    },
    title: 'Alaric — Machine Locked',
  });
  lockedWin.setMenu(null);
  lockedWin.setAlwaysOnTop(true, 'screen-saver', 1);
  lockedWin.loadFile('src/renderer/locked.html');
  lockedWin.webContents.once('did-finish-load', () => {
    lockedWin.webContents.send('lock-data', lockData || {});
  });
  // Prevent closing — only Release Machine can exit
  lockedWin.on('close', e => {
    if (!app._quitting) e.preventDefault();
  });
}

// ─── Window creators ──────────────────────────────────────────────────────────
function createLauncher() {
  launcherWin = new BrowserWindow({
    width:       960,
    height:      700,
    minWidth:    800,
    minHeight:   600,
    resizable:   false,
    maximizable: false,
    frame:       true,
    backgroundColor: '#f1f5f9',
    webPreferences: {
      preload:          path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration:  false,
    },
    title: 'Alaric Secure Browser',
  });

  launcherWin.setMenu(null);
  launcherWin.loadFile('src/renderer/launcher.html');

  // Allow dev tools in development
  if (process.env.NODE_ENV === 'development') {
    launcherWin.webContents.openDevTools({ mode: 'detach' });
  }

  // Windows deep link: app was launched cold with the protocol URL in argv
  const coldLink = extractDeepLink(process.argv);
  if (coldLink) {
    launcherWin.webContents.once('did-finish-load', () => sendDeepLink(coldLink));
  }

  // Start auto-updater only in production (packaged) builds
  if (app.isPackaged) {
    launcherWin.webContents.once('did-finish-load', () => setupAutoUpdater());
  } else {
    // Dev mode: send "current" so the version badge still shows
    launcherWin.webContents.once('did-finish-load', () => {
      sendToLauncher('update-status', { phase: 'dev', version: app.getVersion() });
    });
  }

  // Prevent accidental close — ask confirmation
  launcherWin.on('close', e => {
    if (app._quitting) return;       // Allow during intentional quit
    e.preventDefault();
    dialog.showMessageBox(launcherWin, {
      type:    'question',
      buttons: ['Cancel', 'Exit'],
      defaultId: 0,
      title:   'Exit Alaric Secure Browser',
      message: 'Are you sure you want to exit?',
    }).then(({ response }) => {
      if (response === 1) {
        app._quitting = true;
        app.quit();
      }
    });
  });
}

function createExamWindow(examUrl) {
  const { bounds } = screen.getPrimaryDisplay();

  examWin = new BrowserWindow({
    x:      bounds.x,
    y:      bounds.y,
    width:  bounds.width,
    height: bounds.height,
    fullscreen: true,
    kiosk:  true,            // OS-level kiosk — no taskbar, no alt-F4
    frame:  false,
    backgroundColor: '#000',
    alwaysOnTop: true,
    skipTaskbar: true,       // Remove from taskbar / Dock
    webPreferences: {
      preload:           path.join(__dirname, 'preload.js'),
      contextIsolation:  true,
      nodeIntegration:   false,
      devTools:          false,    // Disabled in exam mode
    },
    title: 'Alaric Secure Exam',
  });

  examWin.setMenu(null);
  examWin.setAlwaysOnTop(true, 'screen-saver', 1);

  // Block right-click
  examWin.webContents.on('context-menu', e => e.preventDefault());

  // Block dev tools keyboard shortcuts inside the page
  examWin.webContents.on('before-input-event', (_, input) => {
    const { key, control, meta, shift, alt } = input;
    if (key === 'F12') return;    // already blocked by kiosk but belt-and-suspenders
    if ((control || meta) && shift && ['i','j','c'].includes(key.toLowerCase())) {
      // swallow — devtools
    }
    // TEMP escape: Ctrl+Shift+Alt+Q — remove before production
    if (control && shift && alt && key.toLowerCase() === 'q') {
      app._quitting = true;
      app.quit();
    }
  });

  // Keep fullscreen enforced
  examWin.on('leave-full-screen', () => {
    if (isExamLive && examWin && !examWin.isDestroyed()) examWin.setFullScreen(true);
  });

  // Keep focus on exam window; log the focus loss as a tab_switch security event
  examWin.on('blur', () => {
    if (!isExamLive || !examWin || examWin.isDestroyed()) return;
    examWin.focus();
    examWin.webContents.send('security-event', {
      type: 'tab_switch',
      message: 'Window focus lost',
      severity: 'warning',
    });
  });

  examWin.loadURL(examUrl);
  isExamLive = true;

  examWin.on('closed', () => {
    examWin    = null;
    isExamLive = false;
    stopSecurity();
    machineCheck.stopWatchdog();
    stopDisplayWatcher();
    machineCheck.restoreAll().catch(() => {});
    const lockData = readLockData();
    if (lockData) {
      // Machine is locked — show locked window instead of quitting
      networkMonitor.restore().finally(() => createLockedWindow(lockData));
    } else {
      networkMonitor.restore().finally(() => app.quit());
    }
  });
}

// ─── Security lifecycle ───────────────────────────────────────────────────────
function startSecurity(examServerHost) {
  keyboardLock.start();

  const onViolation = (ev) => {
    // Forward to exam window so exam page can report via its WS
    if (examWin && !examWin.isDestroyed()) {
      examWin.webContents.send('security-event', ev);
    }
    // Re-focus exam window if it lost focus
    if (examWin && !examWin.isDestroyed() && ev.severity === 'critical') {
      examWin.focus();
      examWin.setAlwaysOnTop(true, 'screen-saver', 1);
    }
    console.warn('[security]', ev.type, ev.message);
  };

  processMonitor.start(onViolation);
  usbMonitor.start(onViolation);
  networkMonitor.start(examServerHost, onViolation);   // Async — non-blocking
}

function stopSecurity() {
  keyboardLock.stop();
  processMonitor.stop();
  usbMonitor.stop();
  networkMonitor.stop();
}

// ─── IPC handlers ─────────────────────────────────────────────────────────────
ipcMain.handle('run-machine-checks', (_, config) => machineCheck.runAll(config || {}));

ipcMain.handle('get-display-count', () => screen.getAllDisplays().length);

ipcMain.handle('check-remote-session', async () => {
  try {
    if (process.platform === 'win32') {
      const { stdout } = await execAsync(
        `powershell -NoProfile -Command "Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class U32{[DllImport(\\"user32.dll\\")]public static extern int GetSystemMetrics(int n);}' -PassThru 2>$null | Out-Null; [U32]::GetSystemMetrics(0x1000)"`,
        { timeout: 8000 }
      );
      return parseInt(stdout.trim()) !== 0;
    } else {
      const { stdout } = await execAsync("who 2>/dev/null | grep -v 'console' | wc -l", { timeout: 5000 });
      return parseInt(stdout.trim()) > 0;
    }
  } catch { return false; }
});

ipcMain.handle('get-machine-id', async () => {
  try {
    const { machineId } = require('node-machine-id');
    return await machineId();
  } catch { return 'unknown'; }
});

ipcMain.handle('open-external', (_, url) => shell.openExternal(url));

ipcMain.handle('get-app-version', () => app.getVersion());

// ── Machine lock / release ────────────────────────────────────────────────────
ipcMain.handle('lock-machine', async (_, data) => {
  writeLockData(data || {});
  await addAutoStart();
  return { ok: true };
});

ipcMain.handle('release-machine', async () => {
  await runRelease(); // also calls app.quit()
  return { ok: true };
});

// ── macOS permission status ───────────────────────────────────────────────────
ipcMain.handle('check-mac-permissions', () => {
  if (process.platform !== 'darwin') return { platform: 'win32', allGranted: true };
  const acc   = systemPreferences.isTrustedAccessibilityClient(false);
  const scr   = systemPreferences.getMediaAccessStatus('screen');
  const mic   = systemPreferences.getMediaAccessStatus('microphone');
  const cam   = systemPreferences.getMediaAccessStatus('camera');
  return {
    platform:       'darwin',
    accessibility:  acc,
    screenRecording:scr,
    microphone:     mic,
    camera:         cam,
    allGranted:     acc && scr === 'granted' && mic === 'granted' && cam === 'granted',
  };
});

ipcMain.handle('open-privacy-settings', (_, section) => {
  const urls = {
    accessibility:   'x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility',
    screenRecording: 'x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture',
    microphone:      'x-apple.systempreferences:com.apple.preference.security?Privacy_Microphone',
    camera:          'x-apple.systempreferences:com.apple.preference.security?Privacy_Camera',
  };
  shell.openExternal(urls[section] || urls.accessibility);
});

ipcMain.handle('request-media-access', async (_, type) => {
  if (process.platform !== 'darwin') return 'granted';
  return systemPreferences.askForMediaAccess(type).then(g => g ? 'granted' : 'denied').catch(() => 'denied');
});

ipcMain.handle('fix-multi-monitor', async () => {
  const ok = await switchToInternalDisplay();
  return { ok, displayCount: screen.getAllDisplays().length };
});

ipcMain.handle('generate-qr', async (_, url) => {
  try {
    const QRCode = require('qrcode');
    // Returns base64 data URL — no server, no CORS, works offline
    return await QRCode.toDataURL(url, { width: 220, margin: 2, color: { dark: '#1e293b', light: '#ffffff' } });
  } catch(e) { return null; }
});

ipcMain.handle('open-verify-window', (_, url) => {
  const win = new BrowserWindow({
    width:  500,
    height: 800,
    title:  'Identity Verification — Alaric',
    parent: launcherWin || undefined,
    modal:  false,
    webPreferences: { contextIsolation: true, nodeIntegration: false },
  });
  win.setMenu(null);
  win.loadURL(url);

  // Prevent Chrome-style "Leave site?" dialog when user clicks X
  // The page may have a beforeunload handler — bypass it so window closes cleanly
  win.webContents.on('will-prevent-unload', (event) => {
    event.preventDefault(); // allow close without dialog
  });
});

ipcMain.handle('restore-display', async () => {
  // Restore to extended/multi-monitor mode (undo switchToInternalDisplay)
  if (process.platform === 'win32') {
    await execAsync('DisplaySwitch.exe /extend', { timeout: 8000 }).catch(() => {});
    _displayWasExtended = false;
  }
  return { displayCount: screen.getAllDisplays().length };
});

ipcMain.handle('check-for-update', () => {
  if (app.isPackaged) autoUpdater.checkForUpdates().catch(() => {});
});

ipcMain.handle('close-exam', () => {
  if (examWin && !examWin.isDestroyed()) {
    isExamLive = false;
    examWin.destroy();
  }
});

ipcMain.handle('get-screen-source', async () => {
  try {
    const { desktopCapturer } = require('electron');
    const sources = await desktopCapturer.getSources({
      types: ['screen'],
      thumbnailSize: { width: 1, height: 1 },
    });
    return sources[0]?.id || null;
  } catch { return null; }
});

ipcMain.handle('start-exam', async (_, { examUrl, examServerHost }) => {
  startSecurity(examServerHost);
  machineCheck.startWatchdog((ev) => {
    if (examWin && !examWin.isDestroyed()) examWin.webContents.send('security-event', ev);
  });
  startDisplayWatcher(); // auto-disconnect any monitor plugged in mid-exam
  if (launcherWin) launcherWin.hide();
  createExamWindow(examUrl);
  return { success: true };
});

// ─── App lifecycle ────────────────────────────────────────────────────────────
app.whenReady().then(async () => {
  // NOTE: Admin elevation is handled by the exe manifest (requestedExecutionLevel:
  // requireAdministrator in package.json). Windows automatically prompts UAC when
  // launching the app — including when opened via alaricexam:// deep link.
  // We do NOT do a runtime relaunch here because that loses the deep link argv.
  // The pre-check in Step 2 shows a clear admin rights error if somehow not elevated.

  // Create window first — dialog.showMessageBox() requires a parent window on macOS
  const lockData = readLockData();
  if (lockData) {
    createLockedWindow(lockData);
  } else {
    createLauncher();
  }

  // macOS: request permissions AFTER window exists (dialogs need a parent window)
  if (process.platform === 'darwin') {
    setupMacPermissions().catch(e => console.warn('[permissions]', e.message));
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      const ld = readLockData();
      if (ld) createLockedWindow(ld); else createLauncher();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  app._quitting = true;
  stopSecurity();
});

// macOS deep link
app.on('open-url', (event, url) => {
  event.preventDefault();
  sendDeepLink(url);
});

// Second instance — focus existing window + handle Windows deep link
app.on('second-instance', (event, argv) => {
  if (launcherWin) { launcherWin.show(); launcherWin.focus(); }
  if (examWin)     { examWin.focus(); }
  const deepLink = extractDeepLink(argv);
  if (deepLink) sendDeepLink(deepLink);
});
