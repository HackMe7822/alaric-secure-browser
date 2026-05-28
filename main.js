'use strict';
const { app, BrowserWindow, ipcMain, screen, shell, dialog } = require('electron');
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

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
let isExamLive  = false;

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
    examWin  = null;
    isExamLive = false;
    stopSecurity();
    networkMonitor.restore().finally(() => app.quit());
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
ipcMain.handle('run-machine-checks', () => machineCheck.runAll());

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
  if (launcherWin) launcherWin.hide();
  createExamWindow(examUrl);
  return { success: true };
});

// ─── App lifecycle ────────────────────────────────────────────────────────────
app.whenReady().then(() => {
  createLauncher();

  // macOS: re-open on dock click
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createLauncher();
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
