const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('AlaricProctor', {
  // Identity
  isSecureBrowser: true,
  version: '1.0.0',
  platform: process.platform,

  // ── Launcher APIs ──────────────────────────────────────────
  runMachineChecks:  (cfg)           => ipcRenderer.invoke('run-machine-checks', cfg),
  getDisplayCount:   ()              => ipcRenderer.invoke('get-display-count'),
  checkRemoteSession:()              => ipcRenderer.invoke('check-remote-session'),
  getMachineId:      ()              => ipcRenderer.invoke('get-machine-id'),
  startExam:         (url, host)     => ipcRenderer.invoke('start-exam', { examUrl: url, examServerHost: host }),
  openExternal:      (url)           => ipcRenderer.invoke('open-external', url),

  // ── Exam window APIs ───────────────────────────────────────
  // Security violations from main process → forwarded to exam WS
  onSecurityEvent: (cb) => {
    ipcRenderer.on('security-event', (_, data) => cb(data));
  },
  // Suppress next fullscreen event (sent when Electron restores fullscreen, not user exit)
  onSuppressFullscreen: (cb) => {
    ipcRenderer.on('suppress-fullscreen-event', () => cb());
  },

  // Protocol deep-link URL passed at launch
  onProtocolUrl: (cb) => {
    ipcRenderer.on('protocol-url', (_, url) => cb(url));
  },

  // Proctor waiting-room signals
  onStartExam: (cb) => {
    ipcRenderer.on('start-exam-signal', (_, data) => cb(data));
  },

  // Generate QR code locally (no server, no CORS issues)
  generateQR:         (url) => ipcRenderer.invoke('generate-qr', url),
  // Open verify/upload page inside Electron (not external browser)
  openVerifyWindow:    (url) => ipcRenderer.invoke('open-verify-window', url),
  // Close the verify window after photos submitted (window.close() doesn't work in Electron child)
  closeVerifyWindow:   ()    => ipcRenderer.invoke('close-verify-window'),
  // Auto-disconnect duplicate monitors (Windows: DisplaySwitch /internal)
  fixMultiMonitor:    () => ipcRenderer.invoke('fix-multi-monitor'),
  // Restore multi-monitor (DisplaySwitch /extend) — undo after exam / during testing
  restoreDisplay:     () => ipcRenderer.invoke('restore-display'),

  // Screen capture for exam recording (returns desktopCapturer source ID)
  getScreenSourceId: () => ipcRenderer.invoke('get-screen-source'),

  // Close the exam kiosk window after submission
  closeExam: () => ipcRenderer.invoke('close-exam'),

  // ── Auto-update APIs ────────────────────────────────────────────────────────
  getAppVersion:    () => ipcRenderer.invoke('get-app-version'),
  checkForUpdate:   () => ipcRenderer.invoke('check-for-update'),
  onUpdateStatus:   (cb) => { ipcRenderer.on('update-status', (_, data) => cb(data)); },

  // ── Machine lock / release ──────────────────────────────────────────────────
  lockMachine:     (data) => ipcRenderer.invoke('lock-machine', data),
  releaseMachine:  ()     => ipcRenderer.invoke('release-machine'),
  onLockData:      (cb)   => { ipcRenderer.on('lock-data', (_, data) => cb(data)); },

  // ── macOS permissions ───────────────────────────────────────────────────────
  checkMacPermissions:  ()      => ipcRenderer.invoke('check-mac-permissions'),
  openPrivacySettings:  (sec)   => ipcRenderer.invoke('open-privacy-settings', sec),
  requestMediaAccess:   (type)  => ipcRenderer.invoke('request-media-access', type),
});
