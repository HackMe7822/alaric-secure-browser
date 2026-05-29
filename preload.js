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

  // Protocol deep-link URL passed at launch
  onProtocolUrl: (cb) => {
    ipcRenderer.on('protocol-url', (_, url) => cb(url));
  },

  // Proctor waiting-room signals
  onStartExam: (cb) => {
    ipcRenderer.on('start-exam-signal', (_, data) => cb(data));
  },

  // Auto-disconnect duplicate monitors (Windows: DisplaySwitch /internal)
  fixMultiMonitor:   () => ipcRenderer.invoke('fix-multi-monitor'),

  // Screen capture for exam recording (returns desktopCapturer source ID)
  getScreenSourceId: () => ipcRenderer.invoke('get-screen-source'),

  // Close the exam kiosk window after submission
  closeExam: () => ipcRenderer.invoke('close-exam'),

  // ── Auto-update APIs ────────────────────────────────────────────────────────
  getAppVersion:    () => ipcRenderer.invoke('get-app-version'),
  checkForUpdate:   () => ipcRenderer.invoke('check-for-update'),
  onUpdateStatus:   (cb) => { ipcRenderer.on('update-status', (_, data) => cb(data)); },
});
