const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('AlaricProctor', {
  // Identity
  isSecureBrowser: true,
  version: '1.0.0',
  platform: process.platform,

  // ── Launcher APIs ──────────────────────────────────────────
  runMachineChecks:  ()              => ipcRenderer.invoke('run-machine-checks'),
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

  // Screen capture for exam recording (returns desktopCapturer source ID)
  getScreenSourceId: () => ipcRenderer.invoke('get-screen-source'),
});
