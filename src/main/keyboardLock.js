/**
 * keyboardLock.js
 * Two layers:
 *   1. electron.globalShortcut — blocks most combos at app level
 *   2. uiohook-napi (optional) — low-level OS hook for Win/Meta key etc.
 */
'use strict';
const { globalShortcut, BrowserWindow } = require('electron');

const BLOCK = [
  // Window/tab management
  'Alt+Tab','Alt+Shift+Tab',
  'Alt+F4',
  'Meta+Tab','Meta+Shift+Tab',   // Cmd+Tab Mac
  'Meta+`',                       // Cycle windows Mac
  // macOS system
  'Meta+Space',                   // Spotlight
  'Meta+M',                       // Minimise
  'Meta+H',                       // Hide
  'Meta+Q',                       // Quit app
  'Meta+W',                       // Close window
  'Meta+Ctrl+F',                  // Toggle fullscreen Mac
  // Windows system
  'Ctrl+Escape',                  // Start menu
  'Ctrl+Shift+Escape',            // Task Manager
  'Meta+L',                       // Lock screen
  'Meta+D',                       // Show desktop
  'Meta+R',                       // Run dialog
  'Meta+E',                       // Explorer
  'Meta+I',                       // Settings
  'Meta+P',                       // Projector
  'Meta+X',                       // Power User menu
  // Capture / screenshot
  'PrintScreen',
  'Alt+PrintScreen',
  'Meta+PrintScreen',
  'Meta+Shift+S',                 // Snipping Tool
  'Ctrl+Shift+S',
  // F-keys
  'F1','F2','F3','F4','F5','F6','F7','F8','F9','F10','F11','F12',
  // Browser / dev tools shortcuts that could escape
  'Ctrl+W','Ctrl+T','Ctrl+N','Ctrl+Shift+N',
  'Meta+N','Meta+T',
  'Ctrl+Alt+T',                   // Linux terminal
];

let _running = false;
let _uiohook  = null;

function start() {
  if (_running) return;
  _running = true;

  // Layer 1 — globalShortcut
  BLOCK.forEach(s => {
    try { globalShortcut.register(s, () => { /* swallow */ }); }
    catch (_) {}                  // Ignore invalid combos on current OS
  });

  // Layer 2 — uiohook-napi (catches Win key, Alt+Tab at lower level)
  try {
    const { uIOhook } = require('uiohook-napi');
    _uiohook = uIOhook;

    uIOhook.on('keydown', (e) => {
      // Win key left (3675) or right (3676) — bring exam window back to front
      if (e.keycode === 3675 || e.keycode === 3676) {
        const wins = BrowserWindow.getAllWindows();
        wins.forEach(w => { if (!w.isDestroyed()) { w.focus(); w.setAlwaysOnTop(true, 'screen-saver'); } });
      }
    });

    uIOhook.start();
    console.log('[keyboardLock] uiohook-napi active');
  } catch (err) {
    console.warn('[keyboardLock] uiohook-napi unavailable — globalShortcut only:', err.message);
  }
}

function stop() {
  if (!_running) return;
  _running = false;
  try { globalShortcut.unregisterAll(); } catch (_) {}
  if (_uiohook) {
    try { _uiohook.stop(); } catch (_) {}
    _uiohook = null;
  }
}

module.exports = { start, stop };
