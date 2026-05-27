/**
 * usbMonitor.js — Snapshots USB/HID devices at exam start.
 * Any new device connected during exam triggers an alert.
 */
'use strict';
const { exec }      = require('child_process');
const { promisify } = require('util');
const execAsync     = promisify(exec);

let _interval     = null;
let _callback     = null;
let _baseline     = null;    // Set of device IDs at exam start

async function getDevices() {
  try {
    if (process.platform === 'win32') {
      const { stdout } = await execAsync(
        'powershell -NoProfile -Command "Get-PnpDevice -Class HIDClass,USB -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq \'OK\'} | Select-Object -ExpandProperty InstanceId | ConvertTo-Json -Compress"',
        { timeout: 10000 }
      );
      if (!stdout.trim()) return new Set();
      const raw = JSON.parse(stdout.trim());
      return new Set(Array.isArray(raw) ? raw : [raw]);
    } else {
      const { stdout } = await execAsync(
        "system_profiler SPUSBDataType -json 2>/dev/null | python3 -c \"import json,sys;d=json.load(sys.stdin);items=[];[items.extend(g.get('_items',[])) for g in d.get('SPUSBDataType',[])];print('\\n'.join(i.get('_name','?')+':'+i.get('serial_num','') for i in items))\"",
        { timeout: 10000 }
      );
      return new Set(stdout.trim().split('\n').filter(Boolean));
    }
  } catch {
    return new Set();
  }
}

async function start(callback) {
  _callback = callback;
  _baseline = await getDevices();
  console.log(`[usbMonitor] Baseline: ${_baseline.size} device(s)`);

  _interval = setInterval(async () => {
    const current = await getDevices();
    const added   = [...current].filter(d => !_baseline.has(d));
    if (added.length > 0 && _callback) {
      _callback({
        type:      'usb_added',
        severity:  'critical',
        message:   `New USB device connected: ${added.join(', ')}`,
        devices:   added,
        timestamp: Date.now(),
      });
    }
    _baseline = current;          // Update baseline (handles removals too)
  }, 4000);
}

function stop() {
  if (_interval) { clearInterval(_interval); _interval = null; }
  _callback = null;
  _baseline = null;
}

module.exports = { start, stop };
