/**
 * processMonitor.js — Scans running processes every 3 s during exam.
 * Also checks services (Windows) and kernel drivers every 30 s.
 */
'use strict';
const { exec }      = require('child_process');
const { promisify } = require('util');
const path          = require('path');
const execAsync     = promisify(exec);
const { BLACKLISTED } = require('./machineCheck');

let _procInterval   = null;
let _driverInterval = null;
let _callback       = null;
let _alerted        = new Set();     // Avoid spamming same violation

async function getProcessList() {
  try {
    if (process.platform === 'win32') {
      const { stdout } = await execAsync('tasklist /fo csv /nh', { timeout: 8000 });
      return stdout.split('\n').map(l => l.replace(/"/g,'').toLowerCase().split(',')[0].trim()).filter(Boolean);
    } else {
      const { stdout } = await execAsync('ps -ax -o comm=', { timeout: 8000 });
      return stdout.split('\n').map(l => path.basename(l.trim()).toLowerCase()).filter(Boolean);
    }
  } catch { return []; }
}

async function scanProcesses() {
  const list = await getProcessList();
  const found = BLACKLISTED.filter(b => list.some(p => p.replace('.exe','').includes(b)));
  const newViolations = found.filter(v => !_alerted.has(v));

  if (newViolations.length > 0 && _callback) {
    newViolations.forEach(v => _alerted.add(v));
    _callback({
      type:      'process_violation',
      severity:  'critical',
      message:   `Blocked application detected: ${[...new Set(newViolations)].join(', ')}`,
      violations: newViolations,
      timestamp:  Date.now(),
    });
  }
}

async function scanDrivers() {
  if (process.platform !== 'win32') return;
  try {
    const { stdout } = await execAsync(
      'powershell -NoProfile -Command "Get-WmiObject Win32_SystemDriver | Where-Object {$_.State -eq \'Running\'} | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress"',
      { timeout: 12000 }
    );
    const drivers = JSON.parse(stdout || '[]');
    const arr = Array.isArray(drivers) ? drivers : [drivers];
    const lc = arr.map(d => d.toLowerCase());
    const suspicious = ['vboxdrv','vboxnetflt','vmhgfs','vmrawdsk','vmxnet','vnet'].filter(d => lc.includes(d));
    if (suspicious.length > 0 && _callback) {
      _callback({
        type:     'driver_violation',
        severity: 'critical',
        message:  `Virtual machine driver detected: ${suspicious.join(', ')}`,
        violations: suspicious,
        timestamp: Date.now(),
      });
    }
  } catch {}
}

function start(callback) {
  _callback = callback;
  _alerted.clear();
  scanProcesses();                                          // Immediate
  _procInterval   = setInterval(scanProcesses, 3000);
  _driverInterval = setInterval(scanDrivers, 30000);
  scanDrivers();
}

function stop() {
  if (_procInterval)   { clearInterval(_procInterval);   _procInterval   = null; }
  if (_driverInterval) { clearInterval(_driverInterval); _driverInterval = null; }
  _callback = null;
  _alerted.clear();
}

module.exports = { start, stop };
