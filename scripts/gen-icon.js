/**
 * Generates assets/icon.png (1024×1024) — no external deps, pure Node.js
 * Run: node scripts/gen-icon.js
 */
'use strict';
const fs   = require('fs');
const path = require('path');
const zlib = require('zlib');

const SIZE = 1024;

// ─── Build raw RGBA pixel buffer ──────────────────────────────────────────────
const buf = Buffer.alloc(SIZE * SIZE * 4);

for (let y = 0; y < SIZE; y++) {
  for (let x = 0; x < SIZE; x++) {
    const idx = (y * SIZE + x) * 4;
    const cx = x - SIZE / 2, cy = y - SIZE / 2;
    const dist = Math.sqrt(cx * cx + cy * cy);
    const r = SIZE * 0.48;           // outer radius
    const ri = SIZE * 0.44;          // inner (slightly rounded square)

    // Background — outside circle → transparent
    if (dist > r) { buf[idx + 3] = 0; continue; }

    // Dark gradient background
    const t = dist / r;
    buf[idx + 0] = Math.round(10  + t * 5);     // R
    buf[idx + 1] = Math.round(20  + t * 10);    // G
    buf[idx + 2] = Math.round(50  + t * 30);    // B
    buf[idx + 3] = 255;

    // Shield shape — outer ring
    if (dist > ri) {
      buf[idx + 0] = Math.round(0   + t * 20);
      buf[idx + 1] = Math.round(100 + t * 80);
      buf[idx + 2] = Math.round(180 + t * 36);
      buf[idx + 3] = 255;
      continue;
    }

    // "A" letter — bounding box centred
    const lx = x - SIZE * 0.33;    // Normalised x within letter area
    const ly = y - SIZE * 0.22;    // Normalised y within letter area
    const lw = SIZE * 0.34;        // letter width
    const lh = SIZE * 0.56;        // letter height
    const stroke = SIZE * 0.075;   // stroke thickness

    // left leg
    const leftDist = Math.abs(lx - (ly / lh) * (lw / 2));
    // right leg
    const rightDist = Math.abs(lx - lw + (ly / lh) * (lw / 2));
    // crossbar
    const crossY = lh * 0.55;
    const inCross = ly > crossY - stroke / 2 && ly < crossY + stroke / 2
                 && lx > stroke && lx < lw - stroke;

    const inLetter = (leftDist < stroke && ly > 0 && ly < lh)
                  || (rightDist < stroke && ly > 0 && ly < lh)
                  || inCross;

    if (inLetter) {
      buf[idx + 0] = 255;
      buf[idx + 1] = 255;
      buf[idx + 2] = 255;
      buf[idx + 3] = 255;
    }
  }
}

// ─── Encode as PNG ────────────────────────────────────────────────────────────
function crc32(buf) {
  const table = (() => {
    const t = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let j = 0; j < 8; j++) c = (c & 1) ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
      t[i] = c;
    }
    return t;
  })();
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function chunk(type, data) {
  const typeBytes = Buffer.from(type, 'ascii');
  const lenBuf    = Buffer.allocUnsafe(4);
  lenBuf.writeUInt32BE(data.length, 0);
  const crcBuf    = Buffer.allocUnsafe(4);
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBytes, data])), 0);
  return Buffer.concat([lenBuf, typeBytes, data, crcBuf]);
}

// IHDR
const ihdr = Buffer.allocUnsafe(13);
ihdr.writeUInt32BE(SIZE,  0);  // width
ihdr.writeUInt32BE(SIZE,  4);  // height
ihdr[8]  = 8;   // bit depth
ihdr[9]  = 6;   // colour type: RGBA
ihdr[10] = 0;   // compression
ihdr[11] = 0;   // filter
ihdr[12] = 0;   // interlace

// IDAT — filter byte 0 (None) prepended to each row, then zlib compress
const rawRows = Buffer.alloc(SIZE * (SIZE * 4 + 1));
for (let y = 0; y < SIZE; y++) {
  rawRows[y * (SIZE * 4 + 1)] = 0;   // filter: None
  buf.copy(rawRows, y * (SIZE * 4 + 1) + 1, y * SIZE * 4, (y + 1) * SIZE * 4);
}
const compressed = zlib.deflateSync(rawRows, { level: 6 });

const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),  // signature
  chunk('IHDR', ihdr),
  chunk('IDAT', compressed),
  chunk('IEND', Buffer.alloc(0)),
]);

const outPath = path.join(__dirname, '..', 'assets', 'icon.png');
fs.writeFileSync(outPath, png);
console.log(`✓ Written ${outPath} (${(png.length / 1024).toFixed(0)} KB)`);
