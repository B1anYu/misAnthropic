#!/usr/bin/env node
/**
 * MisAnthropic Build Pipeline
 *
 * Produces three artifacts from index.js (Windows / WSL / Linux edition):
 *
 *   1. dist/mis.bundle.js    — esbuild bundle, readable but single-file
 *   2. dist/mis.obfuscated.js — javascript-obfuscator heavy transform
 *                               (control flow flattening, dead code, string array)
 *   3. dist/mis.xor.js        — XOR-obfuscated with self-extracting bootstrap
 *                               (key=91, XOR 自解压)
 *
 * Usage:
 *   node build.js              # build all
 *   node build.js --clean      # build only the clean bundle
 *   node build.js --obfuscate  # build only the obfuscated version
 *   node build.js --xor        # build only the XOR version
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const DIST = path.join(__dirname, 'dist');
const SRC  = path.join(__dirname, 'index.js');

// ─── ensure dist ────────────────────────────────────────────────────────────
if (!fs.existsSync(DIST)) fs.mkdirSync(DIST, { recursive: true });

// ─── helpers ────────────────────────────────────────────────────────────────
function log(label) { console.log(`\x1b[36m[${label}]\x1b[0m`); }
function size(file) { return (fs.statSync(file).size / 1024).toFixed(1) + ' KB'; }

// ─── 1. esbuild bundle ──────────────────────────────────────────────────────
function bundle() {
  log('esbuild');
  execSync(`npx esbuild "${SRC}" --bundle --platform=node --target=node18 --outfile="${DIST}/mis.bundle.js" --external:esbuild --external:javascript-obfuscator`, { stdio: 'inherit' });
  console.log(`  → dist/mis.bundle.js  ${size(path.join(DIST, 'mis.bundle.js'))}`);
}

// ─── 2. javascript-obfuscator ────────────────────────────────────────────────
function obfuscate() {
  log('javascript-obfuscator');
  const JavaScriptObfuscator = require('javascript-obfuscator');
  const code = fs.readFileSync(path.join(DIST, 'mis.bundle.js'), 'utf-8');

  const result = JavaScriptObfuscator.obfuscate(code, {
    compact: true,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.75,
    deadCodeInjection: true,
    deadCodeInjectionThreshold: 0.4,
    debugProtection: false,          // set true for extra annoyance
    debugProtectionInterval: 0,
    disableConsoleOutput: false,
    identifierNamesGenerator: 'hexadecimal',
    log: false,
    numbersToExpressions: true,
    renameGlobals: false,
    selfDefending: false,
    simplify: true,
    splitStrings: true,
    splitStringsChunkLength: 10,
    stringArray: true,
    stringArrayCallsTransform: true,
    stringArrayCallsTransformThreshold: 0.75,
    stringArrayEncoding: ['base64'],
    stringArrayIndexShift: true,
    stringArrayRotate: true,
    stringArrayShuffle: true,
    stringArrayWrappersCount: 2,
    stringArrayWrappersChainedCalls: true,
    stringArrayWrappersParametersMaxCount: 4,
    stringArrayWrappersType: 'function',
    stringArrayThreshold: 0.75,
    transformObjectKeys: true,
    unicodeEscapeSequence: false,
  });

  fs.writeFileSync(path.join(DIST, 'mis.obfuscated.js'), result.getObfuscatedCode());
  console.log(`  → dist/mis.obfuscated.js  ${size(path.join(DIST, 'mis.obfuscated.js'))}`);
}

// ─── 3. XOR wrapper (key=91) ─────────────────────────────────────────────
function xorBuild() {
  log('xor (key=91)');

  const code = fs.readFileSync(path.join(DIST, 'mis.bundle.js'), 'utf-8');

  // XOR each byte with key 91
  const KEY = 91;
  const encoded = Buffer.from(code, 'utf-8').map(b => b ^ KEY);

  // Self-extracting bootstrap
  const bootstrap = `#!/usr/bin/env node
/* ⚠ XOR-obfuscated payload. Self-extracting bootstrap with key=91. */
'use strict';
const KEY=91;
const payload=${JSON.stringify(encoded.toString('base64'))};
const code=Buffer.from(payload,'base64').map(b=>b^KEY).toString('utf8');
eval(code);
`;

  fs.writeFileSync(path.join(DIST, 'mis.xor.js'), bootstrap);
  // Make executable
  try { fs.chmodSync(path.join(DIST, 'mis.xor.js'), 0o755); } catch {}
  console.log(`  → dist/mis.xor.js  ${size(path.join(DIST, 'mis.xor.js'))}`);
  console.log(`  → Raw payload: ${size(path.join(DIST, 'mis.bundle.js'))} → XOR → ${Buffer.from(bootstrap).length / 1024} KB wrapper`);
  console.log(`  → \x1b[33mXOR-bootstrap 可自解压执行，无需额外工具。\x1b[0m`);
}

// ─── main ───────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const doAll = args.length === 0;

try {
  if (doAll || args.includes('--clean')) bundle();
  if (doAll || args.includes('--obfuscate')) {
    if (!fs.existsSync(path.join(DIST, 'mis.bundle.js'))) bundle();
    obfuscate();
  }
  if (doAll || args.includes('--xor')) {
    if (!fs.existsSync(path.join(DIST, 'mis.bundle.js'))) bundle();
    xorBuild();
  }
  console.log(`\n\x1b[32mDone. All artifacts in dist/\x1b[0m`);
} catch (e) {
  console.error(`\x1b[31mBuild failed:\x1b[0m ${e.message}`);
  process.exit(1);
}
