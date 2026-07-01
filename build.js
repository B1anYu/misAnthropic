#!/usr/bin/env node
/**
 * AID Build Pipeline
 *
 * Produces three artifacts from index.js:
 *
 *   1. dist/aid.bundle.js    — esbuild bundle, readable but single-file
 *   2. dist/aid.obfuscated.js — javascript-obfuscator heavy transform
 *                               (control flow flattening, dead code, string array)
 *   3. dist/aid.xor.js        — XOR-obfuscated with self-extracting bootstrap
 *                               (key=91, same as Anthropic's Claude Code binary)
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
  execSync(`npx esbuild "${SRC}" --bundle --platform=node --target=node18 --outfile="${DIST}/aid.bundle.js" --external:esbuild --external:javascript-obfuscator`, { stdio: 'inherit' });
  console.log(`  → dist/aid.bundle.js  ${size(path.join(DIST, 'aid.bundle.js'))}`);
}

// ─── 2. javascript-obfuscator ────────────────────────────────────────────────
function obfuscate() {
  log('javascript-obfuscator');
  const JavaScriptObfuscator = require('javascript-obfuscator');
  const code = fs.readFileSync(path.join(DIST, 'aid.bundle.js'), 'utf-8');

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

  fs.writeFileSync(path.join(DIST, 'aid.obfuscated.js'), result.getObfuscatedCode());
  console.log(`  → dist/aid.obfuscated.js  ${size(path.join(DIST, 'aid.obfuscated.js'))}`);
}

// ─── 3. XOR wrapper (Anthropic-style, key=91) ───────────────────────────────
function xorBuild() {
  log('xor (key=91)');

  const code = fs.readFileSync(path.join(DIST, 'aid.bundle.js'), 'utf-8');

  // XOR each byte with key 91
  const KEY = 91;
  const encoded = Buffer.from(code, 'utf-8').map(b => b ^ KEY);

  // Self-extracting bootstrap
  const bootstrap = `#!/usr/bin/env node
/* ⚠ This file is XOR-obfuscated. Anthropic uses the same technique in Claude Code
 * with key 91 to hide the geo-profiling functions Crt/Rrt/e0t/Zup/edp/Vla. */
'use strict';
const KEY=91;
const payload=${JSON.stringify(encoded.toString('base64'))};
const code=Buffer.from(payload,'base64').map(b=>b^KEY).toString('utf8');
eval(code);
`;

  fs.writeFileSync(path.join(DIST, 'aid.xor.js'), bootstrap);
  // Make executable
  try { fs.chmodSync(path.join(DIST, 'aid.xor.js'), 0o755); } catch {}
  console.log(`  → dist/aid.xor.js  ${size(path.join(DIST, 'aid.xor.js'))}`);
  console.log(`  → Raw payload: ${size(path.join(DIST, 'aid.bundle.js'))} → XOR → ${Buffer.from(bootstrap).length / 1024} KB wrapper`);
  console.log(`  → \x1b[33mJust like Anthropic hides Crt() in the Claude Code binary.\x1b[0m`);
}

// ─── main ───────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const doAll = args.length === 0;

try {
  if (doAll || args.includes('--clean')) bundle();
  if (doAll || args.includes('--obfuscate')) {
    if (!fs.existsSync(path.join(DIST, 'aid.bundle.js'))) bundle();
    obfuscate();
  }
  if (doAll || args.includes('--xor')) {
    if (!fs.existsSync(path.join(DIST, 'aid.bundle.js'))) bundle();
    xorBuild();
  }
  console.log(`\n\x1b[32mDone. All artifacts in dist/\x1b[0m`);
} catch (e) {
  console.error(`\x1b[31mBuild failed:\x1b[0m ${e.message}`);
  process.exit(1);
}
