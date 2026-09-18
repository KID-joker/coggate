import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { dirname, relative, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const retired = ['agent', 'gate'].join('');

async function filesBelow(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (['build', 'node_modules'].includes(entry.name)) continue;
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...await filesBelow(path));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

test('npm package exposes only the CogGate API and metadata', async () => {
  const packageJson = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8'));
  assert.equal(packageJson.name, 'coggate');
  assert.equal(packageJson.description, 'Native Node.js SDK for CogGate');
  assert.equal(packageJson.main, './lib/index.js');
  assert.equal(packageJson.types, './lib/index.d.ts');
  assert.deepEqual(packageJson.exports, {
    '.': { types: './lib/index.d.ts', import: './lib/index.js' },
  });
  assert.equal(packageJson.readme, 'README.md');
  assert.equal(packageJson.scripts.build, 'node-gyp rebuild --release');
  assert.equal(packageJson.scripts.install, 'node -e ""');
  assert.equal(packageJson.scripts.prepack, 'node scripts/verify-package.mjs');
  assert.equal(packageJson.scripts.test, 'node --expose-gc --test');
  assert.equal(packageJson.scripts.example, 'node examples/complete.js');
  assert.deepEqual(packageJson.files, [
    'README.md',
    'lib',
    'build/Release/coggate.node',
    'build/Release/libcoggate_ffi.so',
    'build/Release/libcoggate_ffi.dylib',
    'build/Release/coggate_ffi.dll',
    'scripts/verify-package.mjs',
  ]);

  const declarations = await readFile(resolve(root, 'lib/index.d.ts'), 'utf8');
  assert.match(declarations, /export class CogGateError extends Error/);
  assert.doesNotMatch(declarations.toLowerCase(), new RegExp(retired));
  const readme = await readFile(resolve(root, 'README.md'), 'utf8');
  assert.match(readme, /^# CogGate Node\.js SDK$/m);
});

test('native build and loader use only the CogGate names and environment variable', async () => {
  const gyp = await readFile(resolve(root, 'binding.gyp'), 'utf8');
  const loader = await readFile(resolve(root, 'lib/service.js'), 'utf8');
  const example = await readFile(resolve(root, 'examples/complete.js'), 'utf8');
  const source = await readFile(resolve(root, 'src/coggate.cc'), 'utf8');
  assert.match(gyp, /"target_name": "coggate"/);
  assert.deepEqual(new Set(gyp.match(/COGGATE_[A-Z_]+/g)), new Set(['COGGATE_LIBRARY_PATH']));
  assert.match(gyp, /coggate_ffi/);
  assert.match(loader, /build\/Release\/coggate\.node/);
  assert.match(example, /from 'coggate'/);
  assert.match(source, /#include "coggate\.h"/);
});

test('Node SDK has no retired product spelling or compatibility entry point', async () => {
  const matches = [];
  for (const path of await filesBelow(root)) {
    if (path.endsWith('branding.test.js')) continue;
    const content = await readFile(path, 'utf8');
    if (relative(root, path).toLowerCase().includes(retired) ||
        content.toLowerCase().includes(retired)) matches.push(relative(root, path));
  }
  assert.deepEqual(matches, []);
  await assert.rejects(import(retired), /(?:not find|not found|cannot find)/i);
});
