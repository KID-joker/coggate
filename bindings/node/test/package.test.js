import assert from 'node:assert/strict';
import { copyFile, mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const runtime = {
  darwin: 'libcoggate_ffi.dylib',
  linux: 'libcoggate_ffi.so',
  win32: 'coggate_ffi.dll',
}[process.platform];

function cleanEnvironment() {
  const environment = { ...process.env };
  for (const key of [
    'COGGATE_LIBRARY_PATH', 'COGGATE_LIBRARY', 'COGGATE_RUNTIME_LIBRARY',
    'LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH',
  ]) delete environment[key];
  return environment;
}

function run(command, args, options = {}) {
  return spawnSync(command, args, {
    encoding: 'utf8',
    env: cleanEnvironment(),
    ...options,
  });
}

test('npm pack fails closed when native package artifacts are absent', async (context) => {
  if (runtime === undefined) return context.skip(`unsupported platform ${process.platform}`);
  for (const missing of ['addon', 'runtime']) {
    const temporary = await mkdtemp(join(tmpdir(), `coggate-node-pack-missing-${missing}-`));
    try {
      await copyFile(resolve(root, 'package.json'), join(temporary, 'package.json'));
      await mkdir(join(temporary, 'scripts'));
      await copyFile(resolve(root, 'scripts/verify-package.mjs'),
        join(temporary, 'scripts/verify-package.mjs'));
      if (missing === 'runtime') {
        await mkdir(join(temporary, 'build/Release'), { recursive: true });
        await writeFile(join(temporary, 'build/Release/coggate.node'), 'addon');
      }
      const packed = run('npm', ['pack', '--json'], {
        cwd: temporary,
        env: { ...cleanEnvironment(), npm_config_cache: join(temporary, '.npm-cache') },
      });
      assert.notEqual(packed.status, 0);
      const expected = missing === 'addon' ? 'coggate.node' : runtime;
      assert.match(packed.stderr + packed.stdout,
        new RegExp(`missing native package artifact.*${expected.replaceAll('.', '\\.')}`, 'i'));
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  }
});

test('packed SDK installs and runs by package name without external loader paths', async (context) => {
  if (runtime === undefined) return context.skip(`unsupported platform ${process.platform}`);
  const temporary = await mkdtemp(join(tmpdir(), 'coggate-node-pack-consumer-'));
  try {
    const npmEnvironment = {
      ...cleanEnvironment(),
      npm_config_cache: join(temporary, '.npm-cache'),
    };
    const packed = run('npm', ['pack', '--json', '--pack-destination', temporary], {
      cwd: root,
      env: npmEnvironment,
    });
    assert.equal(packed.status, 0, packed.stderr + packed.stdout);
    const metadata = JSON.parse(packed.stdout);
    const packedPaths = new Set(metadata[0].files.map((entry) => entry.path));
    for (const required of [
      'README.md', 'build/Release/coggate.node', `build/Release/${runtime}`,
      'scripts/verify-package.mjs',
    ]) assert.equal(packedPaths.has(required), true, `tarball missing ${required}`);
    const tarball = join(temporary, metadata[0].filename);
    const consumer = join(temporary, 'consumer');
    await mkdir(consumer);
    await writeFile(join(consumer, 'package.json'),
      JSON.stringify({ name: 'consumer', private: true, type: 'module' }));
    const installed = run('npm', [
      'install', '--ignore-scripts=false', '--no-audit', '--no-fund', tarball,
    ], { cwd: consumer, env: npmEnvironment });
    assert.equal(installed.status, 0, installed.stderr + installed.stdout);

    const examplePath = join(consumer, 'accepted.mjs');
    await writeFile(examplePath, await readFile(resolve(root, 'examples/complete.js'), 'utf8'));
    const accepted = run(process.execPath, [examplePath], { cwd: consumer });
    assert.equal(accepted.status, 0, accepted.stderr + accepted.stdout);
    assert.match(accepted.stdout, /verify: accepted/);

    const packagedRuntime = join(consumer, 'node_modules/coggate/build/Release', runtime);
    const missingRuntime = packagedRuntime + '.missing';
    await rename(packagedRuntime, missingRuntime);
    const missing = run(process.execPath, ['--input-type=module', '-e', "import 'coggate'"],
      { cwd: consumer });
    assert.notEqual(missing.status, 0);
    await rename(missingRuntime, packagedRuntime);
    await writeFile(packagedRuntime, 'corrupt native library');
    const corrupt = run(process.execPath, ['--input-type=module', '-e', "import 'coggate'"],
      { cwd: consumer });
    assert.notEqual(corrupt.status, 0);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
