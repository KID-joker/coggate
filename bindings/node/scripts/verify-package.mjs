import { lstat } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const runtime = {
  darwin: 'libcoggate_ffi.dylib',
  linux: 'libcoggate_ffi.so',
  win32: 'coggate_ffi.dll',
}[process.platform];

if (runtime === undefined) {
  throw new Error(`unsupported native package platform: ${process.platform}`);
}

async function requireArtifact(relative) {
  let metadata;
  try {
    metadata = await lstat(resolve(root, relative));
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw new Error(`missing native package artifact: ${relative}`);
    }
    throw error;
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size === 0) {
    throw new Error(`invalid native package artifact: ${relative}`);
  }
}

await requireArtifact('build/Release/coggate.node');
await requireArtifact(`build/Release/${runtime}`);
