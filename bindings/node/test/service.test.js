import assert from 'node:assert/strict';
import { copyFileSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  CogGateError,
  IssueRequest,
  Service,
  Submission,
  newV1IssueRequest,
} from '../lib/index.js';

const binding = Uint8Array.from([0, 17, 34, 51, 68, 85, 102, 119]);
const key = Uint8Array.from(Buffer.from('3031323334353637383961626364656630313233343536373839616263646566', 'hex'));
const material = new TextEncoder().encode('{"challenge_id":"Y2hhbGxlbmdlLTEyMzQ1Ng","generator_version":"1.0","nonce":"bm9uY2UtMTIzNDU2Nzg5MA","issued_at":1788062400,"expires_at":1788062408,"mac_key_id":"2026-08","answer_mac":"ccdffbb67b4c9da34f91d56d12970b311d7345e8bcf579d1326fc4a78633330c","answer_encoding":"base64url"}');

function providers(overrides = {}) {
  return {
    lifecycle: {
      storeIssued: () => 0,
      beginAttempt: () => ({ status: 0, material, token: Uint8Array.from([0xaa, 0xbb, 0xcc, 0xdd]) }),
      finishAttempt: () => 0,
      ...overrides.lifecycle,
    },
    keys: {
      activeKey: () => ({ status: 0, keyId: new TextEncoder().encode('active-2026-09'), key }),
      keyById: () => ({ status: 0, key }),
      ...overrides.keys,
    },
    observer: overrides.observer,
  };
}

test('addon exposes N-API 9 and synchronous service issue/verify/close', () => {
  assert.equal(Service.nativeApiVersion, 9);
  const service = new Service(providers());
  const challenge = service.issue(newV1IssueRequest(binding));
  assert.equal(challenge.generatorVersion, '1.0');
  const outcome = service.verify(new Submission({
    challengeId: 'Y2hhbGxlbmdlLTEyMzQ1Ng', nonce: 'bm9uY2UtMTIzNDU2Nzg5MA', answer: 'YQ',
  }), binding);
  assert.equal(outcome.status, 'accepted');
  service.close();
  service.close();
  assert.throws(() => service.issue(newV1IssueRequest(binding)),
    (error) => error instanceof CogGateError && error.code === 'invalid_argument');
});

test('issue callback receives exact private schema, binding, limit and challenge-correlated values', () => {
  let stored;
  let supplied;
  let limit;
  const value = providers({ lifecycle: { storeIssued: (privateJson, seenBinding, seenLimit) => {
    stored = JSON.parse(new TextDecoder().decode(privateJson));
    supplied = seenBinding.slice();
    limit = seenLimit;
    return 0;
  } } });
  const service = new Service(value);
  const challenge = service.issue(newV1IssueRequest(binding));
  assert.deepEqual(supplied, binding);
  assert.equal(limit, 1);
  assert.deepEqual(new Set(Object.keys(stored)), new Set(['challenge_id', 'generator_version',
    'nonce', 'issued_at', 'expires_at', 'mac_key_id', 'answer_mac', 'answer_encoding']));
  assert.equal(stored.challenge_id, challenge.challengeId);
  assert.equal(stored.generator_version, challenge.generatorVersion);
  assert.equal(stored.nonce, challenge.nonce);
  assert.equal(stored.issued_at, challenge.issuedAt);
  assert.equal(stored.expires_at, challenge.expiresAt);
  assert.equal(stored.mac_key_id, 'active-2026-09');
  assert.match(stored.answer_mac, /^[0-9a-f]{64}$/);
  assert.equal(stored.answer_encoding, 'base64url');
  service.close();
});

test('callback exceptions are cleared and observer exceptions are swallowed', () => {
  const throwing = providers({
    lifecycle: { beginAttempt: () => { throw new Error('CALLBACK_EXCEPTION_SENTINEL'); } },
    observer: () => { throw new Error('OBSERVER_SECRET_SENTINEL'); },
  });
  const service = new Service(throwing);
  assert.throws(() => service.verify(new Submission({
    challengeId: 'Y2hhbGxlbmdlLTEyMzQ1Ng', nonce: 'bm9uY2UtMTIzNDU2Nzg5MA', answer: 'YQ',
  }), binding), (error) => error.code === 'internal_error' && !String(error).includes('SENTINEL'));
  assert.doesNotThrow(() => service.close());
});

test('callback statuses accept only exact closed integer enum values', () => {
  const invalid = [-1, 4, 0.5, 2 ** 32, Number.NaN, Number.POSITIVE_INFINITY, '0', 0n,
    new Number(0)];
  for (const status of invalid) {
    const issueService = new Service(providers({ lifecycle: { storeIssued: () => status } }));
    assert.throws(() => issueService.issue(newV1IssueRequest(binding)),
      (error) => error.code === 'callback_failed');
    issueService.close();

    const beginService = new Service(providers({ lifecycle: {
      beginAttempt: () => ({ status, material, token: new Uint8Array() }),
    } }));
    assert.throws(() => beginService.verify(new Submission({
      challengeId: 'Y2hhbGxlbmdlLTEyMzQ1Ng', nonce: 'bm9uY2UtMTIzNDU2Nzg5MA', answer: 'YQ',
    }), binding), (error) => error.code === 'callback_failed');
    beginService.close();

    const keyService = new Service(providers({ keys: {
      keyById: () => ({ status, key }),
    } }));
    assert.throws(() => keyService.verify(new Submission({
      challengeId: 'Y2hhbGxlbmdlLTEyMzQ1Ng', nonce: 'bm9uY2UtMTIzNDU2Nzg5MA', answer: 'YQ',
    }), binding), (error) => error.code === 'callback_failed');
    keyService.close();

    const finishService = new Service(providers({ lifecycle: { finishAttempt: () => status } }));
    assert.throws(() => finishService.verify(new Submission({
      challengeId: 'Y2hhbGxlbmdlLTEyMzQ1Ng', nonce: 'bm9uY2UtMTIzNDU2Nzg5MA', answer: 'YQ',
    }), binding), (error) => error.code === 'callback_failed');
    finishService.close();
  }
});

test('addon-created callback input arrays are wiped before returning to the caller', () => {
  const retained = [];
  const value = providers({
    lifecycle: {
      storeIssued: (...args) => { retained.push(...args.slice(0, 2)); return 0; },
      beginAttempt: (...args) => {
        retained.push(...args.slice(0, 2));
        return { status: 0, material, token: Uint8Array.from([0xaa, 0xbb, 0xcc, 0xdd]) };
      },
      finishAttempt: (token) => { retained.push(token); return 0; },
    },
    keys: { keyById: (id) => { retained.push(id); return { status: 0, key }; } },
    observer: (event) => retained.push(event),
  });
  const service = new Service(value);
  service.issue(newV1IssueRequest(binding));
  service.verify(new Submission({ challengeId: 'Y2hhbGxlbmdlLTEyMzQ1Ng',
    nonce: 'bm9uY2UtMTIzNDU2Nzg5MA', answer: 'YQ' }), binding);
  assert.ok(retained.length >= 8);
  for (const bytes of retained) assert.ok(bytes.every((value) => value === 0));
  service.close();
});

test('callback input arrays are wiped on callback and observer failure paths', () => {
  const retained = [];
  const issueService = new Service(providers({ lifecycle: { storeIssued: (...args) => {
    retained.push(...args.slice(0, 2));
    throw new Error('STORE_FAILURE_SENTINEL');
  } } }));
  assert.throws(() => issueService.issue(newV1IssueRequest(binding)));
  issueService.close();
  const verifyService = new Service(providers({ lifecycle: { beginAttempt: (...args) => {
    retained.push(...args.slice(0, 2));
    throw new Error('BEGIN_FAILURE_SENTINEL');
  } } }));
  assert.throws(() => verifyService.verify(new Submission({
    challengeId: 'Y2hhbGxlbmdlLTEyMzQ1Ng', nonce: 'bm9uY2UtMTIzNDU2Nzg5MA', answer: 'YQ',
  }), binding));
  verifyService.close();
  const observerService = new Service(providers({ observer: (event) => {
    retained.push(event);
    throw new Error('OBSERVER_FAILURE_SENTINEL');
  } }));
  observerService.issue(newV1IssueRequest(binding));
  observerService.close();
  for (const bytes of retained) assert.ok(bytes.every((value) => value === 0));
});

test('throwing callback result accessors are cleared and later calls stay healthy', () => {
  let first = true;
  const value = providers({ lifecycle: { beginAttempt: () => {
    if (!first) return { status: 0, material, token: Uint8Array.from([0xaa, 0xbb, 0xcc, 0xdd]) };
    first = false;
    return Object.defineProperty({}, 'status', { get() { throw new Error('NAPI_SENTINEL'); } });
  } } });
  const service = new Service(value);
  const submission = new Submission({ challengeId: 'Y2hhbGxlbmdlLTEyMzQ1Ng',
    nonce: 'bm9uY2UtMTIzNDU2Nzg5MA', answer: 'YQ' });
  assert.throws(() => service.verify(submission, binding),
    (error) => !String(error).includes('NAPI_SENTINEL'));
  assert.equal(service.verify(submission, binding).status, 'accepted');
  service.close();
});

test('injected N-API property failure fails closed and the next call stays healthy', () => {
  const service = new Service(providers());
  const submission = new Submission({ challengeId: 'Y2hhbGxlbmdlLTEyMzQ1Ng',
    nonce: 'bm9uY2UtMTIzNDU2Nzg5MA', answer: 'YQ' });
  Service.testFailNextNapi();
  assert.throws(() => service.verify(submission, binding),
    (error) => error instanceof CogGateError && error.code === 'internal_error');
  assert.equal(service.verify(submission, binding).status, 'accepted');
  service.close();
});

test('callback-time close and reentry fail fast', () => {
  let service;
  const seen = [];
  const values = providers({ lifecycle: { storeIssued: () => {
    for (const call of [() => service.close(), () => service.issue(new IssueRequest({
      version: '1.0', binding, attemptLimit: 1,
    }))]) assert.throws(call, (error) => (seen.push(error.code), error.code === 'invalid_argument'));
    return 0;
  } } });
  service = new Service(values);
  service.issue(newV1IssueRequest(binding));
  assert.deepEqual(seen, ['invalid_argument', 'invalid_argument']);
  service.close();
});

test('explicit-length UTF-8 and opaque buffers preserve NUL and non-BMP', () => {
  const unusual = new TextEncoder().encode('nul\0-雪-🚀');
  let seen;
  const value = providers({ lifecycle: { storeIssued: (_json, supplied) => { seen = supplied.slice(); return 0; } } });
  const service = new Service(value);
  service.issue(newV1IssueRequest(unusual));
  assert.deepEqual(seen, unusual);
  service.close();
});

test('callbacks remain alive after forced GC', { skip: typeof global.gc !== 'function' }, () => {
  let values = providers();
  const weak = new WeakRef(values.lifecycle);
  const service = new Service(values);
  values = null;
  for (let index = 0; index < 20; index += 1) global.gc();
  assert.ok(weak.deref());
  service.issue(newV1IssueRequest(binding));
  service.close();
});

test('host callback allocations are wiped and released exactly once', () => {
  const allocationBefore = Service.testAllocationCount();
  const releaseBefore = Service.testReleaseCount();
  const wipeBefore = Service.testWipeCount();
  const service = new Service(providers());
  const outcome = service.verify(new Submission({
    challengeId: 'Y2hhbGxlbmdlLTEyMzQ1Ng', nonce: 'bm9uY2UtMTIzNDU2Nzg5MA', answer: 'YQ',
  }), binding);
  assert.equal(outcome.status, 'accepted');
  service.close();
  assert.equal(Service.testAllocationCount() - allocationBefore, 3n);
  assert.equal(Service.testReleaseCount() - releaseBefore, 3n);
  assert.equal(Service.testWipeCount() - wipeBefore, 3n);
});

test('unclosed service and provider closure cycle finalize with one native destroy',
  { skip: typeof global.gc !== 'function', timeout: 10_000 }, async () => {
    const before = Service.testDestroyCount();
    function createCycle() {
      let service;
      const value = providers({ lifecycle: { storeIssued: () => service ? 0 : 3 } });
      service = new Service(value);
      return new WeakRef(service);
    }
    const reference = createCycle();
    for (let index = 0; index < 50; index += 1) {
      global.gc();
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(reference.deref(), undefined);
    assert.equal(Service.testDestroyCount(), before + 1n);
  });

test('macOS addon is loader-relative and relocates through spaces and non-BMP paths',
  { skip: process.platform !== 'darwin' }, () => {
    const release = fileURLToPath(new URL('../build/Release/', import.meta.url));
    const addonPath = join(release, 'coggate.node');
    const dependency = join(release, 'libcoggate_ffi.dylib');
    const linked = spawnSync('otool', ['-L', addonPath], { encoding: 'utf8' });
    assert.equal(linked.status, 0, linked.stderr);
    const dependencies = linked.stdout.split(/\r?\n/).slice(1).join('\n');
    assert.match(dependencies, /@rpath\/libcoggate_ffi\.dylib/);
    assert.doesNotMatch(dependencies, /coggate-complete-rename\/|target\/release/);
    const identifier = spawnSync('otool', ['-D', dependency], { encoding: 'utf8' });
    assert.equal(identifier.status, 0, identifier.stderr);
    assert.match(identifier.stdout.split(/\r?\n/).at(-2) ?? '', /^@rpath\/libcoggate_ffi\.dylib$/);
    const destination = mkdtempSync(join(tmpdir(), 'CogGate Node 雪🚀 '));
    try {
      const copiedAddon = join(destination, basename(addonPath));
      copyFileSync(addonPath, copiedAddon);
      copyFileSync(dependency, join(destination, basename(dependency)));
      const environment = { ...process.env };
      delete environment.DYLD_LIBRARY_PATH;
      const loaded = spawnSync(process.execPath,
        ['-e', `const a=require(${JSON.stringify(copiedAddon)});if(a.napiVersion!==9)process.exit(2)`],
        { encoding: 'utf8', env: environment });
      assert.equal(loaded.status, 0, loaded.stderr);
    } finally {
      rmSync(destination, { recursive: true, force: true });
    }
  });

test('binding config guards Darwin tooling and declares synchronized native state', () => {
  const gyp = readFileSync(new URL('../binding.gyp', import.meta.url), 'utf8');
  const addonSource = readFileSync(new URL('../src/coggate.cc', import.meta.url), 'utf8');
  assert.match(gyp, /process\.platform\s*===\s*['"]darwin['"]/);
  assert.match(gyp, /install_name_tool.*-id/s);
  assert.match(
    gyp,
    /"inputs": \["<\(PRODUCT_DIR\)\/coggate\.node", "<\(coggate_library_path\)"\]/,
  );
  assert.match(gyp, /\["OS=='win'",\s*\{[\s\S]*?"ExceptionHandling":\s*1[\s\S]*?"WarningLevel":\s*4[\s\S]*?"TreatWarningAsError":\s*True[\s\S]*?"AdditionalOptions":\s*\["\/std:c\+\+17"\]/);
  assert.match(gyp, /\["OS=='win'",/);
  assert.doesNotMatch(gyp, /STATIC/);
  assert.match(addonSource, /std::mutex/);
});

test('service option reflection failures normalize without exposing getter text', () => {
  const options = Object.defineProperty({}, 'lifecycle', {
    enumerable: true, get() { throw new Error('OPTIONS_GETTER_SENTINEL'); },
  });
  Object.defineProperty(options, 'keys', { enumerable: true, value: providers().keys });
  assert.throws(() => new Service(options), (error) => error instanceof CogGateError &&
    error.code === 'invalid_argument' && !String(error).includes('SENTINEL'));
  const { proxy, revoke } = Proxy.revocable({}, {});
  revoke();
  assert.throws(() => new Service(proxy), (error) => error instanceof CogGateError &&
    error.code === 'invalid_argument');
});
