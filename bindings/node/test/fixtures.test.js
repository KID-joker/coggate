import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { AgentGateError, Service, Submission } from '../lib/index.js';

class StrictJson {
  constructor(text) { this.text = text; this.index = 0; }
  parse() { this.space(); this.value(); this.space(); if (this.index !== this.text.length) this.fail(); }
  value() {
    const current = this.text[this.index];
    if (current === '{') return this.object();
    if (current === '[') return this.array();
    if (current === '"') return this.string();
    if (current === '-' || /[0-9]/.test(current ?? '')) return this.number();
    for (const literal of ['true', 'false', 'null']) {
      if (this.text.startsWith(literal, this.index)) { this.index += literal.length; return; }
    }
    this.fail();
  }
  object() {
    this.index += 1; this.space();
    const keys = new Set();
    if (this.text[this.index] === '}') { this.index += 1; return; }
    while (true) {
      if (this.text[this.index] !== '"') this.fail();
      const key = this.string();
      if (keys.has(key)) this.fail();
      keys.add(key); this.space();
      if (this.text[this.index++] !== ':') this.fail();
      this.space(); this.value(); this.space();
      const delimiter = this.text[this.index++];
      if (delimiter === '}') return;
      if (delimiter !== ',') this.fail();
      this.space();
    }
  }
  array() {
    this.index += 1; this.space();
    if (this.text[this.index] === ']') { this.index += 1; return; }
    while (true) {
      this.value(); this.space();
      const delimiter = this.text[this.index++];
      if (delimiter === ']') return;
      if (delimiter !== ',') this.fail();
      this.space();
    }
  }
  string() {
    const start = this.index++;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index++);
      if (code === 0x22) {
        try { return JSON.parse(this.text.slice(start, this.index)); } catch { this.fail(); }
      }
      if (code < 0x20) this.fail();
      if (code === 0x5c) {
        const escape = this.text[this.index++];
        if ('"\\/bfnrt'.includes(escape)) continue;
        if (escape !== 'u' || !/^[0-9a-fA-F]{4}$/.test(this.text.slice(this.index, this.index + 4))) this.fail();
        const unit = Number.parseInt(this.text.slice(this.index, this.index + 4), 16);
        this.index += 4;
        if (unit >= 0xd800 && unit <= 0xdbff) {
          if (this.text.slice(this.index, this.index + 2) !== '\\u' ||
              !/^[0-9a-fA-F]{4}$/.test(this.text.slice(this.index + 2, this.index + 6))) this.fail();
          const low = Number.parseInt(this.text.slice(this.index + 2, this.index + 6), 16);
          if (low < 0xdc00 || low > 0xdfff) this.fail();
          this.index += 6;
        } else if (unit >= 0xdc00 && unit <= 0xdfff) this.fail();
      } else if (code >= 0xd800 && code <= 0xdbff) {
        const low = this.text.charCodeAt(this.index++);
        if (low < 0xdc00 || low > 0xdfff) this.fail();
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        this.fail();
      }
    }
    this.fail();
  }
  number() {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(this.text.slice(this.index));
    if (match === null) this.fail();
    this.index += match[0].length;
  }
  space() { while (' \n\r\t'.includes(this.text[this.index])) this.index += 1; }
  fail() { throw new Error('invalid fixture manifest'); }
}

function exactKeys(value, keys) {
  assert.equal(value !== null && typeof value === 'object' && !Array.isArray(value), true);
  assert.deepEqual(new Set(Object.keys(value)), new Set(keys));
}

function strictManifest(text) {
  new StrictJson(text).parse();
  const value = JSON.parse(text);
  exactKeys(value, ['fixture_version', 'statuses', 'vectors', 'cases']);
  assert.equal(value.fixture_version, 1);
  exactKeys(value.statuses, ['ok', 'invalid_configuration', 'generation_failed',
    'invalid_challenge_material', 'invalid_answer_encoding', 'answer_mismatch',
    'unsupported_generator_version', 'internal_error', 'invalid_argument', 'callback_failed',
    'panic_caught']);
  for (const status of Object.values(value.statuses)) {
    exactKeys(status, ['value', 'code']);
    assert.equal(Number.isInteger(status.value), true);
    assert.equal(typeof status.code, 'string');
  }
  exactKeys(value.vectors, ['challenge_id', 'nonce', 'answer', 'wrong_answer', 'binding_hex',
    'token_hex', 'active_key_id', 'active_key_hex', 'old_key_id', 'old_key_hex',
    'private_material', 'observer_allowlist']);
  for (const key of ['challenge_id', 'nonce', 'answer', 'wrong_answer', 'binding_hex', 'token_hex',
    'active_key_id', 'active_key_hex', 'old_key_id', 'old_key_hex']) {
    assert.equal(typeof value.vectors[key], 'string');
  }
  exactKeys(value.vectors.private_material, ['challenge_id', 'generator_version', 'nonce',
    'issued_at', 'expires_at', 'mac_key_id', 'answer_mac', 'answer_encoding']);
  assert.equal(Number.isInteger(value.vectors.private_material.issued_at), true);
  assert.equal(Number.isInteger(value.vectors.private_material.expires_at), true);
  assert.equal(Array.isArray(value.vectors.observer_allowlist), true);
  assert.ok(value.vectors.observer_allowlist.every((field) => typeof field === 'string'));
  assert.equal(Array.isArray(value.cases), true);
  const caseKeys = ['id', 'operation', 'submission', 'binding_hex', 'lifecycle', 'keys',
    'expected_status', 'expected_code', 'expected_outcome', 'expected_trace',
    'expected_release_count', 'forbidden_sentinels'];
  const lifecycleKeys = ['begin_status', 'finish_status', 'material', 'token', 'replay',
    'callback_exception'];
  const keyKeys = ['status', 'key_id', 'callback_exception'];
  for (const fixture of value.cases) {
    exactKeys(fixture, caseKeys);
    exactKeys(fixture.lifecycle, lifecycleKeys);
    exactKeys(fixture.keys, keyKeys);
    assert.equal(typeof fixture.id, 'string');
    assert.ok(['verify', 'close', 'observe', 'release'].includes(fixture.operation));
    if (fixture.submission === null) assert.equal(fixture.operation, 'close');
    else {
      exactKeys(fixture.submission, ['challenge_id', 'nonce', 'answer']);
      assert.ok(Object.values(fixture.submission).every((field) => typeof field === 'string'));
    }
    assert.equal(typeof fixture.binding_hex, 'string');
    assert.match(fixture.binding_hex, /^(?:[0-9a-f]{2})*$/);
    assert.ok(['ok', 'unavailable', 'conflict', 'internal', 'not_found', 'expired',
      'already_consumed', 'binding_mismatch', 'nonce_mismatch', 'attempts_exhausted',
      'exception', 'unused'].includes(fixture.lifecycle.begin_status));
    assert.ok(['ok', 'unavailable', 'conflict', 'internal', 'exception', 'unused']
      .includes(fixture.lifecycle.finish_status));
    assert.ok(['primary', 'none'].includes(fixture.lifecycle.material));
    assert.ok(['default', 'empty', 'none'].includes(fixture.lifecycle.token));
    assert.ok(['ok', 'unavailable', 'not_found', 'invalid_material', 'unused']
      .includes(fixture.keys.status));
    assert.ok(['old', 'active', 'none'].includes(fixture.keys.key_id));
    assert.equal(Number.isInteger(fixture.expected_status), true);
    assert.equal(typeof fixture.expected_code, 'string');
    const expectedStatus = Object.values(value.statuses)
      .find(({ value: status }) => status === fixture.expected_status);
    assert.equal(expectedStatus?.code, fixture.expected_code);
    if (fixture.expected_outcome !== null) {
      if (fixture.expected_outcome.status === 'accepted') exactKeys(fixture.expected_outcome, ['status']);
      else {
        exactKeys(fixture.expected_outcome, ['status', 'reason']);
        assert.equal(fixture.expected_outcome.status, 'rejected');
        assert.ok(['not_found', 'expired', 'already_consumed', 'binding_mismatch',
          'nonce_mismatch', 'attempts_exhausted'].includes(fixture.expected_outcome.reason));
      }
    }
    assert.equal(Array.isArray(fixture.expected_trace), true);
    assert.ok(fixture.expected_trace.every((entry) => typeof entry === 'string'));
    assert.equal(Number.isInteger(fixture.expected_release_count) &&
      fixture.expected_release_count >= 0, true);
    assert.equal(Array.isArray(fixture.forbidden_sentinels), true);
    assert.ok(fixture.forbidden_sentinels.every((entry) => typeof entry === 'string'));
    assert.equal(typeof fixture.lifecycle.replay, 'boolean');
    assert.equal(typeof fixture.lifecycle.callback_exception, 'boolean');
    assert.equal(typeof fixture.keys.callback_exception, 'boolean');
  }
  return value;
}

const manifestText = new TextDecoder('utf-8', { fatal: true }).decode(
  await readFile(new URL('../../../fixtures/bindings/v1.json', import.meta.url)));
const manifest = strictManifest(manifestText);
const vectors = manifest.vectors;
const fromHex = (value) => Uint8Array.from(Buffer.from(value, 'hex'));
const encode = (value) => new TextEncoder().encode(value);
const decode = (value) => new TextDecoder('utf-8', { fatal: true }).decode(value);
const lifecycleStatus = { ok: 0, unavailable: 1, conflict: 2, internal: 3 };
const beginStatus = {
  ok: 0, unavailable: 1, conflict: 2, internal: 3, not_found: 10, expired: 11,
  already_consumed: 12, binding_mismatch: 13, nonce_mismatch: 14, attempts_exhausted: 15,
};
const keyStatus = { ok: 0, unavailable: 1, not_found: 2, invalid_material: 3 };
const outcomeName = { 1: 'accepted', 2: 'rejected', 3: 'system_failure' };

function makeHarness(fixture) {
  const trace = [];
  const events = [];
  let begins = 0;
  const expectedBinding = fromHex(fixture.binding_hex);
  const lifecycle = {
    released(tag) { trace.push(`release:${tag}`); },
    storeIssued(privateJson, binding, limit) {
      trace.push('store_issued');
      assert.deepEqual(binding, expectedBinding);
      assert.equal(limit, 1);
      assert.equal(typeof JSON.parse(decode(privateJson)).challenge_id, 'string');
      return 0;
    },
    beginAttempt(identity, binding, serverTime) {
      begins += 1;
      const replayWarmup = fixture.lifecycle.replay && begins === 1;
      const scripted = replayWarmup ? 'ok' : fixture.lifecycle.begin_status;
      if (scripted === 'exception') {
        trace.push('begin_attempt:exception');
        throw new Error('CALLBACK_EXCEPTION_SENTINEL');
      }
      trace.push('begin_attempt');
      assert.deepEqual(binding, expectedBinding);
      const parsed = JSON.parse(decode(identity));
      assert.deepEqual(new Set(Object.keys(parsed)), new Set(['challenge_id', 'nonce']));
      assert.equal(parsed.challenge_id, vectors.challenge_id);
      assert.equal(parsed.nonce, vectors.nonce);
      assert.equal(typeof serverTime, 'number');
      if (scripted !== 'ok') return { status: beginStatus[scripted] };
      return {
        status: 0,
        material: encode(JSON.stringify(vectors.private_material)),
        token: fixture.lifecycle.token === 'empty' ? new Uint8Array() : fromHex(vectors.token_hex),
      };
    },
    finishAttempt(token, outcome) {
      trace.push(`finish_attempt:${outcomeName[outcome]}`);
      assert.deepEqual(token, fromHex(vectors.token_hex));
      if (fixture.lifecycle.finish_status === 'exception') throw new Error('FINISH_FAILURE_SENTINEL');
      return fixture.lifecycle.replay && begins === 1 ? 0 : lifecycleStatus[fixture.lifecycle.finish_status];
    },
  };
  const keys = {
    activeKey() {
      trace.push('active_key');
      if (fixture.keys.callback_exception) throw new Error('KEY_EXCEPTION_SENTINEL');
      return { status: keyStatus[fixture.keys.status], keyId: encode(vectors.active_key_id),
        key: fromHex(vectors.active_key_hex) };
    },
    keyById(keyId) {
      trace.push(`key_by_id:${decode(keyId) === vectors.old_key_id ? 'old' : 'unexpected'}`);
      assert.equal(decode(keyId), vectors.old_key_id);
      if (fixture.keys.callback_exception) throw new Error('KEY_EXCEPTION_SENTINEL');
      return { status: fixture.lifecycle.replay && begins === 1 ? 0 : keyStatus[fixture.keys.status],
        key: fromHex(vectors.old_key_hex) };
    },
  };
  const observer = (payload) => {
    const event = JSON.parse(decode(payload));
    if (fixture.id === 'observer_allowlist' && event.event === 'verification_completed') {
      assert.deepEqual(new Set(Object.keys(event)), new Set(vectors.observer_allowlist));
    }
    events.push(event);
    trace.push(`observe:${event.event}`);
  };
  return { trace, events, lifecycle, keys, observer };
}

test('every shared fixture exercises the native wrapper contract exactly', () => {
  assert.equal(manifest.fixture_version, 1);
  assert.equal(manifest.cases.length, 15);
  assert.deepEqual(new Set(manifest.cases.map(({ id }) => id)), new Set([
    'accepted', 'answer_mismatch', 'callback_exception', 'close_after_use', 'exact_release',
    'finish_failure', 'key_rotation_old_key', 'lifecycle_already_consumed',
    'lifecycle_attempts_exhausted', 'lifecycle_binding_mismatch', 'lifecycle_expired',
    'lifecycle_nonce_mismatch', 'lifecycle_not_found', 'observer_allowlist',
    'replay_after_accept',
  ]));
  for (const fixture of manifest.cases) {
    const harness = makeHarness(fixture);
    const observed = fixture.operation === 'verify' || fixture.operation === 'observe';
    const service = new Service({ lifecycle: harness.lifecycle, keys: harness.keys,
      observer: observed ? harness.observer : undefined });
    const baseline = Service.testReleaseCount();
    const observationBaseline = Service.testObservationCount();
    let outcome = null;
    let error = null;
    try {
      if (fixture.operation === 'close') {
        service.close();
        harness.trace.push('service_destroy');
      } else {
        const submission = new Submission({
          challengeId: fixture.submission.challenge_id,
          nonce: fixture.submission.nonce,
          answer: fixture.submission.answer,
        });
        const binding = fromHex(fixture.binding_hex);
        if (fixture.lifecycle.replay) {
          const accepted = service.verify(submission, binding);
          assert.equal(accepted.status, 'accepted');
          harness.trace.length = 0;
        }
        outcome = service.verify(submission, binding);
      }
    } catch (caught) {
      error = caught;
    } finally {
      service.close();
    }
    const releaseCount = Number(Service.testReleaseCount() - baseline);
    if (fixture.id === 'callback_exception') {
      assert.equal(Number(Service.testObservationCount() - observationBaseline), 1,
        'native observer callback count');
    }
    if (fixture.lifecycle.replay) assert.equal(releaseCount, fixture.expected_release_count + 3,
      `${fixture.id}: warm-up plus checked replay release count`);
    else assert.equal(releaseCount, fixture.expected_release_count, `${fixture.id}: release count`);
    assert.deepEqual(harness.trace, fixture.expected_trace, `${fixture.id}: trace`);
    if (fixture.expected_status === 0) {
      assert.equal(error, null, `${fixture.id}: no error`);
      if (fixture.expected_outcome !== null) {
        assert.equal(outcome.status, fixture.expected_outcome.status);
        assert.equal(outcome.reason ?? undefined, fixture.expected_outcome.reason);
      }
    } else {
      assert.ok(error instanceof AgentGateError, `${fixture.id}: stable error`);
      assert.equal(error.code, fixture.expected_code);
    }
    const publicText = JSON.stringify({ trace: harness.trace, events: harness.events,
      outcome, error: error?.toJSON() });
    for (const sentinel of fixture.forbidden_sentinels) assert.ok(!publicText.includes(sentinel));
  }
});

test('fixture reader rejects duplicate escaped keys and trailing roots', () => {
  assert.throws(() => strictManifest(manifestText.replace('{', '{"fixture_version":1,')));
  assert.throws(() => strictManifest(manifestText.replace('{', '{"fixture_\\u0076ersion":1,')));
  assert.throws(() => strictManifest(`${manifestText} {}`));
});
