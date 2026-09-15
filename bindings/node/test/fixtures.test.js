import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { AgentGateError, Service, Submission } from '../lib/index.js';

const manifest = JSON.parse(await readFile(
  new URL('../../../fixtures/bindings/v1.json', import.meta.url)));
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
