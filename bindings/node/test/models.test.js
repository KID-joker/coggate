import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import test from 'node:test';

import { AgentGateError, errorForStatus } from '../lib/errors.js';
import {
  decodePublicChallenge,
  decodeSubmission,
  decodeVerificationOutcome,
  encodePublicChallenge,
  encodeSubmission,
  encodeVerificationOutcome,
} from '../lib/json.js';
import {
  AnswerEncoding,
  AttemptLimit,
  IssueRequest,
  PublicChallenge,
  RejectionReason,
  Submission,
  VerificationOutcome,
  VerificationStatus,
  newV1IssueRequest,
} from '../lib/models.js';

const utf8 = (value) => Buffer.from(value, 'utf8');

function assertInvalid(action) {
  assert.throws(action, (error) => {
    assert.ok(error instanceof AgentGateError);
    assert.equal(error.code, 'invalid_argument');
    assert.equal(error.message, 'invalid_argument');
    assert.equal(String(error), 'invalid_argument');
    return true;
  });
}

test('v1 issue request has fixed defaults and defensive binding copies', () => {
  const source = Uint8Array.from([1, 2, 3]);
  const request = newV1IssueRequest(source);
  source[0] = 9;
  const returned = request.binding;
  returned[1] = 9;

  assert.equal(request.version, '1.0');
  assert.equal(request.attemptLimit, AttemptLimit.ONE);
  assert.deepEqual(request.binding, Uint8Array.from([1, 2, 3]));
  assert.deepEqual(Object.keys(request), ['version', 'binding', 'attemptLimit']);
  assert.ok(Object.isFrozen(request));
  assert.ok(Object.isFrozen(AttemptLimit));
  assert.deepEqual(AttemptLimit, { ONE: 1, TWO: 2 });
});

test('issue requests reject invalid values and non-exact object shapes', () => {
  const valid = { version: '1.0', binding: Uint8Array.of(1), attemptLimit: 1 };
  for (const value of [
    null,
    [],
    Object.create(null),
    { ...valid, extra: true },
    { version: '1.0', binding: Uint8Array.of(1) },
    { ...valid, version: null },
    { ...valid, version: 'bad\ud800' },
    { ...valid, binding: null },
    { ...valid, binding: Uint8Array.of() },
    { ...valid, binding: new Uint8Array(257) },
    { ...valid, attemptLimit: 3 },
  ]) {
    assertInvalid(() => new IssueRequest(value));
  }
  const inherited = Object.create(valid);
  Object.assign(inherited, valid);
  assertInvalid(() => new IssueRequest(inherited));
  const symbol = { ...valid, [Symbol('hidden')]: true };
  assertInvalid(() => new IssueRequest(symbol));
  const accessor = { ...valid };
  Object.defineProperty(accessor, 'version', { enumerable: true, get: () => '1.0' });
  assertInvalid(() => new IssueRequest(accessor));
  assertInvalid(() => new IssueRequest(valid, 'ignored'));
  assertInvalid(() => newV1IssueRequest(Uint8Array.of(1), 'ignored'));
});

test('public models require exact plain-object shapes and freeze outputs', () => {
  const challengeValues = {
    challengeId: 'challenge', generatorVersion: '1.0', nonce: 'nonce',
    issuedAt: 1, expiresAt: 2, question: 'question', answerEncoding: 'base64url',
  };
  const submissionValues = { challengeId: 'challenge', nonce: 'nonce', answer: 'answer' };
  const challenge = new PublicChallenge(challengeValues);
  const submission = new Submission(submissionValues);

  assert.deepEqual(Object.keys(challenge), Object.keys(challengeValues));
  assert.deepEqual(Object.keys(submission), Object.keys(submissionValues));
  assert.ok(Object.isFrozen(challenge));
  assert.ok(Object.isFrozen(submission));
  assert.throws(() => { challenge.question = 'changed'; }, TypeError);
  assert.equal(challenge.question, 'question');

  for (const changed of [
    { ...challengeValues, issuedAt: 1.5 },
    { ...challengeValues, expiresAt: Number.MAX_SAFE_INTEGER + 1 },
    { ...challengeValues, answerEncoding: 'BASE64URL' },
    { ...challengeValues, question: 'bad\udfff' },
    { ...challengeValues, Extra: true },
  ]) assertInvalid(() => new PublicChallenge(changed));
  assertInvalid(() => new Submission({ ...submissionValues, answer: 1 }));
  assertInvalid(() => new Submission({ ...submissionValues, Answer: 'answer' }));
  assertInvalid(() => new Submission(Object.assign(Object.create({ polluted: true }), submissionValues)));
  assertInvalid(() => new PublicChallenge(challengeValues, 'ignored'));
  assertInvalid(() => new Submission(submissionValues, 'ignored'));
});

test('typed model construction copies explicit fields and rejects prototype tricks', () => {
  const values = { challengeId: 'c', nonce: 'n', answer: 'a' };
  const model = new Submission(values);
  values.answer = 'changed';
  values.extra = 'later';
  assert.equal(model.answer, 'a');
  assert.deepEqual(Object.keys(model), ['challengeId', 'nonce', 'answer']);

  const nonEnumerable = { ...values };
  delete nonEnumerable.extra;
  Object.defineProperty(nonEnumerable, 'hidden', { value: true });
  assertInvalid(() => new Submission(nonEnumerable));
});

test('model constructors reject malicious subclasses before they can leak secrets', () => {
  const sentinel = 'SUBCLASS_SECRET_SENTINEL';
  class LeakyIssueRequest extends IssueRequest {
    toJSON() { return sentinel; }
    [inspect.custom]() { return sentinel; }
  }
  class LeakyPublicChallenge extends PublicChallenge {
    toJSON() { return sentinel; }
    [inspect.custom]() { return sentinel; }
  }
  class LeakySubmission extends Submission {
    toJSON() { return sentinel; }
    [inspect.custom]() { return sentinel; }
  }
  class LeakyVerificationOutcome extends VerificationOutcome {
    toJSON() { return sentinel; }
    [inspect.custom]() { return sentinel; }
  }

  const cases = [
    () => new LeakyIssueRequest({
      version: '1.0', binding: Uint8Array.of(1), attemptLimit: AttemptLimit.ONE,
    }),
    () => new LeakyPublicChallenge({
      challengeId: 'c', generatorVersion: '1.0', nonce: sentinel,
      issuedAt: 1, expiresAt: 2, question: sentinel,
      answerEncoding: AnswerEncoding.BASE64URL,
    }),
    () => new LeakySubmission({ challengeId: 'c', nonce: sentinel, answer: sentinel }),
    () => new LeakyVerificationOutcome(Symbol(sentinel), 'accepted', null),
  ];
  for (const construct of cases) {
    let caught;
    try { construct(); } catch (error) { caught = error; }
    assert.ok(caught instanceof AgentGateError);
    assert.equal(caught.code, 'invalid_argument');
    for (const rendered of [String(caught), inspect(caught), JSON.stringify(caught)]) {
      assert.equal(rendered.includes(sentinel), false);
    }
  }
});

test('issue requests require an exact genuine Uint8Array and normalize intrinsic failures', () => {
  class DerivedBytes extends Uint8Array {}
  const customPrototype = Object.create(Uint8Array.prototype);
  const customView = Uint8Array.of(1);
  Object.setPrototypeOf(customView, customPrototype);
  const proxy = new Proxy(Uint8Array.of(1), {});
  const detached = Uint8Array.of(1);
  structuredClone(detached.buffer, { transfer: [detached.buffer] });

  for (const binding of [
    Object.create(Uint8Array.prototype),
    new DerivedBytes([1]),
    Buffer.from([1]),
    customView,
    proxy,
    detached,
  ]) {
    assertInvalid(() => newV1IssueRequest(binding));
  }
});

test('model string, inspection, and implicit JSON forms redact secrets', () => {
  const sentinels = ['BINDING_SENTINEL', 'NONCE_SENTINEL', 'ANSWER_SENTINEL', 'QUESTION_SENTINEL'];
  const models = [
    newV1IssueRequest(Uint8Array.from(utf8(sentinels[0]))),
    new PublicChallenge({
      challengeId: 'challenge', generatorVersion: '1.0', nonce: sentinels[1],
      issuedAt: 1, expiresAt: 2, question: sentinels[3], answerEncoding: AnswerEncoding.BASE64URL,
    }),
    new Submission({ challengeId: 'challenge', nonce: sentinels[1], answer: sentinels[2] }),
  ];
  for (const model of models) {
    for (const rendered of [String(model), inspect(model), JSON.stringify(model)]) {
      for (const sentinel of sentinels) assert.equal(rendered.includes(sentinel), false);
    }
  }
});

test('submission round-trips with exact deterministic bytes and non-BMP Unicode', () => {
  const expected = new Submission({ challengeId: '雪🚀', nonce: 'nonce', answer: 'answer' });
  const encoded = encodeSubmission(expected);
  assert.ok(encoded instanceof Uint8Array);
  assert.equal(Buffer.from(encoded).toString('utf8'),
    '{"challenge_id":"雪🚀","nonce":"nonce","answer":"answer"}');
  assert.deepEqual(decodeSubmission(encoded), expected);
});

test('public challenge round-trips with exact safe integers and encoding', () => {
  const expected = new PublicChallenge({
    challengeId: 'challenge', generatorVersion: '1.0', nonce: 'nonce',
    issuedAt: Number.MIN_SAFE_INTEGER, expiresAt: Number.MAX_SAFE_INTEGER,
    question: '雪🚀', answerEncoding: AnswerEncoding.BASE64URL,
  });
  const encoded = encodePublicChallenge(expected);
  assert.equal(Buffer.from(encoded).toString('utf8'),
    '{"challenge_id":"challenge","generator_version":"1.0","nonce":"nonce",' +
      '"issued_at":-9007199254740991,"expires_at":9007199254740991,' +
      '"question":"雪🚀","answer_encoding":"base64url"}');
  assert.deepEqual(decodePublicChallenge(encoded), expected);
});

test('verification outcomes round-trip with exact closed shapes', () => {
  const accepted = VerificationOutcome.accepted();
  assert.equal(Buffer.from(encodeVerificationOutcome(accepted)).toString(), '{"status":"accepted"}');
  assert.deepEqual(decodeVerificationOutcome(encodeVerificationOutcome(accepted)), accepted);

  const reasons = Object.values(RejectionReason);
  assert.equal(reasons.length, 6);
  for (const reason of reasons) {
    const rejected = VerificationOutcome.rejected(reason);
    const exact = `{"status":"rejected","reason":"${reason}"}`;
    assert.equal(Buffer.from(encodeVerificationOutcome(rejected)).toString(), exact);
    assert.deepEqual(decodeVerificationOutcome(utf8(exact)), rejected);
    assert.ok(Object.isFrozen(rejected));
  }
  assert.deepEqual(VerificationStatus, { ACCEPTED: 'accepted', REJECTED: 'rejected' });
  assertInvalid(() => VerificationOutcome.accepted('ignored'));
  assertInvalid(() => VerificationOutcome.rejected(RejectionReason.EXPIRED, 'ignored'));
});

test('duplicate keys are rejected at every nesting depth and after escape decoding', () => {
  for (const json of [
    '{"status":"accepted","status":"accepted"}',
    '{"challenge_id":"c","nonce":"n","answer":"a","extra":{"same":1,"same":2}}',
    '{"challenge_id":"c","nonce":"n","answer":"a","extra":[{"same":1,"s\\u0061me":2}]}',
    '{"challenge_id":"c","nonce":"n","answer":"a","extra":{"\\\"":1,"\\u0022":2}}',
  ]) assertInvalid(() => decodeVerificationOutcome(utf8(json)));
});

test('strict scanner rejects malformed syntax, trailing roots, and invalid UTF-8', () => {
  for (const bytes of [
    utf8('{"status":"accepted"} {"status":"accepted"}'),
    utf8('{"status":"accepted",}'),
    utf8('{"status":"accepted"'),
    utf8('{status:"accepted"}'),
    utf8('{"status":tru}'),
    utf8('{"status":"accepted"} garbage'),
    Uint8Array.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xc3, 0x28, 0x22, 0x7d]),
  ]) assertInvalid(() => decodeVerificationOutcome(bytes));
});

test('strict scanner accepts JSON whitespace, escapes, arrays, and valid raw Unicode', () => {
  assert.deepEqual(
    decodeSubmission(utf8(' \n\t {"challenge_id":"雪🚀","nonce":"n","answer":"a"}\r ')),
    new Submission({ challengeId: '雪🚀', nonce: 'n', answer: 'a' }),
  );
  assertInvalid(() => decodeSubmission(utf8(
    '{"challenge_id":"c","nonce":"n","answer":"a","extra":[1,true,null,{"x":"y"}]}')));
});

test('lone and unpaired surrogates are rejected in values and keys', () => {
  for (const json of [
    '{"challenge_id":"\\uD800","nonce":"n","answer":"a"}',
    '{"challenge_id":"\\uDC00","nonce":"n","answer":"a"}',
    '{"challenge_id":"\\uD800x","nonce":"n","answer":"a"}',
    '{"\\uD800":"x","nonce":"n","answer":"a"}',
  ]) assertInvalid(() => decodeSubmission(utf8(json)));
  assertInvalid(() => encodeSubmission({ challengeId: 'bad\ud800', nonce: 'n', answer: 'a' }));
});

test('decoders reject missing, extra, wrong-case, wrong-token and non-object roots', () => {
  for (const json of [
    '{"challenge_id":"c","nonce":"n"}',
    '{"challenge_id":"c","nonce":"n","answer":"a","extra":true}',
    '{"Challenge_id":"c","nonce":"n","answer":"a"}',
    '{"challenge_id":1,"nonce":"n","answer":"a"}',
    '{"challenge_id":null,"nonce":"n","answer":"a"}',
    '[]', 'null', '"object"',
  ]) assertInvalid(() => decodeSubmission(utf8(json)));
});

test('public challenge decoder rejects floats, exponents, unsafe integers and enums', () => {
  const make = (issuedAt, encoding = 'base64url') => utf8(
    `{"challenge_id":"c","generator_version":"1.0","nonce":"n",` +
    `"issued_at":${issuedAt},"expires_at":2,"question":"q","answer_encoding":"${encoding}"}`);
  for (const input of [make('1.0'), make('1e0'), make('9007199254740992'), make('1', 'BASE64URL')]) {
    assertInvalid(() => decodePublicChallenge(input));
  }
});

test('outcome decoder rejects unknown status/reason and inconsistent shapes', () => {
  for (const json of [
    '{"status":"unknown"}',
    '{"status":"rejected","reason":"unknown"}',
    '{"status":"rejected"}',
    '{"status":"accepted","reason":"expired"}',
    '{"Status":"accepted"}',
  ]) assertInvalid(() => decodeVerificationOutcome(utf8(json)));
});

test('encoders accept only exact model instances and never pass through extra fields', () => {
  const submission = new Submission({ challengeId: 'c', nonce: 'n', answer: 'a' });
  assert.equal(Buffer.from(encodeSubmission(submission)).toString(),
    '{"challenge_id":"c","nonce":"n","answer":"a"}');
  assertInvalid(() => encodeSubmission({ challengeId: 'c', nonce: 'n', answer: 'a' }));
  assertInvalid(() => encodePublicChallenge({}));
  assertInvalid(() => encodeVerificationOutcome({ status: 'accepted' }));
});

test('encoders reject objects forged from public model prototypes', () => {
  const forgedSubmission = Object.assign(Object.create(Submission.prototype), {
    challengeId: 'c', nonce: 'n', answer: 'a',
  });
  const forgedChallenge = Object.assign(Object.create(PublicChallenge.prototype), {
    challengeId: 'c', generatorVersion: '1.0', nonce: 'n', issuedAt: 1, expiresAt: 2,
    question: 'q', answerEncoding: AnswerEncoding.BASE64URL,
  });
  const forgedOutcome = Object.assign(Object.create(VerificationOutcome.prototype), {
    status: VerificationStatus.ACCEPTED, reason: null,
  });
  assertInvalid(() => encodeSubmission(forgedSubmission));
  assertInvalid(() => encodePublicChallenge(forgedChallenge));
  assertInvalid(() => encodeVerificationOutcome(forgedOutcome));
});

test('native status mapping is exact and unknown values fail closed', () => {
  assert.equal(errorForStatus(0), null);
  const statuses = [1, 2, 3, 4, 5, 6, 7, 100, 101, 102];
  const codes = [
    'invalid_configuration', 'generation_failed', 'invalid_challenge_material',
    'invalid_answer_encoding', 'answer_mismatch', 'unsupported_generator_version',
    'internal_error', 'invalid_argument', 'callback_failed', 'panic_caught',
  ];
  assert.deepEqual(statuses.map((status) => errorForStatus(status).code), codes);
  assert.equal(errorForStatus(-1).code, 'internal_error');
  assert.equal(errorForStatus(999).code, 'internal_error');
});

test('errors expose and render only their stable code', () => {
  const error = errorForStatus(5, new Error('NATIVE_SECRET'));
  assert.ok(error instanceof Error);
  assert.ok(error instanceof AgentGateError);
  assert.deepEqual(Object.keys(error), ['code']);
  assert.equal(error.name, 'AgentGateError');
  assert.equal(error.message, 'answer_mismatch');
  assert.equal(error.stack, undefined);
  assert.equal(error.cause, undefined);
  for (const rendered of [String(error), inspect(error), JSON.stringify(error)]) {
    assert.equal(rendered.includes('answer_mismatch'), true);
    assert.equal(rendered.includes('NATIVE_SECRET'), false);
  }
});
