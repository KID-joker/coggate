import { inspect } from 'node:util';

import { invalidArgument } from './errors.js';

export const AttemptLimit = Object.freeze({ ONE: 1, TWO: 2 });
export const AnswerEncoding = Object.freeze({ BASE64URL: 'base64url' });
export const VerificationStatus = Object.freeze({ ACCEPTED: 'accepted', REJECTED: 'rejected' });
export const RejectionReason = Object.freeze({
  NOT_FOUND: 'not_found',
  EXPIRED: 'expired',
  ALREADY_CONSUMED: 'already_consumed',
  BINDING_MISMATCH: 'binding_mismatch',
  NONCE_MISMATCH: 'nonce_mismatch',
  ATTEMPTS_EXHAUSTED: 'attempts_exhausted',
});

const attemptLimits = new Set(Object.values(AttemptLimit));
const answerEncodings = new Set(Object.values(AnswerEncoding));
const rejectionReasons = new Set(Object.values(RejectionReason));
function exactPlainObject(value, keys) {
  if (value === null || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) {
    throw invalidArgument();
  }
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.length !== keys.length || ownKeys.some((key) => typeof key !== 'string') ||
      keys.some((key) => !ownKeys.includes(key))) {
    throw invalidArgument();
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw invalidArgument();
  }
}

function validString(value) {
  if (typeof value !== 'string') return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (++index >= value.length) return false;
      const low = value.charCodeAt(index);
      if (low < 0xdc00 || low > 0xdfff) return false;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function requireString(value) {
  if (!validString(value)) throw invalidArgument();
}

function redactPrototype(prototype, label) {
  Object.defineProperties(prototype, {
    toString: { configurable: true, value: () => `${label}()` },
    toJSON: { configurable: true, value: () => `${label}()` },
    [inspect.custom]: { configurable: true, value: () => `${label}()` },
  });
  Object.freeze(prototype);
}

export class IssueRequest {
  #binding;
  #brand;

  constructor(value) {
    if (arguments.length !== 1) throw invalidArgument();
    exactPlainObject(value, ['version', 'binding', 'attemptLimit']);
    requireString(value.version);
    if (!(value.binding instanceof Uint8Array) || value.binding.byteLength < 1 ||
        value.binding.byteLength > 256 || !attemptLimits.has(value.attemptLimit)) {
      throw invalidArgument();
    }
    this.#binding = Uint8Array.from(value.binding);
    Object.defineProperties(this, {
      version: { enumerable: true, value: value.version },
      binding: { enumerable: true, get: () => Uint8Array.from(this.#binding) },
      attemptLimit: { enumerable: true, value: value.attemptLimit },
    });
    Object.freeze(this);
  }

  static is(value) {
    return typeof value === 'object' && value !== null && #brand in value;
  }
}

redactPrototype(IssueRequest.prototype, 'IssueRequest');
Object.freeze(IssueRequest);

export function newV1IssueRequest(binding) {
  if (arguments.length !== 1) throw invalidArgument();
  return new IssueRequest({ version: '1.0', binding, attemptLimit: AttemptLimit.ONE });
}

export class PublicChallenge {
  #brand;

  constructor(value) {
    if (arguments.length !== 1) throw invalidArgument();
    const keys = [
      'challengeId', 'generatorVersion', 'nonce', 'issuedAt', 'expiresAt', 'question',
      'answerEncoding',
    ];
    exactPlainObject(value, keys);
    for (const key of ['challengeId', 'generatorVersion', 'nonce', 'question']) requireString(value[key]);
    if (!Number.isSafeInteger(value.issuedAt) || !Number.isSafeInteger(value.expiresAt) ||
        !answerEncodings.has(value.answerEncoding)) {
      throw invalidArgument();
    }
    for (const key of keys) {
      Object.defineProperty(this, key, { enumerable: true, value: value[key] });
    }
    Object.freeze(this);
  }

  static is(value) {
    return typeof value === 'object' && value !== null && #brand in value;
  }
}

redactPrototype(PublicChallenge.prototype, 'PublicChallenge');
Object.freeze(PublicChallenge);

export class Submission {
  #brand;

  constructor(value) {
    if (arguments.length !== 1) throw invalidArgument();
    const keys = ['challengeId', 'nonce', 'answer'];
    exactPlainObject(value, keys);
    for (const key of keys) requireString(value[key]);
    for (const key of keys) {
      Object.defineProperty(this, key, { enumerable: true, value: value[key] });
    }
    Object.freeze(this);
  }

  static is(value) {
    return typeof value === 'object' && value !== null && #brand in value;
  }
}

redactPrototype(Submission.prototype, 'Submission');
Object.freeze(Submission);

const outcomeToken = Symbol('VerificationOutcome');

export class VerificationOutcome {
  #brand;

  constructor(token, status, reason) {
    if (token !== outcomeToken) throw invalidArgument();
    Object.defineProperty(this, 'status', { enumerable: true, value: status });
    Object.defineProperty(this, 'reason', { enumerable: true, value: reason });
    Object.freeze(this);
  }

  static accepted() {
    if (arguments.length !== 0) throw invalidArgument();
    return new VerificationOutcome(outcomeToken, VerificationStatus.ACCEPTED, null);
  }

  static rejected(reason) {
    if (arguments.length !== 1 || !rejectionReasons.has(reason)) throw invalidArgument();
    return new VerificationOutcome(outcomeToken, VerificationStatus.REJECTED, reason);
  }

  static is(value) {
    return typeof value === 'object' && value !== null && #brand in value;
  }
}

redactPrototype(VerificationOutcome.prototype, 'VerificationOutcome');
Object.freeze(VerificationOutcome);
