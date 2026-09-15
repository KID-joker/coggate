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
const uint8ArrayPrototype = Uint8Array.prototype;
const uint8ArraySlice = Uint8Array.prototype.slice;

function exactPlainObject(value, keys) {
  try {
    if (value === null || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) {
      throw invalidArgument();
    }
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.length !== keys.length || ownKeys.some((key) => typeof key !== 'string') ||
        keys.some((key) => !ownKeys.includes(key))) {
      throw invalidArgument();
    }
    const fields = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw invalidArgument();
      fields[key] = descriptor.value;
    }
    return fields;
  } catch {
    throw invalidArgument();
  }
}

function requireExactConstruction(instance, newTarget, target) {
  if (newTarget !== target || Object.getPrototypeOf(instance) !== target.prototype ||
      instance.constructor !== target) {
    throw invalidArgument();
  }
}

function copyBinding(value) {
  try {
    if (!ArrayBuffer.isView(value) || Object.getPrototypeOf(value) !== uint8ArrayPrototype) {
      throw invalidArgument();
    }
    const copied = uint8ArraySlice.call(value);
    if (copied.byteLength < 1 || copied.byteLength > 256) throw invalidArgument();
    return copied;
  } catch {
    throw invalidArgument();
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
    requireExactConstruction(this, new.target, IssueRequest);
    const fields = exactPlainObject(value, ['version', 'binding', 'attemptLimit']);
    requireString(fields.version);
    if (!attemptLimits.has(fields.attemptLimit)) throw invalidArgument();
    this.#binding = copyBinding(fields.binding);
    Object.defineProperties(this, {
      version: { enumerable: true, value: fields.version },
      binding: { enumerable: true, get: () => uint8ArraySlice.call(this.#binding) },
      attemptLimit: { enumerable: true, value: fields.attemptLimit },
    });
    Object.freeze(this);
  }

  static is(value) {
    return typeof value === 'object' && value !== null && #brand in value &&
      Object.getPrototypeOf(value) === IssueRequest.prototype && value.constructor === IssueRequest;
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
    requireExactConstruction(this, new.target, PublicChallenge);
    const keys = [
      'challengeId', 'generatorVersion', 'nonce', 'issuedAt', 'expiresAt', 'question',
      'answerEncoding',
    ];
    const fields = exactPlainObject(value, keys);
    for (const key of ['challengeId', 'generatorVersion', 'nonce', 'question']) requireString(fields[key]);
    if (!Number.isSafeInteger(fields.issuedAt) || !Number.isSafeInteger(fields.expiresAt) ||
        !answerEncodings.has(fields.answerEncoding)) {
      throw invalidArgument();
    }
    for (const key of keys) {
      Object.defineProperty(this, key, { enumerable: true, value: fields[key] });
    }
    Object.freeze(this);
  }

  static is(value) {
    return typeof value === 'object' && value !== null && #brand in value &&
      Object.getPrototypeOf(value) === PublicChallenge.prototype && value.constructor === PublicChallenge;
  }
}

redactPrototype(PublicChallenge.prototype, 'PublicChallenge');
Object.freeze(PublicChallenge);

export class Submission {
  #brand;

  constructor(value) {
    if (arguments.length !== 1) throw invalidArgument();
    requireExactConstruction(this, new.target, Submission);
    const keys = ['challengeId', 'nonce', 'answer'];
    const fields = exactPlainObject(value, keys);
    for (const key of keys) requireString(fields[key]);
    for (const key of keys) {
      Object.defineProperty(this, key, { enumerable: true, value: fields[key] });
    }
    Object.freeze(this);
  }

  static is(value) {
    return typeof value === 'object' && value !== null && #brand in value &&
      Object.getPrototypeOf(value) === Submission.prototype && value.constructor === Submission;
  }
}

redactPrototype(Submission.prototype, 'Submission');
Object.freeze(Submission);

const outcomeToken = Symbol('VerificationOutcome');

export class VerificationOutcome {
  #brand;

  constructor(token, status, reason) {
    requireExactConstruction(this, new.target, VerificationOutcome);
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
    return typeof value === 'object' && value !== null && #brand in value &&
      Object.getPrototypeOf(value) === VerificationOutcome.prototype &&
      value.constructor === VerificationOutcome;
  }
}

redactPrototype(VerificationOutcome.prototype, 'VerificationOutcome');
Object.freeze(VerificationOutcome);
