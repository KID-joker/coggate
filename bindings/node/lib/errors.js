import { inspect } from 'node:util';

const STATUS_CODES = new Map([
  [1, 'invalid_configuration'],
  [2, 'generation_failed'],
  [3, 'invalid_challenge_material'],
  [4, 'invalid_answer_encoding'],
  [5, 'answer_mismatch'],
  [6, 'unsupported_generator_version'],
  [7, 'internal_error'],
  [100, 'invalid_argument'],
  [101, 'callback_failed'],
  [102, 'panic_caught'],
]);

const STABLE_CODES = new Set(STATUS_CODES.values());

export class CogGateError extends Error {
  constructor(code) {
    const stableCode = STABLE_CODES.has(code) ? code : 'internal_error';
    super(stableCode);
    Object.defineProperty(this, 'name', {
      configurable: false,
      enumerable: false,
      value: 'CogGateError',
      writable: false,
    });
    Object.defineProperty(this, 'code', {
      configurable: false,
      enumerable: true,
      value: stableCode,
      writable: false,
    });
    delete this.stack;
    Object.freeze(this);
  }

  toString() {
    return this.code;
  }

  toJSON() {
    return { code: this.code };
  }

  [inspect.custom]() {
    return `CogGateError(${this.code})`;
  }
}

Object.freeze(CogGateError.prototype);

export function errorForStatus(status) {
  if (status === 0) return null;
  return new CogGateError(STATUS_CODES.get(status) ?? 'internal_error');
}

export function invalidArgument() {
  return new CogGateError('invalid_argument');
}
