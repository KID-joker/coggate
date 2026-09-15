import { invalidArgument } from './errors.js';
import {
  AnswerEncoding,
  PublicChallenge,
  Submission,
  VerificationOutcome,
  VerificationStatus,
} from './models.js';

const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();
const integerPattern = /^-?(?:0|[1-9][0-9]*)$/;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedArrayBuffer = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get;
const typedArrayByteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get;
const typedArrayByteOffset = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteOffset').get;
const typedArrayTag = Object.getOwnPropertyDescriptor(
  typedArrayPrototype, Symbol.toStringTag,
).get;
const uint8ArraySet = Uint8Array.prototype.set;

class Scanner {
  constructor(text) {
    this.text = text;
    this.index = 0;
  }

  scan() {
    this.#space();
    const metadata = this.#value();
    this.#space();
    if (this.index !== this.text.length) this.#fail();
    return metadata;
  }

  #value() {
    const current = this.text[this.index];
    if (current === '{') return this.#object();
    if (current === '[') return this.#array();
    if (current === '"') return { kind: 'string', value: this.#string() };
    if (current === '-' || (current >= '0' && current <= '9')) return this.#number();
    for (const literal of ['true', 'false', 'null']) {
      if (this.text.startsWith(literal, this.index)) {
        this.index += literal.length;
        return { kind: literal };
      }
    }
    return this.#fail();
  }

  #object() {
    this.index += 1;
    const fields = new Map();
    this.#space();
    if (this.text[this.index] === '}') {
      this.index += 1;
      return { kind: 'object', fields };
    }
    while (true) {
      if (this.text[this.index] !== '"') this.#fail();
      const key = this.#string();
      if (fields.has(key)) this.#fail();
      this.#space();
      if (this.text[this.index++] !== ':') this.#fail();
      this.#space();
      fields.set(key, this.#value());
      this.#space();
      const delimiter = this.text[this.index++];
      if (delimiter === '}') return { kind: 'object', fields };
      if (delimiter !== ',') this.#fail();
      this.#space();
    }
  }

  #array() {
    this.index += 1;
    const items = [];
    this.#space();
    if (this.text[this.index] === ']') {
      this.index += 1;
      return { kind: 'array', items };
    }
    while (true) {
      items.push(this.#value());
      this.#space();
      const delimiter = this.text[this.index++];
      if (delimiter === ']') return { kind: 'array', items };
      if (delimiter !== ',') this.#fail();
      this.#space();
    }
  }

  #string() {
    const start = this.index;
    this.index += 1;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      if (code === 0x22) {
        this.index += 1;
        const raw = this.text.slice(start, this.index);
        try {
          return JSON.parse(raw);
        } catch {
          this.#fail();
        }
      }
      if (code < 0x20) this.#fail();
      if (code === 0x5c) {
        this.index += 1;
        const escape = this.text[this.index++];
        if ('"\\/bfnrt'.includes(escape)) continue;
        if (escape !== 'u') this.#fail();
        const high = this.#hexCodeUnit();
        if (high >= 0xd800 && high <= 0xdbff) {
          if (this.text[this.index++] !== '\\' || this.text[this.index++] !== 'u') this.#fail();
          const low = this.#hexCodeUnit();
          if (low < 0xdc00 || low > 0xdfff) this.#fail();
        } else if (high >= 0xdc00 && high <= 0xdfff) {
          this.#fail();
        }
        continue;
      }
      if (code >= 0xd800 && code <= 0xdbff) {
        const low = this.text.charCodeAt(this.index + 1);
        if (low < 0xdc00 || low > 0xdfff) this.#fail();
        this.index += 2;
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        this.#fail();
      } else {
        this.index += 1;
      }
    }
    return this.#fail();
  }

  #hexCodeUnit() {
    const hex = this.text.slice(this.index, this.index + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.#fail();
    this.index += 4;
    return Number.parseInt(hex, 16);
  }

  #number() {
    const start = this.index;
    if (this.text[this.index] === '-') this.index += 1;
    if (this.text[this.index] === '0') {
      this.index += 1;
      if (this.text[this.index] >= '0' && this.text[this.index] <= '9') this.#fail();
    } else {
      if (this.text[this.index] < '1' || this.text[this.index] > '9') this.#fail();
      while (this.text[this.index] >= '0' && this.text[this.index] <= '9') this.index += 1;
    }
    if (this.text[this.index] === '.') {
      this.index += 1;
      if (this.text[this.index] < '0' || this.text[this.index] > '9') this.#fail();
      while (this.text[this.index] >= '0' && this.text[this.index] <= '9') this.index += 1;
    }
    if (this.text[this.index] === 'e' || this.text[this.index] === 'E') {
      this.index += 1;
      if (this.text[this.index] === '+' || this.text[this.index] === '-') this.index += 1;
      if (this.text[this.index] < '0' || this.text[this.index] > '9') this.#fail();
      while (this.text[this.index] >= '0' && this.text[this.index] <= '9') this.index += 1;
    }
    return { kind: 'number', raw: this.text.slice(start, this.index) };
  }

  #space() {
    while (' \n\r\t'.includes(this.text[this.index])) this.index += 1;
  }

  #fail() {
    throw invalidArgument();
  }
}

function decodePayload(payload) {
  try {
    if (!ArrayBuffer.isView(payload) || typedArrayTag.call(payload) !== 'Uint8Array') {
      throw invalidArgument();
    }
    const buffer = typedArrayBuffer.call(payload);
    const byteOffset = typedArrayByteOffset.call(payload);
    const byteLength = typedArrayByteLength.call(payload);
    const copy = new Uint8Array(byteLength);
    uint8ArraySet.call(copy, new Uint8Array(buffer, byteOffset, byteLength));
    return decoder.decode(copy);
  } catch {
    throw invalidArgument();
  }
}

function parse(payload) {
  const text = decodePayload(payload);
  let metadata;
  let value;
  try {
    metadata = new Scanner(text).scan();
    value = JSON.parse(text);
  } catch {
    throw invalidArgument();
  }
  return { metadata, value };
}

function exactWireObject(value, metadata, keys) {
  if (metadata.kind !== 'object') throw invalidArgument();
  if (value === null || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) {
    throw invalidArgument();
  }
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.length !== keys.length || ownKeys.some((key) => typeof key !== 'string') ||
      keys.some((key) => !ownKeys.includes(key))) {
    throw invalidArgument();
  }
}

function integerField(value, metadata) {
  return metadata?.kind === 'number' && integerPattern.test(metadata.raw) && Number.isSafeInteger(value);
}

function encode(value) {
  try {
    return encoder.encode(JSON.stringify(value));
  } catch {
    throw invalidArgument();
  }
}

export function decodeSubmission(payload) {
  const { value, metadata } = parse(payload);
  exactWireObject(value, metadata, ['challenge_id', 'nonce', 'answer']);
  return new Submission({
    challengeId: value.challenge_id,
    nonce: value.nonce,
    answer: value.answer,
  });
}

export function encodeSubmission(submission) {
  if (!Submission.is(submission)) throw invalidArgument();
  return encode({
    challenge_id: submission.challengeId,
    nonce: submission.nonce,
    answer: submission.answer,
  });
}

export function decodePublicChallenge(payload) {
  const { value, metadata } = parse(payload);
  const keys = [
    'challenge_id', 'generator_version', 'nonce', 'issued_at', 'expires_at', 'question',
    'answer_encoding',
  ];
  exactWireObject(value, metadata, keys);
  if (!integerField(value.issued_at, metadata.fields.get('issued_at')) ||
      !integerField(value.expires_at, metadata.fields.get('expires_at'))) {
    throw invalidArgument();
  }
  return new PublicChallenge({
    challengeId: value.challenge_id,
    generatorVersion: value.generator_version,
    nonce: value.nonce,
    issuedAt: value.issued_at,
    expiresAt: value.expires_at,
    question: value.question,
    answerEncoding: value.answer_encoding,
  });
}

export function encodePublicChallenge(challenge) {
  if (!PublicChallenge.is(challenge)) throw invalidArgument();
  return encode({
    challenge_id: challenge.challengeId,
    generator_version: challenge.generatorVersion,
    nonce: challenge.nonce,
    issued_at: challenge.issuedAt,
    expires_at: challenge.expiresAt,
    question: challenge.question,
    answer_encoding: challenge.answerEncoding,
  });
}

export function decodeVerificationOutcome(payload) {
  const { value, metadata } = parse(payload);
  if (value?.status === VerificationStatus.ACCEPTED) {
    exactWireObject(value, metadata, ['status']);
    return VerificationOutcome.accepted();
  }
  if (value?.status === VerificationStatus.REJECTED) {
    exactWireObject(value, metadata, ['status', 'reason']);
    return VerificationOutcome.rejected(value.reason);
  }
  throw invalidArgument();
}

export function encodeVerificationOutcome(outcome) {
  if (!VerificationOutcome.is(outcome)) throw invalidArgument();
  if (outcome.status === VerificationStatus.ACCEPTED && outcome.reason === null) {
    return encode({ status: outcome.status });
  }
  if (outcome.status === VerificationStatus.REJECTED) {
    return encode({ status: outcome.status, reason: outcome.reason });
  }
  throw invalidArgument();
}
