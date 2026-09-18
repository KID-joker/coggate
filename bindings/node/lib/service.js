import { createRequire } from 'node:module';

import { errorForStatus, invalidArgument } from './errors.js';
import { decodePublicChallenge, decodeVerificationOutcome, encodeSubmission } from './json.js';
import { IssueRequest, Submission } from './models.js';

const require = createRequire(import.meta.url);
const addon = require('../build/Release/coggate.node');
const encoder = new TextEncoder();
const uint8ArrayPrototype = Uint8Array.prototype;
const uint8ArraySlice = Uint8Array.prototype.slice;

function exactObject(value, required) {
  try {
    if (value === null || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) {
      throw invalidArgument();
    }
    const keys = Reflect.ownKeys(value);
    const allowed = new Set([...required, 'observer']);
    if (keys.some((key) => typeof key !== 'string' || !allowed.has(key)) ||
        required.some((key) => !keys.includes(key))) throw invalidArgument();
    const fields = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw invalidArgument();
      }
      fields[key] = descriptor.value;
    }
    return fields;
  } catch { throw invalidArgument(); }
}

function methodObject(value, methods) {
  try {
    if (value === null || typeof value !== 'object') throw invalidArgument();
    for (const method of methods) if (typeof value[method] !== 'function') throw invalidArgument();
  } catch { throw invalidArgument(); }
}

function copyBinding(value) {
  try {
    if (Object.getPrototypeOf(value) !== uint8ArrayPrototype) throw invalidArgument();
    const result = uint8ArraySlice.call(value);
    if (result.length < 1 || result.length > 256) throw invalidArgument();
    return result;
  } catch { throw invalidArgument(); }
}

function check(result) {
  if (result === null || typeof result !== 'object' || !Number.isInteger(result.status)) {
    throw errorForStatus(7);
  }
  const error = errorForStatus(result.status);
  if (error !== null) throw error;
  return result.data;
}

function bridge(target, methods) {
  const reference = new WeakRef(target);
  const result = {};
  for (const method of methods) {
    result[method] = (...args) => {
      const current = reference.deref();
      if (current === undefined) throw invalidArgument();
      const callback = current[method];
      if (callback === undefined && method === 'released') return undefined;
      return callback.apply(current, args);
    };
  }
  return Object.freeze(result);
}

export class Service {
  static nativeApiVersion = addon.napiVersion;
  #handle;
  #lifecycle;
  #keys;
  #observer;
  #closed = false;

  constructor(options) {
    if (arguments.length !== 1) throw invalidArgument();
    let fields;
    try {
      fields = exactObject(options, ['lifecycle', 'keys']);
      methodObject(fields.lifecycle, ['storeIssued', 'beginAttempt', 'finishAttempt']);
      methodObject(fields.keys, ['activeKey', 'keyById']);
      if (fields.observer !== undefined && typeof fields.observer !== 'function') throw invalidArgument();
    } catch { throw invalidArgument(); }
    this.#lifecycle = fields.lifecycle;
    this.#keys = fields.keys;
    this.#observer = fields.observer;
    const lifecycleBridge = bridge(this.#lifecycle,
      ['storeIssued', 'beginAttempt', 'finishAttempt', 'released']);
    const keysBridge = bridge(this.#keys, ['activeKey', 'keyById']);
    const observerReference = this.#observer === undefined ? undefined : new WeakRef(this.#observer);
    const observerBridge = observerReference === undefined ? undefined : Object.freeze({
      observe: (...args) => {
        const current = observerReference.deref();
        if (current !== undefined) return current(...args);
        return undefined;
      },
    });
    const result = addon.create(lifecycleBridge, keysBridge, observerBridge);
    if (result === null || typeof result !== 'object') throw errorForStatus(7);
    const error = errorForStatus(result.status);
    if (error !== null) throw error;
    this.#handle = result.handle;
  }

  issue(request) {
    if (arguments.length !== 1 || !IssueRequest.is(request) || this.#closed) throw invalidArgument();
    const version = encoder.encode(request.version);
    const binding = request.binding;
    try {
      const output = check(addon.issue(this.#handle, version, binding, request.attemptLimit));
      try { return decodePublicChallenge(output); } finally { output.fill(0); }
    } finally {
      version.fill(0);
      binding.fill(0);
    }
  }

  verify(submission, suppliedBinding) {
    if (arguments.length !== 2 || !Submission.is(submission) || this.#closed) throw invalidArgument();
    const binding = copyBinding(suppliedBinding);
    const payload = encodeSubmission(submission);
    try {
      const output = check(addon.verify(this.#handle, payload, binding));
      try { return decodeVerificationOutcome(output); } finally { output.fill(0); }
    } finally {
      payload.fill(0);
      binding.fill(0);
    }
  }

  close() {
    if (arguments.length !== 0) throw invalidArgument();
    if (this.#closed) return;
    const result = addon.destroy(this.#handle);
    const error = errorForStatus(result?.status ?? 7);
    if (error !== null) throw error;
    this.#closed = true;
    this.#lifecycle = undefined;
    this.#keys = undefined;
    this.#observer = undefined;
  }

  toString() { return 'Service()'; }

  static testAllocationCount() { return addon.allocationCount(); }
  static testReleaseCount() { return addon.releaseCount(); }
  static testDestroyCount() { return addon.destroyCount(); }
  static testWipeCount() { return addon.wipeCount(); }
  static testObservationCount() { return addon.observationCount(); }
  static testFailNextNapi() { addon.failNextNapi(); }
}

Object.freeze(Service.prototype);
Object.freeze(Service);
