export type StableErrorCode =
  | 'invalid_configuration'
  | 'generation_failed'
  | 'invalid_challenge_material'
  | 'invalid_answer_encoding'
  | 'answer_mismatch'
  | 'unsupported_generator_version'
  | 'internal_error'
  | 'invalid_argument'
  | 'callback_failed'
  | 'panic_caught';

export class CogGateError extends Error {
  readonly code: StableErrorCode;
  constructor(code: StableErrorCode);
  toJSON(): { code: StableErrorCode };
}

export function errorForStatus(status: number): CogGateError | null;

export const AttemptLimit: Readonly<{ ONE: 1; TWO: 2 }>;
export const AnswerEncoding: Readonly<{ BASE64URL: 'base64url' }>;
export const VerificationStatus: Readonly<{ ACCEPTED: 'accepted'; REJECTED: 'rejected' }>;
export const RejectionReason: Readonly<{
  NOT_FOUND: 'not_found';
  EXPIRED: 'expired';
  ALREADY_CONSUMED: 'already_consumed';
  BINDING_MISMATCH: 'binding_mismatch';
  NONCE_MISMATCH: 'nonce_mismatch';
  ATTEMPTS_EXHAUSTED: 'attempts_exhausted';
}>;

export type AttemptLimitValue = 1 | 2;
export type AnswerEncodingValue = 'base64url';
export type RejectionReasonValue = typeof RejectionReason[keyof typeof RejectionReason];

export class IssueRequest {
  readonly version: string;
  readonly binding: Uint8Array;
  readonly attemptLimit: AttemptLimitValue;
  constructor(value: { version: string; binding: Uint8Array; attemptLimit: AttemptLimitValue });
  static is(value: unknown): value is IssueRequest;
}

export function newV1IssueRequest(binding: Uint8Array): IssueRequest;

export class PublicChallenge {
  readonly challengeId: string;
  readonly generatorVersion: string;
  readonly nonce: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly question: string;
  readonly answerEncoding: AnswerEncodingValue;
  constructor(value: {
    challengeId: string;
    generatorVersion: string;
    nonce: string;
    issuedAt: number;
    expiresAt: number;
    question: string;
    answerEncoding: AnswerEncodingValue;
  });
  static is(value: unknown): value is PublicChallenge;
}

export class Submission {
  readonly challengeId: string;
  readonly nonce: string;
  readonly answer: string;
  constructor(value: { challengeId: string; nonce: string; answer: string });
  static is(value: unknown): value is Submission;
}

export class VerificationOutcome {
  readonly status: 'accepted' | 'rejected';
  readonly reason: RejectionReasonValue | null;
  private constructor();
  static accepted(): VerificationOutcome;
  static rejected(reason: RejectionReasonValue): VerificationOutcome;
  static is(value: unknown): value is VerificationOutcome;
}

export interface LifecycleProvider {
  storeIssued(privateJson: Uint8Array, binding: Uint8Array, attemptLimit: AttemptLimitValue): number;
  beginAttempt(identity: Uint8Array, binding: Uint8Array, serverTime: number): {
    status: number;
    material?: Uint8Array;
    token?: Uint8Array;
  };
  finishAttempt(token: Uint8Array, outcome: number): number;
  released?(tag: string): void;
}

export interface KeyProvider {
  activeKey(): { status: number; keyId?: Uint8Array; key?: Uint8Array };
  keyById(keyId: Uint8Array): { status: number; key?: Uint8Array };
}

export class Service {
  static readonly nativeApiVersion: number;
  constructor(options: {
    lifecycle: LifecycleProvider;
    keys: KeyProvider;
    observer?: (event: Uint8Array) => void;
  });
  issue(request: IssueRequest): PublicChallenge;
  verify(submission: Submission, binding: Uint8Array): VerificationOutcome;
  close(): void;
}

export function decodePublicChallenge(value: Uint8Array): PublicChallenge;
export function decodeSubmission(value: Uint8Array): Submission;
export function decodeVerificationOutcome(value: Uint8Array): VerificationOutcome;
export function encodePublicChallenge(value: PublicChallenge): Uint8Array;
export function encodeSubmission(value: Submission): Uint8Array;
export function encodeVerificationOutcome(value: VerificationOutcome): Uint8Array;
