export interface Winner {
  github_login: string;
  profile_url: string;
  submission_id: string;
}

export interface Quota {
  used_today: number;
  remaining_today: number;
}

export interface Arena {
  round_id: string;
  epoch: number;
  status: 'PREPARING' | 'OPEN' | 'SOLVED' | 'MAINTENANCE' | 'ARCHIVED';
  sdk_version: string;
  sdk_commit: string;
  generator_version: string;
  supported_languages: Language[];
  daily_limit: number;
  source_limit_bytes: number;
  winner: Winner | null;
  issue_url: string | null;
}

export type Language = 'c' | 'cpp' | 'rust' | 'go' | 'java' | 'python' | 'node';

export interface Challenge {
  challenge_id: string;
  generator_version: string;
  nonce: string;
  issued_at: number;
  expires_at: number;
  question: string;
  answer_encoding: 'base64url';
}

export interface Preview {
  round_id: string;
  epoch: number;
  challenge: Challenge;
}

export interface Me {
  github_id: number;
  github_login: string;
  quota: Quota;
}

export interface Execution {
  compile_ms: number | null;
  run_ms: number | null;
  exit_code: number | null;
  compile_output: string | null;
  stdout: string | null;
  stderr: string | null;
  output_encoding: string | null;
  stdout_truncated: boolean;
  stderr_truncated: boolean;
}

export interface Submission {
  submission_id: string;
  status: string;
  language: Language;
  source_sha256: string;
  challenge: Challenge | null;
  execution: Execution;
  verification_disposition: string | null;
  quota: Quota;
  arena_status: string;
  winner: Winner | null;
}

export interface Accepted {
  submission_id: string;
  created: boolean;
  quota: Quota;
}

export interface Draft {
  epoch: number;
  language: Language;
  source: string;
  publication_agreed: boolean;
  idempotency_key: string;
}

export interface ApiErrorBody {
  error?: string;
  submission_id?: string;
}
