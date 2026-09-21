PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    github_id INTEGER PRIMARY KEY,
    github_login TEXT NOT NULL,
    last_login_at INTEGER NOT NULL,
    disabled_at INTEGER
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash TEXT PRIMARY KEY,
    github_id INTEGER NOT NULL REFERENCES users(github_id),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_sessions_expires_idx ON auth_sessions(expires_at);

CREATE TABLE IF NOT EXISTS oauth_states (
    state_hash TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
);
CREATE INDEX IF NOT EXISTS oauth_states_expires_idx ON oauth_states(expires_at);

CREATE TABLE IF NOT EXISTS arena_rounds (
    id TEXT PRIMARY KEY,
    epoch INTEGER NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK(status IN ('PREPARING','OPEN','SOLVED','MAINTENANCE','ARCHIVED')),
    sdk_version TEXT NOT NULL,
    sdk_commit TEXT NOT NULL,
    generator_version TEXT NOT NULL,
    runner_manifest_digest TEXT NOT NULL,
    winner_github_id INTEGER REFERENCES users(github_id),
    winner_github_login TEXT,
    winner_submission_id TEXT UNIQUE,
    opened_at INTEGER,
    solved_at INTEGER,
    CHECK (
        (winner_github_id IS NULL AND winner_github_login IS NULL AND winner_submission_id IS NULL AND solved_at IS NULL AND status <> 'SOLVED')
        OR
        (winner_github_id IS NOT NULL AND winner_github_login IS NOT NULL AND winner_submission_id IS NOT NULL AND solved_at IS NOT NULL AND status IN ('SOLVED','ARCHIVED'))
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS one_open_round ON arena_rounds(status) WHERE status = 'OPEN';
CREATE UNIQUE INDEX IF NOT EXISTS one_preparing_round ON arena_rounds(status) WHERE status = 'PREPARING';

CREATE TABLE IF NOT EXISTS daily_quotas (
    github_id INTEGER NOT NULL REFERENCES users(github_id),
    quota_date TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0 CHECK(used >= 0),
    manual_credit INTEGER NOT NULL DEFAULT 0 CHECK(manual_credit >= 0),
    PRIMARY KEY(github_id, quota_date)
);

CREATE TABLE IF NOT EXISTS submissions (
    id TEXT PRIMARY KEY,
    round_id TEXT NOT NULL REFERENCES arena_rounds(id),
    epoch INTEGER NOT NULL,
    github_id INTEGER NOT NULL REFERENCES users(github_id),
    idempotency_key TEXT NOT NULL,
    language TEXT NOT NULL CHECK(language IN ('c','cpp','rust','go','java','python','node')),
    source TEXT,
    source_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN (
        'ACCEPTED','COMPILING','COMPILE_ERROR','READY','CHALLENGE_ISSUED','RUNNING',
        'RUNTIME_ERROR','TIMED_OUT','OUTPUT_LIMIT_EXCEEDED','INVALID_OUTPUT','CHALLENGE_EXPIRED',
        'VERIFYING','WRONG_ANSWER','VERIFIED_ACCEPTED_PENDING_FINALIZE','PASSED',
        'CORRECT_BUT_LOST_RACE','ARENA_CLOSED','INTERNAL_ERROR'
    )),
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    finished_at INTEGER,
    worker_id TEXT,
    lease_id TEXT,
    lease_expires_at INTEGER,
    heartbeat_at INTEGER,
    execution_attempt INTEGER NOT NULL DEFAULT 0,
    challenge_id TEXT,
    public_challenge_json TEXT,
    verification_deadline INTEGER,
    compile_ms INTEGER,
    run_ms INTEGER,
    exit_code INTEGER,
    compile_output TEXT,
    stdout TEXT,
    stderr TEXT,
    output_encoding TEXT,
    stdout_truncated INTEGER NOT NULL DEFAULT 0,
    stderr_truncated INTEGER NOT NULL DEFAULT 0,
    verification_disposition TEXT,
    runner_image_digest TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    result_expires_at INTEGER,
    UNIQUE(github_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS submissions_status_created_idx ON submissions(status, created_at);
CREATE INDEX IF NOT EXISTS submissions_user_status_idx ON submissions(github_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS one_inflight_submission_per_user
ON submissions(github_id)
WHERE status IN ('ACCEPTED','COMPILING','READY','CHALLENGE_ISSUED','RUNNING','VERIFYING','VERIFIED_ACCEPTED_PENDING_FINALIZE');

CREATE TABLE IF NOT EXISTS challenge_lifecycle (
    challenge_id TEXT PRIMARY KEY,
    submission_id TEXT REFERENCES submissions(id),
    private_material_json TEXT NOT NULL,
    binding BLOB NOT NULL,
    nonce TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('ISSUED','RESERVED','ACCEPTED','REJECTED','SYSTEM_FAILURE','EXPIRED')),
    attempts_remaining INTEGER NOT NULL CHECK(attempts_remaining >= 0),
    reservation_token TEXT,
    outcome TEXT,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS lifecycle_expires_idx ON challenge_lifecycle(expires_at);

CREATE TABLE IF NOT EXISTS outbox (
    id TEXT PRIMARY KEY,
    round_id TEXT NOT NULL REFERENCES arena_rounds(id),
    submission_id TEXT NOT NULL REFERENCES submissions(id),
    event_type TEXT NOT NULL,
    status TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    issue_number INTEGER,
    issue_url TEXT,
    last_error_code TEXT,
    UNIQUE(round_id, event_type)
);
CREATE INDEX IF NOT EXISTS outbox_status_next_idx ON outbox(status, next_attempt_at);

CREATE TABLE IF NOT EXISTS admin_audit (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_id TEXT,
    created_at INTEGER NOT NULL,
    reason_code TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS submission_pending_requires_accepted_lifecycle
BEFORE UPDATE OF status ON submissions
WHEN NEW.status = 'VERIFIED_ACCEPTED_PENDING_FINALIZE'
 AND NOT EXISTS (
    SELECT 1 FROM challenge_lifecycle
    WHERE submission_id = NEW.id AND state = 'ACCEPTED' AND outcome = 'accepted'
 )
BEGIN
    SELECT RAISE(ABORT, 'accepted lifecycle required');
END;

CREATE TRIGGER IF NOT EXISTS passed_submission_must_be_round_winner
BEFORE UPDATE OF status ON submissions
WHEN NEW.status = 'PASSED'
 AND NOT EXISTS (
    SELECT 1 FROM arena_rounds
    WHERE id = NEW.round_id AND winner_submission_id = NEW.id AND status = 'SOLVED'
 )
BEGIN
    SELECT RAISE(ABORT, 'round winner required');
END;

PRAGMA user_version = 1;
