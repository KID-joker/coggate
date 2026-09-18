import json
from dataclasses import dataclass
from enum import Enum, IntEnum


_I64_MIN = -(2 ** 63)
_I64_MAX = 2 ** 63 - 1


def _invalid_json():
    raise ValueError("invalid CogGate JSON")


def _object_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _invalid_json()
        result[key] = value
    return result


def _parse_object(payload):
    if type(payload) is not str:
        _invalid_json()
    try:
        value = json.loads(payload, object_pairs_hook=_object_without_duplicates)
    except (json.JSONDecodeError, UnicodeError):
        _invalid_json()
    if type(value) is not dict:
        _invalid_json()
    return value


def _require_keys(value, keys):
    if set(value) != set(keys) or len(value) != len(keys):
        _invalid_json()


def _require_string(value, key):
    item = value[key]
    if not _is_utf8_string(item):
        _invalid_json()
    return item


def _is_utf8_string(value):
    if type(value) is not str:
        return False
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    return True


def _require_i64(value, key):
    item = value[key]
    if type(item) is not int or not _I64_MIN <= item <= _I64_MAX:
        _invalid_json()
    return item


def _dump(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


class _SafeModel:
    def __repr__(self):
        return "{}()".format(type(self).__name__)

    __str__ = __repr__


class AttemptLimit(IntEnum):
    ONE = 1
    TWO = 2


@dataclass(frozen=True, repr=False)
class IssueRequest(_SafeModel):
    version: str
    binding: bytes
    attempt_limit: AttemptLimit = AttemptLimit.ONE

    def __post_init__(self):
        if not _is_utf8_string(self.version):
            raise ValueError("invalid CogGate version")
        if type(self.binding) is not bytes or not 1 <= len(self.binding) <= 256:
            raise ValueError("invalid CogGate binding")
        if type(self.attempt_limit) is not AttemptLimit:
            raise ValueError("invalid CogGate attempt limit")

    @classmethod
    def v1(cls, binding, attempt_limit=AttemptLimit.ONE):
        return cls("1.0", binding, attempt_limit)


@dataclass(frozen=True, repr=False)
class Submission(_SafeModel):
    challenge_id: str
    nonce: str
    answer: str

    def __post_init__(self):
        if any(not _is_utf8_string(value) for value in (self.challenge_id, self.nonce, self.answer)):
            raise ValueError("invalid CogGate JSON")

    @classmethod
    def from_json(cls, payload):
        value = _parse_object(payload)
        _require_keys(value, ("challenge_id", "nonce", "answer"))
        return cls(
            _require_string(value, "challenge_id"),
            _require_string(value, "nonce"),
            _require_string(value, "answer"),
        )

    def to_json(self):
        return _dump({
            "challenge_id": self.challenge_id,
            "nonce": self.nonce,
            "answer": self.answer,
        })


class AnswerEncoding(Enum):
    BASE64URL = "base64url"


@dataclass(frozen=True, repr=False)
class PublicChallenge(_SafeModel):
    challenge_id: str
    generator_version: str
    nonce: str
    issued_at: int
    expires_at: int
    question: str
    answer_encoding: AnswerEncoding

    def __post_init__(self):
        text = (self.challenge_id, self.generator_version, self.nonce, self.question)
        if any(not _is_utf8_string(value) for value in text):
            _invalid_json()
        if any(type(value) is not int or not _I64_MIN <= value <= _I64_MAX for value in (self.issued_at, self.expires_at)):
            _invalid_json()
        if type(self.answer_encoding) is not AnswerEncoding:
            _invalid_json()

    @classmethod
    def from_json(cls, payload):
        value = _parse_object(payload)
        keys = (
            "challenge_id", "generator_version", "nonce", "issued_at",
            "expires_at", "question", "answer_encoding",
        )
        _require_keys(value, keys)
        encoding = _require_string(value, "answer_encoding")
        if encoding != AnswerEncoding.BASE64URL.value:
            _invalid_json()
        return cls(
            _require_string(value, "challenge_id"),
            _require_string(value, "generator_version"),
            _require_string(value, "nonce"),
            _require_i64(value, "issued_at"),
            _require_i64(value, "expires_at"),
            _require_string(value, "question"),
            AnswerEncoding.BASE64URL,
        )

    def to_json(self):
        return _dump({
            "challenge_id": self.challenge_id,
            "generator_version": self.generator_version,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "question": self.question,
            "answer_encoding": self.answer_encoding.value,
        })


class VerificationStatus(Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class RejectionReason(Enum):
    NOT_FOUND = "not_found"
    EXPIRED = "expired"
    ALREADY_CONSUMED = "already_consumed"
    BINDING_MISMATCH = "binding_mismatch"
    NONCE_MISMATCH = "nonce_mismatch"
    ATTEMPTS_EXHAUSTED = "attempts_exhausted"


@dataclass(frozen=True, repr=False)
class VerificationOutcome(_SafeModel):
    status: VerificationStatus
    reason: object = None

    def __post_init__(self):
        valid = (
            self.status is VerificationStatus.ACCEPTED and self.reason is None
        ) or (
            self.status is VerificationStatus.REJECTED
            and type(self.reason) is RejectionReason
        )
        if not valid:
            _invalid_json()

    @classmethod
    def accepted(cls):
        return cls(VerificationStatus.ACCEPTED)

    @classmethod
    def rejected(cls, reason):
        return cls(VerificationStatus.REJECTED, reason)

    @classmethod
    def from_json(cls, payload):
        value = _parse_object(payload)
        status = _require_string(value, "status") if "status" in value else _invalid_json()
        if status == VerificationStatus.ACCEPTED.value:
            _require_keys(value, ("status",))
            return cls.accepted()
        if status != VerificationStatus.REJECTED.value:
            _invalid_json()
        _require_keys(value, ("status", "reason"))
        try:
            reason = RejectionReason(_require_string(value, "reason"))
        except ValueError:
            _invalid_json()
        return cls.rejected(reason)

    def to_json(self):
        value = {"status": self.status.value}
        if self.reason is not None:
            value["reason"] = self.reason.value
        return _dump(value)
