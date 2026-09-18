_STATUS_CODES = {
    0: "ok",
    1: "invalid_configuration",
    2: "generation_failed",
    3: "invalid_challenge_material",
    4: "invalid_answer_encoding",
    5: "answer_mismatch",
    6: "unsupported_generator_version",
    7: "internal_error",
    100: "invalid_argument",
    101: "callback_failed",
    102: "panic_caught",
}


def code_for_status(status):
    if type(status) is not int or status not in _STATUS_CODES:
        raise ValueError("invalid CogGate status")
    return _STATUS_CODES[status]


class CogGateError(RuntimeError):
    def __init__(self, status):
        self.status = status
        self.code = code_for_status(status)
        super().__init__(self.code)

    def __repr__(self):
        return "CogGateError(code={!r})".format(self.code)
