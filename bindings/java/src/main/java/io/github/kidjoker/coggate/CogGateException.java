package io.github.kidjoker.coggate;

/** Detail-free exception exposing only a stable CogGate error code. */
public final class CogGateException extends RuntimeException {
  private final String code;

  private CogGateException(String code) {
    super(code, null, false, false);
    this.code = code;
  }

  /** Returns null for success, otherwise an exception for the native status. */
  public static CogGateException fromStatus(int status) {
    String code = switch (status) {
      case 0 -> null;
      case 1 -> "invalid_configuration";
      case 2 -> "generation_failed";
      case 3 -> "invalid_challenge_material";
      case 4 -> "invalid_answer_encoding";
      case 5 -> "answer_mismatch";
      case 6 -> "unsupported_generator_version";
      case 7 -> "internal_error";
      case 100 -> "invalid_argument";
      case 101 -> "callback_failed";
      case 102 -> "panic_caught";
      default -> "internal_error";
    };
    return code == null ? null : new CogGateException(code);
  }

  static CogGateException invalidArgument() {
    return new CogGateException("invalid_argument");
  }

  public String code() {
    return code;
  }

  @Override
  public String toString() {
    return code;
  }
}
