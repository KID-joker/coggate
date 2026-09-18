package io.github.kidjoker.coggate;

import java.util.Objects;

/** A verification result with a closed status and rejection-reason set. */
public final class VerificationOutcome {
  public enum Status {
    ACCEPTED("accepted"),
    REJECTED("rejected");

    private final String wireValue;

    Status(String wireValue) {
      this.wireValue = wireValue;
    }

    public String wireValue() {
      return wireValue;
    }
  }

  public enum RejectionReason {
    NOT_FOUND("not_found"),
    EXPIRED("expired"),
    ALREADY_CONSUMED("already_consumed"),
    BINDING_MISMATCH("binding_mismatch"),
    NONCE_MISMATCH("nonce_mismatch"),
    ATTEMPTS_EXHAUSTED("attempts_exhausted");

    private final String wireValue;

    RejectionReason(String wireValue) {
      this.wireValue = wireValue;
    }

    public String wireValue() {
      return wireValue;
    }

    static RejectionReason fromWireValue(String value) {
      for (RejectionReason reason : values()) {
        if (reason.wireValue.equals(value)) {
          return reason;
        }
      }
      throw CogGateException.invalidArgument();
    }
  }

  private final Status status;
  private final RejectionReason reason;

  private VerificationOutcome(Status status, RejectionReason reason) {
    this.status = Objects.requireNonNull(status, "status");
    this.reason = reason;
  }

  public static VerificationOutcome accepted() {
    return new VerificationOutcome(Status.ACCEPTED, null);
  }

  public static VerificationOutcome rejected(RejectionReason reason) {
    return new VerificationOutcome(Status.REJECTED, Objects.requireNonNull(reason, "reason"));
  }

  public Status status() {
    return status;
  }

  public RejectionReason reason() {
    return reason;
  }

  @Override
  public boolean equals(Object other) {
    return this == other
        || (other instanceof VerificationOutcome outcome
            && status == outcome.status
            && reason == outcome.reason);
  }

  @Override
  public int hashCode() {
    return Objects.hash(status, reason);
  }

  @Override
  public String toString() {
    return "VerificationOutcome()";
  }
}
