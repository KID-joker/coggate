package io.github.kidjoker.coggate;

/** Durable challenge lifecycle callbacks. Inputs are independent byte-array copies. */
public interface Lifecycle {
  enum Status {
    OK(0), UNAVAILABLE(1), CONFLICT(2), INTERNAL(3);

    private final int value;
    Status(int value) { this.value = value; }
    public int value() { return value; }
  }

  enum BeginStatus {
    OK(0), UNAVAILABLE(1), CONFLICT(2), INTERNAL(3), NOT_FOUND(10), EXPIRED(11),
    ALREADY_CONSUMED(12), BINDING_MISMATCH(13), NONCE_MISMATCH(14), ATTEMPTS_EXHAUSTED(15);

    private final int value;
    BeginStatus(int value) { this.value = value; }
    public int value() { return value; }
  }

  enum AttemptOutcome {
    ACCEPTED(1), REJECTED(2), SYSTEM_FAILURE(3);

    private final int value;
    AttemptOutcome(int value) { this.value = value; }
    public int value() { return value; }
  }

  /** A closed begin status plus private material and an optional opaque token. */
  final class BeginResult {
    private final BeginStatus status;
    private final byte[] material;
    private final byte[] token;

    public BeginResult(BeginStatus status, byte[] material, byte[] token) {
      if (status == null) throw new IllegalArgumentException("invalid lifecycle result");
      this.status = status;
      this.material = material == null ? null : material.clone();
      this.token = token == null ? null : token.clone();
    }

    public BeginStatus status() { return status; }
    public byte[] material() { return material == null ? null : material.clone(); }
    public byte[] token() { return token == null ? null : token.clone(); }
    @Override public String toString() { return "BeginResult()"; }
  }

  Status storeIssued(byte[] privateJson, byte[] binding, AttemptLimit limit);
  BeginResult beginAttempt(byte[] identityJson, byte[] binding, long serverTime);
  Status finishAttempt(byte[] token, AttemptOutcome outcome);
}
