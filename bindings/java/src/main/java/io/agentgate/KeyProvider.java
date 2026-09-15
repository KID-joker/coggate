package io.agentgate;

/** Supplies the active signing key and exact historical key lookups. */
public interface KeyProvider {
  enum Status {
    OK(0), UNAVAILABLE(1), NOT_FOUND(2), INVALID_MATERIAL(3);

    private final int value;
    Status(int value) { this.value = value; }
    public int value() { return value; }
  }

  /** Active key identifier and bytes. Both values are defensively copied. */
  final class ActiveResult {
    private final Status status;
    private final byte[] keyId;
    private final byte[] key;

    public ActiveResult(Status status, byte[] keyId, byte[] key) {
      if (status == null) throw new IllegalArgumentException("invalid key result");
      this.status = status;
      this.keyId = keyId == null ? null : keyId.clone();
      this.key = key == null ? null : key.clone();
    }

    public Status status() { return status; }
    public byte[] keyId() { return keyId == null ? null : keyId.clone(); }
    public byte[] key() { return key == null ? null : key.clone(); }
    @Override public String toString() { return "ActiveResult()"; }
  }

  /** Key bytes for an exact identifier lookup. */
  final class Result {
    private final Status status;
    private final byte[] key;

    public Result(Status status, byte[] key) {
      if (status == null) throw new IllegalArgumentException("invalid key result");
      this.status = status;
      this.key = key == null ? null : key.clone();
    }

    public Status status() { return status; }
    public byte[] key() { return key == null ? null : key.clone(); }
    @Override public String toString() { return "Result()"; }
  }

  ActiveResult activeKey();
  Result keyById(byte[] keyId);
}
