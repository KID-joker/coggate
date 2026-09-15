package io.agentgate;

import java.util.Objects;

/** Immutable parameters used to issue a challenge. */
public final class IssueRequest {
  private static final int MAX_BINDING_BYTES = 256;

  private final String version;
  private final byte[] binding;
  private final AttemptLimit attemptLimit;

  public IssueRequest(String version, byte[] binding, AttemptLimit attemptLimit) {
    if (!JsonCodec.isValidUnicode(version)
        || binding == null
        || binding.length == 0
        || binding.length > MAX_BINDING_BYTES
        || attemptLimit == null) {
      throw new IllegalArgumentException("invalid AgentGate issue request");
    }
    this.version = version;
    this.binding = binding.clone();
    this.attemptLimit = attemptLimit;
  }

  /** Creates a protocol 1.0 request with exactly one permitted attempt. */
  public static IssueRequest newV1IssueRequest(byte[] binding) {
    return new IssueRequest("1.0", binding, AttemptLimit.ONE);
  }

  public String version() {
    return version;
  }

  public byte[] binding() {
    return binding.clone();
  }

  public AttemptLimit attemptLimit() {
    return attemptLimit;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof IssueRequest request)) {
      return false;
    }
    return version.equals(request.version)
        && java.util.Arrays.equals(binding, request.binding)
        && attemptLimit == request.attemptLimit;
  }

  @Override
  public int hashCode() {
    return Objects.hash(version, java.util.Arrays.hashCode(binding), attemptLimit);
  }

  @Override
  public String toString() {
    return "IssueRequest()";
  }
}
