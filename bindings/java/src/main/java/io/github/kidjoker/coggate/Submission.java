package io.github.kidjoker.coggate;

/** Immutable challenge response contract. */
public record Submission(String challengeId, String nonce, String answer) {
  public Submission {
    if (!JsonCodec.isValidUnicode(challengeId)
        || !JsonCodec.isValidUnicode(nonce)
        || !JsonCodec.isValidUnicode(answer)) {
      throw new IllegalArgumentException("invalid CogGate submission");
    }
  }

  @Override
  public String toString() {
    return "Submission()";
  }
}
