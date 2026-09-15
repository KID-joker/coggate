package io.agentgate;

/** Immutable public challenge contract. */
public record PublicChallenge(
    String challengeId,
    String generatorVersion,
    String nonce,
    long issuedAt,
    long expiresAt,
    String question,
    AnswerEncoding answerEncoding) {

  /** Closed answer representation set for the frozen challenge contract. */
  public enum AnswerEncoding {
    BASE64URL("base64url");

    private final String wireValue;

    AnswerEncoding(String wireValue) {
      this.wireValue = wireValue;
    }

    public String wireValue() {
      return wireValue;
    }

    static AnswerEncoding fromWireValue(String value) {
      if (BASE64URL.wireValue.equals(value)) {
        return BASE64URL;
      }
      throw AgentGateException.invalidArgument();
    }
  }

  public PublicChallenge {
    if (!JsonCodec.isValidUnicode(challengeId)
        || !JsonCodec.isValidUnicode(generatorVersion)
        || !JsonCodec.isValidUnicode(nonce)
        || !JsonCodec.isValidUnicode(question)
        || answerEncoding == null) {
      throw new IllegalArgumentException("invalid AgentGate public challenge");
    }
  }

  @Override
  public String toString() {
    return "PublicChallenge()";
  }
}
