package io.agentgate;

/** Immutable public challenge contract. */
public record PublicChallenge(
    String challengeId,
    String generatorVersion,
    String nonce,
    long issuedAt,
    long expiresAt,
    String question,
    String answerEncoding) {

  public PublicChallenge {
    if (!JsonCodec.isValidUnicode(challengeId)
        || !JsonCodec.isValidUnicode(generatorVersion)
        || !JsonCodec.isValidUnicode(nonce)
        || !JsonCodec.isValidUnicode(question)
        || !"base64url".equals(answerEncoding)) {
      throw new IllegalArgumentException("invalid AgentGate public challenge");
    }
  }

  @Override
  public String toString() {
    return "PublicChallenge()";
  }
}
