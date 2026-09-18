package io.github.kidjoker.coggate;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

final class JsonCodecTest {
  @Test
  void issueRequestV1UsesFixedDefaultsAndDefensiveCopies() {
    byte[] source = {1, 2, 3};
    IssueRequest request = IssueRequest.newV1IssueRequest(source);
    source[0] = 9;
    byte[] returned = request.binding();
    returned[1] = 9;

    assertEquals("1.0", request.version());
    assertEquals(AttemptLimit.ONE, request.attemptLimit());
    assertArrayEquals(new byte[] {1, 2, 3}, request.binding());
    assertEquals(1, AttemptLimit.ONE.value());
    assertEquals(2, AttemptLimit.TWO.value());
  }

  @Test
  void issueRequestRejectsInvalidArguments() {
    assertThrows(IllegalArgumentException.class,
        () -> new IssueRequest(null, new byte[] {1}, AttemptLimit.ONE));
    assertThrows(IllegalArgumentException.class,
        () -> new IssueRequest("1.0", null, AttemptLimit.ONE));
    assertThrows(IllegalArgumentException.class,
        () -> new IssueRequest("1.0", new byte[0], AttemptLimit.ONE));
    assertThrows(IllegalArgumentException.class,
        () -> new IssueRequest("1.0", new byte[257], AttemptLimit.ONE));
    assertThrows(IllegalArgumentException.class,
        () -> new IssueRequest("1.0", new byte[] {1}, null));
    assertThrows(IllegalArgumentException.class,
        () -> new IssueRequest("bad\ud800", new byte[] {1}, AttemptLimit.ONE));
  }

  @Test
  void modelTextIsRedacted() {
    String bindingSecret = "BINDING_SENTINEL";
    String nonceSecret = "NONCE_SENTINEL";
    String answerSecret = "ANSWER_SENTINEL";
    String questionSecret = "QUESTION_SENTINEL";
    IssueRequest request = IssueRequest.newV1IssueRequest(bindingSecret.getBytes(UTF_8));
    PublicChallenge challenge = new PublicChallenge(
        "challenge", "1.0", nonceSecret, 1L, 2L, questionSecret,
        PublicChallenge.AnswerEncoding.BASE64URL);
    Submission submission = new Submission("challenge", nonceSecret, answerSecret);

    for (String rendered : List.of(request.toString(), challenge.toString(), submission.toString())) {
      assertFalse(rendered.contains(bindingSecret));
      assertFalse(rendered.contains(nonceSecret));
      assertFalse(rendered.contains(answerSecret));
      assertFalse(rendered.contains(questionSecret));
    }
  }

  @Test
  void submissionRoundTripsWithExactDeterministicEncoding() {
    Submission expected = new Submission("雪\uD83D\uDE80", "nonce", "answer");
    byte[] encoded = JsonCodec.encodeSubmission(expected);

    assertEquals(
        "{\"challenge_id\":\"雪🚀\",\"nonce\":\"nonce\",\"answer\":\"answer\"}",
        new String(encoded, UTF_8));
    assertEquals(expected, JsonCodec.decodeSubmission(encoded));
  }

  @Test
  void publicChallengeRoundTripsWithExactInt64AndEncoding() {
    PublicChallenge expected = new PublicChallenge(
        "challenge", "1.0", "nonce", Long.MIN_VALUE, Long.MAX_VALUE, "雪🚀",
        PublicChallenge.AnswerEncoding.BASE64URL);
    byte[] encoded = JsonCodec.encodePublicChallenge(expected);

    assertEquals(PublicChallenge.AnswerEncoding.BASE64URL, expected.answerEncoding());
    assertEquals("base64url", expected.answerEncoding().wireValue());
    assertEquals(
        "{\"challenge_id\":\"challenge\",\"generator_version\":\"1.0\","
            + "\"nonce\":\"nonce\",\"issued_at\":-9223372036854775808,"
            + "\"expires_at\":9223372036854775807,\"question\":\"雪🚀\","
            + "\"answer_encoding\":\"base64url\"}",
        new String(encoded, UTF_8));
    assertEquals(expected, JsonCodec.decodePublicChallenge(encoded));
  }

  @Test
  void verificationOutcomesRoundTripWithExactShapes() {
    VerificationOutcome accepted = VerificationOutcome.accepted();
    assertEquals("{\"status\":\"accepted\"}",
        new String(JsonCodec.encodeOutcome(accepted), UTF_8));
    assertEquals(accepted, JsonCodec.decodeOutcome(JsonCodec.encodeOutcome(accepted)));

    for (VerificationOutcome.RejectionReason reason
        : VerificationOutcome.RejectionReason.values()) {
      VerificationOutcome rejected = VerificationOutcome.rejected(reason);
      String expected = "{\"status\":\"rejected\",\"reason\":\""
          + reason.wireValue() + "\"}";
      assertEquals(expected, new String(JsonCodec.encodeOutcome(rejected), UTF_8));
      assertEquals(rejected, JsonCodec.decodeOutcome(expected.getBytes(UTF_8)));
    }
    assertEquals(6, VerificationOutcome.RejectionReason.values().length);
    assertNull(accepted.reason());
  }

  @Test
  void rejectsDuplicateFieldsIncludingNestedDuplicates() {
    assertInvalid(() -> JsonCodec.decodeOutcome(
        "{\"status\":\"accepted\",\"status\":\"accepted\"}".getBytes(UTF_8)));
    assertInvalid(() -> JsonCodec.decodeSubmission(
        ("{\"challenge_id\":\"c\",\"nonce\":\"n\",\"answer\":\"a\","
            + "\"extra\":{\"nested\":1,\"nested\":2}}").getBytes(UTF_8)));
  }

  @Test
  void rejectsMissingUnknownCaseVariantAndWrongTokenFields() {
    assertInvalid(() -> JsonCodec.decodeSubmission(
        "{\"challenge_id\":\"c\",\"nonce\":\"n\"}".getBytes(UTF_8)));
    assertInvalid(() -> JsonCodec.decodeSubmission(
        ("{\"challenge_id\":\"c\",\"nonce\":\"n\",\"answer\":\"a\","
            + "\"extra\":true}").getBytes(UTF_8)));
    assertInvalid(() -> JsonCodec.decodeSubmission(
        "{\"Challenge_id\":\"c\",\"nonce\":\"n\",\"answer\":\"a\"}".getBytes(UTF_8)));
    assertInvalid(() -> JsonCodec.decodeSubmission(
        "{\"challenge_id\":1,\"nonce\":\"n\",\"answer\":\"a\"}".getBytes(UTF_8)));
    assertInvalid(() -> JsonCodec.decodeSubmission(
        "{\"challenge_id\":null,\"nonce\":\"n\",\"answer\":\"a\"}".getBytes(UTF_8)));
    assertInvalid(() -> JsonCodec.decodeSubmission("[]".getBytes(UTF_8)));
  }

  @Test
  void rejectsNonIntegralAndOverflowingInt64Values() {
    String template = "{\"challenge_id\":\"c\",\"generator_version\":\"1.0\","
        + "\"nonce\":\"n\",\"issued_at\":%s,\"expires_at\":2,"
        + "\"question\":\"q\",\"answer_encoding\":\"base64url\"}";

    assertInvalid(() -> JsonCodec.decodePublicChallenge(
        template.formatted("1.0").getBytes(UTF_8)));
    assertInvalid(() -> JsonCodec.decodePublicChallenge(
        template.formatted("9223372036854775808").getBytes(UTF_8)));
    assertInvalid(() -> JsonCodec.decodePublicChallenge(
        template.formatted("1e0").getBytes(UTF_8)));
  }

  @Test
  void rejectsTrailingRootsMalformedUtf8AndUnpairedSurrogates() {
    assertInvalid(() -> JsonCodec.decodeOutcome(
        "{\"status\":\"accepted\"} {\"status\":\"accepted\"}".getBytes(UTF_8)));
    assertInvalid(() -> JsonCodec.decodeSubmission(new byte[] {
        '{', '"', 'c', 'h', 'a', 'l', 'l', 'e', 'n', 'g', 'e', '_', 'i', 'd', '"', ':',
        '"', (byte) 0xc3, (byte) 0x28, '"', ',', '"', 'n', 'o', 'n', 'c', 'e', '"', ':',
        '"', 'n', '"', ',', '"', 'a', 'n', 's', 'w', 'e', 'r', '"', ':', '"', 'a', '"', '}'
    }));
    assertInvalid(() -> JsonCodec.decodeSubmission(
        "{\"challenge_id\":\"\\uD800\",\"nonce\":\"n\",\"answer\":\"a\"}"
            .getBytes(UTF_8)));
    assertThrows(IllegalArgumentException.class,
        () -> JsonCodec.encodeSubmission(new Submission("bad\udfff", "n", "a")));
  }

  @Test
  void rejectsUnknownEnumStatusReasonAndInvalidOutcomeShapes() {
    assertInvalid(() -> JsonCodec.decodePublicChallenge(validChallenge("BASE64URL")));
    assertInvalid(() -> JsonCodec.decodeOutcome("{\"status\":\"unknown\"}".getBytes(UTF_8)));
    assertInvalid(() -> JsonCodec.decodeOutcome(
        "{\"status\":\"rejected\",\"reason\":\"unknown\"}".getBytes(UTF_8)));
    assertInvalid(() -> JsonCodec.decodeOutcome(
        "{\"status\":\"rejected\"}".getBytes(UTF_8)));
    assertInvalid(() -> JsonCodec.decodeOutcome(
        "{\"status\":\"accepted\",\"reason\":\"expired\"}".getBytes(UTF_8)));
  }

  @Test
  void statusMappingIsExactAndUnknownFailsClosed() {
    assertNull(CogGateException.fromStatus(0));
    assertEquals(List.of(
            "invalid_configuration", "generation_failed", "invalid_challenge_material",
            "invalid_answer_encoding", "answer_mismatch", "unsupported_generator_version",
            "internal_error", "invalid_argument", "callback_failed", "panic_caught"),
        Arrays.stream(new int[] {1, 2, 3, 4, 5, 6, 7, 100, 101, 102})
            .mapToObj(status -> CogGateException.fromStatus(status).code())
            .toList());
    assertEquals("internal_error", CogGateException.fromStatus(-1).code());
    assertEquals("internal_error", CogGateException.fromStatus(999).code());
  }

  @Test
  void errorTextContainsOnlyStableCodeAndNoStackOrCause() {
    CogGateException error = CogGateException.fromStatus(5);
    assertEquals("answer_mismatch", error.code());
    assertEquals("answer_mismatch", error.getMessage());
    assertEquals("answer_mismatch", error.toString());
    assertNull(error.getCause());
    assertEquals(0, error.getStackTrace().length);
  }

  private static byte[] validChallenge(String encoding) {
    return ("{\"challenge_id\":\"c\",\"generator_version\":\"1.0\","
        + "\"nonce\":\"n\",\"issued_at\":1,\"expires_at\":2,"
        + "\"question\":\"q\",\"answer_encoding\":\"" + encoding + "\"}")
        .getBytes(UTF_8);
  }

  private static void assertInvalid(org.junit.jupiter.api.function.Executable executable) {
    CogGateException error = assertThrows(CogGateException.class, executable);
    assertEquals("invalid_argument", error.code());
    assertEquals("invalid_argument", error.toString());
  }
}
