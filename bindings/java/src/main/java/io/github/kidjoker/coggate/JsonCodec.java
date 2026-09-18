package io.github.kidjoker.coggate;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.json.JsonWriteFeature;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/** Strict streaming JSON codec for the frozen CogGate binding contract. */
public final class JsonCodec {
  private static final JsonFactory FACTORY = JsonFactory.builder()
      .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
      .enable(JsonWriteFeature.COMBINE_UNICODE_SURROGATES_IN_UTF8)
      .build();

  private JsonCodec() {}

  public static Submission decodeSubmission(byte[] payload) {
    validateUtf8(payload);
    try (JsonParser parser = FACTORY.createParser(payload)) {
      requireObject(parser);
      String challengeId = null;
      String nonce = null;
      String answer = null;
      boolean challengeIdSeen = false;
      boolean nonceSeen = false;
      boolean answerSeen = false;
      boolean unknown = false;
      while (parser.nextToken() != JsonToken.END_OBJECT) {
        requireField(parser);
        String field = parser.currentName();
        JsonToken valueToken = parser.nextToken();
        if (valueToken == null) {
          throw invalid();
        }
        switch (field) {
          case "challenge_id" -> {
            challengeId = requireString(parser, valueToken);
            challengeIdSeen = true;
          }
          case "nonce" -> {
            nonce = requireString(parser, valueToken);
            nonceSeen = true;
          }
          case "answer" -> {
            answer = requireString(parser, valueToken);
            answerSeen = true;
          }
          default -> {
            unknown = true;
            parser.skipChildren();
          }
        }
      }
      requireComplete(parser, unknown || !challengeIdSeen || !nonceSeen || !answerSeen);
      return new Submission(challengeId, nonce, answer);
    } catch (CogGateException error) {
      throw error;
    } catch (IOException | IllegalArgumentException error) {
      throw invalid();
    }
  }

  public static byte[] encodeSubmission(Submission submission) {
    if (submission == null) {
      throw invalid();
    }
    return generate(generator -> {
      generator.writeStartObject();
      generator.writeStringField("challenge_id", submission.challengeId());
      generator.writeStringField("nonce", submission.nonce());
      generator.writeStringField("answer", submission.answer());
      generator.writeEndObject();
    });
  }

  public static PublicChallenge decodePublicChallenge(byte[] payload) {
    validateUtf8(payload);
    try (JsonParser parser = FACTORY.createParser(payload)) {
      requireObject(parser);
      String challengeId = null;
      String generatorVersion = null;
      String nonce = null;
      long issuedAt = 0;
      long expiresAt = 0;
      String question = null;
      PublicChallenge.AnswerEncoding answerEncoding = null;
      int seen = 0;
      boolean unknown = false;
      while (parser.nextToken() != JsonToken.END_OBJECT) {
        requireField(parser);
        String field = parser.currentName();
        JsonToken valueToken = parser.nextToken();
        if (valueToken == null) {
          throw invalid();
        }
        switch (field) {
          case "challenge_id" -> {
            challengeId = requireString(parser, valueToken);
            seen |= 1;
          }
          case "generator_version" -> {
            generatorVersion = requireString(parser, valueToken);
            seen |= 2;
          }
          case "nonce" -> {
            nonce = requireString(parser, valueToken);
            seen |= 4;
          }
          case "issued_at" -> {
            issuedAt = requireLong(parser, valueToken);
            seen |= 8;
          }
          case "expires_at" -> {
            expiresAt = requireLong(parser, valueToken);
            seen |= 16;
          }
          case "question" -> {
            question = requireString(parser, valueToken);
            seen |= 32;
          }
          case "answer_encoding" -> {
            answerEncoding = PublicChallenge.AnswerEncoding.fromWireValue(
                requireString(parser, valueToken));
            seen |= 64;
          }
          default -> {
            unknown = true;
            parser.skipChildren();
          }
        }
      }
      requireComplete(parser, unknown || seen != 127);
      return new PublicChallenge(
          challengeId, generatorVersion, nonce, issuedAt, expiresAt, question, answerEncoding);
    } catch (CogGateException error) {
      throw error;
    } catch (IOException | IllegalArgumentException error) {
      throw invalid();
    }
  }

  public static byte[] encodePublicChallenge(PublicChallenge challenge) {
    if (challenge == null) {
      throw invalid();
    }
    return generate(generator -> {
      generator.writeStartObject();
      generator.writeStringField("challenge_id", challenge.challengeId());
      generator.writeStringField("generator_version", challenge.generatorVersion());
      generator.writeStringField("nonce", challenge.nonce());
      generator.writeNumberField("issued_at", challenge.issuedAt());
      generator.writeNumberField("expires_at", challenge.expiresAt());
      generator.writeStringField("question", challenge.question());
      generator.writeStringField("answer_encoding", challenge.answerEncoding().wireValue());
      generator.writeEndObject();
    });
  }

  public static VerificationOutcome decodeOutcome(byte[] payload) {
    validateUtf8(payload);
    try (JsonParser parser = FACTORY.createParser(payload)) {
      requireObject(parser);
      String status = null;
      String reason = null;
      boolean statusSeen = false;
      boolean reasonSeen = false;
      boolean unknown = false;
      while (parser.nextToken() != JsonToken.END_OBJECT) {
        requireField(parser);
        String field = parser.currentName();
        JsonToken valueToken = parser.nextToken();
        if (valueToken == null) {
          throw invalid();
        }
        switch (field) {
          case "status" -> {
            status = requireString(parser, valueToken);
            statusSeen = true;
          }
          case "reason" -> {
            reason = requireString(parser, valueToken);
            reasonSeen = true;
          }
          default -> {
            unknown = true;
            parser.skipChildren();
          }
        }
      }
      requireComplete(parser, unknown || !statusSeen);
      if ("accepted".equals(status) && !reasonSeen) {
        return VerificationOutcome.accepted();
      }
      if ("rejected".equals(status) && reasonSeen) {
        return VerificationOutcome.rejected(
            VerificationOutcome.RejectionReason.fromWireValue(reason));
      }
      throw invalid();
    } catch (CogGateException error) {
      throw error;
    } catch (IOException | IllegalArgumentException error) {
      throw invalid();
    }
  }

  public static byte[] encodeOutcome(VerificationOutcome outcome) {
    if (outcome == null) {
      throw invalid();
    }
    return generate(generator -> {
      generator.writeStartObject();
      generator.writeStringField("status", outcome.status().wireValue());
      if (outcome.status() == VerificationOutcome.Status.REJECTED) {
        if (outcome.reason() == null) {
          throw invalid();
        }
        generator.writeStringField("reason", outcome.reason().wireValue());
      } else if (outcome.reason() != null) {
        throw invalid();
      }
      generator.writeEndObject();
    });
  }

  static boolean isValidUnicode(String value) {
    if (value == null) {
      return false;
    }
    for (int index = 0; index < value.length(); index++) {
      char current = value.charAt(index);
      if (Character.isHighSurrogate(current)) {
        if (++index >= value.length() || !Character.isLowSurrogate(value.charAt(index))) {
          return false;
        }
      } else if (Character.isLowSurrogate(current)) {
        return false;
      }
    }
    return true;
  }

  private static void validateUtf8(byte[] payload) {
    if (payload == null) {
      throw invalid();
    }
    try {
      StandardCharsets.UTF_8.newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(payload));
    } catch (CharacterCodingException error) {
      throw invalid();
    }
  }

  private static void requireObject(JsonParser parser) throws IOException {
    if (parser.nextToken() != JsonToken.START_OBJECT) {
      throw invalid();
    }
  }

  private static void requireField(JsonParser parser) {
    if (parser.currentToken() != JsonToken.FIELD_NAME) {
      throw invalid();
    }
  }

  private static String requireString(JsonParser parser, JsonToken token) throws IOException {
    if (token != JsonToken.VALUE_STRING) {
      throw invalid();
    }
    String value = parser.getText();
    if (!isValidUnicode(value)) {
      throw invalid();
    }
    return value;
  }

  private static long requireLong(JsonParser parser, JsonToken token) throws IOException {
    if (token != JsonToken.VALUE_NUMBER_INT) {
      throw invalid();
    }
    return parser.getLongValue();
  }

  private static void requireComplete(JsonParser parser, boolean invalidShape) throws IOException {
    if (invalidShape || parser.nextToken() != null) {
      throw invalid();
    }
  }

  private static byte[] generate(JsonWriter writer) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (JsonGenerator generator = FACTORY.createGenerator(output)) {
      writer.write(generator);
    } catch (CogGateException error) {
      throw error;
    } catch (IOException | IllegalArgumentException error) {
      throw invalid();
    }
    return output.toByteArray();
  }

  private static CogGateException invalid() {
    return CogGateException.invalidArgument();
  }

  @FunctionalInterface
  private interface JsonWriter {
    void write(JsonGenerator generator) throws IOException;
  }
}
