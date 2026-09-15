package io.agentgate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

final class FixtureContractTest {
  private static final Set<String> REQUIRED = Set.of(
      "accepted", "answer_mismatch", "callback_exception", "close_after_use", "exact_release",
      "finish_failure", "key_rotation_old_key", "lifecycle_already_consumed",
      "lifecycle_attempts_exhausted", "lifecycle_binding_mismatch", "lifecycle_expired",
      "lifecycle_nonce_mismatch", "lifecycle_not_found", "observer_allowlist",
      "replay_after_accept");
  private static Map<String, Object> manifest;

  @BeforeAll
  static void load() throws IOException {
    Service.loadNative(Path.of(System.getProperty("agentgate.jni.path")));
    Path fixture = Path.of("..", "..", "fixtures", "bindings", "v1.json");
    try (JsonParser parser = new JsonFactory().createParser(Files.readAllBytes(fixture))) {
      parser.nextToken();
      manifest = castMap(readValue(parser));
    }
  }

  @Test
  void everySharedFixtureIsConsumedWithExactStatusOutcomeTraceAndReleaseCount() {
    @SuppressWarnings("unchecked") List<Map<String, Object>> cases =
        (List<Map<String, Object>>) manifest.get("cases");
    List<String> consumed = new ArrayList<>();
    for (Map<String, Object> fixture : cases) {
      String id = string(fixture, "id");
      consumed.add(id);
      try {
        runFixture(fixture);
      } catch (Throwable error) {
        throw new AssertionError("fixture failed: " + id, error);
      }
    }
    assertEquals(REQUIRED, Set.copyOf(consumed));
    assertEquals(REQUIRED.size(), consumed.size());
  }

  private static void runFixture(Map<String, Object> fixture) {
    @SuppressWarnings("unchecked") Map<String, Object> vectors =
        (Map<String, Object>) manifest.get("vectors");
    @SuppressWarnings("unchecked") Map<String, Object> lifecycleSpec =
        (Map<String, Object>) fixture.get("lifecycle");
    @SuppressWarnings("unchecked") Map<String, Object> keysSpec =
        (Map<String, Object>) fixture.get("keys");
    @SuppressWarnings("unchecked") List<String> expectedTrace =
        (List<String>) fixture.get("expected_trace");
    List<String> trace = new ArrayList<>();
    byte[] material = jsonBytes(vectors.get("private_material"));
    byte[] token = hex(string(vectors, "token_hex"));
    byte[] oldKey = hex(string(vectors, "old_key_hex"));
    byte[] expectedBinding = binding(fixture);
    byte[] expectedIdentity = identity(fixture);
    boolean[] consumed = {false};
    List<Long> serverTimes = new ArrayList<>();
    AtomicReference<AssertionError> callbackAssertion = new AtomicReference<>();

    Lifecycle lifecycle = new Lifecycle() {
      public Status storeIssued(byte[] privateJson, byte[] binding, AttemptLimit limit) {
        trace.add("store_issued");
        return Status.OK;
      }
      public BeginResult beginAttempt(byte[] identity, byte[] binding, long serverTime) {
        captureAssertion(callbackAssertion, () -> {
          assertArrayEquals(expectedIdentity, identity, "identity_json");
          assertArrayEquals(expectedBinding, binding, "begin binding");
          assertTrue(serverTime > 0, "server_time");
        });
        serverTimes.add(serverTime);
        if (Boolean.TRUE.equals(lifecycleSpec.get("callback_exception"))) {
          trace.add("begin_attempt:exception");
          throw new IllegalStateException("CALLBACK_EXCEPTION_SENTINEL");
        }
        trace.add("begin_attempt");
        if (Boolean.TRUE.equals(lifecycleSpec.get("replay")) && !consumed[0]) {
          return new BeginResult(BeginStatus.OK, material, token);
        }
        return new BeginResult(beginStatus(string(lifecycleSpec, "begin_status")),
            "primary".equals(lifecycleSpec.get("material")) ? material : null,
            "default".equals(lifecycleSpec.get("token")) ? token : null);
      }
      public Status finishAttempt(byte[] value, AttemptOutcome outcome) {
        captureAssertion(callbackAssertion, () -> {
          assertArrayEquals(token, value, "finish token");
          AttemptOutcome expected = string(castMap(fixture.get("submission")), "answer")
              .equals(string(vectors, "answer")) ? AttemptOutcome.ACCEPTED : AttemptOutcome.REJECTED;
          assertEquals(expected, outcome, "finish outcome");
        });
        String outcomeName = outcome.name().toLowerCase(java.util.Locale.ROOT);
        trace.add("finish_attempt:" + outcomeName);
        if (outcome == AttemptOutcome.ACCEPTED) consumed[0] = true;
        return "internal".equals(lifecycleSpec.get("finish_status")) ? Status.INTERNAL : Status.OK;
      }
    };
    KeyProvider keys = new KeyProvider() {
      public ActiveResult activeKey() {
        trace.add("active_key");
        return new ActiveResult(Status.OK,
            string(vectors, "active_key_id").getBytes(StandardCharsets.UTF_8),
            hex(string(vectors, "active_key_hex")));
      }
      public Result keyById(byte[] id) {
        String actualId = strictUtf8(id);
        String oldId = string(vectors, "old_key_id");
        String activeId = string(vectors, "active_key_id");
        captureAssertion(callbackAssertion, () -> assertEquals(oldId, actualId, "key id"));
        trace.add("key_by_id:" + (actualId.equals(oldId) ? "old"
            : actualId.equals(activeId) ? "active" : actualId));
        if (Boolean.TRUE.equals(keysSpec.get("callback_exception"))) {
          throw new IllegalStateException("KEY_CALLBACK_EXCEPTION_SENTINEL");
        }
        if (Boolean.TRUE.equals(lifecycleSpec.get("replay")) && !consumed[0]) {
          return new Result(Status.OK, oldKey);
        }
        return new Result(keyStatus(string(keysSpec, "status")), oldKey);
      }
    };
    Observer observer = event -> {
      String eventText = new String(event, StandardCharsets.UTF_8);
      String name = eventText.replaceAll(".*\\\"event\\\":\\\"([^\\\"]+)\\\".*", "$1");
      trace.add("observe:" + name);
      if ("observer_allowlist".equals(string(fixture, "id"))) {
        @SuppressWarnings("unchecked") List<String> allow =
            (List<String>) vectors.get("observer_allowlist");
        Map<String, Object> object = parseObject(event);
        assertFalse(object.keySet().stream().anyMatch(key -> !allow.contains(key)));
      }
      @SuppressWarnings("unchecked") List<String> sentinels =
          (List<String>) fixture.get("forbidden_sentinels");
      for (String sentinel : sentinels) assertFalse(eventText.contains(sentinel));
    };

    long releasesBefore = Service.testReleaseCount();
    Service.setTestReleaseListener(tag -> trace.add("release:" + switch (tag) {
      case 1 -> "material";
      case 2 -> "token";
      case 3 -> "key_id";
      case 4 -> "key";
      default -> "unknown";
    }));
    VerificationOutcome outcome = null;
    AgentGateException error = null;
    long verifyWindowStart = java.time.Instant.now().getEpochSecond() - 1;
    try (Service service = new Service(lifecycle, keys,
        "release".equals(fixture.get("operation")) ? null : observer)) {
      String operation = string(fixture, "operation");
      if (Boolean.TRUE.equals(lifecycleSpec.get("replay"))) {
        assertEquals(VerificationOutcome.accepted(), service.verify(submission(fixture), binding(fixture)));
        trace.clear();
        releasesBefore = Service.testReleaseCount();
      }
      if ("close".equals(operation)) {
        service.close();
        service.close();
        trace.add("service_destroy");
      } else {
        try {
          outcome = service.verify(submission(fixture), binding(fixture));
        } catch (AgentGateException caught) {
          error = caught;
        }
      }
    } finally {
      Service.setTestReleaseListener(null);
    }
    long verifyWindowEnd = java.time.Instant.now().getEpochSecond() + 1;
    if (callbackAssertion.get() != null) throw callbackAssertion.get();
    for (long serverTime : serverTimes) {
      assertTrue(serverTime >= verifyWindowStart && serverTime <= verifyWindowEnd,
          "server_time outside verification window");
    }
    int expectedStatus = ((Number) fixture.get("expected_status")).intValue();
    int actualStatus = statusFor(error == null ? "ok" : error.code());
    assertEquals(expectedStatus, actualStatus, string(fixture, "id"));
    assertEquals(expectedStatus == 0 ? null : string(fixture, "expected_code"),
        error == null ? null : error.code(), string(fixture, "id"));
    Object expectedOutcome = fixture.get("expected_outcome");
    if (expectedOutcome != null) {
      assertNotNull(outcome);
      assertEquals(parseExpectedOutcome(expectedOutcome), outcome);
    }
    assertEquals(expectedTrace, trace, string(fixture, "id"));
    assertEquals(((Number) fixture.get("expected_release_count")).longValue(),
        Service.testReleaseCount() - releasesBefore, string(fixture, "id"));
    @SuppressWarnings("unchecked") List<String> sentinels =
        (List<String>) fixture.get("forbidden_sentinels");
    String publicText = String.valueOf(error) + String.valueOf(outcome);
    for (String sentinel : sentinels) assertFalse(publicText.contains(sentinel));
  }

  private static Submission submission(Map<String, Object> fixture) {
    @SuppressWarnings("unchecked") Map<String, Object> value =
        (Map<String, Object>) fixture.get("submission");
    return new Submission(string(value, "challenge_id"), string(value, "nonce"), string(value, "answer"));
  }

  private static byte[] binding(Map<String, Object> fixture) {
    return hex(string(fixture, "binding_hex"));
  }

  private static byte[] identity(Map<String, Object> fixture) {
    @SuppressWarnings("unchecked") Map<String, Object> submission =
        (Map<String, Object>) fixture.get("submission");
    if (submission == null) return null;
    Map<String, Object> identity = new LinkedHashMap<>();
    identity.put("challenge_id", submission.get("challenge_id"));
    identity.put("nonce", submission.get("nonce"));
    return jsonBytes(identity);
  }

  private static void captureAssertion(AtomicReference<AssertionError> destination,
      Runnable assertion) {
    try {
      assertion.run();
    } catch (AssertionError error) {
      destination.compareAndSet(null, error);
      throw error;
    }
  }

  private static String strictUtf8(byte[] value) {
    try {
      return StandardCharsets.UTF_8.newDecoder()
          .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
          .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
          .decode(java.nio.ByteBuffer.wrap(value)).toString();
    } catch (java.nio.charset.CharacterCodingException error) {
      throw new AssertionError("invalid callback UTF-8", error);
    }
  }

  private static VerificationOutcome parseExpectedOutcome(Object value) {
    return JsonCodec.decodeOutcome(jsonBytes(value));
  }

  private static byte[] jsonBytes(Object value) {
    try {
      java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
      try (com.fasterxml.jackson.core.JsonGenerator generator = new JsonFactory().createGenerator(output)) {
        writeValue(generator, value);
      }
      return output.toByteArray();
    } catch (IOException error) {
      throw new AssertionError(error);
    }
  }

  private static Map<String, Object> parseObject(byte[] bytes) {
    try (JsonParser parser = new JsonFactory().createParser(bytes)) {
      parser.nextToken();
      return castMap(readValue(parser));
    } catch (IOException error) {
      throw new AssertionError(error);
    }
  }

  private static Lifecycle.BeginStatus beginStatus(String value) {
    return switch (value) {
      case "ok" -> Lifecycle.BeginStatus.OK;
      case "unavailable" -> Lifecycle.BeginStatus.UNAVAILABLE;
      case "conflict" -> Lifecycle.BeginStatus.CONFLICT;
      case "internal" -> Lifecycle.BeginStatus.INTERNAL;
      case "not_found" -> Lifecycle.BeginStatus.NOT_FOUND;
      case "expired" -> Lifecycle.BeginStatus.EXPIRED;
      case "already_consumed" -> Lifecycle.BeginStatus.ALREADY_CONSUMED;
      case "binding_mismatch" -> Lifecycle.BeginStatus.BINDING_MISMATCH;
      case "nonce_mismatch" -> Lifecycle.BeginStatus.NONCE_MISMATCH;
      case "attempts_exhausted" -> Lifecycle.BeginStatus.ATTEMPTS_EXHAUSTED;
      default -> Lifecycle.BeginStatus.INTERNAL;
    };
  }

  private static KeyProvider.Status keyStatus(String value) {
    return switch (value) {
      case "ok" -> KeyProvider.Status.OK;
      case "unavailable" -> KeyProvider.Status.UNAVAILABLE;
      case "not_found" -> KeyProvider.Status.NOT_FOUND;
      case "invalid_material" -> KeyProvider.Status.INVALID_MATERIAL;
      default -> KeyProvider.Status.UNAVAILABLE;
    };
  }

  private static int statusFor(String code) {
    @SuppressWarnings("unchecked") Map<String, Object> statuses =
        (Map<String, Object>) manifest.get("statuses");
    @SuppressWarnings("unchecked") Map<String, Object> status =
        (Map<String, Object>) statuses.get(code);
    return ((Number) status.get("value")).intValue();
  }

  private static String string(Map<String, Object> map, String key) {
    return String.valueOf(map.get(key));
  }

  private static byte[] hex(String value) { return HexFormat.of().parseHex(value); }

  private static Object readValue(JsonParser parser) throws IOException {
    return switch (parser.currentToken()) {
      case START_OBJECT -> {
        Map<String, Object> object = new LinkedHashMap<>();
        while (parser.nextToken() != com.fasterxml.jackson.core.JsonToken.END_OBJECT) {
          String field = parser.currentName();
          parser.nextToken();
          object.put(field, readValue(parser));
        }
        yield object;
      }
      case START_ARRAY -> {
        List<Object> array = new ArrayList<>();
        while (parser.nextToken() != com.fasterxml.jackson.core.JsonToken.END_ARRAY) {
          array.add(readValue(parser));
        }
        yield array;
      }
      case VALUE_STRING -> parser.getText();
      case VALUE_NUMBER_INT -> parser.getLongValue();
      case VALUE_TRUE -> true;
      case VALUE_FALSE -> false;
      case VALUE_NULL -> null;
      default -> throw new IOException("unsupported fixture JSON token");
    };
  }

  private static void writeValue(com.fasterxml.jackson.core.JsonGenerator generator, Object value)
      throws IOException {
    if (value == null) {
      generator.writeNull();
    } else if (value instanceof Map<?, ?> object) {
      generator.writeStartObject();
      for (Map.Entry<?, ?> entry : object.entrySet()) {
        generator.writeFieldName(String.valueOf(entry.getKey()));
        writeValue(generator, entry.getValue());
      }
      generator.writeEndObject();
    } else if (value instanceof List<?> array) {
      generator.writeStartArray();
      for (Object item : array) writeValue(generator, item);
      generator.writeEndArray();
    } else if (value instanceof String string) {
      generator.writeString(string);
    } else if (value instanceof Number number) {
      generator.writeNumber(number.longValue());
    } else if (value instanceof Boolean bool) {
      generator.writeBoolean(bool);
    } else {
      throw new IOException("unsupported fixture JSON value");
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> castMap(Object value) {
    return (Map<String, Object>) value;
  }
}
