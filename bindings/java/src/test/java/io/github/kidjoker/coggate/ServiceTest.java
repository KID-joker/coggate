package io.github.kidjoker.coggate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Files;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

final class ServiceTest {
  private static final byte[] BINDING = hex("0011223344556677");
  private static final byte[] KEY = hex(
      "3031323334353637383961626364656630313233343536373839616263646566");
  private static final byte[] MATERIAL = ("{\"challenge_id\":\"Y2hhbGxlbmdlLTEyMzQ1Ng\","
      + "\"generator_version\":\"1.0\",\"nonce\":\"bm9uY2UtMTIzNDU2Nzg5MA\","
      + "\"issued_at\":1788062400,\"expires_at\":1788062408,"
      + "\"mac_key_id\":\"2026-08\","
      + "\"answer_mac\":\"ccdffbb67b4c9da34f91d56d12970b311d7345e8bcf579d1326fc4a78633330c\","
      + "\"answer_encoding\":\"base64url\"}").getBytes(StandardCharsets.UTF_8);

  @BeforeAll
  static void loadNative() {
    String path = System.getProperty("coggate.jni.path");
    assertNotNull(path, "-Dcoggate.jni.path must name the built JNI shim");
    Service.loadNative(Path.of(path));
  }

  @Test
  void callbackStatusValuesMatchFrozenAbi() {
    assertEquals(0, Lifecycle.Status.OK.value());
    assertEquals(3, Lifecycle.Status.INTERNAL.value());
    assertEquals(10, Lifecycle.BeginStatus.NOT_FOUND.value());
    assertEquals(15, Lifecycle.BeginStatus.ATTEMPTS_EXHAUSTED.value());
    assertEquals(3, Lifecycle.AttemptOutcome.SYSTEM_FAILURE.value());
    assertEquals(3, KeyProvider.Status.INVALID_MATERIAL.value());
  }

  @Test
  void issueUsesUtf8BytesWithoutModifiedUtf8OrSecretLogging() {
    AtomicReference<byte[]> seenBinding = new AtomicReference<>();
    AtomicReference<byte[]> stored = new AtomicReference<>();
    byte[] binding = "nul\0-雪-\uD83D\uDE80".getBytes(StandardCharsets.UTF_8);
    Lifecycle lifecycle = lifecycle((privateJson, supplied, limit) -> {
      stored.set(privateJson.clone());
      seenBinding.set(supplied.clone());
      assertEquals(AttemptLimit.ONE, limit);
      return Lifecycle.Status.OK;
    }, null, null);
    long allocations = Service.testAllocationCount();
    long releases = Service.testReleaseCount();
    try (Service service = new Service(lifecycle, keys(), null)) {
      PublicChallenge challenge = service.issue(IssueRequest.newV1IssueRequest(binding));
      assertEquals("1.0", challenge.generatorVersion());
      assertArrayEquals(binding, seenBinding.get());
      Map<String, Object> privateMaterial = parseObject(stored.get());
      assertEquals(Set.of("challenge_id", "generator_version", "nonce", "issued_at",
          "expires_at", "mac_key_id", "answer_mac", "answer_encoding"),
          privateMaterial.keySet());
      assertEquals(challenge.challengeId(), privateMaterial.get("challenge_id"));
      assertEquals(challenge.generatorVersion(), privateMaterial.get("generator_version"));
      assertEquals(challenge.nonce(), privateMaterial.get("nonce"));
      assertEquals(challenge.issuedAt(), privateMaterial.get("issued_at"));
      assertEquals(challenge.expiresAt(), privateMaterial.get("expires_at"));
      assertEquals("active-2026-09", privateMaterial.get("mac_key_id"));
      assertTrue(String.valueOf(privateMaterial.get("answer_mac")).matches("[0-9a-f]{64}"));
      assertEquals("base64url", privateMaterial.get("answer_encoding"));
      assertFalse(service.toString().contains("nul"));
    }
    assertEquals(allocations + 2, Service.testAllocationCount());
    assertEquals(releases + 2, Service.testReleaseCount());
  }

  @Test
  void callbackExceptionIsClearedAndMappedWithoutLeakingText() {
    Lifecycle lifecycle = lifecycle(null, (identity, binding, time) -> {
      throw new IllegalStateException("CALLBACK_EXCEPTION_SENTINEL");
    }, null);
    try (Service service = new Service(lifecycle, keys(), null)) {
      CogGateException error = assertThrows(CogGateException.class,
          () -> service.verify(submission(), BINDING));
      assertEquals("internal_error", error.code());
      assertFalse(error.toString().contains("CALLBACK_EXCEPTION_SENTINEL"));
      assertFalse(error.toString().contains("coggate_ffi"));
      assertDoesNotThrow(() -> service.close());
    }
  }

  @Test
  void finishExceptionSentinelIsClearedAndMappedWithoutLeakingText() {
    List<byte[]> events = new ArrayList<>();
    Lifecycle lifecycle = lifecycle(null,
        (identity, binding, time) -> new Lifecycle.BeginResult(
            Lifecycle.BeginStatus.OK, MATERIAL, hex("aabbccdd")),
        (token, outcome) -> { throw new IllegalStateException("FINISH_FAILURE_SENTINEL"); });
    try (Service service = new Service(lifecycle, keys(), event -> events.add(event.clone()))) {
      CogGateException error = assertThrows(CogGateException.class,
          () -> service.verify(submission(), BINDING));
      assertEquals("internal_error", error.code());
      assertFalse((error + eventsText(events)).contains("FINISH_FAILURE_SENTINEL"));
      assertDoesNotThrow(service::close);
    }
  }

  @Test
  void observerExceptionIsSwallowed() {
    Observer observer = event -> { throw new AssertionError("OBSERVER_SECRET_SENTINEL"); };
    try (Service service = new Service(lifecycle(), keys(), observer)) {
      assertNotNull(service.issue(IssueRequest.newV1IssueRequest(BINDING)));
    }
  }

  @Test
  void globalReferencesKeepCallbacksAliveAcrossGc() throws Exception {
    Lifecycle lifecycle = lifecycle();
    KeyProvider keys = keys();
    WeakReference<Lifecycle> lifecycleReference = new WeakReference<>(lifecycle);
    WeakReference<KeyProvider> keyReference = new WeakReference<>(keys);
    try (Service service = new Service(lifecycle, keys, null)) {
      lifecycle = null;
      keys = null;
      forceGc();
      assertNotNull(lifecycleReference.get());
      assertNotNull(keyReference.get());
      assertNotNull(service.issue(IssueRequest.newV1IssueRequest(BINDING)));
    }
  }

  @Test
  @Timeout(10)
  void cleanerStateDoesNotRetainServiceAndDestroysOnce() throws Exception {
    long before = Service.testDestroyCount();
    WeakReference<Service> reference = unclosedService();
    long deadline = System.nanoTime() + Duration.ofSeconds(8).toNanos();
    while ((reference.get() != null || Service.testDestroyCount() == before)
        && System.nanoTime() < deadline) {
      System.gc();
      System.runFinalization();
      Thread.sleep(20);
    }
    assertEquals(null, reference.get());
    assertEquals(before + 1, Service.testDestroyCount());
  }

  @Test
  void attachedNativeThreadIsDetachedAfterCallback() {
    AtomicInteger calls = new AtomicInteger();
    Lifecycle lifecycle = lifecycle((privateJson, binding, limit) -> {
      calls.incrementAndGet();
      return Lifecycle.Status.OK;
    }, null, null);
    assertTrue(Service.testCallbackFromAttachedThread(lifecycle));
    assertEquals(1, calls.get());
    assertEquals(Service.testAttachCount(), Service.testDetachCount());
  }

  @Test
  @Timeout(10)
  void concurrentCloseWaitsForInflightAndDestroysOnce() throws Exception {
    CountDownLatch entered = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    Lifecycle lifecycle = lifecycle((privateJson, binding, limit) -> {
      entered.countDown();
      await(release);
      return Lifecycle.Status.OK;
    }, null, null);
    Service service = new Service(lifecycle, keys(), null);
    long before = Service.testDestroyCount();
    ExecutorService pool = Executors.newFixedThreadPool(3);
    try {
      Future<?> issue = pool.submit(() -> service.issue(IssueRequest.newV1IssueRequest(BINDING)));
      assertTrue(entered.await(5, TimeUnit.SECONDS));
      Future<?> closeOne = pool.submit(service::close);
      Future<?> closeTwo = pool.submit(service::close);
      Thread.sleep(50);
      assertFalse(closeOne.isDone());
      release.countDown();
      issue.get(5, TimeUnit.SECONDS);
      closeOne.get(5, TimeUnit.SECONDS);
      closeTwo.get(5, TimeUnit.SECONDS);
      assertEquals(before + 1, Service.testDestroyCount());
      assertDoesNotThrow(service::close);
      assertEquals(before + 1, Service.testDestroyCount());
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void useAfterCloseAndCallbackTimeReentryFailFast() {
    AtomicReference<Service> reference = new AtomicReference<>();
    List<String> errors = Collections.synchronizedList(new ArrayList<>());
    Lifecycle lifecycle = lifecycle((privateJson, binding, limit) -> {
      errors.add(assertThrows(CogGateException.class, reference.get()::close).code());
      errors.add(assertThrows(CogGateException.class,
          () -> reference.get().issue(IssueRequest.newV1IssueRequest(BINDING))).code());
      return Lifecycle.Status.OK;
    }, null, null);
    Service service = new Service(lifecycle, keys(), null);
    reference.set(service);
    service.issue(IssueRequest.newV1IssueRequest(BINDING));
    assertEquals(List.of("invalid_argument", "invalid_argument"), errors);
    service.close();
    assertEquals("invalid_argument", assertThrows(CogGateException.class,
        () -> service.issue(IssueRequest.newV1IssueRequest(BINDING))).code());
    assertEquals("invalid_argument", assertThrows(CogGateException.class,
        () -> service.verify(submission(), BINDING)).code());
  }

  @Test
  void callbackAllowsCrossServiceNestingButRejectsSameServiceReentry() {
    AtomicReference<Service> serviceA = new AtomicReference<>();
    List<String> events = new ArrayList<>();
    Lifecycle lifecycleB = lifecycle((privateJson, binding, limit) -> {
      events.add("b");
      return Lifecycle.Status.OK;
    }, null, null);
    try (Service serviceB = new Service(lifecycleB, keys(), null)) {
      Lifecycle lifecycleA = lifecycle((privateJson, binding, limit) -> {
        events.add(assertThrows(CogGateException.class,
            () -> serviceA.get().issue(IssueRequest.newV1IssueRequest(BINDING))).code());
        serviceB.issue(IssueRequest.newV1IssueRequest(BINDING));
        events.add("nested");
        return Lifecycle.Status.OK;
      }, null, null);
      try (Service service = new Service(lifecycleA, keys(), null)) {
        serviceA.set(service);
        service.issue(IssueRequest.newV1IssueRequest(BINDING));
      }
    }
    assertEquals(List.of("invalid_argument", "b", "nested"), events);
  }

  @Test
  void callbackOutputsAreCopiedAndReleasedExactlyOnce() {
    byte[] material = MATERIAL.clone();
    byte[] token = hex("aabbccdd");
    byte[] key = KEY.clone();
    Lifecycle lifecycle = lifecycle(null,
        (identity, binding, time) -> new Lifecycle.BeginResult(
            Lifecycle.BeginStatus.OK, material, token),
        (value, outcome) -> Lifecycle.Status.OK);
    KeyProvider keys = keys((id) -> new KeyProvider.Result(KeyProvider.Status.OK, key));
    long allocations = Service.testAllocationCount();
    long releases = Service.testReleaseCount();
    long wipes = Service.testWipeCount();
    long wipeFailures = Service.testWipeFailureCount();
    AtomicInteger releaseSequence = new AtomicInteger();
    AtomicReference<AssertionError> wipeOrderingFailure = new AtomicReference<>();
    Service.setTestReleaseListener(tag -> {
      try {
        assertEquals(wipes + releaseSequence.incrementAndGet(), Service.testWipeCount(),
            "host buffer must be wiped before release notification");
      } catch (AssertionError error) {
        wipeOrderingFailure.compareAndSet(null, error);
        throw error;
      }
    });
    try {
      try (Service service = new Service(lifecycle, keys, null)) {
        assertEquals(VerificationOutcome.accepted(), service.verify(submission(), BINDING));
      }
    } finally {
      Service.setTestReleaseListener(null);
    }
    assertEquals(allocations + 3, Service.testAllocationCount());
    assertEquals(releases + 3, Service.testReleaseCount());
    assertEquals(wipes + 3, Service.testWipeCount());
    assertEquals(wipeFailures, Service.testWipeFailureCount());
    assertEquals(3, releaseSequence.get());
    if (wipeOrderingFailure.get() != null) throw wipeOrderingFailure.get();
    assertArrayEquals(MATERIAL, material);
    assertArrayEquals(hex("aabbccdd"), token);
    assertArrayEquals(KEY, key);
  }

  @Test
  void preNativeFailureCannotLeakInflightOrBlockClose() {
    Service service = new Service(lifecycle(), keys(), null);
    Service.setTestBeforeNativeHook(() -> { throw new IllegalStateException("ENCODE_SENTINEL"); });
    try {
      CogGateException error = assertThrows(CogGateException.class,
          () -> service.verify(submission(), BINDING));
      assertEquals("internal_error", error.code());
      assertFalse(error.toString().contains("ENCODE_SENTINEL"));
    } finally {
      Service.setTestBeforeNativeHook(null);
    }
    assertTimeout(Duration.ofSeconds(2), service::close);
  }

  @Test
  @Timeout(10)
  void cleanerCollectsCallbackCycleAndDestroysExactlyOnce() throws Exception {
    long before = Service.testDestroyCount();
    WeakReference<Service> reference = cyclicUnclosedService();
    long deadline = System.nanoTime() + Duration.ofSeconds(8).toNanos();
    while ((reference.get() != null || Service.testDestroyCount() == before)
        && System.nanoTime() < deadline) {
      System.gc();
      System.runFinalization();
      Thread.sleep(20);
    }
    assertNull(reference.get());
    assertEquals(before + 1, Service.testDestroyCount());
  }

  @Test
  void pendingCallbackExceptionCleanupClearsBeforeExitCallback() {
    assertTrue(Service.testPendingExceptionCleanup());
    assertTrue(Service.testPendingExceptionAudit(
        new Lifecycle.BeginResult(Lifecycle.BeginStatus.OK, MATERIAL, new byte[0]),
        Lifecycle.Status.OK));
    assertDoesNotThrow(Service::testReleaseCount);
  }

  @Test
  void nativeBuildAndWindowsLoadingUseExplicitRelocatableDependencies() throws IOException {
    String cmake = Files.readString(Path.of("CMakeLists.txt"));
    assertFalse(cmake.contains("${JNI_LIBRARIES}"));
    assertFalse(cmake.contains("if(WIN32 AND COGGATE_RUNTIME_LIBRARY)"));
    assertTrue(cmake.contains("copy_if_different"));
    assertTrue(cmake.contains("@loader_path"));
    assertTrue(cmake.contains("$ORIGIN"));
    assertTrue(cmake.contains("option(COGGATE_STATIC_LINK"));
    assertTrue(cmake.contains("COGGATE_STATIC"));
    assertTrue(cmake.contains("WIN32 AND NOT COGGATE_STATIC_LINK"));
    assertTrue(cmake.contains("COGGATE_RUNTIME_LIBRARY is required"));

    String service = Files.readString(
        Path.of("src", "main", "java", "io", "github", "kidjoker", "coggate", "Service.java"));
    int coreLoad = service.indexOf("System.load(core.toString())");
    int shimLoad = service.indexOf("System.load(shim.toString())");
    assertTrue(coreLoad >= 0 && shimLoad > coreLoad);
    assertTrue(service.contains("coggate_ffi.dll"));
    assertTrue(service.contains("Files.isRegularFile(core)"));
  }

  @Test
  void malformedPrivateMaterialUtf8FailsClosedAndLeavesNoPendingException() {
    byte[] malformed = {(byte) 0xC3, 0x28};
    Lifecycle lifecycle = lifecycle(null,
        (identity, binding, time) -> new Lifecycle.BeginResult(
            Lifecycle.BeginStatus.OK, malformed, new byte[0]), null);
    try (Service service = new Service(lifecycle, keys(), null)) {
      CogGateException error = assertThrows(CogGateException.class,
          () -> service.verify(submission(), BINDING));
      assertEquals("callback_failed", error.code());
      assertEquals("callback_failed", error.toString());
      assertDoesNotThrow(service::close);
    }
  }

  @Test
  void malformedActiveKeyIdUtf8FailsClosedAndLeavesNoPendingException() {
    byte[] malformed = {(byte) 0x80};
    KeyProvider keys = new KeyProvider() {
      public ActiveResult activeKey() { return new ActiveResult(Status.OK, malformed, KEY); }
      public Result keyById(byte[] keyId) { return new Result(Status.OK, KEY); }
    };
    try (Service service = new Service(lifecycle(), keys, null)) {
      CogGateException error = assertThrows(CogGateException.class,
          () -> service.issue(IssueRequest.newV1IssueRequest(BINDING)));
      assertEquals("callback_failed", error.code());
      assertEquals("callback_failed", error.toString());
      assertDoesNotThrow(service::close);
    }
  }

  @Test
  void opaqueKeyAndTokenPreserveMalformedUtf8BytesExactly() {
    byte[] rawKey = new byte[32];
    for (int index = 0; index < rawKey.length; index += 2) {
      rawKey[index] = (byte) 0xC3;
      rawKey[index + 1] = 0x28;
    }
    KeyProvider issueKeys = new KeyProvider() {
      public ActiveResult activeKey() {
        return new ActiveResult(Status.OK, "raw-key".getBytes(StandardCharsets.UTF_8), rawKey);
      }
      public Result keyById(byte[] keyId) { return new Result(Status.OK, rawKey); }
    };
    try (Service service = new Service(lifecycle(), issueKeys, null)) {
      assertNotNull(service.issue(IssueRequest.newV1IssueRequest(BINDING)));
    }

    byte[] rawToken = {(byte) 0xC3, 0x28, (byte) 0x80, 0, (byte) 0xFF};
    AtomicReference<byte[]> finished = new AtomicReference<>();
    Lifecycle lifecycle = lifecycle(null,
        (identity, binding, time) -> new Lifecycle.BeginResult(
            Lifecycle.BeginStatus.OK, MATERIAL, rawToken),
        (token, outcome) -> {
          finished.set(token.clone());
          return Lifecycle.Status.OK;
        });
    try (Service service = new Service(lifecycle, keys(), null)) {
      assertEquals(VerificationOutcome.accepted(), service.verify(submission(), BINDING));
    }
    assertArrayEquals(rawToken, finished.get());
  }

  @Test
  void observerReceivesStrictUtf8JsonBytesIncludingNonBmpSafeMetadata() {
    AtomicInteger observations = new AtomicInteger();
    Observer observer = event -> {
      assertStrictUtf8(event);
      Map<String, Object> object = parseObject(event);
      assertNotNull(object.get("event"));
      observations.incrementAndGet();
    };
    byte[] binding = "observer\0-雪-\uD83D\uDE80".getBytes(StandardCharsets.UTF_8);
    try (Service service = new Service(lifecycle(), keys(), observer)) {
      service.issue(IssueRequest.newV1IssueRequest(binding));
      assertEquals(VerificationOutcome.accepted(), service.verify(submission(), binding));
    }
    assertTrue(observations.get() > 0);
  }

  @Test
  void lifecycleSentinelsTraversePrivateBoundariesButNeverPublicSurfaces() {
    Set<String> sentinels = Set.of("PRIVATE_ANSWER_SENTINEL", "BINDING_SENTINEL",
        "NONCE_SENTINEL", "MATERIAL_SENTINEL", "TOKEN_SENTINEL",
        "REPLAY_MATERIAL_SENTINEL");
    byte[] secretBinding = "BINDING_SENTINEL".getBytes(StandardCharsets.UTF_8);
    List<byte[]> events = new ArrayList<>();
    AtomicInteger call = new AtomicInteger();
    Lifecycle lifecycle = lifecycle(null, (identity, binding, time) -> {
      assertArrayEquals(secretBinding, binding);
      String identityText = new String(identity, StandardCharsets.UTF_8);
      assertTrue(identityText.contains("NONCE_SENTINEL"));
      assertFalse(identityText.contains("PRIVATE_ANSWER_SENTINEL"));
      String materialSecret = call.getAndIncrement() == 0
          ? "MATERIAL_SENTINEL" : "REPLAY_MATERIAL_SENTINEL";
      return new Lifecycle.BeginResult(Lifecycle.BeginStatus.NONCE_MISMATCH,
          materialSecret.getBytes(StandardCharsets.UTF_8),
          "TOKEN_SENTINEL".getBytes(StandardCharsets.UTF_8));
    }, null);
    try (Service service = new Service(lifecycle, keys(), event -> events.add(event.clone()))) {
      Submission secretSubmission = new Submission("Y2hhbGxlbmdlLTEyMzQ1Ng",
          "NONCE_SENTINEL", "PRIVATE_ANSWER_SENTINEL");
      VerificationOutcome first = service.verify(secretSubmission, secretBinding);
      VerificationOutcome second = service.verify(secretSubmission, secretBinding);
      assertEquals(VerificationOutcome.rejected(
          VerificationOutcome.RejectionReason.NONCE_MISMATCH), first);
      assertEquals(first, second);
      String publicText = String.valueOf(first) + second + service;
      for (String sentinel : sentinels) assertFalse(publicText.contains(sentinel));
    }
    String observed = events.stream().map(bytes -> new String(bytes, StandardCharsets.UTF_8))
        .reduce("", String::concat);
    for (String sentinel : sentinels) assertFalse(observed.contains(sentinel));
  }

  @Test
  void keyActiveCloseAndReleaseSentinelsDoNotLeak() {
    List<byte[]> issueEvents = new ArrayList<>();
    KeyProvider activeSentinel = new KeyProvider() {
      public ActiveResult activeKey() {
        return new ActiveResult(Status.OK,
            "ACTIVE_KEY_SENTINEL".getBytes(StandardCharsets.UTF_8), KEY);
      }
      public Result keyById(byte[] keyId) { throw new IllegalStateException("KEY_SENTINEL"); }
    };
    Service issueService = new Service(lifecycle(), activeSentinel,
        event -> issueEvents.add(event.clone()));
    PublicChallenge challenge = issueService.issue(IssueRequest.newV1IssueRequest(BINDING));
    String issuePublic = String.valueOf(challenge) + issueService + eventsText(issueEvents);
    assertFalse(issuePublic.contains("ACTIVE_KEY_SENTINEL"));
    CogGateException keyError = assertThrows(CogGateException.class,
        () -> issueService.verify(submission(), BINDING));
    assertEquals("internal_error", keyError.code());
    assertFalse((keyError + eventsText(issueEvents)).contains("KEY_SENTINEL"));
    issueService.close();
    CogGateException closed = assertThrows(CogGateException.class,
        () -> issueService.issue(IssueRequest.newV1IssueRequest(
            "CLOSED_SERVICE_SENTINEL".getBytes(StandardCharsets.UTF_8))));
    assertEquals("invalid_argument", closed.code());
    assertFalse(closed.toString().contains("CLOSED_SERVICE_SENTINEL"));

    byte[] releaseToken = "DOUBLE_RELEASE_SENTINEL".getBytes(StandardCharsets.UTF_8);
    AtomicReference<byte[]> finished = new AtomicReference<>();
    Lifecycle releaseLifecycle = lifecycle(null,
        (identity, binding, time) -> new Lifecycle.BeginResult(
            Lifecycle.BeginStatus.OK, MATERIAL, releaseToken),
        (token, outcome) -> {
          finished.set(token.clone());
          return Lifecycle.Status.OK;
        });
    long releases = Service.testReleaseCount();
    VerificationOutcome result;
    try (Service service = new Service(releaseLifecycle, keys(), null)) {
      result = service.verify(submission(), BINDING);
      assertFalse((String.valueOf(result) + service).contains("DOUBLE_RELEASE_SENTINEL"));
    }
    assertArrayEquals(releaseToken, finished.get());
    assertEquals(releases + 3, Service.testReleaseCount());
  }

  private static Lifecycle lifecycle() {
    return lifecycle((privateJson, binding, limit) -> Lifecycle.Status.OK,
        (identity, binding, time) -> new Lifecycle.BeginResult(
            Lifecycle.BeginStatus.OK, MATERIAL, hex("aabbccdd")),
        (token, outcome) -> Lifecycle.Status.OK);
  }

  private static Lifecycle lifecycle(Store store, Begin begin, Finish finish) {
    Store actualStore = store == null ? (a, b, c) -> Lifecycle.Status.OK : store;
    Begin actualBegin = begin == null ? (a, b, c) -> new Lifecycle.BeginResult(
        Lifecycle.BeginStatus.OK, MATERIAL, hex("aabbccdd")) : begin;
    Finish actualFinish = finish == null ? (a, b) -> Lifecycle.Status.OK : finish;
    return new Lifecycle() {
      public Status storeIssued(byte[] privateJson, byte[] binding, AttemptLimit limit) {
        return actualStore.call(privateJson, binding, limit);
      }
      public BeginResult beginAttempt(byte[] identityJson, byte[] binding, long serverTime) {
        return actualBegin.call(identityJson, binding, serverTime);
      }
      public Status finishAttempt(byte[] token, AttemptOutcome outcome) {
        return actualFinish.call(token, outcome);
      }
    };
  }

  private static KeyProvider keys() {
    return keys(id -> new KeyProvider.Result(KeyProvider.Status.OK, KEY));
  }

  private static KeyProvider keys(Lookup lookup) {
    return new KeyProvider() {
      public ActiveResult activeKey() {
        return new ActiveResult(Status.OK, "active-2026-09".getBytes(StandardCharsets.UTF_8), KEY);
      }
      public Result keyById(byte[] keyId) { return lookup.call(keyId); }
    };
  }

  private static Submission submission() {
    return new Submission("Y2hhbGxlbmdlLTEyMzQ1Ng", "bm9uY2UtMTIzNDU2Nzg5MA", "YQ");
  }

  private static byte[] hex(String value) {
    return java.util.HexFormat.of().parseHex(value);
  }

  private static void forceGc() throws InterruptedException {
    for (int count = 0; count < 5; count++) {
      System.gc();
      Thread.sleep(20);
    }
  }

  private static WeakReference<Service> unclosedService() {
    Service service = new Service(lifecycle(), keys(), null);
    return new WeakReference<>(service);
  }

  private static WeakReference<Service> cyclicUnclosedService() {
    AtomicReference<Service> holder = new AtomicReference<>();
    Lifecycle lifecycle = lifecycle((privateJson, binding, limit) -> {
      if (holder.get() == null) throw new AssertionError("missing service cycle");
      return Lifecycle.Status.OK;
    }, null, null);
    Service service = new Service(lifecycle, keys(), null);
    holder.set(service);
    return new WeakReference<>(service);
  }

  private static void await(CountDownLatch latch) {
    try {
      assertTrue(latch.await(5, TimeUnit.SECONDS));
    } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
      throw new AssertionError(error);
    }
  }

  private static Map<String, Object> parseObject(byte[] value) {
    try (JsonParser parser = new JsonFactory().createParser(value)) {
      assertEquals(JsonToken.START_OBJECT, parser.nextToken());
      Map<String, Object> result = new LinkedHashMap<>();
      while (parser.nextToken() != JsonToken.END_OBJECT) {
        String field = parser.currentName();
        JsonToken token = parser.nextToken();
        Object fieldValue = switch (token) {
          case VALUE_STRING -> parser.getText();
          case VALUE_NUMBER_INT -> parser.getLongValue();
          default -> throw new AssertionError("unexpected JSON token " + token);
        };
        result.put(field, fieldValue);
      }
      assertNull(parser.nextToken());
      return result;
    } catch (IOException error) {
      throw new AssertionError(error);
    }
  }

  private static void assertStrictUtf8(byte[] value) {
    try {
      StandardCharsets.UTF_8.newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(value));
    } catch (CharacterCodingException error) {
      throw new AssertionError("malformed observer UTF-8", error);
    }
  }

  private static String eventsText(List<byte[]> events) {
    return events.stream().map(bytes -> new String(bytes, StandardCharsets.UTF_8))
        .reduce("", String::concat);
  }

  @FunctionalInterface private interface Store {
    Lifecycle.Status call(byte[] privateJson, byte[] binding, AttemptLimit limit);
  }
  @FunctionalInterface private interface Begin {
    Lifecycle.BeginResult call(byte[] identity, byte[] binding, long time);
  }
  @FunctionalInterface private interface Finish {
    Lifecycle.Status call(byte[] token, Lifecycle.AttemptOutcome outcome);
  }
  @FunctionalInterface private interface Lookup {
    KeyProvider.Result call(byte[] keyId);
  }
}
