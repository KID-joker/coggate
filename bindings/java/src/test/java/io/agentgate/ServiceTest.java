package io.agentgate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.ref.WeakReference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
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
      + "\"answer_mac\":\"b9cb8fd013b40e31c7bc3a1c33b7e36143ef98d045a924ed09ebd38ff07cec2c\","
      + "\"answer_encoding\":\"base64url\"}").getBytes(StandardCharsets.UTF_8);

  @BeforeAll
  static void loadNative() {
    String path = System.getProperty("agentgate.jni.path");
    assertNotNull(path, "-Dagentgate.jni.path must name the built JNI shim");
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
      assertFalse(new String(stored.get(), StandardCharsets.UTF_8).contains("\"answer\":"));
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
      AgentGateException error = assertThrows(AgentGateException.class,
          () -> service.verify(submission(), BINDING));
      assertEquals("internal_error", error.code());
      assertFalse(error.toString().contains("CALLBACK_EXCEPTION_SENTINEL"));
      assertFalse(error.toString().contains("agentgate_ffi"));
      assertDoesNotThrow(() -> service.close());
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
      errors.add(assertThrows(AgentGateException.class, reference.get()::close).code());
      errors.add(assertThrows(AgentGateException.class,
          () -> reference.get().issue(IssueRequest.newV1IssueRequest(BINDING))).code());
      return Lifecycle.Status.OK;
    }, null, null);
    Service service = new Service(lifecycle, keys(), null);
    reference.set(service);
    service.issue(IssueRequest.newV1IssueRequest(BINDING));
    assertEquals(List.of("invalid_argument", "invalid_argument"), errors);
    service.close();
    assertEquals("invalid_argument", assertThrows(AgentGateException.class,
        () -> service.issue(IssueRequest.newV1IssueRequest(BINDING))).code());
    assertEquals("invalid_argument", assertThrows(AgentGateException.class,
        () -> service.verify(submission(), BINDING)).code());
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
    try (Service service = new Service(lifecycle, keys, null)) {
      assertEquals(VerificationOutcome.accepted(), service.verify(submission(), BINDING));
    }
    assertEquals(allocations + 3, Service.testAllocationCount());
    assertEquals(releases + 3, Service.testReleaseCount());
    assertArrayEquals(MATERIAL, material);
    assertArrayEquals(hex("aabbccdd"), token);
    assertArrayEquals(KEY, key);
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

  private static void await(CountDownLatch latch) {
    try {
      assertTrue(latch.await(5, TimeUnit.SECONDS));
    } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
      throw new AssertionError(error);
    }
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
