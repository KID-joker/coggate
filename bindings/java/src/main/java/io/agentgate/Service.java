package io.agentgate;

import java.lang.ref.Cleaner;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.IntConsumer;

/** Thread-safe native AgentGate service with deterministic close semantics. */
public final class Service implements AutoCloseable {
  private static final Cleaner CLEANER = Cleaner.create();
  private static final ThreadLocal<List<Long>> ACTIVE_CALLBACKS = new ThreadLocal<>();
  private static final Object LOAD_LOCK = new Object();
  private static volatile boolean loaded;
  private static volatile IntConsumer testReleaseListener;
  private static volatile Runnable testBeforeNativeHook;

  private final Object lock = new Object();
  private final Lifecycle lifecycle;
  private final KeyProvider keys;
  private final Observer observer;
  private final State state;
  private final Cleaner.Cleanable cleanable;
  private boolean closed;
  private int inFlight;

  public static void loadNative(Path path) {
    Objects.requireNonNull(path, "path");
    synchronized (LOAD_LOCK) {
      if (!loaded) {
        Path shim = path.toAbsolutePath().normalize();
        try {
          if (System.getProperty("os.name", "").startsWith("Windows")) {
            String configuredCore = System.getProperty("agentgate.core.path");
            Path core = configuredCore == null || configuredCore.isBlank()
                ? shim.resolveSibling("agentgate_ffi.dll")
                : Path.of(configuredCore).toAbsolutePath().normalize();
            if (Files.isRegularFile(core)) System.load(core.toString());
          }
          System.load(shim.toString());
          loaded = true;
        } catch (LinkageError | RuntimeException error) {
          throw new UnsatisfiedLinkError("AgentGate native library unavailable");
        }
      }
    }
  }

  public Service(Lifecycle lifecycle, KeyProvider keys, Observer observer) {
    if (!loaded || lifecycle == null || keys == null) throw AgentGateException.invalidArgument();
    this.lifecycle = lifecycle;
    this.keys = keys;
    this.observer = observer;
    long handle = nativeCreate(lifecycle, keys, observer);
    if (handle == 0) throw AgentGateException.fromStatus(7);
    state = new State(handle);
    cleanable = CLEANER.register(this, state);
  }

  public PublicChallenge issue(IssueRequest request) {
    if (request == null) throw AgentGateException.invalidArgument();
    long handle = beginCall();
    byte[] version = null;
    byte[] binding = null;
    try {
      runTestBeforeNativeHook();
      version = request.version().getBytes(StandardCharsets.UTF_8);
      binding = request.binding();
      return JsonCodec.decodePublicChallenge(
          nativeIssue(handle, version, binding, request.attemptLimit().value()));
    } catch (AgentGateException error) {
      throw error;
    } catch (RuntimeException error) {
      throw AgentGateException.fromStatus(7);
    } finally {
      if (version != null) Arrays.fill(version, (byte) 0);
      if (binding != null) Arrays.fill(binding, (byte) 0);
      endCall();
    }
  }

  public VerificationOutcome verify(Submission submission, byte[] binding) {
    if (submission == null || binding == null || binding.length == 0 || binding.length > 256) {
      throw AgentGateException.invalidArgument();
    }
    long handle = beginCall();
    byte[] payload = null;
    byte[] bindingCopy = null;
    try {
      runTestBeforeNativeHook();
      payload = JsonCodec.encodeSubmission(submission);
      bindingCopy = binding.clone();
      return JsonCodec.decodeOutcome(nativeVerify(handle, payload, bindingCopy));
    } catch (AgentGateException error) {
      throw error;
    } catch (RuntimeException error) {
      throw AgentGateException.fromStatus(7);
    } finally {
      if (payload != null) Arrays.fill(payload, (byte) 0);
      if (bindingCopy != null) Arrays.fill(bindingCopy, (byte) 0);
      endCall();
    }
  }

  @Override
  public void close() {
    if (inCallback()) throw AgentGateException.invalidArgument();
    boolean interrupted = false;
    synchronized (lock) {
      closed = true;
      while (inFlight != 0) {
        try {
          lock.wait();
        } catch (InterruptedException error) {
          interrupted = true;
        }
      }
    }
    int status = state.destroy();
    cleanable.clean();
    if (interrupted) Thread.currentThread().interrupt();
    AgentGateException error = AgentGateException.fromStatus(status);
    if (error != null) throw error;
  }

  private long beginCall() {
    if (inCallback()) throw AgentGateException.invalidArgument();
    synchronized (lock) {
      if (closed) throw AgentGateException.invalidArgument();
      long handle = state.handle.get();
      if (handle == 0) throw AgentGateException.invalidArgument();
      inFlight++;
      return handle;
    }
  }

  private void endCall() {
    synchronized (lock) {
      inFlight--;
      if (inFlight == 0) lock.notifyAll();
    }
  }

  private boolean inCallback() {
    long handle = state.handle.get();
    List<Long> callbacks = ACTIVE_CALLBACKS.get();
    return handle != 0 && callbacks != null && callbacks.contains(handle);
  }
  private static void runTestBeforeNativeHook() {
    Runnable hook = testBeforeNativeHook;
    if (hook != null) hook.run();
  }

  // Called only by the JNI callback boundary.
  private static void enterCallback(long handle) {
    List<Long> callbacks = ACTIVE_CALLBACKS.get();
    if (callbacks == null) {
      callbacks = new ArrayList<>();
      ACTIVE_CALLBACKS.set(callbacks);
    }
    callbacks.add(handle);
  }
  private static void exitCallback(long handle) {
    List<Long> callbacks = ACTIVE_CALLBACKS.get();
    if (callbacks == null) throw new IllegalStateException("callback handle is not active");
    for (int index = callbacks.size() - 1; index >= 0; index--) {
      if (callbacks.get(index) == handle) {
        callbacks.remove(index);
        if (callbacks.isEmpty()) ACTIVE_CALLBACKS.remove();
        return;
      }
    }
    throw new IllegalStateException("callback handle is not active");
  }
  private static void released(int tag) {
    IntConsumer listener = testReleaseListener;
    if (listener != null) listener.accept(tag);
  }

  static boolean testCallbackFromAttachedThread(Lifecycle lifecycle) {
    return nativeTestCallbackFromAttachedThread(lifecycle);
  }
  static long testAttachCount() { return nativeTestAttachCount(); }
  static long testDetachCount() { return nativeTestDetachCount(); }
  static long testAllocationCount() { return nativeTestAllocationCount(); }
  static long testReleaseCount() { return nativeTestReleaseCount(); }
  static long testDestroyCount() { return nativeTestDestroyCount(); }
  static long testWipeCount() { return nativeTestWipeCount(); }
  static long testWipeFailureCount() { return nativeTestWipeFailureCount(); }
  static boolean testPendingExceptionCleanup() { return nativeTestPendingExceptionCleanup(); }
  static boolean testPendingExceptionAudit(
      Lifecycle.BeginResult result, Lifecycle.Status status) {
    return nativeTestPendingExceptionAudit(result, status);
  }
  static void setTestReleaseListener(IntConsumer listener) { testReleaseListener = listener; }
  static void setTestBeforeNativeHook(Runnable hook) { testBeforeNativeHook = hook; }

  @Override public String toString() { return "Service()"; }

  private static final class State implements Runnable {
    private final AtomicLong handle;
    State(long handle) { this.handle = new AtomicLong(handle); }
    int destroy() {
      long value = handle.getAndSet(0);
      return value == 0 ? 0 : nativeDestroy(value);
    }
    @Override public void run() { destroy(); }
  }

  private static native long nativeCreate(Lifecycle lifecycle, KeyProvider keys, Observer observer);
  private static native int nativeDestroy(long handle);
  private static native byte[] nativeIssue(long handle, byte[] version, byte[] binding, int limit);
  private static native byte[] nativeVerify(long handle, byte[] submission, byte[] binding);
  private static native boolean nativeTestCallbackFromAttachedThread(Lifecycle lifecycle);
  private static native long nativeTestAttachCount();
  private static native long nativeTestDetachCount();
  private static native long nativeTestAllocationCount();
  private static native long nativeTestReleaseCount();
  private static native long nativeTestDestroyCount();
  private static native long nativeTestWipeCount();
  private static native long nativeTestWipeFailureCount();
  private static native boolean nativeTestPendingExceptionCleanup();
  private static native boolean nativeTestPendingExceptionAudit(
      Lifecycle.BeginResult result, Lifecycle.Status status);
}
