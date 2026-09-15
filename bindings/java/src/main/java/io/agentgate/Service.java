package io.agentgate;

import java.lang.ref.Cleaner;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.IntConsumer;

/** Thread-safe native AgentGate service with deterministic close semantics. */
public final class Service implements AutoCloseable {
  private static final Cleaner CLEANER = Cleaner.create();
  private static final ThreadLocal<Integer> CALLBACK_DEPTH = ThreadLocal.withInitial(() -> 0);
  private static final Object LOAD_LOCK = new Object();
  private static volatile boolean loaded;
  private static volatile IntConsumer testReleaseListener;

  private final Object lock = new Object();
  private final State state;
  private final Cleaner.Cleanable cleanable;
  private boolean closed;
  private int inFlight;

  public static void loadNative(Path path) {
    Objects.requireNonNull(path, "path");
    synchronized (LOAD_LOCK) {
      if (!loaded) {
        System.load(path.toAbsolutePath().normalize().toString());
        loaded = true;
      }
    }
  }

  public Service(Lifecycle lifecycle, KeyProvider keys, Observer observer) {
    if (!loaded || lifecycle == null || keys == null) throw AgentGateException.invalidArgument();
    long handle = nativeCreate(lifecycle, keys, observer);
    if (handle == 0) throw AgentGateException.fromStatus(7);
    state = new State(handle);
    cleanable = CLEANER.register(this, state);
  }

  public PublicChallenge issue(IssueRequest request) {
    if (request == null) throw AgentGateException.invalidArgument();
    long handle = beginCall();
    byte[] version = request.version().getBytes(StandardCharsets.UTF_8);
    byte[] binding = request.binding();
    try {
      return JsonCodec.decodePublicChallenge(
          nativeIssue(handle, version, binding, request.attemptLimit().value()));
    } catch (AgentGateException error) {
      throw error;
    } catch (RuntimeException error) {
      throw AgentGateException.fromStatus(7);
    } finally {
      Arrays.fill(version, (byte) 0);
      Arrays.fill(binding, (byte) 0);
      endCall();
    }
  }

  public VerificationOutcome verify(Submission submission, byte[] binding) {
    if (submission == null || binding == null || binding.length == 0 || binding.length > 256) {
      throw AgentGateException.invalidArgument();
    }
    long handle = beginCall();
    byte[] payload = JsonCodec.encodeSubmission(submission);
    byte[] bindingCopy = binding.clone();
    try {
      return JsonCodec.decodeOutcome(nativeVerify(handle, payload, bindingCopy));
    } catch (AgentGateException error) {
      throw error;
    } catch (RuntimeException error) {
      throw AgentGateException.fromStatus(7);
    } finally {
      Arrays.fill(payload, (byte) 0);
      Arrays.fill(bindingCopy, (byte) 0);
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

  private static boolean inCallback() { return CALLBACK_DEPTH.get() != 0; }

  // Called only by the JNI callback boundary.
  private static void enterCallback() { CALLBACK_DEPTH.set(CALLBACK_DEPTH.get() + 1); }
  private static void exitCallback() {
    int depth = CALLBACK_DEPTH.get() - 1;
    if (depth == 0) CALLBACK_DEPTH.remove(); else CALLBACK_DEPTH.set(depth);
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
  static void setTestReleaseListener(IntConsumer listener) { testReleaseListener = listener; }

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
}
