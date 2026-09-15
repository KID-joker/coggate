package io.agentgate;

/** Best-effort secret-safe event callback. Exceptions are swallowed by the JNI shim. */
@FunctionalInterface
public interface Observer {
  void observe(byte[] eventJson);
}
