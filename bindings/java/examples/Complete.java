package io.agentgate.examples;

import io.agentgate.AttemptLimit;
import io.agentgate.IssueRequest;
import io.agentgate.KeyProvider;
import io.agentgate.Lifecycle;
import io.agentgate.PublicChallenge;
import io.agentgate.Service;
import io.agentgate.Submission;
import io.agentgate.VerificationOutcome;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

/** Minimal full issue/verify/close example. It prints only safe result statuses. */
public final class Complete {
  private Complete() {}

  public static void main(String[] args) {
    if (args.length != 1) throw new IllegalArgumentException("expected JNI library path");
    Service.loadNative(Path.of(args[0]));
    byte[] activeKey = java.util.HexFormat.of().parseHex(
        "1111111111111111111111111111111111111111111111111111111111111111");
    byte[] oldKey = java.util.HexFormat.of().parseHex(
        "3031323334353637383961626364656630313233343536373839616263646566");
    byte[] fixtureMaterial = ("{\"challenge_id\":\"Y2hhbGxlbmdlLTEyMzQ1Ng\","
        + "\"generator_version\":\"1.0\",\"nonce\":\"bm9uY2UtMTIzNDU2Nzg5MA\","
        + "\"issued_at\":1788062400,\"expires_at\":1788062408,"
        + "\"mac_key_id\":\"2026-08\","
        + "\"answer_mac\":\"b9cb8fd013b40e31c7bc3a1c33b7e36143ef98d045a924ed09ebd38ff07cec2c\","
        + "\"answer_encoding\":\"base64url\"}").getBytes(StandardCharsets.UTF_8);
    AtomicReference<byte[]> issuedMaterial = new AtomicReference<>();
    Lifecycle lifecycle = new Lifecycle() {
      public Status storeIssued(byte[] privateJson, byte[] binding, AttemptLimit limit) {
        issuedMaterial.set(privateJson.clone());
        return Status.OK;
      }
      public BeginResult beginAttempt(byte[] identity, byte[] binding, long serverTime) {
        // Demonstrates verification of the repository's checked-in, previously issued vector.
        return new BeginResult(BeginStatus.OK, fixtureMaterial, new byte[0]);
      }
      public Status finishAttempt(byte[] value, AttemptOutcome outcome) { return Status.OK; }
    };
    KeyProvider keys = new KeyProvider() {
      public ActiveResult activeKey() {
        return new ActiveResult(Status.OK,
            "active-2026-09".getBytes(StandardCharsets.UTF_8), activeKey);
      }
      public Result keyById(byte[] keyId) { return new Result(Status.OK, oldKey); }
    };
    try (Service service = new Service(lifecycle, keys, null)) {
      byte[] binding = java.util.HexFormat.of().parseHex("0011223344556677");
      PublicChallenge challenge = service.issue(IssueRequest.newV1IssueRequest(binding));
      System.out.println("issue: ok");
      if (challenge == null || issuedMaterial.get() == null) throw new IllegalStateException("issue failed");
      Submission submission = new Submission(
          "Y2hhbGxlbmdlLTEyMzQ1Ng", "bm9uY2UtMTIzNDU2Nzg5MA", "YQ");
      VerificationOutcome outcome = service.verify(submission, binding);
      System.out.println("verify: " + outcome.status().wireValue());
    }
  }
}
