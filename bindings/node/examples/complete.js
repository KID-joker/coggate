import { Service, Submission, newV1IssueRequest } from 'coggate';

const binding = Uint8Array.from(Buffer.from('0011223344556677', 'hex'));
const key = Uint8Array.from(Buffer.from(
  '3031323334353637383961626364656630313233343536373839616263646566', 'hex'));
const material = new TextEncoder().encode('{"challenge_id":"Y2hhbGxlbmdlLTEyMzQ1Ng","generator_version":"1.0","nonce":"bm9uY2UtMTIzNDU2Nzg5MA","issued_at":1788062400,"expires_at":1788062408,"mac_key_id":"2026-08","answer_mac":"ccdffbb67b4c9da34f91d56d12970b311d7345e8bcf579d1326fc4a78633330c","answer_encoding":"base64url"}');
const service = new Service({
  lifecycle: {
    storeIssued: () => 0,
    beginAttempt: () => ({ status: 0, material, token: Uint8Array.from([0xaa, 0xbb, 0xcc, 0xdd]) }),
    finishAttempt: () => 0,
  },
  keys: {
    activeKey: () => ({ status: 0, keyId: new TextEncoder().encode('active-2026-09'), key }),
    keyById: () => ({ status: 0, key }),
  },
});

try {
  service.issue(newV1IssueRequest(binding));
  console.log('issue: ok');
  const outcome = service.verify(new Submission({
    challengeId: 'Y2hhbGxlbmdlLTEyMzQ1Ng',
    nonce: 'bm9uY2UtMTIzNDU2Nzg5MA',
    answer: 'YQ',
  }), binding);
  console.log(`verify: ${outcome.status}`);
} finally {
  service.close();
}
