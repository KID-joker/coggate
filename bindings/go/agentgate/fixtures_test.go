package agentgate

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

type goFixtureManifest struct {
	FixtureVersion int `json:"fixture_version"`
	Vectors        struct {
		BindingHex        string         `json:"binding_hex"`
		TokenHex          string         `json:"token_hex"`
		ActiveKeyID       string         `json:"active_key_id"`
		ActiveKeyHex      string         `json:"active_key_hex"`
		OldKeyID          string         `json:"old_key_id"`
		OldKeyHex         string         `json:"old_key_hex"`
		PrivateMaterial   map[string]any `json:"private_material"`
		ObserverAllowlist []string       `json:"observer_allowlist"`
	} `json:"vectors"`
	Cases []struct {
		ID           string      `json:"id"`
		Operation    string      `json:"operation"`
		BindingHex   string      `json:"binding_hex"`
		ExpectedCode string      `json:"expected_code"`
		Submission   *Submission `json:"submission"`
		Lifecycle    struct {
			BeginStatus       string `json:"begin_status"`
			FinishStatus      string `json:"finish_status"`
			Material          string `json:"material"`
			Token             string `json:"token"`
			CallbackException bool   `json:"callback_exception"`
		} `json:"lifecycle"`
		ExpectedStatus       int32                `json:"expected_status"`
		ExpectedOutcome      *VerificationOutcome `json:"expected_outcome"`
		ExpectedTrace        []string             `json:"expected_trace"`
		ExpectedReleaseCount uint64               `json:"expected_release_count"`
		ForbiddenSentinels   []string             `json:"forbidden_sentinels"`
	} `json:"cases"`
}

func loadGoFixture(t *testing.T) goFixtureManifest {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "..", "..", "fixtures", "bindings", "v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture goFixtureManifest
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func fixtureBeginStatus(name string) BeginStatus {
	return map[string]BeginStatus{"ok": BeginStatusOK, "unavailable": BeginStatusUnavailable, "conflict": BeginStatusConflict, "internal": BeginStatusInternal, "not_found": BeginStatusNotFound, "expired": BeginStatusExpired, "already_consumed": BeginStatusAlreadyConsumed, "binding_mismatch": BeginStatusBindingMismatch, "nonce_mismatch": BeginStatusNonceMismatch, "attempts_exhausted": BeginStatusAttemptsExhausted}[name]
}

func TestAllSharedBindingFixtureCasesAreConsumedExactly(t *testing.T) {
	requireDirectLinkedNativeLibrary(t)
	manifest := loadGoFixture(t)
	required := []string{"accepted", "answer_mismatch", "callback_exception", "close_after_use", "exact_release", "finish_failure", "key_rotation_old_key", "lifecycle_already_consumed", "lifecycle_attempts_exhausted", "lifecycle_binding_mismatch", "lifecycle_expired", "lifecycle_nonce_mismatch", "lifecycle_not_found", "observer_allowlist", "replay_after_accept"}
	consumed := make([]string, 0, len(manifest.Cases))
	privateJSON, _ := json.Marshal(manifest.Vectors.PrivateMaterial)
	binding, _ := hex.DecodeString(manifest.Vectors.BindingHex)
	token, _ := hex.DecodeString(manifest.Vectors.TokenHex)
	oldKey, _ := hex.DecodeString(manifest.Vectors.OldKeyHex)
	activeKey, _ := hex.DecodeString(manifest.Vectors.ActiveKeyHex)

	for _, fixture := range manifest.Cases {
		t.Run(fixture.ID, func(t *testing.T) {
			consumed = append(consumed, fixture.ID)
			var trace, observed []string
			lifecycle := &serviceLifecycle{
				beginFn: func([]byte, []byte, int64) BeginAttemptResult {
					if fixture.Lifecycle.CallbackException {
						trace = append(trace, "begin_attempt:exception")
						panic("CALLBACK_EXCEPTION_SENTINEL")
					}
					trace = append(trace, "begin_attempt")
					status := fixtureBeginStatus(fixture.Lifecycle.BeginStatus)
					if status != BeginStatusOK {
						return BeginAttemptResult{Status: status, Material: []byte("MATERIAL_SENTINEL"), Token: []byte("TOKEN_SENTINEL")}
					}
					return BeginAttemptResult{Status: status, Material: privateJSON, Token: token}
				},
				finishFn: func(_ []byte, outcome AttemptOutcome) LifecycleStatus {
					trace = append(trace, "finish_attempt:"+map[AttemptOutcome]string{AttemptOutcomeAccepted: "accepted", AttemptOutcomeRejected: "rejected", AttemptOutcomeSystemFailure: "system_failure"}[outcome])
					if fixture.Lifecycle.FinishStatus == "internal" {
						return LifecycleStatusInternal
					}
					return LifecycleStatusOK
				},
			}
			keys := &serviceKeys{
				activeFn: func() ActiveKeyResult {
					trace = append(trace, "active_key")
					return ActiveKeyResult{Status: KeyStatusOK, KeyID: manifest.Vectors.ActiveKeyID, Key: activeKey}
				},
				byIDFn: func(id string) KeyResult {
					trace = append(trace, "key_by_id:old")
					if id != manifest.Vectors.OldKeyID {
						t.Errorf("key id = %q", id)
					}
					return KeyResult{Status: KeyStatusOK, Key: oldKey}
				},
			}
			observerEnabled := fixture.Operation != "release"
			var observer Observer
			if observerEnabled {
				observer = &serviceObserver{fn: func(event []byte) {
					var object map[string]any
					if json.Unmarshal(event, &object) != nil {
						t.Error("invalid observer JSON")
						return
					}
					name, _ := object["event"].(string)
					trace = append(trace, "observe:"+name)
					observed = append(observed, string(event))
				}}
			}
			service, err := NewService(lifecycle, keys, observer, "")
			if err != nil {
				t.Fatal(err)
			}
			if fixture.Operation == "close" {
				if err := service.Close(); err != nil {
					t.Fatal(err)
				}
				if err := service.Close(); err != nil {
					t.Fatal(err)
				}
				trace = append(trace, "service_destroy")
			} else {
				nativeResetHostAllocationCounters()
				outcome, verifyErr := service.Verify(*fixture.Submission, binding)
				if got := stableErrorCode(verifyErr); got != map[bool]string{true: fixture.ExpectedCode, false: ""}[fixture.ExpectedStatus != 0] {
					t.Fatalf("Verify error = %q want %q", got, fixture.ExpectedCode)
				}
				if fixture.ExpectedStatus == 0 && outcome != *fixture.ExpectedOutcome {
					t.Fatalf("outcome = %#v want %#v", outcome, *fixture.ExpectedOutcome)
				}
				allocations, releases := nativeHostAllocationCounters()
				if allocations != fixture.ExpectedReleaseCount || releases != fixture.ExpectedReleaseCount {
					t.Fatalf("release counts = %d/%d want %d", allocations, releases, fixture.ExpectedReleaseCount)
				}
				if err := service.Close(); err != nil {
					t.Fatal(err)
				}
			}
			wantTrace := make([]string, 0, len(fixture.ExpectedTrace))
			for _, item := range fixture.ExpectedTrace {
				if len(item) < 8 || item[:8] != "release:" {
					wantTrace = append(wantTrace, item)
				}
			}
			if !slices.Equal(trace, wantTrace) {
				t.Fatalf("trace = %v want %v", trace, wantTrace)
			}
			public := bytes.Join([][]byte{[]byte(stableErrorCode(err)), []byte(joinStrings(observed))}, nil)
			for _, sentinel := range fixture.ForbiddenSentinels {
				if bytes.Contains(public, []byte(sentinel)) {
					t.Fatalf("public output leaked %q", sentinel)
				}
			}
			for _, raw := range observed {
				var event map[string]any
				if json.Unmarshal([]byte(raw), &event) != nil {
					t.Fatalf("invalid observer event: %q", raw)
				}
				allowed := map[string]bool{"event": true, "challenge_id": true, "generator_version": true, "stage": true, "error": true, "attempts": true, "duration_us": true}
				if event["event"] != "service_failed" {
					allowed = make(map[string]bool, len(manifest.Vectors.ObserverAllowlist))
					for _, field := range manifest.Vectors.ObserverAllowlist {
						allowed[field] = true
					}
				}
				for field := range event {
					if !allowed[field] {
						t.Errorf("observer exposed field %q", field)
					}
				}
				for _, secret := range []string{fixture.Submission.Answer, fixture.Submission.Nonce, manifest.Vectors.OldKeyID} {
					if secret != "" && bytes.Contains([]byte(raw), []byte(secret)) {
						t.Errorf("observer exposed sensitive value")
					}
				}
			}
		})
	}
	slices.Sort(consumed)
	if !slices.Equal(consumed, required) {
		t.Fatalf("consumed IDs = %v want %v", consumed, required)
	}
}

func joinStrings(values []string) string {
	var result string
	for _, value := range values {
		result += value
	}
	return result
}
