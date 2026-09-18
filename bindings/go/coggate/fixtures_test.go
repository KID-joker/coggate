package coggate

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

type goFixtureManifest struct {
	FixtureVersion int `json:"fixture_version"`
	Statuses       map[string]struct {
		Value int32  `json:"value"`
		Code  string `json:"code"`
	} `json:"statuses"`
	Vectors struct {
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
			Replay            bool   `json:"replay"`
		} `json:"lifecycle"`
		Keys struct {
			Status            string `json:"status"`
			KeyID             string `json:"key_id"`
			CallbackException bool   `json:"callback_exception"`
		} `json:"keys"`
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

func fixtureKeyStatus(name string) KeyStatus {
	return map[string]KeyStatus{
		"ok": KeyStatusOK, "unavailable": KeyStatusUnavailable,
		"not_found": KeyStatusNotFound, "invalid_material": KeyStatusInvalidMaterial,
	}[name]
}

func fixtureStatusForError(manifest goFixtureManifest, err error) int32 {
	if err == nil {
		return 0
	}
	code := stableErrorCode(err)
	for _, status := range manifest.Statuses {
		if status.Code == code {
			return status.Value
		}
	}
	return -1
}

func TestAllSharedBindingFixtureCasesAreConsumedExactly(t *testing.T) {
	requireDirectLinkedNativeLibrary(t)
	manifest := loadGoFixture(t)
	required := []string{"accepted", "answer_mismatch", "callback_exception", "close_after_use", "exact_release", "finish_failure", "key_rotation_old_key", "lifecycle_already_consumed", "lifecycle_attempts_exhausted", "lifecycle_binding_mismatch", "lifecycle_expired", "lifecycle_nonce_mismatch", "lifecycle_not_found", "observer_allowlist", "replay_after_accept"}
	consumed := make([]string, 0, len(manifest.Cases))
	privateJSON, _ := json.Marshal(manifest.Vectors.PrivateMaterial)
	defaultToken, _ := hex.DecodeString(manifest.Vectors.TokenHex)
	oldKey, _ := hex.DecodeString(manifest.Vectors.OldKeyHex)
	activeKey, _ := hex.DecodeString(manifest.Vectors.ActiveKeyHex)

	for _, fixture := range manifest.Cases {
		t.Run(fixture.ID, func(t *testing.T) {
			consumed = append(consumed, fixture.ID)
			var trace, observed []string
			var traceMu sync.Mutex
			appendTrace := func(value string) {
				traceMu.Lock()
				defer traceMu.Unlock()
				trace = append(trace, value)
			}
			binding := mustHex(t, fixture.BindingHex)
			material := map[string][]byte{"primary": privateJSON, "none": nil}[fixture.Lifecycle.Material]
			token := map[string][]byte{"default": defaultToken, "none": nil}[fixture.Lifecycle.Token]
			if fixture.Lifecycle.Material != "primary" && fixture.Lifecycle.Material != "none" {
				t.Fatalf("unknown fixture material %q", fixture.Lifecycle.Material)
			}
			if fixture.Lifecycle.Token != "default" && fixture.Lifecycle.Token != "none" {
				t.Fatalf("unknown fixture token %q", fixture.Lifecycle.Token)
			}
			attemptConsumed := false
			lifecycle := &serviceLifecycle{
				beginFn: func([]byte, []byte, int64) BeginAttemptResult {
					if fixture.Lifecycle.CallbackException {
						appendTrace("begin_attempt:exception")
						panic("CALLBACK_EXCEPTION_SENTINEL")
					}
					appendTrace("begin_attempt")
					if fixture.Lifecycle.Replay && !attemptConsumed {
						return BeginAttemptResult{Status: BeginStatusOK, Material: privateJSON, Token: defaultToken}
					}
					status := fixtureBeginStatus(fixture.Lifecycle.BeginStatus)
					if status != BeginStatusOK {
						return BeginAttemptResult{Status: status, Material: material, Token: token}
					}
					return BeginAttemptResult{Status: status, Material: material, Token: token}
				},
				finishFn: func(_ []byte, outcome AttemptOutcome) LifecycleStatus {
					appendTrace("finish_attempt:" + map[AttemptOutcome]string{AttemptOutcomeAccepted: "accepted", AttemptOutcomeRejected: "rejected", AttemptOutcomeSystemFailure: "system_failure"}[outcome])
					if outcome == AttemptOutcomeAccepted {
						attemptConsumed = true
					}
					if fixture.Lifecycle.FinishStatus == "internal" {
						return LifecycleStatusInternal
					}
					return LifecycleStatusOK
				},
			}
			keys := &serviceKeys{
				activeFn: func() ActiveKeyResult {
					appendTrace("active_key")
					if fixture.Keys.CallbackException {
						panic("KEY_CALLBACK_EXCEPTION_SENTINEL")
					}
					return ActiveKeyResult{Status: fixtureKeyStatus(fixture.Keys.Status), KeyID: manifest.Vectors.ActiveKeyID, Key: activeKey}
				},
				byIDFn: func(id string) KeyResult {
					appendTrace("key_by_id:" + fixture.Keys.KeyID)
					if fixture.Keys.CallbackException {
						panic("KEY_CALLBACK_EXCEPTION_SENTINEL")
					}
					keyID, keyStatus := fixture.Keys.KeyID, fixture.Keys.Status
					if fixture.Lifecycle.Replay && !attemptConsumed {
						keyID, keyStatus = "old", "ok"
					}
					wantID := map[string]string{"old": manifest.Vectors.OldKeyID, "active": manifest.Vectors.ActiveKeyID, "none": ""}[keyID]
					if id != wantID {
						t.Errorf("key id = %q want %q", id, wantID)
					}
					key := map[string][]byte{"old": oldKey, "active": activeKey, "none": nil}[keyID]
					return KeyResult{Status: fixtureKeyStatus(keyStatus), Key: key}
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
					appendTrace("observe:" + name)
					observed = append(observed, string(event))
				}}
			}
			service, err := NewService(lifecycle, keys, observer, "")
			if err != nil {
				t.Fatal(err)
			}
			service.callbacks.releaseHook = func(tag hostReleaseTag) { appendTrace("release:" + tag.String()) }
			var publicError error
			var outcome VerificationOutcome
			if fixture.Lifecycle.Replay {
				first, firstErr := service.Verify(*fixture.Submission, binding)
				if firstErr != nil || first.Status != VerificationStatusAccepted || !attemptConsumed {
					t.Fatalf("replay setup did not accept: %#v %v consumed=%v", first, firstErr, attemptConsumed)
				}
				trace, observed = nil, nil
			}
			nativeResetHostAllocationCounters()
			switch fixture.Operation {
			case "close":
				if err := service.Close(); err != nil {
					t.Fatal(err)
				}
				if err := service.Close(); err != nil {
					t.Fatal(err)
				}
				appendTrace("service_destroy")
			case "verify", "release", "observe":
				outcome, publicError = service.Verify(*fixture.Submission, binding)
				if err := service.Close(); err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatalf("unknown fixture operation %q", fixture.Operation)
			}
			gotCode := "ok"
			if publicError != nil {
				gotCode = stableErrorCode(publicError)
			}
			if gotCode != fixture.ExpectedCode {
				t.Fatalf("public code = %q want %q", gotCode, fixture.ExpectedCode)
			}
			if gotStatus := fixtureStatusForError(manifest, publicError); gotStatus != fixture.ExpectedStatus {
				t.Fatalf("public status = %d want %d", gotStatus, fixture.ExpectedStatus)
			}
			if fixture.ExpectedOutcome == nil {
				if outcome != (VerificationOutcome{}) {
					t.Fatalf("outcome = %#v want none", outcome)
				}
			} else if outcome != *fixture.ExpectedOutcome {
				t.Fatalf("outcome = %#v want %#v", outcome, *fixture.ExpectedOutcome)
			}
			allocations, releases := nativeHostAllocationCounters()
			if allocations != fixture.ExpectedReleaseCount || releases != fixture.ExpectedReleaseCount {
				t.Fatalf("release counts = %d/%d want %d", allocations, releases, fixture.ExpectedReleaseCount)
			}
			if !slices.Equal(trace, fixture.ExpectedTrace) {
				t.Fatalf("trace = %v want %v", trace, fixture.ExpectedTrace)
			}
			outcomeJSON, _ := json.Marshal(outcome)
			public := bytes.Join([][]byte{
				[]byte(stableErrorCode(publicError)), []byte(fmt.Sprint(publicError)),
				outcomeJSON, []byte(joinStrings(observed)),
			}, nil)
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
				if fixture.ID == "observer_allowlist" && event["event"] == "verification_completed" {
					allowed := make(map[string]bool, len(manifest.Vectors.ObserverAllowlist))
					for _, field := range manifest.Vectors.ObserverAllowlist {
						allowed[field] = true
					}
					if len(event) != len(allowed) {
						t.Errorf("observer key count = %d want exactly %v", len(event), manifest.Vectors.ObserverAllowlist)
					}
					for field := range event {
						if !allowed[field] {
							t.Errorf("observer exposed field %q", field)
						}
					}
				}
				var answer, nonce string
				if fixture.Submission != nil {
					answer, nonce = fixture.Submission.Answer, fixture.Submission.Nonce
				}
				for _, secret := range []string{answer, nonce, manifest.Vectors.OldKeyID} {
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
