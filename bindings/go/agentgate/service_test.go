package agentgate

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type serviceLifecycle struct {
	storeFn  func([]byte, []byte, AttemptLimit) LifecycleStatus
	beginFn  func([]byte, []byte, int64) BeginAttemptResult
	finishFn func([]byte, AttemptOutcome) LifecycleStatus
}

func (value *serviceLifecycle) StoreIssued(privateJSON, binding []byte, limit AttemptLimit) LifecycleStatus {
	if value.storeFn != nil {
		return value.storeFn(privateJSON, binding, limit)
	}
	return LifecycleStatusOK
}
func (value *serviceLifecycle) BeginAttempt(identityJSON, binding []byte, serverTime int64) BeginAttemptResult {
	if value.beginFn != nil {
		return value.beginFn(identityJSON, binding, serverTime)
	}
	return BeginAttemptResult{Status: BeginStatusNotFound}
}
func (value *serviceLifecycle) FinishAttempt(token []byte, outcome AttemptOutcome) LifecycleStatus {
	if value.finishFn != nil {
		return value.finishFn(token, outcome)
	}
	return LifecycleStatusOK
}

type serviceKeys struct {
	activeFn func() ActiveKeyResult
	byIDFn   func(string) KeyResult
}

func (value *serviceKeys) ActiveKey() ActiveKeyResult {
	if value.activeFn != nil {
		return value.activeFn()
	}
	return ActiveKeyResult{Status: KeyStatusUnavailable}
}
func (value *serviceKeys) KeyByID(id string) KeyResult {
	if value.byIDFn != nil {
		return value.byIDFn(id)
	}
	return KeyResult{Status: KeyStatusNotFound}
}

type serviceObserver struct{ fn func([]byte) }

func (value *serviceObserver) Observe(event []byte) {
	if value.fn != nil {
		value.fn(event)
	}
}

func validServiceProviders() (*serviceLifecycle, *serviceKeys) {
	return &serviceLifecycle{}, &serviceKeys{activeFn: func() ActiveKeyResult {
		return ActiveKeyResult{Status: KeyStatusOK, KeyID: "active", Key: bytes.Repeat([]byte{0x11}, 32)}
	}}
}

func TestCallbackStatusesAndResultsHaveSafeFormatting(t *testing.T) {
	if LifecycleStatusOK != 0 || LifecycleStatusInternal != 3 || BeginStatusNotFound != 10 || BeginStatusAttemptsExhausted != 15 || KeyStatusInvalidMaterial != 3 || AttemptOutcomeSystemFailure != 3 {
		t.Fatal("callback status values do not match the frozen ABI")
	}
	values := []any{
		BeginAttemptResult{Status: BeginStatusOK, Material: []byte("PRIVATE_JSON_SENTINEL"), Token: []byte("TOKEN_SENTINEL")},
		ActiveKeyResult{Status: KeyStatusOK, KeyID: "KEY_ID_SENTINEL", Key: []byte("KEY_SENTINEL")},
		KeyResult{Status: KeyStatusOK, Key: []byte("KEY_SENTINEL")},
	}
	for _, value := range values {
		for _, output := range []string{fmt.Sprint(value), fmt.Sprintf("%#v", value), value.(slog.LogValuer).LogValue().String()} {
			for _, secret := range []string{"PRIVATE_JSON_SENTINEL", "TOKEN_SENTINEL", "KEY_ID_SENTINEL", "KEY_SENTINEL"} {
				if strings.Contains(output, secret) {
					t.Fatalf("%T formatting leaked %q: %q", value, secret, output)
				}
			}
		}
	}
}

func TestNewServiceRejectsNilAndTypedNilProviders(t *testing.T) {
	lifecycle, keys := validServiceProviders()
	var typedNilLifecycle *serviceLifecycle
	var typedNilKeys *serviceKeys
	for _, test := range []struct {
		name      string
		lifecycle Lifecycle
		keys      KeyProvider
	}{
		{"nil lifecycle", nil, keys}, {"typed nil lifecycle", typedNilLifecycle, keys},
		{"nil keys", lifecycle, nil}, {"typed nil keys", lifecycle, typedNilKeys},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, err := NewService(test.lifecycle, test.keys, nil, "")
			if service != nil || stableErrorCode(err) != "invalid_argument" {
				t.Fatalf("NewService = %#v, %v", service, err)
			}
		})
	}
}

func TestServiceIssuesAndCopiesCallbackInputs(t *testing.T) {
	requireDirectLinkedNativeLibrary(t)
	lifecycle, keys := validServiceProviders()
	var sawBinding string
	var privateWasValid bool
	lifecycle.storeFn = func(privateJSON, binding []byte, limit AttemptLimit) LifecycleStatus {
		sawBinding, privateWasValid = string(binding), json.Valid(privateJSON)
		if limit != AttemptLimitTwo {
			t.Errorf("limit = %d", limit)
		}
		privateJSON[0] = 'X'
		binding[0] = 'Z'
		return LifecycleStatusOK
	}
	service, err := NewService(lifecycle, keys, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	binding := []byte("issue-binding")
	request, _ := NewIssueRequest("1.0", binding, AttemptLimitTwo)
	challenge, err := service.Issue(request)
	if err != nil || challenge.ChallengeID == "" {
		t.Fatalf("Issue = %#v, %v", challenge, err)
	}
	binding[0] = 'X'
	request.binding[1] = 'Y'
	if sawBinding != "issue-binding" || !privateWasValid {
		t.Fatalf("callback input = %q valid-private=%v", sawBinding, privateWasValid)
	}
	if request.binding[0] != 'i' {
		t.Fatal("callback input aliases request storage")
	}
}

func TestServiceRejectsMalformedCallbackSuccessAndPanics(t *testing.T) {
	requireDirectLinkedNativeLibrary(t)
	for _, test := range []struct {
		name   string
		active func() ActiveKeyResult
	}{
		{"panic", func() ActiveKeyResult { panic("KEY_SECRET_SENTINEL") }},
		{"empty id", func() ActiveKeyResult { return ActiveKeyResult{Status: KeyStatusOK, Key: bytes.Repeat([]byte{1}, 32)} }},
		{"short key", func() ActiveKeyResult { return ActiveKeyResult{Status: KeyStatusOK, KeyID: "id", Key: []byte("short")} }},
		{"invalid status", func() ActiveKeyResult {
			return ActiveKeyResult{Status: KeyStatus(99), KeyID: "id", Key: bytes.Repeat([]byte{1}, 32)}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			lifecycle, keys := validServiceProviders()
			keys.activeFn = test.active
			service, err := NewService(lifecycle, keys, nil, "")
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			request, _ := NewV1IssueRequest([]byte("binding"))
			_, issueErr := service.Issue(request)
			if stableErrorCode(issueErr) != "internal_error" {
				t.Fatalf("Issue error = %v", issueErr)
			}
			if strings.Contains(fmt.Sprint(issueErr), "SENTINEL") {
				t.Fatal("error leaked callback panic")
			}
		})
	}
}

func TestServiceObserverPanicIsSwallowed(t *testing.T) {
	requireDirectLinkedNativeLibrary(t)
	lifecycle, keys := validServiceProviders()
	observer := &serviceObserver{fn: func([]byte) { panic("OBSERVER_SECRET_SENTINEL") }}
	service, err := NewService(lifecycle, keys, observer, "")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	request, _ := NewV1IssueRequest([]byte("binding"))
	if _, err := service.Issue(request); err != nil {
		t.Fatalf("observer panic affected Issue: %v", err)
	}
}

func TestServiceCloseIsIdempotentAndRejectsUseAfterClose(t *testing.T) {
	requireDirectLinkedNativeLibrary(t)
	lifecycle, keys := validServiceProviders()
	service, err := NewService(lifecycle, keys, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	request, _ := NewV1IssueRequest([]byte("binding"))
	if _, err := service.Issue(request); stableErrorCode(err) != "invalid_argument" {
		t.Fatalf("Issue after close = %v", err)
	}
	if _, err := service.Verify(Submission{}, []byte("binding")); stableErrorCode(err) != "invalid_argument" {
		t.Fatalf("Verify after close = %v", err)
	}
}

func TestFinalizerPathIsBestEffortAndIdempotent(t *testing.T) {
	requireDirectLinkedNativeLibrary(t)
	lifecycle, keys := validServiceProviders()
	service, err := NewService(lifecycle, keys, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	finalizeService(service)
	finalizeService(service)
	request, _ := NewV1IssueRequest([]byte("binding"))
	if _, err := service.Issue(request); stableErrorCode(err) != "invalid_argument" {
		t.Fatalf("Issue after finalizer path = %v", err)
	}
}

func TestSameServiceCallbackReentryFailsWithoutDeadlock(t *testing.T) {
	requireDirectLinkedNativeLibrary(t)
	lifecycle, keys := validServiceProviders()
	var service *Service
	results := make(chan string, 3)
	lifecycle.storeFn = func([]byte, []byte, AttemptLimit) LifecycleStatus {
		request, _ := NewV1IssueRequest([]byte("nested"))
		_, issueErr := service.Issue(request)
		results <- stableErrorCode(issueErr)
		_, verifyErr := service.Verify(Submission{}, []byte("nested"))
		results <- stableErrorCode(verifyErr)
		results <- stableErrorCode(service.Close())
		return LifecycleStatusOK
	}
	var err error
	service, err = NewService(lifecycle, keys, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	request, _ := NewV1IssueRequest([]byte("binding"))
	done := make(chan error, 1)
	go func() { _, issueErr := service.Issue(request); done <- issueErr }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Issue deadlocked on callback reentry")
	}
	for range 3 {
		if got := <-results; got != "invalid_argument" {
			t.Fatalf("reentry error = %q", got)
		}
	}
}

func TestExternalCloseWaitsForInFlightCall(t *testing.T) {
	requireDirectLinkedNativeLibrary(t)
	lifecycle, keys := validServiceProviders()
	entered, release := make(chan struct{}), make(chan struct{})
	lifecycle.storeFn = func([]byte, []byte, AttemptLimit) LifecycleStatus {
		close(entered)
		<-release
		return LifecycleStatusOK
	}
	service, err := NewService(lifecycle, keys, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewV1IssueRequest([]byte("binding"))
	issueDone := make(chan error, 1)
	go func() { _, e := service.Issue(request); issueDone <- e }()
	<-entered
	closeDone := make(chan error, 1)
	// Start Close while Issue owns the call lock but before allowing the callback to return.
	go func() { closeDone <- service.closeWaitingForInflight() }()
	select {
	case <-closeDone:
		t.Fatal("Close did not wait")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-issueDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
}

func TestCallbackAdaptersValidateBeginAndKeyResults(t *testing.T) {
	badJSON := []byte("\xff")
	for _, result := range []BeginAttemptResult{
		{Status: BeginStatusOK}, {Status: BeginStatusOK, Material: badJSON},
		{Status: BeginStatus(99), Material: []byte(`{}`)},
		{Status: BeginStatusNotFound, Material: []byte(`{"secret":true}`)},
	} {
		lifecycle := &serviceLifecycle{beginFn: func([]byte, []byte, int64) BeginAttemptResult { return result }}
		adapter := newCallbackAdapter(lifecycle, &serviceKeys{}, nil)
		status, material, token := adapter.beginAttempt(nil, nil, 0)
		if result.Status == BeginStatusNotFound {
			if status != int32(BeginStatusNotFound) || material != nil || token != nil {
				t.Fatalf("non-OK result transferred output: %d %q %q", status, material, token)
			}
		} else if status != int32(BeginStatusInternal) {
			t.Fatalf("invalid begin result returned %d", status)
		}
	}

	keyIDBytes := []byte("exact-é")
	seen := ""
	adapter := newCallbackAdapter(&serviceLifecycle{}, &serviceKeys{byIDFn: func(id string) KeyResult {
		seen = id
		return KeyResult{Status: KeyStatusOK, Key: bytes.Repeat([]byte{2}, 32)}
	}}, nil)
	status, key := adapter.keyByID(keyIDBytes)
	if status != int32(KeyStatusOK) || seen != string(keyIDBytes) || !bytes.Equal(key, bytes.Repeat([]byte{2}, 32)) {
		t.Fatalf("exact key lookup failed: %d %q", status, seen)
	}
	key[0] = 9
	if reflect.DeepEqual(key, bytes.Repeat([]byte{2}, 32)) {
		t.Fatal("test setup did not mutate returned copy")
	}

	sourceMaterial := []byte(`{"challenge_id":"copy"}`)
	sourceToken := []byte("token")
	copying := newCallbackAdapter(&serviceLifecycle{beginFn: func([]byte, []byte, int64) BeginAttemptResult {
		return BeginAttemptResult{Status: BeginStatusOK, Material: sourceMaterial, Token: sourceToken}
	}}, &serviceKeys{}, nil)
	_, materialCopy, tokenCopy := copying.beginAttempt(nil, nil, 0)
	sourceMaterial[0], sourceToken[0] = 'X', 'X'
	if string(materialCopy) != `{"challenge_id":"copy"}` || string(tokenCopy) != "token" {
		t.Fatalf("callback outputs were not copied: %q %q", materialCopy, tokenCopy)
	}
}

func TestConcurrentServiceCallsAreSerialized(t *testing.T) {
	requireDirectLinkedNativeLibrary(t)
	lifecycle, keys := validServiceProviders()
	var active, maximum int
	var lock sync.Mutex
	lifecycle.storeFn = func([]byte, []byte, AttemptLimit) LifecycleStatus {
		lock.Lock()
		active++
		if active > maximum {
			maximum = active
		}
		lock.Unlock()
		time.Sleep(time.Millisecond)
		lock.Lock()
		active--
		lock.Unlock()
		return LifecycleStatusOK
	}
	service, err := NewService(lifecycle, keys, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	request, _ := NewV1IssueRequest([]byte("binding"))
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := service.Issue(request); err != nil && stableErrorCode(err) != "invalid_argument" {
				t.Errorf("Issue: %v", err)
			}
		}()
	}
	wait.Wait()
	if maximum != 1 {
		t.Fatalf("maximum concurrent callbacks = %d", maximum)
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	result, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
