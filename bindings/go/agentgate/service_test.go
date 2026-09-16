package agentgate

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"runtime"
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

const serviceCallDeadline = 3 * time.Second

func awaitServiceSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(serviceCallDeadline):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func awaitServiceRelease(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(serviceCallDeadline):
		t.Errorf("timed out waiting for %s", name)
	}
}

func awaitServiceCall(t *testing.T, done <-chan error, name string) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	case <-time.After(serviceCallDeadline):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func gateNextServiceCall(t *testing.T, service *Service) (<-chan struct{}, func()) {
	t.Helper()
	started := make(chan struct{})
	proceed := make(chan struct{})
	proceedingToLock := make(chan struct{})
	service.beforeCallMuLockForTest = func() {
		close(started)
		awaitServiceRelease(t, proceed, "test call gate release")
		close(proceedingToLock)
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			close(proceed)
			awaitServiceSignal(t, proceedingToLock, "call proceeding to service lock")
			service.beforeCallMuLockForTest = nil
		})
	}
	t.Cleanup(release)
	return started, release
}

func assertServiceCallWaitsForCallback(
	t *testing.T,
	service *Service,
	callbackEntered <-chan struct{},
	releaseCallback func(),
	inFlightCall func() error,
	waitingCall func() error,
) {
	t.Helper()
	inFlightDone := make(chan error, 1)
	go func() { inFlightDone <- inFlightCall() }()
	awaitServiceSignal(t, callbackEntered, "callback entry")

	callStarted, releaseCall := gateNextServiceCall(t, service)
	waitingDone := make(chan error, 1)
	go func() { waitingDone <- waitingCall() }()
	awaitServiceSignal(t, callStarted, "waiting call start")
	releaseCall()
	runtime.Gosched()
	select {
	case err := <-waitingDone:
		releaseCallback()
		awaitServiceCall(t, inFlightDone, "in-flight call")
		t.Fatalf("waiting call returned during callback: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	releaseCallback()
	awaitServiceCall(t, inFlightDone, "in-flight call")
	awaitServiceCall(t, waitingDone, "waiting call")
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

func TestPublicCloseDuringCallbackWaitsThenClosesIdempotently(t *testing.T) {
	requireDirectLinkedNativeLibrary(t)
	lifecycle, keys := validServiceProviders()
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseCallback := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseCallback)
	lifecycle.storeFn = func([]byte, []byte, AttemptLimit) LifecycleStatus {
		close(entered)
		awaitServiceRelease(t, release, "callback release")
		return LifecycleStatusOK
	}
	service, err := NewService(lifecycle, keys, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewV1IssueRequest([]byte("binding"))
	assertServiceCallWaitsForCallback(t, service, entered, releaseCallback,
		func() error { _, err := service.Issue(request); return err },
		service.Close,
	)
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestIssueDuringCallbackWaitsThenSucceeds(t *testing.T) {
	requireDirectLinkedNativeLibrary(t)
	lifecycle, keys := validServiceProviders()
	entered, release := make(chan struct{}), make(chan struct{})
	var blockOnce, releaseOnce sync.Once
	releaseCallback := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseCallback)
	lifecycle.storeFn = func([]byte, []byte, AttemptLimit) LifecycleStatus {
		blockOnce.Do(func() {
			close(entered)
			awaitServiceRelease(t, release, "callback release")
		})
		return LifecycleStatusOK
	}
	service, err := NewService(lifecycle, keys, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		releaseCallback()
		service.beforeCallMuLockForTest = nil
		_ = service.Close()
	})
	request, _ := NewV1IssueRequest([]byte("binding"))
	issue := func() error { _, err := service.Issue(request); return err }
	assertServiceCallWaitsForCallback(t, service, entered, releaseCallback, issue, issue)
}

func TestVerifyDuringCallbackWaitsThenSucceeds(t *testing.T) {
	requireDirectLinkedNativeLibrary(t)
	fixture := loadGoFixture(t)
	material, err := json.Marshal(fixture.Vectors.PrivateMaterial)
	if err != nil {
		t.Fatal(err)
	}
	token := mustHex(t, fixture.Vectors.TokenHex)
	oldKey := mustHex(t, fixture.Vectors.OldKeyHex)
	entered, release := make(chan struct{}), make(chan struct{})
	var blockOnce, releaseOnce sync.Once
	releaseCallback := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseCallback)
	lifecycle := &serviceLifecycle{beginFn: func([]byte, []byte, int64) BeginAttemptResult {
		blockOnce.Do(func() {
			close(entered)
			awaitServiceRelease(t, release, "callback release")
		})
		return BeginAttemptResult{Status: BeginStatusOK, Material: material, Token: token}
	}}
	keys := &serviceKeys{byIDFn: func(string) KeyResult {
		return KeyResult{Status: KeyStatusOK, Key: oldKey}
	}}
	service, err := NewService(lifecycle, keys, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		releaseCallback()
		service.beforeCallMuLockForTest = nil
		_ = service.Close()
	})
	caseFixture := fixture.Cases[0]
	binding := mustHex(t, caseFixture.BindingHex)
	verify := func() error { _, err := service.Verify(*caseFixture.Submission, binding); return err }
	assertServiceCallWaitsForCallback(t, service, entered, releaseCallback, verify, verify)
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

	sourceMaterial := []byte(`{"challenge_id":"copy","generator_version":"1.0","nonce":"nonce","issued_at":1,"expires_at":2,"mac_key_id":"old","answer_mac":"0000000000000000000000000000000000000000000000000000000000000000","answer_encoding":"base64url"}`)
	sourceToken := []byte("token")
	wantMaterial, wantToken := bytes.Clone(sourceMaterial), bytes.Clone(sourceToken)
	copying := newCallbackAdapter(&serviceLifecycle{beginFn: func([]byte, []byte, int64) BeginAttemptResult {
		return BeginAttemptResult{Status: BeginStatusOK, Material: sourceMaterial, Token: sourceToken}
	}}, &serviceKeys{}, nil)
	_, materialCopy, tokenCopy := copying.beginAttempt(nil, nil, 0)
	sourceMaterial[0], sourceToken[0] = 'X', 'X'
	if !bytes.Equal(materialCopy, wantMaterial) || !bytes.Equal(tokenCopy, wantToken) {
		t.Fatalf("callback outputs were not copied: %q %q", materialCopy, tokenCopy)
	}
}

func TestBeginAttemptRejectsStructurallyInvalidPrivateMaterial(t *testing.T) {
	valid := `{"challenge_id":"id","generator_version":"1.0","nonce":"nonce","issued_at":1,"expires_at":2,"mac_key_id":"old","answer_mac":"0000000000000000000000000000000000000000000000000000000000000000","answer_encoding":"base64url"}`
	cases := map[string][]byte{
		"non-object":             []byte(`[]`),
		"duplicate":              []byte(`{"challenge_id":"id","challenge_id":"again","generator_version":"1.0","nonce":"nonce","issued_at":1,"expires_at":2,"mac_key_id":"old","answer_mac":"0000000000000000000000000000000000000000000000000000000000000000","answer_encoding":"base64url"}`),
		"unknown":                []byte(valid[:len(valid)-1] + `,"extra":true}`),
		"missing":                []byte(`{"challenge_id":"id"}`),
		"challenge id type":      []byte(strings.Replace(valid, `"id"`, `1`, 1)),
		"generator version type": []byte(strings.Replace(valid, `"1.0"`, `false`, 1)),
		"nonce type":             []byte(strings.Replace(valid, `"nonce"`, `[]`, 1)),
		"issued at type":         []byte(strings.Replace(valid, `"issued_at":1`, `"issued_at":"1"`, 1)),
		"expires at type":        []byte(strings.Replace(valid, `"expires_at":2`, `"expires_at":2.5`, 1)),
		"key id type":            []byte(strings.Replace(valid, `"old"`, `null`, 1)),
		"answer mac type":        []byte(strings.Replace(valid, `"0000000000000000000000000000000000000000000000000000000000000000"`, `{}`, 1)),
		"answer encoding type":   []byte(strings.Replace(valid, `"base64url"`, `7`, 1)),
		"invalid enum":           []byte(strings.Replace(valid, `"base64url"`, `"hex"`, 1)),
		"invalid utf8":           bytes.Replace([]byte(valid), []byte(`"id"`), []byte{'"', 0xff, '"'}, 1),
		"lone surrogate":         []byte(strings.Replace(valid, `"id"`, `"\ud800"`, 1)),
		"trailing document":      []byte(valid + `{}`),
	}
	for name, material := range cases {
		t.Run(name, func(t *testing.T) {
			adapter := newCallbackAdapter(&serviceLifecycle{beginFn: func([]byte, []byte, int64) BeginAttemptResult {
				return BeginAttemptResult{Status: BeginStatusOK, Material: material, Token: []byte("token")}
			}}, &serviceKeys{}, nil)
			status, returnedMaterial, token := adapter.beginAttempt(nil, nil, 0)
			if status != int32(BeginStatusInternal) || returnedMaterial != nil || token != nil {
				t.Fatalf("invalid material accepted: status=%d material=%q token=%q", status, returnedMaterial, token)
			}
		})
	}
}

func TestNativeCopiesAreClearedWithoutMutatingProviderOwnedSlices(t *testing.T) {
	requireDirectLinkedNativeLibrary(t)
	fixture := loadGoFixture(t)
	providerMaterial, _ := json.Marshal(fixture.Vectors.PrivateMaterial)
	providerToken := mustHex(t, fixture.Vectors.TokenHex)
	providerKey := mustHex(t, fixture.Vectors.OldKeyHex)
	providerActiveKey := mustHex(t, fixture.Vectors.ActiveKeyHex)
	originalMaterial, originalToken := bytes.Clone(providerMaterial), bytes.Clone(providerToken)
	originalKey, originalActiveKey := bytes.Clone(providerKey), bytes.Clone(providerActiveKey)
	lifecycle := &serviceLifecycle{
		beginFn: func([]byte, []byte, int64) BeginAttemptResult {
			return BeginAttemptResult{Status: BeginStatusOK, Material: providerMaterial, Token: providerToken}
		},
	}
	keys := &serviceKeys{
		activeFn: func() ActiveKeyResult {
			return ActiveKeyResult{Status: KeyStatusOK, KeyID: fixture.Vectors.ActiveKeyID, Key: providerActiveKey}
		},
		byIDFn: func(string) KeyResult {
			return KeyResult{Status: KeyStatusOK, Key: providerKey}
		},
	}
	service, err := NewService(lifecycle, keys, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	var cleared []hostReleaseTag
	service.callbacks.transientClearedHook = func(tag hostReleaseTag, value []byte) {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Errorf("%s transient was not cleared", tag)
		}
		cleared = append(cleared, tag)
	}
	request, err := NewV1IssueRequest([]byte("transient-clear-binding"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Issue(request); err != nil {
		t.Fatal(err)
	}
	caseFixture := fixture.Cases[0]
	binding := mustHex(t, caseFixture.BindingHex)
	if _, err := service.Verify(*caseFixture.Submission, binding); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(providerMaterial, originalMaterial) || !bytes.Equal(providerToken, originalToken) ||
		!bytes.Equal(providerKey, originalKey) || !bytes.Equal(providerActiveKey, originalActiveKey) {
		t.Fatal("provider-owned callback result was mutated")
	}
	if !reflect.DeepEqual(cleared, []hostReleaseTag{
		hostReleaseActiveKeyID, hostReleaseActiveKey,
		hostReleaseMaterial, hostReleaseToken, hostReleaseKey,
	}) {
		t.Fatalf("cleared tags = %v", cleared)
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
	request, _ := NewV1IssueRequest([]byte("binding"))
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := service.Issue(request); err != nil {
				t.Errorf("Issue: %v", err)
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		wait.Wait()
		close(done)
	}()
	awaitServiceSignal(t, done, "concurrent service calls")
	closeDone := make(chan error, 1)
	go func() { closeDone <- service.Close() }()
	awaitServiceCall(t, closeDone, "service close")
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
