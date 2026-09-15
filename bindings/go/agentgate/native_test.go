package agentgate

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

var testAgentGateLibrary = flag.String(
	"agentgate-library", "", "absolute path to the AgentGate shared library",
)

func TestMain(m *testing.M) {
	flag.Parse()
	if err := initializeNativeLibrary(*testAgentGateLibrary); err != nil {
		fmt.Fprintf(os.Stderr, "agentgate native library initialization failed: %s\n", stableErrorCode(err))
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestAgentGateLibraryFlagIsRegistered(t *testing.T) {
	if flag.Lookup("agentgate-library") == nil {
		t.Fatal("--agentgate-library is not registered for the Go test binary")
	}
}

func TestNativeABIConstantsAndLayoutsMatchFrozenHeader(t *testing.T) {
	contract := nativeABIContract()

	wantStatuses := []int32{0, 1, 2, 3, 4, 5, 6, 7, 100, 101, 102}
	if !slices.Equal(contract.statuses, wantStatuses) {
		t.Fatalf("top-level statuses = %v, want %v", contract.statuses, wantStatuses)
	}
	wantLifecycle := []int32{0, 1, 2, 3}
	if !slices.Equal(contract.lifecycleStatuses, wantLifecycle) {
		t.Fatalf("lifecycle statuses = %v, want %v", contract.lifecycleStatuses, wantLifecycle)
	}
	wantBegin := []int32{0, 1, 2, 3, 10, 11, 12, 13, 14, 15}
	if !slices.Equal(contract.beginStatuses, wantBegin) {
		t.Fatalf("begin statuses = %v, want %v", contract.beginStatuses, wantBegin)
	}
	wantKeys := []int32{0, 1, 2, 3}
	if !slices.Equal(contract.keyStatuses, wantKeys) {
		t.Fatalf("key statuses = %v, want %v", contract.keyStatuses, wantKeys)
	}
	wantOutcomes := []int32{1, 2, 3}
	if !slices.Equal(contract.attemptOutcomes, wantOutcomes) {
		t.Fatalf("attempt outcomes = %v, want %v", contract.attemptOutcomes, wantOutcomes)
	}
	wantLimits := []uint32{1, 2}
	if !slices.Equal(contract.attemptLimits, wantLimits) {
		t.Fatalf("attempt limits = %v, want %v", contract.attemptLimits, wantLimits)
	}

	if ^uintptr(0) != uintptr(0xffffffffffffffff) {
		t.Skip("the frozen layout assertions apply to 64-bit targets")
	}
	wantLayouts := map[string]nativeStructLayout{
		"byte_slice":          {size: 16, offsets: []uintptr{0, 8}},
		"owned_buffer":        {size: 24, offsets: []uintptr{0, 8, 16}},
		"host_buffer":         {size: 32, offsets: []uintptr{0, 8, 16, 24}},
		"callback_header":     {size: 8, offsets: []uintptr{0, 4}},
		"lifecycle_callbacks": {size: 40, offsets: []uintptr{0, 4, 8, 16, 24, 32}},
		"key_callbacks":       {size: 32, offsets: []uintptr{0, 4, 8, 16, 24}},
		"observer_callbacks":  {size: 24, offsets: []uintptr{0, 4, 8, 16}},
	}
	for name, want := range wantLayouts {
		got, ok := contract.layouts[name]
		if !ok || got.size != want.size || !slices.Equal(got.offsets, want.offsets) {
			t.Errorf("%s layout = %#v, want %#v", name, got, want)
		}
	}
}

func TestNativeLibraryABIVersionCoreVersionAndCanonicalFree(t *testing.T) {
	requireDirectLinkedNativeLibrary(t)
	if got := nativeABIVersion(); got != 1 {
		t.Fatalf("ABI version = %d, want 1", got)
	}
	version := nativeCoreVersion()
	if len(version) == 0 || !strings.Contains(string(version), ".") {
		t.Fatalf("unexpected core version %q", version)
	}
	version[0] ^= 0xff
	if again := nativeCoreVersion(); len(again) == 0 || again[0] == version[0] {
		t.Fatal("core version did not return a copy of borrowed static storage")
	}
	status, canonical := nativeFreeCanonicalBuffer()
	if status != 0 || !canonical {
		t.Fatalf("canonical free = status %d canonical %v", status, canonical)
	}
}

func TestNativeHostBufferAllocationPairsExactlyOnce(t *testing.T) {
	nativeResetHostAllocationCounters()
	for _, test := range []struct {
		name    string
		value   []byte
		present bool
	}{
		{name: "bytes", value: []byte("copied native output"), present: true},
		{name: "present empty", value: []byte{}, present: true},
		{name: "absent", value: nil, present: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, nonnull := nativeTestHostBufferRoundTrip(test.value, test.present)
			if !slices.Equal(got, test.value) || nonnull != test.present {
				t.Fatalf("round trip = %q, nonnull=%v", got, nonnull)
			}
		})
	}
	allocations, releases := nativeHostAllocationCounters()
	if allocations != 2 || releases != 2 {
		t.Fatalf("allocation counters = (%d, %d), want (2, 2)", allocations, releases)
	}
}

func TestNativeHostReleaseTagsAreClosedAndStable(t *testing.T) {
	want := []hostReleaseTag{
		hostReleaseMaterial,
		hostReleaseToken,
		hostReleaseActiveKeyID,
		hostReleaseActiveKey,
		hostReleaseKey,
	}
	for index, tag := range want {
		if tag != hostReleaseTag(index+1) || !tag.valid() {
			t.Fatalf("release tag %d = %d valid=%v", index, tag, tag.valid())
		}
	}
	for _, tag := range []hostReleaseTag{0, 6, 255} {
		if tag.valid() {
			t.Fatalf("unexpected valid release tag %d", tag)
		}
	}
}

func TestNativeHostReleaseNotificationFailsSafeForInvalidHandlesAndTags(t *testing.T) {
	nativeTestHostReleaseNotification(0, hostReleaseMaterial)
	nativeTestDeletedHandleReleaseNotification(&nativeTestCallbacks{}, hostReleaseToken)

	var released []hostReleaseTag
	callbacks := &nativeTestCallbacks{releasedFn: func(tag hostReleaseTag) {
		released = append(released, tag)
	}}
	nativeTestHostReleaseNotificationForCallbacks(callbacks, hostReleaseTag(99))
	if len(released) != 0 {
		t.Fatalf("invalid release tag reached callbacks: %v", released)
	}
}

func TestNativeHostBufferCountersAreAtomicAcrossConcurrentCallbacks(t *testing.T) {
	nativeResetHostAllocationCounters()
	const workers = 32
	const iterations = 2000
	var wait sync.WaitGroup
	wait.Add(workers)
	failed := make(chan struct{}, 1)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				value, nonnull := nativeTestHostBufferRoundTrip([]byte("atomic"), true)
				if !nonnull || string(value) != "atomic" {
					select {
					case failed <- struct{}{}:
					default:
					}
					return
				}
			}
		}()
	}
	wait.Wait()
	select {
	case <-failed:
		t.Fatal("concurrent host-buffer round trip was corrupted")
	default:
	}
	allocations, releases := nativeHostAllocationCounters()
	want := uint64(workers * iterations)
	if allocations != want || releases != want {
		t.Fatalf("concurrent counters = (%d, %d), want (%d, %d)",
			allocations, releases, want, want)
	}
}

func TestNativeNonOKCallbackDoesNotTransferHostOwnership(t *testing.T) {
	nativeResetHostAllocationCounters()
	nativeTestCallbackOutput(3, []byte("must remain Go-owned"))
	allocations, releases := nativeHostAllocationCounters()
	if allocations != 0 || releases != 0 {
		t.Fatalf("non-OK callback transferred ownership: (%d, %d)", allocations, releases)
	}
}

func TestNativeOversizedHostBufferAssignmentFailsWithoutOwnershipTransfer(t *testing.T) {
	nativeResetHostAllocationCounters()
	if !nativeTestHostBufferOversizedAssignFails() {
		t.Fatal("oversized host buffer assignment succeeded")
	}
	allocations, releases := nativeHostAllocationCounters()
	if allocations != 0 || releases != 0 {
		t.Fatalf("failed assignment transferred ownership: (%d, %d)", allocations, releases)
	}
}

func TestNativeCallbacksCopyBorrowedInputsAndPairTransferredOutputs(t *testing.T) {
	requireDirectLinkedNativeLibrary(t)
	var retainedBinding []byte
	callbacks := &nativeTestCallbacks{
		activeKeyFn: func() (int32, []byte, []byte) {
			return 0, []byte("test-key"), bytesOf('k', 32)
		},
		storeIssuedFn: func(_ []byte, binding []byte, _ AttemptLimit) int32 {
			retainedBinding = binding
			return 0
		},
	}
	nativeResetHostAllocationCounters()
	service, err := nativeServiceCreate(callbacks, false)
	if err != nil {
		t.Fatalf("nativeServiceCreate: %v", err)
	}
	binding := []byte("borrowed-binding")
	output, issueErr := nativeServiceIssue(service, []byte("1.0"), binding, AttemptLimitOne)
	binding[0] = 'X'
	if issueErr != nil || len(output) == 0 {
		t.Fatalf("nativeServiceIssue: output=%q err=%v", output, issueErr)
	}
	if string(retainedBinding) != "borrowed-binding" {
		t.Fatalf("callback retained borrowed native storage: %q", retainedBinding)
	}
	if err := nativeServiceDestroy(service); err != nil {
		t.Fatalf("nativeServiceDestroy: %v", err)
	}
	allocations, releases := nativeHostAllocationCounters()
	if allocations != 2 || releases != 2 {
		t.Fatalf("native callback ownership = (%d, %d), want (2, 2)", allocations, releases)
	}
}

func TestNativeRealVerifyTraversesCallbacksAndReleasesExactlyOnce(t *testing.T) {
	fixture := loadNativeBindingFixture(t)
	var trace []string
	var callbackIssue string
	callbacks := &nativeTestCallbacks{
		beginAttemptFn: func(_ []byte, binding []byte, _ int64) (int32, []byte, []byte) {
			trace = append(trace, "begin_attempt")
			if !slices.Equal(binding, fixture.binding) {
				callbackIssue = fmt.Sprintf("begin binding = %x, want %x", binding, fixture.binding)
				return 3, nil, nil
			}
			return 0, fixture.privateMaterial, fixture.token
		},
		keyByIDFn: func(keyID []byte) (int32, []byte) {
			trace = append(trace, "key_by_id")
			if string(keyID) != fixture.oldKeyID {
				callbackIssue = fmt.Sprintf("key id = %q, want %q", keyID, fixture.oldKeyID)
				return 2, nil
			}
			return 0, fixture.oldKey
		},
		finishAttemptFn: func(token []byte, outcome int32) int32 {
			trace = append(trace, "finish_attempt")
			if !slices.Equal(token, fixture.token) || outcome != 1 {
				callbackIssue = fmt.Sprintf("finish = token %x outcome %d", token, outcome)
				return 3
			}
			return 0
		},
		releasedFn: func(tag hostReleaseTag) {
			trace = append(trace, "release:"+tag.String())
		},
	}
	service, err := nativeServiceCreate(callbacks, false)
	if err != nil {
		t.Fatalf("nativeServiceCreate: %v", err)
	}
	nativeResetHostAllocationCounters()
	output, verifyErr := nativeServiceVerify(service, fixture.submission, fixture.binding)
	if callbackIssue != "" {
		t.Fatal(callbackIssue)
	}
	if verifyErr != nil {
		t.Fatalf("nativeServiceVerify: %v", verifyErr)
	}
	if string(output) != `{"status":"accepted"}` {
		t.Fatalf("accepted output = %s", output)
	}
	outcome, err := decodeVerificationOutcome(output)
	if err != nil || outcome.Status != VerificationStatusAccepted {
		t.Fatalf("outcome = %s, %v", output, err)
	}
	if !slices.Equal(trace, []string{
		"begin_attempt", "release:token", "release:material", "key_by_id",
		"release:key", "finish_attempt",
	}) {
		t.Fatalf("callback trace = %v", trace)
	}
	allocations, releases := nativeHostAllocationCounters()
	if allocations != 3 || releases != 3 {
		t.Fatalf("verify callback ownership = (%d, %d), want (3, 3)", allocations, releases)
	}
	if err := nativeServiceDestroy(service); err != nil {
		t.Fatalf("nativeServiceDestroy: %v", err)
	}
}

func TestNativeRealVerifyLifecycleRejectionSkipsKeyAndFinish(t *testing.T) {
	fixture := loadNativeBindingFixture(t)
	var trace []string
	callbacks := &nativeTestCallbacks{
		beginAttemptFn: func([]byte, []byte, int64) (int32, []byte, []byte) {
			trace = append(trace, "begin_attempt")
			return 12, fixture.privateMaterial, fixture.token
		},
		keyByIDFn: func([]byte) (int32, []byte) {
			trace = append(trace, "unexpected_key_by_id")
			return 0, fixture.oldKey
		},
		finishAttemptFn: func([]byte, int32) int32 {
			trace = append(trace, "unexpected_finish_attempt")
			return 0
		},
	}
	service, err := nativeServiceCreate(callbacks, false)
	if err != nil {
		t.Fatalf("nativeServiceCreate: %v", err)
	}
	nativeResetHostAllocationCounters()
	output, verifyErr := nativeServiceVerify(service, fixture.submission, fixture.binding)
	if verifyErr != nil {
		t.Fatalf("nativeServiceVerify: %v", verifyErr)
	}
	if string(output) != `{"status":"rejected","reason":"already_consumed"}` {
		t.Fatalf("rejected output = %s", output)
	}
	outcome, err := decodeVerificationOutcome(output)
	if err != nil || outcome.Status != VerificationStatusRejected ||
		outcome.Reason != RejectionReasonAlreadyConsumed {
		t.Fatalf("outcome = %s, %v", output, err)
	}
	if !slices.Equal(trace, []string{"begin_attempt"}) {
		t.Fatalf("callback trace = %v", trace)
	}
	allocations, releases := nativeHostAllocationCounters()
	if allocations != 0 || releases != 0 {
		t.Fatalf("rejected callback ownership = (%d, %d), want (0, 0)", allocations, releases)
	}
	if err := nativeServiceDestroy(service); err != nil {
		t.Fatalf("nativeServiceDestroy: %v", err)
	}
}

func TestNativeCallbackPanicsFailClosedAndObserverPanicIsSwallowed(t *testing.T) {
	requireDirectLinkedNativeLibrary(t)
	t.Run("key callback", func(t *testing.T) {
		callbacks := &nativeTestCallbacks{activeKeyFn: func() (int32, []byte, []byte) {
			panic("secret panic")
		}}
		service, err := nativeServiceCreate(callbacks, false)
		if err != nil {
			t.Fatalf("nativeServiceCreate: %v", err)
		}
		_, issueErr := nativeServiceIssue(service, []byte("1.0"), []byte("binding"), AttemptLimitOne)
		if got := stableErrorCode(issueErr); got != "internal_error" {
			t.Fatalf("panic error = %q, want internal_error", got)
		}
		if err := nativeServiceDestroy(service); err != nil {
			t.Fatalf("nativeServiceDestroy: %v", err)
		}
	})

	t.Run("lifecycle and observer callbacks", func(t *testing.T) {
		callbacks := &nativeTestCallbacks{
			activeKeyFn: func() (int32, []byte, []byte) {
				return 0, []byte("test-key"), bytesOf('k', 32)
			},
			storeIssuedFn: func([]byte, []byte, AttemptLimit) int32 {
				panic("secret panic")
			},
			observeFn: func([]byte) { panic("secret panic") },
		}
		service, err := nativeServiceCreate(callbacks, true)
		if err != nil {
			t.Fatalf("nativeServiceCreate: %v", err)
		}
		_, issueErr := nativeServiceIssue(service, []byte("1.0"), []byte("binding"), AttemptLimitOne)
		if got := stableErrorCode(issueErr); got != "internal_error" {
			t.Fatalf("panic error = %q, want internal_error", got)
		}
		if err := nativeServiceDestroy(service); err != nil {
			t.Fatalf("nativeServiceDestroy: %v", err)
		}
	})

	t.Run("observer callback", func(t *testing.T) {
		observed := false
		callbacks := &nativeTestCallbacks{
			activeKeyFn: func() (int32, []byte, []byte) {
				return 0, []byte("test-key"), bytesOf('k', 32)
			},
			observeFn: func([]byte) {
				observed = true
				panic("secret panic")
			},
		}
		service, err := nativeServiceCreate(callbacks, true)
		if err != nil {
			t.Fatalf("nativeServiceCreate: %v", err)
		}
		output, issueErr := nativeServiceIssue(service, []byte("1.0"), []byte("binding"), AttemptLimitOne)
		if issueErr != nil || len(output) == 0 {
			t.Fatalf("observer panic changed issue result: output=%q err=%v", output, issueErr)
		}
		if !observed {
			t.Fatal("native issue did not invoke the observer callback")
		}
		if err := nativeServiceDestroy(service); err != nil {
			t.Fatalf("nativeServiceDestroy: %v", err)
		}
	})
}

func requireDirectLinkedNativeLibrary(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows loader behavior is covered by its platform contract tests")
	}
}

func TestEveryExportedGoCallbackContainsPanics(t *testing.T) {
	source := readNativeSource(t, "native.go")
	if got := strings.Count(source, "_ = recover()"); got != 7 {
		t.Fatalf("panic recovery guards = %d, want one for each of seven Go callback exports", got)
	}
}

func TestNativeInvalidHandlePanicsFailClosedAtEveryCallbackBoundary(t *testing.T) {
	statuses := nativeTestInvalidHandleCallbackStatuses()
	if statuses.storeIssued != 3 || statuses.beginAttempt != 3 || statuses.finishAttempt != 3 {
		t.Fatalf("invalid lifecycle handle statuses = %#v, want all internal", statuses)
	}
	if statuses.activeKey != 1 || statuses.keyByID != 1 {
		t.Fatalf("invalid key handle statuses = %#v, want all unavailable", statuses)
	}
}

type nativeTestCallbacks struct {
	storeIssuedFn   func([]byte, []byte, AttemptLimit) int32
	beginAttemptFn  func([]byte, []byte, int64) (int32, []byte, []byte)
	finishAttemptFn func([]byte, int32) int32
	activeKeyFn     func() (int32, []byte, []byte)
	keyByIDFn       func([]byte) (int32, []byte)
	observeFn       func([]byte)
	releasedFn      func(hostReleaseTag)
}

func (callbacks *nativeTestCallbacks) hostReleased(tag hostReleaseTag) {
	if callbacks.releasedFn != nil {
		callbacks.releasedFn(tag)
	}
}

func (callbacks *nativeTestCallbacks) storeIssued(privateJSON, binding []byte, limit AttemptLimit) int32 {
	if callbacks.storeIssuedFn != nil {
		return callbacks.storeIssuedFn(privateJSON, binding, limit)
	}
	return 0
}

func (callbacks *nativeTestCallbacks) beginAttempt(identity, binding []byte, serverTime int64) (int32, []byte, []byte) {
	if callbacks.beginAttemptFn != nil {
		return callbacks.beginAttemptFn(identity, binding, serverTime)
	}
	return 3, nil, nil
}

func (callbacks *nativeTestCallbacks) finishAttempt(token []byte, outcome int32) int32 {
	if callbacks.finishAttemptFn != nil {
		return callbacks.finishAttemptFn(token, outcome)
	}
	return 3
}

func (callbacks *nativeTestCallbacks) activeKey() (int32, []byte, []byte) {
	if callbacks.activeKeyFn != nil {
		return callbacks.activeKeyFn()
	}
	return 1, nil, nil
}

func (callbacks *nativeTestCallbacks) keyByID(keyID []byte) (int32, []byte) {
	if callbacks.keyByIDFn != nil {
		return callbacks.keyByIDFn(keyID)
	}
	return 1, nil
}

func (callbacks *nativeTestCallbacks) observe(event []byte) {
	if callbacks.observeFn != nil {
		callbacks.observeFn(event)
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func stableErrorCode(err error) string {
	if typed, ok := err.(*AgentGateError); ok {
		return typed.Code()
	}
	return ""
}

func TestWindowsLoaderSourceContract(t *testing.T) {
	bridge := readNativeSource(t, "native_bridge.c")
	native := readNativeSource(t, "native.go")
	windows := readNativeSource(t, "native_windows.go")
	goSource := native + windows

	for _, required := range []string{
		"LoadLibraryExW", "LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR", "LOAD_LIBRARY_SEARCH_DEFAULT_DIRS",
		"INIT_ONCE", "InitOnceExecuteOnce", "ag_go_loader_vtable", "ag_go_resolve_exports",
		"exports_out->symbols[i] == 0", "loader->abi_version", "loader->unload_library(loader->context, module)",
		"static HMODULE ag_go_module", "InterlockedIncrement64", "atomic_fetch_add_explicit",
	} {
		if !strings.Contains(bridge, required) {
			t.Errorf("native_bridge.c lacks %q", required)
		}
	}
	if strings.Contains(bridge, "LoadLibraryA") || strings.Contains(bridge, "FormatMessage") {
		t.Fatal("Windows bridge uses an ANSI loader or exposes raw OS loader messages")
	}
	if strings.Contains(goSource, "log.") || strings.Contains(goSource, "fmt.") {
		t.Fatal("Windows loader must not log loader paths or raw errors")
	}

	symbols := []string{
		"ag_abi_version", "ag_core_version", "ag_service_create", "ag_service_destroy",
		"ag_service_issue", "ag_service_verify", "ag_buffer_free",
	}
	for _, symbol := range symbols {
		if got := strings.Count(bridge, `"`+symbol+`"`); got != 1 {
			t.Errorf("loader source contains %q %d times, want exactly once", symbol, got)
		}
	}
	for _, required := range []string{"AGENTGATE_LIBRARY_PATH", "filepath.IsAbs", "utf16.Encode", "agentgate_ffi.dll"} {
		if !strings.Contains(goSource, required) {
			t.Errorf("Go Windows loader sources lack %q", required)
		}
	}
}

func TestNativeInjectedResolverStateMachine(t *testing.T) {
	assertResult := func(t *testing.T, got nativeResolverTestResult, status int32,
		loads, lookups, abiCalls, unloads uint32, retained bool) {
		t.Helper()
		if got.status != status || got.loads != loads || got.lookups != lookups ||
			got.abiCalls != abiCalls || got.unloads != unloads || got.retained != retained {
			t.Fatalf("resolver result = %#v", got)
		}
	}

	t.Run("missing library", func(t *testing.T) {
		assertResult(t, nativeTestResolveExports(true, -1, 1), 7, 1, 0, 0, 0, false)
	})
	for missing := 0; missing < 7; missing++ {
		t.Run(fmt.Sprintf("missing symbol %d", missing), func(t *testing.T) {
			assertResult(t, nativeTestResolveExports(false, missing, 1), 7,
				1, uint32(missing+1), 0, 1, false)
		})
	}
	t.Run("ABI mismatch", func(t *testing.T) {
		assertResult(t, nativeTestResolveExports(false, -1, 2), 7, 1, 7, 1, 1, false)
	})
	t.Run("success retains module", func(t *testing.T) {
		assertResult(t, nativeTestResolveExports(false, -1, 1), 0, 1, 7, 1, 0, true)
	})
}

func TestWindowsLibraryRequestValidationAndFlags(t *testing.T) {
	absolute := filepath.Join(t.TempDir(), "Unicode 库 with spaces", "agentgate_ffi.dll")
	path, includeDirectory, err := resolveWindowsNativeLibraryRequest(absolute, "ignored")
	if err != nil || path != absolute || !includeDirectory {
		t.Fatalf("explicit request = (%q, %v, %v)", path, includeDirectory, err)
	}
	path, includeDirectory, err = resolveWindowsNativeLibraryRequest("", absolute)
	if err != nil || path != absolute || !includeDirectory {
		t.Fatalf("environment request = (%q, %v, %v)", path, includeDirectory, err)
	}
	path, includeDirectory, err = resolveWindowsNativeLibraryRequest("", "")
	if err != nil || path != "agentgate_ffi.dll" || includeDirectory {
		t.Fatalf("default request = (%q, %v, %v)", path, includeDirectory, err)
	}
	for _, invalid := range []string{"relative.dll", absolute + "\x00suffix"} {
		if _, _, err := resolveWindowsNativeLibraryRequest(invalid, ""); stableErrorCode(err) != "invalid_argument" {
			t.Fatalf("invalid path %q error = %v", invalid, err)
		}
	}
}

func TestNativeLibraryInitializationFailureIsSticky(t *testing.T) {
	absolute := filepath.Join(t.TempDir(), "agentgate_ffi.dll")
	for _, invalid := range []string{"relative.dll", absolute + "\x00suffix"} {
		t.Run(fmt.Sprintf("first path %q", invalid), func(t *testing.T) {
			var calls atomic.Int32
			initializer := nativeLibraryInitializer{load: func(path string) error {
				calls.Add(1)
				_, _, err := resolveWindowsNativeLibraryRequest(path, "")
				return err
			}}
			first := initializer.initialize(invalid)
			second := initializer.initialize(absolute)
			if stableErrorCode(first) != "invalid_argument" || first != second {
				t.Fatalf("sticky failure = (%v, %v)", first, second)
			}
			if calls.Load() != 1 {
				t.Fatalf("load calls = %d, want 1", calls.Load())
			}
		})
	}
}

func TestNativeLibraryInitializationSuccessIsSticky(t *testing.T) {
	var calls atomic.Int32
	initializer := nativeLibraryInitializer{load: func(path string) error {
		calls.Add(1)
		_, _, err := resolveWindowsNativeLibraryRequest(path, "")
		return err
	}}
	absolute := filepath.Join(t.TempDir(), "agentgate_ffi.dll")
	if err := initializer.initialize(absolute); err != nil {
		t.Fatalf("first initialization: %v", err)
	}
	for _, later := range []string{"relative.dll", "invalid\x00later", filepath.Join(t.TempDir(), "different.dll")} {
		if err := initializer.initialize(later); err != nil {
			t.Fatalf("stored successful result changed for %q: %v", later, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("load calls = %d, want 1", calls.Load())
	}
}

func TestNativeLibraryInitializationIsConcurrentExactOnce(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	initializer := nativeLibraryInitializer{load: func(string) error {
		calls.Add(1)
		close(entered)
		<-release
		return nil
	}}

	const callers = 32
	errors := make(chan error, callers)
	var wait sync.WaitGroup
	wait.Add(callers)
	for index := 0; index < callers; index++ {
		go func() {
			defer wait.Done()
			errors <- initializer.initialize("first")
		}()
	}
	<-entered
	close(release)
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent initialization: %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("load calls = %d, want 1", calls.Load())
	}
}

type nativeBindingFixture struct {
	binding         []byte
	token           []byte
	oldKeyID        string
	oldKey          []byte
	privateMaterial []byte
	submission      []byte
}

func loadNativeBindingFixture(t *testing.T) nativeBindingFixture {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	payload, err := os.ReadFile(filepath.Join(filepath.Dir(current), "../../../fixtures/bindings/v1.json"))
	if err != nil {
		t.Fatalf("read binding fixture: %v", err)
	}
	var document struct {
		Vectors struct {
			BindingHex      string          `json:"binding_hex"`
			TokenHex        string          `json:"token_hex"`
			OldKeyID        string          `json:"old_key_id"`
			OldKeyHex       string          `json:"old_key_hex"`
			PrivateMaterial json.RawMessage `json:"private_material"`
		} `json:"vectors"`
		Cases []struct {
			ID         string          `json:"id"`
			Submission json.RawMessage `json:"submission"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("decode binding fixture: %v", err)
	}
	decodeHex := func(name, value string) []byte {
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		return decoded
	}
	var submission []byte
	for _, fixtureCase := range document.Cases {
		if fixtureCase.ID == "accepted" {
			submission = bytes.Clone(fixtureCase.Submission)
			break
		}
	}
	if len(submission) == 0 {
		t.Fatal("binding fixture lacks accepted case")
	}
	return nativeBindingFixture{
		binding:         decodeHex("binding_hex", document.Vectors.BindingHex),
		token:           decodeHex("token_hex", document.Vectors.TokenHex),
		oldKeyID:        document.Vectors.OldKeyID,
		oldKey:          decodeHex("old_key_hex", document.Vectors.OldKeyHex),
		privateMaterial: bytes.Clone(document.Vectors.PrivateMaterial),
		submission:      submission,
	}
}

func readNativeSource(t *testing.T, name string) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	payload, err := os.ReadFile(filepath.Join(filepath.Dir(current), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(payload)
}
