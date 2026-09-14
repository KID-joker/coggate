package agentgate

import (
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

func TestNativeNonOKCallbackDoesNotTransferHostOwnership(t *testing.T) {
	nativeResetHostAllocationCounters()
	nativeTestCallbackOutput(3, []byte("must remain Go-owned"))
	allocations, releases := nativeHostAllocationCounters()
	if allocations != 0 || releases != 0 {
		t.Fatalf("non-OK callback transferred ownership: (%d, %d)", allocations, releases)
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
	if got := strings.Count(source, "_ = recover()"); got != 6 {
		t.Fatalf("panic recovery guards = %d, want one for each of six Go callback exports", got)
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
	storeIssuedFn func([]byte, []byte, AttemptLimit) int32
	activeKeyFn   func() (int32, []byte, []byte)
	observeFn     func([]byte)
}

func (callbacks *nativeTestCallbacks) storeIssued(privateJSON, binding []byte, limit AttemptLimit) int32 {
	if callbacks.storeIssuedFn != nil {
		return callbacks.storeIssuedFn(privateJSON, binding, limit)
	}
	return 0
}

func (*nativeTestCallbacks) beginAttempt([]byte, []byte, int64) (int32, []byte, []byte) {
	return 3, nil, nil
}

func (*nativeTestCallbacks) finishAttempt([]byte, int32) int32 { return 3 }

func (callbacks *nativeTestCallbacks) activeKey() (int32, []byte, []byte) {
	if callbacks.activeKeyFn != nil {
		return callbacks.activeKeyFn()
	}
	return 1, nil, nil
}

func (*nativeTestCallbacks) keyByID([]byte) (int32, []byte) { return 1, nil }

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
		"static HMODULE ag_go_module",
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
