package coggate

/*
#cgo CFLAGS: -I${SRCDIR}/../../../packages/ffi/include
#include "native_bridge.h"
*/
import "C"

import (
	"bytes"
	"path/filepath"
	"runtime"
	"runtime/cgo"
	"strings"
	"sync"
	"unsafe"
)

type nativeStructLayout struct {
	size    uintptr
	offsets []uintptr
}

type nativeContract struct {
	statuses          []int32
	lifecycleStatuses []int32
	beginStatuses     []int32
	keyStatuses       []int32
	attemptOutcomes   []int32
	attemptLimits     []uint32
	layouts           map[string]nativeStructLayout
}

func nativeABIContract() nativeContract {
	return nativeContract{
		statuses: []int32{
			int32(C.AG_STATUS_OK), int32(C.AG_STATUS_INVALID_CONFIGURATION),
			int32(C.AG_STATUS_GENERATION_FAILED), int32(C.AG_STATUS_INVALID_CHALLENGE_MATERIAL),
			int32(C.AG_STATUS_INVALID_ANSWER_ENCODING), int32(C.AG_STATUS_ANSWER_MISMATCH),
			int32(C.AG_STATUS_UNSUPPORTED_GENERATOR_VERSION), int32(C.AG_STATUS_INTERNAL_ERROR),
			int32(C.AG_STATUS_INVALID_ARGUMENT), int32(C.AG_STATUS_CALLBACK_FAILED),
			int32(C.AG_STATUS_PANIC_CAUGHT),
		},
		lifecycleStatuses: []int32{
			int32(C.AG_LIFECYCLE_STATUS_OK), int32(C.AG_LIFECYCLE_STATUS_UNAVAILABLE),
			int32(C.AG_LIFECYCLE_STATUS_CONFLICT), int32(C.AG_LIFECYCLE_STATUS_INTERNAL),
		},
		beginStatuses: []int32{
			int32(C.AG_BEGIN_STATUS_OK), int32(C.AG_BEGIN_STATUS_UNAVAILABLE),
			int32(C.AG_BEGIN_STATUS_CONFLICT), int32(C.AG_BEGIN_STATUS_INTERNAL),
			int32(C.AG_BEGIN_STATUS_NOT_FOUND), int32(C.AG_BEGIN_STATUS_EXPIRED),
			int32(C.AG_BEGIN_STATUS_ALREADY_CONSUMED), int32(C.AG_BEGIN_STATUS_BINDING_MISMATCH),
			int32(C.AG_BEGIN_STATUS_NONCE_MISMATCH), int32(C.AG_BEGIN_STATUS_ATTEMPTS_EXHAUSTED),
		},
		keyStatuses: []int32{
			int32(C.AG_KEY_STATUS_OK), int32(C.AG_KEY_STATUS_UNAVAILABLE),
			int32(C.AG_KEY_STATUS_NOT_FOUND), int32(C.AG_KEY_STATUS_INVALID_MATERIAL),
		},
		attemptOutcomes: []int32{
			int32(C.AG_ATTEMPT_OUTCOME_ACCEPTED), int32(C.AG_ATTEMPT_OUTCOME_REJECTED),
			int32(C.AG_ATTEMPT_OUTCOME_SYSTEM_FAILURE),
		},
		attemptLimits: []uint32{uint32(C.AG_ATTEMPT_LIMIT_ONE), uint32(C.AG_ATTEMPT_LIMIT_TWO)},
		layouts: map[string]nativeStructLayout{
			"byte_slice":          nativeLayout(C.ag_go_layout_byte_slice(), 2),
			"owned_buffer":        nativeLayout(C.ag_go_layout_owned_buffer(), 3),
			"host_buffer":         nativeLayout(C.ag_go_layout_host_buffer(), 4),
			"callback_header":     nativeLayout(C.ag_go_layout_callback_header(), 2),
			"lifecycle_callbacks": nativeLayout(C.ag_go_layout_lifecycle_callbacks(), 6),
			"key_callbacks":       nativeLayout(C.ag_go_layout_key_callbacks(), 5),
			"observer_callbacks":  nativeLayout(C.ag_go_layout_observer_callbacks(), 4),
		},
	}
}

func nativeLayout(layout C.ag_go_layout, count int) nativeStructLayout {
	offsets := make([]uintptr, count)
	for index := range offsets {
		offsets[index] = uintptr(layout.offsets[index])
	}
	return nativeStructLayout{size: uintptr(layout.size), offsets: offsets}
}

func nativeABIVersion() uint32 { return uint32(C.ag_go_abi_version()) }

func nativeCoreVersion() []byte {
	value := C.ag_go_core_version()
	return copyBorrowed(value.data, value.len)
}

func nativeFreeCanonicalBuffer() (int32, bool) {
	var buffer C.ag_owned_buffer
	status := C.ag_go_buffer_free(&buffer)
	return int32(status), buffer.data == nil && buffer.len == 0 && buffer.capacity == 0
}

type nativeCallbacks interface {
	storeIssued(privateJSON, binding []byte, attemptLimit AttemptLimit) int32
	beginAttempt(identityJSON, binding []byte, serverTime int64) (status int32, material, token []byte)
	finishAttempt(token []byte, outcome int32) int32
	activeKey() (status int32, keyID, key []byte)
	keyByID(keyID []byte) (status int32, key []byte)
	observe(eventJSON []byte)
}

type hostReleaseTag int32

const (
	hostReleaseMaterial hostReleaseTag = iota + 1
	hostReleaseToken
	hostReleaseActiveKeyID
	hostReleaseActiveKey
	hostReleaseKey
)

func (tag hostReleaseTag) valid() bool {
	return tag >= hostReleaseMaterial && tag <= hostReleaseKey
}

func (tag hostReleaseTag) String() string {
	return map[hostReleaseTag]string{
		hostReleaseMaterial: "material", hostReleaseToken: "token",
		hostReleaseActiveKeyID: "active_key_id", hostReleaseActiveKey: "active_key",
		hostReleaseKey: "key",
	}[tag]
}

type hostReleaseObserver interface{ hostReleased(hostReleaseTag) }
type hostTransientClearer interface {
	clearTransient(hostReleaseTag, []byte)
}

func clearHostTransient(callbacks nativeCallbacks, tag hostReleaseTag, value []byte) {
	if clearer, ok := callbacks.(hostTransientClearer); ok {
		clearer.clearTransient(tag, value)
	}
}

type nativeService struct {
	pointer        *C.ag_service
	callbackHandle cgo.Handle
}

type nativeLibraryInitializer struct {
	once   sync.Once
	load   func(string) error
	result error
}

func (initializer *nativeLibraryInitializer) initialize(path string) error {
	initializer.once.Do(func() {
		initializer.result = initializer.load(path)
	})
	return initializer.result
}

func resolveWindowsNativeLibraryRequest(explicitPath, environmentPath string) (string, bool, error) {
	path := explicitPath
	includeDLLDirectory := path != ""
	if path == "" {
		path = environmentPath
		includeDLLDirectory = path != ""
	}
	if path == "" {
		return "coggate_ffi.dll", false, nil
	}
	if !filepath.IsAbs(path) || strings.IndexByte(path, 0) >= 0 {
		return "", false, errorForStatus(int32(C.AG_STATUS_INVALID_ARGUMENT))
	}
	return path, includeDLLDirectory, nil
}

func nativeServiceCreate(callbacks nativeCallbacks, withObserver bool) (*nativeService, error) {
	if callbacks == nil {
		return nil, errorForStatus(int32(C.AG_STATUS_INVALID_ARGUMENT))
	}
	handle := cgo.NewHandle(callbacks)
	lifecycle := C.ag_go_make_lifecycle_callbacks(C.uintptr_t(handle))
	keys := C.ag_go_make_key_callbacks(C.uintptr_t(handle))
	var observer *C.ag_observer_callbacks
	var observerValue C.ag_observer_callbacks
	if withObserver {
		observerValue = C.ag_go_make_observer_callbacks(C.uintptr_t(handle))
		observer = &observerValue
	}
	var pointer *C.ag_service
	status := C.ag_go_service_create(&lifecycle, &keys, observer, &pointer)
	runtime.KeepAlive(callbacks)
	if status != C.AG_STATUS_OK {
		handle.Delete()
		return nil, errorForStatus(int32(status))
	}
	return &nativeService{pointer: pointer, callbackHandle: handle}, nil
}

func nativeServiceDestroy(service *nativeService) error {
	if service == nil || service.pointer == nil {
		return errorForStatus(int32(C.AG_STATUS_INVALID_ARGUMENT))
	}
	status := C.ag_go_service_destroy(service.pointer)
	runtime.KeepAlive(service)
	if status != C.AG_STATUS_OK {
		return errorForStatus(int32(status))
	}
	service.pointer = nil
	service.callbackHandle.Delete()
	service.callbackHandle = 0
	return nil
}

func nativeServiceIssue(service *nativeService, version, binding []byte, limit AttemptLimit) ([]byte, error) {
	if service == nil || service.pointer == nil {
		return nil, errorForStatus(int32(C.AG_STATUS_INVALID_ARGUMENT))
	}
	versionSlice := nativeByteSlice(version)
	bindingSlice := nativeByteSlice(binding)
	var output C.ag_owned_buffer
	status := C.ag_go_service_issue(service.pointer, versionSlice, bindingSlice, C.ag_attempt_limit(limit), &output)
	runtime.KeepAlive(version)
	runtime.KeepAlive(binding)
	runtime.KeepAlive(service)
	return nativeOwnedResult(status, &output)
}

func nativeServiceVerify(service *nativeService, submissionJSON, binding []byte) ([]byte, error) {
	if service == nil || service.pointer == nil {
		return nil, errorForStatus(int32(C.AG_STATUS_INVALID_ARGUMENT))
	}
	submissionSlice := nativeByteSlice(submissionJSON)
	bindingSlice := nativeByteSlice(binding)
	var output C.ag_owned_buffer
	status := C.ag_go_service_verify(service.pointer, submissionSlice, bindingSlice, &output)
	runtime.KeepAlive(submissionJSON)
	runtime.KeepAlive(binding)
	runtime.KeepAlive(service)
	return nativeOwnedResult(status, &output)
}

func nativeByteSlice(value []byte) C.ag_byte_slice {
	var data *C.uint8_t
	if len(value) != 0 {
		data = (*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(value)))
	}
	return C.ag_byte_slice{data: data, len: C.size_t(len(value))}
}

func nativeOwnedResult(status C.ag_status, output *C.ag_owned_buffer) ([]byte, error) {
	if status != C.AG_STATUS_OK {
		return nil, errorForStatus(int32(status))
	}
	value := copyBorrowed(output.data, output.len)
	freeStatus := C.ag_go_buffer_free(output)
	if freeStatus != C.AG_STATUS_OK {
		return nil, errorForStatus(int32(freeStatus))
	}
	return value, nil
}

func copyBorrowed(data *C.uint8_t, length C.size_t) []byte {
	if length == 0 {
		return []byte{}
	}
	if data == nil || uint64(length) > uint64(^uint(0)>>1) {
		panic("invalid borrowed native byte slice")
	}
	return bytes.Clone(unsafe.Slice((*byte)(unsafe.Pointer(data)), int(length)))
}

func callbacksForHandle(handle C.uintptr_t) nativeCallbacks {
	return cgo.Handle(uintptr(handle)).Value().(nativeCallbacks)
}

func assignHostBuffer(output *C.ag_host_buffer, value []byte, handle C.uintptr_t, tag hostReleaseTag) bool {
	present := value != nil
	var data *C.uint8_t
	if len(value) != 0 {
		data = (*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(value)))
	}
	ok := C.ag_go_host_buffer_assign(output, data, C.size_t(len(value)), C.int(boolInt(present)),
		handle, C.ag_go_host_release_tag(tag)) != 0
	runtime.KeepAlive(value)
	return ok
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

//export agGoStoreIssued
func agGoStoreIssued(handle C.uintptr_t, privateData *C.uint8_t, privateLen C.size_t,
	bindingData *C.uint8_t, bindingLen C.size_t, limit C.uint32_t) (status C.int32_t) {
	status = C.AG_LIFECYCLE_STATUS_INTERNAL
	defer func() { _ = recover() }()
	callbacks := callbacksForHandle(handle)
	status = C.int32_t(callbacks.storeIssued(copyBorrowed(privateData, privateLen),
		copyBorrowed(bindingData, bindingLen), AttemptLimit(limit)))
	runtime.KeepAlive(callbacks)
	return
}

//export agGoBeginAttempt
func agGoBeginAttempt(handle C.uintptr_t, identityData *C.uint8_t, identityLen C.size_t,
	bindingData *C.uint8_t, bindingLen C.size_t, serverTime C.int64_t,
	materialOut, tokenOut *C.ag_host_buffer) (status C.int32_t) {
	status = C.AG_BEGIN_STATUS_INTERNAL
	defer func() { _ = recover() }()
	callbacks := callbacksForHandle(handle)
	callbackStatus, material, token := callbacks.beginAttempt(copyBorrowed(identityData, identityLen),
		copyBorrowed(bindingData, bindingLen), int64(serverTime))
	defer clearHostTransient(callbacks, hostReleaseToken, token)
	defer clearHostTransient(callbacks, hostReleaseMaterial, material)
	if callbackStatus != int32(C.AG_BEGIN_STATUS_OK) {
		return C.int32_t(callbackStatus)
	}
	if !assignHostBuffer(materialOut, material, handle, hostReleaseMaterial) {
		return C.AG_BEGIN_STATUS_INTERNAL
	}
	if !assignHostBuffer(tokenOut, token, handle, hostReleaseToken) {
		C.ag_go_host_buffer_discard(materialOut)
		return C.AG_BEGIN_STATUS_INTERNAL
	}
	runtime.KeepAlive(callbacks)
	return C.AG_BEGIN_STATUS_OK
}

//export agGoFinishAttempt
func agGoFinishAttempt(handle C.uintptr_t, tokenData *C.uint8_t, tokenLen C.size_t,
	outcome C.int32_t) (status C.int32_t) {
	status = C.AG_LIFECYCLE_STATUS_INTERNAL
	defer func() { _ = recover() }()
	callbacks := callbacksForHandle(handle)
	status = C.int32_t(callbacks.finishAttempt(copyBorrowed(tokenData, tokenLen), int32(outcome)))
	runtime.KeepAlive(callbacks)
	return
}

//export agGoActiveKey
func agGoActiveKey(handle C.uintptr_t, keyIDOut, keyOut *C.ag_host_buffer) (status C.int32_t) {
	status = C.AG_KEY_STATUS_UNAVAILABLE
	defer func() { _ = recover() }()
	callbacks := callbacksForHandle(handle)
	callbackStatus, keyID, key := callbacks.activeKey()
	defer clearHostTransient(callbacks, hostReleaseActiveKey, key)
	defer clearHostTransient(callbacks, hostReleaseActiveKeyID, keyID)
	if callbackStatus != int32(C.AG_KEY_STATUS_OK) {
		return C.int32_t(callbackStatus)
	}
	if !assignHostBuffer(keyIDOut, keyID, handle, hostReleaseActiveKeyID) {
		return C.AG_KEY_STATUS_UNAVAILABLE
	}
	if !assignHostBuffer(keyOut, key, handle, hostReleaseActiveKey) {
		C.ag_go_host_buffer_discard(keyIDOut)
		return C.AG_KEY_STATUS_UNAVAILABLE
	}
	runtime.KeepAlive(callbacks)
	return C.AG_KEY_STATUS_OK
}

//export agGoKeyByID
func agGoKeyByID(handle C.uintptr_t, keyIDData *C.uint8_t, keyIDLen C.size_t,
	keyOut *C.ag_host_buffer) (status C.int32_t) {
	status = C.AG_KEY_STATUS_UNAVAILABLE
	defer func() { _ = recover() }()
	callbacks := callbacksForHandle(handle)
	callbackStatus, key := callbacks.keyByID(copyBorrowed(keyIDData, keyIDLen))
	defer clearHostTransient(callbacks, hostReleaseKey, key)
	if callbackStatus != int32(C.AG_KEY_STATUS_OK) {
		return C.int32_t(callbackStatus)
	}
	if !assignHostBuffer(keyOut, key, handle, hostReleaseKey) {
		return C.AG_KEY_STATUS_UNAVAILABLE
	}
	runtime.KeepAlive(callbacks)
	return C.AG_KEY_STATUS_OK
}

//export agGoObserve
func agGoObserve(handle C.uintptr_t, eventData *C.uint8_t, eventLen C.size_t) {
	defer func() { _ = recover() }()
	callbacks := callbacksForHandle(handle)
	callbacks.observe(copyBorrowed(eventData, eventLen))
	runtime.KeepAlive(callbacks)
}

//export agGoHostReleased
func agGoHostReleased(handle C.uintptr_t, rawTag C.int32_t) {
	defer func() { _ = recover() }()
	tag := hostReleaseTag(rawTag)
	if !tag.valid() {
		return
	}
	callbacks := callbacksForHandle(handle)
	if observer, ok := callbacks.(hostReleaseObserver); ok {
		observer.hostReleased(tag)
	}
	runtime.KeepAlive(callbacks)
}

func nativeResetHostAllocationCounters() { C.ag_go_host_allocation_counters_reset() }

func nativeHostAllocationCounters() (uint64, uint64) {
	return uint64(C.ag_go_host_allocation_count()), uint64(C.ag_go_host_release_count())
}

type nativeCallbackStatuses struct {
	storeIssued   int32
	beginAttempt  int32
	finishAttempt int32
	activeKey     int32
	keyByID       int32
}

type nativeResolverTestResult struct {
	status   int32
	loads    uint32
	lookups  uint32
	abiCalls uint32
	unloads  uint32
	retained bool
}

func nativeTestResolveExports(missingLibrary bool, missingSymbol int, abiVersion uint32) nativeResolverTestResult {
	result := C.ag_go_test_resolve_exports(C.int(boolInt(missingLibrary)), C.int(missingSymbol), C.uint32_t(abiVersion))
	return nativeResolverTestResult{
		status: int32(result.status), loads: uint32(result.loads), lookups: uint32(result.lookups),
		abiCalls: uint32(result.abi_calls), unloads: uint32(result.unloads), retained: result.retained != 0,
	}
}

func nativeTestInvalidHandleCallbackStatuses() nativeCallbackStatuses {
	statuses := C.ag_go_test_invalid_handle_callbacks()
	return nativeCallbackStatuses{
		storeIssued: int32(statuses.store_issued), beginAttempt: int32(statuses.begin_attempt),
		finishAttempt: int32(statuses.finish_attempt), activeKey: int32(statuses.active_key),
		keyByID: int32(statuses.key_by_id),
	}
}

func nativeTestHostBufferRoundTrip(value []byte, present bool) ([]byte, bool) {
	var output C.ag_host_buffer
	if present && value == nil {
		value = []byte{}
	}
	if !present {
		value = nil
	}
	if !assignHostBuffer(&output, value, 0, hostReleaseMaterial) {
		panic("host allocation failed")
	}
	nonnull := output.data != nil
	copy := copyBorrowed(output.data, output.len)
	C.ag_go_host_buffer_discard(&output)
	return copy, nonnull
}

func nativeTestCallbackOutput(status int32, value []byte) {
	if status != int32(C.AG_BEGIN_STATUS_OK) {
		return
	}
	var output C.ag_host_buffer
	if assignHostBuffer(&output, value, 0, hostReleaseMaterial) {
		C.ag_go_host_buffer_discard(&output)
	}
}

func nativeTestHostReleaseNotification(handle uintptr, tag hostReleaseTag) {
	agGoHostReleased(C.uintptr_t(handle), C.int32_t(tag))
}

func nativeTestDeletedHandleReleaseNotification(callbacks nativeCallbacks, tag hostReleaseTag) {
	handle := cgo.NewHandle(callbacks)
	raw := uintptr(handle)
	handle.Delete()
	nativeTestHostReleaseNotification(raw, tag)
}

func nativeTestHostReleaseNotificationForCallbacks(callbacks nativeCallbacks, tag hostReleaseTag) {
	handle := cgo.NewHandle(callbacks)
	defer handle.Delete()
	nativeTestHostReleaseNotification(uintptr(handle), tag)
}

func nativeTestHostBufferOversizedAssignFails() bool {
	return C.ag_go_test_host_buffer_oversized_assign() == 0
}
