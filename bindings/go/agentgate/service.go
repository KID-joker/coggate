package agentgate

import (
	"bytes"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
)

// Service is a serialized, explicitly closable AgentGate native service.
type Service struct {
	callMu    sync.Mutex
	native    *nativeService
	callbacks *callbackAdapter
	active    *atomic.Bool
}

// NewService initializes the native library and creates a service. On Unix the
// library path is ignored because the shared library is resolved by the linker.
func NewService(lifecycle Lifecycle, keys KeyProvider, observer Observer, nativeLibraryPath string) (*Service, error) {
	if nilInterface(lifecycle) || nilInterface(keys) {
		return nil, errorForStatus(100)
	}
	if nilInterface(observer) {
		observer = nil
	}
	if err := initializeNativeLibrary(nativeLibraryPath); err != nil {
		return nil, err
	}
	callbacks := newCallbackAdapter(lifecycle, keys, observer)
	native, err := nativeServiceCreate(callbacks, observer != nil)
	if err != nil {
		return nil, err
	}
	service := &Service{native: native, callbacks: callbacks, active: &callbacks.active}
	runtime.SetFinalizer(service, finalizeService)
	return service, nil
}

// Issue creates and stores a challenge, returning only its public portion.
func (service *Service) Issue(request IssueRequest) (PublicChallenge, error) {
	if service == nil || service.callbackActive() {
		return PublicChallenge{}, errorForStatus(100)
	}
	service.callMu.Lock()
	defer service.callMu.Unlock()
	if service.native == nil || !validIssueRequest(request) {
		return PublicChallenge{}, errorForStatus(100)
	}
	version := []byte(request.version)
	binding := bytes.Clone(request.binding)
	payload, err := nativeServiceIssue(service.native, version, binding, request.attemptLimit)
	if err != nil {
		return PublicChallenge{}, err
	}
	challenge, decodeErr := decodePublicChallenge(payload)
	if decodeErr != nil {
		return PublicChallenge{}, errorForStatus(7)
	}
	return challenge, nil
}

// Verify checks one submission. Lifecycle rejection is returned as an outcome;
// native failures are returned as stable AgentGateError values.
func (service *Service) Verify(submission Submission, binding []byte) (VerificationOutcome, error) {
	if service == nil || service.callbackActive() {
		return VerificationOutcome{}, errorForStatus(100)
	}
	service.callMu.Lock()
	defer service.callMu.Unlock()
	if service.native == nil || len(binding) == 0 || len(binding) > maxBindingBytes {
		return VerificationOutcome{}, errorForStatus(100)
	}
	payload, err := encodeSubmission(submission)
	if err != nil {
		return VerificationOutcome{}, errorForStatus(100)
	}
	output, err := nativeServiceVerify(service.native, payload, bytes.Clone(binding))
	if err != nil {
		return VerificationOutcome{}, err
	}
	outcome, decodeErr := decodeVerificationOutcome(output)
	if decodeErr != nil {
		return VerificationOutcome{}, errorForStatus(7)
	}
	return outcome, nil
}

// Close destroys the native service exactly once. Calls made from a callback
// fail fast; an external call that reaches the service lock waits for in-flight work.
func (service *Service) Close() error {
	if service == nil || service.callbackActive() {
		return errorForStatus(100)
	}
	return service.closeWaitingForInflight()
}

func (service *Service) closeWaitingForInflight() error {
	service.callMu.Lock()
	defer service.callMu.Unlock()
	if service.native == nil {
		return nil
	}
	native := service.native
	err := nativeServiceDestroy(native)
	if err != nil {
		return err
	}
	service.native = nil
	service.callbacks = nil
	runtime.SetFinalizer(service, nil)
	return nil
}

func (service *Service) callbackActive() bool {
	return service.active != nil && service.active.Load()
}

func finalizeService(service *Service) {
	if service == nil {
		return
	}
	_ = service.closeWaitingForInflight()
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	switch kind {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflect.ValueOf(value).IsNil()
	default:
		return false
	}
}

func validIssueRequest(request IssueRequest) bool {
	return request.version != "" && stringsValid(request.version) && len(request.binding) > 0 && len(request.binding) <= maxBindingBytes && request.attemptLimit.valid()
}
