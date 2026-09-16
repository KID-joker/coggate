package agentgate

import (
	"bytes"
	"log/slog"
	"sync/atomic"
	"unicode/utf8"
)

// LifecycleStatus is a closed status returned by lifecycle write callbacks.
type LifecycleStatus int32

const (
	LifecycleStatusOK LifecycleStatus = iota
	LifecycleStatusUnavailable
	LifecycleStatusConflict
	LifecycleStatusInternal
)

// BeginStatus is a closed status returned by Lifecycle.BeginAttempt.
type BeginStatus int32

const (
	BeginStatusOK                BeginStatus = 0
	BeginStatusUnavailable       BeginStatus = 1
	BeginStatusConflict          BeginStatus = 2
	BeginStatusInternal          BeginStatus = 3
	BeginStatusNotFound          BeginStatus = 10
	BeginStatusExpired           BeginStatus = 11
	BeginStatusAlreadyConsumed   BeginStatus = 12
	BeginStatusBindingMismatch   BeginStatus = 13
	BeginStatusNonceMismatch     BeginStatus = 14
	BeginStatusAttemptsExhausted BeginStatus = 15
)

// KeyStatus is a closed status returned by key-provider callbacks.
type KeyStatus int32

const (
	KeyStatusOK KeyStatus = iota
	KeyStatusUnavailable
	KeyStatusNotFound
	KeyStatusInvalidMaterial
)

// AttemptOutcome describes how a begun verification attempt completed.
type AttemptOutcome int32

const (
	AttemptOutcomeAccepted AttemptOutcome = iota + 1
	AttemptOutcomeRejected
	AttemptOutcomeSystemFailure
)

// BeginAttemptResult supplies lifecycle material and an optional token. AgentGate
// copies both outputs before returning from the callback.
type BeginAttemptResult struct {
	Status   BeginStatus
	Material []byte
	Token    []byte
}

func (BeginAttemptResult) String() string       { return "BeginAttemptResult()" }
func (BeginAttemptResult) GoString() string     { return "BeginAttemptResult()" }
func (BeginAttemptResult) LogValue() slog.Value { return slog.StringValue("BeginAttemptResult()") }

// ActiveKeyResult contains an exact UTF-8 key identifier and key material.
type ActiveKeyResult struct {
	Status KeyStatus
	KeyID  string
	Key    []byte
}

func (ActiveKeyResult) String() string       { return "ActiveKeyResult()" }
func (ActiveKeyResult) GoString() string     { return "ActiveKeyResult()" }
func (ActiveKeyResult) LogValue() slog.Value { return slog.StringValue("ActiveKeyResult()") }

// KeyResult contains key material for an exact identifier lookup.
type KeyResult struct {
	Status KeyStatus
	Key    []byte
}

func (KeyResult) String() string       { return "KeyResult()" }
func (KeyResult) GoString() string     { return "KeyResult()" }
func (KeyResult) LogValue() slog.Value { return slog.StringValue("KeyResult()") }

// Lifecycle owns issued challenge state. All byte slices received by these
// methods are independent copies whose contents are guaranteed only for the
// duration of the callback. Implementations must not call Issue, Verify, or
// Close on the Service currently invoking the callback.
type Lifecycle interface {
	StoreIssued(privateJSON []byte, binding []byte, limit AttemptLimit) LifecycleStatus
	BeginAttempt(identityJSON []byte, binding []byte, serverTime int64) BeginAttemptResult
	FinishAttempt(token []byte, outcome AttemptOutcome) LifecycleStatus
}

// KeyProvider supplies the active signing key and exact historical key lookups.
// Implementations must not reenter the Service currently invoking the callback.
type KeyProvider interface {
	ActiveKey() ActiveKeyResult
	KeyByID(keyID string) KeyResult
}

// Observer receives best-effort public event JSON. Panics are swallowed.
// Implementations must not reenter the Service currently invoking the callback.
type Observer interface{ Observe(eventJSON []byte) }

type callbackAdapter struct {
	lifecycle            Lifecycle
	keys                 KeyProvider
	observer             Observer
	active               atomic.Bool
	releaseHook          func(hostReleaseTag)
	transientClearedHook func(hostReleaseTag, []byte)
}

func newCallbackAdapter(lifecycle Lifecycle, keys KeyProvider, observer Observer) *callbackAdapter {
	return &callbackAdapter{lifecycle: lifecycle, keys: keys, observer: observer}
}

func (adapter *callbackAdapter) enter() bool { return adapter.active.CompareAndSwap(false, true) }
func (adapter *callbackAdapter) leave()      { adapter.active.Store(false) }

func (adapter *callbackAdapter) storeIssued(privateJSON, binding []byte, limit AttemptLimit) (status int32) {
	status = int32(LifecycleStatusInternal)
	if !adapter.enter() {
		return
	}
	defer adapter.leave()
	defer func() {
		if recover() != nil {
			status = int32(LifecycleStatusInternal)
		}
	}()
	result := adapter.lifecycle.StoreIssued(bytes.Clone(privateJSON), bytes.Clone(binding), limit)
	if !validLifecycleStatus(result) {
		return int32(LifecycleStatusInternal)
	}
	return int32(result)
}

func (adapter *callbackAdapter) beginAttempt(identityJSON, binding []byte, serverTime int64) (status int32, material, token []byte) {
	status = int32(BeginStatusInternal)
	if !adapter.enter() {
		return status, nil, nil
	}
	defer adapter.leave()
	defer func() {
		if recover() != nil {
			status, material, token = int32(BeginStatusInternal), nil, nil
		}
	}()
	result := adapter.lifecycle.BeginAttempt(bytes.Clone(identityJSON), bytes.Clone(binding), serverTime)
	if !validBeginStatus(result.Status) {
		return status, nil, nil
	}
	if result.Status != BeginStatusOK {
		return int32(result.Status), nil, nil
	}
	if !validPrivateChallengeMaterial(result.Material) {
		return status, nil, nil
	}
	return int32(BeginStatusOK), bytes.Clone(result.Material), bytes.Clone(result.Token)
}

func validPrivateChallengeMaterial(payload []byte) bool {
	type wirePrivateChallengeMaterial struct {
		ChallengeID      *string         `json:"challenge_id"`
		GeneratorVersion *string         `json:"generator_version"`
		Nonce            *string         `json:"nonce"`
		IssuedAt         *int64          `json:"issued_at"`
		ExpiresAt        *int64          `json:"expires_at"`
		MacKeyID         *string         `json:"mac_key_id"`
		AnswerMAC        *string         `json:"answer_mac"`
		AnswerEncoding   *AnswerEncoding `json:"answer_encoding"`
	}
	var wire wirePrivateChallengeMaterial
	if strictDecodeObject(payload, &wire,
		"challenge_id", "generator_version", "nonce", "issued_at", "expires_at",
		"mac_key_id", "answer_mac", "answer_encoding") != nil {
		return false
	}
	return wire.ChallengeID != nil && wire.GeneratorVersion != nil && wire.Nonce != nil &&
		wire.IssuedAt != nil && wire.ExpiresAt != nil && wire.MacKeyID != nil &&
		wire.AnswerMAC != nil && wire.AnswerEncoding != nil &&
		*wire.AnswerEncoding == AnswerEncodingBase64URL
}

func (adapter *callbackAdapter) hostReleased(tag hostReleaseTag) {
	if adapter.releaseHook != nil {
		adapter.releaseHook(tag)
	}
}

func (adapter *callbackAdapter) clearTransient(tag hostReleaseTag, value []byte) {
	for index := range value {
		value[index] = 0
	}
	if adapter.transientClearedHook != nil {
		adapter.transientClearedHook(tag, value)
	}
}

func (adapter *callbackAdapter) finishAttempt(token []byte, outcome int32) (status int32) {
	status = int32(LifecycleStatusInternal)
	if !adapter.enter() {
		return
	}
	defer adapter.leave()
	defer func() {
		if recover() != nil {
			status = int32(LifecycleStatusInternal)
		}
	}()
	converted := AttemptOutcome(outcome)
	if !validAttemptOutcome(converted) {
		return
	}
	result := adapter.lifecycle.FinishAttempt(bytes.Clone(token), converted)
	if !validLifecycleStatus(result) {
		return
	}
	return int32(result)
}

func (adapter *callbackAdapter) activeKey() (status int32, keyID, key []byte) {
	status = int32(KeyStatusUnavailable)
	if !adapter.enter() {
		return status, nil, nil
	}
	defer adapter.leave()
	defer func() {
		if recover() != nil {
			status, keyID, key = int32(KeyStatusUnavailable), nil, nil
		}
	}()
	result := adapter.keys.ActiveKey()
	if !validKeyStatus(result.Status) {
		return status, nil, nil
	}
	if result.Status != KeyStatusOK {
		return int32(result.Status), nil, nil
	}
	if result.KeyID == "" || !utf8.ValidString(result.KeyID) || len(result.Key) < 32 {
		return status, nil, nil
	}
	return int32(KeyStatusOK), []byte(result.KeyID), bytes.Clone(result.Key)
}

func (adapter *callbackAdapter) keyByID(keyID []byte) (status int32, key []byte) {
	status = int32(KeyStatusUnavailable)
	if !adapter.enter() {
		return status, nil
	}
	defer adapter.leave()
	defer func() {
		if recover() != nil {
			status, key = int32(KeyStatusUnavailable), nil
		}
	}()
	if !utf8.Valid(keyID) {
		return status, nil
	}
	result := adapter.keys.KeyByID(string(bytes.Clone(keyID)))
	if !validKeyStatus(result.Status) {
		return status, nil
	}
	if result.Status != KeyStatusOK {
		return int32(result.Status), nil
	}
	if len(result.Key) < 32 {
		return status, nil
	}
	return int32(KeyStatusOK), bytes.Clone(result.Key)
}

func (adapter *callbackAdapter) observe(eventJSON []byte) {
	if adapter.observer == nil || !adapter.enter() {
		return
	}
	defer adapter.leave()
	defer func() { _ = recover() }()
	adapter.observer.Observe(bytes.Clone(eventJSON))
}

func validLifecycleStatus(value LifecycleStatus) bool {
	return value >= LifecycleStatusOK && value <= LifecycleStatusInternal
}
func validKeyStatus(value KeyStatus) bool {
	return value >= KeyStatusOK && value <= KeyStatusInvalidMaterial
}
func validAttemptOutcome(value AttemptOutcome) bool {
	return value >= AttemptOutcomeAccepted && value <= AttemptOutcomeSystemFailure
}
func validBeginStatus(value BeginStatus) bool {
	switch value {
	case BeginStatusOK, BeginStatusUnavailable, BeginStatusConflict, BeginStatusInternal,
		BeginStatusNotFound, BeginStatusExpired, BeginStatusAlreadyConsumed,
		BeginStatusBindingMismatch, BeginStatusNonceMismatch, BeginStatusAttemptsExhausted:
		return true
	default:
		return false
	}
}
