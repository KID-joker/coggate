package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/KID-joker/coggate/bindings/go/coggate"
)

type storedChallenge struct {
	material []byte
	binding  []byte
	consumed bool
}

// Callbacks run while the Service holds callMu. They must not synchronously
// reenter that Service through Issue, Verify, or Close, or they will deadlock.
type memoryLifecycle struct {
	mu         sync.Mutex
	challenges map[string]*storedChallenge
}

func (store *memoryLifecycle) seed(challengeID string, material, binding []byte) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.challenges[challengeID] = &storedChallenge{
		material: bytes.Clone(material), binding: bytes.Clone(binding),
	}
}

func (store *memoryLifecycle) StoreIssued(privateJSON, binding []byte, _ coggate.AttemptLimit) coggate.LifecycleStatus {
	var identity struct {
		ChallengeID string `json:"challenge_id"`
	}
	if json.Unmarshal(privateJSON, &identity) != nil || identity.ChallengeID == "" {
		return coggate.LifecycleStatusInternal
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.challenges[identity.ChallengeID] = &storedChallenge{material: bytes.Clone(privateJSON), binding: bytes.Clone(binding)}
	return coggate.LifecycleStatusOK
}

func (store *memoryLifecycle) BeginAttempt(identityJSON, binding []byte, _ int64) coggate.BeginAttemptResult {
	var identity struct {
		ChallengeID string `json:"challenge_id"`
	}
	if json.Unmarshal(identityJSON, &identity) != nil {
		return coggate.BeginAttemptResult{Status: coggate.BeginStatusInternal}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	challenge := store.challenges[identity.ChallengeID]
	if challenge == nil {
		return coggate.BeginAttemptResult{Status: coggate.BeginStatusNotFound}
	}
	if challenge.consumed {
		return coggate.BeginAttemptResult{Status: coggate.BeginStatusAlreadyConsumed}
	}
	if !bytes.Equal(challenge.binding, binding) {
		return coggate.BeginAttemptResult{Status: coggate.BeginStatusBindingMismatch}
	}
	return coggate.BeginAttemptResult{Status: coggate.BeginStatusOK, Material: bytes.Clone(challenge.material), Token: []byte(identity.ChallengeID)}
}

func (store *memoryLifecycle) FinishAttempt(token []byte, _ coggate.AttemptOutcome) coggate.LifecycleStatus {
	store.mu.Lock()
	defer store.mu.Unlock()
	challenge := store.challenges[string(token)]
	if challenge == nil {
		return coggate.LifecycleStatusConflict
	}
	challenge.consumed = true
	return coggate.LifecycleStatusOK
}

type memoryKeys struct {
	activeID  string
	activeKey []byte
	oldID     string
	oldKey    []byte
}

func (keys *memoryKeys) ActiveKey() coggate.ActiveKeyResult {
	return coggate.ActiveKeyResult{Status: coggate.KeyStatusOK, KeyID: keys.activeID, Key: bytes.Clone(keys.activeKey)}
}
func (keys *memoryKeys) KeyByID(id string) coggate.KeyResult {
	switch id {
	case keys.activeID:
		return coggate.KeyResult{Status: coggate.KeyStatusOK, Key: bytes.Clone(keys.activeKey)}
	case keys.oldID:
		return coggate.KeyResult{Status: coggate.KeyStatusOK, Key: bytes.Clone(keys.oldKey)}
	default:
		return coggate.KeyResult{Status: coggate.KeyStatusNotFound}
	}
}

type discardObserver struct{}

func (discardObserver) Observe([]byte) {}

func main() {
	library := flag.String("library", "", "path to coggate_ffi.dll on Windows")
	answer := flag.String("answer", "YQ", "application-supplied unpadded base64url answer")
	flag.Parse()
	if err := run(*library, *answer); err != nil {
		fmt.Fprintln(os.Stderr, errorCode(err))
		os.Exit(1)
	}
}

func run(library, answer string) error {
	issueBinding := []byte("complete-example-binding")
	lifecycle := &memoryLifecycle{challenges: make(map[string]*storedChallenge)}
	keys := &memoryKeys{
		activeID: "example-2026-09", activeKey: bytes.Repeat([]byte{0x41}, 32),
		oldID: "2026-08", oldKey: []byte("0123456789abcdef0123456789abcdef"),
	}
	// External goroutines may call Issue, Verify, and Close concurrently; the
	// Service serializes those calls and waits for the current call to finish.
	service, err := coggate.NewService(lifecycle, keys, discardObserver{}, library)
	if err != nil {
		return err
	}
	// Correctness must not depend on the finalizer; callers explicitly Close.
	defer service.Close()

	request, err := coggate.NewV1IssueRequest(issueBinding)
	if err != nil {
		return err
	}
	_, err = service.Issue(request)
	if err != nil {
		return err
	}
	fmt.Println("issue: ok")

	// This accepted path uses the shared deterministic fixture. Applications do
	// not reproduce CogGate's MAC construction; they persist private material
	// from Issue and later return it from BeginAttempt in the same way.
	fixtureBinding := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
	const fixtureChallengeID = "Y2hhbGxlbmdlLTEyMzQ1Ng"
	const fixtureNonce = "bm9uY2UtMTIzNDU2Nzg5MA"
	fixtureMaterial := []byte(`{"challenge_id":"Y2hhbGxlbmdlLTEyMzQ1Ng","generator_version":"1.0","nonce":"bm9uY2UtMTIzNDU2Nzg5MA","issued_at":1788062400,"expires_at":1788062408,"mac_key_id":"2026-08","answer_mac":"ccdffbb67b4c9da34f91d56d12970b311d7345e8bcf579d1326fc4a78633330c","answer_encoding":"base64url"}`)
	lifecycle.seed(fixtureChallengeID, fixtureMaterial, fixtureBinding)
	outcome, err := service.Verify(coggate.Submission{
		ChallengeID: fixtureChallengeID, Nonce: fixtureNonce, Answer: answer,
	}, fixtureBinding)
	if err != nil {
		fmt.Println("verify:", errorCode(err))
		return nil
	}
	fmt.Println("verify:", outcome.Status)
	return nil
}

func errorCode(err error) string {
	if typed, ok := err.(*coggate.CogGateError); ok {
		return typed.Code()
	}
	return "internal_error"
}
