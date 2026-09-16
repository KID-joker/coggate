package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/agentgate/agentgate/bindings/go/agentgate"
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

func (store *memoryLifecycle) StoreIssued(privateJSON, binding []byte, _ agentgate.AttemptLimit) agentgate.LifecycleStatus {
	var identity struct {
		ChallengeID string `json:"challenge_id"`
	}
	if json.Unmarshal(privateJSON, &identity) != nil || identity.ChallengeID == "" {
		return agentgate.LifecycleStatusInternal
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.challenges[identity.ChallengeID] = &storedChallenge{material: bytes.Clone(privateJSON), binding: bytes.Clone(binding)}
	return agentgate.LifecycleStatusOK
}

func (store *memoryLifecycle) BeginAttempt(identityJSON, binding []byte, _ int64) agentgate.BeginAttemptResult {
	var identity struct {
		ChallengeID string `json:"challenge_id"`
	}
	if json.Unmarshal(identityJSON, &identity) != nil {
		return agentgate.BeginAttemptResult{Status: agentgate.BeginStatusInternal}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	challenge := store.challenges[identity.ChallengeID]
	if challenge == nil {
		return agentgate.BeginAttemptResult{Status: agentgate.BeginStatusNotFound}
	}
	if challenge.consumed {
		return agentgate.BeginAttemptResult{Status: agentgate.BeginStatusAlreadyConsumed}
	}
	if !bytes.Equal(challenge.binding, binding) {
		return agentgate.BeginAttemptResult{Status: agentgate.BeginStatusBindingMismatch}
	}
	return agentgate.BeginAttemptResult{Status: agentgate.BeginStatusOK, Material: bytes.Clone(challenge.material), Token: []byte(identity.ChallengeID)}
}

func (store *memoryLifecycle) FinishAttempt(token []byte, _ agentgate.AttemptOutcome) agentgate.LifecycleStatus {
	store.mu.Lock()
	defer store.mu.Unlock()
	challenge := store.challenges[string(token)]
	if challenge == nil {
		return agentgate.LifecycleStatusConflict
	}
	challenge.consumed = true
	return agentgate.LifecycleStatusOK
}

type memoryKeys struct {
	activeID  string
	activeKey []byte
	oldID     string
	oldKey    []byte
}

func (keys *memoryKeys) ActiveKey() agentgate.ActiveKeyResult {
	return agentgate.ActiveKeyResult{Status: agentgate.KeyStatusOK, KeyID: keys.activeID, Key: bytes.Clone(keys.activeKey)}
}
func (keys *memoryKeys) KeyByID(id string) agentgate.KeyResult {
	switch id {
	case keys.activeID:
		return agentgate.KeyResult{Status: agentgate.KeyStatusOK, Key: bytes.Clone(keys.activeKey)}
	case keys.oldID:
		return agentgate.KeyResult{Status: agentgate.KeyStatusOK, Key: bytes.Clone(keys.oldKey)}
	default:
		return agentgate.KeyResult{Status: agentgate.KeyStatusNotFound}
	}
}

type discardObserver struct{}

func (discardObserver) Observe([]byte) {}

func main() {
	library := flag.String("library", "", "path to agentgate_ffi.dll on Windows")
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
	service, err := agentgate.NewService(lifecycle, keys, discardObserver{}, library)
	if err != nil {
		return err
	}
	// Correctness must not depend on the finalizer; callers explicitly Close.
	defer service.Close()

	request, err := agentgate.NewV1IssueRequest(issueBinding)
	if err != nil {
		return err
	}
	_, err = service.Issue(request)
	if err != nil {
		return err
	}
	fmt.Println("issue: ok")

	// This accepted path uses the shared deterministic fixture. Applications do
	// not reproduce AgentGate's MAC construction; they persist private material
	// from Issue and later return it from BeginAttempt in the same way.
	fixtureBinding := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
	const fixtureChallengeID = "Y2hhbGxlbmdlLTEyMzQ1Ng"
	const fixtureNonce = "bm9uY2UtMTIzNDU2Nzg5MA"
	fixtureMaterial := []byte(`{"challenge_id":"Y2hhbGxlbmdlLTEyMzQ1Ng","generator_version":"1.0","nonce":"bm9uY2UtMTIzNDU2Nzg5MA","issued_at":1788062400,"expires_at":1788062408,"mac_key_id":"2026-08","answer_mac":"b9cb8fd013b40e31c7bc3a1c33b7e36143ef98d045a924ed09ebd38ff07cec2c","answer_encoding":"base64url"}`)
	lifecycle.seed(fixtureChallengeID, fixtureMaterial, fixtureBinding)
	outcome, err := service.Verify(agentgate.Submission{
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
	if typed, ok := err.(*agentgate.AgentGateError); ok {
		return typed.Code()
	}
	return "internal_error"
}
