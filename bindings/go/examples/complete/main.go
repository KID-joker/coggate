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

type memoryLifecycle struct {
	mu         sync.Mutex
	challenges map[string]*storedChallenge
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
	id  string
	key []byte
}

func (keys *memoryKeys) ActiveKey() agentgate.ActiveKeyResult {
	return agentgate.ActiveKeyResult{Status: agentgate.KeyStatusOK, KeyID: keys.id, Key: bytes.Clone(keys.key)}
}
func (keys *memoryKeys) KeyByID(id string) agentgate.KeyResult {
	if id != keys.id {
		return agentgate.KeyResult{Status: agentgate.KeyStatusNotFound}
	}
	return agentgate.KeyResult{Status: agentgate.KeyStatusOK, Key: bytes.Clone(keys.key)}
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
	binding := []byte("complete-example-binding")
	lifecycle := &memoryLifecycle{challenges: make(map[string]*storedChallenge)}
	keys := &memoryKeys{id: "example-2026-09", key: bytes.Repeat([]byte{0x41}, 32)}
	service, err := agentgate.NewService(lifecycle, keys, discardObserver{}, library)
	if err != nil {
		return err
	}
	defer service.Close()

	request, err := agentgate.NewV1IssueRequest(binding)
	if err != nil {
		return err
	}
	challenge, err := service.Issue(request)
	if err != nil {
		return err
	}
	fmt.Println("issue: ok")

	outcome, err := service.Verify(agentgate.Submission{ChallengeID: challenge.ChallengeID, Nonce: challenge.Nonce, Answer: answer}, binding)
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
