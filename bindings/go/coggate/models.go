package coggate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"unicode/utf8"
)

const maxBindingBytes = 256

var (
	errInvalidJSON         = errors.New("invalid CogGate JSON")
	errInvalidIssueRequest = errors.New("invalid CogGate issue request")
)

// AttemptLimit is the closed V1 verification-attempt budget.
type AttemptLimit uint32

const (
	AttemptLimitOne AttemptLimit = 1
	AttemptLimitTwo AttemptLimit = 2
)

func (limit AttemptLimit) valid() bool {
	return limit == AttemptLimitOne || limit == AttemptLimitTwo
}

// IssueRequest contains the non-JSON parameters used to issue a challenge.
type IssueRequest struct {
	version      string
	binding      []byte
	attemptLimit AttemptLimit
}

// NewIssueRequest validates and copies an issue request.
func NewIssueRequest(version string, binding []byte, attemptLimit AttemptLimit) (IssueRequest, error) {
	if !utf8.ValidString(version) || len(binding) == 0 || len(binding) > maxBindingBytes || !attemptLimit.valid() {
		return IssueRequest{}, errInvalidIssueRequest
	}
	return IssueRequest{
		version:      version,
		binding:      bytes.Clone(binding),
		attemptLimit: attemptLimit,
	}, nil
}

// NewV1IssueRequest creates a version 1.0 issue request with one attempt.
func NewV1IssueRequest(binding []byte) (IssueRequest, error) {
	return NewIssueRequest("1.0", binding, AttemptLimitOne)
}

// Version returns the requested generator version.
func (request IssueRequest) Version() string {
	return request.version
}

// AttemptLimit returns the requested lifecycle attempt budget.
func (request IssueRequest) AttemptLimit() AttemptLimit {
	return request.attemptLimit
}

func (IssueRequest) String() string {
	return "IssueRequest()"
}

func (IssueRequest) GoString() string {
	return "IssueRequest()"
}

func (IssueRequest) LogValue() slog.Value {
	return slog.StringValue("IssueRequest()")
}

// AnswerEncoding identifies the submission answer representation.
type AnswerEncoding string

const AnswerEncodingBase64URL AnswerEncoding = "base64url"

// PublicChallenge is the public portion of an issued challenge.
type PublicChallenge struct {
	ChallengeID      string         `json:"challenge_id"`
	GeneratorVersion string         `json:"generator_version"`
	Nonce            string         `json:"nonce"`
	IssuedAt         int64          `json:"issued_at"`
	ExpiresAt        int64          `json:"expires_at"`
	Question         string         `json:"question"`
	AnswerEncoding   AnswerEncoding `json:"answer_encoding"`
}

func (PublicChallenge) String() string {
	return "PublicChallenge()"
}

func (PublicChallenge) GoString() string {
	return "PublicChallenge()"
}

func (PublicChallenge) LogValue() slog.Value {
	return slog.StringValue("PublicChallenge()")
}

// Submission contains the public response to a challenge.
type Submission struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	Answer      string `json:"answer"`
}

func (Submission) String() string {
	return "Submission()"
}

func (Submission) GoString() string {
	return "Submission()"
}

func (Submission) LogValue() slog.Value {
	return slog.StringValue("Submission()")
}

// VerificationStatus is the stable outcome status.
type VerificationStatus string

const (
	VerificationStatusAccepted VerificationStatus = "accepted"
	VerificationStatusRejected VerificationStatus = "rejected"
)

// RejectionReason is a stable lifecycle rejection category.
type RejectionReason string

const (
	RejectionReasonNotFound          RejectionReason = "not_found"
	RejectionReasonExpired           RejectionReason = "expired"
	RejectionReasonAlreadyConsumed   RejectionReason = "already_consumed"
	RejectionReasonBindingMismatch   RejectionReason = "binding_mismatch"
	RejectionReasonNonceMismatch     RejectionReason = "nonce_mismatch"
	RejectionReasonAttemptsExhausted RejectionReason = "attempts_exhausted"
)

func (reason RejectionReason) valid() bool {
	switch reason {
	case RejectionReasonNotFound,
		RejectionReasonExpired,
		RejectionReasonAlreadyConsumed,
		RejectionReasonBindingMismatch,
		RejectionReasonNonceMismatch,
		RejectionReasonAttemptsExhausted:
		return true
	default:
		return false
	}
}

// VerificationOutcome is either accepted or rejected for one lifecycle reason.
type VerificationOutcome struct {
	Status VerificationStatus `json:"status"`
	Reason RejectionReason    `json:"reason,omitempty"`
}

func (outcome VerificationOutcome) valid() bool {
	return (outcome.Status == VerificationStatusAccepted && outcome.Reason == "") ||
		(outcome.Status == VerificationStatusRejected && outcome.Reason.valid())
}

func stringsValid(values ...string) bool {
	for _, value := range values {
		if !utf8.ValidString(value) {
			return false
		}
	}
	return true
}

func decodeSubmission(payload []byte) (Submission, error) {
	type wireSubmission struct {
		ChallengeID *string `json:"challenge_id"`
		Nonce       *string `json:"nonce"`
		Answer      *string `json:"answer"`
	}
	var wire wireSubmission
	if err := strictDecodeObject(payload, &wire, "challenge_id", "nonce", "answer"); err != nil || wire.ChallengeID == nil || wire.Nonce == nil || wire.Answer == nil {
		return Submission{}, errInvalidJSON
	}
	return Submission{ChallengeID: *wire.ChallengeID, Nonce: *wire.Nonce, Answer: *wire.Answer}, nil
}

func encodeSubmission(submission Submission) ([]byte, error) {
	if !stringsValid(submission.ChallengeID, submission.Nonce, submission.Answer) {
		return nil, errInvalidJSON
	}
	type wireSubmission Submission
	payload, err := json.Marshal(wireSubmission(submission))
	if err != nil {
		return nil, errInvalidJSON
	}
	return payload, nil
}

func (submission Submission) MarshalJSON() ([]byte, error) {
	return encodeSubmission(submission)
}

func (submission *Submission) UnmarshalJSON(payload []byte) error {
	decoded, err := decodeSubmission(payload)
	if err != nil {
		return err
	}
	*submission = decoded
	return nil
}

func decodePublicChallenge(payload []byte) (PublicChallenge, error) {
	type wireChallenge struct {
		ChallengeID      *string         `json:"challenge_id"`
		GeneratorVersion *string         `json:"generator_version"`
		Nonce            *string         `json:"nonce"`
		IssuedAt         *int64          `json:"issued_at"`
		ExpiresAt        *int64          `json:"expires_at"`
		Question         *string         `json:"question"`
		AnswerEncoding   *AnswerEncoding `json:"answer_encoding"`
	}
	var wire wireChallenge
	if err := strictDecodeObject(payload, &wire,
		"challenge_id", "generator_version", "nonce", "issued_at", "expires_at", "question", "answer_encoding"); err != nil ||
		wire.ChallengeID == nil || wire.GeneratorVersion == nil || wire.Nonce == nil ||
		wire.IssuedAt == nil || wire.ExpiresAt == nil || wire.Question == nil || wire.AnswerEncoding == nil ||
		*wire.AnswerEncoding != AnswerEncodingBase64URL {
		return PublicChallenge{}, errInvalidJSON
	}
	return PublicChallenge{
		ChallengeID:      *wire.ChallengeID,
		GeneratorVersion: *wire.GeneratorVersion,
		Nonce:            *wire.Nonce,
		IssuedAt:         *wire.IssuedAt,
		ExpiresAt:        *wire.ExpiresAt,
		Question:         *wire.Question,
		AnswerEncoding:   *wire.AnswerEncoding,
	}, nil
}

func encodePublicChallenge(challenge PublicChallenge) ([]byte, error) {
	if !stringsValid(challenge.ChallengeID, challenge.GeneratorVersion, challenge.Nonce, challenge.Question) ||
		challenge.AnswerEncoding != AnswerEncodingBase64URL {
		return nil, errInvalidJSON
	}
	type wireChallenge PublicChallenge
	payload, err := json.Marshal(wireChallenge(challenge))
	if err != nil {
		return nil, errInvalidJSON
	}
	return payload, nil
}

func (challenge PublicChallenge) MarshalJSON() ([]byte, error) {
	return encodePublicChallenge(challenge)
}

func (challenge *PublicChallenge) UnmarshalJSON(payload []byte) error {
	decoded, err := decodePublicChallenge(payload)
	if err != nil {
		return err
	}
	*challenge = decoded
	return nil
}

func decodeVerificationOutcome(payload []byte) (VerificationOutcome, error) {
	type wireOutcome struct {
		Status *VerificationStatus `json:"status"`
		Reason *RejectionReason    `json:"reason"`
	}
	var wire wireOutcome
	if err := strictDecodeObject(payload, &wire, "status", "reason"); err != nil || wire.Status == nil {
		return VerificationOutcome{}, errInvalidJSON
	}
	outcome := VerificationOutcome{Status: *wire.Status}
	if wire.Reason != nil {
		outcome.Reason = *wire.Reason
	}
	if !outcome.valid() || (outcome.Status == VerificationStatusAccepted && wire.Reason != nil) {
		return VerificationOutcome{}, errInvalidJSON
	}
	return outcome, nil
}

func encodeVerificationOutcome(outcome VerificationOutcome) ([]byte, error) {
	if !outcome.valid() {
		return nil, errInvalidJSON
	}
	type wireOutcome VerificationOutcome
	payload, err := json.Marshal(wireOutcome(outcome))
	if err != nil {
		return nil, errInvalidJSON
	}
	return payload, nil
}

func (outcome VerificationOutcome) MarshalJSON() ([]byte, error) {
	return encodeVerificationOutcome(outcome)
}

func (outcome *VerificationOutcome) UnmarshalJSON(payload []byte) error {
	decoded, err := decodeVerificationOutcome(payload)
	if err != nil {
		return err
	}
	*outcome = decoded
	return nil
}

func strictDecodeObject(payload []byte, target any, exactKeys ...string) error {
	if !utf8.Valid(payload) || !validJSONUnicodeEscapes(payload) || rejectDuplicateKeysAndExtraRoots(payload) != nil {
		return errInvalidJSON
	}
	if len(exactKeys) != 0 && !hasOnlyExactKeys(payload, exactKeys) {
		return errInvalidJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errInvalidJSON
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return errInvalidJSON
	}
	return nil
}

func hasOnlyExactKeys(payload []byte, exactKeys []string) bool {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil || object == nil {
		return false
	}
	allowed := make(map[string]struct{}, len(exactKeys))
	for _, key := range exactKeys {
		allowed[key] = struct{}{}
	}
	for key := range object {
		if _, ok := allowed[key]; !ok {
			return false
		}
	}
	return true
}

func validJSONUnicodeEscapes(payload []byte) bool {
	inString := false
	for index := 0; index < len(payload); index++ {
		switch payload[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(payload) {
				continue
			}
			if payload[index+1] != 'u' {
				index++
				continue
			}
			value, ok := decodeHexQuad(payload, index+2)
			if !ok {
				return false
			}
			if value >= 0xd800 && value <= 0xdbff {
				if index+11 >= len(payload) || payload[index+6] != '\\' || payload[index+7] != 'u' {
					return false
				}
				low, ok := decodeHexQuad(payload, index+8)
				if !ok || low < 0xdc00 || low > 0xdfff {
					return false
				}
				index += 11
				continue
			}
			if value >= 0xdc00 && value <= 0xdfff {
				return false
			}
			index += 5
		}
	}
	return true
}

func decodeHexQuad(payload []byte, start int) (uint16, bool) {
	if start+4 > len(payload) {
		return 0, false
	}
	var value uint16
	for _, digit := range payload[start : start+4] {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value |= uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value |= uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value |= uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func rejectDuplicateKeysAndExtraRoots(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errInvalidJSON
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return errInvalidJSON
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return errInvalidJSON
			}
			key, ok := keyToken.(string)
			if !ok {
				return errInvalidJSON
			}
			if _, exists := keys[key]; exists {
				return errInvalidJSON
			}
			keys[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errInvalidJSON
		}
		return nil
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errInvalidJSON
		}
		return nil
	default:
		return errInvalidJSON
	}
}
