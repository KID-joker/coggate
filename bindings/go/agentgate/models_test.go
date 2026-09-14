package agentgate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math"
	"strings"
	"testing"
)

func TestIssueRequestValidation(t *testing.T) {
	request, err := NewV1IssueRequest([]byte{0x00, 0xff})
	if err != nil {
		t.Fatalf("NewV1IssueRequest: %v", err)
	}
	if request.Version() != "1.0" || request.AttemptLimit() != AttemptLimitOne {
		t.Fatalf("unexpected request: version=%q limit=%d", request.Version(), request.AttemptLimit())
	}

	invalid := []struct {
		name    string
		version string
		binding []byte
		limit   AttemptLimit
	}{
		{"empty binding", "1.0", nil, AttemptLimitOne},
		{"long binding", "1.0", make([]byte, 257), AttemptLimitOne},
		{"invalid limit", "1.0", []byte("binding"), AttemptLimit(3)},
		{"invalid version UTF-8", string([]byte{0xff}), []byte("binding"), AttemptLimitOne},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewIssueRequest(test.version, test.binding, test.limit); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestV1IssueRequestDefaultsToOneAttempt(t *testing.T) {
	var constructor func([]byte) (IssueRequest, error) = NewV1IssueRequest
	request, err := constructor([]byte("binding"))
	if err != nil || request.AttemptLimit() != AttemptLimitOne {
		t.Fatalf("unexpected V1 default: %#v, %v", request, err)
	}
}

func TestIssueRequestCopiesBinding(t *testing.T) {
	binding := []byte("binding")
	request, err := NewIssueRequest("1.0", binding, AttemptLimitTwo)
	if err != nil {
		t.Fatalf("NewIssueRequest: %v", err)
	}
	binding[0] = 'X'
	if string(request.binding) != "binding" {
		t.Fatalf("stored binding changed with caller input: %q", request.binding)
	}
}

func TestSecretBearingModelsUseSafeFormattingAndLogging(t *testing.T) {
	issue, err := NewIssueRequest("VERSION_SENTINEL", []byte("BINDING_SENTINEL"), AttemptLimitTwo)
	if err != nil {
		t.Fatalf("NewIssueRequest: %v", err)
	}
	models := []struct {
		name      string
		value     any
		forbidden []string
	}{
		{
			name:  "issue request",
			value: issue,
			forbidden: []string{
				"VERSION_SENTINEL", "BINDING_SENTINEL", fmt.Sprint([]byte("BINDING_SENTINEL")),
			},
		},
		{
			name: "submission",
			value: Submission{
				ChallengeID: "CHALLENGE_SENTINEL", Nonce: "NONCE_SENTINEL", Answer: "ANSWER_SENTINEL",
			},
			forbidden: []string{"NONCE_SENTINEL", "ANSWER_SENTINEL"},
		},
		{
			name: "public challenge",
			value: PublicChallenge{
				ChallengeID: "CHALLENGE_SENTINEL", GeneratorVersion: "1.0", Nonce: "NONCE_SENTINEL",
				IssuedAt: 1, ExpiresAt: 2, Question: "QUESTION_SENTINEL", AnswerEncoding: AnswerEncodingBase64URL,
			},
			forbidden: []string{"NONCE_SENTINEL", "QUESTION_SENTINEL"},
		},
	}

	for _, model := range models {
		t.Run(model.name, func(t *testing.T) {
			outputs := []string{
				fmt.Sprintf("%v", model.value),
				fmt.Sprintf("%+v", model.value),
				fmt.Sprintf("%#v", model.value),
			}

			var standardLog bytes.Buffer
			log.New(&standardLog, "", 0).Print(model.value)
			outputs = append(outputs, standardLog.String())

			var structuredLog bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&structuredLog, nil))
			logger.Info("model", "value", model.value)
			outputs = append(outputs, structuredLog.String())

			for _, output := range outputs {
				for _, sentinel := range model.forbidden {
					if strings.Contains(output, sentinel) {
						t.Errorf("format leaked %q in %q", sentinel, output)
					}
				}
			}
		})
	}
}

func TestSubmissionStrictJSONAndUnicodeRoundTrip(t *testing.T) {
	payload := []byte(`{"challenge_id":"挑战-1","nonce":"bm9uY2U","answer":"YQ"}`)
	got, err := decodeSubmission(payload)
	if err != nil {
		t.Fatalf("decodeSubmission: %v", err)
	}
	if got.ChallengeID != "挑战-1" || got.Nonce != "bm9uY2U" || got.Answer != "YQ" {
		t.Fatalf("unexpected submission: %#v", got)
	}
	encoded, err := encodeSubmission(got)
	if err != nil {
		t.Fatalf("encodeSubmission: %v", err)
	}
	if string(encoded) != string(payload) {
		t.Fatalf("round trip mismatch: %s", encoded)
	}
}

func TestPublicChallengeStrictJSONAndIntegerBounds(t *testing.T) {
	payload := []byte(`{"challenge_id":"id","generator_version":"1.0","nonce":"nonce","issued_at":-9223372036854775808,"expires_at":9223372036854775807,"question":"2 加 2？","answer_encoding":"base64url"}`)
	got, err := decodePublicChallenge(payload)
	if err != nil {
		t.Fatalf("decodePublicChallenge: %v", err)
	}
	if got.IssuedAt != math.MinInt64 || got.ExpiresAt != math.MaxInt64 || got.AnswerEncoding != AnswerEncodingBase64URL {
		t.Fatalf("unexpected challenge: %#v", got)
	}
	encoded, err := encodePublicChallenge(got)
	if err != nil {
		t.Fatalf("encodePublicChallenge: %v", err)
	}
	if string(encoded) != string(payload) {
		t.Fatalf("round trip mismatch: %s", encoded)
	}
}

func TestVerificationOutcomeAcceptedAndRejected(t *testing.T) {
	accepted, err := decodeVerificationOutcome([]byte(`{"status":"accepted"}`))
	if err != nil || accepted.Status != VerificationStatusAccepted || accepted.Reason != "" {
		t.Fatalf("accepted outcome: %#v, %v", accepted, err)
	}

	reasons := []RejectionReason{
		RejectionReasonNotFound,
		RejectionReasonExpired,
		RejectionReasonAlreadyConsumed,
		RejectionReasonBindingMismatch,
		RejectionReasonNonceMismatch,
		RejectionReasonAttemptsExhausted,
	}
	for _, reason := range reasons {
		t.Run(string(reason), func(t *testing.T) {
			payload := []byte(`{"status":"rejected","reason":"` + string(reason) + `"}`)
			outcome, err := decodeVerificationOutcome(payload)
			if err != nil || outcome.Status != VerificationStatusRejected || outcome.Reason != reason {
				t.Fatalf("rejected outcome: %#v, %v", outcome, err)
			}
			encoded, err := encodeVerificationOutcome(outcome)
			if err != nil || string(encoded) != string(payload) {
				t.Fatalf("encode: %s, %v", encoded, err)
			}
		})
	}
}

func TestStrictDecodersRejectMalformedJSON(t *testing.T) {
	validSubmission := `{"challenge_id":"id","nonce":"nonce","answer":"YQ"}`
	cases := map[string]string{
		"unknown field":    `{"challenge_id":"id","nonce":"nonce","answer":"YQ","extra":1}`,
		"wrong case":       `{"Challenge_ID":"id","nonce":"nonce","answer":"YQ"}`,
		"alias collision":  `{"challenge_id":"id","Challenge_ID":"replacement","nonce":"nonce","answer":"YQ"}`,
		"duplicate field":  `{"challenge_id":"id","nonce":"nonce","answer":"YQ","answer":"Yg"}`,
		"trailing value":   validSubmission + ` {}`,
		"missing field":    `{"challenge_id":"id","nonce":"nonce"}`,
		"wrong field type": `{"challenge_id":"id","nonce":3,"answer":"YQ"}`,
		"not an object":    `[]`,
		"invalid UTF-8":    "{\"challenge_id\":\"\xff\",\"nonce\":\"nonce\",\"answer\":\"YQ\"}",
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeSubmission([]byte(payload)); !errors.Is(err, errInvalidJSON) {
				t.Fatalf("expected stable invalid JSON error, got %v", err)
			}
		})
	}
}

func TestStrictDecodersRejectWrongCaseKeys(t *testing.T) {
	challenge := []byte(`{"challenge_id":"id","generator_version":"1.0","nonce":"nonce","issued_at":1,"expires_at":2,"question":"q","Answer_Encoding":"base64url"}`)
	if _, err := decodePublicChallenge(challenge); !errors.Is(err, errInvalidJSON) {
		t.Fatalf("accepted wrong-case challenge key: %v", err)
	}

	outcome := []byte(`{"STATUS":"accepted"}`)
	if _, err := decodeVerificationOutcome(outcome); !errors.Is(err, errInvalidJSON) {
		t.Fatalf("accepted wrong-case outcome key: %v", err)
	}
}

func TestStrictDecoderRejectsUnpairedUnicodeSurrogates(t *testing.T) {
	for _, escaped := range []string{`\ud800`, `\udbff`, `\udc00`, `\udfff`} {
		payload := []byte(`{"challenge_id":"` + escaped + `","nonce":"nonce","answer":"YQ"}`)
		if _, err := decodeSubmission(payload); !errors.Is(err, errInvalidJSON) {
			t.Errorf("accepted unpaired surrogate %s: %v", escaped, err)
		}
	}
	got, err := decodeSubmission([]byte(`{"challenge_id":"\ud83d\ude00","nonce":"nonce","answer":"YQ"}`))
	if err != nil || got.ChallengeID != "😀" {
		t.Fatalf("valid surrogate pair was not preserved: %#v, %v", got, err)
	}
}

func TestStrictDecoderHandlesEscapedBackslashesBeforeSurrogates(t *testing.T) {
	got, err := decodeSubmission([]byte(`{"challenge_id":"\\ud800","nonce":"nonce","answer":"YQ"}`))
	if err != nil || got.ChallengeID != `\ud800` {
		t.Fatalf("escaped backslash was treated as a surrogate: %#v, %v", got, err)
	}
}

func TestDuplicateKeyPreScanUsesDecodedKeysAndTraversesArrays(t *testing.T) {
	var escaped struct {
		Answer string `json:"answer"`
	}
	if err := strictDecodeObject([]byte(`{"answer":"YQ","\u0061nswer":"Yg"}`), &escaped); !errors.Is(err, errInvalidJSON) {
		t.Fatalf("expected semantic duplicate rejection, got %v", err)
	}

	var nested struct {
		Items []map[string]any `json:"items"`
	}
	if err := strictDecodeObject([]byte(`{"items":[{"key":1,"key":2}]}`), &nested); !errors.Is(err, errInvalidJSON) {
		t.Fatalf("expected duplicate rejection inside array, got %v", err)
	}
}

func TestDuplicateKeyPreScanRejectsNestedObjects(t *testing.T) {
	var target struct {
		Nested map[string]any `json:"nested"`
	}
	if err := strictDecodeObject([]byte(`{"nested":{"key":1,"key":2}}`), &target); !errors.Is(err, errInvalidJSON) {
		t.Fatalf("expected nested duplicate rejection, got %v", err)
	}
}

func TestPublicChallengeRejectsInvalidFields(t *testing.T) {
	base := `{"challenge_id":"id","generator_version":"1.0","nonce":"nonce","issued_at":1,"expires_at":2,"question":"q","answer_encoding":"base64url"}`
	cases := map[string]string{
		"missing time":       strings.Replace(base, `"issued_at":1,`, "", 1),
		"null time":          strings.Replace(base, `"issued_at":1`, `"issued_at":null`, 1),
		"fractional time":    strings.Replace(base, `"issued_at":1`, `"issued_at":1.5`, 1),
		"time overflow":      strings.Replace(base, `"issued_at":1`, `"issued_at":9223372036854775808`, 1),
		"unknown encoding":   strings.Replace(base, `"base64url"`, `"BASE64URL"`, 1),
		"encoding is null":   strings.Replace(base, `"base64url"`, `null`, 1),
		"duplicate encoding": strings.Replace(base, `"answer_encoding":"base64url"`, `"answer_encoding":"base64url","answer_encoding":"base64url"`, 1),
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodePublicChallenge([]byte(payload)); !errors.Is(err, errInvalidJSON) {
				t.Fatalf("expected invalid JSON error, got %v", err)
			}
		})
	}
}

func TestVerificationOutcomeRejectsInvalidCombinations(t *testing.T) {
	cases := []string{
		`{"status":"accepted","reason":"expired"}`,
		`{"status":"rejected"}`,
		`{"status":"rejected","reason":null}`,
		`{"status":"unknown"}`,
		`{"status":"rejected","reason":"unknown"}`,
		`{"status":"rejected","reason":"expired","extra":true}`,
	}
	for _, payload := range cases {
		if _, err := decodeVerificationOutcome([]byte(payload)); !errors.Is(err, errInvalidJSON) {
			t.Errorf("%s: expected invalid JSON error, got %v", payload, err)
		}
	}

	invalidModels := []VerificationOutcome{
		{Status: VerificationStatusAccepted, Reason: RejectionReasonExpired},
		{Status: VerificationStatusRejected},
		{Status: VerificationStatus("unknown")},
		{Status: VerificationStatusRejected, Reason: RejectionReason("unknown")},
	}
	for _, outcome := range invalidModels {
		if _, err := encodeVerificationOutcome(outcome); !errors.Is(err, errInvalidJSON) {
			t.Errorf("%#v: expected invalid JSON error, got %v", outcome, err)
		}
	}
}

func TestEncodeRejectsInvalidStringsAndEnums(t *testing.T) {
	bad := string([]byte{0xff})
	if _, err := encodeSubmission(Submission{ChallengeID: bad, Nonce: "nonce", Answer: "YQ"}); !errors.Is(err, errInvalidJSON) {
		t.Fatalf("submission invalid UTF-8: %v", err)
	}
	challenge := PublicChallenge{
		ChallengeID: "id", GeneratorVersion: "1.0", Nonce: "nonce",
		IssuedAt: 1, ExpiresAt: 2, Question: "q", AnswerEncoding: AnswerEncoding("unknown"),
	}
	if _, err := encodePublicChallenge(challenge); !errors.Is(err, errInvalidJSON) {
		t.Fatalf("challenge invalid enum: %v", err)
	}
}

func TestJSONMethodsUseStrictCodec(t *testing.T) {
	var submission Submission
	if err := json.Unmarshal([]byte(`{"challenge_id":"id","nonce":"nonce","answer":"YQ","extra":true}`), &submission); !errors.Is(err, errInvalidJSON) {
		t.Fatalf("UnmarshalJSON was not strict: %v", err)
	}
	payload, err := json.Marshal(Submission{ChallengeID: "挑战", Nonce: "n", Answer: "a"})
	if err != nil || string(payload) != `{"challenge_id":"挑战","nonce":"n","answer":"a"}` {
		t.Fatalf("MarshalJSON mismatch: %s, %v", payload, err)
	}
}

func TestAgentGateErrorMapsStableCodesAndFailsClosed(t *testing.T) {
	cases := map[int32]string{
		1: "invalid_configuration", 2: "generation_failed", 3: "invalid_challenge_material",
		4: "invalid_answer_encoding", 5: "answer_mismatch", 6: "unsupported_generator_version",
		7: "internal_error", 100: "invalid_argument", 101: "callback_failed", 102: "panic_caught",
	}
	if err := errorForStatus(0); err != nil {
		t.Fatalf("OK returned error: %v", err)
	}
	for status, code := range cases {
		err := errorForStatus(status)
		var agentGateErr *AgentGateError
		if !errors.As(err, &agentGateErr) {
			t.Fatalf("status %d: wrong error type %T", status, err)
		}
		if agentGateErr.Code() != code || agentGateErr.Error() != code {
			t.Fatalf("status %d: got code=%q error=%q", status, agentGateErr.Code(), agentGateErr.Error())
		}
	}
	for _, status := range []int32{-1, 8, 99, 103, math.MaxInt32} {
		err := errorForStatus(status)
		var agentGateErr *AgentGateError
		if !errors.As(err, &agentGateErr) || agentGateErr.Code() != "internal_error" || agentGateErr.Error() != "internal_error" {
			t.Fatalf("unknown status %d did not fail closed: %v", status, err)
		}
	}
}
