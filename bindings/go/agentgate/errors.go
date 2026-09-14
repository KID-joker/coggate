package agentgate

// AgentGateError is a stable, detail-free native status error.
type AgentGateError struct {
	code string
}

// Error returns only the stable error code.
func (err *AgentGateError) Error() string {
	return err.code
}

// Code returns the stable error code.
func (err *AgentGateError) Code() string {
	return err.code
}

func errorForStatus(status int32) error {
	if status == 0 {
		return nil
	}
	var code string
	switch status {
	case 1:
		code = "invalid_configuration"
	case 2:
		code = "generation_failed"
	case 3:
		code = "invalid_challenge_material"
	case 4:
		code = "invalid_answer_encoding"
	case 5:
		code = "answer_mismatch"
	case 6:
		code = "unsupported_generator_version"
	case 7:
		code = "internal_error"
	case 100:
		code = "invalid_argument"
	case 101:
		code = "callback_failed"
	case 102:
		code = "panic_caught"
	default:
		code = "internal_error"
	}
	return &AgentGateError{code: code}
}
