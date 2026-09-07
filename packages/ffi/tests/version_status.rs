use agentgate_ffi::{AG_ABI_VERSION_1, AgStatus, ag_abi_version};

#[test]
fn freezes_abi_version_and_status_values() {
    assert_eq!(AG_ABI_VERSION_1, 1);
    assert_eq!(ag_abi_version(), 1);
    assert_eq!(AgStatus::Ok as i32, 0);
    assert_eq!(AgStatus::InvalidConfiguration as i32, 1);
    assert_eq!(AgStatus::GenerationFailed as i32, 2);
    assert_eq!(AgStatus::InvalidChallengeMaterial as i32, 3);
    assert_eq!(AgStatus::InvalidAnswerEncoding as i32, 4);
    assert_eq!(AgStatus::AnswerMismatch as i32, 5);
    assert_eq!(AgStatus::UnsupportedGeneratorVersion as i32, 6);
    assert_eq!(AgStatus::InternalError as i32, 7);
    assert_eq!(AgStatus::InvalidArgument as i32, 100);
    assert_eq!(AgStatus::CallbackFailed as i32, 101);
    assert_eq!(AgStatus::PanicCaught as i32, 102);
}
