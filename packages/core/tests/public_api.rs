#[test]
fn reexports_contracts_crate() {
    assert_eq!(agentgate_core::contracts::GENERATOR_VERSION_V1, "1.0");
}
