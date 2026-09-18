#[test]
fn reexports_contracts_crate() {
    assert_eq!(coggate_core::contracts::GENERATOR_VERSION_V1, "1.0");
}
