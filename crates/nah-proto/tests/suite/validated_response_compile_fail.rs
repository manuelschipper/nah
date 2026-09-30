#[test]
fn validated_response_cannot_cross_the_raw_or_persistence_boundaries() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/validated_response_*.rs");
}
