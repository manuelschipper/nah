// The blessed messages carry the paths `.cargo/rustc-wrapper.sh` remaps, and
// Windows builds cannot run that wrapper. The boundary under test is the same
// type check on every platform, so Unix runs cover it.
#[cfg(unix)]
#[test]
fn validated_response_cannot_cross_the_raw_or_persistence_boundaries() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/validated_response_*.rs");
}
