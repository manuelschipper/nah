use gosyn::parse_source;

static BINCODE_001: &[u8] = &[
    12, 12, 112, 97, 99, 107, 97, 103, 101, 12, 102, 12, 12, 12, 12, 12, 116, 121, 112, 101, 12,
    12, 97, 103, 101, 12, 102, 12, 12, 12, 12, 12, 116, 121, 112, 101, 12, 12, 12, 12, 108, 91, 47,
    47, 47, 91, 0, 0, 12, 54, 54, 12, 12, 12, 12, 12, 54, 54, 12, 12, 63, 12, 12, 12, 34,
];

#[test]
fn parse_fuzz_input() {
    let _ = parse_source(include_str!("testdata/fuzz001.go.txt"));
    let _ = parse_source(std::str::from_utf8(BINCODE_001).unwrap());
}
