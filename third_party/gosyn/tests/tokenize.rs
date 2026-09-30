use gosyn::{tokenize_source, LexicalToken};

fn token_text(source: &str, token: &LexicalToken) -> String {
    source
        .chars()
        .skip(token.start)
        .take(token.end - token.start)
        .collect()
}

#[test]
fn returns_scalar_ranges_and_filters_scanner_inserted_semicolons() {
    let source = "package café;\nvalue := 1";
    let tokens = tokenize_source(source).unwrap();
    let text = tokens
        .iter()
        .map(|token| token_text(source, token))
        .collect::<Vec<_>>();

    assert_eq!(text, ["package", "café", ";", "value", ":=", "1"]);
    assert_eq!((tokens[1].start, tokens[1].end), (8, 12));
}
