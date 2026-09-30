use criterion::{criterion_group, criterion_main, Criterion};

use gosyn::parse_source;

pub fn parse_unicode_literal(c: &mut Criterion) {
    let source =
        include_str!("/usr/local/go/src/vendor/golang.org/x/text/unicode/norm/tables13.0.0.go");

    c.bench_function("parse_unicode_literal", |b| {
        b.iter(|| parse_source(source).unwrap());
    });
}

criterion_group!(benches, parse_unicode_literal);
criterion_main!(benches);
