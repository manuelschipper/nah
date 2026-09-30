use criterion::{criterion_group, criterion_main, Criterion};

fn next_nchar0(source: &str, n: usize) -> String {
    let source = &source[4..];
    source.chars().take(n).collect()
}

fn next_nchar1(chars_indices: &[(usize, char)], n: usize) -> String {
    chars_indices[1..]
        .iter()
        .map(|(_, ch)| ch)
        .take(n)
        .collect::<String>()
}

pub fn bench_scan_nchars(c: &mut Criterion) {
    let source = String::from("😄😄😄😄");
    let chars = source.char_indices().collect::<Vec<_>>();

    let mut group = c.benchmark_group("next_nchar");
    group.bench_function("next_nchar0", |b| {
        b.iter(|| next_nchar0(&source, 2));
    });

    group.bench_function("next_nchar1", |b| {
        b.iter(|| next_nchar1(&chars, 2));
    });

    group.finish();
}

criterion_group!(benches, bench_scan_nchars);
criterion_main!(benches);
