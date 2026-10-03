//! Property/fuzz test for reverse-query selector parsing. A fixed-seed LCG
//! feeds thousands of adversarial strings to `ResourceSelector::parse`, which must
//! never panic (only ever Ok or Err) and must be deterministic.

use effinterp_repo::ResourceSelector;

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed ^ 0x9e3779b97f4a7c15)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545f4914f6cdd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

const PARTS: &[&str] = &[
    "fs",
    "db",
    "env",
    "git",
    "net",
    "container",
    "cloud",
    "obj",
    "host",
    "any-realm",
    "pod",
    "container:pg",
    ":",
    "/",
    "fs:",
    "env:HOME",
    "git:worktree=\"/repo\";git_dir=null;pathspec=\"src/*\"",
    "/etc/passwd",
    "public.users",
    "s3://b/k",
    "",
    "*",
    "..",
    "\0",
    "🔥",
    "\\",
    "://",
    "host/",
    "pod:ns/p/",
    "fs:/*",
    "-",
    "  ",
    "\n",
];

fn gen_selector(rng: &mut Rng) -> String {
    match rng.below(8) {
        0 => String::new(),
        1 => ":".repeat(1 + rng.below(50)),
        2 => "/".repeat(1 + rng.below(50)),
        3 => {
            // random Unicode soup
            let n = rng.below(40);
            (0..n)
                .map(|_| char::from_u32(rng.below(0x110000) as u32).unwrap_or('?'))
                .collect()
        }
        _ => {
            let n = rng.below(12);
            (0..n).map(|_| PARTS[rng.below(PARTS.len())]).collect()
        }
    }
}

#[test]
fn selector_parse_never_panics_and_is_deterministic() {
    let mut rng = Rng::new(0x5E1EC709);
    for i in 0..20_000u64 {
        let input = gen_selector(&mut rng);
        let a = std::panic::catch_unwind(|| ResourceSelector::parse(&input));
        let a = match a {
            Ok(r) => r,
            Err(_) => panic!("PANIC parsing selector {input:?} at iteration {i}"),
        };
        // Deterministic: parsing the same string twice agrees.
        let b = ResourceSelector::parse(&input);
        assert_eq!(a.is_ok(), b.is_ok(), "nondeterministic parse of {input:?}");
    }
}
