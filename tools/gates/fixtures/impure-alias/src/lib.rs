#![forbid(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

extern crate std as platform;

static START: platform::sync::Once = platform::sync::Once::new();

pub fn unix_socket() {
    let _ = platform::os::unix::net::UnixStream::connect("/tmp/nah-seeded");
}

pub fn global_state() {
    START.call_once(|| {});
}

pub fn thread_spawn() {
    let _ = platform::thread::Builder::new().spawn(|| {});
}
