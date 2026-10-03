#![allow(clippy::disallowed_methods)]

use effinterp_testkit::repo_fixture::repo_test_fixture;
use std::path::Path;

use crate::support::deletes_important;

#[test]
fn uncalled_import_not_attributed_but_called_is() {
    // never_called()'s cross-file delete must NOT reach the surface.
    let uncalled = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "er-uncalled",
        &[
            (
                "app.py",
                "from util import wipe\n\ndef never_called():\n    wipe(\"/important\")\n\nif __name__ == \"__main__\":\n    print(\"safe\")\n",
            ),
            ("util.py", "import os\n\ndef wipe(p):\n    os.remove(p)\n"),
        ],
    );
    assert!(
        !deletes_important(&uncalled),
        "uncalled function's delete must not be attributed"
    );

    // A function transitively reached from execution DOES contribute.
    let called = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "er-called",
        &[
            (
                "app.py",
                "from util import wipe\n\ndef used():\n    wipe(\"/important\")\n\nif __name__ == \"__main__\":\n    used()\n",
            ),
            ("util.py", "import os\n\ndef wipe(p):\n    os.remove(p)\n"),
        ],
    );
    assert!(
        deletes_important(&called),
        "a reachable function's cross-file delete must be attributed"
    );
}
