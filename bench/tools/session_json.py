"""Own the canonical session JSON bytes shared by session normalization and call export."""

import json


def canonical_session_json(value):
    """Serialize with sorted keys, compact separators and raw Unicode.

    Session, case and call identity digests, deduplication and emitted cache files depend on these exact bytes.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
