from datetime import UTC, datetime

import pytest
from astria_common.errors import AstriaError

from astria_audit.chain import GENESIS_PREV, NotCanonical, canonical, entry_hash, sha256_hex


def test_canonical_is_sorted_compact_and_nfc() -> None:
    assert canonical({"b": 1, "a": "é"}) == '{"a":"é","b":1}'.encode()


@pytest.mark.parametrize(
    "payload",
    [{"x": 1.5}, {"x": "a\x00b"}, {"password": "x"}, {"nested": {"api_key": "k"}}, {"x": object()}],
)
def test_rejects_non_canonical_payload(payload: dict) -> None:
    with pytest.raises(NotCanonical):
        canonical(payload)


def test_not_canonical_is_422() -> None:
    assert issubclass(NotCanonical, AstriaError)
    assert NotCanonical("x").status == 422


def test_entry_hash_changes_with_any_field() -> None:
    entry = {
        "seq": 1,
        "occurred_at": datetime(2026, 11, 10, tzinfo=UTC).isoformat(),
        "recorded_at": datetime(2026, 11, 10, tzinfo=UTC).isoformat(),
        "actor": "svc:ingest",
        "actor_type": "service",
        "action": "ingest.sample.emitted",
        "target_type": "job",
        "target_id": "ING-1",
        "via": "system",
        "idempotency_key": "k1",
        "payload_hash": sha256_hex(canonical({})),
        "prev_hash": GENESIS_PREV,
    }
    base = entry_hash(entry)
    assert len(base) == 64
    for key in entry:
        changed = dict(entry)
        changed[key] = 2 if key == "seq" else str(entry[key]) + "x"
        assert entry_hash(changed) != base, key
