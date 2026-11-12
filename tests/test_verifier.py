"""Uji murni verifier dan CLI offline `verify-file` (tanpa basis data)."""

import copy
import random
from pathlib import Path

import orjson
import pytest
from chainfactory import build_chain, to_lines

from astria_audit.__main__ import main
from astria_audit.chain.canonical import canonical, sha256_hex
from astria_audit.chain.hashing import GENESIS_PREV
from astria_audit.chain.verifier import ChainVerifier, verify_lines


def test_valid_chain_passes() -> None:
    result = verify_lines(to_lines(build_chain(25)))
    assert result.ok and result.checked == 25 and (result.from_seq, result.to_seq) == (1, 25)


def test_empty_file_is_ok_and_empty() -> None:
    result = verify_lines([])
    assert result.ok and result.checked == 0 and result.from_seq is None


def test_partial_export_trusts_first_prev_hash() -> None:
    tail = build_chain(10)[4:]
    result = verify_lines(to_lines(tail))
    assert result.ok and result.from_seq == 5 and result.checked == 6


def test_canonical_is_stable_for_key_order_and_unicode_form() -> None:
    a = canonical({"b": 1, "a": "é"})
    b = canonical({"a": "é", "b": 1})  # NFD menjadi NFC
    assert a == b
    assert sha256_hex(a) == sha256_hex(b)


def test_changing_any_single_field_is_detected() -> None:
    chain = build_chain(6)
    for field in ("occurred_at", "recorded_at", "actor", "actor_type", "action", "target_type", "target_id", "via"):
        tampered = copy.deepcopy(chain)
        tampered[2][field] = str(tampered[2][field]) + "x"
        result = verify_lines(to_lines(tampered))
        assert not result.ok, field
        assert result.first_bad_seq == 3, field
        assert result.reason == "entry_hash_tidak_cocok", field


def test_payload_change_is_payload_hash_mismatch() -> None:
    chain = build_chain(6)
    chain[3]["payload"]["n"] = 999
    result = verify_lines(to_lines(chain))
    assert (result.ok, result.first_bad_seq, result.reason) == (False, 4, "payload_hash_tidak_cocok")
    assert result.checked == 3


def test_non_canonical_payload_is_reported() -> None:
    chain = build_chain(3)
    chain[1]["payload"]["n"] = 1.5
    result = verify_lines(to_lines(chain))
    assert (result.first_bad_seq, result.reason) == (2, "payload_tidak_kanonik")


def test_deleted_line_is_a_gap() -> None:
    lines = to_lines(build_chain(6))
    del lines[2]
    result = verify_lines(lines)
    assert (result.ok, result.first_bad_seq, result.reason) == (False, 4, "nomor_urut_berlubang")


def test_swapped_lines_break_the_sequence() -> None:
    lines = to_lines(build_chain(6))
    lines[2], lines[3] = lines[3], lines[2]
    result = verify_lines(lines)
    assert (result.ok, result.first_bad_seq, result.reason) == (False, 4, "nomor_urut_berlubang")


def test_replaced_entry_breaks_prev_hash_of_next() -> None:
    chain = build_chain(5)
    forged = build_chain(1, start_seq=3, prev_hash=chain[1]["entry_hash"])[0]
    forged["payload"]["n"] = 1000  # entri 3 dipalsukan dengan hash sendiri yang konsisten
    forged["payload_hash"] = sha256_hex(canonical(forged["payload"]))
    from astria_audit.chain.hashing import entry_hash

    forged["entry_hash"] = entry_hash(forged)
    chain[2] = forged
    result = verify_lines(to_lines(chain))
    assert (result.first_bad_seq, result.reason) == (4, "prev_hash_tidak_cocok")


def test_first_entry_with_wrong_genesis_is_rejected() -> None:
    chain = build_chain(3, prev_hash="1" * 64)
    result = verify_lines(to_lines(chain))
    assert (result.first_bad_seq, result.reason) == (1, "prev_hash_tidak_cocok")


@pytest.mark.parametrize(
    "line",
    [b"bukan json\n", b"[1,2]\n", b'{"seq": 1}\n', b'{"seq": "1"}\n'],
    ids=["bukan-json", "bukan-objek", "field-hilang", "seq-bukan-angka"],
)
def test_malformed_lines_are_reported(line: bytes) -> None:
    result = verify_lines([line])
    assert not result.ok and result.reason == "baris_tidak_valid" and result.detail.startswith("baris 1")


def test_random_single_mutation_is_always_detected() -> None:
    rng = random.Random(20261112)  # noqa: S311 - acak untuk uji, bukan kripto
    base = build_chain(12)
    for _ in range(200):
        chain = copy.deepcopy(base)
        i = rng.randrange(len(chain))
        kind = rng.choice(["payload", "hash", "prev", "action"])
        if kind == "payload":
            chain[i]["payload"]["n"] = rng.randrange(10_000, 20_000)
        elif kind == "hash":
            chain[i]["entry_hash"] = f"{rng.getrandbits(256):064x}"
        elif kind == "prev":
            chain[i]["prev_hash"] = f"{rng.getrandbits(256):064x}"
        else:
            chain[i]["action"] = "x." + str(rng.randrange(1000))
        result = verify_lines(to_lines(chain))
        assert not result.ok, (i, kind)
        assert result.first_bad_seq is not None and result.first_bad_seq <= i + 2


def test_verifier_state_does_not_advance_on_failure() -> None:
    chain = build_chain(3)
    verifier = ChainVerifier()
    assert verifier.check(chain[0]) is None
    bad = dict(chain[1], payload_hash="0" * 64)
    assert verifier.check(bad) == "payload_hash_tidak_cocok"
    assert (verifier.checked, verifier.last_seq, verifier.expected_seq) == (1, 1, 2)
    assert verifier.prev_hash != GENESIS_PREV


# --- CLI offline ---


def write_file(path: Path, lines: list[bytes]) -> Path:
    path.write_bytes(b"".join(lines))
    return path


def test_cli_verify_file_ok_without_any_astria_settings(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # conftest menghapus ASTRIA_*; Settings() akan gagal, jadi lolosnya perintah ini membuktikan tidak dimuat.
    path = write_file(tmp_path / "ok.jsonl", to_lines(build_chain(8)))
    assert main(["verify-file", str(path)]) == 0
    assert "UTUH: 8 entri" in capsys.readouterr().out


def test_cli_verify_file_tamper_byte_in_payload(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    lines = to_lines(build_chain(5))
    raw = lines[2]
    idx = raw.index(b'"n":3')
    lines[2] = raw[: idx + 4] + b"9" + raw[idx + 5 :]  # satu byte: "n":3 menjadi "n":9
    path = write_file(tmp_path / "bad.jsonl", lines)
    assert main(["verify-file", str(path)]) == 1
    out = capsys.readouterr().out
    assert "payload_hash_tidak_cocok" in out and "seq 3" in out


def test_cli_verify_file_deleted_line(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    lines = to_lines(build_chain(5))
    del lines[1]
    assert main(["verify-file", str(write_file(tmp_path / "gap.jsonl", lines))]) == 1
    out = capsys.readouterr().out
    assert "nomor_urut_berlubang" in out and "seq 3" in out


def test_cli_verify_file_swapped_lines(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    lines = to_lines(build_chain(5))
    lines[3], lines[4] = lines[4], lines[3]
    assert main(["verify-file", str(write_file(tmp_path / "swap.jsonl", lines))]) == 1
    assert "nomor_urut_berlubang" in capsys.readouterr().out


def test_cli_verify_file_missing_file_is_exit_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["verify-file", str(tmp_path / "tidak-ada.jsonl")]) == 2
    assert "tidak terbaca" in capsys.readouterr().err


def test_export_line_format_is_sorted_keys_json() -> None:
    line = to_lines(build_chain(1))[0]
    parsed = orjson.loads(line)
    assert list(parsed) == sorted(parsed)
    assert "request_hash" not in parsed
