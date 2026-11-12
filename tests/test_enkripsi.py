"""Enkripsi age untuk ekspor audit: aturan penerima, CLI (`export`, `verify-file --identity`), dan `/export`.

Uji yang memakai basis data butuh ASTRIA_TEST_DATABASE_URL (bila kosong di-skip), sama seperti uji lain.
"""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import orjson
import pyrage
import pytest
from astria_common.errors import AstriaError
from chainfactory import build_chain, to_lines
from conftest import PG_URL
from fastapi.testclient import TestClient
from pydantic import SecretStr
from test_api import FakeVerifier, auth, write

from astria_audit import __main__ as cli
from astria_audit import enkripsi
from astria_audit.chain.verifier import verify_lines
from astria_audit.main import build_app
from astria_audit.settings import Settings


@pytest.fixture
def kunci(tmp_path: Path) -> tuple[pyrage.x25519.Identity, str, Path]:
    """Identity uji: (identity, kunci publik `age1...`, berkas gaya age-keygen)."""
    ident = pyrage.x25519.Identity.generate()
    berkas = tmp_path / "kunci.txt"
    berkas.write_text(f"# created: uji\n# public key: {ident.to_public()}\n{ident}\n", encoding="utf-8")
    return ident, str(ident.to_public()), berkas


def _kunci_lain(tmp_path: Path) -> Path:
    lain = pyrage.x25519.Identity.generate()
    berkas = tmp_path / "lain.txt"
    berkas.write_text(f"{lain}\n", encoding="utf-8")
    return berkas


def test_resolve_tanpa_konfigurasi_ekspor_polos_atau_terenkripsi(kunci: Any) -> None:
    _, pub, _ = kunci
    assert enkripsi.resolve_recipients((), []) == []
    assert enkripsi.resolve_recipients((), [pub, pub]) == [pub]  # unik, urutan dipertahankan


def test_resolve_wajib_terenkripsi_bila_dikonfigurasi(kunci: Any) -> None:
    _, pub, _ = kunci
    with pytest.raises(AstriaError) as wajib:
        enkripsi.resolve_recipients((pub,), [])
    assert (wajib.value.code, wajib.value.status) == ("EKSPOR_WAJIB_TERENKRIPSI", 400)
    with pytest.raises(AstriaError) as asing:
        enkripsi.resolve_recipients((pub,), [str(pyrage.x25519.Identity.generate().to_public())])
    assert (asing.value.code, asing.value.status) == ("PENERIMA_TIDAK_DIIZINKAN", 400)
    assert enkripsi.resolve_recipients((pub,), [pub]) == [pub]


def test_resolve_format_penerima_salah_ditolak() -> None:
    with pytest.raises(AstriaError) as galat:
        enkripsi.resolve_recipients((), ["age1rusak"])
    assert (galat.value.code, galat.value.status) == ("VALIDASI_GAGAL", 400)


def test_daftar_penerima_dari_env_berupa_json(kunci: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _, pub, _ = kunci
    monkeypatch.setenv("ASTRIA_ENV", "test")
    monkeypatch.setenv("ASTRIA_EXPORT_AGE_RECIPIENTS", json.dumps([pub]))
    assert Settings().export_age_recipients == (pub,)


def test_verify_file_terenkripsi_perlu_identity(tmp_path: Path, kunci: Any, capsys: pytest.CaptureFixture[str]) -> None:
    _, pub, berkas_kunci = kunci
    enc = tmp_path / "ekspor.jsonl.age"
    enc.write_bytes(enkripsi.encrypt_bytes(b"".join(to_lines(build_chain(4))), [pub]))

    assert cli.main(["verify-file", str(enc)]) == 2
    assert "--identity" in capsys.readouterr().err
    assert cli.main(["verify-file", str(enc), "--identity", str(berkas_kunci)]) == 0
    assert "UTUH: 4 entri" in capsys.readouterr().out
    assert cli.main(["verify-file", str(enc), "--identity", str(_kunci_lain(tmp_path))]) == 2
    assert "tidak bisa didekripsi" in capsys.readouterr().err


def test_verify_file_terenkripsi_yang_dirusak_terdeteksi(tmp_path: Path, kunci: Any) -> None:
    _, pub, berkas_kunci = kunci
    entries = build_chain(4)
    entries[2]["payload"] = {"n": 999}  # isi berubah setelah rantai dibuat
    enc = tmp_path / "rusak.jsonl.age"
    enc.write_bytes(enkripsi.encrypt_bytes(b"".join(to_lines(entries)), [pub]))
    assert cli.main(["verify-file", str(enc), "--identity", str(berkas_kunci)]) == 1


def test_verify_file_plain_tetap_tanpa_identity(tmp_path: Path) -> None:
    plain = tmp_path / "ekspor.jsonl"
    plain.write_bytes(b"".join(to_lines(build_chain(3))))
    assert cli.main(["verify-file", str(plain)]) == 0


def test_identity_tanpa_rahasia_ditolak(tmp_path: Path, kunci: Any) -> None:
    _, pub, _ = kunci
    enc = tmp_path / "e.age"
    enc.write_bytes(enkripsi.encrypt_bytes(b"", [pub]))
    publik_saja = tmp_path / "publik.txt"
    publik_saja.write_text(f"{pub}\n", encoding="utf-8")
    assert cli.main(["verify-file", str(enc), "--identity", str(publik_saja)]) == 2


@pytest.fixture
def make_client(pg_schema: str) -> Iterator[Any]:
    clients: list[TestClient] = []

    def _make(recipients: tuple[str, ...] = ()) -> TestClient:
        if not PG_URL:
            pytest.skip("ASTRIA_TEST_DATABASE_URL tidak diisi")
        settings = Settings(
            env="test",
            database_url=SecretStr(PG_URL),
            db_schema=pg_schema,
            anchor_interval_min=0,
            export_age_recipients=recipients,
        )
        app = build_app(settings)
        app.state.token_verifier = FakeVerifier()
        client = TestClient(app)
        client.__enter__()
        clients.append(client)
        return client

    yield _make
    for client in clients:
        client.__exit__(None, None, None)


def rec_body(key: str) -> dict[str, Any]:
    return {
        "idempotency_key": key,
        "occurred_at": "2026-11-12T01:02:03.000004Z",
        "actor": "usr_a",
        "actor_type": "user",
        "action": "ticket.claimed",
        "target_type": "ticket",
        "target_id": "IC-1",
        "via": "ui",
        "payload": {"n": 1},
    }


def test_export_wajib_terenkripsi_menolak_ekspor_polos(make_client: Any, kunci: Any) -> None:
    _, pub, _ = kunci
    client = make_client((pub,))
    write(client, "k1")
    resp = client.get("/internal/v1/export", headers=auth("api", "admin"))
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "EKSPOR_WAJIB_TERENKRIPSI"
    asing = client.get(
        "/internal/v1/export",
        params={"recipient": str(pyrage.x25519.Identity.generate().to_public())},
        headers=auth("api", "admin"),
    )
    assert asing.status_code == 400 and asing.json()["error"]["code"] == "PENERIMA_TIDAK_DIIZINKAN"


def test_export_terenkripsi_bisa_didekripsi_dan_diverifikasi(make_client: Any, kunci: Any) -> None:
    ident, pub, _ = kunci
    client = make_client((pub,))
    for i in range(3):
        write(client, f"k{i}", payload={"n": i})
    resp = client.get("/internal/v1/export", params={"recipient": pub}, headers=auth("api", "admin"))
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/age")
    assert resp.headers["content-disposition"].endswith('.jsonl.age"')
    lines = enkripsi.decrypt_bytes(resp.content, [ident]).splitlines()
    assert len(lines) == 3 and orjson.loads(lines[0])["seq"] == 1
    assert verify_lines(lines).ok


def test_export_tanpa_konfigurasi_recipient_opsional(make_client: Any, kunci: Any) -> None:
    ident, pub, _ = kunci
    client = make_client()
    write(client, "k1")
    write(client, "k2")
    polos = client.get("/internal/v1/export", headers=auth("api", "admin"))
    assert polos.headers["content-type"].startswith("application/x-ndjson")
    assert verify_lines(polos.content.splitlines()).ok
    terenkripsi = client.get("/internal/v1/export", params={"recipient": pub}, headers=auth("api", "admin"))
    assert len(enkripsi.decrypt_bytes(terenkripsi.content, [ident]).splitlines()) == 2


def test_cli_export_terenkripsi_lalu_verify_file(
    make_client: Any, kunci: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _, pub, berkas_kunci = kunci
    client = make_client((pub,))
    write(client, "k1")
    write(client, "k2")
    monkeypatch.setenv("ASTRIA_ENV", "test")
    monkeypatch.setenv("ASTRIA_DATABASE_URL", PG_URL or "")
    monkeypatch.setenv("ASTRIA_DB_SCHEMA", client.app.state.settings.db_schema)
    monkeypatch.setenv("ASTRIA_EXPORT_AGE_RECIPIENTS", json.dumps([pub]))
    out = tmp_path / "ekspor.jsonl.age"

    assert cli.main(["export", "--out", str(out)]) == 2  # tanpa --recipient: ditolak
    assert cli.main(["export", "--out", str(out), "--recipient", pub]) == 0
    assert "terenkripsi" in capsys.readouterr().out
    assert cli.main(["verify-file", str(out), "--identity", str(berkas_kunci)]) == 0
    assert "UTUH: 2 entri" in capsys.readouterr().out
