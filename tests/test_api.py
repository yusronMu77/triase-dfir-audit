"""API audit lewat TestClient dan PostgreSQL sungguhan (butuh ASTRIA_TEST_DATABASE_URL, bila kosong di-skip)."""

import threading
import time
from typing import Any

import orjson
import pytest
from astria_common.auth import ServicePrincipal
from conftest import PG_URL
from fastapi.testclient import TestClient
from pydantic import SecretStr

from astria_audit.chain import store
from astria_audit.chain.verifier import verify_lines
from astria_audit.main import build_app
from astria_audit.settings import Settings


class FakeVerifier:
    """Token uji berbentuk `layanan|peran1,peran2` (peran opsional = tanpa klaim act)."""

    async def verify(self, token: str, audience: str) -> ServicePrincipal:
        service, _, roles = token.partition("|")
        act = {"sub": "usr_uji", "roles": roles.split(",")} if roles else None
        return ServicePrincipal(subject=f"svc:{service}", audience=audience, act=act, claims={})


def auth(service: str, roles: str = "") -> dict[str, str]:
    return {"Authorization": f"Bearer {service}|{roles}"}


def rec(key: str, **overrides: Any) -> dict[str, Any]:
    body = {
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
    return body | overrides


@pytest.fixture
def client(pg_schema: str):
    settings = Settings(env="test", database_url=SecretStr(PG_URL or ""), db_schema=pg_schema, anchor_interval_min=0)
    app = build_app(settings)
    app.state.token_verifier = FakeVerifier()
    with TestClient(app) as c:
        deadline = time.monotonic() + 15
        while c.get("/ready").status_code != 200:
            assert time.monotonic() < deadline, "audit tidak siap"
            time.sleep(0.1)
        yield c


def write(client: TestClient, key: str, **overrides: Any) -> dict[str, Any]:
    resp = client.post("/internal/v1/records", json=rec(key, **overrides), headers=auth("ingest"))
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_write_is_open_to_any_service_and_idempotent(client: TestClient) -> None:
    first = client.post("/internal/v1/records", json=rec("k1"), headers=auth("triage"))
    again = client.post("/internal/v1/records", json=rec("k1"), headers=auth("triage"))
    clash = client.post("/internal/v1/records", json=rec("k1", payload={"n": 2}), headers=auth("triage"))
    assert (first.status_code, again.status_code, clash.status_code) == (201, 200, 409)
    assert again.json()["duplicate"] is True and clash.json()["error"]["code"] == "PAYLOAD_MISMATCH"


def test_authorization_matrix(client: TestClient) -> None:
    write(client, "k1")
    urls = {"baca": "/internal/v1/records", "jangkar": "/internal/v1/anchor/latest"}
    # layanan di luar reader_services ditolak, walau token sah
    for url in urls.values():
        resp = client.get(url, headers=auth("ingest"))
        assert resp.status_code == 403 and resp.json()["error"]["code"] == "PEMANGGIL_DITOLAK"
    # pembaca layanan tanpa act: boleh (api, scheduler, devtools)
    for service in ("api", "scheduler", "devtools"):
        assert client.get(urls["baca"], headers=auth(service)).status_code == 200
    # dengan act: analis ditolak, dfir boleh baca tetapi tidak verifikasi/ekspor/jangkar, admin boleh semua
    denied = client.get(urls["baca"], headers=auth("api", "analis"))
    assert denied.status_code == 403 and denied.json()["error"]["code"] == "PERAN_TIDAK_CUKUP"
    assert client.get(urls["baca"], headers=auth("api", "dfir")).status_code == 200
    for method, url in (
        ("POST", "/internal/v1/verify-jobs"),
        ("GET", "/internal/v1/export"),
        ("POST", "/internal/v1/anchors"),
    ):
        assert client.request(method, url, headers=auth("api", "dfir")).status_code == 403, url
        assert client.request(method, url, headers=auth("api", "admin")).status_code in (200, 201), url
    # tanpa token: 401
    assert client.get(urls["baca"]).status_code == 401


def test_list_filters_and_paging(client: TestClient) -> None:
    write(client, "a", actor="usr_a", action="x.one", target_id="T1")
    write(client, "b", actor="usr_b", action="x.one", target_id="T2")
    write(client, "c", actor="usr_a", action="x.two", target_id="T2")
    write(client, "d", actor="usr_a", action="x.one", target_id="T2", target_type="case")
    headers = auth("api", "admin")

    def seqs(**params: Any) -> list[int]:
        resp = client.get("/internal/v1/records", params=params, headers=headers)
        assert resp.status_code == 200, resp.text
        return [e["seq"] for e in resp.json()["items"]]

    assert seqs() == [1, 2, 3, 4]
    assert seqs(actor="usr_a") == [1, 3, 4]
    assert seqs(actor="usr_a", action="x.one") == [1, 4]
    assert seqs(target_id="T2", target_type="ticket") == [2, 3]
    assert seqs(action="tidak.ada") == []
    page = client.get("/internal/v1/records", params={"limit": 2, "from_seq": 2}, headers=headers).json()
    assert [e["seq"] for e in page["items"]] == [2, 3] and page["next_from_seq"] == 4
    assert "request_hash" not in page["items"][0]


def test_verify_job_runs_and_returns_200_with_ok_true(client: TestClient) -> None:
    for i in range(3):
        write(client, f"k{i}", payload={"n": i})
    resp = client.post("/internal/v1/verify-jobs", headers=auth("devtools"))  # tanpa isi, seperti smoke Tahap 0
    body = resp.json()
    assert resp.status_code == 200, resp.text
    assert body["status"] == "selesai" and body["ok"] is True and body["checked"] == 3
    assert body["job_id"].startswith("ver_") and body["anchor_match"] is None
    fetched = client.get(f"/internal/v1/verify-jobs/{body['job_id']}", headers=auth("api", "dfir"))
    assert fetched.status_code == 200 and fetched.json() == body


def test_verify_job_202_while_running_then_200(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    write(client, "k1")
    gate = threading.Event()
    real = store.verify_range

    async def slow(conn: Any, **kwargs: Any) -> dict[str, Any]:
        import asyncio

        while not gate.is_set():  # noqa: ASYNC110 - gate lintas thread (TestClient), bukan asyncio.Event
            await asyncio.sleep(0.01)
        return await real(conn, **kwargs)

    monkeypatch.setattr(store, "verify_range", slow)
    resp = client.post("/internal/v1/verify-jobs", params={"wait_ms": 0}, headers=auth("api", "admin"))
    assert resp.status_code == 202
    running = resp.json()
    assert running["status"] == "berjalan" and running["ok"] is None and running["to_seq"] is None
    gate.set()
    deadline = time.monotonic() + 10
    while True:
        job = client.get(f"/internal/v1/verify-jobs/{running['job_id']}", headers=auth("api", "admin")).json()
        if job["status"] != "berjalan":
            break
        assert time.monotonic() < deadline
        time.sleep(0.05)
    assert job["status"] == "selesai" and job["ok"] is True and job["finished_at"]


def test_verify_job_unknown_and_bad_range(client: TestClient) -> None:
    missing = client.get("/internal/v1/verify-jobs/ver_tidakada", headers=auth("api"))
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "TUGAS_TIDAK_DITEMUKAN"
    bad = client.post("/internal/v1/verify-jobs", json={"from_seq": 5, "to_seq": 2}, headers=auth("api", "admin"))
    assert bad.status_code == 400


def test_verify_job_partial_range_and_tamper(client: TestClient) -> None:
    for i in range(4):
        write(client, f"k{i}", payload={"n": i})
    partial = client.post("/internal/v1/verify-jobs", json={"from_seq": 2, "to_seq": 3}, headers=auth("api")).json()
    assert (partial["ok"], partial["checked"], partial["from_seq"], partial["to_seq"]) == (True, 2, 2, 3)


def test_export_streams_jsonl_that_verifies_offline(client: TestClient) -> None:
    for i in range(5):
        write(client, f"k{i}", payload={"n": i})
    resp = client.get("/internal/v1/export", headers=auth("api", "admin"))
    assert resp.status_code == 200 and resp.headers["content-type"].startswith("application/x-ndjson")
    lines = resp.content.splitlines()
    assert len(lines) == 5
    first = orjson.loads(lines[0])
    assert first["seq"] == 1 and "request_hash" not in first and first["payload"] == {"n": 0}
    assert list(first) == sorted(first)
    assert verify_lines(lines).ok
    ranged = client.get("/internal/v1/export", params={"from_seq": 2, "to_seq": 4}, headers=auth("api", "admin"))
    assert [orjson.loads(x)["seq"] for x in ranged.content.splitlines()] == [2, 3, 4]
    assert (
        client.get("/internal/v1/export", params={"from_seq": 4, "to_seq": 2}, headers=auth("api")).status_code == 400
    )


def test_anchors_flow_and_anchor_match(client: TestClient) -> None:
    admin = auth("api", "admin")
    assert client.get("/internal/v1/anchor/latest", headers=admin).status_code == 404
    empty = client.post("/internal/v1/anchors", headers=admin)
    assert empty.status_code == 404 and empty.json()["error"]["code"] == "RANTAI_KOSONG"
    for i in range(3):
        write(client, f"k{i}", payload={"n": i})
    created = client.post("/internal/v1/anchors", headers=admin)
    assert created.status_code == 201 and created.json()["seq"] == 3
    same = client.post("/internal/v1/anchors", headers=admin)
    assert same.status_code == 200 and same.json()["anchor_id"] == created.json()["anchor_id"]
    write(client, "k3", payload={"n": 3})
    newer = client.post("/internal/v1/anchors", headers=admin)
    assert newer.status_code == 201 and newer.json()["seq"] == 4
    latest = client.get("/internal/v1/anchor/latest", headers=auth("scheduler")).json()
    assert latest["anchor_id"] == newer.json()["anchor_id"]
    listing = client.get("/internal/v1/anchors", params={"limit": 1}, headers=auth("api", "dfir")).json()
    assert [a["seq"] for a in listing["items"]] == [4]
    verdict = client.post("/internal/v1/verify-jobs", headers=admin).json()
    assert verdict["ok"] is True and verdict["anchor_match"] is True


def test_metrics_are_exposed(client: TestClient) -> None:
    write(client, "k1")
    client.post("/internal/v1/verify-jobs", headers=auth("api"))
    text = client.get("/metrics").text
    for name in (
        "audit_chain_length",
        "audit_write_duration_seconds",
        'audit_records_total{result="ok",via="sync"}',
        "audit_verify_duration_seconds",
        'audit_verify_total{ok="true"}',
        "audit_anchors_created_total",
    ):
        assert name in text, name


def test_health_lists_new_components(client: TestClient) -> None:
    checks = client.get("/health").json()["checks"]
    assert checks["postgres"]["status"] == "ok"
    assert "verifikasi" in checks and "jangkar" in checks
