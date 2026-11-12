"""Perintah audit: `astria-audit [serve|migrate|verify-file|export]` (atau `python -m astria_audit`).

- `serve` (bawaan): jalankan layanan (menerapkan migrasi di awal).
- `migrate`: terapkan migrasi skema ke `ASTRIA_DATABASE_URL` lalu keluar. Jalankan sekali sebagai pemilik basis data
  sebelum `sql/roles.sql`; untuk DB yang sudah ada tabelnya, perintah ini hanya menandai (`stamp`).
- `verify-file <berkas> [--identity <kunci>]`: verifikasi berkas ekspor secara offline, plain JSONL atau age
  (terenkripsi; perlu `--identity`). Hanya membaca berkas; tidak memuat pengaturan `ASTRIA_*`, tidak membuka basis data
  atau jaringan. Keluar 0 bila rantai utuh, 1 bila rusak, 2 bila berkas tidak terbaca atau tidak bisa didekripsi.
- `export --from N --to M --out <berkas> [--recipient age1...]`: ekspor JSONL langsung dari basis data
  (`ASTRIA_DATABASE_URL`). Dengan `--recipient` berkasnya terenkripsi age; bila `ASTRIA_EXPORT_AGE_RECIPIENTS`
  diatur, `--recipient` wajib dan harus termasuk daftar itu.
"""

from __future__ import annotations

import argparse
import asyncio
import io
import sys
from pathlib import Path
from typing import Any


def _serve() -> int:
    from astria_common.app import run

    from astria_audit.main import build_app
    from astria_audit.settings import Settings

    settings = Settings()
    run(build_app(settings), settings)
    return 0


def _laporan_verifikasi(result: Any) -> int:
    span = f"seq {result.from_seq}..{result.to_seq}" if result.from_seq is not None else "kosong"
    if result.ok:
        print(f"UTUH: {result.checked} entri diperiksa ({span})")  # noqa: T201
        return 0
    where = f", entri rusak pertama seq {result.first_bad_seq}" if result.first_bad_seq is not None else ""
    detail = f" ({result.detail})" if result.detail else ""
    print(f"RUSAK: {result.reason}{where}{detail}; {result.checked} entri sah sebelumnya ({span})")  # noqa: T201
    return 1


def _verify_file(path: Path, identity: Path | None) -> int:
    from astria_audit import enkripsi
    from astria_audit.chain.verifier import verify_lines

    try:
        with path.open("rb") as handle:
            head = handle.read(len(enkripsi.AGE_MAGIC))
            if head != enkripsi.AGE_MAGIC:
                handle.seek(0)
                return _laporan_verifikasi(verify_lines(handle))
            blob = head + handle.read()
    except OSError as exc:
        print(f"berkas tidak terbaca: {exc.strerror or type(exc).__name__}", file=sys.stderr)  # noqa: T201
        return 2
    if identity is None:
        print("berkas terenkripsi age: beri --identity <berkas-kunci-rahasia>", file=sys.stderr)  # noqa: T201
        return 2
    try:
        plain = enkripsi.decrypt_bytes(blob, enkripsi.load_identities(identity))
    except (OSError, ValueError, *enkripsi.GALAT_AGE):
        print("berkas tidak bisa didekripsi dengan identity ini", file=sys.stderr)  # noqa: T201
        return 2
    return _laporan_verifikasi(verify_lines(plain.splitlines()))


def _migrate() -> int:
    from astria_audit.settings import Settings
    from astria_audit.skema import SkemaGagal, terapkan

    settings = Settings()
    if settings.database_url is None:
        print("ASTRIA_DATABASE_URL belum diisi", file=sys.stderr)  # noqa: T201
        return 2
    try:
        tindakan = terapkan(settings.database_url.get_secret_value(), settings.db_schema)
    except SkemaGagal as exc:
        print(f"migrasi gagal: {exc}", file=sys.stderr)  # noqa: T201
        return 1
    print(f"migrasi audit: {tindakan}")  # noqa: T201
    return 0


async def _export(from_seq: int, to_seq: int | None, out: Path, recipients: list[str]) -> int:
    import orjson
    from astria_common.db import normalize_url
    from astria_common.errors import AstriaError
    from sqlalchemy.ext.asyncio import create_async_engine

    from astria_audit import enkripsi
    from astria_audit.chain import store
    from astria_audit.settings import Settings

    settings = Settings()
    if settings.database_url is None:
        print("ASTRIA_DATABASE_URL belum diisi", file=sys.stderr)  # noqa: T201
        return 2
    try:
        penerima = enkripsi.resolve_recipients(settings.export_age_recipients, recipients)
    except AstriaError as exc:
        print(f"ekspor ditolak: {exc.message}", file=sys.stderr)  # noqa: T201
        return 2
    connect_args = {"options": f"-csearch_path={settings.db_schema}"} if settings.db_schema else {}
    engine = create_async_engine(normalize_url(settings.database_url.get_secret_value()), connect_args=connect_args)
    buf = io.BytesIO()
    count = 0
    try:
        async with engine.connect() as conn:
            target = buf if penerima else out.open("wb")
            try:
                async for entry in store.iter_entries(conn, from_seq=from_seq, to_seq=to_seq):
                    target.write(orjson.dumps(entry, option=orjson.OPT_SORT_KEYS) + b"\n")
                    count += 1
            finally:
                if not penerima:
                    target.close()
    finally:
        await engine.dispose()
    if penerima:
        await asyncio.to_thread(out.write_bytes, enkripsi.encrypt_bytes(buf.getvalue(), penerima))
        print(f"{count} entri terenkripsi ({len(penerima)} penerima) ditulis ke {out}")  # noqa: T201
    else:
        print(f"{count} entri ditulis ke {out}")  # noqa: T201
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="astria-audit", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="jalankan layanan (bawaan)")
    sub.add_parser("migrate", help="terapkan migrasi skema audit ke ASTRIA_DATABASE_URL")
    verify = sub.add_parser("verify-file", help="verifikasi berkas ekspor JSONL (plain atau age) secara offline")
    verify.add_argument("file", type=Path)
    verify.add_argument("--identity", type=Path, default=None, help="kunci rahasia age (berkas terenkripsi)")
    export = sub.add_parser("export", help="ekspor entri ke berkas JSONL dari basis data")
    export.add_argument("--from", dest="from_seq", type=int, default=1)
    export.add_argument("--to", dest="to_seq", type=int, default=None)
    export.add_argument("--out", type=Path, required=True)
    export.add_argument("--recipient", action="append", default=[], help="kunci publik age1... (berulang)")
    args = parser.parse_args(argv)

    if args.command == "migrate":
        return _migrate()
    if args.command == "verify-file":
        return _verify_file(args.file, args.identity)
    if args.command == "export":
        return asyncio.run(_export(args.from_seq, args.to_seq, args.out, args.recipient))
    return _serve()


if __name__ == "__main__":
    sys.exit(main())
