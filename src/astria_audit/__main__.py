"""Perintah audit: `astria-audit [serve|verify-file|export]` (atau `python -m astria_audit`).

- `serve` (bawaan): jalankan layanan.
- `verify-file <berkas.jsonl>`: verifikasi berkas ekspor secara offline. Hanya membaca berkas; tidak memuat pengaturan
  `ASTRIA_*`, tidak membuka basis data atau jaringan. Keluar 0 bila rantai utuh, 1 bila rusak, 2 bila berkas
  tidak terbaca.
- `export --from N --to M --out <berkas>`: ekspor JSONL langsung dari basis data (`ASTRIA_DATABASE_URL`).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path


def _serve() -> int:
    from astria_common.app import run

    from astria_audit.main import build_app
    from astria_audit.settings import Settings

    settings = Settings()
    run(build_app(settings), settings)
    return 0


def _verify_file(path: Path) -> int:
    from astria_audit.chain.verifier import verify_lines

    try:
        with path.open("rb") as handle:
            result = verify_lines(handle)
    except OSError as exc:
        print(f"berkas tidak terbaca: {exc.strerror or type(exc).__name__}", file=sys.stderr)  # noqa: T201
        return 2
    span = f"seq {result.from_seq}..{result.to_seq}" if result.from_seq is not None else "kosong"
    if result.ok:
        print(f"UTUH: {result.checked} entri diperiksa ({span})")  # noqa: T201
        return 0
    where = f", entri rusak pertama seq {result.first_bad_seq}" if result.first_bad_seq is not None else ""
    detail = f" ({result.detail})" if result.detail else ""
    print(f"RUSAK: {result.reason}{where}{detail}; {result.checked} entri sah sebelumnya ({span})")  # noqa: T201
    return 1


async def _export(from_seq: int, to_seq: int | None, out: Path) -> int:
    import orjson
    from astria_common.db import normalize_url
    from sqlalchemy.ext.asyncio import create_async_engine

    from astria_audit.chain import store
    from astria_audit.settings import Settings

    settings = Settings()
    if settings.database_url is None:
        print("ASTRIA_DATABASE_URL belum diisi", file=sys.stderr)  # noqa: T201
        return 2
    connect_args = {"options": f"-csearch_path={settings.db_schema}"} if settings.db_schema else {}
    engine = create_async_engine(normalize_url(settings.database_url.get_secret_value()), connect_args=connect_args)
    count = 0
    try:
        async with engine.connect() as conn:
            with out.open("wb") as handle:
                async for entry in store.iter_entries(conn, from_seq=from_seq, to_seq=to_seq):
                    handle.write(orjson.dumps(entry, option=orjson.OPT_SORT_KEYS) + b"\n")
                    count += 1
    finally:
        await engine.dispose()
    print(f"{count} entri ditulis ke {out}")  # noqa: T201
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="astria-audit", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="jalankan layanan (bawaan)")
    verify = sub.add_parser("verify-file", help="verifikasi berkas ekspor JSONL secara offline")
    verify.add_argument("file", type=Path)
    export = sub.add_parser("export", help="ekspor entri ke berkas JSONL dari basis data")
    export.add_argument("--from", dest="from_seq", type=int, default=1)
    export.add_argument("--to", dest="to_seq", type=int, default=None)
    export.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    if args.command == "verify-file":
        return _verify_file(args.file)
    if args.command == "export":
        return asyncio.run(_export(args.from_seq, args.to_seq, args.out))
    return _serve()


if __name__ == "__main__":
    sys.exit(main())
