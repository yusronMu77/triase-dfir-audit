"""Jalankan layanan: `astria-audit` atau `python -m astria_audit`."""

from astria_common.app import run

from astria_audit.main import build_app
from astria_audit.settings import Settings


def main() -> None:
    settings = Settings()
    run(build_app(settings), settings)


if __name__ == "__main__":
    main()
