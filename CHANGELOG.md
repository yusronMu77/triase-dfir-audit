# Changelog

## [Unreleased]

### Added

- Kerangka layanan Tahap 0 dari templat `common` v0.1.0: `/health`, `/ready`, `/metrics`, token layanan, Dockerfile non-root, CI (lint, uji, gitleaks, build image, smoke `/ready`).
- Buku besar audit berantai hash: `POST/GET /internal/v1/records` (sinkron, idempoten), `POST /internal/v1/verify-jobs`, konsumen `audit.record`, pemicu append-only.
- Logo Astria di kepala README (`.github/assets/`, dari kit logo di repo `triase-dfir-uiux`).
