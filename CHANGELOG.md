# Changelog

All notable changes to the **APK Inspector** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.0] - 2026-10-18

### Added
- **Configurable PostgreSQL Host Port (`POSTGRES_PORT`)**: Made Docker Compose database port binding configurable via `${POSTGRES_PORT:-5438}`, safely defaulting to `5438` to prevent port collisions with existing local PostgreSQL instances (such as ports `5432-5435`).
- **Configurable Application Port (`PORT`)**: Mapped container port to `${PORT:-3001}` in `docker-compose.yml` to prevent conflicts with local Next.js / dev servers running on `3000`.
- **Prisma ORM & PostgreSQL Support**: Added `prisma/schema.prisma` with `AnalysisReport` model to store, index, and query completed APK security scans.
- **Resilient Dual-Mode Database Fallback**: Added `PrismaService` connection health verification. If `DATABASE_URL` is unconfigured or unreachable, the service transparently falls back to filesystem JSON storage in `reports/` without downtime or endpoint failures.
- **Neon.tech Production Database Integration**: Added support for Neon Serverless PostgreSQL with SSL connection string, plus blueprint environment declaration in `render.yaml`.
- **Health Check Database Indicator**: Extended `/health` endpoint to return `databaseConnected: true/false`.

### Changed
- Updated `docker-compose.yml` with configurable environment variable interpolation.
- Updated `.env.example` with local Docker port `5438` and Neon.tech production templates.
- Updated Dockerfile multi-stage build to include `prisma/` schema and run `npx prisma generate`.
- Added `"postinstall": "prisma generate"` in `package.json` for seamless CI/CD and deployment workflows.

---

## [1.1.0] - 2026-10-18

### Added
- **Configurable LLM Model Settings**: Introduced `.env` variables `GEMINI_MODEL`, `GEMINI_MAX_TOKENS`, and `GEMINI_THINKING_BUDGET`.
- **Thinking Token Budget Control**: Configured `thinkingBudget: 0` for `gemini-2.5-flash` so internal reasoning tokens do not consume the maximum output token quota.
- **Forced Summary Regeneration**: Added `?force=true` query parameter on `POST /summarize/:id` and `GET /report/:id/summary` to overwrite truncated cached summaries.

### Fixed
- Fixed AI executive risk summary truncation issue where reasoning models (`gemini-2.5-flash`) exhausted output tokens mid-sentence.
- Resolved 404 model errors by defaulting from deprecated `gemini-1.5-flash` to active `gemini-2.5-flash` with automatic fallback to `gemini-flash-latest`.

---

## [1.0.0] - 2026-10-18

### Added
- **Core Python Reverse-Engineering Engine**: Integrated `androguard` for static analysis of Android APK binaries without device execution.
- **Manifest & Internals Inspector**: Extracted package ID, SDK versions, dangerous permissions, and unprotected exported components (Activities, Services, Receivers, Providers).
- **Dalvik Bytecode & Smali Scanner**: Pattern-matched hardcoded cloud credentials (AWS, Google API, JWT, private keys), unencrypted `http://` URLs, and dangerous runtime APIs (`Runtime.exec`, `ProcessBuilder`, `DexClassLoader`).
- **Native Shared Object (.so) & ABI Enumerator**: Extracted bundled native libraries and target ABIs (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`).
- **OWASP MASVS Rule Engine**: Mapped findings to MASVS categories and calculated automated security grades (`A` to `F`).
- **Glassmorphic Web Dashboard**: Single-page frontend dashboard served directly at `/` featuring drag-and-drop file upload, real-time status, metric cards, and Markdown AI reports.
- **Interactive OpenAPI / Swagger UI**: Full API contract interactive explorer available at `/api/docs`.
- **Automated Test APK Generator**: `engine/create_test_apk.py` script generating benign Android APK binaries for unit and E2E verification.
- **Docker & CI/CD Pipeline**: Multi-stage `Dockerfile`, `docker-compose.yml`, and GitHub Actions CI workflow.
