# AEGIS-X Enterprise ASM Architecture

## Philosophy

**Deterministic Security ETL** — no AI in extract, transform, or load. Playwright captures verbatim artifacts; static rules evaluate them; contextual risk profiles adjust severity. AI is optional and async (scan chat copilot only).

## Pipeline

```
Extract (Playwright) → Transform (rules) → Risk (profiler + debt) → Load (memory/Postgres) → Delta (diff)
```

| Layer | Path | Responsibility |
|-------|------|----------------|
| Extract | `src/backend/extract/` | Isolated browser per scan, HTTP capture, DNS, TCP ports, fingerprinting |
| Transform | `src/backend/rules/` | SEC-*, COOKIE-*, CONTENT-*, INFO-* rules with literal `SecurityEvidence` |
| Risk | `src/backend/transform/` | Org profiles (Fintech, Healthcare, …), security debt calculator |
| Load | `src/backend/load/` | Repository, optional `DATABASE_URL` Postgres, `to-intelligence-report` bridge |
| API | `src/backend/api/` | `/api/v2/*` direct ETL endpoints |
| UX | `src/components/enterprise/` | Executive ↔ Technical dashboard |

## Primary integration

- **Scans**: `POST /api/scans` → `executeRun` → `executeEtlPipeline` in `src/backend/etl/pipeline.ts`
- **Results**: `GET /api/runs/:id` returns `IntelligenceReport` with `enterprise.scanResult` for the dashboard
- **Direct ETL**: `POST /api/v2/scan` with `{ targetUrl, orgType }`

## Deployment

- **Vercel**: frontend (`vite build`)
- **Render**: API (`npm start` → `tsx scripts/dev-api.ts`)
- **Postgres** (optional): set `DATABASE_URL` and run `supabase/migrations/20250603000000_enterprise_etl.sql`

## Render note

Install Playwright browsers on the API service:

```bash
npx playwright install chromium
```
