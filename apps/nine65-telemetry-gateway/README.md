# NINE65 Telemetry Gateway

Node/Next.js gateway that accepts ciphertext telemetry, persists to Postgres via Prisma, and forwards evaluate requests to the Rust FHE service.

Status: pre-production (NINE65 v5 guardrail)

## Implemented routes
- `GET /healthz`
- `GET /v1/version`
- `GET /v1/fhe/public-key`
- `POST /v1/telemetry/events`
- `POST /v1/fhe/evaluate` (internal token protected)
- `GET /v1/metrics`

## Local run
1. Start Postgres:
```bash
docker compose up -d
```
2. Create env file:
```bash
cp .env.example .env
```
3. Install deps and initialize DB:
```bash
npm install
npm run prisma:generate
npm run prisma:push
```
4. Run dev server:
```bash
npm run dev
```

## Required upstream
Run `crates/fhe-service` on `FHE_SERVICE_URL` (default `http://127.0.0.1:8080`).

## Smoke scripts
- `scripts/generate_telemetry.py`
- `scripts/post_telemetry.py`
