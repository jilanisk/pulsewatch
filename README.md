# PulseWatch 2.0

Self-hosted website uptime monitoring with a responsive dashboard, SQLite history, concurrent checks, administrator authentication, incident tracking, and optional Telegram/email alerts.

## Requirements
- Docker Engine and Docker Compose (recommended), or Node.js 22.13+

## Docker deployment

```bash
cp .env.example .env
```

Edit `.env` and set `ADMIN_PASSWORD` (12+ characters) and a unique `SESSION_SECRET` (32+ characters). Generate a secret with:

```bash
openssl rand -base64 48
```

Then run:

```bash
docker compose up -d --build
```

Open `http://localhost:3000` and sign in with `ADMIN_USER` / `ADMIN_PASSWORD` from `.env`. Put PulseWatch behind HTTPS before exposing it to the internet. Do not publish the raw HTTP port publicly.

## Run without Docker

```bash
cp .env.example .env
npm install
# The start script loads .env automatically. For local HTTP testing, set COOKIE_SECURE=false in .env.
npm start
```

Node does not automatically load `.env`; use Docker Compose or provide the variables through your process manager.

## V1 migration

On first startup, if `DATA_DIR/sites.json` exists, PulseWatch imports sites, recent checks, and incident entries into SQLite. The source file is renamed to `sites.json.migrated` after a successful import. The Docker image seeds a brand-new named volume with the V1 `data/sites.json` included in this release; an existing named volume is left untouched and its own V1 JSON file is imported. Back up your V1 data directory / Docker volume before upgrading. The SQLite database is stored at `DATA_DIR/pulsewatch.sqlite`.

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `PORT` | `3000` | HTTP listen port |
| `DATA_DIR` | `./data` | Persistent database directory |
| `CHECK_INTERVAL` | `60000` | Scheduler interval in milliseconds (minimum 15 seconds) |
| `CHECK_CONCURRENCY` | `10` | Maximum simultaneous checks (1–50) |
| `CHECK_TIMEOUT` | `10000` | Per-request timeout in milliseconds |
| `ADMIN_USER` | `admin` | Administrator username |
| `ADMIN_PASSWORD` | required in production | Administrator password, minimum 12 characters |
| `SESSION_SECRET` | required in production | HMAC signing secret, minimum 32 characters |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | empty | Optional Telegram alerts |
| `SMTP_*`, `ALERT_EMAIL_*` | empty | Optional email alerts via SMTP |

## API

All `/api` routes except `/api/health` and `/api/auth/*` require an authenticated administrator session (HTTP-only cookie).

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Liveness and scheduler state |
| POST | `/api/auth/login` | Administrator login |
| POST | `/api/auth/logout` | End session |
| GET | `/api/auth/session` | Session state |
| GET | `/api/overview` | Dashboard totals |
| GET | `/api/sites` | Sites with recent history |
| POST | `/api/sites` | Add and immediately check a site |
| POST | `/api/sites/:id/check` | Run a manual check |
| PATCH | `/api/sites/:id` | Rename or pause/resume a site |
| DELETE | `/api/sites/:id` | Delete site and related records |
| GET | `/api/sites/:id/reports` | Rolling 30-day uptime/latency summary |
| GET | `/api/incidents` | Recent incidents |

## Security notes
- Outbound checks accept HTTP/HTTPS on standard ports only, reject non-public DNS answers, pin the resolved address for each connection, and validate redirect destinations before following them.
- Admin APIs require an HTTP-only, SameSite=Strict signed session cookie. Login is rate-limited.
- Set a strong unique session secret and password. Use HTTPS through a reverse proxy for public deployments.
- This is a single-administrator self-hosted tool, not a multi-tenant SaaS service. Restrict network access and keep the host updated.

## V2 notes / limitations
- SQLite is used through Node.js `node:sqlite` (available in supported Node 22 releases; Node may emit an experimental warning depending on its version).
- Uptime is calculated from recorded checks; it is not an external synthetic monitoring SLA.
- Notifications are emitted on state transitions (down and recovery), not on every failed check.
- Configure SMTP/Telegram credentials only if you want those optional alert channels.

MIT License.
