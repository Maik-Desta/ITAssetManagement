# Bank IT Asset & Infrastructure Management (ITAM) Platform

A working implementation of the **Centralized IT Asset & Infrastructure Management Programme** proposal (v4):
one asset database (CMDB) for 100+ branches, live monitoring and alerting, governed lifecycle workflows with
maker-checker approval, automated and physical audits, executive dashboards and programme KPIs.

> The proposal recommends selecting a commercial suite through an RFP. This application implements the functional
> requirements in the deck, so it can serve as the interim platform (Option C, the "quick win"), as a reference
> for the RFP and the proof of concept, or as the production system if the Bank chooses to build.

## What it does — mapped to the proposal

| Proposal | Implementation |
|---|---|
| **Single source of truth** (slide 9, 16) | Relational CMDB: Region → Branch → Location; Asset (CI) with model/vendor (EOL/EOS), contract/warranty, custodian, finance FA number, PCI scope; monitoring events; changes; audit records |
| **Asset number standard** `CC-RRR-BBBB-TTT-NNNNN` (slide 16) | Issued automatically per prefix on registration and never changed when the asset moves. Printable tamper-evident QR labels; the QR opens the asset record on a phone |
| **Lifecycle, one status at a time** (slide 18) | In stock → In transit → Installed – active / faulty → Under repair → Missing → Retired → Disposed, with an enforced transition table and a per-asset history |
| **New equipment** (slide 19) | Request → IT and budget approval (maker-checker) → Procurement PO → receive & tag at the central store → dispatch (transfer) → install with a hardening checklist (SNMPv3, syslog, NTP) → **discovery confirms go-live** → branch manager accepts custody |
| **Moves, repairs, retirement, disposal** (slide 20) | The approval matrix exactly as in the deck (e.g. retire critical device = Head of Infrastructure + CISO; dispose = CIO + CFO). Requester can't approve; one person can't give both approvals. Tag scan required at execution. Evidence enforced (transfer note, RMA, data-wipe certificate, disposal certificate). Finance confirms the fixed-asset write-off |
| **Monitoring & alerting** (slide 21) | Collector API for poll results, syslog/traps, config changes and discovery. Severity rules P1–P4 (branch offline, redundancy lost, core device down, server down, degradation, environment). Event correlation suppresses child alarms while a branch is offline. Response targets of 15 min, 30 min, 4 h and next business day. Unacknowledged alerts escalate engineer → regional lead → Head of Infrastructure → CIO. P1 goes by SMS + voice + e-mail + chat |
| **Unapproved removal** (slide 20) | A device that drops out of discovery without an approved change raises an alert to NOC, CISO and the branch manager. After 72 h unseen it becomes **Missing**, with an exception. Detection is suppressed while the region's collector is silent, so a WAN outage isn't read as a theft |
| **Automated auditing** (slide 22) | Daily discovery vs register (rogue, missing, swapped serial/MAC, wrong branch). Weekly exception report with ageing. Monthly data-quality league table. Quarterly cyclical physical audit (25% of branches, least-recently audited first) with mobile/camera QR scanning. Annual branch-manager attestation and Finance fixed-asset reconciliation (CSV). Internal Audit control tests |
| **Executive dashboard** (slide 23) | Branches online, assets registered, healthy %, missing/rogue, open P1/P2, live branch map, warranty/EOL due in 90 days, audit score per branch, MTTD/MTTR trends, asset age profile, unapproved changes, collector health |
| **Governance & RACI** (slides 25–26) | 14 roles (CIO, CFO, CISO, Head of Infra, IT Asset Manager, regional lead/engineer, branch manager, NOC, Procurement, Finance, Internal Audit, Executive, Admin). Regional staff see only their region and branch managers only their branch |
| **KPIs** (slide 33) | All nine KPIs computed live against their targets |
| **Rollout** (slides 30–31) | Waves (Pilot, 1–3), the "branch day" playbook checklist per stage (T-10 → Day 0 → Day +1 → Day +2 sign-off). A branch can't go live without the custodian's attestation. Decision gates G1–G5 with budget plan vs actual |
| **Security** (slides 15, 32, 34) | scrypt passwords, TOTP MFA (enforceable per role), login lockout, CSRF on every form, strict CSP and security headers, hashed collector API keys with rotation, and an **append-only hash-chained audit log** (DB triggers block UPDATE/DELETE; chain verification detects tampering). Optional syslog forwarding to the SIEM |
| **Integrations** (slide 14) | Finance ERP (fixed-asset CSV reconciliation and export), Procurement (PO on request), HR leaver feed (`/api/v1/integrations/hr/leavers`) raising custodian exceptions, SIEM (syslog), e-mail (SMTP), SMS/voice gateway and Teams/chat webhook |

## Quick start (demo)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
export ITAM_SECRET_KEY=change-me
python -m itam.cli seed            # Cameroon: 10 regions, 250 branches, ~2,700 assets, users for every role, live alerts
python -m itam.cli serve           # http://127.0.0.1:8000
```

Demo password for every seeded user: `ChangeMe!2026` (demo only).

| User | Role | Try |
|---|---|---|
| `ceo` / `cio` | Executive / CIO | Dashboard, KPIs, approve disposals |
| `noc` | NOC analyst | NOC console: acknowledge/resolve, log user-reported incidents |
| `itam` | IT Asset Manager | Register, receive & tag, second approvals, exceptions, audits |
| `lead.lit`, `eng.lit` (also `.cen`, `.oue`, …) | Regional lead / engineer (Littoral – Douala) | Approve moves, install, execute changes, scan audits |
| `bm0002` … `bm0250` | Branch managers | Accept custody, attest, approve transfers out |
| `head.infra`, `ciso`, `cfo`, `finance`, `procurement`, `audit`, `admin` | | Their own steps in the workflows |

To make the demo move, run the collector simulator against the running server:

```bash
python -m itam.simulator --url http://127.0.0.1:8000 --cycles 10 --interval 30
```

API documentation (OpenAPI) is at `/api/docs`.

## Deploy a shareable test instance (Render)

The repo includes a `render.yaml` Blueprint that creates the web app and a PostgreSQL database.

1. In Render: **New → Blueprint**, then pick this repository and branch.
2. When asked for `ITAM_DEMO_PASSWORD`, enter the password every demo user will share. If you leave it empty,
   the default `ChangeMe!2026` is used, which is public in this README.
3. Apply. On first start the app loads the demo data (`ITAM_DEMO_SEED=true`); restarts don't reload it.
   When a new version of the demo dataset ships (e.g. the switch to Cameroon), an older demo database is
   replaced automatically on the next deploy. A database holding real (non-demo) data is never touched.
   The public URL is shown on the service page.

Free Render instances sleep when idle, so the first request after a pause takes about a minute. The free
database expires after 30 days. For a real deployment, remove `ITAM_DEMO_SEED` and create users through
*Administration → Users & roles*.

## Collector API

Regional collectors authenticate with `X-API-Key` (created under *Administration → Collectors* or with
`python -m itam.cli create-collector NAME --region LIT`; only a hash is stored). A collector may only report on
branches in its own region.

```bash
# Poll results (every 1–5 min). Buffered results may carry their original timestamp.
curl -X POST $URL/api/v1/collector/poll -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '[{"asset_number":"CM-LIT-0012-RTR-00001","state":"DOWN","occurred_at":"2026-10-11T08:00:00Z","message":"ICMP timeout"},
       {"ip":"10.20.12.7","metrics":{"on_battery":true}}]'

# Syslog / traps / config changes
curl -X POST $URL/api/v1/collector/events -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '[{"ip":"10.20.12.1","kind":"CONFIG_CHANGE","message":"running-config changed by admin"}]'

# Discovery scan of a branch management VLAN
curl -X POST $URL/api/v1/collector/discovery -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"branch_code":"0012","devices":[{"ip":"10.20.12.1","mac":"00:11:22:33:44:55","serial":"FTX1234"}]}'
```

Devices are matched by asset number, serial, MAC, then IP.

## Configuration

Environment variables (prefix `ITAM_`):

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./itam.db` | SQLAlchemy URL. Use PostgreSQL in production. A plain `DATABASE_URL` (e.g. Render's `postgres://…`) is also accepted |
| `DEMO_SEED` / `DEMO_PASSWORD` | `false` / `ChangeMe!2026` | Load demo data on first start into an empty database; password for the demo users |
| `SECRET_KEY` | random per process | Session signing key. **Set it**, or sessions reset on restart |
| `COUNTRY_CODE` / `BANK_NAME` / `CURRENCY` | `CM` / `The Bank` / `XAF` | CC part of asset numbers; branding; currency shown for asset values |
| `MFA_REQUIRED_ROLES` | — | e.g. `ADMIN,CIO,CFO,CISO,IT_ASSET_MANAGER` |
| `SECURE_COOKIES` | `false` | Set `true` behind TLS |
| `MISSING_AFTER_HOURS` / `REMOVAL_ALERT_MINUTES` | 72 / 15 | Slide 18 / 20 thresholds |
| `COLLECTOR_STALE_MINUTES` | 30 | A collector silent this long raises an alert and pauses missing detection |
| `WARRANTY_WARNING_DAYS` | 90 | Warranty/EOS horizon |
| `SCHEDULER_ENABLED` / `SCHEDULER_INTERVAL` | `true` / 60 | Built-in job runner. Enable on **one** node only |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM` | — | E-mail delivery |
| `SMS_GATEWAY_URL` | — | JSON POST `{to, subject, text, type}` for SMS and voice |
| `CHAT_WEBHOOK_URL` | — | Teams/chat webhook |
| `SIEM_SYSLOG` | — | `host:port` for audit-log and alert forwarding |

Channels without a gateway still record every message in the **notification outbox** (*Administration → Notification outbox*).

## Operations

```bash
python -m itam.cli init-db                 # create schema
python -m itam.cli create-admin alice      # first administrator
python -m itam.cli run-jobs [--all]        # run scheduled jobs (cron alternative to the built-in scheduler)
python -m itam.cli verify-audit-log        # verify the hash chain (exit code 1 if tampered)
```

Scheduled jobs: alert escalation (1 min), notification delivery (1 min), collector health (5 min), missing
detection (15 min), warranty/EOL alerts (daily), weekly exception report.

**Deployment** (`Dockerfile`, `docker-compose.yml`): the compose file runs the app with PostgreSQL. For the
production topology in slide 15, run two app nodes behind a TLS load balancer (scheduler enabled on one), a 2-node
encrypted PostgreSQL cluster replicated to the DR site (RPO ≤ 15 min), and collectors on the management network.

## Development

```bash
pip install -r requirements-dev.txt
pytest            # 48 tests: business rules, workflows, monitoring, discovery, audits, security, HTTP flows
```

Code layout:

```
itam/
  models.py, enums.py      data model and controlled vocabularies
  numbering.py             asset number standard
  rbac.py                  roles, permissions, regional/branch scoping
  auditlog.py              hash-chained, append-only audit trail
  notifications.py         outbox + e-mail / SMS / voice / chat adapters
  services/                business logic (assets, requests, changes, monitoring, discovery,
                           audits, integrations, rollout, dashboard/KPIs, jobs)
  api/routes.py            REST API (collectors, integrations, read/act API)
  web/                     server-rendered UI (Jinja2), static CSS/JS (no inline scripts; strict CSP)
  seed.py, simulator.py    demo data and collector simulator
tests/
```

## Known gaps / next steps

- **Collectors** are an API contract. The repo includes a simulator but no SNMPv3/ICMP poller; use the chosen
  monitoring engine (Zabbix, OpManager, etc.) or a small poller that posts to the collector endpoints.
- **Active Directory / SSO** is not wired in: authentication is local with MFA. Add LDAP/SAML/OIDC before go-live.
- **Schema migrations**: the schema is created with `create_all`. Introduce Alembic before the first production upgrade.
- **ITSM tickets** use internal references (`INC-…`, `EXC-…`, `CHG-…`). Integrating with the Bank's ITSM tool is an extension point.
- **Login lockout** state is in memory per process. Use a shared store (e.g. Redis) when running several nodes.
