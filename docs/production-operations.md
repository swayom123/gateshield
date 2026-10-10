# Production Operations

## Deployment topology

Run one or more GateShield containers behind a trusted TLS ingress and connect all replicas to the same PostgreSQL database. The ingress authenticates application callers, limits request rates and connection counts, and enforces a body-size limit at least as strict as `GATESHIELD_MAX_REQUEST_BYTES`. GateShield does not provide general caller authentication, tenant isolation, or distributed rate limiting. Keep the database and provider endpoints on private networks.

Build the image with `docker build -t gateshield:release .`. The image runs as an unprivileged account and handles `SIGTERM` with a 30-second Uvicorn graceful-shutdown window. Run `alembic upgrade head` once as a release job using the same production environment before rolling out application replicas. Do not let every replica race to create or migrate the schema. Configure readiness probes against `/ready` and liveness probes against `/health`.

Required production configuration includes:

- `GATESHIELD_ENVIRONMENT=production`
- `GATESHIELD_DATABASE_URL=postgresql+asyncpg://...` and pool sizing appropriate to the database connection limit
- an HTTPS `GATESHIELD_PROVIDER_BASE_URL` and the correct `GATESHIELD_PROVIDER_TYPE`
- `GATESHIELD_CONSOLE_USERS` with at least one account, 16-character minimum passwords, and a supported role
- `GATESHIELD_LOGGING_MODE=METADATA_ONLY` or `REDACTED_CONTENT`
- a stable `GATESHIELD_APPLICATION_ID` and strong externally managed agent/approval keys when those features are enabled

Keep credentials in the deployment platform's secret store. Restrict console access at the ingress as well as using GateShield role checks. Rotate console credentials by deploying a newly generated account secret, confirming access, and removing the old credential in the same controlled rollout. Rotate agent enrollment and approval signing keys with an operational plan for outstanding agents and approvals; changing the signing key invalidates pending approvals. Never place production secrets in image layers or checked-in env files.

## Migrations and recovery

Back up PostgreSQL before schema changes. The CI job upgrades a clean SQLite database; test every migration against the PostgreSQL version used in deployment before release. Keep migrations backward-compatible during rolling deploys: expand schema first, deploy code, backfill if needed, then remove old schema in a later release.

Create a logical backup with a restricted backup identity:

```bash
pg_dump --format=custom --no-owner --file=gateshield-$(date -u +%Y%m%dT%H%M%SZ).dump "$GATESHIELD_BACKUP_URL"
```

Restore to a new database first, then validate schema and application records before switching the service:

```bash
createdb gateshield_restore
pg_restore --no-owner --dbname=gateshield_restore gateshield-backup.dump
GATESHIELD_DATABASE_URL='postgresql+asyncpg://user:password@host/gateshield_restore' alembic current
```

Use managed PostgreSQL point-in-time recovery for recovery point objectives that require continuous WAL archiving. Encrypt backups, restrict access, and periodically perform a restore exercise. Do not use an unverified backup as the only recovery copy.

## Retention and deletion

Set and document a retention window appropriate to the data protection policy and backup obligations. Preview deletion before applying it; use an ISO-8601 cutoff with timezone:

```bash
python scripts/expire_data.py --before 2026-01-01T00:00:00Z
python scripts/expire_data.py --before 2026-01-01T00:00:00Z --apply
```

The command removes matching request rows and their correlated security events, tool invocations, and behavior signals. Preview is the default. Console administration audit records are preserved by this command. Backups may retain deleted data until their own expiry; include backup retention and legal hold requirements in the deletion procedure.

## Monitoring and incident response

Application logs are JSON and include request and trace IDs where available. Forward them to a restricted log service and alert on repeated readiness failures, provider failures, denied requests, and database errors. Optional OTLP/HTTP tracing is enabled with the observability extra and the OpenTelemetry settings in the README. Spans include request/trace IDs and stage timing, but never prompt bodies, tool arguments, credentials, or provider responses. Preserve relevant audit records during an incident and follow the retention/legal-hold procedure before cleanup.

The current design does not provide SSO, organization isolation, or a general application authentication layer. Do not treat separate `application_id` values as a tenant boundary when callers can choose or spoof that identity.
