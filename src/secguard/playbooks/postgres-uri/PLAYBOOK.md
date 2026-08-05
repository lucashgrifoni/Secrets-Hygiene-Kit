# PostgreSQL Connection URI Leak Playbook

Vetted: 2026-08-04

## Scope

Use this playbook when a PostgreSQL connection URI containing credentials is exposed, for
example `postgresql://user:password@host:5432/database`. The URI leaks three things at once:
the credential, the hostname, and the database name.

Do not paste the full URI into tickets, chat, or logs. Reference the role and database name
without the password and host.

## Identify

- Record the repository path, commit hash, detector rule, timestamp, and the database and
  role names.
- Determine reachability first, because it decides the severity. Check whether the host
  resolves publicly, whether the security group, firewall, or `pg_hba.conf` allows access from
  the internet, and whether TLS is required.
- Identify the role's privileges: superuser, table ownership, `CREATE` rights, and access to
  other databases in the cluster.
- Confirm whether this is a production, staging, or local database. Local fixtures are the
  common false positive here and are a valid waiver candidate.

## Invalidate

- Change the role password with `ALTER ROLE ... WITH PASSWORD`.
- If the database is internet-reachable, restrict network access at the same time. Rotating a
  password on a publicly exposed database is half a fix.
- If abuse is suspected, revoke the role's connect privilege on the database while you
  investigate, then terminate its active sessions.

## Rotate

- Distribute the new credential through the approved secret manager or CI/CD variable store.
- Prefer short-lived credentials: IAM authentication on RDS or Cloud SQL, or a secrets manager
  with dynamic database credentials.
- Give the application a role scoped to the tables and operations it uses, rather than an
  owner or superuser role.
- Redeploy every consumer, including migrations, cron jobs, and analytics connections.

## Audit Usage

- Review connection logs for the exposure window: `log_connections`, `log_disconnections`, and
  the cloud provider's database logs.
- If connection logging was disabled, record that gap rather than reporting a clean window.
- Look for connections from unfamiliar client addresses, and for `CREATE ROLE`, `CREATE
  EXTENSION`, `COPY ... TO`, and large sequential scans on tables holding personal data.
- Check for new roles, changed grants, and objects created outside the application's schema.

## Communicate

- Notify the service owner, AppSec, and the database or platform owner.
- If personal data was reachable and access cannot be ruled out, involve privacy or legal for
  LGPD and GDPR assessment.
- State the exposure window, network reachability, what the audit covered, and residual risk.

## Close

- Remove the URI from source, artifacts, images, and CI logs.
- Add detection for database connection strings in pre-commit and CI.
- If the match was an intentional local fixture, replace the realistic value with an obviously
  fake one before opening a waiver.
- Record residual risk with an owner and a review date.
