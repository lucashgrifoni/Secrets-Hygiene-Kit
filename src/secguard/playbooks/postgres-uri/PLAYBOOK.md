# PostgreSQL Connection URI Leak Playbook

Vetted: 2026-10-05

## Scope

Use this playbook when a PostgreSQL connection URI containing credentials is exposed, for
example `postgresql://user:password@host:5432/database`. The URI leaks three things at once:
the credential, the hostname, and the database name.

Do not paste the full URI into tickets, chat, or logs. Reference the role and database name
without the password and host.

## Identify

- Record the repository path, commit hash, detector rule, timestamp, and the database and
  role names.
- Determine reachability and privileges, because both affect impact. Check whether the host
  resolves publicly, whether the security group, firewall, or `pg_hba.conf` allows access from
  the internet, and whether TLS is required.
- Identify the role's privileges: superuser, table ownership, `CREATE` rights, and access to
  other databases in the cluster.
- Confirm whether this is a production, staging, or local database. A waiver requires proof
  that the fixture is synthetic; a local database can still have a real credential.

## Invalidate

- Change the role password with `ALTER ROLE ... WITH PASSWORD`.
- Use an approved password-handling path that keeps the value out of command history and
  logs. PostgreSQL recommends the interactive `\password` command in psql to avoid placing
  a cleartext password in an SQL statement. Verify that the active authentication method
  actually uses this password.
- If the database is internet-reachable, restrict network access at the same time. Rotating a
  password on a publicly exposed database is half a fix.
- Password changes do not end established sessions. If abuse is suspected, have the database
  owner block new logins with the appropriate role or authentication controls and terminate
  the affected sessions under an authorized recovery plan. Revoking a role's direct CONNECT
  grant alone may leave access through PUBLIC or another role.

## Rotate

- Distribute the new credential through the approved secret manager or CI/CD variable store.
- Prefer short-lived credentials: IAM authentication on RDS or Cloud SQL, or a secrets manager
  with dynamic database credentials.
- Give the application a role scoped to the tables and operations it uses, rather than an
  owner or superuser role.
- Apply each consumer's refresh or reconnect contract, including connection pools,
  migrations, cron jobs, and analytics connections. Verify new authenticated connections
  with the replacement and confirm the required session termination separately.

## Audit Usage

- Review connection logs for the exposure window: `log_connections`, `log_disconnections`, and
  the cloud provider's database logs.
- If connection logging was disabled, record that gap rather than reporting a clean window.
- Look for connections from unfamiliar client addresses, and for `CREATE ROLE`, `CREATE
  EXTENSION`, `COPY ... TO`, and large sequential scans on tables holding personal data.
- Check for new roles, changed grants, and objects created outside the application's schema.
- Connection logs do not establish which queries ran. Review statement or database audit
  coverage where available; record retention and interval gaps before concluding no data
  access occurred.

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

## References

- [Role password changes and safe password entry](https://www.postgresql.org/docs/current/sql-alterrole.html)
- [Login and role attributes](https://www.postgresql.org/docs/current/role-attributes.html)
- [CONNECT grants and PUBLIC privileges](https://www.postgresql.org/docs/current/ddl-priv.html)
- [Session termination and outcome semantics](https://www.postgresql.org/docs/current/functions-admin.html)

Confirm the deployed PostgreSQL version and the managed service's authentication and audit
features before acting.
