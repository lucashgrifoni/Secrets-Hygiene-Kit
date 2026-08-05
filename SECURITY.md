# Security Policy

Do not include secret values in issues, pull requests, logs, screenshots, fixtures, or waiver
reasons. If you need to reference an exposed credential, use the provider, rule ID, redacted
fingerprint, file path, commit hash, and timestamp instead of the raw value.

This project does not revoke or rotate credentials automatically. Follow the relevant playbook,
rotate through the authoritative provider console or API, and preserve evidence without copying
the secret.

