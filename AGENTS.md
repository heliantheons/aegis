# Aegis

This repository owns Helios authentication and authorization behavior.

## Boundaries

- Identity persistence and provisioning belong to Hermes.
- Reusable token, key, service, and guard packages belong to `heliantheon/aegis-go`.
- Domain-independent infrastructure belongs to `heliantheon/common`.
- Protocol contracts belong to `heliantheon/proto`.

## Commands

```bash
make test
make lint
make build
make run
```

## Verification

- Add tests for changes to OAuth, token, challenge, MFA, or identity-provider flows.
- Treat redirect validation, cookie policy, token claims, and key handling as security-sensitive.
- Update the matching document under `docs/` when behavior or protocol semantics change.
