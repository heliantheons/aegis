# Aegis

This repository owns Helios authentication and authorization behavior.

## Boundaries

- Identity persistence and provisioning belong to Hermes.
- Reusable token, key, service, and guard packages belong to `heliantheon/aegis-go`.
- Domain-independent infrastructure belongs to `heliantheon/common`.
- Hermes protocol contracts belong to `heliantheon/hermes`; Aegis generates private client bindings from a fixed Schema tag.
- Kubernetes desired state belongs to the private `heliantheons/applications`
  repository. This public repository owns the image, not deployment manifests.

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
- Regenerate `internal/rpc/hermes/v1` whenever the pinned Hermes Schema tag changes.
