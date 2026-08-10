# Aegis

Aegis is the authentication and authorization service for the Helios system. It handles OAuth flows, identity providers, MFA and WebAuthn, token issuance, sessions, and relationship-based access checks.

## Run locally

Aegis needs Redis and a running Hermes instance. Copy the example configuration and fill in the generated keys and provider credentials:

```bash
cp example.toml config.toml
make run
```

The HTTP server listens on port `18000` by default. Database-backed identity data is owned by Hermes; Aegis keeps short-lived flow and token state in Redis.

## Development

```bash
make test
make lint
make build
```

Design notes live in [`docs/`](docs/). Shared client and guard code is maintained in [`aegis-go`](https://github.com/heliantheon/aegis-go).
