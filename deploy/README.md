# Kubernetes deployment contract

`deploy/` is Aegis' reusable, environment-neutral Kubernetes contract.

- `base/` owns the Deployment, Service, and dedicated ServiceAccount.
- `config/` owns non-sensitive defaults and documents required Secret keys.
- `ingress/` owns only the Aegis `/api` route; the Pallas UI owns `/`.

The private `heliantheon/applications` repository pins this contract and owns
the promoted image plus encrypted production Secret. CI must not edit this
directory.

