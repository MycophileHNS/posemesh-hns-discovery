# Security Policy

## Prototype Status

`posemesh-hns-discovery` is an unofficial proof-of-concept repository for discussing Handshake `.posemesh` discovery for Posemesh.

It is not official Auki software, not endorsed by Auki Labs, and not a production Posemesh SDK. Do not treat this package as a trusted production discovery client without an independent security review and Auki-owned operational decisions.

## Supported Versions

| Version | Status |
| --- | --- |
| `0.1.x` | Prototype review only. Security fixes may be accepted, but there is no production support guarantee. |
| `<0.1.0` | Not supported. |

## Reporting Security Issues

Please do not publish exploit details in a public issue.

Preferred reporting path:

1. Use GitHub private vulnerability reporting or a private security advisory for this repository if it is enabled.
2. If private reporting is not enabled, open a minimal public issue asking the maintainer to enable a private disclosure channel. Do not include exploit details, private keys, live infrastructure targets, or sensitive resolver logs.

Useful report details include:

- affected version or commit
- whether the issue affects demo mode, live mode, or both
- a minimal reproduction using mock records when possible
- observed error codes or warnings
- impact on manifest verification, resolver trust, DANE/TLS behavior, SSRF protections, or parser limits

## Known Security Limitations

- This project does not prove that Auki controls `.posemesh`.
- The manifest schema is not an official Auki schema.
- Demo mode intentionally accepts unsigned or invalid signed manifests with warnings.
- Permissive mode accepts unsigned manifests and is not a production trust mode.
- DANE TLSA validation is opt-in and requires a Handshake-aware TLSA resolver for real `.posemesh` deployments.
- DNS-over-TLS is currently an explicit prototype stub.
- The core library reports cache policy metadata but does not implement a persistent client cache.
- Resolver consensus can reduce disagreement risk, but it does not replace a trusted resolver policy.
- No dependency, CI, or audit gate replaces a full production security review.

## Dependency Surface

The runtime library has no third-party runtime dependencies. Development dependencies are limited to TypeScript and Node.js type definitions.

CI runs:

- TypeScript typecheck
- Node test suite
- package build
- `npm audit`
- `npm pack --dry-run`

These gates are intended to catch obvious packaging and dependency problems before review. They are not a substitute for Auki-owned production hardening.
