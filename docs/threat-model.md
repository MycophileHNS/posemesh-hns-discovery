# Security Model & Threat Model

This document describes the security posture of `posemesh-hns-discovery`.

This repository is an unofficial prototype. It is not official Auki software, not endorsed by Auki Labs, and not a production Posemesh SDK. The model below is intended to make the prototype easier to review and safer to discuss.

## Assets This Prototype Tries To Protect

- The binding between a requested `.posemesh` subname and the discovery metadata returned to a client.
- The integrity of remote manifest JSON when strict signed-manifest mode is used.
- The availability of discovery results under malformed TXT records, oversized inputs, resolver failures, and manifest fetch failures.
- The clarity of failure modes for reviewers and future implementers.

## Trust Anchors

- TXT records for the requested `.posemesh` name may anchor manifest verification keys.
- Callers may also pass explicit trusted manifest verification keys.
- In strict mode, fetched manifests must be signed by an anchored or trusted key.
- Optional DANE TLSA validation can bind HTTPS certificate material to DNS-published TLSA records when the caller supplies a Handshake-aware TLSA resolver.

## Main Threats

### TXT Record Tampering

An attacker who can alter TXT lookup results could point a client at malicious metadata.

Current mitigations:

- Strict mode requires signed manifest envelopes for fetched manifests.
- Manifest signing keys must be anchored in TXT metadata or supplied by the caller.
- Multiple manifest URLs in TXT are treated as ambiguous and skipped.

Remaining production work:

- Auki would need an official key governance model, revocation process, and resolver policy.

### Manifest Tampering

An attacker who controls or intercepts the manifest host could return altered JSON.

Current mitigations:

- Strict mode fails closed unless the manifest signature verifies.
- Signed payloads are checked against the requested name and manifest URL.
- Signed payloads must include `issuedAt` and `expiresAt` in strict mode.

Remaining production work:

- Define canonical signing format, key rotation policy, and independent security review.

### Replay Attacks

An attacker could replay old but previously valid discovery metadata.

Current mitigations:

- Strict signed manifests require ISO-8601 `issuedAt` and `expiresAt`.
- The fetcher enforces clock skew, maximum TTL, and optional maximum age.
- Cache metadata reports freshness status.

Remaining production work:

- Auki would need operational TTL guidance and emergency revocation procedures.

### SSRF And Unsafe Manifest URLs

Manifest URLs could try to target localhost, private networks, link-local ranges, documentation ranges, multicast, or reserved addresses.

Current mitigations:

- Manifest URLs must use `https:`.
- Hostname resolution rejects the entire host if any resolved address is non-public.
- The HTTPS request is pinned to the checked address.
- Redirects are rejected.
- Response size and timeout limits are enforced.

Remaining production work:

- Run production clients in network-isolated environments and decide whether any private infrastructure exceptions are allowed.

### DNS Resolver Failure Or Disagreement

Different resolvers may return different answers or fail in different ways.

Current mitigations:

- Resolver results can include structured status, attempts, and error codes.
- `CompositeResolver` supports first-success, quorum, and strict-consensus strategies.
- DoH is implemented with native `fetch`; DoT is clearly marked as a prototype stub.

Remaining production work:

- Auki would need to select official resolver infrastructure, fallback behavior, and monitoring.

### Denial Of Service By Oversized Inputs

TXT records or manifests could be oversized or contain too many fields.

Current mitigations:

- TXT parser limits cover record count, record size, total size, field count, capability count, and public key count.
- Manifest limits cover strings, URLs, arrays, service categories, wallets, models, keys, and audiences.
- Manifest fetching enforces response byte limits.

Remaining production work:

- Tune limits against real Posemesh service metadata and production client memory budgets.

### Misleading Logs

Discovery logs can accidentally expose signatures, payloads, keys, pins, or other sensitive material.

Current mitigations:

- Logging is opt-in.
- Logger fields are structured.
- Common sensitive keys are redacted before calling the user-provided logger.
- Warnings and errors carry stable codes so callers do not need to parse messages.

Remaining production work:

- Auki would need central logging policy, privacy review, and operational retention rules.

### Packaging And Dependency Drift

A prototype that looks small can still become risky if dependencies or package contents drift unnoticed.

Current mitigations:

- The runtime library has no third-party runtime dependencies.
- Development dependencies are limited to TypeScript and Node.js type definitions.
- CI runs typecheck, tests, build, `npm audit`, and `npm pack --dry-run`.
- `package.json` uses an explicit package `files` allowlist.

Remaining production work:

- Auki would need release signing, provenance, dependency update policy, and a maintained vulnerability response process.

## Default Modes

- `strict`: default for live manifest fetching. Requires valid signed manifests and anchored keys.
- `permissive`: allows unsigned manifests, but verifies signed envelopes when present.
- `demo`: accepts unsigned or invalid signed manifests with explicit warnings.

Reviewers should treat `demo` and `permissive` as prototype conveniences, not production trust modes.

## What This Prototype Does Not Guarantee

- It does not prove that `.posemesh` is controlled by Auki.
- It does not define official Auki key management.
- It does not replace Posemesh APIs, the Posemesh Console, or Auki infrastructure.
- It does not make ordinary system DNS resolvers Handshake-aware.
- It does not implement a full production cache.
- It does not implement a production DoT resolver.
- It does not provide an official manifest schema.

## Recommended Production Review Checklist

- Confirm official namespace ownership and governance.
- Define the signed manifest schema and canonical serialization.
- Define key issuance, rotation, revocation, and emergency recovery.
- Decide resolver strategy and DANE TLSA requirements.
- Set production limits and cache policy from real deployment data.
- Decide package provenance, release signing, and CI requirements.
- Run external security review for SSRF, replay, downgrade, resolver disagreement, and operator impersonation.
