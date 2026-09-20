# GenosDB Audit

GenosDB-specific tools for reviewing Zero Trust audit receipts and recording the provenance of the official CDN release.

**Public preview, v0.1.0.** This repository publishes the defensive, command-line portion of a local audit project. It does not include the interactive protocol test runner, packet injection, vulnerability reproductions, raw audit records, or GenosDB binaries. It does not run a Zero Trust security campaign or prove that GenosDB is impenetrable.

## Quick Start

Requires Node.js 22 or newer and Git. No GenosDB installation, account, npm dependencies, Python, Bun, or browser is needed.

```sh
git clone https://github.com/estebanrfp/genosdb-audit.git
cd genosdb-audit
npm test
npm run audit:validate
npm run audit:plan
```

The included target and tests use **synthetic fixtures**, not a GenosDB instance. Their success confirms behavior of this reviewer only. All of these commands work offline after cloning.

## Official CDN

```sh
npm run cdn:verify
```

This is the only command that requires network access. It reads the official [GenosDB latest entry](https://cdn.jsdelivr.net/npm/genosdb@latest/dist/index.min.js), resolves the package version once, and fingerprints the entry and its version-pinned distribution modules. It also compares the latest entry bytes against the version-pinned entry to detect inconsistent alias resolution.

All requests are GETs to fixed paths at `cdn.jsdelivr.net`. Redirects are refused and responses have time and size limits. Downloaded JavaScript is hashed in memory, never imported or executed. The report is written to the ignored `.runtime/cdn.json`; a failed refresh replaces any earlier successful result.

`verified: true` means the observed version headers and entry bytes were consistent during this check. It is **not** a vulnerability verdict, an independent authenticity signature, or protection against a compromised package/CDN. The record contains the observation time, exact version, URLs, sizes and SHA-256 hashes. A mutable `latest` URL is not a reproducible version identifier by itself.

GenosDB remains separately licensed. This repository's MIT license does not relicense GenosDB or any artifacts inspected on the CDN.

## Evidence Review

```sh
node auditor/cli.mjs validate /path/to/target.json
node auditor/cli.mjs plan /path/to/target.json --json
node auditor/cli.mjs verify /path/to/target.json /path/to/receipt.json --json
```

The manifest format is described in [auditor/app-target.schema.json](auditor/app-target.schema.json); [examples/target.json](examples/target.json) is a minimal synthetic example. Paths resolve relative to the manifest as shown there. Keep real manifests, receipts, identities and evidence outside the repository.

The reviewer hashes local target artifacts and the declared adapter, builds a capability-based plan, and checks receipt fingerprints, counts, verdict requirements, coverage and recorded oracle assertions. Declared adapter code is **not executed**. Network origins in manifests must be loopback addresses; the reviewer does not connect to them.

Exit codes: `0` for a valid receipt with only PASS results, `1` for a valid receipt containing FAIL or INCONCLUSIVE, and `2` for input or receipt validation errors. The CDN command returns `1` on failure.

**Trust boundary:** receipt assertions are supplied by their producer. Evidence hash fields are checked for format, but the reviewer does not retrieve their referenced evidence bytes or independently observe delivery, state or plaintext. A self-consistent fabricated receipt can pass these checks. Human review and independently preserved evidence remain necessary.

## Scope and Status

The model describes 16 GenosDB Zero Trust families in [docs/verification-model.md](docs/verification-model.md). A plan is a list of obligations, not executed coverage. Non-GenosDB scanners, arbitrary remote targets and autonomous offensive workflows are outside this release.

See [RELEASE-STATUS.md](RELEASE-STATUS.md) for the validation boundary and unresolved historical result. Local audit records and reproduction code are intentionally not published. GitHub CI runs offline reviewer tests only; a green badge must not be interpreted as a GenosDB security certificate.

## Contributing

Keep contributions scoped to GenosDB evidence quality, passive provenance checks and reviewer reliability. Add offline synthetic tests for behavior changes. Do not include credentials, mnemonics, user data, absolute local paths, vulnerability payloads or raw audit records in commits or issues. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE), copyright 2026 Esteban Fuster Pozzi.
