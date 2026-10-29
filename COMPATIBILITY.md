# Compatibility

Validated with synthetic native boundaries, not a universal live T3 compatibility promise. Uses orchestration-v2 SQLite projections, existing MCP read APIs and optional private native orchestration RPC. Qualify your actual installed T3 version before enabling commands. No native patching is required or supported.

TypeScript source compiles to ESM `.mjs` with declarations and source maps.
`tsrs` is pinned to `0.20.1-ts7.1.0-beta`; the separate reference type checker is
TypeScript `7.0.2`. These are development/build dependencies, absent from the
running sidecar. The runtime protocol compatibility identifier stays `0.11.0`;
the package/release version is `0.1.0-alpha.2`. See the
[sidecar contract](docs/t3-sidecar.md) for the embedding API and type coverage.

Development toolchain: Node ^22.18.0 or ^24.11.0 or >=26.0.0; SQLite support is experimental in Node 22. Core synthetic tests are platform independent. Windows service, Keeper, fleet credential installation and tunnel onboarding scripts/tests are excluded because they are private operator adapters, not core requirements. Browser acceptance needs an explicitly supplied installed Chromium via T3_TEST_BROWSER_PATH and uses only synthetic identities/native recordings.

No provider/model changes, auto-renewal of execution grants, new credential bootstrap in read transport, native permission approval bypass or exactly-once execution guarantees.
