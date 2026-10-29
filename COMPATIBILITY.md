# Compatibility

Validated with synthetic native boundaries, not a universal live T3 compatibility promise. Uses orchestration-v2 SQLite projections, existing MCP read APIs and optional private native orchestration RPC. Qualify your actual installed T3 version before enabling commands. No native patching is required or supported.

Development toolchain: Node ^22.18.0 or ^24.11.0 or >=26.0.0; SQLite support is experimental in Node 22. Core synthetic tests are platform independent. Windows service, Keeper, fleet credential installation and tunnel onboarding scripts/tests are excluded because they are private operator adapters, not core requirements. Browser acceptance needs an explicitly supplied installed Chromium via T3_TEST_BROWSER_PATH and uses only synthetic identities/native recordings.

No provider/model changes, auto-renewal of execution grants, new credential bootstrap in read transport, native permission approval bypass or exactly-once execution guarantees.
