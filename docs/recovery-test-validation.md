# Recovery integration validation

## Retained failure and diagnosis

PR48 head `0ae89e6b7e6f36d727fccfcab5f22ae1225576e7` inherited the
run405 aggregate failure (Node 26.12.1, native Windows): 72/75 passed.
The three failures were:

| Case                           | Actual failing boundary                                                    | Intended assertion                          |
| ------------------------------ | -------------------------------------------------------------------------- | ------------------------------------------- |
| Managed Windows retirement     | `legacy_process_probe_failed`, 10,648 ms total, from the bounded CIM child | Refuse open ingress                         |
| Principal expiry during upload | `central_transport_uncertain` in fixture's initial reserve                 | Refuse expired authority during import      |
| Frozen current-state resume    | `central_transport_uncertain` on the repeated challenge read               | Stable challenge and exact retirement proof |

The original native activity record is run405, position18479. The original
operation deadlines were 10 seconds. All three cases passed individually on
both the pre-fix PR head `0982e91` and `0ae89e6`. None of the recovery,
managed-retirement or transport source changed between those heads.

This establishes failure at prerequisite/process/transport boundaries, not a
failed recovery-policy assertion. The historical errors do **not** retain enough
detail to prove which OS/workerd stall caused them, or even distinguish every
possible transport error from its timeout. A green rerun cannot supply that
missing evidence. Workerd's previously observed pipe-abort remains a separate,
unresolved diagnostic.

## Bounded harness correction

The package previously ran six integration files concurrently by Node's default
CPU-count-based scheduling. Several files independently start workerd runtimes;
the retirement case also starts PowerShell/CIM. Run405 overlapped this aggregate
with compiler and secret-scan work. The harness had no process-heavy file budget.

`test:node` now explicitly admits one file at a time. `npm test` still builds,
runs the Workers suite, and then runs every Node integration file. Tests within
each file retain their existing behavior; concurrent admission/recovery tests
are not removed. No operation deadline, assertion, retry rule or production
setting changes. Do not run competing build/scanner lanes on the same local
workstation during timing-sensitive integration validation.

This corrects uncontrolled fixture fan-out, not a demonstrated production
recovery defect. Deterministic transport tests additionally cover a stall before
headers and while reading the body: 9,999 ms does not abort, 10,000 ms does, each
operation attempts once and reports uncertainty without leaking input. They do
not assert that either was the historical stall's cause.

## Evidence and remaining gates

Run413's unchanged six-file aggregate passed 75/75 in 25.2 seconds; that result
alone did not close the diagnosis. Local logs retain that run
(`grok-recovery-concurrent-413.txt`) and the bounded lane
(`grok-recovery-bounded-413.txt`) in the existing T3 scratch directory.
The bounded lane passed 76/76 in 38.9 seconds. The full package lane then passed
53 Workers tests and 76 Node tests (40.0 seconds for the Node phase), with the
previous pipe-abort still emitted. Both root compilers, formatting/lint,
control-plane typecheck and release validation passed. Node was 26.12.1;
hosted Node 22/24 qualification has not been rerun for this follow-up.

Promotion still requires the exact changed head's normal source/security checks,
hosted CI/CodeQL and current review. The earlier rate-limited review is not an
approval; no review retry or alternate identity is implied here. Merge and all
credential/grant/runtime activation remain held. No live recovery or Grok
activation is qualified by these synthetic tests.
