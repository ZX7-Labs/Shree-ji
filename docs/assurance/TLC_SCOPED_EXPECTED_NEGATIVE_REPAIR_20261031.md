# TLC audit semantic-gate repair — scoped quarantine checkpoint (2026-10-31)

## Exact change boundary
Public verification-controller repository: `ZX7-Labs/Shree-ji`.
Staging branch: `quarantine/tlc-expected-negative-audit-repair-20261031`.
Base controller revision: `8efff6cb7562cb3f148f2c0f24bdc18a3b907628`.
Original tracked workflow: `.github/workflows/assurance-all-tlc-audit-022.yml`.

The research-only 207-config TLC audit previously required **zero native exit and the positive no-error receipt for every profile**, including 12 deliberately negative source-pinned invariant probes. Its short-lived negative-case failure could therefore be a healthy counterexample rejected by an incorrect verification wrapper. No model-level counterexample classification is claimed without its raw private receipt.

## Quarantined source correction
- Derive the case-to-model mapping, deadlock exception, and exact expected invariant from the **private exact-revision canonical map generator**. Refuse absent/ambiguous map or a profile-count mismatch.
- Require exactly 207 source-controlled profiles and 12 declared negative controls; reject a negative profile without a rule and a positive profile with one.
- Let the canonical private TLC receipt classifier require native exit 12 plus the *specified* invariant violation for a negative; require native exit 0 plus complete state-space evidence for a positive. Crashes, stale output and surprise clean negatives are not success.
- Distinguish time/resource interruption from completed verification.
- Eliminate publicly printed deterministic profile-path hashes, which can be dictionary-matched to possible private names. Raw case logs and receipt details remain runner-private.
- Preserve the exact private revision proof, tool hash pins, private source recovery, tracked-file checks, clean-tree check and scoped-not-release status.

## Verification evidence and limits
- Source-read audit identified the mismatch in the canonical verifier's 12 negative controls vs the old public audit's uniform positive success test.
- A **separate local reference case gate** and synthetic 207-case source-plan test suite ran 26/26 tests PASS. They test intended semantics; they do **not** compile or execute the edited GitHub YAML.
- **No GitHub workflow run, no exact-workflow YAML + Bash parse receipt, and no native 207-profile PASS** are claimed for this staged change. The commit uses `[skip ci]` to avoid unrequested runner consumption.
- Existing 9-minute per-case cut-off and 95-minute shard run ceiling may produce INCOMPLETE results for large models. Do not turn a resource timeout into success or imply the all-profile audit is practical without measured capacity.
- The source-owned manifest is not independent approval custody. This remains research evidence, not promotion authority.

## Before any merge
Obtain an independent review of the workflow and privacy handling; run actual YAML / Bash / Python syntax tests against the *exact committed bytes*; run native negative and positive TLC fixtures using the pinned jar; run all source-mandatory profiles with valid full evidence and distinguish timeout/resource issues from model failures. Then separately re-evaluate actual physical Root-to-Reality, antirollback and other production gates. Never merge into production or claim the entire system is green based on this scoped work.
