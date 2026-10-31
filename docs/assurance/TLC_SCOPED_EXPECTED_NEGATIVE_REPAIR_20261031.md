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

## Exact canonical soundness alignment (subsequent quarantine repair)
The original public 207-profile audit used TLA+ 1.7.2, `-workers 2 -fp 0`, a globally supplied `-deadlock`, and root-relative TLC paths. The private exact-source canonical verifier at `fe6d42ea0512bca33c60289f7f07d69eafa7f410` instead pins TLA+ 1.7.4 by SHA-1 `bee4a54f3ee3d4afc347c3240ec2d9e93b075104`, uses `-workers auto -lncheck final -fp 0`, applies `-deadlock` only when its audited per-profile manifest requires it, and invokes TLC in the config/model directory. The isolated workflow has now been brought into alignment. It intentionally makes no claim about liveness proof completeness or runtime performance before native execution. A SHA-256 pin for this **new** 1.7.4 jar is not asserted until independently verified; do not reuse the older 1.7.2 SHA-256 digest.

**Review branch** `quarantine/tlc-expected-negative-audit-repair-20261031`; **draft PR** https://github.com/ZX7-Labs/Shree-ji/pull/12 into the already-quarantined scoped-native bridge, NOT `main`. The submitted PR and source are for independent validation, not accepted production behavior. A source-equivalent reference test is not a CI run of the edited YAML. The workflow execution remains unverified.

## Exact committed workflow native syntax preflight
A separate **public-only** preflight workflow `.github/workflows/tlc-audit-quick-preflight.yml` uses a pinned checkout on `ubuntu-24.04`, parses the *exact GitHub YAML* with Ruby Psych YAML, extracts and `bash -n` checks **all three actual Bash run blocks**, then Python-compiles the real embedded canonical-map extractor and asserts 207/12 scope, v1.7.4/final-liveness and non-leaking diagnostic markers. It has **no private repository token or private source access**.

Initial preflight run 41181942752 FAILED in the preflight **test harness**: the heredoc extraction regex accidentally matched the Python string containing the marker, causing an unterminated-triple-quote parse. The regex was repaired to anchor to the actual Bash `if ! python3 -I -B - ... <<'PY'` command. Re-run **41181976414 SUCCESS** on exact public controller SHA `63afc8f22074388a34739587b2f6c6a03391dd9c`, with YAML parse, all three `bash -n` checks and embedded Python syntax PASS. No private-source TLC was executed by this preflight. The first failure is retained as historical evidence; it is not counted as a product model error.

This newly executed preflight closes the edited-workflow **syntax** gap only. Complete Rust/Ada/SPARK/TLC, full private 207-profile model execution, independently approved test-plan custody, time/resource closure, physical Root/Reality and release acceptance remain OPEN.
