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
The original public 207-profile audit used TLA+ 1.7.2, `-workers 2 -fp 0`, a globally supplied `-deadlock`, and root-relative TLC paths. The private exact-source canonical verifier at `the privately pinned candidate identified by the public one-way revision proof` instead pins TLA+ 1.7.4 by SHA-1 `bee4a54f3ee3d4afc347c3240ec2d9e93b075104`, uses `-workers auto -lncheck final -fp 0`, applies `-deadlock` only when its audited per-profile manifest requires it, and invokes TLC in the config/model directory. The isolated workflow has now been brought into alignment. It intentionally makes no claim about liveness proof completeness or runtime performance before native execution. A SHA-256 pin for this **new** 1.7.4 jar is not asserted until independently verified; do not reuse the older 1.7.2 SHA-256 digest.

**Review branch** `quarantine/tlc-expected-negative-audit-repair-20261031`; **draft PR** https://github.com/ZX7-Labs/Shree-ji/pull/12 into the already-quarantined scoped-native bridge, NOT `main`. The submitted PR and source are for independent validation, not accepted production behavior. A source-equivalent reference test is not a CI run of the edited YAML. The workflow execution remains unverified.

## Exact committed workflow native syntax preflight
A separate **public-only** preflight workflow `.github/workflows/tlc-audit-quick-preflight.yml` uses a pinned checkout on `ubuntu-24.04`, parses the *exact GitHub YAML* with Ruby Psych YAML, extracts and `bash -n` checks **all three actual Bash run blocks**, then Python-compiles the real embedded canonical-map extractor and asserts 207/12 scope, v1.7.4/final-liveness and non-leaking diagnostic markers. It has **no private repository token or private source access**.

Initial preflight run 41181942752 FAILED in the preflight **test harness**: the heredoc extraction regex accidentally matched the Python string containing the marker, causing an unterminated-triple-quote parse. The regex was repaired to anchor to the actual Bash `if ! python3 -I -B - ... <<'PY'` command. Re-run **41181976414 SUCCESS** on exact public controller SHA `63afc8f22074388a34739587b2f6c6a03391dd9c`, with YAML parse, all three `bash -n` checks and embedded Python syntax PASS. No private-source TLC was executed by this preflight. The first failure is retained as historical evidence; it is not counted as a product model error.

This newly executed preflight closes the edited-workflow **syntax** gap only. Complete Rust/Ada/SPARK/TLC, full private 207-profile model execution, independently approved test-plan custody, time/resource closure, physical Root/Reality and release acceptance remain OPEN.

## First exact-source native two-case smoke (actual CI)
Public standard-runner workflow `.github/workflows/quarantine-two-case-tlc-smoke.yml` recovers exact private SHA proof `1adce8a16b15daa5022b11634ffccb7c21785e6ccb449a6055acf2e2d5514e43`, checks its pinned private test-runner identity, downloads the exact private-canonical TLA+ 1.7.4 SHA-1 jar, derives 207 profiles and 12 expected negatives through the pinned canonical map and keeps raw model/log data private.

**Run 41182126237:** source/tool admission PASS; canonical 207/12 map PASS; **first real expected-negative TLC profile actually passed the exact source-owned invariant/Java-exit/finished-record classifier** at 2026-10-31 07:49:51 UTC. The independently selected small-file **positive** profile did not finish before the conservative 4-minute bound and correctly yielded `INCOMPLETE:RESOURCE_BOUND` at 07:53:51 UTC; job FAIL. The positive timeout is not a model defect, and the first native negative PASS does **not** certify all 12 negative controls. This is important non-vacuous evidence that a native expected negative *can* be treated correctly, unlike the original uniformly-positive audit.

**Next controlled experiment:** The follow-up two-case smoke selects the positive from two source-matched, historically native-tested positive smoke profiles (from the pinned public two-profile workflow), while still using current canonical TLA+ **1.7.4 and final liveness**. Historical 1.7.2 green is only selection guidance, not current proof. No complete candidate or release acceptance is implied.

## Native source-bound positive + expected-negative verified (2026-10-31)
After the first smoke's valid negative and bounded positive timeout, profile selection was narrowed to a **historically scoped positive candidate** already tracked in `assurance-tlc-two-profile-021.yml`, but execution now uses **new canonical TLA+ 1.7.4**, canonical model mapping, `-lncheck final`, source-pinned exact current private SHA, and the current private receipt classifier. The second actual native run **41182486999** passed both the expected-negative case and completed positive profile under pinned-source checks: https://github.com/ZX7-Labs/Shree-ji/actions/runs/41182486999. This is exactly **two profiles**, not all 207.

Both new quarantine workflows' checkout dependency was then upgraded from pinned v4.2.2 (deprecated Node20 runtime warning) to official **actions/checkout v5.0.0** Node24 commit `08c6903cd8c0fde910a37f88322edcfb5dd907a8`, verified against the upstream official Git ref. `persist-credentials: false` remains set. Exact public-source syntax preflight run **41182554123** PASS: https://github.com/ZX7-Labs/Shree-ji/actions/runs/41182554123. Final v5 native two-case run **41182557495** PASS with both genuine TLC case receipts, no private source filenames in public completion messages and no Node20 deprecation warnings: https://github.com/ZX7-Labs/Shree-ji/actions/runs/41182557495.

**Do not reinterpret:** two-case native-green and edited source static preflight are **scoped acceptance evidence only**. The 207-case old run 41178481890 ended FAIL in all eight shards; seven are slow model cases/possible resource-bound incompletes, and one was an expected-negative probe misclassified by the legacy positive-only runner. Nothing here certifies the remaining 205 cases, all independent Python MUST-RUN obligations, complete canonical Rust/Ada/SPARK/FFI, release/custody approval, or real physical Root/Reality. `main`, previous PRs and original proof history remain unchanged.

## All 12 canonical negative controls: native exact-source evidence

The isolated `.github/workflows/quarantine-all-negative-tlc-controls.yml` validates the **source-pinned 207-case census with 12 negative and 195 positive classifications**, and runs *each of the 12* negative configurations using pinned TLA+ 1.7.4 and canonical `-lncheck final` flags. The native private receipt classifier demands Java exit 12, exactly the specified invariant counterexample, a valid finished marker, and no runtime/checker failure; an unexpected clean run or other invariant cannot pass.

- GitHub Actions **41182646853**: **SUCCESS**, 12/12 native negative counterexamples matched the exact pinned source-owned invariant rules, no private model names printed in completion output.
- Follow-up privacy-hardening kept Python plan tracebacks and source paths private rather than allowing them in public logs. Exact-source rerun **41182719585**: **SUCCESS**, again 12/12 native negatives with protected plan output. Private source pin and TLA jar SHA-1 were checked by the runner, and the job was not considered a release proof.
- Repeated private-source positive/negative smoke with the same plan-output hardening: **41182722071 SUCCESS**.

This closes the *bounded, source-controlled native 12-negative test execution* gap for the source revision under test. It does **not** establish independent obligation-plan custody, all 195 positive model-check results, formal refinement from abstract models to Rust/Ada implementation, externally authenticated Reality events or real hardware Root effects. The 12 expected failures are **tests that intentionally exhibit violations**; they must not be misreported as safe-positive model executions.

**Adversarial limitation:** private-side canonical generator and classifier still share project custody; the pinned checkout plus public runner pin prevents silent substitution for this test, but it is not independent approval for future source versions. No 207/207 full acceptance or protected main promotion is asserted.


## Canonical TLA+ 1.7.4 dual-checksum pin and native rerun

The official TLA+ 1.7.4 jar already pinned by canonical SHA-1 `bee4a54f3ee3d4afc347c3240ec2d9e93b075104` was byte-hashed by a real authorized public compute runner after exact private source/tool admission. **Run 41182883770** emitted the *public tool artifact* SHA-256 `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`, and all 12 native negatives completed successfully. This is a newly measured SHA-256 for **1.7.4**; it is not the older SHA-256 of 1.7.2.

The isolated 207-profile controller now **requires both SHA-1 and SHA-256** for that exact official jar, failing closed on either mismatch. Its exact GitHub workflow YAML, all three Bash scripts and embedded Python passed public-native syntactic preflight **41182941798**. The all-12 negative workflow independently asserts the new source-workflow SHA-256 pin is present and re-runs the pinned private 12-case matrix; **41182968434 SUCCESS**. This adds a real second native download+hash confirmation, not merely a static copied digest.

**Status remains SCOPED-TESTED / NO MERGE.** It does not certify 195 positive model executions, slow checkpoint/restart, physical Root or independent approval custody. No production `main` files were changed.


## Native TLC checkpoint/restart feasibility — exact-source evidence
<https://github.com/ZX7-Labs/Shree-ji/actions/runs/41182769611> **completed SUCCESS**. The exact private candidate was source-checked, canonical TLA+ 1.7.4 artifact pinned, and one intentionally slow positive model selected from the canonical 207-profile map. On the live GitHub Linux runner, the first `-checkpoint 1` slice completed a genuine TLC barrier under current `-lncheck final` semantics and yielded checkpoint queue/variable files. After an intentional resource-bounded interruption, TLC launched with `-recover` from the same immutable in-run source/tool/metadata and produced a **distinct later checkpoint** in a second bounded slice. No private model filename or source was printed. Stage markers `FIRST_REAL_BARRIER_COMPLETE` then `RESTARTED_AND_ADVANCED_CHECKPOINT_NOT_MODEL_PASS` and `SCOPED_SAME_RUNNER_FEASIBILITY_ONLY_NOT_RELEASE` are in the actual job log.

This proves a nontrivial local checkpoint/restart capability on one slow source-bound profile, **not** completion of that model, cross-run artifact custody, checkpoint authentication, crash-proof exactly-once semantics, all-207 formal acceptance, or any production permission. Next engineering should bind resumable checkpoints to source SHA/verified tree, exact canonical cfg/TLA content, verifier + tool binary, TLC runtime fingerprint, plan identity, slot/attempt ordinal, and protected independent HMAC/nonce provenance; reject archives from other source, worker profile or run. A formerly green historical 202-profile checkpoint must NEVER silently carry into current 207 acceptance. A full candidate still requires every positive+negative receipt and independent release review.

## Native real-log mutation challenge: all 12 accepted counterexamples (2026-10-31)

Added the public-source, runner-private `tools/verification/native_tlc_receipt_mutation_audit.py` and integrated it into the quarantined 12-negative native workflow. For **each of the 12 real TLC counterexample traces**, the exact private classifier reaccepts the original and must reject seven independently perturbed cases: wrong Java exit, failed log writer, wrong expected invariant, injected positive banner, duplicated finish marker, missing finish marker, and foreign error record. Any accepted corruption aborts the job, and all inputs/outputs are discarded from private ephemeral space; only fixed audit markers enter public logs.

**GitHub Actions run 41183162281 completed SUCCESS**: source/tool pins, canonical plan 207/12 census, 12 native expected counterexample receipts, and **84/84 real-log corruption rejections** passed. Native source and public candidate remain isolated; these are tests of the receipt classifier, not formal proofs for the remaining 195 positive configurations.

**Adversarial limits:** these seven mutations do not cover every possible JVM/OS failure or model-checker bug; the classifier is still source-owned, and a passing self-test is not independent release approval.


## Strengthened recovery witness (not model completion)

The checkpoint/restart feasibility workflow was additionally hardened to require TLC's **own recovery-start message in the private second-slice log**, not only a changed checkpoint-file hash. Private Python planner errors are no longer echoed into the public Actions console. **Run 41183266981 completed SUCCESS:** source/tool admission, first genuine checkpoint barrier, native TLC recovery startup evidence, and distinct later checkpoint all passed. The output still explicitly says `RESTARTED_AND_ADVANCED_CHECKPOINT_NOT_MODEL_PASS`. This proves same-run recovery on one slow case; it does not authorize cross-run upload or establish that the positive model completed.


## Cross-job encrypted checkpoint: real private-source continuation, security HOLD

**Run 41183395437 completed SUCCESS on its original workflow revision `fa7f3adce8...`.** The producer used the exact immutable private source/canonical TLA+ 1.7.4 to create a real bounded checkpoint, then encrypted its metadata bundle and generated a separate HMAC. Only an encrypted artifact and HMAC were uploaded (Actions artifact `las-quarantine-checkpoint-ciphertext`, approximately 47 MB, configured one-day retention). In an **independent second GitHub job**, the consumer downloaded it, re-fetched the exact source/tool, verified the HMAC before decryption, rejected a flipped-ciphertext mutant, checked encrypted identity/manifest source+tool+profile+Java/workers, and invoked real TLC `-recover`. It produced an advanced later checkpoint and finished the scoped job. Public markers were `AUTHENTICATION_AND_TAMPER_REJECTION_PASS`, `SEALED_DIFFERENT_JOB_RECOVERY_ADVANCED_NOT_MODEL_PASS` and `SCOPED_ARTIFACT_CUSTODY_FEASIBILITY_NOT_RELEASE`.

**This does NOT prove model checking completed, production-safe persistence, archive antirollback, independent protected custody, or private checkpoint export authorization.** In particular, the earlier proof's encryption/MAC context used workflow SHA and run ID, but lacked the GitHub run **attempt** ordinal; a retry within one run is therefore a replay ambiguity. The subsequent **unexecuted quarantine patch** adds `GITHUB_RUN_ATTEMPT` consistently to encryption/MAC derivation and authenticated identity plus producer/consumer manifest checks; its exact YAML/Bash/Python syntax was checked by public-only preflight **41183780345 PASS**. That static check does not authenticate a real artifact or certify the revised crypto contract.

**Owner/security decision required before further public artifact uploads or promotion:** the original private/public bridge authorizes encrypted **diagnostics**, but a TLC checkpoint is a potentially proprietary *source-derived state artifact*. This new data class requires explicit confidentiality/retention approval and independent adversarial review of key custody, encryption/MAC, arbitrary TAR member handling, wrong key/attempt/replay, and rollback. A review HOLD is recorded on draft PR #12. The project must not silently count the research-only encrypted checkpoint as production accepted.

