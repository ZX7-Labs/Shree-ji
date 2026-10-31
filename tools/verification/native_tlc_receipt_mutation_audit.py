#!/usr/bin/env python3
"""Fail-closed real-log mutation checks for the pinned private TLC result classifier.

Run only after a real source-exact expected-negative TLC model was accepted.
Inputs and derived traces remain in runner-private ephemeral storage. The public
output is a fixed count/status, never a model path, receipt or diagnostic text.
This is scoped adversarial evidence, not independent proof custody or release.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

FINISH = re.compile(r"^Finished in .+ at \([^)]+\)$", re.MULTILINE)
POSITIVE = "Model checking completed. No error has been found.\n"
WRONG_EXPECTATION = r"Invariant DefinitelyAbsentNegativeControl is violated"


def verify(classifier: Path, log: Path, original_rc: int, expectation: str) -> bool:
    if original_rc != 12 or not expectation or not classifier.is_file() or not log.is_file():
        return False
    try:
        body = log.read_text(encoding="utf-8")
        finished = FINISH.findall(body)
        if len(finished) != 1 or POSITIVE.strip() in body:
            return False
        if "DefinitelyAbsentNegativeControl" in body or "Synthetic unrelated error" in body:
            return False
        with tempfile.TemporaryDirectory(prefix="las-native-mutations-", dir=log.parent) as tmp:
            private = Path(tmp)

            def classify(text: str, java_rc: int, tee_rc: int, rule: str) -> int:
                test_log = private / "mutated.log"
                test_log.write_text(text, encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, "-I", "-B", str(classifier), str(test_log),
                     str(java_rc), str(tee_rc), "--expectation", rule],
                    cwd=private, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, check=False, timeout=12,
                    env={"PATH": os.defpath, "PYTHONNOUSERSITE": "1"},
                )
                return result.returncode

            # Non-vacuity: the very same private classifier must accept the
            # original real model trace before rejection tests mean anything.
            if classify(body, original_rc, 0, expectation) != 0:
                return False
            corruptions = [
                ("wrong-java-exit", body, 0, 0, expectation),
                ("failed-log-writer", body, 12, 1, expectation),
                ("wrong-invariant", body, 12, 0, WRONG_EXPECTATION),
                ("injected-positive", body + "\n" + POSITIVE, 12, 0, expectation),
                ("duplicate-finish", body + "\n" + finished[0] + "\n", 12, 0, expectation),
                ("missing-finish", body.replace(finished[0], "", 1), 12, 0, expectation),
                ("foreign-error", body + "\nError: Synthetic unrelated error\n", 12, 0, expectation),
            ]
            for name, altered, java_rc, tee_rc, rule in corruptions:
                if classify(altered, java_rc, tee_rc, rule) == 0:
                    return False
            return True
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        return False


def main() -> int:
    if len(sys.argv) != 5:
        print("LAS_NATIVE_MUTATION=FAIL:ARGUMENTS")
        return 2
    _, classifier, log, raw_rc, rule = sys.argv
    try:
        java_rc = int(raw_rc)
    except ValueError:
        print("LAS_NATIVE_MUTATION=FAIL:STATUS")
        return 2
    if not verify(Path(classifier), Path(log), java_rc, rule):
        print("LAS_NATIVE_MUTATION=FAIL:RECEIPT_OR_RED_CONTROLS")
        return 1
    print("LAS_NATIVE_MUTATION=PASS_7_REAL_LOG_RED_CONTROLS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
