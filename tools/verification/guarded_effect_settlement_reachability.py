#!/usr/bin/env python3
"""Source-scoped, fail-closed production settlement-driver census.

This is a *necessary* release criterion only, never sufficient proof that
authenticated Reality evidence reaches a physical actuator or that the Root
persists it durably. Run against an exactly pinned PRIVATE commit and expose
only generic fixed markers in PUBLIC CI; never print private source paths.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
import tempfile
import unittest

CALL = re.compile(r"\.\s*persist_verified_settlement\s*\(")
OBSERVE_CALL = re.compile(r"\.\s*observe_reality\s*\(")
FN = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z_0-9]*)\b")
COMMENT = re.compile(r"//[^\n]*")
TEST_MARKER = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
MIN_MODULES = 80


def census(root: Path, min_modules: int = MIN_MODULES) -> tuple[int, int, int, int, int]:
    base = root / "src" / "effect_fabric"
    if not base.is_dir() or base.is_symlink():
        raise ValueError("source boundary missing")
    files = sorted(base.rglob("*.rs"))
    if len(files) < min_modules or any(p.is_symlink() for p in files):
        raise ValueError("source inventory incomplete")
    mandatory = (
        base / "root_guarded_effect_service.rs",
        base / "root_guarded_effect_runtime.rs",
        base / "guarded_effect_settlement.rs",
    )
    if any(not p.is_file() or p.is_symlink() for p in mandatory):
        raise ValueError("required trust-seam module absent")
    contents = [p.read_text(encoding="utf-8") for p in mandatory]
    if not (
        "fn observe_reality" in contents[0]
        and "fn persist_verified_settlement" in contents[0]
        and "record_effect_settlement" in contents[0]
        and "verified_settlement" in contents[1]
        and "verify_precommit_guarded_effect_settlement" in contents[1]
        and "verify_precommit_guarded_effect_settlement" in contents[2]
    ):
        raise ValueError("Root settlement trust seam changed without review")
    forwarders = test_calls = candidates = 0
    reality_forwarders = reality_test_calls = reality_drivers = 0
    for file in files:
        source = file.read_text(encoding="utf-8")
        # A lexical detector: comments and strings cannot establish production
        # reachability. This is a conservative candidate census, NOT AST proof.
        clean = COMMENT.sub("", source)
        is_test_file = file.name.endswith("_tests.rs") or file.name.startswith("test_")
        fns = list(FN.finditer(clean))
        markers = [m.start() for m in TEST_MARKER.finditer(clean)]
        for call in CALL.finditer(clean):
            preceding = [m for m in fns if m.start() < call.start()]
            if not preceding:
                raise ValueError("unattributed method call")
            fn = preceding[-1]
            # Test cfg in a mixed Rust file must not count as a driver.
            test_region = any(start < fn.start() for start in markers)
            if is_test_file or test_region:
                test_calls += 1
            elif fn.group(1) == "persist_verified_settlement":
                forwarders += 1
            else:
                candidates += 1
        for call in OBSERVE_CALL.finditer(clean):
            preceding = [m for m in fns if m.start() < call.start()]
            if not preceding:
                raise ValueError("unattributed Reality observation")
            fn = preceding[-1]
            test_region = any(start < fn.start() for start in markers)
            if is_test_file or test_region:
                reality_test_calls += 1
            elif fn.group(1) == "observe_reality":
                reality_forwarders += 1
            else:
                reality_drivers += 1
    if forwarders < 3 or test_calls < 2:
        raise ValueError("settlement reference census changed unexpectedly")
    if reality_forwarders < 3 or reality_test_calls < 1:
        raise ValueError("Reality reference census changed unexpectedly")
    return len(files), forwarders, test_calls, candidates, reality_drivers


class CensusTests(unittest.TestCase):
    def fixture(self, root: Path, runtime: str, tests: str = "") -> None:
        base = root / "src" / "effect_fabric"
        base.mkdir(parents=True, exist_ok=True)
        (base / "root_guarded_effect_service.rs").write_text(
            "fn persist_verified_settlement() { self.root.record_effect_settlement(&x);"
            " self.effects.verified_settlement(id); }\n"
            "fn observe_reality() {self.effects.observe_reality(obs);}\n", encoding="utf-8"
        )
        (base / "root_guarded_effect_runtime.rs").write_text(
            "fn verified_settlement() { verify_precommit_guarded_effect_settlement(a,b,c); }\n",
            encoding="utf-8"
        )
        (base / "guarded_effect_settlement.rs").write_text(
            "fn verify_precommit_guarded_effect_settlement() {}\n", encoding="utf-8"
        )
        (base / "root_supervisor_linux_service.rs").write_text(
            "fn persist_verified_settlement() { self.core.persist_verified_settlement(id); }\n"
            "fn observe_reality() {self.core.observe_reality(obs);}\n",
            encoding="utf-8"
        )
        (base / "root_supervisor_linux_deployment.rs").write_text(
            "fn persist_verified_settlement() { self.service.persist_verified_settlement(id); }\n"
            "fn observe_reality() {self.service.observe_reality(obs);}\n",
            encoding="utf-8"
        )
        (base / "root_supervisor_linux_production_runtime_facade.rs").write_text(
            "fn persist_verified_settlement() { self.service.persist_verified_settlement(id); }\n"
            "fn observe_reality() {self.service.observe_reality(obs);}\n",
            encoding="utf-8"
        )
        (base / "root_supervisor_linux_production_runtime.rs").write_text(
            runtime, encoding="utf-8"
        )
        (base / "root_supervisor_linux_test_tests.rs").write_text(
            tests or "fn test_only() { self.service.persist_verified_settlement(id);"
                     " self.service.persist_verified_settlement(id);"
                     " self.service.observe_reality(obs); }\n",
            encoding="utf-8"
        )

    def test_forwarders_and_tests_are_not_production_driver(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root, "fn idle() {}\n")
            result = census(root, min_modules=8)
            self.assertEqual(result[-1], 0)
            self.assertGreaterEqual(result[1], 3)
            self.assertEqual(result[2], 2)

    def test_nonforwarding_production_call_is_only_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root, "fn drive_verified_sensor() {"
                      " self.service.observe_reality(obs);"
                      " self.service.persist_verified_settlement(commit_id); }\n")
            self.assertEqual(census(root, min_modules=8)[-1], 1)

    def test_mixed_file_cfg_test_is_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root, "#[cfg(test)]\nmod tests {\n"
                      "fn test_drive() {self.service.observe_reality(obs);"
                      "self.service.persist_verified_settlement(id);}\n}\n")
            self.assertEqual(census(root, min_modules=8)[-1], 0)

    def test_missing_source_boundary_fails(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                census(Path(d), min_modules=0)

    def test_comment_cannot_create_driver(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root, "// fn run() {self.service.observe_reality(obs);"
                      "self.service.persist_verified_settlement(id);}\n")
            self.assertEqual(census(root, min_modules=8)[-1], 0)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--source-root", type=Path)
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(CensusTests)
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=0).run(suite)
        print("LAS_SETTLEMENT_CENSUS_SELFTEST=" + ("PASS" if result.wasSuccessful() else "FAIL"))
        return 0 if result.wasSuccessful() else 1
    if args.source_root is None:
        print("LAS_SETTLEMENT_REACHABILITY=FAIL:SOURCE_ROOT_MISSING")
        return 2
    try:
        module_count, forwarders, tests, driver_candidates, reality_drivers = census(args.source_root)
    except (OSError, UnicodeError, ValueError):
        print("LAS_SETTLEMENT_REACHABILITY=FAIL:SOURCE_OR_TRUST_SEAM_UNVERIFIED")
        return 2
    if driver_candidates == 0 or reality_drivers == 0:
        print("LAS_SETTLEMENT_REACHABILITY=FAIL:NO_NONFORWARDING_PRODUCTION_DRIVER")
        return 17
    # This is never evidence of physical reachability, only a review target.
    print("LAS_SETTLEMENT_REACHABILITY=CANDIDATE_FOUND_INDEPENDENT_REVIEW_REQUIRED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
