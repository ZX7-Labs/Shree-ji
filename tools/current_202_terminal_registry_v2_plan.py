#!/usr/bin/env python3
"""Deterministic execution-policy planner for the current-202 terminal registry v2."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable

import current_202_terminal_registry_v2 as registry

PLAN_SCHEMA = "las-current-202-terminal-registry-plan-v1"
PROFILE28 = 28


class PlanError(ValueError):
    pass


def _canonical_indices(values: Iterable[int]) -> list[int]:
    out = sorted(set(values))
    if not out:
        raise PlanError("expected replacement set must not be empty")
    for index in out:
        if not 0 <= index < 202 or index == 39:
            raise PlanError(f"replacement profile {index} is outside the generic non-39 domain")
    return out


def required_executor(index: int) -> str:
    return registry.V5_EXECUTOR_ID if index == PROFILE28 else registry.V4_EXECUTOR_ID


def build_plan(data: Any, expected_indices: Iterable[int], *, require_complete: bool) -> dict[str, Any]:
    doc = registry.validate_v2(data)
    expected = _canonical_indices(expected_indices)
    expected_set = set(expected)
    profiles = doc["profiles"]
    actual = {int(key) for key in profiles}
    extra = sorted(actual - expected_set)
    if extra:
        raise PlanError(f"registry contains non-required replacement profiles: {extra}")

    present: dict[str, Any] = {}
    missing: list[int] = []
    for index in expected:
        key = str(index)
        required = required_executor(index)
        entry = profiles.get(key)
        if entry is None:
            missing.append(index)
            continue
        if entry["executor_id"] != required:
            raise PlanError(
                f"profile {index} uses {entry['executor_id']!r}, but policy requires {required!r}"
            )
        present[key] = {
            "executor_id": required,
            "profile_binding_sha256": entry["profile_binding_sha256"],
            "terminal_run_id": entry["terminal_run_id"],
            "validation_job_id": entry["validation_job_id"],
            "terminal_job_id": entry["terminal_job_id"],
            "terminal_segment": entry["terminal_segment"],
            "migration_lineage": entry["migration_lineage"],
        }

    if require_complete and missing:
        raise PlanError(f"terminal registry is incomplete; missing profiles={missing}")

    dispatch = {
        str(index): {"executor_id": required_executor(index)}
        for index in missing
    }
    return {
        "schema": PLAN_SCHEMA,
        "registry_schema": registry.SCHEMA_V2,
        "expected_profiles": expected,
        "present": present,
        "missing": missing,
        "dispatch": dispatch,
        "complete": not missing,
    }


def _parse_indices(text: str) -> list[int]:
    parts = text.split()
    if not parts:
        raise PlanError("expected profile list is empty")
    values=[]
    for raw in parts:
        if not raw.isdigit() or str(int(raw)) != raw:
            raise PlanError(f"non-canonical profile index {raw!r}")
        values.append(int(raw))
    if len(values) != len(set(values)):
        raise PlanError("expected profile list contains duplicates")
    return values


def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser()
    parser.add_argument("registry")
    parser.add_argument("--expected", required=True, help="space-separated canonical generic replacement indices")
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--output")
    args=parser.parse_args(argv)
    try:
        data=json.loads(Path(args.registry).read_text(encoding="utf-8"))
        plan=build_plan(data, _parse_indices(args.expected), require_complete=args.require_complete)
        rendered=json.dumps(plan, indent=2, sort_keys=False)+"\n"
        if args.output:
            Path(args.output).write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        print("LAS_CURRENT_202_REGISTRY_V2_PLAN=PASS", file=sys.stderr)
        return 0
    except (OSError, json.JSONDecodeError, registry.RegistryError, PlanError, ValueError) as exc:
        print(f"LAS_CURRENT_202_REGISTRY_V2_PLAN_ERROR={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
