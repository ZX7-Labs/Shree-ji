#!/usr/bin/env python3
"""Fail-closed schema tooling for current-202 non-39 terminal attestations.

This module deliberately separates immutable executor provenance from per-profile
terminal evidence. It supports a single lossless migration from the historical
v1 registry into v2 and strict validation of v2 documents.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping

SCHEMA_V1 = "las-current-202-non39-terminal-registry-v1"
SCHEMA_V2 = "las-current-202-non39-terminal-registry-v2"
V4_EXECUTOR_ID = "current-202-v4"
V5_EXECUTOR_ID = "current-202-v5-storage-repair-exp1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")

V4_EXECUTOR = {
    "protocol": "current-202-v4",
    "runner_ref": "current-202-tlc-continuation-v4-runner",
    "runner_sha": "3d37edb1debc9a4dd32da51ec3164840dbc4b252",
    "wrapper_workflow_path": ".github/workflows/private-assurance-slow-tlc-continuation.yml",
    "wrapper_workflow_blob": "70b8c18144f55625460e86337e8c5999a699facf",
    "slice_workflow_path": ".github/workflows/_private-assurance-tlc-continuation-slice.yml",
    "slice_workflow_blob": "30f44487a8d433045bfc5c3310aa7356a5b8d2ea",
    "checkpoint_schema": "current-202-periodic-barrier-v4",
    "tlc_workers": 4,
}

V5_EXECUTOR = {
    "protocol": "current-202-v5-storage-repair-exp1",
    "runner_ref": "current-202-tlc28-v5-storage-repair-experiment",
    "runner_sha": "dc7221eb78f71256fde7e532145de21cb3b3aa66",
    "wrapper_workflow_path": ".github/workflows/private-assurance-slow-tlc-continuation.yml",
    "wrapper_workflow_blob": "df1a4ef27481e378b32b72c01dc945e94f6010b7",
    "slice_workflow_path": ".github/workflows/_private-assurance-tlc-continuation-slice.yml",
    "slice_workflow_blob": "646b27926b4f934369158d93a601f600e9b24ea4",
    "checkpoint_schema": "current-202-periodic-barrier-v5-storage-repair-exp1",
    "tlc_workers": 4,
}

COMMON_KEYS = (
    "private_snapshot_proof",
    "private_tree_proof",
    "canonical_verifier_blob",
    "tlc_map_sha256",
)
TERMINAL_KEYS = (
    "profile_binding_sha256",
    "terminal_run_id",
    "validation_job_id",
    "terminal_job_id",
    "terminal_segment",
    "terminal_job_log_sha256",
    "tlc_log_sha256",
    "states_generated",
    "distinct_states",
    "states_left_on_queue",
    "cut_reason",
    "result",
)


class RegistryError(ValueError):
    pass


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RegistryError(f"{label} must be an object")
    return value


def _exact_keys(obj: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(obj)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise RegistryError(f"{label} keys mismatch missing={missing} extra={extra}")


def _hex(value: Any, n: int, label: str) -> str:
    regex = HEX40 if n == 40 else HEX64
    if not isinstance(value, str) or not regex.fullmatch(value):
        raise RegistryError(f"{label} must be {n}-hex")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RegistryError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RegistryError(f"{label} must be a non-negative integer")
    return value


def _validate_executor(executor_id: str, raw: Any) -> dict[str, Any]:
    obj = _object(raw, f"executor {executor_id}")
    expected = {
        "protocol", "runner_ref", "runner_sha", "wrapper_workflow_path",
        "wrapper_workflow_blob", "slice_workflow_path", "slice_workflow_blob",
        "checkpoint_schema", "tlc_workers",
    }
    _exact_keys(obj, expected, f"executor {executor_id}")
    for key in ("protocol", "runner_ref", "wrapper_workflow_path", "slice_workflow_path", "checkpoint_schema"):
        if not isinstance(obj[key], str) or not obj[key]:
            raise RegistryError(f"executor {executor_id}.{key} must be non-empty text")
    _hex(obj["runner_sha"], 40, f"executor {executor_id}.runner_sha")
    _hex(obj["wrapper_workflow_blob"], 40, f"executor {executor_id}.wrapper_workflow_blob")
    _hex(obj["slice_workflow_blob"], 40, f"executor {executor_id}.slice_workflow_blob")
    if obj["tlc_workers"] != 4:
        raise RegistryError(f"executor {executor_id}.tlc_workers must remain 4")

    canonical = {V4_EXECUTOR_ID: V4_EXECUTOR, V5_EXECUTOR_ID: V5_EXECUTOR}.get(executor_id)
    if canonical is None:
        raise RegistryError(f"unknown executor id {executor_id!r}")
    if obj != canonical:
        raise RegistryError(f"executor {executor_id} does not match its immutable canonical descriptor")
    return obj


def _validate_lineage(raw: Any, *, executor_id: str, label: str) -> dict[str, Any] | None:
    if executor_id == V4_EXECUTOR_ID:
        if raw is not None:
            raise RegistryError(f"{label}.migration_lineage must be absent for v4 evidence")
        return None
    if executor_id != V5_EXECUTOR_ID:
        raise RegistryError(f"{label} uses unsupported executor {executor_id!r}")
    obj = _object(raw, f"{label}.migration_lineage")
    expected = {
        "source_executor_id", "source_run_id", "source_segment", "source_artifact",
        "source_checkpoint_digest", "bootstrap_run_id",
    }
    _exact_keys(obj, expected, f"{label}.migration_lineage")
    if obj["source_executor_id"] != V4_EXECUTOR_ID:
        raise RegistryError(f"{label}.migration_lineage must originate from {V4_EXECUTOR_ID}")
    _positive_int(obj["source_run_id"], f"{label}.migration_lineage.source_run_id")
    _positive_int(obj["source_segment"], f"{label}.migration_lineage.source_segment")
    _positive_int(obj["bootstrap_run_id"], f"{label}.migration_lineage.bootstrap_run_id")
    if not isinstance(obj["source_artifact"], str) or not obj["source_artifact"]:
        raise RegistryError(f"{label}.migration_lineage.source_artifact must be non-empty text")
    digest = obj["source_checkpoint_digest"]
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise RegistryError(f"{label}.migration_lineage.source_checkpoint_digest must be sha256:<64-hex>")
    return obj


def _validate_profile(index: int, raw: Any, executors: Mapping[str, Any]) -> dict[str, Any]:
    label = f"profile {index}"
    obj = _object(raw, label)
    expected = set(TERMINAL_KEYS) | {"executor_id", "migration_lineage"}
    _exact_keys(obj, expected, label)
    executor_id = obj["executor_id"]
    if not isinstance(executor_id, str) or executor_id not in executors:
        raise RegistryError(f"{label}.executor_id does not name a declared executor")
    _validate_lineage(obj["migration_lineage"], executor_id=executor_id, label=label)
    _hex(obj["profile_binding_sha256"], 64, f"{label}.profile_binding_sha256")
    for key in ("terminal_run_id", "validation_job_id", "terminal_job_id", "terminal_segment"):
        _positive_int(obj[key], f"{label}.{key}")
    _hex(obj["terminal_job_log_sha256"], 64, f"{label}.terminal_job_log_sha256")
    _hex(obj["tlc_log_sha256"], 64, f"{label}.tlc_log_sha256")
    for key in ("states_generated", "distinct_states", "states_left_on_queue"):
        _nonnegative_int(obj[key], f"{label}.{key}")
    if obj["cut_reason"] != "none":
        raise RegistryError(f"{label}.cut_reason must be 'none' for terminal PASS evidence")
    if obj["states_left_on_queue"] != 0:
        raise RegistryError(f"{label}.states_left_on_queue must be zero for terminal PASS evidence")
    if obj["result"] != "PASS":
        raise RegistryError(f"{label}.result must be PASS")
    return obj


def validate_v2(data: Any) -> dict[str, Any]:
    obj = _object(data, "registry")
    expected = {"schema", *COMMON_KEYS, "executors", "profiles"}
    _exact_keys(obj, expected, "registry")
    if obj["schema"] != SCHEMA_V2:
        raise RegistryError(f"registry.schema must be {SCHEMA_V2}")
    _hex(obj["private_snapshot_proof"], 64, "private_snapshot_proof")
    _hex(obj["private_tree_proof"], 64, "private_tree_proof")
    _hex(obj["canonical_verifier_blob"], 40, "canonical_verifier_blob")
    _hex(obj["tlc_map_sha256"], 64, "tlc_map_sha256")

    executors = _object(obj["executors"], "executors")
    if not executors:
        raise RegistryError("executors must not be empty")
    for executor_id in sorted(executors):
        if not isinstance(executor_id, str) or not executor_id:
            raise RegistryError("executor id must be non-empty text")
        _validate_executor(executor_id, executors[executor_id])

    profiles = _object(obj["profiles"], "profiles")
    normalized_keys: set[str] = set()
    for key, raw in profiles.items():
        if not isinstance(key, str) or not DECIMAL.fullmatch(key):
            raise RegistryError("profile keys must be canonical decimal indices")
        index = int(key)
        if not 0 <= index < 202 or index == 39:
            raise RegistryError(f"profile index {index} is outside the generic non-39 domain")
        canonical = str(index)
        if canonical != key or canonical in normalized_keys:
            raise RegistryError("profile keys are not canonical and unique")
        normalized_keys.add(canonical)
        _validate_profile(index, raw, executors)
    return obj


def migrate_v1(data: Any) -> dict[str, Any]:
    src = _object(data, "v1 registry")
    expected = {"schema", *COMMON_KEYS, "runner_sha", "wrapper_workflow_blob", "slice_workflow_blob", "profiles"}
    _exact_keys(src, expected, "v1 registry")
    if src["schema"] != SCHEMA_V1:
        raise RegistryError(f"source registry.schema must be {SCHEMA_V1}")
    for key in ("private_snapshot_proof", "private_tree_proof", "tlc_map_sha256"):
        _hex(src[key], 64, key)
    _hex(src["canonical_verifier_blob"], 40, "canonical_verifier_blob")
    if src["runner_sha"] != V4_EXECUTOR["runner_sha"]:
        raise RegistryError("v1 runner_sha is not the frozen v4 runner")
    if src["wrapper_workflow_blob"] != V4_EXECUTOR["wrapper_workflow_blob"]:
        raise RegistryError("v1 wrapper_workflow_blob is not the frozen v4 wrapper")
    if src["slice_workflow_blob"] != V4_EXECUTOR["slice_workflow_blob"]:
        raise RegistryError("v1 slice_workflow_blob is not the frozen v4 slice")

    profiles = _object(src["profiles"], "v1 profiles")
    migrated_profiles: dict[str, Any] = {}
    for key in sorted(profiles, key=lambda value: int(value)):
        if not isinstance(key, str) or not DECIMAL.fullmatch(key) or str(int(key)) != key:
            raise RegistryError("v1 profile keys must be canonical decimal indices")
        index = int(key)
        if not 0 <= index < 202 or index == 39:
            raise RegistryError(f"v1 profile index {index} is outside the generic non-39 domain")
        entry = _object(profiles[key], f"v1 profile {index}")
        _exact_keys(entry, set(TERMINAL_KEYS), f"v1 profile {index}")
        migrated_profiles[key] = {
            "executor_id": V4_EXECUTOR_ID,
            "migration_lineage": None,
            **copy.deepcopy(entry),
        }

    out = {
        "schema": SCHEMA_V2,
        **{key: src[key] for key in COMMON_KEYS},
        "executors": {V4_EXECUTOR_ID: copy.deepcopy(V4_EXECUTOR)},
        "profiles": migrated_profiles,
    }
    validate_v2(out)
    return out


def canonical_executor(executor_id: str) -> dict[str, Any]:
    canonical = {V4_EXECUTOR_ID: V4_EXECUTOR, V5_EXECUTOR_ID: V5_EXECUTOR}.get(executor_id)
    if canonical is None:
        raise RegistryError(f"unknown executor id {executor_id!r}")
    return copy.deepcopy(canonical)


def record_profile(
    data: Any,
    *,
    index: int,
    executor_id: str,
    terminal_evidence: Mapping[str, Any],
    migration_lineage: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], bool]:
    if not 0 <= index < 202 or index == 39:
        raise RegistryError(f"profile index {index} is outside the generic non-39 domain")
    registry = copy.deepcopy(validate_v2(data))
    executors = registry["executors"]
    canonical = canonical_executor(executor_id)
    prior_executor = executors.get(executor_id)
    if prior_executor is None:
        executors[executor_id] = canonical
    elif prior_executor != canonical:
        raise RegistryError(f"existing executor {executor_id} conflicts with canonical descriptor")

    evidence = _object(dict(terminal_evidence), f"profile {index} terminal evidence")
    _exact_keys(evidence, set(TERMINAL_KEYS), f"profile {index} terminal evidence")
    entry = {
        "executor_id": executor_id,
        "migration_lineage": copy.deepcopy(migration_lineage),
        **copy.deepcopy(evidence),
    }
    _validate_profile(index, entry, executors)
    key = str(index)
    prior = registry["profiles"].get(key)
    if prior is not None:
        if prior != entry:
            raise RegistryError(f"conflicting terminal attestation already exists for profile {index}")
        return registry, False
    registry["profiles"][key] = entry
    registry["profiles"] = {
        profile: registry["profiles"][profile]
        for profile in sorted(registry["profiles"], key=lambda value: int(value))
    }
    validate_v2(registry)
    return registry, True


def evidence_projection_v1(data: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "common": {key: data[key] for key in COMMON_KEYS},
        "profiles": copy.deepcopy(data["profiles"]),
    }


def evidence_projection_v2(data: Mapping[str, Any]) -> dict[str, Any]:
    profiles = {}
    for key, entry in data["profiles"].items():
        profiles[key] = {name: entry[name] for name in TERMINAL_KEYS}
    return {
        "common": {key: data[key] for key in COMMON_KEYS},
        "profiles": profiles,
    }


def lossless_migration_digest(v1: Mapping[str, Any], v2: Mapping[str, Any]) -> str:
    left = evidence_projection_v1(v1)
    right = evidence_projection_v2(v2)
    if left != right:
        raise RegistryError("v1→v2 migration changed terminal evidence")
    canonical = json.dumps(right, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _load(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write(path: str, value: Any) -> None:
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    p_validate = sub.add_parser("validate-v2")
    p_validate.add_argument("path")
    p_migrate = sub.add_parser("migrate-v1")
    p_migrate.add_argument("source")
    p_migrate.add_argument("destination")
    p_migrate.add_argument("--print-evidence-digest", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-v2":
            validate_v2(_load(args.path))
            print("LAS_CURRENT_202_REGISTRY_V2_VALIDATE=PASS")
            return 0
        src = _load(args.source)
        out = migrate_v1(src)
        digest = lossless_migration_digest(src, out)
        _write(args.destination, out)
        if args.print_evidence_digest:
            print(f"LAS_CURRENT_202_REGISTRY_V2_EVIDENCE_SHA256={digest}")
        print("LAS_CURRENT_202_REGISTRY_V1_TO_V2=PASS")
        return 0
    except (OSError, json.JSONDecodeError, RegistryError, ValueError) as exc:
        print(f"LAS_CURRENT_202_REGISTRY_V2_ERROR={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
