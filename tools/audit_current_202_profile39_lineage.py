#!/usr/bin/env python3
import json
import os
import re
import urllib.parse
import urllib.request

repo = os.environ["GITHUB_REPOSITORY"]
token = os.environ["GH_TOKEN"]
initial_run = int(os.environ["INITIAL_RUN_ID"])
terminal_run = int(os.environ["TERMINAL_RUN_ID"])
expected_path = os.environ["EXPECTED_WORKFLOW_PATH"]
expected_blob = os.environ["EXPECTED_WORKFLOW_BLOB"]
api = f"https://api.github.com/repos/{repo}"
max_segments = 64

ansi = re.compile(r"\x1b\[[0-9;]*m")
stamp = re.compile(r"^\d{4}-\d{2}-\d{2}T\S+Z\s+(.*)$")
segment_re = re.compile(r"LAS_REPAIRED_202_TLC39_SEGMENT=([1-9][0-9]*)")
resume_id_re = re.compile(r"^\s*RESUME_RUN_ID:\s*([1-9][0-9]*)\s*$")
resume_artifact_re = re.compile(r"^\s*RESUME_ARTIFACT:\s*(\S+)\s*$")


def request_json(url):
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req) as response:
        return json.load(response)


def request_text(url):
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req) as response:
        return response.read().decode("utf-8", errors="replace")


def workflow_blob(head_sha):
    encoded = urllib.parse.quote(expected_path, safe="/")
    data = request_json(f"{api}/contents/{encoded}?ref={head_sha}")
    return data.get("sha", "")


def one_slice_job(run_id, expected_head):
    data = request_json(f"{api}/actions/runs/{run_id}/jobs?filter=latest&per_page=100")
    jobs = data.get("jobs", [])
    if len(jobs) != 1 or jobs[0].get("name") != "slice":
        raise SystemExit(f"run {run_id}: expected exactly one slice job")
    job = jobs[0]
    if job.get("head_sha") != expected_head:
        raise SystemExit(f"run {run_id}: slice head mismatch")
    if job.get("status") != "completed" or job.get("conclusion") != "success":
        raise SystemExit(f"run {run_id}: slice job is not successful")
    return job


def clean_log_lines(text):
    out = []
    for raw in text.splitlines():
        match = stamp.match(raw)
        if not match:
            continue
        out.append(ansi.sub("", match.group(1)))
    return out


seen_runs = set()
chain = []
current = terminal_run
expected_segment = None

while True:
    if current in seen_runs:
        raise SystemExit("profile-39 lineage cycle detected")
    if len(chain) >= max_segments:
        raise SystemExit("profile-39 lineage exceeds safe segment bound")
    seen_runs.add(current)

    run = request_json(f"{api}/actions/runs/{current}")
    if int(run.get("id", 0)) != current:
        raise SystemExit(f"run {current}: id mismatch")
    if run.get("path") != expected_path:
        raise SystemExit(f"run {current}: workflow path mismatch")
    if run.get("run_attempt") != 1:
        raise SystemExit(f"run {current}: unexpected run attempt")
    if run.get("status") != "completed":
        raise SystemExit(f"run {current}: run is not complete")
    if run.get("conclusion") != "success":
        raise SystemExit(f"run {current}: run is not successful")
    head = run.get("head_sha", "")
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise SystemExit(f"run {current}: invalid head SHA")
    if workflow_blob(head) != expected_blob:
        raise SystemExit(f"run {current}: continuation workflow blob drift")

    job = one_slice_job(current, head)
    steps = {
        s.get("name"): (s.get("status"), s.get("conclusion"))
        for s in job.get("steps", [])
    }
    for name in (
        "Validate exact continuation request",
        "Reclaim runner storage for exhaustive TLC",
        "Recover exact frozen repaired candidate",
        "Bind exact canonical map and profile 39",
        "Run exact canonical TLC39 slice",
    ):
        if steps.get(name) != ("completed", "success"):
            raise SystemExit(f"run {current}: required step failed: {name}")

    text = request_text(f"{api}/actions/jobs/{job['id']}/logs")
    lines = clean_log_lines(text)
    line_set = set(lines)
    required_markers = {
        "LAS_REPAIRED_202_TLC39_REQUEST=PASS",
        "LAS_REPAIRED_202_TLC39_RECOVERY=PASS",
        "LAS_REPAIRED_202_TLC39_BINDING=PASS",
    }
    missing = sorted(required_markers - line_set)
    if missing:
        raise SystemExit(f"run {current}: missing binding markers: {missing!r}")

    segments = {
        int(match.group(1))
        for line in lines
        if (match := segment_re.fullmatch(line))
    }
    if len(segments) != 1:
        raise SystemExit(f"run {current}: segment marker missing or ambiguous")
    segment = next(iter(segments))
    if expected_segment is not None and segment != expected_segment:
        raise SystemExit(f"run {current}: non-contiguous segment number")

    resume_ids = {
        int(match.group(1))
        for line in lines
        if (match := resume_id_re.fullmatch(line))
    }
    resume_artifacts = {
        match.group(1)
        for line in lines
        if (match := resume_artifact_re.fullmatch(line))
    }

    is_terminal = not chain
    if is_terminal:
        if "LAS_REPAIRED_202_TLC39_RC=0" not in line_set:
            raise SystemExit(f"run {current}: terminal RC=0 marker missing")
        if "LAS_REPAIRED_202_TLC39_RESULT=PASS" not in line_set:
            raise SystemExit(f"run {current}: terminal PASS marker missing")
        for name in (
            "Seal authenticated encrypted checkpoint",
            "Upload authenticated encrypted checkpoint",
            "Dispatch next exact slice",
        ):
            if steps.get(name) != ("completed", "skipped"):
                raise SystemExit(
                    f"run {current}: terminal run unexpectedly continued: {name}"
                )
    else:
        if "LAS_REPAIRED_202_TLC39_RESULT=SLICE_CHECKPOINT" not in line_set:
            raise SystemExit(f"run {current}: nonterminal checkpoint marker missing")
        if f"LAS_REPAIRED_202_TLC39_NEXT_SEGMENT={segment + 1}" not in line_set:
            raise SystemExit(f"run {current}: next-segment marker mismatch")
        for name in (
            "Seal authenticated encrypted checkpoint",
            "Upload authenticated encrypted checkpoint",
            "Dispatch next exact slice",
        ):
            if steps.get(name) != ("completed", "success"):
                raise SystemExit(
                    f"run {current}: nonterminal continuation step failed: {name}"
                )

    if segment == 1:
        if current != initial_run:
            raise SystemExit("segment 1 is not the exact initial run")
        if run.get("event") != "push":
            raise SystemExit("segment 1 event is not push")
        for name in (
            "Download prior authenticated encrypted checkpoint",
            "Authenticate and restore prior checkpoint",
        ):
            if steps.get(name) != ("completed", "skipped"):
                raise SystemExit(f"initial run unexpectedly resumed: {name}")
        if resume_ids or resume_artifacts:
            raise SystemExit("initial run exposes non-empty resume provenance")
        chain.append((segment, current, head, job["id"], run.get("created_at", "")))
        break

    if run.get("event") != "workflow_dispatch":
        raise SystemExit(f"run {current}: resumed segment event mismatch")
    for name in (
        "Download prior authenticated encrypted checkpoint",
        "Authenticate and restore prior checkpoint",
    ):
        if steps.get(name) != ("completed", "success"):
            raise SystemExit(f"run {current}: resumed checkpoint step failed: {name}")
    for marker in (
        "LAS_REPAIRED_202_TLC39_CHECKPOINT_AUTH=PASS",
        "LAS_REPAIRED_202_TLC39_RECOVER_DIR=PASS",
    ):
        if marker not in line_set:
            raise SystemExit(
                f"run {current}: resumed authentication marker missing: {marker}"
            )
    if len(resume_ids) != 1:
        raise SystemExit(f"run {current}: resume run id missing or ambiguous")
    if len(resume_artifacts) != 1:
        raise SystemExit(f"run {current}: resume artifact missing or ambiguous")
    prior = next(iter(resume_ids))
    artifact = next(iter(resume_artifacts))
    expected_artifact = f"repaired-202-tlc39-state-{segment - 1}"
    if artifact != expected_artifact:
        raise SystemExit(f"run {current}: resume artifact mismatch")
    if prior == current:
        raise SystemExit("profile-39 run self-reference detected")

    chain.append((segment, current, head, job["id"], run.get("created_at", "")))
    expected_segment = segment - 1
    current = prior

chain.reverse()
expected_segments = list(range(1, len(chain) + 1))
actual_segments = [item[0] for item in chain]
if actual_segments != expected_segments:
    raise SystemExit(f"non-contiguous lineage: {actual_segments!r}")
if chain[-1][1] != terminal_run:
    raise SystemExit("terminal run lineage mismatch")
created = [item[4] for item in chain]
if any(not value for value in created) or created != sorted(created):
    raise SystemExit("profile-39 run chronology is inconsistent")

print(f"LAS_CURRENT_202_PROFILE39_LINEAGE_SEGMENTS={len(chain)}")
print(f"LAS_CURRENT_202_PROFILE39_LINEAGE_INITIAL_RUN={initial_run}")
print(f"LAS_CURRENT_202_PROFILE39_LINEAGE_TERMINAL_RUN={terminal_run}")
print("LAS_CURRENT_202_PROFILE39_LINEAGE_WORKFLOW_IDENTITY=PASS")
print("LAS_CURRENT_202_PROFILE39_LINEAGE_PROVENANCE=PASS")
print("LAS_CURRENT_202_PROFILE39_LINEAGE_RESULT=PASS")
