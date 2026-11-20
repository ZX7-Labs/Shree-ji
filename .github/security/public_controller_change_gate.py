#!/usr/bin/env python3
"""Read-only public controller change guard.

Source-level regression gate only. A passing result does NOT certify effective
permissions, transitive action behavior, historic artifacts or key custody.
The trusted BASE copy of this script must execute in production. Never execute
candidate-supplied code or load candidate Python modules.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import sys
import tempfile

RULES = (
    ("PRIVATE_WRITE", re.compile(r"\b(?:PRIVATE_WRITE_TOKEN|[A-Z0-9_]*PRIVATE_[A-Z0-9_]*WRITE[A-Z0-9_]*|[A-Z0-9_]*WRITE_PAT[A-Z0-9_]*)\b")),
    ("ANY_SECRET", re.compile(r"secrets\s*\.", re.I)),
    ("WRITE_PERMISSION", re.compile(r"(?m)^\s*(?:(?:contents|actions|checks|deployments|issues|pull-requests|statuses|workflows|packages|id-token):\s*write\b|permissions:\s*write-all\b)", re.I)),
    ("GIT_PUSH", re.compile(r"\bgit\b[^\n]{0,260}\bpush\b", re.I)),
    ("REMOTE_MUTATION", re.compile(r"(?:\bgh\s+api\b|\bcurl\b)[^\n]{0,260}(?:-X|--request|--method)\s+(?:POST|PATCH|PUT|DELETE)\b", re.I)),
    ("GH_WRITE", re.compile(r"\bgh\s+(?:pr\s+merge|release\s+create|workflow\s+run|repo\s+delete)\b", re.I)),
    ("PATCH_PAYLOAD", re.compile(r"\.github/private-patches/|actions/upload-artifact", re.I)),
    ("PR_TARGET", re.compile(r"\bpull_request_target\s*:", re.I)),
)

def flags(data):
    # A source-level detector: comments removed, but dynamically assembled
    # commands, imported actions and credentials outside this repo are not proven.
    code="\n".join(x for x in data.splitlines() if not x.lstrip().startswith("#"))
    return tuple(name for name,rule in RULES if rule.search(code))

def inventory(root):
    if not root.is_dir() or root.is_symlink():
        raise ValueError("missing or symlink source root")
    items={}
    for directory, subdirs, filenames in os.walk(root, followlinks=False):
        subdirs[:]=[name for name in subdirs if name!=".git"]
        for name in subdirs:
            if (Path(directory)/name).is_symlink():
                raise ValueError("symlink directory is forbidden")
        for name in filenames:
            file=Path(directory)/name
            relative=file.relative_to(root).as_posix()
            if file.is_symlink() or not file.is_file() or file.stat().st_size>524288:
                raise ValueError("invalid source file shape")
            items[relative]=file.read_bytes()
            if len(items)>2500:
                raise ValueError("unbounded source inventory")
    return items

def trusted_guard_bootstrap(path, old, new, markers):
    """Only the audited initial installation may define a PR-target checker.

    A changed existing guard is NOT excepted, even if all sentinels remain.
    This is a source pattern check, not proof of branch protection.
    """
    return (
        old is None
        and path==".github/workflows/opaque-public-controller-new-authority-guard-20261109.yml"
        and markers==("PR_TARGET",)
        and "permissions:\n  contents: read" in new
        and new.count("persist-credentials: false")==2
        and new.count("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")==2
        and 'checker="baseline/.github/security/public_controller_change_gate.py"' in new
        and 'test -f "$checker"' in new
        and '"$checker" --baseline baseline --candidate candidate' in new
        and "refs/pull/{0}/merge" in new
    )

# Independently reviewed first installation only. Subsequent edits remain
# subject to the ordinary workflow authority-change denial.
REVIEWED_FIRST_INSTALL_SHA256 = {
    ".github/workflows/exact-candidate-verification.yml": "f6001132784b59a87f782a1daa84a29e9d0ccf97830695f3d7dc1bd8f3f684c1",
    ".github/workflows/exact-candidate-canonical.yml": "c62dc19615e3b00634b14bf22d3e2664b6f4dce46d72b95d4c4dbc43f17bb885",
}


def reviewed_verifier_install(path, old, new):
    expected = REVIEWED_FIRST_INSTALL_SHA256.get(path)
    return old is None and expected is not None and hashlib.sha256(new).hexdigest() == expected



# A single, fully pinned owner recovery. This is NOT an exception for generic
# changes to risky workflows; old and new *whole-file bytes* must match these
# hashes, and exactly these three workflow paths may change. The base guard
# itself still requires a separate independently authorized security review.
OWNER_SIGNER_RECOVERY_20261120 = {
    ".github/workflows/exact-candidate-canonical.yml": (
        "c62dc19615e3b00634b14bf22d3e2664b6f4dce46d72b95d4c4dbc43f17bb885",
        "d08ca4c4c45fd5c3faf5083a37c062794a3acadd52e5f7e5a5cefcff495a0a9d",
    ),
    ".github/workflows/exact-candidate-verification.yml": (
        "f6001132784b59a87f782a1daa84a29e9d0ccf97830695f3d7dc1bd8f3f684c1",
        "92962d012b891ed9ad738dd9374dad2487b9e875e6037c750746b709d1f7657b",
    ),
    ".github/workflows/signed-private-profile.yml": (
        "d4af748464b99349a096b0c4dd9ab771d17314ddadc5a3b369ad288efe9688e1",
        "203647f237ebf5a26f3b2b6906d14768be325e93972bfb7a6c0847272bd21d9c",
    ),
}


def exact_public_signer_recovery(before, after, pins=OWNER_SIGNER_RECOVERY_20261120):
    """True only for the one exact authorized migration of three public PEMs.

    The normal detector handles every other diff, including additions, partial
    or reversed rotations, and all changes to the security checker itself.
    """
    changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
    if changed != pins.keys():
        return False
    for path, (old_digest, new_digest) in pins.items():
        old_data, new_data = before.get(path), after.get(path)
        if not isinstance(old_data, bytes) or not isinstance(new_data, bytes):
            return False
        if hashlib.sha256(old_data).hexdigest() != old_digest:
            return False
        if hashlib.sha256(new_data).hexdigest() != new_digest:
            return False
    return True


def analyze(before,after):
    if exact_public_signer_recovery(before, after):
        # Exact full-file transition was reviewed as a separate recovery event.
        return [], (0, len(OWNER_SIGNER_RECOVERY_20261120), 0)
    denied=[]
    added=changed=deleted=0
    for path in sorted(set(before)|set(after)):
        old=before.get(path)
        now=after.get(path)
        if old==now:
            continue
        if now is None:
            deleted+=1
            continue  # removing legacy write power is allowed
        if old is None:
            added+=1
        else:
            changed+=1

        if path.startswith(".github/private-patches/"):
            denied.append("LEGACY_PATCH_PAYLOAD_NEW_OR_MODIFIED")
            continue
        if path.startswith(".github/workflows/"):
            if not path.endswith((".yml",".yaml")):
                denied.append("UNEXPECTED_WORKFLOW_EXTENSION")
                continue
            try:
                new=now.decode("utf-8",errors="strict")
                prior=old.decode("utf-8",errors="strict") if old is not None else ""
            except UnicodeError:
                denied.append("INVALID_WORKFLOW_ENCODING")
                continue
            current_rules=flags(new)
            old_rules=flags(prior)
            if current_rules and not (
                trusted_guard_bootstrap(path,old,new,current_rules)
                or reviewed_verifier_install(path, old, now)
            ):
                # Legacy workflows may only be edited if all detected risky
                # markers are removed. The initial trusted-base guard is a
                # narrowly audited exception; edits to it remain forbidden.
                denied.append("NEW_OR_STILL_PRESENT_WORKFLOW_AUTHORITY")
            elif old_rules:
                pass  # exact risk-removing replacement, still review required
            continue
        if path.startswith(".github/security/"):
            if path==".github/security/public_controller_change_gate.py" and old is None:
                continue  # one-time reviewed installation; later edits denied
            denied.append("SECURITY_CHECKER_CHANGE_REQUIRES_INDEPENDENT_REVIEW")
            continue
        if path.endswith((".rs",".ads",".adb",".tla",".cfg",".lean",".pem",".key",".env",".b64",".part1",".part2",".part3",".part4")):
            denied.append("PRIVATE_SOURCE_OR_ENCODED_BLOB_INTRODUCTION")
            continue
        if old is None and not path.endswith((".md",".txt")):
            denied.append("UNEXPECTED_NONVERIFIER_ADDITION")
            continue
        # Existing public non-workflow legacy files are permitted only as
        # source-neutral edits; this is NOT a public source leakage scan.
    return denied,(added,changed,deleted)

def check(base,candidate):
    old=inventory(base)
    new=inventory(candidate)
    violations,counts=analyze(old,new)
    if exact_public_signer_recovery(old,new):
        print("LAS_CHANGE_GUARD_OWNER_SIGNER_RECOVERY=EXACT_THREE_FILE_SHA256_TRANSITION")
    print("LAS_CHANGE_GUARD_NEW_FILES="+str(counts[0]))
    print("LAS_CHANGE_GUARD_MODIFIED_FILES="+str(counts[1]))
    print("LAS_CHANGE_GUARD_DELETED_FILES="+str(counts[2]))
    print("LAS_CHANGE_GUARD_DENIAL_COUNT="+str(len(violations)))
    print("LAS_CHANGE_GUARD_EFFECTIVE_GITHUB_PERMISSIONS=NOT_VERIFIED")
    print("LAS_CHANGE_GUARD_BRANCH_PROTECTION=REQUIRES_ADMIN_ENFORCEMENT")
    print("LAS_CHANGE_GUARD_LEGACY_WORKFLOW_CAPABILITY=OPEN")
    if violations:
        for rule in sorted(set(violations)):
            print("LAS_CHANGE_GUARD_DENIAL_CLASS="+rule)
        print("LAS_CHANGE_GUARD_SOURCE_CHANGE=DENY")
        return 3
    print("LAS_CHANGE_GUARD_SOURCE_CHANGE=NO_NEW_PATTERN_FOUND_NOT_SECURITY_CERTIFICATE")
    return 0

def self_test():
    root=".github/workflows/old.yml"
    old={root:b"name: legacy\nrun: git push origin main\n"}
    cases=(
        ("unchanged legacy",old.copy(),True),
        ("delete legacy",{},True),
        ("remove full legacy", {root:b"permissions:\n  contents: read\n"},True),
        ("still risky modified", {root:b"name: updated\nrun: git push origin main\n"},False),
        ("new private write", {**old,".github/workflows/new.yml":b"env:\n  T: secrets.PRIVATE_WRITE_TOKEN\n"},False),
        ("new write-all", {**old,".github/workflows/new.yml":b"permissions: write-all\n"},False),
        ("new oidc write", {**old,".github/workflows/new.yml":b"permissions:\n  id-token: write\n"},False),
        ("new workflow safe", {**old,".github/workflows/new.yml":b"permissions:\n  contents: read\n"},True),
        ("new patch blob", {**old,".github/private-patches/new.b64":b"QQ=="},False),
        ("mutate patch", {**old,".github/private-patches/existing.b64":b"changed"},False),
        ("new product source", {**old,"src/private.rs":b"pub fn unsafe_effect() {}"},False),
        ("new security script", {**old,".github/security/public_controller_change_gate.py":b"read-only"},True),
        ("alter security script", {**old,".github/security/existing.py":b"changed"},False),
        ("new curl POST", {**old,".github/workflows/new.yml":b"run: curl -X POST https://example.invalid\n"},False),
        ("new PR target", {**old,".github/workflows/new.yml":b"on:\n  pull_request_target:\n"},False),
        ("fake trusted guard", {**old,
            ".github/workflows/opaque-public-controller-new-authority-guard-20261109.yml":
            b"on:\n  pull_request_target:\n"},False),
        ("true trusted guard bootstrap", {**old,
            ".github/workflows/opaque-public-controller-new-authority-guard-20261109.yml":
            (b"on:\n  pull_request_target:\npermissions:\n  contents: read\n"
             b"uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
             b"uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
             b"persist-credentials: false\npersist-credentials: false\n"
             b'checker="baseline/.github/security/public_controller_change_gate.py"\n'
             b'test -f "$checker"\n'
             b'python3 "$checker" --baseline baseline --candidate candidate\n'
             b"refs/pull/{0}/merge\n")},True),
    )
    for name,new,want in cases:
        before={**old}
        if name=="mutate patch":
            before[".github/private-patches/existing.b64"]=b"old"
        if name=="alter security script":
            before[".github/security/existing.py"]=b"old"
        denied,_=analyze(before,new)
        if (not denied)!=want:
            raise ValueError("mutation fixture failed: "+name)
    # Recovery predicate's positive and adversarial cases are separate from
    # the legacy authority detector. Production pins cannot be supplied by PRs.
    _old={"a.yml":b"oldA","b.yml":b"oldB","c.yml":b"oldC","unchanged.md":b"same"}
    _new={**_old,"a.yml":b"newA","b.yml":b"newB","c.yml":b"newC"}
    _pins={k:(hashlib.sha256(_old[k]).hexdigest(),
              hashlib.sha256(_new[k]).hexdigest()) for k in ("a.yml","b.yml","c.yml")}
    if not exact_public_signer_recovery(_old,_new,_pins):
        raise ValueError("owner recovery positive fixture failed")
    _variants=[]
    _variants.append({**_new,"c.yml":_old["c.yml"]})
    _variants.append({**_new,"extra.yml":b"new"})
    _variants.append({**_new,"unchanged.md":b"changed"})
    _variants.append({**_new,"a.yml":_new["a.yml"]+b" "})
    _variants.append({**_new,"a.yml":_new["a.yml"]+b"secrets.PRIVATE_WRITE_TOKEN"})
    _variants.append({k:v for k,v in _new.items() if k!="b.yml"})
    _variants.append({**_new,"a.yml":"not bytes"})
    for _candidate in _variants:
        if exact_public_signer_recovery(_old,_candidate,_pins):
            raise ValueError("owner recovery mutation admitted")
    if exact_public_signer_recovery(_new,_old,_pins):
        raise ValueError("owner recovery reversal admitted")
    if exact_public_signer_recovery(_old,_new,{**_pins,"extra":("0"*64,"1"*64)}):
        raise ValueError("owner recovery extra manifest admitted")
    if exact_public_signer_recovery(
        _old,_new,{**_pins,"a.yml":("0"*64,_pins["a.yml"][1])}
    ):
        raise ValueError("owner recovery old hash mutation admitted")
    if exact_public_signer_recovery(
        _old,_new,{**_pins,"c.yml":(_pins["c.yml"][0],"1"*64)}
    ):
        raise ValueError("owner recovery new hash mutation admitted")
    print("LAS_CHANGE_GUARD_RECOVERY_ADVERSARIAL_CASES=11")
    print("LAS_CHANGE_GUARD_RECOVERY_FIXTURES=PASS")
    print("LAS_CHANGE_GUARD_MUTATION_CASES="+str(len(cases)))
    print("LAS_CHANGE_GUARD_MUTATION_FIXTURES=PASS")
    return 0

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--self-test",action="store_true")
    p.add_argument("--baseline",type=Path)
    p.add_argument("--candidate",type=Path)
    args=p.parse_args()
    try:
        if args.self_test:
            return self_test()
        if args.baseline is None or args.candidate is None:
            raise ValueError("baseline and candidate are required")
        return check(args.baseline,args.candidate)
    except (OSError,UnicodeError,ValueError) as exc:
        print("LAS_CHANGE_GUARD=INCOMPLETE")
        print("LAS_CHANGE_GUARD_ERROR_CLASS="+type(exc).__name__)
        return 2

if __name__=="__main__":
    sys.exit(main())
