#!/usr/bin/env python3
"""Fail closed on newly added/modified public workflows that could gain write authority.

Exact legacy byte identities are grandfathered only as OPEN RISK, never marked safe.
Static regex classifier is incomplete; required branch checks and secret isolation
are separate prerequisites for actual enforcement.
"""
import argparse
import hashlib
from pathlib import Path
import re
import sys
import tempfile

BASE_COMMIT="354914fa0ac1fd13895f1e3973b2c4b1a8e0fca0"
BASE_MANIFEST_BLOB="2822d2a4d8415c163afe53c3d6c2cacef70fc644"
BASE_COUNT=388
PATH=re.compile(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml\Z")
SHA=re.compile(r"[a-f0-9]{40}\Z")
EXPLICIT_READ=re.compile(r"(?m)^permissions:\s*\n\s+contents:\s*read\s*(?:\n|$)")
TRIGGER=re.compile(r"(?m)^on:\s*(?:\n|$)")
USE=re.compile(r"(?m)^\s*uses:\s*(\S+)")
PINNED_USE=re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[a-f0-9]{40}\Z")
DENY=(
 ("WRITE_CREDENTIAL",re.compile(r"\b(?:PRIVATE_WRITE_TOKEN|[A-Z0-9_]*PRIVATE_[A-Z0-9_]*WRITE[A-Z0-9_]*|[A-Z0-9_]*WRITE_PAT[A-Z0-9_]*)\b")),
 ("ANY_SECRET_REFERENCE",re.compile(r"\bsecrets\s*[.\[]",re.I)),
 ("WRITE_PERMISSION",re.compile(r"(?m)^\s*(?:contents|actions|checks|deployments|issues|pull-requests|statuses|workflows|packages|id-token):\s*write\b",re.I)),
 ("GIT_PUSH",re.compile(r"\bgit\b[^\n]{0,260}\bpush\b",re.I)),
 ("GH_MUTATION",re.compile(r"\bgh\s+(?:pr\s+merge|release\s+create|workflow\s+run|issue\s+(?:close|create)|repo\s+(?:delete|create)|api\b[^\n]{0,200}(?:-X|--method)\s+(?:POST|PATCH|PUT|DELETE))\b",re.I)),
 ("CURL_WRITE",re.compile(r"\bcurl\b[^\n]{0,260}(?:-X|--request)\s+(?:POST|PATCH|PUT|DELETE)\b",re.I)),
 ("PRIVILEGED_EVENT",re.compile(r"(?m)^\s*(?:pull_request_target|workflow_run|repository_dispatch|workflow_call):\s*(?:\n|$)",re.I)),
 ("DYNAMIC_ACTION",re.compile(r"(?m)^\s*uses:\s*(?:actions/github-script|docker://)",re.I)),
)
class Denied(ValueError):
    pass
def require(ok,reason):
    if not ok: raise Denied(reason)
def gitsha(data):
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
def baseline(data,expected_sha=BASE_MANIFEST_BLOB,expected_count=BASE_COUNT):
    require(gitsha(data)==expected_sha,"baseline bytes changed")
    lines=data.decode("utf-8","strict").splitlines()
    require(lines and lines[0]=="# LAS_PUBLIC_LEGACY_SOURCE_BASELINE_SHA1\t"+BASE_COMMIT,"baseline origin changed")
    out={};prev=""
    for line in lines[1:]:
        cols=line.split("\t")
        require(len(cols)==2,"invalid baseline record")
        sha,path=cols
        require(SHA.fullmatch(sha) is not None and PATH.fullmatch(path) is not None,"invalid baseline path")
        require(path>prev and path not in out,"unordered baseline")
        out[path]=sha;prev=path
    require(len(out)==expected_count,"baseline incomplete")
    return out
def classify(source):
    text="\n".join(z for z in source.splitlines() if not z.lstrip().startswith("#"))
    hit=[name for name,rule in DENY if rule.search(text)]
    if not EXPLICIT_READ.search(text): hit.append("ROOT_CONTENTS_READ_MISSING")
    if not TRIGGER.search(text): hit.append("ROOT_ON_MISSING")
    if any(PINNED_USE.fullmatch(m.group(1)) is None for m in USE.finditer(text)):
        hit.append("UNPINNED_OR_REUSABLE_ACTION")
    return tuple(hit)
def evaluate(old,new):
    unchanged=risky=changed=0;violations={}
    for path,data in sorted(new.items()):
        if PATH.fullmatch(path) is None: violations[path]=("BAD_PATH",);continue
        if len(data)>512*1024: violations[path]=("OVERSIZED",);continue
        try: decoded=data.decode("utf-8","strict")
        except UnicodeError: violations[path]=("INVALID_UTF8",);continue
        issues=classify(decoded)
        if old.get(path)==gitsha(data):
            unchanged+=1
            risky+=bool(issues)
        elif issues:
            violations[path]=issues
        else: changed+=1
    return unchanged,risky,changed,len(set(old)-set(new)),violations
def collect(root):
    require(root.is_dir() and not root.is_symlink(),"directory missing or symlink")
    found={}
    for node in root.iterdir():
        require(node.is_file() and not node.is_symlink(),"unexpected dir/symlink")
        path=".github/workflows/"+node.name
        require(PATH.fullmatch(path) is not None,"unexpected file")
        require(node.stat().st_size<=512*1024,"oversized file")
        found[path]=node.read_bytes()
    require(10<=len(found)<=2000,"candidate inventory invalid")
    return found
def selftest():
    bad="name: legacy\non:\n  push:\npermissions:\n  contents: write\njobs:\n  a:\n    steps:\n      - run: git push origin main\n"
    safe="name: safe\non:\n  push:\npermissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
    oldpath=".github/workflows/old.yml";newpath=".github/workflows/new.yml"
    old={oldpath:gitsha(bad.encode())}
    cases=[
     ("unchanged-danger-debt",{oldpath:bad.encode()},True),
     ("modified-danger-denied",{oldpath:(bad+"#change\n").encode()},False),
     ("deletion-allowed",{},True),
     ("new-safe",{oldpath:bad.encode(),newpath:safe.encode()},True),
     ("new-git-push",{newpath:(safe+"      - run: git push\n").encode()},False),
     ("new-write-secret",{newpath:(safe+"env:\n  T: secrets.PRIVATE_WRITE_TOKEN\n").encode()},False),
     ("new-read-secret",{newpath:(safe+"env:\n  T: secrets.PRIVATE_READ_TOKEN\n").encode()},False),
     ("new-write-permission",{newpath:safe.replace("contents: read","contents: write").encode()},False),
     ("new-oidc-write",{newpath:(safe+"  id-token: write\n").encode()},False),
     ("new-pr-target",{newpath:(safe+"  pull_request_target:\n").encode()},False),
     ("new-unpinned-action",{newpath:safe.replace("11bd71901bbe5b1630ceea73d27597364c9af683","v4").encode()},False),
     ("new-curl-mutation",{newpath:(safe+"      - run: curl -X POST https://example.invalid\n").encode()},False),
     ("safe-replacement",{oldpath:safe.encode()},True),
     ("bad-path",{"../evil.yml":safe.encode()},False),
     ("invalid-utf8",{newpath:b"\xff"},False),
    ]
    for title,candidate,should_allow in cases:
        accepted=not evaluate(old,candidate)[-1]
        require(accepted==should_allow,"synthetic case failed: "+title)
    try: baseline(b"corrupt")
    except Denied: pass
    else: raise Denied("tampered manifest false green")
    with tempfile.TemporaryDirectory(prefix="las-delta-") as tmp:
        path=Path(tmp);(path/"regular.yml").write_text(safe)
        (path/"link.yml").symlink_to(path/"regular.yml")
        try: collect(path)
        except Denied: pass
        else: raise Denied("symlink false green")
    print("LAS_DELTA_GUARD_SYNTHETIC=PASS")
    print("LAS_DELTA_GUARD_SYNTHETIC_CASES="+str(len(cases)+2))
    return 0
def audit(directory,manifest):
    original=baseline(manifest.read_bytes())
    candidate=collect(directory)
    unchanged,debt,changed,removed,denied=evaluate(original,candidate)
    print("LAS_DELTA_BASELINE_FILES="+str(len(original)))
    print("LAS_DELTA_CANDIDATE_FILES="+str(len(candidate)))
    print("LAS_DELTA_UNCHANGED_FILES="+str(unchanged))
    print("LAS_DELTA_GRANDFATHERED_RISKY="+str(debt))
    print("LAS_DELTA_NEW_OR_REPLACED_CLEAN="+str(changed))
    print("LAS_DELTA_REMOVED_LEGACY="+str(removed))
    print("LAS_DELTA_REJECTED_FILES="+str(len(denied)))
    for path,reasons in sorted(denied.items()):
        print("LAS_DELTA_REJECTED="+path+":"+(",".join(reasons)))
    if denied:
        print("LAS_DELTA_NEW_AUTHORITY_POLICY=DENIED")
        return 3
    print("LAS_DELTA_NEW_AUTHORITY_POLICY=PASS_SCOPED")
    print("LAS_DELTA_LEGACY_ISSUE_65=OPEN")
    print("LAS_DELTA_ADMIN_ENFORCEMENT=NOT_CONFIGURED")
    return 0
def main():
    p=argparse.ArgumentParser()
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test",action="store_true")
    group.add_argument("--scan",type=Path)
    p.add_argument("--manifest",type=Path)
    args=p.parse_args()
    try:
        if args.self_test: return selftest()
        require(args.manifest is not None,"manifest required")
        return audit(args.scan,args.manifest)
    except (Denied,OSError,UnicodeError) as exc:
        print("LAS_DELTA_GUARD=INCOMPLETE")
        print("LAS_DELTA_GUARD_ERROR_CLASS="+type(exc).__name__)
        return 1
if __name__=="__main__":
    sys.exit(main())
