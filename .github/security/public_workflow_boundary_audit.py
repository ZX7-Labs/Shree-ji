#!/usr/bin/env python3
"""Public GitHub workflow source-only private-write capability audit.

Conservative textual classification, NOT a certificate about configured secrets,
effective permissions, transitive action behavior, Git history or runtime effects.
"""
from pathlib import Path
import argparse
import hashlib
import re
import sys

RULES = (
 ("PRIVATE_WRITE_CREDENTIAL", re.compile(r"\b(?:PRIVATE_WRITE_TOKEN|LAS_PRIVATE_WRITE_TOKEN|[A-Z0-9_]*PRIVATE_[A-Z0-9_]*WRITE[A-Z0-9_]*|[A-Z0-9_]*WRITE_PAT[A-Z0-9_]*)\b")),
 ("WRITE_PERMISSION", re.compile(r"(?m)^\s*(?:contents|actions|checks|deployments|issues|pull-requests|statuses|workflows|packages):\s*write\s*(?:#.*)?$", re.I)),
 ("GIT_PUSH", re.compile(r"\bgit\b[^\n]{0,260}\bpush\b", re.I)),
 ("GH_MUTATION", re.compile(r"\bgh\s+(?:pr\s+merge|release\s+create|workflow\s+run|issue\s+(?:close|create)|repo\s+(?:delete|create))\b", re.I)),
 ("GH_API_WRITE", re.compile(r"\bgh\s+api\b[^\n]{0,240}(?:-X|--method)\s+(?:POST|PATCH|PUT|DELETE)\b", re.I)),
 ("CURL_WRITE", re.compile(r"\bcurl\b[^\n]{0,240}(?:-X|--request)\s+(?:POST|PATCH|PUT|DELETE)\b", re.I)),
)
def require(value, message):
    if not value:
        raise ValueError(message)
def classify(text):
    content="\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    return tuple(name for name,rule in RULES if rule.search(content))
def self_test():
    cases=(
      ("read", "permissions:\n  contents: read\nenv:\n  X: secrets.LAS_PRIVATE_READ_TOKEN", ()),
      ("private_write", "env:\n  X: secrets.PRIVATE_WRITE_TOKEN", ("PRIVATE_WRITE_CREDENTIAL",)),
      ("private_write_alt", "env:\n  X: secrets.LAS_PRIVATE_CODE_WRITE_PAT", ("PRIVATE_WRITE_CREDENTIAL",)),
      ("git_push", "run: git -c http.extraHeader=auth push origin HEAD", ("GIT_PUSH",)),
      ("permission", "permissions:\n  contents: write", ("WRITE_PERMISSION",)),
      ("gh_api", "run: gh api -X PATCH repos/a/b", ("GH_API_WRITE",)),
      ("curl", "run: curl -X POST https://example.invalid", ("CURL_WRITE",)),
      ("merge", "run: gh pr merge 123 --squash", ("GH_MUTATION",)),
      ("comment", "# git push\n# secrets.PRIVATE_WRITE_TOKEN\npermissions:\n  contents: read", ()),
      ("remote_read", "run: git remote add origin https://example.invalid", ()),
    )
    for name,code,wanted in cases:
        require(classify(code)==wanted,"discriminating fixture failed: "+name)
    require(len(cases)==10 and len(RULES)==6,"fixture census mutated")
    print("LAS_BOUNDARY_SYNTHETIC=PASS")
    print("LAS_BOUNDARY_SYNTHETIC_CASES=10")
    return 0
def audit(root):
    require(root.is_dir() and not root.is_symlink(),"missing workflow directory")
    files=sorted(list(root.glob("*.yml"))+list(root.glob("*.yaml")))
    require(10<=len(files)<=2000,"unexpected workflow count")
    hits={name:0 for name,_ in RULES}
    fingerprint=hashlib.sha256()
    flagged=0
    for path in files:
        require(path.is_file() and not path.is_symlink(),"invalid workflow entry")
        require(path.stat().st_size<=512*1024,"oversized workflow")
        raw=path.read_text(encoding="utf-8",errors="strict")
        matched=classify(raw)
        fingerprint.update(path.name.encode()+b"\0"+hashlib.sha256(raw.encode()).digest())
        flagged+=bool(matched)
        for name in matched:
            hits[name]+=1
    print("LAS_BOUNDARY_WORKFLOW_FILES="+str(len(files)))
    print("LAS_BOUNDARY_FLAGGED_FILES="+str(flagged))
    for name in sorted(hits):
        print("LAS_BOUNDARY_"+name+"_FILES="+str(hits[name]))
    print("LAS_BOUNDARY_PUBLIC_SOURCE_DIGEST="+fingerprint.hexdigest())
    print("LAS_BOUNDARY_SECRET_VALUE_INSPECTION=NOT_RUN")
    print("LAS_BOUNDARY_EFFECTIVE_PERMISSIONS=NOT_VERIFIED")
    print("LAS_BOUNDARY_TRANSITIVE_ACTIONS=NOT_AUDITED")
    if flagged:
        print("LAS_BOUNDARY_SOURCE_POLICY=DENIED_EXPECTED")
        return 3
    print("LAS_BOUNDARY_SOURCE_POLICY=NO_MATCHES_NOT_CERTIFIED")
    return 2
def main():
    cli=argparse.ArgumentParser()
    group=cli.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test",action="store_true")
    group.add_argument("--scan",type=Path)
    args=cli.parse_args()
    try:
        return self_test() if args.self_test else audit(args.scan)
    except (UnicodeError,OSError,ValueError) as exc:
        print("LAS_BOUNDARY_AUDIT=INCOMPLETE")
        print("LAS_BOUNDARY_ERROR_CLASS="+type(exc).__name__)
        return 1
if __name__=="__main__":
    sys.exit(main())
