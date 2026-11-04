#!/usr/bin/env python3
"""Fail if a previously fixed claim reappears. Matches across line wraps.
Usage: check_regressions.py regressions.tsv   (run from the repo root)"""
import re, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows pipes default to cp1252

def tracked(exts=(".md", ".xml", ".txt", ".conf")):
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout
    return [f for f in out.splitlines() if f.endswith(exts)]

rules = []
for raw in open(sys.argv[1], encoding="utf-8"):
    if not raw.strip() or raw.startswith("#"):
        continue
    pat, fid, why = raw.rstrip("\n").split("\t")
    rules.append((re.compile(pat, re.I), fid, why))

fail = 0
for path in tracked():
    if path.endswith(sys.argv[1]) or path == "docs/decisions.md":
        continue
    text = open(path, encoding="utf-8", errors="replace").read()
    flat = re.sub(r"[ \t]*\n[ \t>#*-]*", " ", text)          # unwrap lines, drop quote/list markers
    flat = re.sub(r"[`*_]", "", flat)                          # drop markdown emphasis/code marks
    for rx, fid, why in rules:
        for m in rx.finditer(flat):
            fail = 1
            print(f"[{fid}] {path}: ...{flat[max(0,m.start()-40):m.end()+40]}...  <- {why}")
sys.exit(fail)
