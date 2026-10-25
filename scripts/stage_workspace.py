#!/usr/bin/env python3
"""stage_workspace.py - copy the project to a throwaway directory and apply the change there.

The real workspace is never modified. The change comes from a unified diff
(--patch) and/or whole-file replacements (--replace REL=SRC) and deletions
(--delete REL).

Safety choices, and why:
  * Secret files (.env, *.pem, ...) are NOT copied, so code under test cannot read them.
  * Symlinks inside the project are skipped; they could point outside it.
  * node_modules / .venv / venv are symlinked, not copied, because they are huge.
    Changes that touch them are rejected so nothing can write through the link.
    Use --copy-deps for a full copy when you want that guarantee.
  * The manifest (what changed, plus hashes of the originals and of the staged files) is written NEXT TO the
    stage directory, not inside it, so code running in the stage cannot tamper with
    what merge_stage.py will later copy back.

Output: one JSON object on stdout:
    {"stage": "stage_workspace", "status": "pass|fail", "findings": [...],
     "reason": "...", "data": {"stage_dir": ..., "manifest": ..., "changed": [...]}}
"""
import argparse
import datetime
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import PurePosixPath

STAGE = "stage_workspace"
IGNORE_DIRS = {".git", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".next", ".tox", ".turbo", ".cache"}
LINK_DIRS = {"node_modules", ".venv", "venv"}
SECRET_PATTERNS = [".env", ".env.*", "*.pem", "*.key", "id_rsa*", "*.p12", "credentials*.json", ".npmrc", ".pypirc"]
SECRET_ALLOW = {".env.example", ".env.sample", ".env.template"}
UNSUPPORTED_PATCH = [
    (r"^(rename|copy) (from|to) ", "renames and copies"),
    (r"^GIT binary patch", "binary patches"),
    (r"^Binary files ", "binary files"),
]


class StageError(Exception):
    """A problem the caller should see verbatim."""


# ---------------------------------------------------------------- helpers
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_rel(rel):
    """Normalise a project-relative path and refuse anything that could escape or hit protected dirs."""
    p = PurePosixPath(rel.replace("\\", "/"))
    if p.is_absolute() or not p.parts:
        raise StageError("path must be relative and non-empty: %r" % rel)
    if ".." in p.parts:
        raise StageError("path escapes the project: %r" % rel)
    blocked = IGNORE_DIRS | LINK_DIRS
    bad = [part for part in p.parts if part in blocked]
    if bad:
        raise StageError("path is inside a protected directory (%s): %r" % (bad[0], rel))
    return str(p)


def is_secret(name):
    if name in SECRET_ALLOW:
        return False
    return any(fnmatch.fnmatch(name, pat) for pat in SECRET_PATTERNS)


def inside(child, parent):
    child, parent = os.path.realpath(child), os.path.realpath(parent)
    return os.path.commonpath([child, parent]) == parent


# ---------------------------------------------------------------- patch parsing
def _clean_header(raw):
    raw = raw.split("\t")[0].strip()
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        raw = raw[1:-1]
    return raw


def _strip(path, n):
    parts = path.split("/")
    if len(parts) <= n:
        raise StageError("patch path has too few components for -p%d: %r" % (n, path))
    return "/".join(parts[n:])


def parse_patch(text):
    """Return ([(path, action)], strip_level). action is modify, create, or delete."""
    for pattern, label in UNSUPPORTED_PATCH:
        if re.search(pattern, text, re.M):
            raise StageError("patch contains unsupported content (%s); use --replace for those files" % label)

    lines = text.splitlines()
    pairs = []
    for i, line in enumerate(lines[:-1]):
        # Require a --- line immediately followed by +++ so removed lines such as "-- comment" are not mistaken for headers.
        if line.startswith("--- ") and lines[i + 1].startswith("+++ "):
            pairs.append((_clean_header(line[4:]), _clean_header(lines[i + 1][4:])))
    if not pairs:
        raise StageError("no file headers (---/+++) found in the patch")

    git_style = all(
        (o == "/dev/null" or o.startswith("a/")) and (n == "/dev/null" or n.startswith("b/"))
        for o, n in pairs
    )
    strip = 1 if git_style else 0

    entries = []
    for old, new in pairs:
        o = None if old == "/dev/null" else _strip(old, strip)
        n = None if new == "/dev/null" else _strip(new, strip)
        if o is None and n is None:
            raise StageError("patch header has /dev/null on both sides")
        if o and n and o != n:
            raise StageError("patch renames %s to %s; renames are unsupported, use --replace and --delete" % (o, n))
        action = "delete" if n is None else ("create" if o is None else "modify")
        entries.append((validate_rel(n or o), action))
    return entries, strip


def apply_patch(stage_dir, patch_file, strip):
    """Check first, then apply, so a bad patch changes nothing."""
    patch_file = os.path.abspath(patch_file)
    if shutil.which("git"):
        cmds = [
            ["git", "apply", "--check", "-p%d" % strip, patch_file],
            ["git", "apply", "-p%d" % strip, "--whitespace=nowarn", patch_file],
        ]
    elif shutil.which("patch"):
        cmds = [
            ["patch", "-p%d" % strip, "--dry-run", "-i", patch_file],
            ["patch", "-p%d" % strip, "-i", patch_file],
        ]
    else:
        raise StageError("neither git nor patch is installed; cannot apply a diff (use --replace instead)")
    for cmd in cmds:
        p = subprocess.run(cmd, cwd=stage_dir, capture_output=True, text=True)
        if p.returncode != 0:
            detail = (p.stderr or p.stdout).strip()
            raise StageError("patch does not apply cleanly: " + detail[:800])


# ---------------------------------------------------------------- copying
def copy_project(src, dst, copy_deps, max_bytes):
    """Copy src to dst. Returns lists of excluded secrets, linked dirs, skipped symlinks, and total bytes."""
    excluded, linked, skipped = [], [], []
    total = 0
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        rel_dir = os.path.relpath(dirpath, src)
        rel_dir = "" if rel_dir == "." else rel_dir
        out_dir = os.path.join(dst, rel_dir) if rel_dir else dst
        os.makedirs(out_dir, exist_ok=True)

        keep = []
        for d in dirnames:
            full = os.path.join(dirpath, d)
            rel = os.path.join(rel_dir, d) if rel_dir else d
            if os.path.islink(full):
                skipped.append(rel)
            elif d in IGNORE_DIRS:
                continue
            elif d in LINK_DIRS and not copy_deps:
                os.symlink(full, os.path.join(out_dir, d))
                linked.append(rel)
            else:
                keep.append(d)
        dirnames[:] = keep

        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.join(rel_dir, name) if rel_dir else name
            if os.path.islink(full):
                skipped.append(rel)
                continue
            if is_secret(name):
                excluded.append(rel)
                continue
            total += os.path.getsize(full)
            if total > max_bytes:
                raise StageError("project exceeds the %d MB staging limit; raise --max-mb or stage a subtree" % (max_bytes // (1024 * 1024)))
            shutil.copy2(full, os.path.join(out_dir, name))
    return excluded, linked, skipped, total


# ---------------------------------------------------------------- main
def build_plan(args):
    """Collect every intended change as {rel: action}, rejecting duplicates and unsafe paths."""
    plan = {}

    def add(rel, action):
        if rel in plan:
            raise StageError("path appears more than once in the change set: " + rel)
        plan[rel] = action

    strip = 0
    if args.patch:
        if not os.path.isfile(args.patch):
            raise StageError("patch file not found: " + args.patch)
        with open(args.patch, encoding="utf-8", errors="replace") as fh:
            entries, strip = parse_patch(fh.read())
        for rel, action in entries:
            add(rel, action)

    replacements = {}
    for spec in args.replace or []:
        if "=" not in spec:
            raise StageError("--replace expects REL=SRC, got %r" % spec)
        rel, src = spec.split("=", 1)
        rel = validate_rel(rel)
        if not os.path.isfile(src):
            raise StageError("replacement source not found: " + src)
        replacements[rel] = src
        add(rel, "replace")  # resolved to create/modify once the original is inspected

    for rel in args.delete or []:
        add(validate_rel(rel), "delete")

    if not plan:
        raise StageError("nothing to stage: pass --patch, --replace, or --delete")
    return plan, strip, replacements


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", required=True, help="path to the real project root (never modified)")
    ap.add_argument("--out", help="stage directory to create (must not exist or be empty); default: a new temp dir")
    ap.add_argument("--patch", help="unified diff to apply inside the stage")
    ap.add_argument("--replace", action="append", metavar="REL=SRC", help="write SRC's content to REL in the stage (repeatable)")
    ap.add_argument("--delete", action="append", metavar="REL", help="delete REL in the stage (repeatable)")
    ap.add_argument("--copy-deps", action="store_true", help="copy node_modules/.venv instead of symlinking them")
    ap.add_argument("--max-mb", type=int, default=500, help="refuse to stage more than this many MB (default 500)")
    args = ap.parse_args()

    project = os.path.abspath(args.project)
    created_stage = False
    stage_dir = None
    try:
        if not os.path.isdir(project):
            raise StageError("project directory not found: " + project)

        # Decide where the stage lives.
        if args.out:
            stage_dir = os.path.abspath(args.out)
            if os.path.exists(stage_dir) and os.listdir(stage_dir):
                raise StageError("--out exists and is not empty: " + stage_dir)
        else:
            stage_dir = os.path.join(tempfile.mkdtemp(prefix="preflight-"), "workspace")
        if inside(stage_dir, project) or inside(project, stage_dir):
            raise StageError("stage directory and project must not contain each other")

        plan, strip, replacements = build_plan(args)

        # Record the originals' hashes BEFORE anything is copied, so merge can detect drift later.
        baselines = {}
        for rel in plan:
            real = os.path.join(project, rel)
            baselines[rel] = sha256(real) if os.path.isfile(real) else None

        # Resolve replace -> create/modify, and sanity-check the rest against reality.
        for rel, action in list(plan.items()):
            exists = baselines[rel] is not None
            if action == "replace":
                plan[rel] = "modify" if exists else "create"
            elif action == "create" and exists:
                raise StageError("patch creates %s but it already exists" % rel)
            elif action in ("modify", "delete") and not exists:
                raise StageError("patch tries to %s %s but it does not exist in the project" % (action, rel))

        os.makedirs(stage_dir, exist_ok=True)
        created_stage = True
        excluded, linked, skipped, total = copy_project(project, stage_dir, args.copy_deps, args.max_mb * 1024 * 1024)

        # Apply the change inside the stage only.
        if args.patch:
            apply_patch(stage_dir, args.patch, strip)
        for rel, src in replacements.items():
            target = os.path.join(stage_dir, rel)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copyfile(src, target)
        for rel, action in plan.items():
            if action == "delete":
                target = os.path.join(stage_dir, rel)
                if os.path.isfile(target):
                    os.remove(target)

        # The manifest lives outside the stage so code running in it cannot rewrite it.
        manifest_path = stage_dir.rstrip(os.sep) + ".manifest.json"
        # Hash what was actually staged. merge_stage.py refuses to copy back a file that no longer matches,
        # so a test run (or anything else) that edits a verified file cannot slip through unnoticed.
        changed = []
        for rel in sorted(plan):
            staged = os.path.join(stage_dir, rel)
            if plan[rel] != "delete" and not os.path.isfile(staged):
                raise StageError("the change did not produce %s in the stage" % rel)
            changed.append({"path": rel, "action": plan[rel], "orig_sha256": baselines[rel],
                            "staged_sha256": sha256(staged) if plan[rel] != "delete" else None})
        manifest = {
            "version": 1,
            "project": project,
            "stage": stage_dir,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "changed": changed,
        }
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)

        findings = []
        if excluded:
            findings.append({"severity": "info", "message": "secret files excluded from the stage: " + ", ".join(sorted(excluded))})
        if linked:
            findings.append({"severity": "warn", "message": "linked (not copied): " + ", ".join(sorted(linked)) +
                             ". Code run in the stage can still read them; use --copy-deps for a full copy."})
        if skipped:
            findings.append({"severity": "info", "message": "symlinks skipped: " + ", ".join(sorted(skipped))})

        result = {
            "stage": STAGE, "status": "pass", "findings": findings, "reason": "",
            "data": {
                "stage_dir": stage_dir, "manifest": manifest_path, "project": project,
                "changed": changed, "copied_bytes": total, "linked": sorted(linked),
                "excluded": sorted(excluded),
            },
        }
        print(json.dumps(result, indent=2))
        return 0

    except StageError as exc:
        if created_stage and stage_dir and os.path.isdir(stage_dir):
            shutil.rmtree(stage_dir, ignore_errors=True)  # only ever our own, freshly created, empty-at-start stage
        print(json.dumps({
            "stage": STAGE, "status": "fail",
            "findings": [{"severity": "error", "message": str(exc)}],
            "reason": str(exc), "data": {},
        }, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())
