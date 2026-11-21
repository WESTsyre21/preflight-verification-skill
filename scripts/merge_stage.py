#!/usr/bin/env python3
"""merge_stage.py - the ONLY script that writes into the real project. It is deliberately strict.

    merge_stage.py --stage <dir> --verdict VERIFIED                    apply the verified change
    merge_stage.py --stage <dir> --verdict PARTIAL --acknowledge-partial
    merge_stage.py --stage <dir> --dry-run                             show what would happen, change nothing
    merge_stage.py --stage <dir> --rollback                            undo a previous merge

What it enforces, and why:
  * Verdict gate: FAILED is refused. PARTIAL needs --acknowledge-partial, a reminder that skipped stages
    must be shown to the user BEFORE merging.
  * VERIFIED requires a saved, passing Tier A sandbox report; Tier B/C can only be PARTIAL.
  * Only the files listed in the manifest are copied. Anything else a test run created in the stage is ignored.
  * No drift: if a real file changed since staging (the user kept editing), nothing is written. Re-stage instead
    of overwriting someone's newer work.
  * No tampering: a staged file must still match the hash recorded at staging time. If a run edited a file
    that was "verified", the verified content is no longer what would be merged, so the merge stops.
  * All checks run BEFORE the first write. Originals are backed up next to the stage (<stage>.backup/),
    each file is replaced atomically, and a failure part-way rolls back what was already applied.
  * Never follows symlinks and never writes outside the project.

Output: {"stage": "merge_stage", "status": "pass|fail", "findings": [...], "reason": "...", "data": {...}}
"""
import argparse
import datetime
import json
import os
import shutil
import sys

from _common import emit, finding, manifest_path
from stage_workspace import StageError, sha256, validate_rel

STAGE = "merge_stage"
TOOL = "merge"


def backup_dir(stage):
    return stage.rstrip(os.sep) + ".backup"


def load_manifest(stage):
    path = manifest_path(stage)
    try:
        with open(path, encoding="utf-8") as fh:
            m = json.load(fh)
    except (OSError, ValueError):
        raise StageError("no readable manifest at %s: this is not a directory made by stage_workspace.py" % path)
    if os.path.realpath(m.get("stage", "")) != os.path.realpath(stage):
        raise StageError("the manifest does not belong to this stage directory")
    if not isinstance(m.get("changed"), list) or not m.get("project"):
        raise StageError("the manifest is malformed")
    return m


def inside(child, parent):
    child, parent = os.path.realpath(child), os.path.realpath(parent)
    return os.path.commonpath([child, parent]) == parent


def plan_merge(stage, project, manifest):
    """Validate every entry and return (actions, problems). Nothing is written here."""
    actions, problems = [], []
    for entry in manifest["changed"]:
        try:
            rel = validate_rel(entry["path"])
        except (StageError, KeyError) as exc:
            problems.append("bad path in manifest: %s" % exc)
            continue
        action = entry.get("action")
        target, staged = os.path.join(project, rel), os.path.join(stage, rel)
        orig, want = entry.get("orig_sha256"), entry.get("staged_sha256")

        if action not in ("modify", "create", "delete"):
            problems.append("%s: unknown action %r" % (rel, action))
            continue
        if not inside(os.path.dirname(target) or project, project):
            problems.append("%s: resolves outside the project" % rel)
            continue
        if os.path.islink(target):
            problems.append("%s: the real path is a symlink; refusing to write through it" % rel)
            continue

        # Drift: the real file must still be exactly what it was when we staged.
        exists = os.path.isfile(target)
        current = sha256(target) if exists else None
        if current != orig:
            what = "was created" if orig is None else ("was deleted" if current is None else "was edited")
            problems.append("%s: the real file %s since staging; re-stage on top of the current version" % (rel, what))
            continue

        # Tampering: the staged file must still be the one that was verified.
        if action == "delete":
            if os.path.exists(staged):
                problems.append("%s: staged as a deletion but the file exists in the stage again" % rel)
                continue
        else:
            if not os.path.isfile(staged) or os.path.islink(staged):
                problems.append("%s: missing from the stage" % rel)
                continue
            if want is None:
                problems.append("%s: manifest has no staged hash (staged with an older stage_workspace.py); re-stage" % rel)
                continue
            if sha256(staged) != want:
                problems.append("%s: changed after staging (a run edited a verified file); re-stage and re-verify" % rel)
                continue
        actions.append({"path": rel, "action": action, "target": target, "staged": staged,
                        "orig_sha256": orig, "staged_sha256": want})
    return actions, problems


def load_sandbox_report(path):
    """Read the recorded sandbox result used to support a merge verdict."""
    if not path:
        return None, None, "--sandbox-report is required for a merge"
    try:
        with open(path, encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, ValueError) as exc:
        return None, None, "could not read sandbox report: %s" % exc
    if report.get("stage") != "run_sandboxed" or report.get("status") not in ("pass", "fail", "skipped"):
        return None, None, "sandbox report must be a run_sandboxed JSON result"
    tier = (report.get("data") or {}).get("tier")
    if tier not in ("A", "B", "C"):
        return None, None, "sandbox report has no valid tier"
    return tier, report["status"], None


def validate_verdict(verdict, sandbox_tier, sandbox_status, acknowledge_partial):
    """Fail closed when the requested merge verdict is not supported by its sandbox tier."""
    if verdict is None:
        return "--verdict is required (VERIFIED or PARTIAL) unless --dry-run"
    if verdict == "FAILED":
        return "refusing to merge a FAILED verdict: fix the problems and re-verify first"
    if sandbox_tier is None:
        return "a valid --sandbox-report is required for a merge"
    if verdict == "VERIFIED" and (sandbox_tier != "A" or sandbox_status != "pass"):
        return "VERIFIED requires a passing Tier A sandbox report; Tier B/C or a failed/skipped run can only be PARTIAL"
    if verdict == "PARTIAL" and not acknowledge_partial:
        return "PARTIAL verdict: tell the user which stages were skipped, then re-run with --acknowledge-partial"
    return None


def atomic_copy(src, dst, mode_from=None):
    tmp = dst + ".preflight-tmp"
    shutil.copyfile(src, tmp)
    shutil.copymode(mode_from or src, tmp)
    os.replace(tmp, dst)


def apply_actions(actions, bdir):
    """Back up originals, apply, verify. Returns (applied entries, created dirs). Raises after rolling back on error."""
    files_dir = os.path.join(bdir, "files")
    os.makedirs(files_dir, exist_ok=False)
    applied, created_dirs = [], []
    try:
        for a in actions:
            if a["orig_sha256"] is not None:
                keep = os.path.join(files_dir, a["path"])
                os.makedirs(os.path.dirname(keep), exist_ok=True)
                shutil.copy2(a["target"], keep)
        for a in actions:
            if a["action"] == "delete":
                os.remove(a["target"])
                applied.append(a)
            else:
                parent = os.path.dirname(a["target"])
                missing = []
                p = parent
                while not os.path.isdir(p):
                    missing.append(p)
                    p = os.path.dirname(p)
                os.makedirs(parent, exist_ok=True)
                created_dirs += reversed(missing)
                atomic_copy(a["staged"], a["target"], mode_from=a["target"] if a["action"] == "modify" else None)
                applied.append(a)  # recorded BEFORE the check, so a failed check is rolled back too
                if sha256(a["target"]) != a["staged_sha256"]:
                    raise OSError("%s does not match the verified content after writing" % a["path"])
    except Exception:
        undo(applied, bdir, created_dirs, check_current=False)
        raise
    return applied, created_dirs


def diverged(a):
    """Why a merged file can no longer be safely reverted, or None. Used so a rollback never clobbers later work."""
    target = a["target"]
    if a["action"] == "delete":
        return "%s: re-created since the merge; left alone" % a["path"] if os.path.exists(target) else None
    if os.path.isfile(target) and sha256(target) != a["staged_sha256"]:
        return "%s: edited since the merge; left alone" % a["path"]
    return None


def undo(applied, bdir, created_dirs, check_current=True):
    """Reverse applied actions (newest first). All-or-nothing when check_current is set: if any file has diverged
    since the merge, nothing is touched. Returns a list of problems; empty means everything was restored."""
    if check_current:
        blockers = [m for m in (diverged(a) for a in applied) if m]
        if blockers:
            return blockers
    problems = []
    for a in reversed(applied):
        target = a["target"]
        try:
            if a["action"] == "create":
                if os.path.isfile(target):
                    os.remove(target)
            else:  # modify or delete: restore the original from the backup
                shutil.copy2(os.path.join(bdir, "files", a["path"]), target)
        except OSError as exc:
            problems.append("%s: could not restore (%s)" % (a["path"], exc))
    for d in reversed(created_dirs):
        try:
            os.rmdir(d)  # only succeeds when empty, so it can never remove user content
        except OSError:
            pass
    return problems


def do_rollback(stage):
    bdir = backup_dir(stage)
    log_path = os.path.join(bdir, "merge_log.json")
    try:
        with open(log_path, encoding="utf-8") as fh:
            log = json.load(fh)
    except (OSError, ValueError):
        raise StageError("nothing to roll back: no merge log at " + log_path)
    if log.get("rolled_back"):
        raise StageError("this merge was already rolled back")
    problems = undo(log["applied"], bdir, log.get("created_dirs", []))
    if problems:
        return False, problems, log
    log["rolled_back"] = True
    log["rolled_back_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with open(log_path, "w", encoding="utf-8") as fh:
        json.dump(log, fh, indent=2)
    # Set the backup aside so the same verified stage can be merged again if the user wants.
    parked, n = bdir + ".rolled-back", 1
    while os.path.exists(parked):
        n += 1
        parked = "%s.rolled-back-%d" % (bdir, n)
    os.rename(bdir, parked)
    return True, [], log


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stage", required=True, help="staged workspace created by stage_workspace.py")
    ap.add_argument("--project", help="real project root (default: the one recorded in the manifest; must match if given)")
    ap.add_argument("--verdict", choices=["VERIFIED", "PARTIAL", "FAILED"], help="the verification verdict being acted on")
    ap.add_argument("--sandbox-report", help="JSON result saved from run_sandboxed.py")
    ap.add_argument("--acknowledge-partial", action="store_true",
                    help="confirm the skipped stages were shown to the user before merging a PARTIAL verdict")
    ap.add_argument("--dry-run", action="store_true", help="validate and show the plan; write nothing")
    ap.add_argument("--rollback", action="store_true", help="undo a previous merge from its backup")
    args = ap.parse_args()

    stage = os.path.abspath(args.stage)

    def fail(msg, findings=None, data=None, code=1):
        emit(STAGE, "fail", findings or [finding("error", TOOL, msg)], msg, data or {})
        return code

    try:
        if args.rollback:
            ok, problems, log = do_rollback(stage)
            if not ok:
                return fail("rollback refused and NOTHING was changed: some files were edited after the merge",
                            [finding("error", TOOL, p) for p in problems])
            emit(STAGE, "pass", [], "", {"rolled_back": [a["path"] for a in log["applied"]], "project": log["project"]})
            return 0

        manifest = load_manifest(stage)
        project = os.path.realpath(manifest["project"])
        if args.project and os.path.realpath(args.project) != project:
            return fail("--project does not match the project this stage was made from (%s)" % project, code=2)
        if not os.path.isdir(project):
            return fail("project directory not found: " + project, code=2)

        if not args.dry_run:
            tier, sandbox_status, report_error = load_sandbox_report(args.sandbox_report)
            if report_error:
                return fail(report_error, code=2)
            verdict_error = validate_verdict(args.verdict, tier, sandbox_status, args.acknowledge_partial)
            if verdict_error:
                return fail(verdict_error, code=2)
            if os.path.exists(backup_dir(stage)):
                return fail("this stage was already merged (%s exists). Use --rollback to undo it, or re-stage." % backup_dir(stage), code=2)

        actions, problems = plan_merge(stage, project, manifest)
        if problems:
            return fail("%d problem(s) found; NOTHING was written" % len(problems),
                        [finding("error", TOOL, p, code="merge-blocked") for p in problems])

        plan = [{"path": a["path"], "action": a["action"]} for a in actions]
        if args.dry_run:
            emit(STAGE, "pass", [], "dry run; nothing was written", {"plan": plan, "project": project, "dry_run": True})
            return 0

        bdir = backup_dir(stage)
        try:
            applied, created_dirs = apply_actions(actions, bdir)
        except Exception as exc:
            shutil.rmtree(bdir, ignore_errors=True)  # a rolled-back attempt leaves nothing behind, so it can be retried
            return fail("merge failed and was rolled back: %s" % exc)
        log = {"project": project, "merged_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "verdict": args.verdict, "created_dirs": created_dirs,
               "applied": [{k: a[k] for k in ("path", "action", "target", "orig_sha256", "staged_sha256")} for a in applied]}
        with open(os.path.join(bdir, "merge_log.json"), "w", encoding="utf-8") as fh:
            json.dump(log, fh, indent=2)
        emit(STAGE, "pass", [], "", {"merged": plan, "project": project, "verdict": args.verdict, "backup": bdir,
                                      "undo": "merge_stage.py --stage %s --rollback" % stage})
        return 0
    except StageError as exc:
        return fail(str(exc), code=2)


if __name__ == "__main__":
    sys.exit(main())
