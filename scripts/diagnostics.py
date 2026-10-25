#!/usr/bin/env python3
"""diagnostics.py - turn failing stage reports into the exact next prompt for the self-healing loop.

    diagnostics.py --report static.json --report tests.json --stage <dir> --attempt 1 [--format prompt]

Reads one or more stage reports (the JSON the other scripts print), picks the EARLIEST failing stage
(type errors before runtime errors, because fixing the first often fixes the rest), pulls out file, line,
error text and a code excerpt, and recommends what to do next. The "action" field is the important part:

  fix          a code problem you can repair: make the SMALLEST change that fixes the named error, restage
               it with stage_workspace.py, and re-verify from the static stage
  ask_user     the safety scan blocked something. Do not fix or bypass it yourself: show the user
  environment  not a code problem (missing tool, missing Docker image): say so; editing code will not help
  stop         the retry budget is spent. Stop patching; report what failed, what was tried, your best theory
  none         nothing failed (skipped stages are listed, because they make the verdict PARTIAL)

Repetition: pass the previous diagnostics output with --previous. If the top error is identical, the prompt
says so, because repeating the same patch is the thrash this loop exists to prevent.

Output: JSON by default ({"stage": "diagnostics", ..., "data": {action, errors, prompt, ...}});
--format prompt prints only the text to act on.
"""
import argparse
import hashlib
import json
import os
import re
import sys

from _common import emit, norm

STAGE = "diagnostics"
STAGE_ORDER = ["detect_env", "stage_workspace", "static_check", "dep_check", "safety_scan",
               "run_sandboxed", "run_tests", "merge_stage"]
# Finding codes that mean "fixing the changed source will not help".
ENV_CODES = {
    "type-check-blocked",  # tsc config invalid; type checking did not run
    "image-missing",       # Docker image not pulled
    "tool-missing",        # required checker/runner binary absent
    "config-blocked",      # project config prevents the check from running
}
# Substrings in a stage reason / finding message that also mean environment.
ENV_REASON_MARKERS = (
    "refusing to run",
    "not installed",
    "not found on PATH",
    "command not found",
    "no usable test runner",
    "docker is not available",
    "docker daemon",
    "cannot infer a Docker image",
    "network namespace unavailable and no fallback",  # defensive; normally Tier B still runs
    "stage directory not found",
    "is not a staged workspace",
)
FOREIGN = ("site-packages", "dist-packages", "node_modules", "/usr/lib/python", "/lib/python",
           "<frozen", "node:internal", "<string>", "/usr/local/lib/python")


# ================================================================= reading reports
def load_reports(paths):
    reports = []
    for p in paths:
        try:
            raw = sys.stdin.read() if p == "-" else open(p, encoding="utf-8").read()
            data = json.loads(raw)
        except (OSError, ValueError) as exc:
            raise SystemExit("could not read report %s: %s" % (p, exc))
        if isinstance(data, list):
            reports += [r for r in data if isinstance(r, dict) and "stage" in r]
        elif isinstance(data, dict) and isinstance(data.get("reports"), list):
            reports += data["reports"]
        elif isinstance(data, dict) and "stage" in data:
            reports.append(data)
    return reports


# ================================================================= locating errors in raw output
def rel_path(path, stage):
    """Project-relative path, or None if the frame is not the user's code (dependency, stdlib, outside the stage)."""
    path = path.replace("\\", "/")
    if any(m in path for m in FOREIGN):
        return None
    if stage:
        for prefix in {stage.rstrip("/") + "/", os.path.realpath(stage).rstrip("/") + "/"}:
            if path.startswith(prefix):
                return path[len(prefix):]
        if os.path.isabs(path):
            return None
    return norm(path).lstrip("./") if not os.path.isabs(path) else path


def is_test_path(path):
    return bool(re.search(r"(^|/)(tests?/|__tests__/|test_[^/]*\.py$|[^/]*_test\.py$|[^/]*\.(test|spec)\.[a-z]+$)", path))


def _pytest_section(text, stage):
    e_lines = [m.group(1).strip() for m in re.finditer(r"^E\s+(.*)$", text, re.M)]
    frames = []
    for m in re.finditer(r"^(\S+?\.py):(\d+): (?:in (\S+)|(\w+(?:Error|Exception)\b.*))", text, re.M):
        rp = rel_path(m.group(1), stage)
        if rp:
            frames.append((rp, int(m.group(2))))
    if not e_lines and not frames:
        return None
    source = [f for f in frames if not is_test_path(f[0])]
    file, line = (source or frames or [(None, None)])[-1]
    return {"file": file, "line": line, "message": " ".join(e_lines[:3]) or "test failed"}


def parse_pytest(text, stage):
    """One error per failing test. pytest separates failures with `____ test_name ____` headers."""
    parts = re.split(r"^_{2,} .+? _{2,}$", text, flags=re.M)
    sections = parts[1:] if len(parts) > 1 else [text]
    found = [e for e in (_pytest_section(p, stage) for p in sections) if e]
    return found or None


def parse_python_traceback(text, stage):
    starts = [m.start() for m in re.finditer(r"Traceback \(most recent call last\):", text)]
    if not starts:
        return None
    block = text[starts[-1]:]
    frames = []
    for m in re.finditer(r'File "([^"]+)", line (\d+)', block):
        rp = rel_path(m.group(1), stage)
        if rp:
            frames.append((rp, int(m.group(2))))
    last = ""
    for ln in block.splitlines():
        if ln.strip() and not ln.startswith((" ", "\t", "Traceback")):
            last = ln.strip()
    file, line = frames[-1] if frames else (None, None)
    return {"file": file, "line": line, "message": last or "unhandled exception"}


def parse_node_tap(text, stage):
    """node --test prints failures as TAP/YAML: a `location:` line and an indented `error: |-` block."""
    loc = re.search(r"location: '([^']+?):(\d+):\d+'", text)
    if not loc:
        return None
    rp = rel_path(loc.group(1), stage)
    block = re.search(r"error: \|-?\n((?:[ \t]+[^\n]*\n?){1,8})", text)
    lines = []
    for ln in (block.group(1).splitlines() if block else []):
        ln = ln.strip()
        if re.match(r"(code|name|expected|actual|operator|stack|generatedMessage|duration_ms)\s*:", ln):
            break
        if ln:
            lines.append(ln)
    return {"file": rp, "line": int(loc.group(2)), "message": " ".join(lines[:3]) or "test failed"}


def parse_node(text, stage):
    tap = parse_node_tap(text, stage)
    if tap:
        return tap
    frames = []
    for m in re.finditer(r"\bat (?:[^\s(]+ )?\(?([^()\s]+):(\d+):\d+\)?", text):
        rp = rel_path(m.group(1), stage)
        if rp:
            frames.append((rp, int(m.group(2))))
    msg = None
    for ln in text.splitlines():
        if re.match(r"^\s*(?:Uncaught )?(?:\w*Error|AssertionError)\b", ln):
            msg = ln.strip()
            break
    if not frames and not msg:
        return None
    file, line = frames[0] if frames else (None, None)
    return {"file": file, "line": line, "message": msg or "unhandled error"}


def parse_output(text, stage):
    for parser in (parse_pytest, parse_python_traceback, parse_node):
        got = parser(text, stage)
        if got:
            return got
    return None


def code_excerpt(stage, file, line, ctx=2):
    if not (stage and file and line):
        return None
    try:
        with open(os.path.join(stage, file), encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None
    lo, hi = max(1, line - ctx), min(len(lines), line + ctx)
    return ["%s %4d | %s" % (">" if n == line else " ", n, lines[n - 1][:140]) for n in range(lo, hi + 1)]


# ================================================================= building the error list
def errors_for(report, stage):
    findings = [f for f in report.get("findings", []) if f.get("severity") in ("error", "block")]
    errors = [{"file": f.get("file"), "line": f.get("line"), "code": f.get("code"), "message": f.get("message", ""),
               "stage": report["stage"], "severity": f.get("severity")} for f in findings]
    data = report.get("data") or {}
    text = "\n".join(filter(None, [data.get("stderr_tail"), data.get("stdout_tail"), data.get("output_tail")]))
    parsed = parse_output(text, stage) if text else None
    if parsed:
        parsed = parsed if isinstance(parsed, list) else [parsed]
        fresh = [p for p in parsed if not any(e["file"] == p["file"] and e["line"] == p["line"] for e in errors)]
        if fresh:
            # A located error is more useful than the generic "command exited with code N" finding.
            errors = [e for e in errors if e.get("code") != "nonzero-exit"]
            for p in reversed(fresh):
                errors.insert(0, dict(p, code=None, stage=report["stage"], severity="error"))
    elif text and any(e.get("code") == "nonzero-exit" for e in errors):
        last = next((ln.strip() for ln in reversed(text.splitlines()) if ln.strip()), "")
        for e in errors:
            if e.get("code") == "nonzero-exit" and last:
                e["message"] += " (last output line: %s)" % last[:160]
    if not errors and report.get("status") == "fail":
        errors.append({"file": None, "line": None, "code": None, "message": report.get("reason") or "stage failed",
                       "stage": report["stage"], "severity": "error"})
    errors.sort(key=lambda e: (e["file"] is None, e["line"] is None))
    return errors


def signature(errors):
    basis = "|".join("%s:%s:%s" % (e.get("file"), e.get("line"), (e.get("message") or "")[:120]) for e in errors[:3])
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:12]


# ================================================================= the decision and the prompt
def _looks_like_environment(failing, errors):
    """True when editing the proposed change cannot fix the failure."""
    if any(e.get("code") in ENV_CODES for e in errors):
        return True
    blobs = [failing.get("reason") or ""]
    blobs += [e.get("message") or "" for e in errors]
    for check in (failing.get("data") or {}).get("skipped_checks", []) or []:
        blobs.append(check.get("reason") or "")
        # A hard fail whose only skipped checks are missing tools is still an env problem when
        # the failure message itself mentions the missing tool (see markers below).
        blobs.append(check.get("check") or "")
    text = " ".join(blobs).lower()
    return any(marker in text for marker in ENV_REASON_MARKERS)


def decide(failing, errors, attempt, max_attempts):
    stage = failing["stage"] if failing else None
    if failing is None:
        return "none"
    if stage == "safety_scan" or any(e.get("severity") == "block" for e in errors):
        return "ask_user"
    if _looks_like_environment(failing, errors):
        return "environment"
    if attempt >= max_attempts:
        return "stop"
    return "fix"


def render_error(i, total, e, excerpt):
    loc = "%s:%s" % (e["file"], e["line"]) if e.get("file") and e.get("line") else (e.get("file") or "(no file reported)")
    lines = ["Error %d of %d" % (i, total), "  File: " + loc]
    if e.get("code"):
        lines.append("  Code: " + str(e["code"]))
    lines.append("  Error: " + e["message"])
    if excerpt:
        lines.append("  Context:")
        lines += ["    " + ln for ln in excerpt]
    return "\n".join(lines)


def build_prompt(action, failing, errors, shown, attempt, max_attempts, repeated, skipped, later):
    stage = failing["stage"] if failing else None
    if action == "none":
        out = ["No stage failed."]
        if skipped:
            out.append("Skipped stages (the verdict is PARTIAL, not VERIFIED):")
            out += ["  - %s: %s" % (s["stage"] + (" / " + s["check"] if s.get("check") else ""), s["reason"]) for s in skipped]
            out.append("Tell the user what was skipped and why before merging.")
        else:
            out.append("Every stage ran and passed: the verdict is VERIFIED.")
        return "\n".join(out)

    head = "Verification FAILED at stage: %s (attempt %d of %d)" % (stage, attempt, max_attempts)
    body = [render_error(i, len(errors), e, ex) for i, (e, ex) in enumerate(shown, 1)]
    out = [head, ""] + ["\n\n".join(body)]
    if len(errors) > len(shown):
        out.append("\n(%d more error(s) not shown; fixing the first often clears the rest.)" % (len(errors) - len(shown)))
    if later:
        out.append("\nLater stages also failed (%s). Fix the stage above first and re-verify." % ", ".join(later))
    out.append("")
    if action == "ask_user":
        out += ["ACTION: ask the user. These are safety blocks, not bugs.",
                "Do NOT fix, reword, or work around them yourself. Show the finding(s) to the user and wait.",
                "If the user approves a specific finding, re-run safety_scan.py with --approve FILE:LINE for that finding only."]
    elif action == "environment":
        out += ["ACTION: this is an environment problem, not a code problem. Editing the code will not help.",
                "Tell the user what is missing (a tool, a Docker image, a config) and how to provide it, then re-verify."]
    elif action == "stop":
        out += ["ACTION: the retry budget (%d attempts) is spent. Stop patching." % max_attempts,
                "Report to the user: what failed, what you tried, and your best theory of the cause. Let them steer."]
    else:
        out += ["ACTION: fix. Make the smallest change that resolves the first error, restage it with stage_workspace.py,",
                "and re-verify from the static stage. Do not rewrite unrelated code."]
        if repeated:
            out += ["", "WARNING: this is the SAME error as the previous attempt. Your last change did not address the cause.",
                    "Re-read the code and the error, form a different theory, and do not repeat the same patch."]
    return "\n".join(out)


# ================================================================= main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", action="append", required=True, metavar="FILE", help="stage report JSON (repeatable, '-' for stdin)")
    ap.add_argument("--stage", help="staged workspace, used to show code excerpts and shorten paths")
    ap.add_argument("--attempt", type=int, default=1, help="which verification attempt this was (default 1)")
    ap.add_argument("--max-attempts", type=int, default=3)
    ap.add_argument("--previous", help="the previous diagnostics output, to detect a repeated error")
    ap.add_argument("--max-errors", type=int, default=5)
    ap.add_argument("--format", choices=["json", "prompt"], default="json")
    args = ap.parse_args()

    stage = os.path.abspath(args.stage) if args.stage else None
    reports = load_reports(args.report)

    def rank(r):
        return STAGE_ORDER.index(r["stage"]) if r["stage"] in STAGE_ORDER else len(STAGE_ORDER)

    failing_all = sorted((r for r in reports if r.get("status") == "fail"), key=rank)
    failing = failing_all[0] if failing_all else None
    errors = errors_for(failing, stage) if failing else []
    shown = [(e, code_excerpt(stage, e.get("file"), e.get("line"))) for e in errors[:args.max_errors]]

    skipped = []
    for r in reports:
        if r.get("status") == "skipped":
            skipped.append({"stage": r["stage"], "reason": r.get("reason") or "skipped"})
        for s in (r.get("data") or {}).get("skipped_checks", []) or []:
            skipped.append({"stage": r["stage"], "check": s.get("check"), "reason": s.get("reason", "")})

    sig = signature(errors) if errors else None
    repeated = False
    if args.previous:
        try:
            with open(args.previous, encoding="utf-8") as fh:
                prev = json.load(fh)
            repeated = bool(sig) and (prev.get("data") or {}).get("signature") == sig
        except (OSError, ValueError):
            pass

    action = decide(failing, errors, args.attempt, args.max_attempts)
    later = [r["stage"] for r in failing_all[1:]]
    prompt = build_prompt(action, failing, errors, shown, args.attempt, args.max_attempts, repeated, skipped, later)

    if args.format == "prompt":
        print(prompt)
        return 0
    data = {"action": action, "failing_stage": failing["stage"] if failing else None, "attempt": args.attempt,
            "max_attempts": args.max_attempts, "attempts_left": max(0, args.max_attempts - args.attempt),
            "repeated_error": repeated, "signature": sig, "later_failures": later, "skipped": skipped,
            "errors": [dict(e, excerpt=ex) for e, ex in shown], "prompt": prompt}
    emit(STAGE, "pass", [], "", data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
