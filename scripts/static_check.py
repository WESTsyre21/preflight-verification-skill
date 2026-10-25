#!/usr/bin/env python3
"""static_check.py - type and syntax validation of the staged change. Nothing here runs project code.

TypeScript : tsc --noEmit (project mode via the nearest tsconfig.json, else file mode)
JavaScript : node --check (syntax only)
Python     : ast.parse (always) + ruff fatal rules + pyright, when installed

ESLint is deliberately NOT run here: its config file is JavaScript, so running it would
execute project code. It belongs in the sandboxed stage (run_sandboxed.py).

Which files count as "changed" comes from --changed, else from the manifest that
stage_workspace.py wrote next to the stage directory.

--scope all      (default) a type error ANYWHERE fails the stage. A change that removes an
                 export breaks its importers, and those errors live in files you did not touch.
--scope changed  only errors inside changed files fail; others are downgraded to warnings.
                 Use it for a project that already had errors before the change.

Output: {"stage": "static_check", "status": "pass|fail|skipped", "findings": [...],
         "reason": "...", "data": {"tools_run": [...], "skipped_checks": [...], ...}}
A non-empty data.skipped_checks means coverage was partial: report PARTIAL, not VERIFIED.
"""
import argparse
import ast
import json
import os
import re
import shutil
import sys

from _common import (PY_EXT, TS_EXT, all_source_files, find_node_tool, finding, load_changed,
                     load_json_lenient, norm, project_python, run)

STAGE = "static_check"
NODE_CHECKABLE = {".js", ".mjs", ".cjs"}  # .jsx needs a transform, so node --check cannot parse it
RUFF_FATAL = "E9,F63,F7,F82"  # syntax errors, invalid comparisons, undefined names
TSC_LINE = re.compile(r"^(?P<file>.+?)\((?P<line>\d+),(?P<col>\d+)\): (?P<sev>error|warning) (?P<code>TS\d+): (?P<msg>.*)$")
TSC_GLOBAL = re.compile(r"^(?P<sev>error|warning) (?P<code>TS\d+): (?P<msg>.*)$")


# ---------------------------------------------------------------- TypeScript / JavaScript
def is_solution_tsconfig(abs_path):
    """True for a references-only 'solution' config that checks no files on its own.

    tsc -p on such a config passes trivially, which would hide type errors. Callers should
    fall back to a leaf package config or file mode instead.
    """
    data = load_json_lenient(abs_path)
    if not isinstance(data, dict):
        return False
    refs = data.get("references")
    if not isinstance(refs, list) or not refs:
        return False
    files = data.get("files")
    include = data.get("include")
    has_files = isinstance(files, list) and len(files) > 0
    has_include = isinstance(include, list) and len(include) > 0
    # Explicit empty "files": [] with references is the classic solution-style pattern.
    return not has_files and not has_include


def nearest_tsconfig(stage, rel):
    """Nearest tsconfig that actually type-checks files (skips solution-style parents)."""
    d = os.path.dirname(rel)
    solution_hit = None
    while True:
        cand = os.path.join(stage, d, "tsconfig.json") if d else os.path.join(stage, "tsconfig.json")
        if os.path.isfile(cand):
            rel_cfg = norm(os.path.relpath(cand, stage))
            if is_solution_tsconfig(cand):
                solution_hit = solution_hit or rel_cfg
            else:
                return rel_cfg, solution_hit
        if not d:
            return None, solution_hit
        d = os.path.dirname(d)


def parse_tsc(output, changed_set):
    found, last = [], None
    for raw in output.splitlines():
        m = TSC_LINE.match(raw)
        if m:
            rel = norm(m.group("file"))
            last = finding("error" if m.group("sev") == "error" else "warn", "tsc", m.group("msg"),
                           file=rel, line=int(m.group("line")), col=int(m.group("col")),
                           code=m.group("code"), in_changed=rel in changed_set)
            found.append(last)
            continue
        g = TSC_GLOBAL.match(raw)
        if g:
            last = finding("error" if g.group("sev") == "error" else "warn", "tsc", g.group("msg"), code=g.group("code"))
            found.append(last)
        elif raw.startswith("  ") and last is not None:
            last["message"] += " " + raw.strip()  # tsc continues long messages on indented lines
    return found


IGNORE_DEPRECATIONS = re.compile(r"""ignoreDeprecations["']?\s*:\s*["']?([0-9]+\.[0-9]+)""")


def tsc_once(cmd, stage, timeout, changed_set):
    """Run tsc once. Returns (findings, error text); findings is None when tsc could not complete."""
    rc, so, se = run(cmd, stage, timeout)
    if rc is None:
        return None, se
    return parse_tsc(so + "\n" + se, changed_set), ""


def check_typescript(stage, ts_files, changed_set, timeout, out):
    tsc = find_node_tool(stage, "tsc")
    if not tsc:
        out["skipped"].append({"check": "tsc", "reason": "tsc not installed (npm i -D typescript)"})
        return
    groups = {}
    solution_warned = set()
    for rel in ts_files:
        tsconfig, solution = nearest_tsconfig(stage, rel)
        if solution and solution not in solution_warned:
            solution_warned.add(solution)
            out["findings"].append(finding(
                "warn", "tsc",
                "%s looks like a solution-style config (references only, no files/include). "
                "tsc -p on it would pass without checking sources, so it was skipped%s."
                % (solution, ("; using " + tsconfig if tsconfig else "; using file mode")),
                file=solution, code="solution-tsconfig"))
        groups.setdefault(tsconfig, []).append(rel)

    seen = set()
    for tsconfig, files in groups.items():
        if tsconfig:
            cmd = [tsc, "--noEmit", "--pretty", "false", "-p", tsconfig]
        else:
            cmd = [tsc, "--noEmit", "--pretty", "false", "--strict", "--skipLibCheck", "--esModuleInterop",
                   "--target", "es2020", "--module", "commonjs"] + files
        out["tools"].append("tsc" + (" -p " + tsconfig if tsconfig else " (file mode, no tsconfig.json)"))
        found, err = tsc_once(cmd, stage, timeout, changed_set)
        if found is None:
            out["findings"].append(finding("error", "tsc", "tsc could not complete: " + err))
            continue

        # An options error makes tsc skip type checking entirely, which would hide real errors behind a
        # false pass. Deprecation errors are the one kind we can safely step past, using the value tsc suggests.
        deprecated = [f for f in found if IGNORE_DEPRECATIONS.search(f["message"])]
        if deprecated:
            version = IGNORE_DEPRECATIONS.search(deprecated[0]["message"]).group(1)
            retry, err = tsc_once(cmd + ["--ignoreDeprecations", version], stage, timeout, changed_set)
            if retry is not None:
                found = retry
                out["findings"].append(finding(
                    "warn", "tsc", "tsconfig uses options deprecated in this TypeScript version; checked with "
                    "--ignoreDeprecations %s. Update the config before the next major TypeScript upgrade." % version,
                    file=tsconfig, code="config-deprecated"))

        if any((f.get("code") or "").startswith("TS5") and f["severity"] == "error" for f in found):
            out["findings"].append(finding(
                "error", "tsc", "tsc reported configuration errors, so type checking did NOT run on your code. "
                "Fix the configuration (or pass a working tsconfig) and re-verify.", file=tsconfig, code="type-check-blocked"))

        for f in found:
            key = (f.get("file"), f.get("line"), f.get("col"), f.get("code"), f["message"])
            if key not in seen:
                seen.add(key)
                out["findings"].append(f)
    out["files_checked"] += len(ts_files)


def check_node_syntax(stage, js_files, timeout, out):
    node = shutil.which("node")
    if not node:
        out["skipped"].append({"check": "node --check", "reason": "node not installed"})
        return
    out["tools"].append("node --check")
    for rel in js_files:
        rc, _so, se = run([node, "--check", rel], stage, timeout)
        if rc is None:
            out["findings"].append(finding("error", "node", "syntax check could not complete: " + se, file=rel))
        elif rc != 0:
            m = re.search(r":(\d+)\n", se)
            msg = next((ln for ln in se.splitlines() if "Error" in ln), se.strip()[:300])
            out["findings"].append(finding("error", "node", msg.strip(), file=rel,
                                           line=int(m.group(1)) if m else None, code="SyntaxError", in_changed=True))
    out["files_checked"] += len(js_files)


# ---------------------------------------------------------------- Python
def check_python_syntax(stage, py_files, out):
    """In-process parse: no .pyc files written, no imports executed."""
    broken = set()
    out["tools"].append("ast.parse")
    for rel in py_files:
        try:
            with open(os.path.join(stage, rel), "rb") as fh:
                ast.parse(fh.read(), filename=rel)
        except SyntaxError as exc:
            broken.add(rel)
            out["findings"].append(finding("error", "python", exc.msg or "invalid syntax", file=rel,
                                           line=exc.lineno, col=exc.offset, code="SyntaxError", in_changed=True))
        except (OSError, ValueError) as exc:
            broken.add(rel)
            out["findings"].append(finding("error", "python", "could not read file: %s" % exc, file=rel))
    out["files_checked"] += len(py_files)
    return broken


def check_ruff(stage, py_files, timeout, out):
    ruff = find_node_tool(stage, "ruff")
    if not ruff:
        out["skipped"].append({"check": "ruff", "reason": "not installed (pip install ruff)"})
        return
    cmd = [ruff, "check", "--output-format", "json", "--no-cache", "--isolated", "--select", RUFF_FATAL] + py_files
    rc, so, se = run(cmd, stage, timeout)
    out["tools"].append("ruff (fatal rules " + RUFF_FATAL + ")")
    if rc is None:
        out["findings"].append(finding("error", "ruff", "ruff could not complete: " + se))
        return
    try:
        items = json.loads(so or "[]")
    except ValueError:
        out["findings"].append(finding("error", "ruff", "could not parse ruff output: " + (se or so)[:300]))
        return
    for it in items:
        rel = norm(os.path.relpath(it.get("filename", ""), stage)) if it.get("filename") else None
        loc = it.get("location") or {}
        out["findings"].append(finding("error", "ruff", it.get("message", ""), file=rel, line=loc.get("row"),
                                       col=loc.get("column"), code=it.get("code"), in_changed=True))


def check_pyright(stage, py_files, timeout, out):
    pyright = find_node_tool(stage, "pyright") or shutil.which("pyright")
    if not pyright:
        out["skipped"].append({"check": "pyright", "reason": "not installed (pip install pyright or npm i -D pyright)"})
        return
    cmd = [pyright, "--outputjson"]
    py = project_python(stage)
    if py:
        cmd += ["--pythonpath", py]
    cmd += py_files
    rc, so, se = run(cmd, stage, timeout)
    out["tools"].append("pyright")
    if rc is None:
        out["findings"].append(finding("error", "pyright", "pyright could not complete: " + se))
        return
    try:
        report = json.loads(so)
    except ValueError:
        out["findings"].append(finding("error", "pyright", "could not parse pyright output: " + (se or so)[:300]))
        return
    for d in report.get("generalDiagnostics", []):
        sev = d.get("severity")
        if sev not in ("error", "warning"):
            continue
        rel = norm(os.path.relpath(d["file"], stage)) if d.get("file") else None
        start = (d.get("range") or {}).get("start", {})
        out["findings"].append(finding("error" if sev == "error" else "warn", "pyright", d.get("message", ""),
                                       file=rel, line=start.get("line", 0) + 1, col=start.get("character", 0) + 1,
                                       code=d.get("rule"), in_changed=True))


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stage", required=True, help="staged workspace directory")
    ap.add_argument("--changed", nargs="*", help="changed files relative to the stage (default: read the manifest)")
    ap.add_argument("--lang", choices=["auto", "ts", "py"], default="auto")
    ap.add_argument("--scope", choices=["all", "changed"], default="all")
    ap.add_argument("--timeout", type=int, default=120, help="per-tool timeout in seconds")
    args = ap.parse_args()

    stage = os.path.abspath(args.stage)
    if not os.path.isdir(stage):
        print(json.dumps({"stage": STAGE, "status": "fail", "findings": [], "reason": "stage directory not found: " + stage, "data": {}}, indent=2))
        return 2

    changed, how = load_changed(stage, args.changed)
    extra = []
    if changed is None:
        changed = all_source_files(stage, TS_EXT | NODE_CHECKABLE | PY_EXT)
        extra.append(finding("warn", "static_check", "no manifest or --changed given; checking every source file in the stage"))
    changed_set = set(changed)

    ts_files = [f for f in changed if os.path.splitext(f)[1].lower() in TS_EXT] if args.lang in ("auto", "ts") else []
    js_files = [f for f in changed if os.path.splitext(f)[1].lower() in NODE_CHECKABLE] if args.lang in ("auto", "ts") else []
    py_files = [f for f in changed if os.path.splitext(f)[1].lower() in PY_EXT] if args.lang in ("auto", "py") else []
    for rel in ts_files + js_files + py_files:
        if not os.path.isfile(os.path.join(stage, rel)):
            extra.append(finding("warn", "static_check", "listed as changed but missing from the stage", file=rel))
    ts_files = [f for f in ts_files if os.path.isfile(os.path.join(stage, f))]
    js_files = [f for f in js_files if os.path.isfile(os.path.join(stage, f))]
    py_files = [f for f in py_files if os.path.isfile(os.path.join(stage, f))]

    out = {"findings": extra, "tools": [], "skipped": [], "files_checked": 0}

    if ts_files:
        check_typescript(stage, ts_files, changed_set, args.timeout, out)
    if js_files:
        check_node_syntax(stage, js_files, args.timeout, out)
    if py_files:
        broken = check_python_syntax(stage, py_files, out)
        clean = [f for f in py_files if f not in broken]  # tools choke on files that do not parse
        if clean:
            check_ruff(stage, clean, args.timeout, out)
            check_pyright(stage, clean, args.timeout, out)

    # Apply scope: errors outside changed files become warnings when scope is "changed".
    if args.scope == "changed":
        for f in out["findings"]:
            if f["severity"] == "error" and f.get("in_changed_file") is False:
                f["severity"] = "warn"
                f["message"] += " (outside changed files; may be pre-existing)"

    errors = [f for f in out["findings"] if f["severity"] == "error"]
    data = {
        "changed_source": how,
        "scope": args.scope,
        "files_checked": out["files_checked"],
        "tools_run": out["tools"],
        "skipped_checks": out["skipped"],
        "error_count": len(errors),
        "warning_count": sum(1 for f in out["findings"] if f["severity"] == "warn"),
    }

    if not (ts_files or js_files or py_files):
        status, reason = "skipped", "no checkable TypeScript/JavaScript/Python files in the change set"
    elif not out["tools"]:
        status, reason = "skipped", "no static-analysis tool could run: " + "; ".join(s["check"] + " " + s["reason"] for s in out["skipped"])
    elif errors:
        status, reason = "fail", "%d error(s) found" % len(errors)
    else:
        status, reason = "pass", ("partial coverage: " + ", ".join(s["check"] for s in out["skipped"]) + " skipped") if out["skipped"] else ""

    print(json.dumps({"stage": STAGE, "status": status, "findings": out["findings"], "reason": reason, "data": data}, indent=2))
    return 1 if status == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
