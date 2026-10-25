#!/usr/bin/env python3
"""run_tests.py - run only the tests that cover the change, then probe edge cases. Everything runs in the sandbox.

    run_tests.py --stage <dir> [--tier auto|A|B] [--edge-cases off|warn|strict] [--timeout 120]

1. TEST SELECTION. A changed file is covered by (a) itself, if it is a test, (b) a test named after it
   (test_x.py, x_test.py, x.test.ts, x.spec.ts), and (c) any test that imports it. This looks ONE level
   deep, so a test of something that merely imports the changed file is not selected. That keeps the loop
   fast; the result lists exactly which tests ran so you can see what was and was not covered.
2. RUNNING. pytest (else unittest) for Python; vitest, jest, or `node --test` for JS/TS. All of it goes
   through run_sandboxed.py, so the isolation tier and its caveats apply.
3. EDGE-CASE PROBES (Python only in this version). Public top-level functions are called with boundary
   inputs: "", 0, -1, 2**63, nan, inf, [], None where the signature allows them. With hypothesis installed and a fully
   annotated signature, hypothesis generates the inputs; otherwise a fixed table does. Only programming-error
   exceptions (TypeError, AttributeError, IndexError, KeyError, ZeroDivisionError, RecursionError, NameError)
   and hangs count; a ValueError for bad input is treated as correct validation.
   --edge-cases warn    (default) every probe finding is a warning; they never fail the stage
   --edge-cases strict  a crash on an input the annotation says is VALID fails the stage
   --edge-cases off     skip probes
   JS/TS probes are not supported yet, and the result lists that as a skipped check.

A change with NO covering tests is reported as `skipped`, never as a pass.

Output: {"stage": "run_tests", "status": "pass|fail|skipped", "findings": [...], "reason": "...", "data": {...}}
"""
import argparse
import ast
import json
import os
import re
import shlex
import shutil
import subprocess
import sys

from _common import JS_EXT, PY_EXT, SKIP_DIRS, TS_EXT, emit, finding, load_changed, norm, project_python, run
from dep_check import js_specifiers

STAGE = "run_tests"
TOOL = "tests"
SCRIPTS = os.path.dirname(os.path.abspath(__file__))
JS_ALL = TS_EXT | JS_EXT
JS_NODE_RUNNABLE = {".js", ".mjs", ".cjs"}
PY_TEST_RE = re.compile(r"(^|/)(test_[^/]*\.py|[^/]*_test\.py)$")
JS_TEST_RE = re.compile(
    r"(^|/)([^/]*\.(test|spec)\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)|__tests__/[^/]*\.(js|jsx|mjs|cjs|ts|tsx|mts|cts))$"
)
PY_SKIP_PROBE = re.compile(r"(^|/)(__init__|conftest|setup|manage|wsgi|asgi)\.py$|(^|/)tests?/")
MAX_TESTS = 200


# ================================================================= test discovery and mapping
def find_tests(stage):
    py, js = [], []
    for dirpath, dirnames, filenames in os.walk(stage):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            rel = norm(os.path.relpath(os.path.join(dirpath, name), stage))
            if PY_TEST_RE.search(rel):
                py.append(rel)
            elif JS_TEST_RE.search(rel):
                js.append(rel)
    return sorted(py), sorted(js)


def stem(path):
    """Path without its (known) extension; .d.ts counts as one extension."""
    for ext in (".d.ts",) + tuple(sorted(JS_ALL | PY_EXT)):
        if path.endswith(ext):
            return path[:-len(ext)]
    return path


def py_module_names(rel):
    parts = stem(rel).split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return {".".join(parts[i:]) for i in range(len(parts)) if parts[i:]}


def py_imports(stage, test_rel):
    """(absolute dotted names imported, path stems of relative imports) for one test file."""
    names, stems = set(), set()
    try:
        with open(os.path.join(stage, test_rel), "rb") as fh:
            tree = ast.parse(fh.read())
    except (OSError, SyntaxError, ValueError):
        return names, stems
    here = os.path.dirname(test_rel)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                names.add(node.module)
                names |= {node.module + "." + a.name for a in node.names}
            elif node.level > 0:
                base = os.path.normpath(os.path.join(here, *([".."] * (node.level - 1))))
                mod = os.path.join(base, *(node.module.split("."))) if node.module else base
                stems.add(norm(mod))
                stems |= {norm(os.path.join(mod, a.name)) for a in node.names}
    return names, stems


def map_python(stage, changed_py, test_files):
    mapping = {}
    imports = {t: py_imports(stage, t) for t in test_files}
    for rel in changed_py:
        if PY_TEST_RE.search(rel):
            mapping[rel] = [rel]
            continue
        mods, st = py_module_names(rel), stem(rel)
        base = os.path.basename(st)
        hits = []
        for t in test_files:
            tname = os.path.basename(stem(t))
            named = tname in ("test_" + base, base + "_test")
            names, stems = imports[t]
            if named or (mods & names) or (st in stems) or (st.endswith("/__init__") and os.path.dirname(st) in stems):
                hits.append(t)
        mapping[rel] = hits
    return mapping


def map_js(stage, changed_js, test_files):
    mapping = {}
    specs = {}
    for t in test_files:
        try:
            with open(os.path.join(stage, t), encoding="utf-8", errors="replace") as fh:
                specs[t] = [s for s, _ln in js_specifiers(fh.read()) if s.startswith(".")]
        except OSError:
            specs[t] = []
    for rel in changed_js:
        if JS_TEST_RE.search(rel):
            mapping[rel] = [rel]
            continue
        st = stem(rel)
        base = os.path.basename(st)
        hits = []
        for t in test_files:
            tbase = re.sub(r"\.(test|spec)$", "", os.path.basename(stem(t)))
            named = tbase == base
            imported = False
            for spec in specs[t]:
                target = norm(os.path.join(os.path.dirname(t), spec))
                if stem(target) == st or target == st or (st.endswith("/index") and target == os.path.dirname(st)):
                    imported = True
                    break
            if named or imported:
                hits.append(t)
        mapping[rel] = hits
    return mapping


# ================================================================= running through the sandbox
def sandbox(stage, cmd, args, timeout):
    argv = [sys.executable, os.path.join(SCRIPTS, "run_sandboxed.py"), "--stage", stage, "--cmd", cmd,
            "--tier", args.tier, "--timeout", str(timeout), "--mem-mb", str(args.mem_mb)]
    if args.image:
        argv += ["--image", args.image]
    if args.no_netns:
        argv.append("--no-netns")
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout + 60)
    try:
        return json.loads(proc.stdout)
    except ValueError:
        return {"status": "fail", "reason": "run_sandboxed.py gave no JSON: " + (proc.stderr or proc.stdout)[:300],
                "findings": [], "data": {}}


def python_runner(stage):
    py = project_python(stage) or shutil.which("python3") or sys.executable
    rc, _o, _e = run([py, "-c", "import pytest"], stage, 20)
    return "pytest" if rc == 0 else "unittest"


def js_runner(stage, tests):
    bin_dir = os.path.join(stage, "node_modules", ".bin")
    for name in ("vitest", "jest"):
        if os.path.exists(os.path.join(bin_dir, name)):
            return name
    if shutil.which("node") and all(os.path.splitext(t)[1] in JS_NODE_RUNNABLE for t in tests):
        return "node"
    return None


def build_cmd(runner, files):
    quoted = " ".join(shlex.quote(f) for f in files)
    if runner == "pytest":
        return "python3 -m pytest -q -rfE --tb=short -p no:cacheprovider " + quoted
    if runner == "unittest":
        mods = " ".join(shlex.quote(stem(f).replace("/", ".")) for f in files)
        return "python3 -m unittest -v " + mods
    if runner == "vitest":
        return "./node_modules/.bin/vitest run " + quoted
    if runner == "jest":
        return "./node_modules/.bin/jest --ci --runTestsByPath " + quoted
    return "node --test " + quoted


def last_int(pattern, text):
    found = re.findall(pattern, text)
    return int(found[-1]) if found else 0


def parse_summary(runner, text):
    s = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0, "collected_none": False}
    names = []
    if runner == "pytest":
        s.update(passed=last_int(r"(\d+) passed", text), failed=last_int(r"(\d+) failed", text),
                 errors=last_int(r"(\d+) errors?\b", text), skipped=last_int(r"(\d+) skipped", text))
        s["collected_none"] = "no tests ran" in text
        names = [(m.group(2), (m.group(3) or "").strip()) for m in re.finditer(r"^(FAILED|ERROR) (\S+)(?: - (.*))?$", text, re.M)]
    elif runner == "unittest":
        ran = last_int(r"Ran (\d+) tests?", text)
        fm = re.search(r"FAILED \(([^)]*)\)", text)
        failed = last_int(r"failures=(\d+)", fm.group(1)) if fm else 0
        errs = last_int(r"errors=(\d+)", fm.group(1)) if fm else 0
        s.update(passed=max(0, ran - failed - errs), failed=failed, errors=errs, collected_none=ran == 0)
        names = [(m.group(2) + " (" + m.group(3) + ")", "") for m in re.finditer(r"^(FAIL|ERROR): (\S+) \((\S+)\)", text, re.M)]
    elif runner in ("jest", "vitest"):
        line = re.search(r"^\s*Tests:?\s+(.*)$", text, re.M)
        chunk = line.group(1) if line else ""
        s.update(passed=last_int(r"(\d+) passed", chunk), failed=last_int(r"(\d+) failed", chunk),
                 skipped=last_int(r"(\d+) skipped", chunk), collected_none=not line)
        pat = r"^\s*●\s+(.+)$" if runner == "jest" else r"^\s*FAIL\s+(.+)$"
        names = [(m.group(1).strip(), "") for m in re.finditer(pat, text, re.M)]
    else:  # node --test
        s.update(passed=last_int(r"# pass (\d+)", text), failed=last_int(r"# fail (\d+)", text),
                 skipped=last_int(r"# skipped (\d+)", text))
        s["collected_none"] = s["passed"] + s["failed"] == 0
        names = [(m.group(1).strip(), "") for m in re.finditer(r"^not ok \d+ - (.+)$", text, re.M)]
    return s, names


def run_group(stage, runner, files, args):
    """Run one language's tests. Returns (summary, findings, sandbox report, cmd)."""
    cmd = build_cmd(runner, files)
    rep = sandbox(stage, cmd, args, args.timeout)
    d = rep.get("data") or {}
    text = "\n".join(filter(None, [d.get("stdout_tail"), d.get("stderr_tail")]))
    summary, failed = parse_summary(runner, text)
    findings = []
    for name, detail in failed[:15]:
        file = name.split("::")[0] if "::" in name and name.split("::")[0].endswith(".py") else None
        findings.append(finding("error", runner, ("%s failed" % name) + (": " + detail if detail else ""),
                                file=file, code="test-failed"))
    for f in rep.get("findings", []):
        if f.get("severity") == "error" and f.get("code") != "nonzero-exit":
            findings.append(f)  # timeout, memory, image-missing, etc. come through untouched
    return summary, findings, rep, cmd


# ================================================================= Python edge-case probes
PROBE = r"""
import ast, contextlib, importlib, importlib.util, inspect, io, json, os, signal, sys, types, typing

ROOT = os.getcwd()
CFG = json.load(open(".preflight_probe.json"))
OUT = ".preflight_probe_out.json"
BUG = (TypeError, AttributeError, IndexError, KeyError, ZeroDivisionError, RecursionError, UnboundLocalError, NameError)
sys.path[:0] = [ROOT, os.path.join(ROOT, "src")]
HYP = False
if CFG["engine"] != "table":
    try:
        from hypothesis import HealthCheck, given, settings, strategies as st
        HYP = True
    except Exception:
        HYP = False

class ProbeTimeout(Exception):
    pass

def _alarm(signum, frame):
    raise ProbeTimeout()

signal.signal(signal.SIGALRM, _alarm)
EMPTY = inspect.Parameter.empty
TABLE = {
    str: ["", " ", "a" * 10000, "\u00fcn\u00ef\u00a9ode", "0", "\n"],
    int: [0, -1, 1, 2 ** 31, 2 ** 63, -2 ** 63],
    float: [0.0, -0.0, float("nan"), float("inf"), float("-inf"), 1e308, -1.5],
    bool: [True, False],
    list: [[], [None], [0] * 10000],
    dict: [{}],
    tuple: [()],
    bytes: [b"", b"\x00"],
}
BASE = {str: "x", int: 1, float: 1.0, bool: True, list: [1], dict: {"a": 1}, tuple: (1,), bytes: b"x"}
GENERIC = [None, 0, -1, "", [], {}]

def short(v):
    r = repr(v)
    return r if len(r) <= 40 else r[:37] + "..."

def domain(ann):
    # (values legal under the annotation or generic probes, annotated?, baseline) ; values None = cannot generate
    if ann is EMPTY or ann is typing.Any:
        return GENERIC, False, 1
    origin = typing.get_origin(ann)
    union_types = (typing.Union, getattr(types, "UnionType", typing.Union))
    nullable, kinds = False, []
    if origin in union_types:
        args = typing.get_args(ann)
        nullable = type(None) in args
        kinds = [typing.get_origin(a) or a for a in args if a is not type(None)]
    else:
        kinds = [origin or ann]
    values = []
    for k in kinds:
        values += TABLE.get(k, [])
    if nullable:
        values.append(None)
    if not values:
        return None, True, None
    return values, True, (BASE.get(kinds[0], values[0]) if kinds else None)

def line_in(exc, path):
    line, tb = None, exc.__traceback__
    while tb:
        if os.path.abspath(tb.tb_frame.f_code.co_filename) == path:
            line = tb.tb_lineno
        tb = tb.tb_next
    return line

def call(fn, args, path):
    sink = io.StringIO()
    signal.setitimer(signal.ITIMER_REAL, CFG["call_timeout"])
    try:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            fn(*args)
    except ProbeTimeout:
        return ("hang", "timeout", "no result within %ss" % CFG["call_timeout"], None)
    except BUG as exc:
        return ("bug", type(exc).__name__, str(exc)[:120], line_in(exc, path))
    except BaseException:
        return None  # SystemExit, ValueError and friends: acceptable behaviour for hostile input
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    return None

def load(rel, path):
    dotted = rel[:-3].replace("/", ".")
    if dotted.startswith("src."):
        dotted = dotted[4:]
    signal.setitimer(signal.ITIMER_REAL, 10)
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                mod = importlib.import_module(dotted)
                if os.path.abspath(getattr(mod, "__file__", "") or "") == path:
                    return mod, None
            except Exception:
                pass
            spec = importlib.util.spec_from_file_location("_pf_" + dotted.replace(".", "_"), path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = mod
            spec.loader.exec_module(mod)
            return mod, None
    except BaseException as exc:
        return None, "%s: %s" % (type(exc).__name__, str(exc)[:120])
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)

def eligible(tree):
    names = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or node.decorator_list or node.name.startswith("_") or node.name == "main":
            continue
        a = node.args
        if a.posonlyargs or not a.args or len(a.args) > 5 or any(d is None for d in a.kw_defaults):
            continue
        if any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in ast.walk(node)):
            continue
        names.append(node.name)
    return names

class Found(Exception):
    pass

NOTES = []

def probe_hypothesis(fn, params, hints, path):
    strategies = []
    for p in params:
        ann = hints.get(p.name, EMPTY)
        if ann is EMPTY or ann is typing.Any:
            return None
        strategies.append(st.from_type(ann))
    seen = []
    def check(*args):
        r = call(fn, list(args), path)
        if r:
            seen.append((args, r))
            raise Found()
    # @given needs a function with NAMED parameters, so build one with exactly this arity.
    names = ["a%d" % i for i in range(len(params))]
    ns = {"check": check}
    exec("def prop(%s):\n    check(%s)\n" % (", ".join(names), ", ".join(names)), ns)
    prop = settings(max_examples=60, deadline=None, database=None, derandomize=True,
                    suppress_health_check=list(HealthCheck))(given(*strategies)(ns["prop"]))
    try:
        prop()
    except Found:
        pass
    except Exception as exc:
        NOTES.append("hypothesis could not run for %s (%s: %s); used the fixed table" % (fn.__name__, type(exc).__name__, str(exc)[:80]))
        return None
    if not seen:
        return []
    args, r = seen[-1]  # hypothesis replays the shrunk, minimal example last
    return [dict(kind=r[0], annotated=True, param=None, value=short(args), exc=r[1], message=r[2], line=r[3], engine="hypothesis")]

def baselines(params, doms):
    # Annotated parameters get a value of their type. Unannotated ones try several plausible values, because
    # one fixed guess (say 1) would make a perfectly good function crash on ordinary input and hide real findings.
    has_unannotated = any(not annotated for (_v, annotated, _b) in doms)
    for cand in (["x", 1, [1], {"a": 1}, 1.0] if has_unannotated else [None]):
        base = []
        for p, (vals, annotated, b) in zip(params, doms):
            if p.default is not EMPTY:
                base.append(p.default)
            elif annotated:
                base.append(b if vals is not None else cand)
            else:
                base.append(cand)
        yield base

def probe_table(fn, params, hints, path):
    doms = [domain(hints.get(p.name, EMPTY)) for p in params]
    base = None
    for cand in baselines(params, doms):
        first = call(fn, list(cand), path)
        if first and first[0] == "hang":
            return [dict(kind="hang", annotated=False, param=None, value=short(tuple(cand)), exc=first[1], message=first[2], line=None, engine="table")]
        if not (first and first[0] == "bug"):
            base = cand
            break
    if base is None:
        return None  # crashes even on ordinary input: a precondition we cannot guess, so probing would only add noise
    out, calls = [], 0
    for i, (p, (vals, annotated, _b)) in enumerate(zip(params, doms)):
        if vals is None:
            continue
        for v in vals:
            if calls >= 40:
                break
            args = list(base)
            args[i] = v
            calls += 1
            r = call(fn, args, path)
            if r:
                out.append(dict(kind=r[0], annotated=annotated, param=p.name, value=short(v), exc=r[1], message=r[2], line=r[3], engine="table"))
    return out

results, notes, probed = [], NOTES, 0
for rel in CFG["files"]:
    path = os.path.abspath(rel)
    try:
        tree = ast.parse(open(path, encoding="utf-8").read())
    except Exception as exc:
        notes.append({"file": rel, "note": "could not parse: %s" % exc})
        continue
    names = eligible(tree)
    if not names:
        continue
    mod, err = load(rel, path)
    if mod is None:
        notes.append({"file": rel, "note": "could not import, so no probes ran: " + err})
        continue
    for name in names:
        fn = getattr(mod, name, None)
        if not callable(fn) or getattr(fn, "__module__", None) != getattr(mod, "__name__", None):
            continue
        try:
            sig = inspect.signature(fn)
            params = [p for p in sig.parameters.values() if p.kind == p.POSITIONAL_OR_KEYWORD]
        except (TypeError, ValueError):
            continue
        try:
            hints = typing.get_type_hints(fn)
        except Exception:
            hints = {}
        found = None
        if HYP:
            found = probe_hypothesis(fn, params, hints, path)
        if found is None:
            found = probe_table(fn, params, hints, path)
        if found is None:
            notes.append({"file": rel, "function": name, "note": "skipped: crashes on ordinary input, so probe results would be noise"})
            continue
        probed += 1
        seen = set()
        for r in found:
            key = (r["param"], r["exc"], r["line"])
            if key in seen:
                continue
            seen.add(key)
            r.update(function=name, file=rel)
            results.append(r)

json.dump({"results": results[:40], "notes": notes, "functions_probed": probed, "hypothesis_available": HYP}, open(OUT, "w"))
"""


def probe_files(changed_py):
    return [f for f in changed_py if not PY_TEST_RE.search(f) and not PY_SKIP_PROBE.search(f)]


def run_probes(stage, files, args):
    """Returns (probe result dict or None, note). Files written into the stage are removed afterwards."""
    cfg_path = os.path.join(stage, ".preflight_probe.json")
    script_path = os.path.join(stage, ".preflight_probe.py")
    out_path = os.path.join(stage, ".preflight_probe_out.json")
    with open(cfg_path, "w") as fh:
        json.dump({"files": files, "engine": args.edge_engine, "call_timeout": 1.0}, fh)
    with open(script_path, "w") as fh:
        fh.write(PROBE)
    try:
        rep = sandbox(stage, "python3 .preflight_probe.py", args, args.probe_timeout)
        if os.path.isfile(out_path):
            with open(out_path) as fh:
                return json.load(fh), None
        why = rep.get("reason") or "no output file"
        return None, "edge-case probes could not complete: " + why[:200]
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return None, "edge-case probes could not complete: %s" % exc
    finally:
        for p in (cfg_path, script_path, out_path):
            try:
                os.remove(p)
            except OSError:
                pass


def probe_findings(result, mode):
    out = []
    for r in result["results"]:
        where = "%s(%s=%s)" % (r["function"], r["param"], r["value"]) if r["param"] else "%s%s" % (r["function"], r["value"])
        if r["kind"] == "hang":
            out.append(finding("warn", "probe/" + r["engine"], "%s did not return within 1s: possible infinite loop or very slow path" % where,
                               file=r["file"], line=r["line"], code="edge-case-hang"))
        elif r["annotated"]:
            sev = "error" if mode == "strict" else "warn"
            out.append(finding(sev, "probe/" + r["engine"], "%s raised %s (%s) on an input its annotation allows" % (where, r["exc"], r["message"]),
                               file=r["file"], line=r["line"], code="edge-case-crash",
                               suggestion="Handle this input, or tighten the type annotation if it is not supported."))
        else:
            out.append(finding("warn", "probe/" + r["engine"], "%s raised %s (%s); the parameter is unannotated, so this may be intended" % (where, r["exc"], r["message"]),
                               file=r["file"], line=r["line"], code="edge-case-fragile"))
    for n in result.get("notes", []):
        out.append(finding("info", "probe", n["note"], file=n.get("file")))
    return out


# ================================================================= main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stage", required=True, help="staged workspace created by stage_workspace.py")
    ap.add_argument("--changed", nargs="*", help="changed files relative to the stage (default: read the manifest)")
    ap.add_argument("--tier", choices=["auto", "A", "B"], default="auto")
    ap.add_argument("--timeout", type=int, default=120, help="seconds allowed for each test run")
    ap.add_argument("--probe-timeout", type=int, default=60, help="seconds allowed for the edge-case probes")
    ap.add_argument("--mem-mb", type=int, default=1024)
    ap.add_argument("--image", help="Docker image for Tier A")
    ap.add_argument("--no-netns", action="store_true", help="Tier B: use network shims instead of a namespace (testing)")
    ap.add_argument("--edge-cases", choices=["off", "warn", "strict"], default="warn")
    ap.add_argument("--edge-engine", choices=["auto", "table"], default="auto", help="'table' forces the fixed input table")
    args = ap.parse_args()

    stage = os.path.abspath(args.stage)
    if not os.path.isdir(stage):
        emit(STAGE, "fail", [], "stage directory not found: " + stage, {})
        return 2
    changed, how = load_changed(stage, args.changed)
    if changed is None:
        emit(STAGE, "fail", [], "no manifest or --changed given: cannot tell which tests cover the change", {})
        return 2

    changed_py = [f for f in changed if os.path.splitext(f)[1] in PY_EXT and os.path.isfile(os.path.join(stage, f))]
    changed_js = [f for f in changed if os.path.splitext(f)[1] in JS_ALL and os.path.isfile(os.path.join(stage, f))]
    if not (changed_py or changed_js):
        emit(STAGE, "skipped", [], "no Python or JavaScript/TypeScript files in the change set", {"changed_source": how})
        return 0

    py_tests, js_tests = find_tests(stage)
    mapping = {}
    mapping.update(map_python(stage, changed_py, py_tests) if changed_py else {})
    mapping.update(map_js(stage, changed_js, js_tests) if changed_js else {})
    sel_py = sorted({t for f in changed_py for t in mapping.get(f, [])})[:MAX_TESTS]
    sel_js = sorted({t for f in changed_js for t in mapping.get(f, [])})[:MAX_TESTS]
    uncovered = sorted(f for f in changed_py + changed_js if not mapping.get(f))

    findings, skipped_checks, runs = [], [], []
    totals = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    sandbox_unavailable, hard_fail = None, False

    for label, files, runner in (("python", sel_py, python_runner(stage) if sel_py else None),
                                 ("javascript/typescript", sel_js, js_runner(stage, sel_js) if sel_js else None)):
        if not files:
            continue
        if runner is None:
            skipped_checks.append({"check": label + " tests", "reason": "no usable test runner (install vitest or jest for TypeScript)"})
            continue
        summary, fnds, rep, cmd = run_group(stage, runner, files, args)
        findings += fnds
        d = rep.get("data") or {}
        if rep.get("status") == "skipped":
            sandbox_unavailable = rep.get("reason") or "no sandbox tier available"
            continue
        for k in totals:
            totals[k] += summary[k]
        ok = (rep.get("status") == "pass" or summary["collected_none"]) and summary["failed"] == 0 and summary["errors"] == 0
        hard_fail = hard_fail or not ok
        if rep.get("status") == "fail" and not fnds:
            findings.append(finding("error", runner, rep.get("reason") or "test run failed", code="test-run-failed"))
        runs.append({"language": label, "runner": runner, "command": cmd, "tests": files, "summary": summary,
                     "exit_code": d.get("exit_code"), "tier": d.get("tier"), "network_block": d.get("network_block"),
                     "duration_s": d.get("duration_s"), "killed_for": d.get("killed_for"),
                     "output_tail": ((d.get("stdout_tail") or "") + (d.get("stderr_tail") or ""))[-8000:]})

    ran_tests = bool(runs)
    collected_none = ran_tests and totals["passed"] + totals["failed"] + totals["errors"] == 0

    # ---- edge-case probes (Python only)
    probe_info = None
    if args.edge_cases == "off":
        skipped_checks.append({"check": "edge-case probes", "reason": "turned off (--edge-cases off)"})
    else:
        targets = probe_files(changed_py)
        if changed_js:
            skipped_checks.append({"check": "edge-case probes (JS/TS)", "reason": "not supported in this version"})
        if targets and sandbox_unavailable is None:
            result, note = run_probes(stage, targets, args)
            if result is None:
                findings.append(finding("warn", "probe", note))
                skipped_checks.append({"check": "edge-case probes", "reason": note})
            else:
                findings += probe_findings(result, args.edge_cases)
                probe_info = {"functions_probed": result["functions_probed"], "findings": len(result["results"]),
                              "hypothesis_available": result["hypothesis_available"], "mode": args.edge_cases}
        elif targets:
            skipped_checks.append({"check": "edge-case probes", "reason": "no sandbox tier available"})

    for f in uncovered:
        findings.append(finding("warn", TOOL, "no test covers this file", file=f, code="no-covering-test",
                                suggestion="Offer to write a test for it."))

    errors = [f for f in findings if f["severity"] == "error"]
    data = {"changed_source": how, "mapping": mapping, "mapping_depth": 1, "tests_selected": sel_py + sel_js,
            "uncovered_files": uncovered, "totals": totals, "runs": runs, "probes": probe_info,
            "skipped_checks": skipped_checks, "output_tail": "\n".join(r["output_tail"] for r in runs)[-8000:]}

    if sandbox_unavailable and not ran_tests:
        status, reason = "skipped", "tests could not run: " + sandbox_unavailable
    elif errors or hard_fail:
        status = "fail"
        reason = "%d failed, %d errors" % (totals["failed"], totals["errors"]) if (totals["failed"] or totals["errors"]) \
            else (errors[0]["message"] if errors else "test run failed")
    elif not (sel_py or sel_js):
        status, reason = "skipped", "no tests cover the changed files (they are not tests, are not named like a test, and no test imports them)"
    elif not ran_tests:
        status, reason = "skipped", "; ".join(s["check"] + ": " + s["reason"] for s in skipped_checks) or "no tests ran"
    elif collected_none:
        status, reason = "skipped", "the runner started but collected 0 tests"
    else:
        status, reason = "pass", ""
    emit(STAGE, status, findings, reason, data)
    return 1 if status == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
