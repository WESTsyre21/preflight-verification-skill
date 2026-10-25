"""_common.py - helpers shared by the preflight-verify stage scripts.

Every stage script prints one JSON object with this shape, so the agent (and
diagnostics.py) can treat all stages uniformly:

    {"stage": "<name>", "status": "pass|fail|skipped", "findings": [...],
     "reason": "<why, when not a plain pass>", "data": {...}}

A finding is {"severity": "error|warn|info|block", "tool": ..., "message": ...} plus
optional file / line / col / code / in_changed_file / suggestion.
"""
import json
import os
import re
import shutil
import subprocess

TS_EXT = {".ts", ".tsx", ".mts", ".cts"}
JS_EXT = {".js", ".jsx", ".mjs", ".cjs"}
PY_EXT = {".py"}
# Directories that hold dependencies or tool state, never the user's own code.
SKIP_DIRS = {"node_modules", ".venv", "venv", ".git", "__pycache__"}


def finding(severity, tool, message, file=None, line=None, col=None, code=None,
            in_changed=None, suggestion=None):
    f = {"severity": severity, "tool": tool, "message": message}
    for key, value in (("file", file), ("line", line), ("col", col), ("code", code),
                       ("in_changed_file", in_changed), ("suggestion", suggestion)):
        if value is not None and value != "":
            f[key] = value
    return f


def norm(path):
    return os.path.normpath(path).replace(os.sep, "/")


def run(cmd, cwd, timeout, input_text=None):
    """Return (returncode, stdout, stderr). returncode None means it could not run or timed out."""
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, input=input_text)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return None, "", "timed out after %ds" % timeout
    except OSError as exc:
        return None, "", str(exc)


def find_node_tool(stage, name):
    """Prefer the project's own node_modules/.bin binary, then PATH."""
    local = os.path.join(stage, "node_modules", ".bin", name)
    if os.path.isfile(local) and os.access(local, os.X_OK):
        return local
    return shutil.which(name)


def project_python(stage):
    """The project's virtualenv interpreter if it has one, else None."""
    for venv in (".venv", "venv"):
        cand = os.path.join(stage, venv, "bin", "python")
        if os.path.isfile(cand):
            return cand
    return None


def manifest_path(stage):
    return stage.rstrip(os.sep) + ".manifest.json"


def load_changed(stage, explicit):
    """Return (changed relative paths or None, how we learned them). Deleted files are excluded."""
    if explicit:
        return [norm(p) for p in explicit], "--changed"
    path = manifest_path(stage)
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return [norm(c["path"]) for c in data.get("changed", []) if c.get("action") != "delete"], "manifest"
    return None, "none"


def all_source_files(stage, exts, limit=5000):
    """Fallback when no change list exists: every source file in the stage, outside dependency dirs."""
    out = []
    for dirpath, dirnames, filenames in os.walk(stage):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1].lower() in exts:
                out.append(norm(os.path.relpath(os.path.join(dirpath, name), stage)))
                if len(out) >= limit:
                    return out
    return out


def ancestors(rel):
    """Directories from the file's own directory up to the project root ('' is the root)."""
    d = os.path.dirname(rel)
    out = []
    while True:
        out.append(d)
        if not d:
            return out
        d = os.path.dirname(d)


def emit(stage_name, status, findings, reason, data):
    print(json.dumps({"stage": stage_name, "status": status, "findings": findings,
                      "reason": reason, "data": data}, indent=2))


def strip_js_comments(src):
    """Blank out comments but keep newlines, so reported line numbers stay right."""
    out, i, n, quote = [], 0, len(src), None
    while i < n:
        c = src[i]
        if quote:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
        elif c in "\"'`":
            quote = c
            out.append(c)
            i += 1
        elif c == "/" and src.startswith("//", i):
            while i < n and src[i] != "\n":
                i += 1
        elif c == "/" and src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append("\n" * src.count("\n", i, j))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def load_json_lenient(path):
    """package.json and tsconfig.json; tsconfig allows comments and trailing commas."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = strip_js_comments(fh.read())
        return json.loads(re.sub(r",(\s*[}\]])", r"\1", text))
    except (OSError, ValueError):
        return {}
