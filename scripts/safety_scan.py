#!/usr/bin/env python3
"""safety_scan.py - early warning before generated code is allowed to run.

Reads the changed files WITHOUT executing them and flags operations that could do damage:
destructive deletes, shell/command injection, eval of dynamic input, writes to system paths,
credential-file access combined with network calls, unsafe deserialization, and so on.

Severities
  block  stops the pipeline. Show the finding to the user and let THEM decide. Never override one
         yourself. After the user explicitly approves a specific finding, re-run with
         --approve FILE:LINE (repeatable); it is downgraded to a warning and the run continues.
  warn   goes in the report; the pipeline continues.

THIS IS A HEURISTIC FILTER, NOT A SECURITY BOUNDARY. Python is analysed with the real AST; JS/TS
with comment-aware pattern matching. Code can hide intent from either (string building, encoding,
indirection), so a clean scan proves nothing. Real containment comes from the sandbox
(run_sandboxed.py). The scan exists to catch the careless and the obvious cheaply, and to give the
user a chance to say no before anything runs.

Output: {"stage": "safety_scan", "status": "pass|fail|skipped", "findings": [...], "data": {...}}
status is "fail" exactly when at least one unapproved block finding remains.
"""
import argparse
import ast
import json
import os
import re
import sys

from _common import (JS_EXT, PY_EXT, TS_EXT, all_source_files, emit, finding, load_changed,
                     load_json_lenient, norm, strip_js_comments)

STAGE = "safety_scan"
TOOL = "safety_scan"
SHELL_EXT = {".sh", ".bash", ".zsh"}
JS_FILE_EXT = TS_EXT | JS_EXT

SYSTEM_DIRS = ("/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/sys", "/proc", "/dev",
               "/var", "/root", "/opt", "/srv", "/System", "/Library", "C:\\Windows", "C:/Windows")
SAFE_PREFIXES = ("/tmp", "/var/tmp", "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/shm")
ROOT_LIKE = {"/", "/*", "~", "~/", "~/*", "$HOME", "$HOME/", "${HOME}", "${HOME}/", "..", "../", "*",
             "/home", "/Users", "C:\\", "C:/"}

# (regex, code, label). Matched against string constants (Python), whole source (JS) and shell scripts.
DANGEROUS_STRINGS = [
    (re.compile(r"\brm\s+(?:-[a-zA-Z]*\s+)*-[a-zA-Z]*[rR][a-zA-Z]*\s+(?:--no-preserve-root\s+)?(?:/|~|\$HOME|\*|\.\.)(?:\s|$|/\*|\"|')"),
     "destructive-shell", "recursive delete of root, home, or everything"),
    (re.compile(r"\bmkfs(?:\.\w+)?\b|\bdd\s+if=\S+\s+of=/dev/"), "destructive-shell", "disk-level write"),
    (re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"), "destructive-shell", "fork bomb"),
    (re.compile(r"\b(?:curl|wget)\b[^|;\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"), "remote-code-pipe", "downloads and pipes straight into a shell"),
    (re.compile(r"\bchmod\s+(?:-R\s+)?[0-7]*777\s+/(?:\s|$)"), "destructive-shell", "world-writable root"),
    (re.compile(r">\s*/dev/(?:sd[a-z]|nvme\d|disk\d)"), "destructive-shell", "redirect into a raw disk device"),
]
WARN_STRINGS = [
    (re.compile(r"\bsudo\b"), "privilege-escalation", "uses sudo"),
    (re.compile(r"\bgit\s+(?:push\s+.*(?:--force|-f)\b|reset\s+--hard|clean\s+-[a-z]*f)"), "destructive-git", "history/working-tree destroying git command"),
    (re.compile(r"\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE)\b", re.I), "destructive-sql", "destructive SQL statement"),
]
# Strong credential locations. ".env" is deliberately absent: loading it is routine and the stage never contains it.
SECRET_MARKERS = re.compile(r"\.ssh\b|id_rsa|id_ed25519|\.aws/credentials|/etc/shadow|/etc/passwd|"
                            r"\.kube/config|\.git-credentials|\.netrc\b|\.docker/config\.json")

PY_SHELL_CALLS = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput", "commands.getoutput"}
PY_SUBPROCESS = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
                 "subprocess.Popen", "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell"}
PY_DELETE = {"shutil.rmtree", "os.remove", "os.unlink", "os.rmdir", "os.removedirs"}
PY_COPY_MOVE = {"shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree", "shutil.move", "os.rename", "os.replace"}
PY_NETWORK_PREFIXES = ("socket.socket", "socket.create_connection", "requests.", "httpx.", "aiohttp.",
                       "urllib.request.", "urllib3.", "http.client.", "smtplib.", "ftplib.", "telnetlib.",
                       "paramiko.", "websocket.", "websockets.")
PY_DESERIAL = {"pickle.load", "pickle.loads", "marshal.load", "marshal.loads", "shelve.open", "dill.load",
               "dill.loads", "yaml.unsafe_load", "jsonpickle.decode", "cloudpickle.load", "cloudpickle.loads"}
PY_NATIVE = {"ctypes.CDLL", "ctypes.PyDLL", "ctypes.WinDLL", "ctypes.cdll.LoadLibrary", "ctypes.windll.LoadLibrary"}


# ================================================================= shared path helpers
def is_system_path(p):
    p = p.replace("\\", "/") if re.match(r"^[A-Za-z]:\\", p) else p
    if any(p == s or p.startswith(s + "/") for s in SAFE_PREFIXES):
        return False
    return any(p == s or p.startswith(s.replace("\\", "/") + "/") or p == s.replace("\\", "/") for s in SYSTEM_DIRS)


def is_root_like(p):
    p = p.strip()
    return p in ROOT_LIKE or p.rstrip("/") in SYSTEM_DIRS


def is_outside_project(p):
    if any(p == s or p.startswith(s + "/") for s in SAFE_PREFIXES):
        return False  # scratch space is routine
    return p.startswith(("/", "~", "$HOME", "${HOME}")) or bool(re.match(r"^[A-Za-z]:[\\/]", p))


class Collector:
    """Collects findings for one file, de-duplicating on (code, line)."""

    def __init__(self, rel):
        self.rel = rel
        self.items = []
        self.seen = set()
        self.network_line = None   # first network call, for exfiltration findings
        self.network_symbols = set()
        self.secret_line = None
        self.env_dump_line = None

    def add(self, severity, code, message, line, suggestion=None):
        key = (code, line)
        if key in self.seen:
            return
        self.seen.add(key)
        self.items.append(finding(severity, TOOL, message, file=self.rel, line=line, code=code,
                                  in_changed=True, suggestion=suggestion))

    def check_strings(self, text, line):
        for rx, code, label in DANGEROUS_STRINGS:
            if rx.search(text):
                self.add("block", code, "string contains a dangerous command: " + label, line,
                         "Remove it, or have the user confirm it is intended.")
        for rx, code, label in WARN_STRINGS:
            if rx.search(text):
                self.add("warn", code, "string contains a risky command: " + label, line)
        if SECRET_MARKERS.search(text):
            self.add("warn", "secret-path", "references a credential file or sensitive system file", line)
            self.secret_line = self.secret_line or line

    def finish(self):
        """Cross-cutting rules that need the whole file."""
        if self.network_line and self.secret_line:
            self.add("block", "exfiltration-pattern",
                     "file references credential files AND makes network calls (%s): possible data exfiltration"
                     % ", ".join(sorted(self.network_symbols)[:4]), self.network_line,
                     "Confirm with the user why this code needs both.")
        elif self.network_line and self.env_dump_line:
            self.add("warn", "possible-exfiltration",
                     "file dumps the whole environment AND makes network calls", self.network_line)
        return self.items


# ================================================================= Python (real AST)
class PyScanner(ast.NodeVisitor):
    def __init__(self, col):
        self.col = col
        self.alias = {}
        self.docstrings = set()

    # --- name resolution
    def prepare(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.alias[a.asname] = a.name
                    else:
                        top = a.name.split(".")[0]
                        self.alias[top] = top
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                for a in node.names:
                    self.alias[a.asname or a.name] = node.module + "." + a.name
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                body = node.body
                if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                        and isinstance(body[0].value.value, str):
                    self.docstrings.add(id(body[0].value))

    def qual(self, node):
        if isinstance(node, ast.Name):
            return self.alias.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.qual(node.value)
            return base + "." + node.attr if base else None
        return None

    @staticmethod
    def is_str(node):
        return isinstance(node, ast.Constant) and isinstance(node.value, str)

    @classmethod
    def is_literal_cmd(cls, node):
        if cls.is_str(node):
            return True
        return isinstance(node, (ast.List, ast.Tuple)) and all(cls.is_str(e) for e in node.elts)

    # --- visitors
    def visit_Constant(self, node):
        if isinstance(node.value, str) and id(node) not in self.docstrings and len(node.value) < 4000:
            self.col.check_strings(node.value, node.lineno)

    def visit_Call(self, node):
        qn = self.qual(node.func)
        attr = node.func.attr if isinstance(node.func, ast.Attribute) else None
        first = node.args[0] if node.args else None
        line = node.lineno
        kw = {k.arg: k.value for k in node.keywords if k.arg}

        if qn in ("eval", "exec"):
            if self.is_str(first):
                self.col.add("warn", "literal-exec", "%s() of a literal string" % qn, line)
            else:
                self.col.add("block", "dynamic-exec", "%s() of non-literal input can run arbitrary code" % qn, line,
                             "Replace with explicit logic, ast.literal_eval, or a lookup table.")

        elif qn in PY_SHELL_CALLS:
            if self.is_str(first):
                self.col.add("warn", "shell-exec", "%s() runs a shell command" % qn, line)
            else:
                self.col.add("block", "shell-injection", "%s() with a non-literal command (shell injection risk)" % qn, line,
                             "Use subprocess with a list of arguments and shell=False.")

        elif qn in PY_SUBPROCESS:
            shell_kw = kw.get("shell")
            shell_on = shell_kw is not None and not (isinstance(shell_kw, ast.Constant) and shell_kw.value is False)
            if qn == "asyncio.create_subprocess_shell":
                shell_on = True
            if shell_on and not self.is_str(first):
                self.col.add("block", "shell-injection", "%s() with shell enabled and a non-literal command" % qn, line,
                             "Pass an argument list and shell=False.")
            elif shell_on:
                self.col.add("warn", "shell-exec", "%s() runs a literal command through a shell" % qn, line)
            elif first is not None and not self.is_literal_cmd(first):
                self.col.add("warn", "dynamic-subprocess", "%s() with a dynamically built command" % qn, line)
            else:
                self.col.add("warn", "subprocess", "%s() starts an external process" % qn, line)

        elif qn and (qn.startswith("os.exec") or qn.startswith("os.spawn") or qn.startswith("os.posix_spawn")):
            self.col.add("warn", "subprocess", "%s() starts or replaces a process" % qn, line)

        elif qn in PY_DELETE:
            if self.is_str(first) and is_root_like(first.value):
                self.col.add("block", "destructive-delete", "%s(%r) deletes a root or home directory" % (qn, first.value), line)
            else:
                self.col.add("warn", "file-delete", "%s() deletes files" % qn, line)

        elif attr in ("unlink", "rmdir") and qn not in PY_DELETE:
            self.col.add("warn", "file-delete", ".%s() deletes files (Path method)" % attr, line)

        elif qn == "open":
            mode = node.args[1] if len(node.args) > 1 else kw.get("mode")
            writing = self.is_str(mode) and any(c in mode.value for c in "wax+")
            if writing and self.is_str(first):
                if is_system_path(first.value):
                    self.col.add("block", "system-path-write", "writes to the system path %r" % first.value, line)
                elif is_outside_project(first.value):
                    self.col.add("warn", "write-outside-project", "writes to %r, outside the project" % first.value, line)

        elif qn in PY_COPY_MOVE:
            dest = node.args[1] if len(node.args) > 1 else None
            if self.is_str(dest) and is_system_path(dest.value):
                self.col.add("block", "system-path-write", "%s() targets the system path %r" % (qn, dest.value), line)

        elif qn in PY_DESERIAL:
            self.col.add("warn", "unsafe-deserialization", "%s() can execute code embedded in untrusted data" % qn, line)

        elif qn == "yaml.load":
            loader = self.qual(kw["Loader"]) if "Loader" in kw else None
            if not (loader and "Safe" in loader):
                self.col.add("warn", "unsafe-deserialization", "yaml.load() without SafeLoader", line,
                             "Use yaml.safe_load().")

        elif qn in ("__import__", "importlib.import_module"):
            if first is not None and not self.is_str(first):
                self.col.add("warn", "dynamic-import", "imports a module chosen at runtime", line)

        elif qn in PY_NATIVE:
            self.col.add("warn", "native-code", "%s() loads native code" % qn, line)

        # Environment dumps (checked in addition to the branches above)
        if qn == "dict" and first is not None and self.qual(first) == "os.environ":
            self.note_env_dump(line)
        elif isinstance(node.func, ast.Attribute) and attr in ("items", "copy", "keys", "values") \
                and self.qual(node.func.value) == "os.environ":
            self.note_env_dump(line)

        # Network (checked in addition)
        if qn and qn.startswith(PY_NETWORK_PREFIXES):
            symbol = ".".join(qn.split(".")[:2])
            self.col.network_symbols.add(symbol)
            self.col.network_line = self.col.network_line or line
            host = self.literal_host(node)
            suffix = " to %s" % host if host else ""
            if (symbol, ) not in self.col.seen:
                self.col.seen.add((symbol,))
                self.col.add("warn", "network", "%s() makes a network call%s (blocked inside the sandbox)" % (qn, suffix), line)

        self.generic_visit(node)

    def note_env_dump(self, line):
        self.col.env_dump_line = self.col.env_dump_line or line
        self.col.add("warn", "env-dump", "reads the entire environment (may include secrets)", line)

    def literal_host(self, call):
        for a in list(call.args) + [k.value for k in call.keywords]:
            if self.is_str(a):
                m = re.match(r"https?://([^/:\s]+)", a.value)
                if m and m.group(1) not in ("localhost", "127.0.0.1", "::1"):
                    return m.group(1)
        return None


def scan_python(stage, rel):
    col = Collector(rel)
    try:
        with open(os.path.join(stage, rel), "rb") as fh:
            tree = ast.parse(fh.read(), filename=rel)
    except SyntaxError:
        return [finding("info", TOOL, "file does not parse; skipped (static_check reports syntax errors)", file=rel)]
    except (OSError, ValueError) as exc:
        return [finding("warn", TOOL, "could not read file: %s" % exc, file=rel)]
    scanner = PyScanner(col)
    scanner.prepare(tree)
    scanner.visit(tree)
    return col.finish()


# ================================================================= JS / TS (pattern based)
def first_arg(src, idx):
    """Classify the first argument of the call whose '(' ends just before idx -> (kind, literal value)."""
    n = len(src)
    while idx < n and src[idx] in " \t\r\n":
        idx += 1
    if idx >= n or src[idx] == ")":
        return "none", None
    q = src[idx]
    if q in "\"'`":
        j = idx + 1
        while j < n and src[j] != q:
            j += 2 if src[j] == "\\" else 1
        body = src[idx + 1:j]
        if q == "`" and "${" in body:
            return "dynamic", None
        k = j + 1
        while k < n and src[k] in " \t\r\n":
            k += 1
        if k < n and src[k] == "+":
            return "dynamic", None
        return "literal", body
    return "dynamic", None


JS_CHILD = re.compile(r"(?<![\w$.])(?:(?:child_process|cp|childProcess)\.)?(execSync|exec|spawnSync|spawn|execFileSync|execFile|fork)\s*\(")
JS_EVAL = re.compile(r"(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\(")
JS_VM = re.compile(r"\bvm\.(?:runIn\w+|Script)\b|\bnew\s+vm\.Script\b")
JS_DELETE = re.compile(r"\b(?:fs|fsp|promises|fse|fsExtra)\.(?:promises\.)?(rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync|remove|removeSync|emptyDir|emptyDirSync)\s*\(|(?<![\w$.])(rimraf|rimrafSync)\s*\(")
JS_WRITE = re.compile(r"\b(?:fs|fsp|promises|fse)\.(?:promises\.)?(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|copyFile|copyFileSync|rename|renameSync|cp|cpSync)\s*\(")
JS_NETWORK = [
    (re.compile(r"(?<![\w$.])fetch\s*\("), "fetch"),
    (re.compile(r"\baxios\b"), "axios"),
    (re.compile(r"\bXMLHttpRequest\b"), "XMLHttpRequest"),
    (re.compile(r"\b(?:http|https|net|tls|dgram|http2)\.(?:request|get|connect|createConnection|createSocket)\s*\("), "node net/http"),
    (re.compile(r"\bnew\s+WebSocket\s*\("), "WebSocket"),
    (re.compile(r"\bnodemailer\b"), "nodemailer"),
]
JS_ENV_DUMP = re.compile(r"\.\.\.\s*process\.env\b|JSON\.stringify\(\s*process\.env\b|Object\.(?:entries|keys|values|assign)\(\s*process\.env\b")
JS_DYNAMIC_REQUIRE = re.compile(r"(?<![\w$.])require\(\s*(?![\"'`\s)])|\bimport\(\s*(?![\"'`\s)])")


def scan_js(stage, rel):
    col = Collector(rel)
    try:
        with open(os.path.join(stage, rel), encoding="utf-8", errors="replace") as fh:
            src = strip_js_comments(fh.read())
    except OSError as exc:
        return [finding("warn", TOOL, "could not read file: %s" % exc, file=rel)]

    def line_of(pos):
        return src.count("\n", 0, pos) + 1

    # Whole-source text patterns, reported with the real line of each match.
    for rx, code, label in DANGEROUS_STRINGS:
        for m in rx.finditer(src):
            col.add("block", code, "contains a dangerous command: " + label, line_of(m.start()),
                    "Remove it, or have the user confirm it is intended.")
    for rx, code, label in WARN_STRINGS:
        for m in rx.finditer(src):
            col.add("warn", code, "contains a risky command: " + label, line_of(m.start()))
    for m in SECRET_MARKERS.finditer(src):
        col.add("warn", "secret-path", "references a credential file or sensitive system file", line_of(m.start()))
        col.secret_line = col.secret_line or line_of(m.start())

    uses_child_process = "child_process" in src
    for m in JS_CHILD.finditer(src):
        if not uses_child_process:
            break
        name, ln = m.group(1), line_of(m.start())
        kind, _val = first_arg(src, m.end())
        if name in ("exec", "execSync"):
            if kind == "dynamic":
                col.add("block", "shell-injection", "%s() with a non-literal command (shell injection risk)" % name, ln,
                        "Use execFile/spawn with an argument array.")
            else:
                col.add("warn", "shell-exec", "%s() runs a shell command" % name, ln)
        else:
            shell_on = re.search(r"shell\s*:\s*true", src[m.end():m.end() + 300]) is not None
            if shell_on and kind == "dynamic":
                col.add("block", "shell-injection", "%s() with shell:true and a non-literal command" % name, ln)
            else:
                col.add("warn", "subprocess", "%s() starts an external process" % name, ln)

    for m in JS_EVAL.finditer(src):
        kind, _val = first_arg(src, m.end())
        if kind == "dynamic":
            col.add("block", "dynamic-exec", "eval/new Function with non-literal input can run arbitrary code", line_of(m.start()))
        else:
            col.add("warn", "literal-exec", "eval/new Function of a literal string", line_of(m.start()))
    for m in JS_VM.finditer(src):
        col.add("warn", "dynamic-exec", "vm module executes code strings", line_of(m.start()))

    for m in JS_DELETE.finditer(src):
        kind, val = first_arg(src, m.end())
        if kind == "literal" and is_root_like(val):
            col.add("block", "destructive-delete", "deletes the root or home directory (%r)" % val, line_of(m.start()))
        else:
            col.add("warn", "file-delete", "deletes files", line_of(m.start()))

    for m in JS_WRITE.finditer(src):
        kind, val = first_arg(src, m.end())
        if kind == "literal":
            if is_system_path(val):
                col.add("block", "system-path-write", "writes to the system path %r" % val, line_of(m.start()))
            elif is_outside_project(val):
                col.add("warn", "write-outside-project", "writes to %r, outside the project" % val, line_of(m.start()))

    for rx, label in JS_NETWORK:
        m = rx.search(src)
        if m:
            col.network_symbols.add(label)
            col.network_line = col.network_line or line_of(m.start())
            col.add("warn", "network", "%s makes network calls (blocked inside the sandbox)" % label, line_of(m.start()))
    m = JS_ENV_DUMP.search(src)
    if m:
        col.env_dump_line = line_of(m.start())
        col.add("warn", "env-dump", "reads the entire environment (may include secrets)", col.env_dump_line)
    for m in JS_DYNAMIC_REQUIRE.finditer(src):
        col.add("warn", "dynamic-import", "loads a module chosen at runtime", line_of(m.start()))
    return col.finish()


# ================================================================= package.json hooks and shell scripts
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly", "prepack", "postpack")


def scan_package_json(stage, rel):
    col = Collector(rel)
    pkg = load_json_lenient(os.path.join(stage, rel))
    scripts = pkg.get("scripts") or {}
    for name, cmd in scripts.items():
        if not isinstance(cmd, str):
            continue
        if name in INSTALL_HOOKS:
            col.add("warn", "install-hook", "script %r runs automatically on install/publish: %s" % (name, cmd[:80]), None,
                    "Confirm this hook is wanted; install hooks run on every consumer's machine.")
        for rx, code, label in DANGEROUS_STRINGS:
            if rx.search(cmd):
                col.add("block", code, "script %r contains a dangerous command: %s" % (name, label), None)
    return col.items


def scan_shell(stage, rel):
    col = Collector(rel)
    try:
        with open(os.path.join(stage, rel), encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        return [finding("warn", TOOL, "could not read file: %s" % exc, file=rel)]
    col.add("warn", "shell-script", "shell script in the change set; review before anything executes it", 1)
    for i, text in enumerate(lines, 1):
        if text.lstrip().startswith("#"):
            continue
        for rx, code, label in DANGEROUS_STRINGS:
            if rx.search(text):
                col.add("block", code, "dangerous command: " + label, i, "Remove it, or have the user confirm it is intended.")
        for rx, code, label in WARN_STRINGS:
            if rx.search(text):
                col.add("warn", code, "risky command: " + label, i)
    return col.items


# ================================================================= main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stage", required=True, help="staged workspace directory")
    ap.add_argument("--changed", nargs="*", help="changed files relative to the stage (default: read the manifest)")
    ap.add_argument("--approve", action="append", default=[], metavar="FILE:LINE",
                    help="downgrade a block finding the USER has explicitly approved (repeatable)")
    args = ap.parse_args()

    stage = os.path.abspath(args.stage)
    if not os.path.isdir(stage):
        emit(STAGE, "fail", [], "stage directory not found: " + stage, {})
        return 2

    changed, how = load_changed(stage, args.changed)
    notes = []
    if changed is None:
        changed = all_source_files(stage, JS_FILE_EXT | PY_EXT | SHELL_EXT)
        notes.append(finding("warn", TOOL, "no manifest or --changed given; scanning every source file in the stage"))

    approvals = {norm(a) for a in args.approve}
    findings, scanned = list(notes), 0
    for rel in changed:
        full = os.path.join(stage, rel)
        if not os.path.isfile(full):
            continue
        ext = os.path.splitext(rel)[1].lower()
        if ext in PY_EXT:
            found = scan_python(stage, rel)
        elif ext in JS_FILE_EXT:
            found = scan_js(stage, rel)
        elif os.path.basename(rel) == "package.json":
            found = scan_package_json(stage, rel)
        elif ext in SHELL_EXT:
            found = scan_shell(stage, rel)
        else:
            continue
        scanned += 1
        findings += found

    approved = 0
    for f in findings:
        if f["severity"] == "block" and "%s:%s" % (f.get("file"), f.get("line")) in approvals:
            f["severity"] = "warn"
            f["message"] += " (approved by the user)"
            approved += 1

    blocks = [f for f in findings if f["severity"] == "block"]
    data = {"changed_source": how, "files_scanned": scanned, "block_count": len(blocks), "approved_count": approved,
            "warning_count": sum(1 for f in findings if f["severity"] == "warn"),
            "needs_user_decision": bool(blocks),
            "caveat": "heuristic filter, not a security boundary; the sandbox provides containment"}
    if scanned == 0:
        status, reason = "skipped", "no scannable files (Python, JS/TS, shell, package.json) in the change set"
    elif blocks:
        status = "fail"
        reason = "%d blocking finding(s): show them to the user and wait for their decision; do not override" % len(blocks)
    else:
        status, reason = "pass", ""
    emit(STAGE, status, findings, reason, data)
    return 1 if status == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
