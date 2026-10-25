#!/usr/bin/env python3
"""dep_check.py - catch hallucinated imports and wrong calls before anything runs.

For every changed file it verifies that:
  * each import resolves to a stdlib/builtin module, a local file, or a package declared in the
    manifest (package.json, requirements*.txt, pyproject.toml, Pipfile);
  * Python names imported from local modules actually exist there;
  * calls to plain local Python functions match the function's signature
    (argument count, keyword names, missing required arguments).

An import that resolves nowhere is the classic sign of a made-up package. With --check-registry
the script asks PyPI / npm whether the name exists, so the message can say "this package does not
exist" rather than only "not declared".

TypeScript/JavaScript imports are found with a comment-aware scanner, not a full parser: import/export
statements must begin a line, and regex literals containing quotes can confuse it. Python uses the real AST.

Output: {"stage": "dep_check", "status": "pass|fail|skipped", "findings": [...], ...}
"""
import argparse
import ast
import collections
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

from _common import (JS_EXT, PY_EXT, TS_EXT, all_source_files, ancestors, emit, finding,
                     load_changed, load_json_lenient, norm, project_python, run, strip_js_comments)

STAGE = "dep_check"
TOOL = "dep_check"
JS_FILE_EXT = TS_EXT | JS_EXT

NODE_BUILTINS = set(
    "assert async_hooks buffer child_process cluster console constants crypto dgram "
    "diagnostics_channel dns domain events fs http http2 https inspector module net os path "
    "perf_hooks process punycode querystring readline repl stream string_decoder sys timers tls "
    "trace_events tty url util v8 vm wasi worker_threads zlib test sea sqlite".split())

RESOLVE_EXTS = [".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".json", ".d.ts"]
EXT_SWAPS = {".js": [".ts", ".tsx"], ".jsx": [".tsx"], ".mjs": [".mts"], ".cjs": [".cts"]}

# import name -> distribution name, for the common cases where they differ.
PY_ALIASES = {
    "yaml": "pyyaml", "PIL": "pillow", "cv2": "opencv-python", "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4", "dateutil": "python-dateutil", "dotenv": "python-dotenv", "jwt": "pyjwt",
    "attr": "attrs", "serial": "pyserial", "OpenSSL": "pyopenssl", "Crypto": "pycryptodome",
    "git": "gitpython", "MySQLdb": "mysqlclient", "magic": "python-magic", "docx": "python-docx",
    "pptx": "python-pptx", "fitz": "pymupdf", "skimage": "scikit-image", "zmq": "pyzmq",
    "psycopg2": "psycopg2-binary", "markdown": "markdown", "gi": "pygobject", "usb": "pyusb",
}


def pynorm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


# ================================================================= manifests
def read_requirements(path, seen=None):
    """Distribution names from a requirements file, following -r includes."""
    seen = seen if seen is not None else set()
    names = set()
    path = os.path.abspath(path)
    if path in seen or not os.path.isfile(path):
        return names
    seen.add(path)
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.split(" #")[0].strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(("-r ", "--requirement ")):
                names |= read_requirements(os.path.join(os.path.dirname(path), line.split(None, 1)[1].strip()), seen)
                continue
            egg = re.search(r"#egg=([A-Za-z0-9._-]+)", raw)
            if egg:
                names.add(pynorm(egg.group(1)))
                continue
            if line.startswith("-"):
                continue
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
            if m and "://" not in line.split("@")[0]:
                names.add(pynorm(m.group(1)))
    return names


def req_name(spec):
    m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", spec) if isinstance(spec, str) else None
    return pynorm(m.group(1)) if m else None


def read_toml_deps(path):
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            return None  # cannot parse; caller degrades gracefully
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, ValueError):
        return set()
    names, specs = set(), []
    proj = data.get("project", {})
    specs += proj.get("dependencies", []) or []
    for group in (proj.get("optional-dependencies") or {}).values():
        specs += group
    for group in (data.get("dependency-groups") or {}).values():
        specs += [s for s in group if isinstance(s, str)]
    tool = data.get("tool", {})
    specs += (tool.get("uv", {}) or {}).get("dev-dependencies", []) or []
    for group in ((tool.get("pdm", {}) or {}).get("dev-dependencies") or {}).values():
        specs += group
    poetry = tool.get("poetry", {}) or {}
    poetry_tables = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})]
    poetry_tables += [g.get("dependencies", {}) for g in (poetry.get("group") or {}).values()]
    for table in poetry_tables:
        names |= {pynorm(k) for k in (table or {}) if k.lower() != "python"}
    for sect in ("packages", "dev-packages"):  # Pipfile
        names |= {pynorm(k) for k in (data.get(sect) or {})}
    names |= {n for n in (req_name(s) for s in specs) if n}
    return names


def collect_py_declared(stage, files):
    """(declared distribution names, manifests read, toml_unparsed). Looks in each file's ancestor dirs."""
    dirs = {d for f in files for d in ancestors(f)} or {""}
    names, used, unparsed = set(), [], False
    for d in sorted(dirs):
        base = os.path.join(stage, d)
        if not os.path.isdir(base):
            continue
        for entry in sorted(os.listdir(base)):
            full = os.path.join(base, entry)
            if re.match(r"^requirements.*\.txt$", entry):
                names |= read_requirements(full)
                used.append(norm(os.path.relpath(full, stage)))
            elif entry in ("pyproject.toml", "Pipfile"):
                got = read_toml_deps(full)
                if got is None:
                    unparsed = True
                else:
                    names |= got
                used.append(norm(os.path.relpath(full, stage)))
        req_dir = os.path.join(base, "requirements")
        if os.path.isdir(req_dir):
            for entry in sorted(os.listdir(req_dir)):
                if entry.endswith(".txt"):
                    names |= read_requirements(os.path.join(req_dir, entry))
                    used.append(norm(os.path.relpath(os.path.join(req_dir, entry), stage)))
    return names, used, unparsed


def collect_js_context(stage, files):
    """Declared packages, workspace package names, path aliases and baseUrls for the changed JS/TS files."""
    declared, workspace, aliases, base_urls, manifests = set(), set(), [], [], []
    dirs = {d for f in files for d in ancestors(f)} or {""}
    for d in sorted(dirs):
        pkg_path = os.path.join(stage, d, "package.json")
        if os.path.isfile(pkg_path):
            pkg = load_json_lenient(pkg_path)
            manifests.append(norm(os.path.relpath(pkg_path, stage)))
            for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                declared |= set((pkg.get(key) or {}).keys())
            if pkg.get("name"):
                workspace.add(pkg["name"])
        ts_path = os.path.join(stage, d, "tsconfig.json")
        if os.path.isfile(ts_path):
            opts = load_json_lenient(ts_path).get("compilerOptions", {}) or {}
            for pattern in (opts.get("paths") or {}):
                aliases.append(pattern.rstrip("*"))
            if opts.get("baseUrl"):
                base_urls.append(os.path.normpath(os.path.join(stage, d, opts["baseUrl"])))
    # Monorepo siblings: other packages' names count as resolvable.
    for dirpath, dirnames, filenames in os.walk(stage):
        dirnames[:] = [x for x in dirnames if x not in ("node_modules", ".git", ".venv", "venv")]
        if "package.json" in filenames and dirpath != stage:
            name = load_json_lenient(os.path.join(dirpath, "package.json")).get("name")
            if name:
                workspace.add(name)
    return declared, workspace, aliases, base_urls, manifests


# ================================================================= JS / TS
JS_IMPORT_PATTERNS = [
    # import/export statements must start a line, so text inside a string literal is not mistaken for one
    re.compile(r"""^[ \t]*import\s+(?:type\s+)?(?:[\w*${}\s,]+?\s+from\s+)?["']([^"']+)["']""", re.M),
    re.compile(r"""^[ \t]*export\s+(?:type\s+)?(?:\*|\{[^}]*\})(?:\s+as\s+\w+)?\s+from\s+["']([^"']+)["']""", re.M),
    re.compile(r"""\brequire\(\s*["']([^"']+)["']\s*\)"""),
    re.compile(r"""\bimport\(\s*["']([^"']+)["']\s*\)"""),
]


def js_specifiers(src):
    clean = strip_js_comments(src)
    found = {}
    for pat in JS_IMPORT_PATTERNS:
        for m in pat.finditer(clean):
            line = clean.count("\n", 0, m.start()) + 1
            found.setdefault((m.group(1), line), None)
    return sorted(found)


def package_name(spec):
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") and len(parts) > 1 else parts[0]


def resolve_file_js(stage, base):
    root, ext = os.path.splitext(base)
    cands = [base] + [root + s for s in EXT_SWAPS.get(ext, [])]
    cands += [base + e for e in RESOLVE_EXTS]
    cands += [os.path.join(base, "index" + e) for e in RESOLVE_EXTS] + [os.path.join(base, "package.json")]
    return any(os.path.isfile(c) for c in cands)


def check_js_file(stage, rel, ctx, out):
    declared, workspace, aliases, base_urls, node_modules_present = ctx
    try:
        with open(os.path.join(stage, rel), encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except OSError as exc:
        out["findings"].append(finding("error", TOOL, "could not read file: %s" % exc, file=rel))
        return
    reported = set()
    for spec, line in js_specifiers(src):
        out["imports"] += 1
        if spec.startswith(("http:", "https:", "data:", "virtual:", "#")):
            continue
        if spec.startswith("."):
            base = os.path.normpath(os.path.join(stage, os.path.dirname(rel), spec))
            if not resolve_file_js(stage, base):
                out["findings"].append(finding(
                    "error", TOOL, "relative import %r does not resolve to any file" % spec, file=rel, line=line,
                    code="unresolved-relative-import",
                    suggestion="Check the path and file name, or create the missing module."))
            continue
        if spec.startswith("node:") or package_name(spec) in NODE_BUILTINS:
            continue
        if any(spec.startswith(a) for a in aliases if a):
            continue  # tsconfig path alias; the compiler (tsc) validates these
        if any(resolve_file_js(stage, os.path.join(b, spec)) for b in base_urls):
            continue
        name = package_name(spec)
        if (name, rel) in reported:
            continue
        reported.add((name, rel))
        types_pkg = "@types/" + (name[1:].replace("/", "__") if name.startswith("@") else name)
        installed = os.path.isdir(os.path.join(stage, "node_modules", *name.split("/")))
        if name in declared or name in workspace or types_pkg in declared:
            if node_modules_present and not installed and name not in workspace and types_pkg not in declared:
                out["not_installed"].add(name)
            continue
        if installed:
            out["findings"].append(finding(
                "warn", TOOL, "%r is installed but not declared in package.json (works here, breaks for anyone else)" % name,
                file=rel, line=line, code="undeclared-dependency",
                suggestion="Add %s to dependencies or devDependencies." % name))
            continue
        out["unresolved"].append({"eco": "npm", "name": name, "file": rel, "line": line,
                                  "manifest": "package.json", "kind": "javascript"})


# ================================================================= Python
def stdlib_names():
    names = getattr(sys, "stdlib_module_names", None)
    if names:
        return set(names) | set(sys.builtin_module_names)
    import sysconfig
    std = sysconfig.get_paths()["stdlib"]
    found = set(sys.builtin_module_names)
    for entry in os.listdir(std):
        found.add(os.path.splitext(entry)[0])
    return found


def installed_info(stage, tops, timeout=30):
    """Which top-level names the project's interpreter can import, and their distributions."""
    py = project_python(stage) or sys.executable
    code = (
        "import importlib.util, json, sys\n"
        "from importlib import metadata\n"
        "names = sys.argv[1:]\n"
        "try:\n"
        "    dist = metadata.packages_distributions()\n"
        "except Exception:\n"
        "    dist = {}\n"
        "print(json.dumps({'found': {n: importlib.util.find_spec(n) is not None for n in names},\n"
        "                  'dist': {n: dist.get(n, []) for n in names}}))\n"
    )
    rc, so, _se = run([py, "-c", code] + sorted(tops), stage, timeout)
    if rc == 0 and so.strip():
        try:
            return json.loads(so.strip().splitlines()[-1])
        except ValueError:
            pass
    return {"found": {}, "dist": {}}


def module_to_path(roots, dotted):
    parts = dotted.split(".")
    for root in roots:
        base = os.path.join(root, *parts)
        if os.path.isfile(base + ".py"):
            return base + ".py", "file"
        if os.path.isfile(os.path.join(base, "__init__.py")):
            return os.path.join(base, "__init__.py"), "package"
        if os.path.isdir(base):
            return base, "namespace"
    return None, None


def module_info(path, cache):
    """(exported top-level names, dynamic?, {function name: ast.arguments}) or None if unparsable."""
    if path in cache:
        return cache[path]
    try:
        with open(path, "rb") as fh:
            tree = ast.parse(fh.read(), filename=path)
    except (OSError, SyntaxError, ValueError):
        cache[path] = None
        return None
    names, sigs, def_count, dynamic = set(), {}, collections.Counter(), False

    def add_target(t):
        if isinstance(t, ast.Name):
            names.add(t.id)
        elif isinstance(t, (ast.Tuple, ast.List)):
            for e in t.elts:
                add_target(e)

    def collect(body, top):
        nonlocal dynamic
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names.add(node.name)
                if top:
                    def_count[node.name] += 1
                    if not node.decorator_list and isinstance(node, ast.FunctionDef):
                        sigs[node.name] = node.args
            elif isinstance(node, ast.ClassDef):
                names.add(node.name)
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    add_target(t)
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                add_target(node.target)
            elif isinstance(node, ast.Import):
                for a in node.names:
                    names.add(a.asname or a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for a in node.names:
                    if a.name == "*":
                        dynamic = True
                    else:
                        names.add(a.asname or a.name)
            elif isinstance(node, (ast.If, ast.Try, ast.With, ast.For, ast.While)):
                for attr in ("body", "orelse", "finalbody"):
                    collect(getattr(node, attr, []) or [], False)
                for h in getattr(node, "handlers", []) or []:
                    collect(h.body, False)

    collect(tree.body, True)
    if "__getattr__" in names:
        dynamic = True
    for name, count in def_count.items():
        if count > 1:
            sigs.pop(name, None)  # redefined: which signature applies is ambiguous
    cache[path] = (names, dynamic, sigs)
    return cache[path]


def handles_import_error(try_node):
    wanted = {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"}
    for h in try_node.handlers:
        t = h.type
        if t is None:
            return True
        elts = t.elts if isinstance(t, ast.Tuple) else [t]
        if any(isinstance(e, ast.Name) and e.id in wanted for e in elts):
            return True
    return False


def is_type_checking(test):
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or \
           (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")


def py_import_nodes(node, guarded=False):
    """Yield (import node, guarded). Guarded = inside try/except ImportError or `if TYPE_CHECKING:`."""
    for child in ast.iter_child_nodes(node):
        g = guarded
        if isinstance(node, ast.Try) and child in node.body and handles_import_error(node):
            g = True
        if isinstance(node, ast.If) and child in node.body and is_type_checking(node.test):
            g = True
        if isinstance(child, (ast.Import, ast.ImportFrom)):
            yield child, g
        else:
            yield from py_import_nodes(child, g)


def sig_problem(args, call):
    """Describe why `call` cannot match `args`, or None when it fits or cannot be judged."""
    if any(isinstance(a, ast.Starred) for a in call.args) or any(k.arg is None for k in call.keywords):
        return None  # *args / **kwargs at the call site: arity is unknowable statically
    posonly = [a.arg for a in args.posonlyargs]
    pos = posonly + [a.arg for a in args.args]
    kwonly = [a.arg for a in args.kwonlyargs]
    n_default = len(args.defaults)
    required = set(pos[:len(pos) - n_default]) if n_default else set(pos)
    required |= {a.arg for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is None}
    n = len(call.args)
    if n > len(pos) and not args.vararg:
        return "takes at most %d positional argument(s) but %d given" % (len(pos), n)
    provided = set(pos[:n])
    for k in call.keywords:
        if k.arg in provided:
            return "got multiple values for argument %r" % k.arg
        if k.arg in posonly and not args.kwarg:
            return "argument %r is positional-only" % k.arg
        if k.arg not in pos and k.arg not in kwonly and not args.kwarg:
            return "unexpected keyword argument %r" % k.arg
        provided.add(k.arg)
    missing = sorted(required - provided)
    return "missing required argument(s): " + ", ".join(missing) if missing else None


def check_py_file(stage, rel, ctx, cache, out):
    stdlib, declared, installed, manifest_found, toml_unparsed = ctx
    try:
        with open(os.path.join(stage, rel), "rb") as fh:
            tree = ast.parse(fh.read(), filename=rel)
    except (OSError, SyntaxError, ValueError):
        return  # static_check reports syntax errors; nothing useful to add here
    here = os.path.dirname(rel)
    roots = [os.path.join(stage, d) for d in reversed(ancestors(rel))] + [os.path.join(stage, "src")]
    seen_pkg = set()
    sig_map = {}  # local binding name -> (ast.arguments, origin)

    def err(node, code, message, suggestion=None):
        out["findings"].append(finding("error", TOOL, message, file=rel, line=node.lineno, code=code,
                                       in_changed=True, suggestion=suggestion))

    for node, guarded in py_import_nodes(tree):
        out["imports"] += 1
        severity = "warn" if guarded else "error"

        # ---- relative imports: resolved against the importing file
        if isinstance(node, ast.ImportFrom) and node.level > 0:
            base = os.path.join(stage, here)
            for _ in range(node.level - 1):
                base = os.path.dirname(base)
            dotted = node.module or ""
            if dotted:
                path, kind = module_to_path([base], dotted)
            else:
                path, kind = os.path.join(base, "__init__.py"), "package"
                if not os.path.isfile(path):
                    path, kind = base, "namespace"
            if kind is None:
                out["findings"].append(finding(
                    severity, TOOL, "relative import %s%s does not resolve to a module" % ("." * node.level, dotted),
                    file=rel, line=node.lineno, code="unresolved-relative-import", in_changed=True))
                continue
            check_from_names(stage, rel, node, path, kind, dotted, cache, sig_map, severity, out)
            continue

        modules = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module]
        for dotted in modules:
            top = dotted.split(".")[0]
            if top in stdlib or top == "__future__":
                continue
            path, kind = module_to_path(roots, dotted)
            if kind is not None:
                if isinstance(node, ast.ImportFrom):
                    check_from_names(stage, rel, node, path, kind, dotted, cache, sig_map, severity, out)
                continue
            if module_to_path(roots, top)[1] is not None:
                err(node, "unresolved-local-module",
                    "local package %r has no module %r" % (top, dotted),
                    "Check the module path or create the file.")
                continue
            # ---- third party
            if (top, rel) in seen_pkg:
                continue
            seen_pkg.add((top, rel))
            dists = {pynorm(d) for d in installed["dist"].get(top, [])}
            ok_declared = pynorm(top) in declared or pynorm(PY_ALIASES.get(top, "")) in declared or bool(dists & declared)
            is_installed = installed["found"].get(top, False)
            if ok_declared:
                if not is_installed:
                    out["not_installed"].add(top)
                continue
            if is_installed:
                if manifest_found and not toml_unparsed:
                    out["findings"].append(finding(
                        "warn", TOOL, "%r is installed but not declared in the dependency manifest" % top,
                        file=rel, line=node.lineno, code="undeclared-dependency", in_changed=True,
                        suggestion="Add it to requirements.txt / pyproject.toml."))
                continue
            if toml_unparsed:
                out["findings"].append(finding(
                    "warn", TOOL, "%r is not installed and pyproject.toml could not be parsed to check it" % top,
                    file=rel, line=node.lineno, code="unverified-dependency", in_changed=True))
                continue
            if guarded:
                out["findings"].append(finding(
                    "warn", TOOL, "optional import %r is not installed (guarded by try/except ImportError)" % top,
                    file=rel, line=node.lineno, code="optional-import-missing", in_changed=True))
                continue
            out["unresolved"].append({"eco": "pypi", "name": PY_ALIASES.get(top, top), "import_name": top, "file": rel,
                                      "line": node.lineno, "manifest": "requirements.txt / pyproject.toml",
                                      "kind": "python"})

    check_calls(rel, tree, sig_map, cache, stage, out)


def check_from_names(stage, rel, node, path, kind, dotted, cache, sig_map, severity, out):
    """Validate `from <module> import names` against what the target module really defines."""
    info = module_info(path, cache) if kind in ("file", "package") else None
    pkg_dir = os.path.dirname(path) if kind in ("file", "package") else path
    for alias in node.names:
        if alias.name == "*":
            continue
        is_submodule = (os.path.isfile(os.path.join(pkg_dir, alias.name + ".py"))
                        or os.path.isdir(os.path.join(pkg_dir, alias.name))) and kind != "file"
        if is_submodule:
            continue
        if kind == "file" or kind == "package":
            if info is None:
                continue  # target unparsable; static_check will say so
            names, dynamic, sigs = info
            if alias.name not in names and not dynamic:
                out["findings"].append(finding(
                    severity, TOOL, "%r is not defined in %s" % (alias.name, norm(os.path.relpath(path, stage))),
                    file=rel, line=node.lineno, code="missing-export", in_changed=True,
                    suggestion="Check the name; it may be hallucinated or renamed."))
                continue
            if alias.name in sigs:
                sig_map[alias.asname or alias.name] = (sigs[alias.name], "%s.%s" % (dotted or ".", alias.name))
        else:
            out["findings"].append(finding(
                severity, TOOL, "%r is not a module inside namespace package %r" % (alias.name, dotted),
                file=rel, line=node.lineno, code="missing-export", in_changed=True))


def check_calls(rel, tree, sig_map, cache, stage, out):
    """Signature check for calls to plain, undecorated, uniquely-bound module-level functions."""
    # Same-file functions count too.
    own = module_info(os.path.join(stage, rel), cache)
    if own:
        for name, args in own[2].items():
            sig_map.setdefault(name, (args, name))
    if not sig_map:
        return
    bindings = collections.Counter()
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            bindings[n.id] += 1
        elif isinstance(n, ast.arg):
            bindings[n.arg] += 1
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bindings[n.name] += 1
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                bindings[(a.asname or a.name).split(".")[0]] += 1
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in sig_map:
            if bindings[n.func.id] != 1:
                continue  # rebound or defined in several ways: not safe to judge
            args, origin = sig_map[n.func.id]
            problem = sig_problem(args, n)
            if problem:
                out["findings"].append(finding(
                    "error", TOOL, "call to %s() is invalid: %s" % (origin, problem), file=rel, line=n.lineno,
                    code="bad-call", in_changed=True))


# ================================================================= registry lookup
def registry_exists(eco, name, timeout=5):
    """True / False, or None when the registry cannot be reached."""
    if eco == "pypi":
        url = "https://pypi.org/pypi/%s/json" % urllib.parse.quote(name)
    else:
        url = "https://registry.npmjs.org/%s" % urllib.parse.quote(name, safe="@").replace("/", "%2F")
    req = urllib.request.Request(url, headers={"User-Agent": "preflight-verify/1.0"})
    try:
        urllib.request.urlopen(req, timeout=timeout).close()
        return True
    except urllib.error.HTTPError as exc:
        return False if exc.code == 404 else None
    except (urllib.error.URLError, OSError):
        return None


def resolve_unresolved(unresolved, check_registry, out):
    """Turn raw unresolved imports into findings; optionally ask the registry whether the package exists."""
    cache, checked = {}, False
    for item in unresolved:
        exists = None
        if check_registry:
            key = (item["eco"], item["name"])
            if key not in cache:
                cache[key] = registry_exists(*key) if len(cache) < 25 else None
            exists = cache[key]
            checked = checked or exists is not None
        label = "PyPI" if item["eco"] == "pypi" else "npm"
        if exists is False:
            msg = "%r is imported but does not exist on %s; this looks like a hallucinated package" % (item["name"], label)
            code, hint = "hallucinated-package", "Remove the import or use a real library."
        elif exists is True:
            msg = "%r is a real %s package but is not declared or installed" % (item["name"], label)
            code, hint = "undeclared-dependency", "Add it to %s and install it." % item["manifest"]
        else:
            msg = "%r is imported but is not a declared dependency, not installed, and not a local file" % item["name"]
            code, hint = "unresolved-import", "Declare it in %s, or remove the import. Re-run with --check-registry to see whether the package exists." % item["manifest"]
        out["findings"].append(finding("error", TOOL, msg, file=item["file"], line=item["line"], code=code,
                                       in_changed=True, suggestion=hint))
    return checked


# ================================================================= main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stage", required=True, help="staged workspace directory")
    ap.add_argument("--changed", nargs="*", help="changed files relative to the stage (default: read the manifest)")
    ap.add_argument("--lang", choices=["auto", "ts", "py"], default="auto")
    ap.add_argument("--check-registry", action="store_true", help="ask PyPI/npm whether unresolved packages exist")
    args = ap.parse_args()

    stage = os.path.abspath(args.stage)
    if not os.path.isdir(stage):
        emit(STAGE, "fail", [], "stage directory not found: " + stage, {})
        return 2

    changed, how = load_changed(stage, args.changed)
    notes = []
    if changed is None:
        changed = all_source_files(stage, JS_FILE_EXT | PY_EXT)
        notes.append(finding("warn", TOOL, "no manifest or --changed given; checking every source file in the stage"))

    js_files = [f for f in changed if os.path.splitext(f)[1].lower() in JS_FILE_EXT] if args.lang in ("auto", "ts") else []
    py_files = [f for f in changed if os.path.splitext(f)[1].lower() in PY_EXT] if args.lang in ("auto", "py") else []
    js_files = [f for f in js_files if os.path.isfile(os.path.join(stage, f))]
    py_files = [f for f in py_files if os.path.isfile(os.path.join(stage, f))]

    out = {"findings": notes, "imports": 0, "unresolved": [], "not_installed": set()}
    data = {"changed_source": how, "files_checked": len(js_files) + len(py_files), "manifests": []}

    if js_files:
        declared, workspace, aliases, base_urls, manifests = collect_js_context(stage, js_files)
        data["manifests"] += manifests
        nm_present = os.path.isdir(os.path.join(stage, "node_modules"))
        if not manifests:
            out["findings"].append(finding("warn", TOOL, "no package.json found; bare imports cannot be checked against declared dependencies"))
        ctx = (declared, workspace, aliases, base_urls, nm_present)
        for rel in js_files:
            check_js_file(stage, rel, ctx, out)

    if py_files:
        declared, used, toml_unparsed = collect_py_declared(stage, py_files)
        data["manifests"] += used
        if toml_unparsed:
            out["findings"].append(finding("warn", TOOL, "pyproject.toml/Pipfile could not be parsed (needs Python 3.11+ or tomli); dependency checks are degraded"))
        if not used:
            out["findings"].append(finding("warn", TOOL, "no requirements.txt / pyproject.toml found; third-party imports are checked against installed packages only"))
        stdlib = stdlib_names()
        roots_all = {os.path.join(stage, d) for f in py_files for d in ancestors(f)} | {os.path.join(stage, "src")}
        tops = set()
        for rel in py_files:
            try:
                with open(os.path.join(stage, rel), "rb") as fh:
                    tree = ast.parse(fh.read())
            except (OSError, SyntaxError, ValueError):
                continue
            for node, _g in py_import_nodes(tree):
                if isinstance(node, ast.Import):
                    tops |= {a.name.split(".")[0] for a in node.names}
                elif node.level == 0 and node.module:
                    tops.add(node.module.split(".")[0])
        tops = {t for t in tops if t not in stdlib and not any(module_to_path([r], t)[1] for r in roots_all)}
        installed = installed_info(stage, tops) if tops else {"found": {}, "dist": {}}
        cache = {}
        ctx = (stdlib, declared, installed, bool(used), toml_unparsed)
        for rel in py_files:
            check_py_file(stage, rel, ctx, cache, out)

    registry_checked = resolve_unresolved(out["unresolved"], args.check_registry, out) if out["unresolved"] else False

    if out["not_installed"]:
        names = sorted(out["not_installed"])
        out["findings"].append(finding(
            "warn", TOOL, "declared but not installed here: %s. Imports are fine, but the dry-run and tests cannot import them until installed." % ", ".join(names),
            code="declared-not-installed", suggestion="Install dependencies before the sandbox stage."))

    errors = [f for f in out["findings"] if f["severity"] == "error"]
    data.update({"imports_checked": out["imports"], "registry_checked": registry_checked,
                 "error_count": len(errors), "warning_count": sum(1 for f in out["findings"] if f["severity"] == "warn")})

    if not (js_files or py_files):
        status, reason = "skipped", "no TypeScript/JavaScript/Python files in the change set"
    elif errors:
        status, reason = "fail", "%d problem(s) found" % len(errors)
    else:
        status, reason = "pass", ""
    emit(STAGE, status, out["findings"], reason, data)
    return 1 if status == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
