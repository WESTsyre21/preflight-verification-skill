#!/usr/bin/env python3
"""detect_env.py - find out what can really run before claiming anything is verified.

Probes the project (languages, test frameworks) and the machine (type checkers,
Docker, network, isolation primitives), then recommends a sandbox tier:

    A  Docker available and its daemon reachable   -> real isolation
    B  POSIX host with resource limits             -> hardened subprocess
    C  neither                                     -> static checks only

Output is a single JSON object on stdout:
    {"stage": "detect_env", "status": "pass|fail", "findings": [...],
     "reason": "...", "data": {...}}
"""
import argparse
import json
import os
import shutil
import socket
import sys

from _common import (JS_EXT, SKIP_DIRS as BASE_SKIP, TS_EXT, emit, find_node_tool,
                     load_json_lenient, project_python as venv_python, run as common_run)

STAGE = "detect_env"

# Extra dirs to skip when counting sources (caches/build output beyond dependency dirs).
SKIP_DIRS = BASE_SKIP | {
    "env", ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build", ".next", ".tox",
    "site-packages",
}
SCAN_LIMIT = 20000  # stop walking enormous repos; a rough count is enough


def run(cmd, cwd=None, timeout=10):
    """Run a command, returning (returncode or None, combined output)."""
    rc, so, se = common_run(cmd, cwd, timeout)
    return rc, (so or "") + (se or "")


def count_sources(root):
    counts = {"ts": 0, "js": 0, "py": 0}
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            seen += 1
            if seen > SCAN_LIMIT:
                return counts, True
            ext = os.path.splitext(name)[1].lower()
            if ext in TS_EXT:
                counts["ts"] += 1
            elif ext in JS_EXT:
                counts["js"] += 1
            elif ext == ".py":
                counts["py"] += 1
    return counts, False


def read_package_json(project):
    path = os.path.join(project, "package.json")
    if not os.path.isfile(path):
        return None
    return load_json_lenient(path)


def project_python(project):
    """Use the project's own virtualenv interpreter when there is one."""
    return venv_python(project) or sys.executable or shutil.which("python3")


def python_modules(python, names):
    """Return {module: bool} using the chosen interpreter's import machinery."""
    code = (
        "import importlib.util, json, sys;"
        "print(json.dumps({n: importlib.util.find_spec(n) is not None for n in sys.argv[1:]}))"
    )
    rc, out = run([python, "-c", code] + list(names))
    if rc == 0:
        try:
            return json.loads(out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            pass
    return {n: False for n in names}


def detect_node(project, pkg):
    node = shutil.which("node")
    deps = {}
    if isinstance(pkg, dict):
        deps.update(pkg.get("dependencies", {}) or {})
        deps.update(pkg.get("devDependencies", {}) or {})
    runner = None
    for name in ("vitest", "jest"):
        if find_node_tool(project, name) or name in deps:
            runner = name
            break
    return {
        "node": node,
        "tsc": find_node_tool(project, "tsc"),
        "eslint": find_node_tool(project, "eslint"),
        "test_runner": runner,
        "test_runner_installed": bool(runner and find_node_tool(project, runner)),
        "fast_check": os.path.isdir(os.path.join(project, "node_modules", "fast-check")),
    }


def detect_python(project):
    py = project_python(project)
    mods = python_modules(py, ["pytest", "hypothesis"]) if py else {}
    return {
        "python": py,
        "pyright": shutil.which("pyright") or find_node_tool(project, "pyright"),
        "ruff": shutil.which("ruff") or find_node_tool(project, "ruff"),
        "pytest": bool(mods.get("pytest")),
        "hypothesis": bool(mods.get("hypothesis")),
    }


def detect_docker():
    exe = shutil.which("docker")
    if not exe:
        return {"cli": False, "daemon": False}
    rc, _ = run([exe, "info", "--format", "{{.ServerVersion}}"], timeout=8)
    return {"cli": True, "daemon": rc == 0}


def detect_network(host="pypi.org", port=443, timeout=3):
    """Can we reach a package registry? Informational: runs stay network-blocked."""
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def detect_isolation():
    posix = os.name == "posix"
    try:
        import resource  # noqa: F401
        has_resource = True
    except ImportError:
        has_resource = False
    unshare = shutil.which("unshare")
    netns = False
    if unshare:
        rc, _ = run([unshare, "-rn", "true"], timeout=5)
        netns = rc == 0
    return {"posix": posix, "resource_limits": has_resource, "network_namespace": netns}


def recommend_tier(docker, isolation):
    if docker["daemon"]:
        return "A", "Docker daemon is reachable"
    if isolation["posix"] and isolation["resource_limits"]:
        how = "network namespace" if isolation["network_namespace"] else "stubbed network (no namespace support)"
        return "B", "no Docker; hardened subprocess with ulimits and " + how
    return "C", "no Docker and no POSIX resource limits; static checks only"


def plan_stages(langs, node, py, tier):
    """Per stage: can it run, and if not, why. Skipped is not the same as passed."""
    stages = {}

    if "ts" in langs or "js" in langs:
        if node["tsc"]:
            stages["static_ts"] = {"can_run": True, "reason": "tsc found"}
        else:
            stages["static_ts"] = {"can_run": False, "reason": "tsc not installed (npm i -D typescript)"}
    if "py" in langs:
        have = [t for t in ("pyright", "ruff") if py.get(t)]
        stages["static_py"] = {
            "can_run": True,
            "reason": ("using " + ", ".join(have)) if have else "only py_compile available (no pyright/ruff)",
        }

    stages["deps"] = {"can_run": bool(langs), "reason": "AST/manifest scan needs no external tools"}
    stages["safety"] = {"can_run": bool(langs), "reason": "pattern scan needs no external tools"}

    if tier == "C":
        stages["dry_run"] = {"can_run": False, "reason": "no usable sandbox tier"}
        stages["tests"] = {"can_run": False, "reason": "no usable sandbox tier"}
    else:
        stages["dry_run"] = {"can_run": True, "reason": "tier " + tier}
        runnable = []
        if ("ts" in langs or "js" in langs) and node["test_runner_installed"]:
            runnable.append(node["test_runner"])
        if "py" in langs and py.get("pytest"):
            runnable.append("pytest")
        if runnable:
            stages["tests"] = {"can_run": True, "reason": "found " + ", ".join(runnable)}
        else:
            stages["tests"] = {"can_run": False, "reason": "no installed test runner detected"}
    return stages


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", required=True, help="path to the project root")
    args = ap.parse_args()

    project = os.path.abspath(args.project)
    if not os.path.isdir(project):
        emit(STAGE, "fail", [], "project directory not found: " + project, {})
        return 2

    findings = []
    counts, truncated = count_sources(project)
    langs = [k for k, v in counts.items() if v > 0]
    if truncated:
        findings.append({"severity": "info", "message": "source count truncated; large repository"})
    if not langs:
        findings.append({"severity": "warn", "message": "no TypeScript, JavaScript, or Python sources found"})

    pkg = read_package_json(project)
    node = detect_node(project, pkg)
    py = detect_python(project)
    docker = detect_docker()
    network = detect_network()
    isolation = detect_isolation()
    tier, tier_reason = recommend_tier(docker, isolation)

    # Secrets are left out of the staged copy; tell the user so a missing .env is no surprise.
    env_files = [n for n in os.listdir(project) if n == ".env" or (n.startswith(".env.") and n not in
                 (".env.example", ".env.sample", ".env.template"))]
    if env_files:
        findings.append({"severity": "info",
                         "message": "secret files will be excluded from the staged copy: " + ", ".join(sorted(env_files))})

    stages = plan_stages(langs, node, py, tier)
    for name, info in stages.items():
        if not info["can_run"] and name not in ("dry_run", "tests"):
            findings.append({"severity": "warn", "message": name + " cannot run: " + info["reason"]})
        elif not info["can_run"]:
            findings.append({"severity": "warn", "message": name + " will be skipped: " + info["reason"]})
    if not network:
        findings.append({"severity": "info", "message": "package registry unreachable; missing tools cannot be installed"})

    data = {
        "project": project,
        "platform": sys.platform,
        "languages": langs,
        "source_counts": counts,
        "tools": {"node": node, "python": py},
        "docker": docker,
        "registry_reachable": network,
        "isolation": isolation,
        "recommended_tier": tier,
        "tier_reason": tier_reason,
        "stages": stages,
    }
    emit(STAGE, "pass", findings, "", data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
