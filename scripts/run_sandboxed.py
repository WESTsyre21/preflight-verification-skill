#!/usr/bin/env python3
"""run_sandboxed.py - run a command against the STAGED workspace under the strongest isolation available.

    run_sandboxed.py --stage <dir> --cmd "pytest -q tests/test_x.py" [--tier auto|A|B] [--timeout 60]

The command is split with shlex and run WITHOUT a shell (use --shell if you need pipes).

TIER A - Docker (real isolation)
    --network none, read-only root filesystem, all capabilities dropped, no-new-privileges, memory/CPU/PID
    limits, non-root user, only the stage mounted writable. Host dependency directories that the stage
    links to (node_modules, .venv) are mounted READ-ONLY.

TIER B - hardened subprocess (damage limiting, NOT a hard boundary)
    * scrubbed environment: only an allow-list is passed, HOME/TMPDIR point at a throwaway scratch dir,
      so API keys and tokens in your shell never reach the code under test
    * network blocked: a network namespace (`unshare -rn`) when the kernel allows it, otherwise
      best-effort Python/Node shims plus a dead proxy. The result says which one was used.
    * wall-clock timeout, CPU/file-size rlimits, and a watchdog that kills the whole process group when it
      exceeds the memory or process-count limit; stray background processes are killed afterwards
    * it does NOT restrict which files the user account can read or write outside the stage. Use Tier A,
      or run in a disposable VM/container, when you do not trust the code.

TIER C - nothing safe is available: the stage is reported as skipped, never as passed.

The run refuses to start unless the directory was created by stage_workspace.py (its manifest must sit
next to it), so it cannot be pointed at your real project by mistake.

Output: {"stage": "run_sandboxed", "status": "pass|fail|skipped", "findings": [...], "reason": "...",
         "data": {tier, exit_code, timed_out, stdout_tail, stderr_tail, fs_changes, network_block, ...}}
"""
import argparse
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from _common import emit, finding, manifest_path, norm, run

STAGE = "run_sandboxed"
TOOL = "sandbox"
SAFE_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM")
LOCAL_NO_PROXY = "localhost,127.0.0.1,::1"
DEAD_PROXY = "http://127.0.0.1:9"
TAIL_BYTES = 8000
CAP_BYTES = 200_000  # beyond this we only count output, never keep it

PY_SHIM = '''\
# preflight-verify: best-effort network block for Python (used only when a network namespace is unavailable)
import errno, socket
_MSG = "network access is blocked by preflight-verify"
_LOCAL = {"localhost", "127.0.0.1", "::1", "0.0.0.0", ""}

def _is_local(addr):
    if isinstance(addr, (str, bytes)):
        return True  # AF_UNIX path
    host = addr[0] if isinstance(addr, tuple) and addr else ""
    return str(host) in _LOCAL

_connect, _connect_ex = socket.socket.connect, socket.socket.connect_ex
def connect(self, address):
    if _is_local(address):
        return _connect(self, address)
    raise OSError(errno.ENETUNREACH, _MSG)
def connect_ex(self, address):
    if _is_local(address):
        return _connect_ex(self, address)
    return errno.ENETUNREACH
socket.socket.connect, socket.socket.connect_ex = connect, connect_ex

_getaddrinfo = socket.getaddrinfo
def getaddrinfo(host, *a, **k):
    if str(host) in _LOCAL or host is None:
        return _getaddrinfo(host, *a, **k)
    raise socket.gaierror(socket.EAI_NONAME, _MSG)
socket.getaddrinfo = getaddrinfo
'''

NODE_SHIM = '''\
// preflight-verify: best-effort network block for Node (used only when a network namespace is unavailable)
const net = require("net"), dns = require("dns");
const LOCAL = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0", ""]);
const MSG = "network access is blocked by preflight-verify";
const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  const a = args[0];
  let host = "", unix = false;
  if (a && typeof a === "object") { host = a.host || ""; unix = !!a.path; if (!a.host && !a.path) host = "localhost"; }
  else if (typeof a === "string" && Number.isNaN(Number(a))) { unix = true; }
  else { host = typeof args[1] === "string" ? args[1] : "localhost"; }
  if (unix || LOCAL.has(String(host))) return origConnect.apply(this, args);
  const err = Object.assign(new Error(MSG), { code: "ENETUNREACH" });
  process.nextTick(() => this.destroy(err));
  return this;
};
const origLookup = dns.lookup;
dns.lookup = function (host, ...rest) {
  if (LOCAL.has(String(host))) return origLookup.call(dns, host, ...rest);
  const cb = rest.find((r) => typeof r === "function");
  const err = Object.assign(new Error(MSG), { code: "ENOTFOUND" });
  if (cb) process.nextTick(() => cb(err)); return {};
};
'''


LO_UP = '''\
# preflight-verify: bring the loopback interface up inside a fresh network namespace (no `ip` needed)
import fcntl, socket, struct
SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    flags = struct.unpack("16sH14s", fcntl.ioctl(s, SIOCGIFFLAGS, struct.pack("16sH14s", b"lo", 0, b"")))[1]
    fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH14s", b"lo", flags | IFF_UP, b""))
'''


# ================================================================= tier selection
def docker_ready():
    if not shutil.which("docker"):
        return False
    rc, _o, _e = run(["docker", "info", "--format", "{{.ServerVersion}}"], None, 8)
    return rc == 0


def posix_limits_ok():
    if os.name != "posix":
        return False
    try:
        import resource  # noqa: F401
        return True
    except ImportError:
        return False


def netns_ok():
    exe = shutil.which("unshare")
    if not exe:
        return False
    rc, _o, _e = run([exe, "-rn", "true"], None, 5)
    return rc == 0


def pick_tier(requested, plan_only):
    """Return (tier or None, reason). plan_only skips availability probes so plans can be inspected anywhere."""
    if requested == "A":
        return ("A", "requested") if plan_only or docker_ready() else (None, "Tier A requested but the Docker daemon is not reachable")
    if requested == "B":
        return ("B", "requested") if posix_limits_ok() else (None, "Tier B requested but POSIX resource limits are unavailable")
    if docker_ready():
        return "A", "Docker daemon reachable"
    if posix_limits_ok():
        return "B", "no Docker; hardened subprocess"
    return None, "no Docker and no POSIX resource limits"


# ================================================================= environment
def build_env(stage, scratch, extra, tier):
    home = os.path.join(scratch, "home")
    tmp = os.path.join(scratch, "tmp")
    os.makedirs(home, exist_ok=True)
    os.makedirs(tmp, exist_ok=True)
    env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ and tier == "B"}
    env.update({
        "HOME": home, "TMPDIR": tmp, "TMP": tmp, "TEMP": tmp,
        "XDG_CACHE_HOME": os.path.join(home, ".cache"), "XDG_CONFIG_HOME": os.path.join(home, ".config"),
        "CI": "true", "NO_COLOR": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1",
        "PYTHONHASHSEED": "0", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "NPM_CONFIG_UPDATE_NOTIFIER": "false",
    })
    env.update(extra)
    return env


def path_additions(stage):
    adds = []
    for rel in ("node_modules/.bin", ".venv/bin", "venv/bin"):
        if os.path.isdir(os.path.join(stage, rel)):
            adds.append(os.path.join(stage, rel))
    return adds


def linked_dependencies(stage):
    """Return dependency directories that are symlinked to the real project."""
    return [name for name in ("node_modules", ".venv", "venv")
            if os.path.islink(os.path.join(stage, name))]


def parse_extra_env(items):
    extra = {}
    for item in items or []:
        if "=" not in item:
            raise ValueError("--env expects KEY=VALUE, got %r" % item)
        k, v = item.split("=", 1)
        extra[k] = v
    return extra


# ================================================================= tier B plumbing
def make_preexec(cpu_seconds, fsize_mb):
    def apply():
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
            fsize = fsize_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            limit = 2048 if hard == resource.RLIM_INFINITY else min(2048, hard)
            resource.setrlimit(resource.RLIMIT_NOFILE, (limit, hard))
        except (ImportError, ValueError, OSError):
            pass
    return apply


def group_usage(pgid):
    """(total RSS bytes, live process count) for a process group. (0, 0) where /proc is unavailable."""
    if not os.path.isdir("/proc"):
        return 0, 0
    page = os.sysconf("SC_PAGE_SIZE")
    rss = count = 0
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % entry) as fh:
                data = fh.read()
            rest = data[data.rindex(")") + 2:].split()
            if int(rest[2]) == pgid and rest[0] != "Z":
                rss += int(rest[21]) * page
                count += 1
        except (OSError, ValueError, IndexError):
            continue
    return rss, count


def kill_group(pgid):
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def snapshot(stage):
    """{relative path: (size, mtime_ns)} for real files in the stage, ignoring linked dependency dirs."""
    snap = {}
    for dirpath, dirnames, filenames in os.walk(stage, followlinks=False):
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d)) and d != ".git"]
        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            snap[norm(os.path.relpath(full, stage))] = (st.st_size, st.st_mtime_ns)
            if len(snap) > 100_000:
                return snap
    return snap


def diff_snapshots(before, after):
    created = sorted(set(after) - set(before))
    deleted = sorted(set(before) - set(after))
    modified = sorted(k for k in set(before) & set(after) if before[k] != after[k])
    return {"created": created[:25], "modified": modified[:25], "deleted": deleted[:25],
            "counts": {"created": len(created), "modified": len(modified), "deleted": len(deleted)}}


def read_tail(path):
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        if size > TAIL_BYTES:
            fh.seek(size - TAIL_BYTES)
        text = fh.read().decode("utf-8", errors="replace")
    return text, size


# ================================================================= the two runners
def _file_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _truncate_to_cap(path):
    """Keep only the last CAP_BYTES of a capture file so runaway output cannot fill the disk."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    if size <= CAP_BYTES:
        return
    with open(path, "rb") as fh:
        fh.seek(size - CAP_BYTES)
        tail = fh.read()
    with open(path, "wb") as fh:
        fh.write(tail)


def execute(argv, cwd, env, args, scratch, docker_name=None):
    """Run argv with limits, returning a dict of raw results. Shared by both tiers."""
    out_path, err_path = os.path.join(scratch, "stdout.txt"), os.path.join(scratch, "stderr.txt")
    limit_bytes = args.mem_mb * 1024 * 1024
    reason, peak_rss, peak_procs, stray = None, 0, 0, 0
    start = time.monotonic()
    with open(out_path, "wb") as fo, open(err_path, "wb") as fe:
        proc = subprocess.Popen(
            argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=fo, stderr=fe, start_new_session=True,
            preexec_fn=make_preexec(args.timeout + 5, args.max_file_mb) if docker_name is None else None)
        pgid = proc.pid
        while True:
            rc = proc.poll()
            if rc is not None:
                break
            if time.monotonic() - start > args.timeout:
                reason = "timeout"
                break
            # Cap capture files so a noisy process cannot fill the disk. JSON still only keeps TAIL_BYTES.
            if _file_size(out_path) > CAP_BYTES or _file_size(err_path) > CAP_BYTES:
                reason = "output"
                break
            if docker_name is None:  # Docker enforces memory and PIDs itself
                rss, count = group_usage(pgid)
                peak_rss, peak_procs = max(peak_rss, rss), max(peak_procs, count)
                if rss > limit_bytes:
                    reason = "memory"
                    break
                if count > args.max_procs:
                    reason = "processes"
                    break
            time.sleep(0.05)
        if reason:
            if docker_name:
                run(["docker", "kill", docker_name], None, 10)
            kill_group(pgid)
            rc = proc.wait()
        elif docker_name is None:
            _rss, left = group_usage(pgid)
            stray = left
        if docker_name is None:
            kill_group(pgid)  # sweep anything the command left running in the background
    # Process may have finished writing a burst larger than CAP_BYTES between polls; trim and flag.
    if _file_size(out_path) > CAP_BYTES or _file_size(err_path) > CAP_BYTES:
        reason = reason or "output"
        _truncate_to_cap(out_path)
        _truncate_to_cap(err_path)
    return {"returncode": rc, "reason": reason, "duration": time.monotonic() - start, "stdout_path": out_path,
            "stderr_path": err_path, "peak_rss_mb": round(peak_rss / 1048576, 1), "peak_procs": peak_procs, "stray": stray}


def plan_tier_b(argv, stage, scratch, extra, args):
    """Build (argv, env, network_block, notes) for Tier B."""
    env = build_env(stage, scratch, extra, "B")
    adds = path_additions(stage)
    env["PATH"] = os.pathsep.join(adds + [env.get("PATH", "/usr/local/bin:/usr/bin:/bin")])
    notes = []

    # network: namespace if possible, shims otherwise. Both are set up so the run works either way.
    shim_dir = os.path.join(scratch, "shim")
    os.makedirs(shim_dir, exist_ok=True)
    with open(os.path.join(shim_dir, "sitecustomize.py"), "w") as fh:
        fh.write(PY_SHIM)
    with open(os.path.join(shim_dir, "preload.js"), "w") as fh:
        fh.write(NODE_SHIM)
    use_ns = netns_ok() and not args.no_netns
    if use_ns:
        method = "network namespace (unshare -rn): no external interfaces"
        lo_script = os.path.join(scratch, "lo_up.py")
        with open(lo_script, "w") as fh:
            fh.write(LO_UP)
        # Loopback starts down in a new namespace; local test servers need it. Try Python, then `ip`.
        bring_up = '%s %s >/dev/null 2>&1 || { command -v ip >/dev/null 2>&1 && ip link set lo up >/dev/null 2>&1; }; exec "$@"' % (
            shlex.quote(sys.executable), shlex.quote(lo_script))
        wrapped = ["unshare", "-rn", "sh", "-c", bring_up, "sh"] + argv
    else:
        method = "best-effort shims (Python sockets, Node net/dns) plus a dead proxy; other languages are NOT blocked"
        wrapped = list(argv)
        env["PYTHONPATH"] = shim_dir
        env["NODE_OPTIONS"] = "--require=" + os.path.join(shim_dir, "preload.js")
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            env[k] = DEAD_PROXY
        env["NO_PROXY"] = env["no_proxy"] = LOCAL_NO_PROXY
        notes.append("network namespace unavailable; only Python and Node network calls are blocked")
    notes.append("Tier B limits damage but does not restrict filesystem access outside the stage")
    return wrapped, env, method, notes


def docker_plan(argv, stage, scratch, extra, args, name):
    """Build the full `docker run` argv for Tier A and the notes that go with it."""
    env = build_env(stage, scratch, extra, "A")
    # Container-side locations: scratch dirs live in the tmpfs, not on the host.
    env.update({"HOME": "/tmp/home", "TMPDIR": "/tmp", "TMP": "/tmp", "TEMP": "/tmp",
                "XDG_CACHE_HOME": "/tmp/home/.cache", "XDG_CONFIG_HOME": "/tmp/home/.config"})
    mounts, notes = [], []
    for entry in sorted(os.listdir(stage)):  # symlinked dependency dirs point at host paths: mount them read-only
        full = os.path.join(stage, entry)
        if os.path.islink(full) and os.path.isdir(full):
            target = os.path.realpath(full)
            mounts += ["-v", "%s:%s:ro" % (target, target)]
            notes.append("%s mounted read-only from %s" % (entry, target))
    py_site = None
    venv_lib = os.path.join(os.path.realpath(os.path.join(stage, ".venv")), "lib") if os.path.islink(os.path.join(stage, ".venv")) else None
    if venv_lib and os.path.isdir(venv_lib):
        for py in sorted(os.listdir(venv_lib)):
            cand = os.path.join(venv_lib, py, "site-packages")
            if os.path.isdir(cand):
                py_site = cand
    if py_site:
        env["PYTHONPATH"] = py_site
        notes.append("host virtualenv site-packages added to PYTHONPATH; the image's Python version must match it")
    env["PATH"] = "/workspace/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    image = args.image
    if not image:
        exe = os.path.basename(argv[0])
        if exe.startswith(("python", "pytest", "pip", "ruff", "pyright", "mypy")):
            image = "python:3.12-slim"
        elif exe in ("node", "npm", "npx", "tsc", "jest", "vitest", "eslint", "pnpm", "yarn"):
            image = "node:22-slim"
        else:
            raise ValueError("cannot infer a Docker image from %r; pass --image" % exe)
    uid = os.getuid() if hasattr(os, "getuid") else 1000
    gid = os.getgid() if hasattr(os, "getgid") else 1000
    cmd = ["docker", "run", "--rm", "--name", name, "--init", "--pull", "never",
           "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,size=256m",
           "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
           "--pids-limit", str(args.max_procs), "--memory", "%dm" % args.mem_mb, "--memory-swap", "%dm" % args.mem_mb,
           "--cpus", "2", "--user", "%d:%d" % (uid, gid),
           "-v", "%s:/workspace:rw" % stage] + mounts + ["-w", "/workspace" + ("/" + args.cwd if args.cwd else "")]
    for k, v in sorted(env.items()):
        cmd += ["-e", "%s=%s" % (k, v)]
    cmd += [image] + argv
    notes.append("image %s must already be pulled (--pull never keeps the run offline)" % image)
    return cmd, env, notes, image


# ================================================================= main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stage", required=True, help="staged workspace created by stage_workspace.py")
    ap.add_argument("--cmd", required=True, help="command to run (split with shlex, no shell)")
    ap.add_argument("--shell", action="store_true", help="run the command through `sh -c` inside the sandbox")
    ap.add_argument("--tier", choices=["auto", "A", "B"], default="auto")
    ap.add_argument("--cwd", default="", help="subdirectory of the stage to run in")
    ap.add_argument("--timeout", type=int, default=60, help="wall-clock seconds (default 60)")
    ap.add_argument("--mem-mb", type=int, default=1024, help="memory limit in MB (default 1024)")
    ap.add_argument("--max-procs", type=int, default=200, help="max processes (default 200)")
    ap.add_argument("--max-file-mb", type=int, default=256, help="max size of any file the command writes (Tier B)")
    ap.add_argument("--env", action="append", metavar="KEY=VALUE", help="extra environment variable to pass (repeatable)")
    ap.add_argument("--image", help="Docker image for Tier A (default inferred from the command)")
    ap.add_argument("--no-netns", action="store_true", help="Tier B: skip the network namespace and use shims (testing)")
    ap.add_argument("--print-plan", action="store_true", help="show what would run, without running it")
    args = ap.parse_args()

    stage = os.path.abspath(args.stage)

    def fail(msg, code=2):
        emit(STAGE, "fail", [finding("error", TOOL, msg)], msg, {})
        return code

    if not os.path.isdir(stage):
        return fail("stage directory not found: " + stage)
    mpath = manifest_path(stage)
    try:
        with open(mpath, encoding="utf-8") as fh:
            recorded = json.load(fh).get("stage")
    except (OSError, ValueError):
        return fail("refusing to run: %s is not a staged workspace (no manifest at %s). Use stage_workspace.py first." % (stage, mpath))
    if os.path.realpath(recorded or "") != os.path.realpath(stage):
        return fail("refusing to run: the manifest does not belong to this directory")

    cwd = stage
    if args.cwd:
        cwd = os.path.realpath(os.path.join(stage, args.cwd))
        if os.path.commonpath([cwd, os.path.realpath(stage)]) != os.path.realpath(stage) or not os.path.isdir(cwd):
            return fail("--cwd must be an existing directory inside the stage")

    try:
        argv = ["sh", "-c", args.cmd] if args.shell else shlex.split(args.cmd)
        extra = parse_extra_env(args.env)
    except ValueError as exc:
        return fail(str(exc))
    if not argv:
        return fail("empty command")

    tier, tier_reason = pick_tier(args.tier, args.print_plan)
    if tier is None:
        status = "fail" if args.tier != "auto" else "skipped"
        emit(STAGE, status, [finding("warn" if status == "skipped" else "error", TOOL, tier_reason)], tier_reason,
             {"tier": "C" if status == "skipped" else args.tier,
              "note": "nothing ran: a skipped sandbox stage is NOT a passed stage"})
        return 1 if status == "fail" else 0

    linked = linked_dependencies(stage)
    if tier == "B" and linked:
        emit(STAGE, "fail", [finding("error", TOOL,
             "Tier B refuses linked dependency directories (%s); re-stage with --copy-deps or use Tier A" %
             ", ".join(linked), code="linked-dependencies")],
             "Tier B could write through dependency symlinks into the real project", {"tier": tier, "linked": linked})
        return 1

    scratch = tempfile.mkdtemp(prefix="preflight-run-")
    try:
        name = "preflight-%d-%d" % (os.getpid(), int(time.time()))
        if tier == "A":
            try:
                full, env, notes, image = docker_plan(argv, stage, scratch, extra, args, name)
            except ValueError as exc:
                return fail(str(exc))
            method, cpu_cwd, docker_name = "docker --network none", stage, name
        else:
            full, env, method, notes = plan_tier_b(argv, stage, scratch, extra, args)
            cpu_cwd, docker_name = cwd, None

        plan = {"tier": tier, "tier_reason": tier_reason, "argv": full, "cwd": cpu_cwd, "network_block": method,
                "env_keys": sorted(env), "limits": {"timeout_s": args.timeout, "mem_mb": args.mem_mb, "max_procs": args.max_procs}}
        if args.print_plan:
            plan["notes"] = notes
            emit(STAGE, "pass", [], "plan only; nothing was run", plan)
            return 0

        before = snapshot(stage)
        res = execute(full, cpu_cwd, env, args, scratch, docker_name)
        changes = diff_snapshots(before, snapshot(stage))
        out_tail, out_size = read_tail(res["stdout_path"])
        err_tail, err_size = read_tail(res["stderr_path"])

        rc, reason = res["returncode"], res["reason"]
        findings = []
        if reason == "timeout":
            findings.append(finding("error", TOOL, "killed after the %ds wall-clock timeout" % args.timeout, code="timeout"))
        elif reason == "memory":
            findings.append(finding("error", TOOL, "killed for exceeding %d MB of memory" % args.mem_mb, code="memory-limit"))
        elif reason == "processes":
            findings.append(finding("error", TOOL, "killed for exceeding %d processes" % args.max_procs, code="process-limit"))
        elif reason == "output":
            findings.append(finding("error", TOOL,
                                   "killed for exceeding the %d-byte stdout/stderr capture cap" % CAP_BYTES,
                                   code="output-limit"))
        elif rc != 0:
            sig = -rc if rc < 0 else (rc - 128 if rc > 128 else None)
            hint = ""
            if sig:
                try:
                    hint = " (signal %s)" % signal.Signals(sig).name
                except ValueError:
                    pass
            if tier == "A" and rc == 137:
                hint += " likely the memory limit"
            findings.append(finding("error", TOOL, "command exited with code %s%s" % (rc, hint), code="nonzero-exit"))
            if tier == "A" and "Unable to find image" in err_tail:
                findings.append(finding("error", TOOL, "Docker image is not present locally; run `docker pull <image>` first", code="image-missing"))
        if res["stray"]:
            findings.append(finding("warn", TOOL, "%d background process(es) were still running and were killed" % res["stray"], code="stray-processes"))
        if changes["counts"]["created"] or changes["counts"]["modified"] or changes["counts"]["deleted"]:
            findings.append(finding("info", TOOL, "the run changed files in the stage: %(created)d created, %(modified)d modified, %(deleted)d deleted" % changes["counts"], code="stage-modified"))

        data = dict(plan)
        data.update({
            "command": args.cmd, "exit_code": rc, "timed_out": reason == "timeout", "killed_for": reason,
            "duration_s": round(res["duration"], 2), "stdout_tail": out_tail, "stderr_tail": err_tail,
            "stdout_bytes": out_size, "stderr_bytes": err_size,
            "output_truncated": out_size > TAIL_BYTES or err_size > TAIL_BYTES or reason == "output",
            "peak_rss_mb": res["peak_rss_mb"], "peak_procs": res["peak_procs"],
            "fs_changes": changes, "notes": notes,
            "isolation": "docker (real isolation)" if tier == "A" else "hardened subprocess (not a hard boundary)",
        })
        ok = rc == 0 and not reason
        emit(STAGE, "pass" if ok else "fail", findings, "" if ok else (findings[0]["message"] if findings else "command failed"), data)
        return 0 if ok else 1
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
