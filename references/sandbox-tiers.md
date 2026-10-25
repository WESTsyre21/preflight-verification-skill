# Sandbox tiers reference

Read this before reporting a dry-run or test result, when a run was killed, when the network behaved oddly, or when you need to tell the user how strong the isolation was. `run_sandboxed.py` runs every command (dry-runs, tests, ESLint, edge-case probes) through the strongest tier available. Tiers are described honestly here, including what they do **not** do.

## Which tier runs

With `--tier auto` (the default):

1. **Tier A** if `docker info` succeeds (the daemon is reachable).
2. Otherwise **Tier B** on a POSIX host (Linux or macOS).
3. Otherwise **Tier C**: nothing runs, and the stage is `skipped`.

`--tier A` or `--tier B` **forces** a tier. If a forced tier is unavailable the stage fails with the reason. It never silently downgrades. `--print-plan` shows the exact command and environment keys without running anything.

| | Tier A: Docker | Tier B: hardened subprocess | Tier C |
|---|---|---|---|
| Network | `--network none` | namespace, or best-effort shims | n/a |
| Filesystem outside the stage | not visible | **readable and writable as your user** | n/a |
| Secrets in your shell | not passed | not passed (allow-listed env) | n/a |
| Memory / process limits | enforced by Docker | watchdog (Linux) | n/a |
| Strength | real isolation | damage limiting, **not a boundary** | nothing ran |

**Say which tier ran in every report.** For code the user does not trust, recommend Tier A or a disposable VM.

## Common to both tiers

- **Refuses unstaged directories.** The stage must have the manifest `stage_workspace.py` wrote next to it, and that manifest must name this directory. `--cwd` must stay inside the stage.
- **No shell** unless `--shell`. The command is split with `shlex`.
- **The network is blocked.** There is no flag to allow it. Install dependencies before this stage. Code that needs a service must be given a stub or test double, and the report should say a stub was used.
- **Defaults:** `--timeout 60` seconds wall clock, `--mem-mb 1024`, `--max-procs 200`, `--max-file-mb 256` (Tier B).
- **Output is capped.** Capture files are killed and trimmed at 200,000 bytes each (`CAP_BYTES`); a run that exceeds that is failed with `killed_for: output`. The last 8,000 bytes of each of stdout and stderr are kept in the JSON (`stdout_tail`, `stderr_tail`). The full sizes are in `stdout_bytes`/`stderr_bytes`, and `output_truncated` says when something was dropped.
- **Changes are reported.** The stage is snapshotted before and after. `fs_changes` lists up to 25 created, modified, and deleted files, with counts. Linked dependency directories are not scanned.
- **Passing extra environment** is only possible with `--env KEY=VALUE`. Only the key names appear in the output (`env_keys`), never the values.

## Tier A: Docker

The command runs as:

```
docker run --rm --name <n> --init --pull never --network none --read-only
  --tmpfs /tmp:rw,size=256m --cap-drop ALL --security-opt no-new-privileges
  --pids-limit <max-procs> --memory <mem>m --memory-swap <mem>m --cpus 2
  --user <your uid:gid> -v <stage>:/workspace:rw -w /workspace  ...  <image> <command>
```

- **Only the stage is writable.** The root filesystem is read-only, with a 256 MB tmpfs at `/tmp`. `HOME` is `/tmp/home`.
- **Linked dependencies are mounted read-only** at their original absolute path, so the stage's `node_modules` symlink resolves. This closes the read-through gap that Tier B has.
- **Image:** inferred from the command, `python:3.12-slim` for `python*`, `pytest`, `pip`, `ruff`, `pyright`, `mypy`, and `node:22-slim` for `node`, `npm`, `npx`, `tsc`, `jest`, `vitest`, `eslint`, `pnpm`, `yarn`. Anything else needs `--image`. The image must **already be pulled** (`--pull never` keeps the run offline). Otherwise you get `image-missing`; the fix is `docker pull <image>`, which is for the user to do.
- **Virtualenv:** a host `.venv` is not runnable inside the image, so its `site-packages` is added to `PYTHONPATH`. The image's Python **minor version must match the virtualenv's**, or compiled packages will fail to import.
- **Timeout:** the container is stopped with `docker kill`. Exit code 137 is reported as "likely the memory limit".
- **Status of this tier:** the command line is verified (`--print-plan`), but Tier A has **not been exercised against a live Docker daemon** in development. Treat the first real run as a smoke test.

## Tier B: hardened subprocess

Tier B limits damage. It is **not** a security boundary, and the report must not describe it as one.

**Environment.** Only `PATH`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`, and `TERM` are copied from your shell. `HOME`, `TMPDIR`, `TMP`, `TEMP`, and the XDG directories point into a throwaway scratch directory that is deleted afterwards. Also set: `CI=true`, `NO_COLOR=1`, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONUNBUFFERED=1`, `PYTHONHASHSEED=0`, `PIP_DISABLE_PIP_VERSION_CHECK=1`, `NPM_CONFIG_UPDATE_NOTIFIER=false`. So API keys, tokens, and cloud credentials in your shell never reach the code. `PATH` gets the stage's `node_modules/.bin`, `.venv/bin`, and `venv/bin` in front when they exist.

**Network** (`data.network_block` says which method was used):
- **Network namespace** (`unshare -rn`), used when the kernel allows it. The process has no external interfaces. The loopback interface is brought up (with a small Python ioctl helper, falling back to `ip link set lo up`), so tests that talk to `localhost` still work. DNS fails, as it should.
- **Shims**, used when namespaces are unavailable or with `--no-netns`. A `sitecustomize.py` (via `PYTHONPATH`) blocks non-local Python sockets and DNS. A preload script (via `NODE_OPTIONS=--require=...`) blocks non-local Node connections and lookups. `HTTP_PROXY` and friends point at a dead local port. **Any other language or tool is not blocked.** If shims were used, say so in the report.

**Limits.**
- Wall-clock timeout, then `SIGKILL` for the whole process group.
- `RLIMIT_CPU` (timeout + 5 s), `RLIMIT_FSIZE` (`--max-file-mb`), core dumps off, open files capped at 2,048.
- A **watchdog** checks every 50 ms (Linux, via `/proc`) and kills the group if the total resident memory exceeds `--mem-mb` or the live process count exceeds `--max-procs`. It is best effort: a very fast fork bomb can briefly exceed the limit before it is caught. Where `/proc` does not exist (macOS), the watchdog is inactive.
- Address-space limits (`RLIMIT_AS`) and per-user process limits (`RLIMIT_NPROC`) are deliberately **not** used. The first breaks V8, and the second counts every process you own.
- After the command exits, anything left running in its process group is killed and reported as `stray-processes`. A process that detaches into its own session can escape this.

**What Tier B does not do.** Code can still read and write any file your user account can, **including outside the stage**. The safety scan flags obvious attempts, but it is not a barrier. The stage's `node_modules` and virtualenv are links to the real ones, so a run can modify them.

## Tier C

Neither Docker nor POSIX resource limits exist. The dry-run and test stages are `skipped` with the reason, and the verdict is `PARTIAL` at best. Never describe a skipped sandbox stage as a pass.

## Reading a result

| Field | Meaning |
|---|---|
| `status` | `pass` only if the command exited 0 and no limit was hit |
| `data.tier`, `data.tier_reason` | which tier ran and why |
| `data.network_block` | how the network was blocked |
| `data.exit_code` | the command's exit code (negative means a signal) |
| `data.killed_for` | `timeout`, `memory`, `processes`, or `output` when a limit ended the run |
| `data.peak_rss_mb`, `data.peak_procs` | peaks seen by the watchdog (Tier B) |
| `data.fs_changes` | files the run created, modified, or deleted in the stage |
| `data.notes` | tier-specific caveats to repeat to the user |

Finding codes:

| Code | Meaning | Usual response |
|---|---|---|
| `nonzero-exit` | the command failed | read `stderr_tail`; run `diagnostics.py` |
| `timeout` | killed at the wall-clock limit | look for an infinite loop or a wait on the blocked network |
| `memory-limit` | exceeded `--mem-mb` | fix the allocation, or raise the limit only if justified |
| `process-limit` | exceeded `--max-procs` | look for a fork loop |
| `output-limit` | exceeded the 200 KB stdout/stderr capture cap | stop unbounded logging/printing; raise the cap only if justified |
| `stray-processes` | background processes were left running and killed | warn: the code starts processes it does not clean up |
| `stage-modified` | the run changed files in the stage | informational; unexpected changes to source files block a merge (see `merge_stage.py`) |
| `image-missing` | Tier A image is not pulled | environment problem for the user |

A test that hangs or fails only inside the sandbox is often waiting on the network. Look for calls to external services before assuming the logic is wrong.

## Possible upgrade (not implemented)

If `bubblewrap` (`bwrap`) is installed, Tier B could use it for a read-only root filesystem and a private network without needing Docker. That would close the filesystem gap above. Until it exists, say plainly that Tier B does not restrict files outside the stage.
