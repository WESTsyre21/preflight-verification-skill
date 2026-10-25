---
name: preflight-verify
description: Pre-flight verification for AI-generated code. Stages a proposed change in a throwaway copy, type-checks it, scans it for hallucinated dependencies and dangerous operations, dry-runs it in the safest available sandbox, runs the affected tests plus edge-case inputs, and only then merges it into the real workspace. Use this skill whenever you are about to write or modify TypeScript/JavaScript or Python source files, whenever the user asks to verify, dry-run, sanity-check, or "make sure it actually compiles/runs" before applying code, and whenever generated code failed once and you are tempted to just patch and hope. Use it even for small edits, because plausible-looking code that fails at runtime is the failure this skill exists to catch.
---

# Pre-Flight Code Verification & Test Dry-Run

AI-written code often looks right and still fails to compile, imports a package that does not exist, or breaks on `null`. Writing straight into the workspace makes those failures expensive: they land in the user's files before anyone finds out. This skill moves discovery earlier. The change is proven in a disposable copy first, and the real files are only touched after it passes.

## Core rule

Never write the proposed change into the real workspace first. Stage it, verify it, then merge. Everything below serves that rule.

## Scripts

All scripts live in `scripts/`, read their inputs from flags, and print JSON of the form `{"stage": "...", "status": "pass|fail|skipped", "findings": [...], "reason": "..."}`. Read the JSON; do not scrape their prose output.

| Script | Purpose |
|---|---|
| `detect_env.py --project <dir>` | Reports languages found, which tools exist (tsc, eslint, pyright, ruff, pytest, jest/vitest, Docker), whether network access exists, and the recommended sandbox tier |
| `stage_workspace.py --project <dir> --patch <file> --out <tmpdir>` | Copies the project to a temp directory and applies the change there |
| `static_check.py --stage <dir> [--scope all\|changed]` | Type and syntax validation: `tsc --noEmit` and `node --check` for TS/JS; `ast`, ruff, and pyright for Python |
| `dep_check.py --stage <dir> [--check-registry]` | Every import resolves to a local file, the standard library, or a declared dependency; imported names exist; local call signatures match. `--check-registry` tells a hallucinated package from a real but undeclared one |
| `safety_scan.py --stage <dir> [--approve FILE:LINE]` | Flags destructive, injecting, or exfiltrating operations before anything runs. `block` findings need the user's decision |
| `run_sandboxed.py --stage <dir> --cmd "<cmd>" [--tier auto\|A\|B] [--timeout 60] [--shell]` | Runs a command against the staged copy in the strongest isolation available; refuses any directory `stage_workspace.py` did not create |
| `run_tests.py --stage <dir> [--edge-cases off\|warn\|strict]` | Selects the tests that cover the change, runs only those in the sandbox, then probes Python functions with edge-case inputs |
| `diagnostics.py --report <json> --stage <dir> --attempt N [--previous <json>] [--format prompt]` | Turns failing stage reports into the exact next prompt and says whether to fix, ask the user, stop, or treat it as an environment problem |
| `merge_stage.py --stage <dir> --verdict VERIFIED\|PARTIAL [--dry-run\|--rollback]` | The only script that writes to the real project. Strict: refuses on drift or tampering, backs up, and can undo |

## Workflow

### 0. Detect the environment

Run `detect_env.py` first. It decides which stages can run and which sandbox tier is available. Skipping this step is how a skill claims "verified" while silently running nothing.

### 1. Stage

Run `stage_workspace.py`. From this point, every command runs against the staged copy.

### 2. Static analysis (no code executes)

Run `static_check.py`, then `dep_check.py` (add `--check-registry` when the network is reachable). These are the cheapest checks and catch the most common agent mistakes: type errors, wrong argument shapes, imports of packages that are not declared anywhere, and names imported from local modules that do not exist. A fail here goes straight to the retry loop.

Read two things in the JSON besides `status`:
- **`data.skipped_checks`** lists tools that were not installed (for example pyright). A non-empty list means coverage was partial, so the final verdict cannot be `VERIFIED`.
- **`--scope`** on `static_check.py`. The default `all` fails on a type error anywhere, because a change that deletes an export breaks its importers in files you never touched. Use `--scope changed` only when the project already had errors before your change; errors elsewhere then become warnings.

ESLint is not run here. Its config file is JavaScript, so running it would execute project code outside the sandbox. Run it in step 4 through `run_sandboxed.py` instead.

### 3. Safety scan

Run `safety_scan.py`. It matches patterns such as `rm -rf`, `child_process`/`subprocess` with dynamic input, `eval`/`exec`, raw sockets, and writes outside the project.

Treat this scan as an early-warning filter, not a security boundary. Code can hide intent in ways a pattern match will not see, so the sandbox in step 4 is what provides real containment. For that reason:
- `warn` findings go in the report and the pipeline continues.
- `block` findings stop the pipeline before execution (`status` is `fail`, `data.needs_user_decision` is true). Show them to the user and let the user decide. Never override one yourself.
- If the user explicitly approves a specific finding, re-run with `--approve FILE:LINE` for that finding only. Approving one finding never approves the others.

### 4. Sandboxed dry-run

Run the code with `run_sandboxed.py --stage <dir> --cmd "<command>"`. It picks the strongest tier available (override with `--tier`), runs the command without a shell unless you pass `--shell`, and refuses any directory that `stage_workspace.py` did not create, so it cannot be pointed at the real project.

- **Tier A, Docker:** real isolation. `--network none`, read-only root filesystem, all capabilities dropped, memory/CPU/PID limits, non-root user. Only the stage is writable; linked dependency folders are mounted read-only. The image must already be pulled, because the run stays offline.
- **Tier B, hardened subprocess:** damage limiting, not a hard boundary. Host API keys and tokens never reach the code (an allow-listed environment, with HOME and TMPDIR pointing at a throwaway directory). A wall-clock timeout, CPU and file-size limits, and a watchdog that kills the whole process group for excess memory or processes. It does not restrict reads or writes outside the stage, so say so in the report, and prefer Tier A for code you do not trust.
- **Tier C, nothing safe available:** the stage is `skipped`, never passed.

Read these fields of the result, not just `status`:
- `data.network_block`: how the network was blocked. A network namespace is solid. The fallback shims only cover Python and Node, and the report must say which was used.
- `data.killed_for`: `timeout`, `memory`, or `processes` when a limit stopped the run.
- `data.fs_changes`: files the run created or modified inside the stage.
- `data.stdout_tail` / `data.stderr_tail`: the end of the output (the full output is capped, `data.output_truncated` says when it was).

The network is blocked in every tier. Code that needs a service must be given a stub, and the report should say a stub was used. Install dependencies before this stage, never inside it. This is also where ESLint runs (`--cmd "npx eslint <files>"`), because its config is executable code.

### 5. Targeted tests and edge cases

Run `run_tests.py --stage <dir>`. It selects the tests that cover the change and runs only those through the sandbox. A test covers a file when it is that file, is named after it (`test_x.py`, `x.test.ts`), or imports it. Selection looks one level deep, so a test of something that merely imports the changed file is not selected. Read `data.tests_selected` and `data.uncovered_files` to see exactly what was and was not covered.

Then it probes edge cases. This works for Python only in this version. Public functions are called with boundary inputs (`""`, `0`, `-1`, `2**63`, `nan`, `inf`, `[]`, and `None` where the signature allows). It uses hypothesis when installed and the parameters are annotated, otherwise a fixed table. Only programming errors (TypeError, IndexError, ZeroDivisionError and similar) and hangs count; a ValueError is treated as correct validation.
- `--edge-cases warn` (default): findings are reported but never fail the stage.
- `--edge-cases strict`: a crash on an input the annotation says is valid fails the stage.
- `--edge-cases off`: skip probes.

TypeScript and JavaScript get tests but no probes yet; that shows up in `data.skipped_checks`.

If no test covers the changed code, the stage is `skipped`, not passed, and the verdict cannot be `VERIFIED`. Say so plainly and offer to write a test. Do the same for any other entry in `data.skipped_checks`.

### 6. Self-healing loop

When a stage fails, save its JSON report and run:

```
diagnostics.py --report <file> [--report <file> ...] --stage <dir> --attempt N [--previous <last diagnostics.json>] --format prompt
```

It picks the earliest failing stage, names the file, line, and error with a code excerpt, and ends with an `ACTION:` that you follow:
- **fix:** make the smallest change that resolves the first error, restage it with `stage_workspace.py`, and re-verify from step 2.
- **ask_user:** the safety scan blocked something. Show it to the user and wait; never work around it.
- **environment:** a tool, image, or config is missing. Editing code will not help; tell the user.
- **stop:** the budget of **3 attempts** is spent. Stop patching and report what failed, what you tried, and your best theory.

Pass `--previous` with the last run's diagnostics output. If the same error comes back, the prompt says so, and you should form a different theory instead of repeating the patch.

### 7. Merge

Run `merge_stage.py --stage <dir> --verdict VERIFIED`. For `PARTIAL`, first tell the user which stages were skipped, then add `--acknowledge-partial`. A `FAILED` verdict is refused.

The merge copies only the files in the manifest. It writes nothing, and says why, if a real file changed since staging (re-stage on top of the current version) or a staged file changed after verification (re-stage and re-verify). Originals are backed up next to the stage, each file is replaced atomically, and a failure part-way undoes itself. Use `--dry-run` to preview. `--rollback` undoes a merge, and refuses if the user has edited those files since.

## Verdicts

Report one of these, never a bare "looks good":

- **VERIFIED:** every stage ran and passed.
- **PARTIAL:** passed, but one or more stages were skipped (no tests found, no sandbox tier, tool missing). Name each skipped stage and why.
- **FAILED:** a stage failed and the retry budget is spent or the user stopped the loop. Include the stage, file, line, and trace.

The distinction matters because a skipped stage is not a passed stage. "PARTIAL: no tests cover this file" tells the user something true, while "verified" would not.

## Report format

End every run with:

```
Verdict: VERIFIED | PARTIAL | FAILED
Tier: A (Docker) | B (subprocess) | C (static-only)
Stages: static ✅  deps ✅  safety ✅  dry-run ✅  tests ⚠️ skipped (no covering tests)
Attempts: 1 of 3
Merged: yes | no
```

## Reference files

Open these only when you need them. Each is short, and none is required for a routine pass.

- `references/typescript.md`: read when the change includes TypeScript, JavaScript, or a `package.json`. It covers how `tsc` configuration errors are handled, how imports are resolved, which patterns the safety scan blocks, which test runners are supported, and the usual fix for each failure.
- `references/python.md`: read when the change includes Python or a dependency manifest. It covers which checks run, how imports and dependencies are matched (including the alias table), the safety patterns, test selection, and exactly how the edge-case probes choose inputs and what they count.
- `references/sandbox-tiers.md`: read before reporting a dry-run or test result, when a run was killed or the network behaved oddly, or when the user asks how strong the isolation was. It states what each tier guarantees, and what Tier B does not.

If a result surprises you, check the relevant file before guessing at the cause.
