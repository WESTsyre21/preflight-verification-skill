# TypeScript / JavaScript reference

Read this when the change set contains `.ts`, `.tsx`, `.mts`, `.cts`, `.js`, `.jsx`, `.mjs`, or `.cjs` files, or a `package.json`. It explains what each stage does for these files, what its output means, and the usual fix when it fails.

## Static analysis (`static_check.py`)

**TypeScript** is checked with `tsc --noEmit`. The binary comes from the project's `node_modules/.bin` first, then `PATH`.
- **With a `tsconfig.json`:** each changed file is checked with the nearest `tsconfig.json` above it (`-p <tsconfig>`). In a monorepo, each package is checked with its own config.
- **Without one:** the changed files are checked together with `--strict --skipLibCheck --esModuleInterop --target es2020 --module commonjs`.
- **Project references:** a solution-style `tsconfig.json` (`references` only, no `files`/`include`) is detected and skipped. The stage walks past it to a leaf package config, or falls back to file mode, and records a `solution-tsconfig` warning so a trivial pass cannot hide type errors.

**JavaScript** (`.js`, `.mjs`, `.cjs`) gets `node --check`, which proves it parses and nothing more. `.jsx` is not checked because it needs a transform first.

**`--scope all` (default) vs `--scope changed`.** A change that deletes or renames an export breaks its importers in files you never touched, so by default a type error anywhere fails the stage. Use `--scope changed` only when the project already had errors before your change. Errors outside the changed files then become warnings.

### Configuration errors are not type errors

tsc skips type checking entirely when its options are invalid, which would otherwise let real errors hide behind a pass. The script handles it like this:
- **Deprecated option** (for example `baseUrl` under TypeScript 6): it re-runs once with the `--ignoreDeprecations` value tsc itself suggests and records a `config-deprecated` warning. The type check then runs normally.
- **Any other `TS5xxx` configuration error:** the stage fails with `type-check-blocked`, saying type checking did not run. This is an **environment** problem: `diagnostics.py` will return `ACTION: environment`. Fix the config; editing the changed code will not help.

### ESLint

ESLint is deliberately not run here, because its config file is JavaScript and running it would execute project code outside the sandbox. Run it in the sandbox stage instead, using the local binary so nothing tries to download:

```
run_sandboxed.py --stage <dir> --cmd "eslint src/a.ts src/b.ts"
```

`node_modules/.bin` is already on the sandbox `PATH`.

## Import and dependency checks (`dep_check.py`)

Imports are found by a comment-aware scanner, not a parser. It recognises `import ... from`, `export ... from`, `require("x")`, and `import("x")`. Two rules keep it honest:
- `import` and `export` statements must **start a line**. A string such as `"import x from 'y'"` is not mistaken for a real import.
- Commented-out imports are ignored. A regex literal containing a quote character can still confuse it.

How a specifier is resolved, in order:

| Specifier | Counts as resolved when |
|---|---|
| relative (`./x`, `../x`) | a file exists with an extension from `.ts .tsx .mts .cts .js .jsx .mjs .cjs .json .d.ts`, or `index.*`, or a `package.json`, in that directory. `./x.js` also matches `x.ts`/`x.tsx` (and `.mjs`→`.mts`, `.cjs`→`.cts`), because TypeScript writes the compiled extension |
| `node:fs`, `path`, `fs/promises` | it is a Node built-in |
| tsconfig `paths` alias (`@app/*`) | the prefix matches an alias. The compiler validates the target, so `tsc` is the judge here |
| `baseUrl`-relative | it resolves under a `baseUrl` |
| bare package (`lodash`, `@scope/pkg`) | it is in `dependencies`, `devDependencies`, `peerDependencies`, or `optionalDependencies` of a `package.json` above the file, is a monorepo sibling package, or its `@types/<name>` is declared |

Outcomes:
- **`unresolved-import` (error):** declared nowhere, not installed, not a local file. With `--check-registry` it becomes either `hallucinated-package` (npm returns 404: the package does not exist) or `undeclared-dependency` (it exists; add it to `package.json`).
- **`undeclared-dependency` (warn):** it is installed in `node_modules` but not declared. It works here and breaks for everyone else.
- **`declared-not-installed` (warn, one summary line):** declared but absent from `node_modules`. The imports are fine, but the dry-run and tests cannot load them. Install dependencies **before** the sandbox stage; the sandbox has no network.

## Safety scan (`safety_scan.py`)

JS/TS is scanned with patterns over the comment-stripped source. A `block` finding stops the pipeline for the user to decide.

| Pattern | Severity |
|---|---|
| `exec`/`execSync` with a non-literal command (concatenation or `${}`) | **block** (shell injection) |
| `spawn`/`execFile` with `shell: true` and a non-literal command | **block** |
| `eval(x)` / `new Function(x)` with a non-literal argument | **block** |
| `fs.rm`/`rimraf`/`unlink` on `/`, `~`, `$HOME`, `..`, or a system directory | **block** |
| `fs.writeFile`/`createWriteStream`/`rename` into `/etc`, `/usr`, `/bin`, `/var`, `/root` and similar | **block** |
| credential paths (`.ssh`, `id_rsa`, `.aws/credentials`, `.kube/config`) together with any network call | **block** (exfiltration pattern) |
| `curl ... \| sh`, `rm -rf /`, fork bombs, in any string | **block** |
| `package.json` script containing a dangerous command | **block** |
| literal `exec`, `spawn`, `eval("1+1")`, `vm.run*`, `fs.rm("dist")`, writes to other absolute paths | warn |
| `fetch`, `axios`, `XMLHttpRequest`, `http(s).request`, `net.connect`, `WebSocket`, `nodemailer` | warn (the sandbox blocks the network anyway) |
| `{ ...process.env }`, `JSON.stringify(process.env)` | warn |
| `require(variable)`, `import(variable)` | warn |
| `preinstall`, `postinstall`, `prepare` and similar hooks | warn (they run on every consumer's machine) |

Remember this is a heuristic filter, not a boundary. A clean scan proves nothing.

## Tests (`run_tests.py`)

- **Which files are tests:** `*.test.<ext>`, `*.spec.<ext>`, or anything in `__tests__/` (extensions: `js`, `jsx`, `mjs`, `cjs`, `ts`, `tsx`, `mts`, `cts`).
- **Which tests cover a change:** the changed file if it is a test, a test named after it (`a.ts` → `a.test.ts`), or a test with a **relative import** of it. Selection is one level deep.
- **Runner, in order:** `vitest` or `jest` from `node_modules/.bin`, else `node --test` **only if every selected test is `.js`, `.mjs`, or `.cjs`**.
  - `./node_modules/.bin/vitest run <files>`
  - `./node_modules/.bin/jest --ci --runTestsByPath <files>`
  - `node --test <files>`
- **TypeScript tests need vitest or jest** (with whatever transform the project already configures). With neither, the stage is `skipped` with the reason, not passed. Do not add a runner to the user's project to make the check run; tell the user what is missing.
- **No edge-case probes for JS/TS yet.** This appears in `data.skipped_checks`, which keeps the verdict at `PARTIAL`.
- A `node --test` failure is reported with its `location:` and `error:` block, and `diagnostics.py` turns that into a file, line, and assertion message.

## Typical failures and the right response

| You see | Meaning | Do this |
|---|---|---|
| `hallucinated-package` | npm says the package does not exist | remove the import or use a real library; never add it to `package.json` |
| `TS2307 Cannot find module 'x'` | the import does not resolve for tsc | check the path, or install the package and its types if it is real |
| `TS2591 Cannot find name 'require'` | Node typings are missing | the project needs `@types/node`; this is a project setup gap, so tell the user |
| `TS5xxx` / `type-check-blocked` | tsconfig is invalid for this TypeScript version | an environment problem; report it, do not patch the code |
| `unresolved-relative-import` | the relative path points at no file | fix the path or create the module |
| test runner skipped for TS | no vitest or jest installed | report it; the verdict is `PARTIAL` |

## Staging note

`node_modules` is **linked** into the stage, not copied, so running code can still read it. Use `stage_workspace.py --copy-deps` when you want a full copy, or Tier A, which mounts it read-only. Changes that touch `node_modules` are refused outright.
