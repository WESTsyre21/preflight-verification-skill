# Python reference

Read this when the change set contains `.py` files, `requirements*.txt`, `pyproject.toml`, or a `Pipfile`. It explains what each stage does for Python, what its output means, and the usual fix when it fails.

## Static analysis (`static_check.py`)

Three checks run, in this order:

1. **`ast.parse` (always).** Syntax errors are reported with line and column. Parsing happens in-process, so no `.pyc` is written and no import runs. A file that does not parse is excluded from the next two checks, because they would only repeat the error.
2. **ruff, fatal rules only.** It runs with `--isolated --select E9,F63,F7,F82`: syntax errors, invalid comparisons, and **undefined names**. The project's own ruff config is deliberately ignored, so style rules never fail a verification.
3. **pyright.** It uses the project's `.venv`/`venv` interpreter (`--pythonpath`) when the stage has one. Pyright errors fail the stage; warnings are reported as warnings.

If ruff or pyright is not installed, that check is listed in `data.skipped_checks` and the verdict becomes `PARTIAL`. Installing it (`pip install ruff pyright`) must happen before verification, because the sandbox has no network.

Pyright also reports unresolved imports (`reportMissingImports`), which overlaps with `dep_check.py`. When both fire for the same import, `dep_check.py`'s message is the more useful one, since it says whether the package exists.

## Import and dependency checks (`dep_check.py`)

Python is analysed with the real AST, and imports are classified in this order:

1. **Standard library** (`sys.stdlib_module_names`) and `__future__`: always fine.
2. **Local module.** It resolves against the importing file's directory, every ancestor directory up to the project root, and `src/`. A module is `name.py`, `name/__init__.py`, or a bare directory (namespace package).
3. **Third-party.** It is accepted if the top-level name matches a declared distribution, in any of these ways:
   - the normalised name matches (`-`, `_`, `.` are equivalent, case ignored);
   - the alias table maps it: `yaml`→`pyyaml`, `PIL`→`pillow`, `cv2`→`opencv-python`, `sklearn`→`scikit-learn`, `bs4`→`beautifulsoup4`, `dateutil`→`python-dateutil`, `dotenv`→`python-dotenv`, `jwt`→`pyjwt`, `attr`→`attrs`, `serial`→`pyserial`, `OpenSSL`→`pyopenssl`, `Crypto`→`pycryptodome`, `git`→`gitpython`, `MySQLdb`→`mysqlclient`, `magic`→`python-magic`, `docx`→`python-docx`, `pptx`→`python-pptx`, `fitz`→`pymupdf`, `skimage`→`scikit-image`, `zmq`→`pyzmq`, `psycopg2`→`psycopg2-binary`, `markdown`→`markdown`, `gi`→`pygobject`, `usb`→`pyusb`;
   - the project's interpreter reports (via `packages_distributions`) that an installed distribution provides that import name.

**Where declarations are read from**, in each changed file's directory and every parent: `requirements*.txt` (following `-r` includes), `requirements/*.txt`, `pyproject.toml` (`[project]` dependencies and optional dependencies, `dependency-groups`, `[tool.uv]`, `[tool.pdm]`, `[tool.poetry]` including groups), and `Pipfile`. Reading TOML needs Python 3.11+ (or `tomli`). Without it the check degrades to warnings and says so.

Outcomes:

| Code | Severity | Meaning |
|---|---|---|
| `unresolved-import` | error | not stdlib, not local, not declared, not installed |
| `hallucinated-package` | error | with `--check-registry`: PyPI returns 404, so the package does not exist |
| `undeclared-dependency` | error with `--check-registry` if it exists on PyPI; otherwise warn when merely installed | add it to `requirements.txt` or `pyproject.toml` |
| `optional-import-missing` | warn | the import sits inside `try/except ImportError` and is not installed |
| `declared-not-installed` | warn (one summary) | declared, so the import is fine, but the sandbox cannot import it until it is installed |
| `unresolved-local-module` | error | the package exists locally but has no such submodule |
| `missing-export` | error | `from pkg.mod import name` where `mod` defines no `name` |
| `bad-call` | error | a call that cannot match the function's signature |

Imports inside `try/except ImportError` and `if TYPE_CHECKING:` are **guarded**, so a failure there is a warning, not an error.

**Name and signature checks** apply to local modules only. A module that uses `from x import *` or defines `__getattr__` is treated as dynamic and skipped.

The call check is deliberately conservative so it produces no false alarms. It applies only to **undecorated, module-level functions bound exactly once** in the file. It is skipped when the call uses `*args` or `**kwargs`, and when the name is rebound anywhere in the file. It reports too many positional arguments, an unexpected or duplicated keyword, a positional-only misuse, and missing required arguments.

## Safety scan (`safety_scan.py`)

Python uses the AST, with import aliases resolved (`import subprocess as sp`, `from os import system`). Docstrings are skipped, so a docstring that mentions `curl | sh` is not flagged.

| Pattern | Severity |
|---|---|
| `eval(x)` / `exec(x)` with a non-literal argument | **block** |
| `os.system`, `os.popen`, `subprocess.getoutput` with a non-literal command | **block** |
| `subprocess.*` with `shell=True` and a non-literal command | **block** |
| `shutil.rmtree`, `os.remove`, `os.unlink`, `os.rmdir` on `/`, `~`, `$HOME`, `..`, or a system directory | **block** |
| `open(path, "w"/"a"/"x")`, or `shutil.copy`/`move`/`os.rename` to a system path | **block** |
| credential paths (`.ssh`, `id_rsa`, `.aws/credentials`, `.kube/config`, `/etc/shadow`) together with a network call | **block** |
| `curl ... \| sh`, `rm -rf /`, fork bomb, `mkfs`, `dd of=/dev/...` in any string | **block** |
| literal `os.system("...")`, `subprocess.run([...])`, `eval("1+1")` | warn |
| `pickle.load(s)`, `marshal.load(s)`, `yaml.load` without a safe loader, `shelve.open` | warn |
| `importlib.import_module(var)`, `__import__(var)`, `ctypes.CDLL` | warn |
| `dict(os.environ)`, `os.environ.items()`, `.copy()` | warn |
| `requests`, `httpx`, `aiohttp`, `urllib.request`, `socket`, `smtplib`, `paramiko` and similar | warn (the sandbox blocks the network anyway) |
| `Path.unlink()`, `.rmdir()` | warn |
| writes to other absolute paths outside `/tmp` | warn |

A heuristic filter, not a boundary. A clean scan proves nothing.

## Tests (`run_tests.py`)

- **Which files are tests:** `test_*.py` and `*_test.py`.
- **Which tests cover a change:** the changed file if it is a test, a test named `test_<module>.py` / `<module>_test.py`, or a test that **imports** the module. Absolute imports match on the dotted name (`pkg.util`, `util`, and `from pkg import util`), and relative imports match on the resolved path. Selection is one level deep. The result lists `data.tests_selected` and `data.uncovered_files` so you can see what was and was not covered.
- **Runner:** `python3 -m pytest -q -rfE --tb=short -p no:cacheprovider <files>` when pytest is importable, otherwise `python3 -m unittest -v <modules>`. unittest finds only `unittest.TestCase` tests, so plain `assert` tests under unittest collect 0 tests and the stage is `skipped`, never passed.
- **Interpreter:** `python3` resolves through the sandbox `PATH`, where the stage's `.venv/bin` or `venv/bin` comes first when present.
- **No covering tests:** the stage is `skipped` and the verdict cannot be `VERIFIED`. Say so, and offer to write one.

## Edge-case probes (`run_tests.py --edge-cases`)

After the tests, public functions in the changed files are called with boundary inputs, **inside the sandbox**.

**Which functions are probed:** top-level, undecorated, non-async, non-generator functions that do not start with `_`, are not named `main`, and have 1 to 5 positional parameters (no positional-only; keyword-only parameters must have defaults). Test files, `__init__.py`, `conftest.py`, and `setup.py` are not probed.

**How inputs are chosen:**
- With **hypothesis installed and every parameter annotated**, hypothesis generates up to 60 examples per function (derandomised, so reruns agree) and reports the shrunk, minimal failing example: `first_char('')`, `half(0)`.
- Otherwise a **fixed table** varies one parameter at a time against a baseline, up to 40 calls per function:
  - `str`: `""`, `" "`, 10,000 characters, non-ASCII, `"0"`, `"\n"`
  - `int`: `0`, `-1`, `1`, `2**31`, `2**63`, `-2**63`
  - `float`: `0.0`, `-0.0`, `nan`, `inf`, `-inf`, `1e308`, `-1.5`
  - `bool`, `list`, `dict`, `tuple`, `bytes`: empty and minimal values
  - `Optional[X]` adds `None`; an unannotated parameter tries `None`, `0`, `-1`, `""`, `[]`, `{}`
- If a function crashes even on ordinary input, it is skipped with a note, because its preconditions cannot be guessed and probing would only add noise. A note is also recorded whenever hypothesis could not run for a function and the table was used instead.

**What counts:** `TypeError`, `AttributeError`, `IndexError`, `KeyError`, `ZeroDivisionError`, `RecursionError`, `UnboundLocalError`, `NameError`, and a call that does not return within **1 second**. A `ValueError` or `SystemExit` is treated as correct validation.

**Severity:**

| Code | Meaning | `warn` mode | `strict` mode |
|---|---|---|---|
| `edge-case-crash` | crashed on an input its **annotation allows** | warn | **error** |
| `edge-case-fragile` | crashed on an input for an **unannotated** parameter | warn | warn |
| `edge-case-hang` | no result within 1 second | warn | warn |

The default is `warn` because a crash on an unusual input is often a deliberate precondition. Treat each finding as a question to the author. The usual fixes are to handle the input (guard the empty string or zero) or to tighten the annotation so it no longer promises what the function cannot do. Use `strict` when the user wants edge cases to gate the merge.

## Typical failures and the right response

| You see | Meaning | Do this |
|---|---|---|
| `hallucinated-package` | PyPI says it does not exist | remove the import; do not add it to `requirements.txt` |
| `undeclared-dependency` | real package, not declared | add it to the manifest; the user must install it |
| `missing-export` | the name is not defined in the local module | check for a typo or a renamed function; do not invent the name |
| `bad-call` | wrong argument count or keyword | read the function's signature and fix the call |
| ruff `F821` | undefined name | a missing import, a typo, or a variable used before assignment |
| pyright `reportAttributeAccessIssue` | the attribute does not exist on that type | fix the type or the attribute name |
| `skipped_checks: ruff / pyright` | tool not installed | report it; the verdict is `PARTIAL` |
| `declared-not-installed` | dependencies are not installed in the environment | tell the user to install them; the sandbox cannot |

## Staging note

`.venv` and `venv` are **linked** into the stage, not copied, so running code can still read them. Use `--copy-deps` for a full copy, or Tier A, which mounts them read-only. When using Tier A with a host virtualenv, the Docker image's Python version must match the virtualenv's, because its `site-packages` is added to `PYTHONPATH`. See `sandbox-tiers.md`.
