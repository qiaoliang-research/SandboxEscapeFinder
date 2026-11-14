# SandboxEscapeFinder — STAR Task 6

Static + dynamic escape finder for Python execution sandboxes.
Task: [STAR-Computing/ProgrammingTask, Task 6](https://github.com/STAR-Computing/ProgrammingTask/blob/master/06_sandbox_escape_finder.md).
Target sandbox: [RestrictedPython](https://github.com/zopefoundation/RestrictedPython) (tested with v9.0, Python 3.12).

**Headline result: 15 attack payloads, all statically flagged, 0 escapes.**
14 are rejected by RestrictedPython at compile time; the 15th (a format-string
attack) is refused at runtime by the `safer_getattr` guard. Both benign
controls run cleanly. The interesting finding is not that the sandbox held —
it is *where* each layer stops each attack, and the one place the static
analyzer was blind until testing exposed it (see X03 below).

## Install

```bash
python -m venv .venv
.venv/bin/pip install -e .
```

Only dependency: `RestrictedPython`. Tests use the standard library only.

## Usage

The exact public API from the task description:

```python
from sandbox_escape_finder import StaticAnalyzer, DynamicProber

analyzer = StaticAnalyzer(config)
findings = analyzer.scan(source_code)

prober = DynamicProber(sandbox_exec, oracle, config)
report = prober.run(payload_corpus)
```

- `config`: dict / JSON — `enabled` technique list (empty = all on),
  `extra_payloads` (custom payloads, see below), `seed`.
- `findings`: one dict per match — `technique`, `lineno`, `col_offset`,
  `node`, `snippet` (the offending AST node's source).
- `sandbox_exec`: `code: str -> result` — a thin wrapper around a real
  RestrictedPython compile-and-exec setup (see `examples/quickstart.py`).
- `oracle`: `(pre_state, exec_result, post_state) -> bool` — True means an
  out-of-sandbox effect happened.
- `report`: per payload — `static_flagged`, `executed`, `escaped`, `error`,
  `elapsed_ms`.

Run the full corpus against a live sandbox:

```bash
python examples/quickstart.py
python -m unittest discover -s tests   # 8 tests
```

## Layout (and why it is organized this way)

```
src/sandbox_escape_finder/
  analyzer.py   StaticAnalyzer — one short detector function per technique
  corpus.py     PAYLOADS (12 catalog + 2 benign) + CUSTOM_PAYLOADS + load_corpus()
  prober.py     DynamicProber — runs payloads, asks the oracle, builds the report
examples/quickstart.py   sandbox setup, subprocess worker, results table
tests/test_analyzer.py   detector + oracle + end-to-end tests
```

The prober never decides what an escape *is*: `sandbox_exec` and `oracle`
are injected by the caller, so the same prober can test a different sandbox
or a stricter oracle without changing its code. The analyzer is likewise
independent — it only reads source, never executes it. That separation is
what makes the false-positive / false-negative comparison meaningful: the
two halves can disagree, and the report shows exactly where.

## Detected technique classes

All detectors work on the AST, not on regex. Each finding cites the
technique name and the offending node's source location.

| # | Technique | What it catches | Why RestrictedPython stops it |
| --- | --- | --- | --- |
| 1 | `subclasses_traversal` | `__subclasses__()` chains reaching for a dangerous class | Compile-time `SyntaxError`: `"__subclasses__"` is an invalid attribute name (starts with `_`) |
| 2 | `dunder_class_access` | `__class__` / `__bases__` / `__mro__` access | Compile-time `SyntaxError`: underscore attribute name |
| 3 | `globals_closure_access` | `__globals__` / `__closure__` / `__code__` access | Compile-time `SyntaxError`: underscore attribute name |
| 4 | `builtins_restoration` | `__builtins__` / `__import__` access | Compile-time `SyntaxError`: underscore variable name |
| 5 | `dynamic_exec` | `eval()` / `exec()` / `compile()` calls | Compile-time `SyntaxError`: "Eval calls are not allowed" / "Exec calls are not allowed" |
| 6 | `frame_introspection` | `sys._getframe`, `inspect.currentframe`, `f_locals` / `f_globals` | Compile-time `SyntaxError`: `"f_locals"` is a restricted name |
| 7 | `format_string_access` | Dunder paths inside a `str.format()` template, e.g. `"{0.__class__}".format("")` | **Runtime** `NotImplementedError`: `safer_getattr` refuses `str.format` outright |

Technique 7 deserves a note. A format string carries its attribute path
inside a string literal, so no AST `Attribute` node exists for detectors
1–3 to see — the first version of this analyzer missed X03 entirely. The
detector parses the template with `string.Formatter().parse()` (real
parsing, not substring search) and flags dunder components of any field
name. Even so, the sandbox would have stopped the payload anyway: that is
defense in depth, and the test suite pins both layers
(`test_format_string_detector_needs_a_dunder`,
`test_format_string_payload_blocked_at_runtime_not_compile_time`).

## Oracle design and isolation

- **Oracle**: a canary file in a throwaway temp directory. `escaped` is
  True only if the canary was created or modified during the run. It is a
  plain callable the caller supplies, so a test suite can assert on it —
  no manual inspection anywhere in the loop.
- **Isolation**: the quickstart runs the whole probe in a child process
  (`--probe-worker` mode); the parent only builds the corpus and prints
  the report. The canary points at a temp directory that is deleted when
  the parent exits. A genuine escape could therefore affect neither the
  parent process nor the host.
- **Oracle sanity check**: the test suite runs the same canary payload
  against an intentionally broken toy sandbox (plain `exec` with full
  builtins) and asserts the oracle fires — proving the oracle *can*
  detect an escape, so the 0-escape result against RestrictedPython is
  evidence about the sandbox, not about a dead oracle.

## Results

`python examples/quickstart.py` (RestrictedPython 9.0, Python 3.12).
`ran = False` means the sandbox *refused* the payload — for 14 payloads
at compile time, for X03 at runtime — not that the prober failed.

| id | technique | static | ran | escaped | blocked by |
| --- | --- | --- | --- | --- | --- |
| P01 | subclasses_traversal | yes | no | no | compile-time: `__subclasses__` invalid attribute |
| P02 | subclasses_traversal | yes | no | no | compile-time: `__builtins__` invalid attribute |
| P03 | globals_closure_access | yes | no | no | compile-time: `__globals__` invalid attribute |
| P04 | globals_closure_access | yes | no | no | compile-time: `__closure__` invalid attribute |
| P05 | builtins_restoration | yes | no | no | compile-time: `__builtins__` invalid variable name |
| P06 | builtins_restoration | yes | no | no | compile-time: `__import__` invalid variable name |
| P07 | dynamic_exec | yes | no | no | compile-time: eval not allowed |
| P08 | dynamic_exec | yes | no | no | compile-time: exec not allowed |
| P09 | frame_introspection | yes | no | no | compile-time: `f_locals` restricted name |
| P10 | frame_introspection | yes | no | no | compile-time: `f_locals` restricted name |
| P11 | dunder_class_access | yes | no | no | compile-time: `__mro__` invalid attribute |
| P12 | dunder_class_access | yes | no | no | compile-time: `__bases__` invalid attribute |
| C01 | benign | no | yes | no | — (ran cleanly) |
| C02 | benign | no | yes | no | — (ran cleanly) |
| X01 | subclasses_traversal | yes | no | no | compile-time: `__subclasses__` invalid attribute |
| X02 | globals_closure_access | yes | no | no | compile-time: `__code__` invalid attribute |
| X03 | format_string_access | yes | no | no | runtime: `str.format` refused (`NotImplementedError`) |

Payload sources: P01–P12 are seeded from the two catalogs named in the
task ([pyjailbreaker](https://github.com/jailctf/pyjailbreaker),
[python_sandbox_escapes](https://github.com/moshekaplan/python_sandbox_escapes))
and the chain quoted in the task statement; X01–X03 are custom payloads
written for this submission (see `corpus.py`).

### False-positive / false-negative analysis (required)

- **Flagged but did not escape: 15.** Every attack payload. This is the
  expected outcome, not a defect: the analyzer flags *attempts*, and the
  sandbox blocks all of them. A flag means "this looks like an escape
  technique", not "this escaped".
- **Escaped but not flagged: 0.** Nothing escaped at all, so there is no
  missed escape to report.
- **Benign controls: 0 false positives**, and both ran — the sandbox lets
  normal code through, so the blocks above are about the payloads, not
  about a sandbox that refuses everything. (C01 deliberately avoids
  `sum`, which is not in `safe_builtins` — an unrelated failure would
  have muddied the control.)

## Limitations (what this does not prove)

- The oracle detects **filesystem escape only** (canary write). A payload
  that exfiltrated information without writing a file would not trip it.
  The claim is therefore scoped: *no filesystem escape was observed* —
  not "the sandbox is unbreakable".
- Static analysis is syntactic. A computed attribute name (e.g. building
  `"__cl" + "ass__"` at runtime) would evade the AST detectors. `getattr`
  is not available inside this sandbox, so the gap does not matter here —
  but the analyzer alone should not be trusted as a sandbox.
- Results are for RestrictedPython 9.0's default guards. A deployment
  that adds `getattr`, `__import__`, or a custom `_getattr_` would need
  re-testing; that is exactly what `sandbox_exec` injection is for.

## Extending

- **New technique**: add a detector branch in `analyzer.py`, a
  positive/negative pair in `tests/test_analyzer.py`, and a payload.
- **New sandbox**: write a `sandbox_exec` + `oracle` pair and pass them
  to `DynamicProber` — no prober changes needed.
- **New payloads**: pass them through config, no code changes:
  `load_corpus({"extra_payloads": [{"id": "X04", "technique": "...",
  "code": "..."}]})`.
