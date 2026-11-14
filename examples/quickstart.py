"""Quickstart for SandboxEscapeFinder (Task 6).

Runs the static analyzer over the payload corpus, then the dynamic
prober against a real RestrictedPython sandbox, and prints the
payload x technique x static-flag x dynamic-escape table the task
requires for the README.

Two processes, on purpose. The dynamic probe runs in a child process
(`--probe-worker` mode below): the parent only builds the corpus and
prints the report, so even a payload that genuinely escaped could not
touch the parent. The canary file lives in a throwaway temp directory
that is deleted when the parent exits.

Sandbox setup (RestrictedPython's documented pattern, v9.0):
  * compile_restricted() compiles the payload with guarded attribute
    access — underscore attributes, eval/exec calls and restricted
    names (f_locals, ...) are rejected at COMPILE time with SyntaxError.
  * The sandbox gets a minimal __builtins__ (safe_builtins: no open,
    eval, exec, __import__, getattr) plus the documented guards:
    _print_ (PrintCollector), _getattr_ (safer_getattr — which also
    refuses str.format outright, the runtime backstop for X03),
    _getitem_ and _getiter_.
  * The oracle watches a canary file in the temp directory:
    escape = the canary was created/modified after the run.

Run:  python examples/quickstart.py   (from the project root, after
        pip install -e . — RestrictedPython is the only dependency)
"""

import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from RestrictedPython import compile_restricted, safe_builtins  # noqa: E402
from RestrictedPython.Guards import safer_getattr  # noqa: E402
from RestrictedPython.PrintCollector import PrintCollector  # noqa: E402

from sandbox_escape_finder import (  # noqa: E402
    CUSTOM_PAYLOADS,
    DynamicProber,
    StaticAnalyzer,
    load_corpus,
)

CANARY_NAME = "canary_outside_sandbox.txt"
WORKER_TIMEOUT_SECONDS = 120


def make_sandbox_exec(canary_dir):
    """Return a sandbox_exec callable closing over its own temp dir."""
    canary_path = os.path.join(canary_dir, CANARY_NAME)

    def sandbox_exec(code):
        # RestrictedPython compile: underscore names, eval/exec and
        # restricted names are rejected here, before anything runs.
        byte_code = compile_restricted(code, "<payload>", "exec")
        restricted_globals = {
            "__builtins__": safe_builtins,
            "_print_": PrintCollector,
            "_getattr_": safer_getattr,
            "_getitem_": lambda obj, key: obj[key],
            "_getiter_": lambda it: iter(it),
        }
        local_vars = {}
        exec(byte_code, restricted_globals, local_vars)  # noqa: S102 - inside sandbox
        return local_vars

    sandbox_exec.canary_path = canary_path
    return sandbox_exec


def make_oracle(canary_path):
    def oracle(pre_state, exec_result, post_state):
        # Escape = the canary file outside the allowed directory appeared
        # or changed. RestrictedPython payloads should never manage this.
        return os.path.exists(canary_path)

    return oracle


def probe_worker(canary_dir, corpus_path):
    """Child-process entry point: run the probe, print the report as JSON.

    Nothing else may print to stdout here — the parent parses it.
    """
    with open(corpus_path, encoding="utf-8") as f:
        corpus = json.load(f)
    config = {"seed": 0}
    analyzer = StaticAnalyzer(config)
    sandbox_exec = make_sandbox_exec(canary_dir)
    prober = DynamicProber(
        sandbox_exec, make_oracle(sandbox_exec.canary_path), config, analyzer
    )
    print(json.dumps(prober.run(corpus)))


def run_probe_in_subprocess(canary_dir, corpus):
    """Spawn the worker, return its parsed report (or exit honestly)."""
    corpus_path = os.path.join(canary_dir, "corpus.json")
    with open(corpus_path, "w", encoding="utf-8") as f:
        json.dump(corpus, f)
    try:
        proc = subprocess.run(
            [sys.executable, __file__, "--probe-worker", canary_dir, corpus_path],
            capture_output=True,
            text=True,
            timeout=WORKER_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        print(f"worker timed out after {WORKER_TIMEOUT_SECONDS}s — no report")
        sys.exit(1)
    if proc.returncode != 0:
        print("worker failed; its stderr (truncated):")
        print(proc.stderr[-2000:])
        sys.exit(1)
    return json.loads(proc.stdout)


def short_error(row, width=64):
    if row["executed"] or not row["error"]:
        return ""
    err = row["error"]
    # RestrictedPython SyntaxErrors stringify as tuples of messages —
    # unwrap to the first readable message for the table.
    if err.startswith("SyntaxError: ("):
        inner = err[len("SyntaxError: ("):]
        if inner.startswith("'"):
            end = inner.find("',")
            if end == -1:
                end = inner.find("')")
            if end != -1:
                return ("SyntaxError: " + inner[1:end])[:width]
    return err.split("\n")[0][:width]


def main():
    config = {"seed": 0, "extra_payloads": CUSTOM_PAYLOADS}
    corpus = load_corpus(config)
    with tempfile.TemporaryDirectory(prefix="sandbox_escape_finder_") as tmp:
        report = run_probe_in_subprocess(tmp, corpus)
    print(f"{'id':<5}{'technique':<24}{'static':<8}{'ran':<6}{'escaped':<9}blocked by")
    for row in report:
        print(
            f"{row['id']:<5}{row['technique']:<24}"
            f"{str(row['static_flagged']):<8}{str(row['executed']):<6}"
            f"{str(row['escaped']):<9}{short_error(row)}"
        )
    flagged_not_escaped = [r for r in report if r["static_flagged"] and not r["escaped"]]
    escaped_not_flagged = [r for r in report if r["escaped"] and not r["static_flagged"]]
    benign_ran = [
        r for r in report if r["technique"] == "benign" and r["executed"]
    ]
    print(f"\nflagged but did not escape: {len(flagged_not_escaped)}")
    print(f"escaped but not flagged: {len(escaped_not_flagged)}")
    print(f"benign controls that ran cleanly: {len(benign_ran)}/2")
    print("canary: temp dir only, deleted with the TemporaryDirectory")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--probe-worker":
        probe_worker(sys.argv[2], sys.argv[3])
    else:
        main()
