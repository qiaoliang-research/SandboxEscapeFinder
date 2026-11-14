"""Dynamic prober for SandboxEscapeFinder (Task 6).

The prober does NOT decide what an escape is — the caller supplies:
  * sandbox_exec: code (str) -> result. A thin wrapper around a real
    RestrictedPython compile-and-exec setup (see examples/quickstart.py).
  * oracle: (pre_state, exec_result, post_state) -> bool. True = an
    out-of-sandbox effect happened (e.g. the canary file outside the
    allowed directory was created, a forbidden module was used).

Isolation: run() itself executes payloads only through sandbox_exec, and
never touches the host filesystem directly. The quickstart (see
examples/quickstart.py) runs the whole probe in a child process, with the
canary pointed at a throwaway temp directory, so a genuine escape cannot
touch the parent process or the host. Never point the oracle's canary at a
real system path.
"""

import time


class DynamicProber:
    def __init__(self, sandbox_exec, oracle, config=None, analyzer=None):
        self.sandbox_exec = sandbox_exec
        self.oracle = oracle
        self.config = config or {}
        self.analyzer = analyzer  # optional StaticAnalyzer, for the FP/FN table

    def run(self, payload_corpus):
        """Return list[dict] per payload: static flag, executed, escaped, timing."""
        report = []
        for payload in payload_corpus:
            code = payload["code"]
            static_flagged = None
            if self.analyzer is not None:
                static_flagged = bool(self.analyzer.scan(code))
            pre_state = self._snapshot()
            started = time.perf_counter()
            try:
                result = self.sandbox_exec(code)
                executed = True
                error = None
            except Exception as exc:  # noqa: BLE001 - record, don't crash the run
                result, executed, error = None, False, f"{type(exc).__name__}: {exc}"
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
            post_state = self._snapshot()
            escaped = bool(self.oracle(pre_state, result, post_state))
            report.append(
                {
                    "id": payload["id"],
                    "technique": payload["technique"],
                    "static_flagged": static_flagged,
                    "executed": executed,
                    "escaped": escaped,
                    "error": error,
                    "elapsed_ms": elapsed_ms,
                }
            )
        return report

    def _snapshot(self):
        # The oracle in quickstart.py reads the canary file itself; the
        # snapshot hook is here so a stricter oracle can compare pre/post.
        return None
