"""Payload corpus for SandboxEscapeFinder (Task 6).

Each payload is attributed to the technique it exercises, as the task
requires. Sources: the two catalogs named in the task file —
github.com/jailctf/pyjailbreaker and
github.com/moshekaplan/python_sandbox_escapes — plus the classic
().__class__.__bases__[0].__subclasses__() chain the task itself quotes.

Safety note: these strings are only ever executed inside the isolated
RestrictedPython sandbox (see prober.py / examples/quickstart.py), against
a canary file in a throwaway temp directory — never against the host.
"""

PAYLOADS = [
    {
        "id": "P01",
        "technique": "subclasses_traversal",
        "source": "pyjailbreaker / task statement",
        "code": "().__class__.__bases__[0].__subclasses__()",
    },
    {
        "id": "P02",
        "technique": "subclasses_traversal",
        "source": "python_sandbox_escapes",
        "code": "[c for c in ().__class__.__bases__[0].__subclasses__() if c.__name__ == 'catch_warnings'][0]()._module.__builtins__",
    },
    {
        "id": "P03",
        "technique": "globals_closure_access",
        "source": "python_sandbox_escapes",
        "code": "(lambda: 0).__globals__",
    },
    {
        "id": "P04",
        "technique": "globals_closure_access",
        "source": "pyjailbreaker",
        "code": "(lambda x: lambda: x)(1).__closure__[0].cell_contents",
    },
    {
        "id": "P05",
        "technique": "builtins_restoration",
        "source": "python_sandbox_escapes",
        "code": "__builtins__['eval']('1+1')",
    },
    {
        "id": "P06",
        "technique": "builtins_restoration",
        "source": "pyjailbreaker",
        "code": "__import__('os').getcwd()",
    },
    {
        "id": "P07",
        "technique": "dynamic_exec",
        "source": "task statement pattern",
        "code": "eval('1 + 1')",
    },
    {
        "id": "P08",
        "technique": "dynamic_exec",
        "source": "task statement pattern",
        "code": "exec('x = 1')",
    },
    {
        "id": "P09",
        "technique": "frame_introspection",
        "source": "python_sandbox_escapes",
        "code": "import inspect\ninspect.currentframe().f_locals",
    },
    {
        "id": "P10",
        "technique": "frame_introspection",
        "source": "pyjailbreaker",
        "code": "import sys\nsys._getframe(0).f_locals",
    },
    {
        "id": "P11",
        "technique": "dunder_class_access",
        "source": "task statement pattern",
        "code": "'a'.__class__.__mro__",
    },
    {
        "id": "P12",
        "technique": "dunder_class_access",
        "source": "task statement pattern",
        "code": "().__class__.__bases__",
    },
    # Benign controls: the analyzer must NOT flag these (false-positive check),
    # and the sandbox must let them RUN (they only use safe builtins: range,
    # print; note `sum` is deliberately avoided — it is not in
    # RestrictedPython's safe_builtins, so it would fail for an unrelated reason).
    {
        "id": "C01",
        "technique": "benign",
        "source": "control",
        "code": "x = [i * 2 for i in range(5)]\ntotal = 0\nfor v in x:\n    total = total + v\nprint(total)",
    },
    {
        "id": "C02",
        "technique": "benign",
        "source": "control",
        "code": "def add(a, b):\n    return a + b\nprint(add(2, 3))",
    },
]

# Custom payloads written for this submission (not copied from the catalogs).
# They are passed in through config["extra_payloads"] (see load_corpus), which
# is also how a reviewer can add their own. Each one probes something the
# catalog payloads do not:
#   X01 — the same subclasses chain, but via __base__ (singular) instead of
#         __bases__[0]: the detector must key on __subclasses__, not on the
#         exact chain spelling.
#   X02 — __code__ object introspection (co_consts), a different member of
#         the globals/closure family than P03/P04.
#   X03 — format-string attribute access: "__class__" lives inside a string
#         literal, so no AST Attribute node exists for the dunder detectors
#         to see. The first version of this analyzer missed it; the
#         format_string_access detector was added after that run (see
#         analyzer.py). RestrictedPython blocks it anyway at runtime:
#         safer_getattr refuses str.format outright (NotImplementedError).
CUSTOM_PAYLOADS = [
    {
        "id": "X01",
        "technique": "subclasses_traversal",
        "source": "custom variant (this submission)",
        "code": "().__class__.__base__.__subclasses__()",
    },
    {
        "id": "X02",
        "technique": "globals_closure_access",
        "source": "custom variant (this submission)",
        "code": "(lambda: 0).__code__.co_consts",
    },
    {
        "id": "X03",
        "technique": "format_string_access",
        "source": "custom variant (this submission)",
        "code": '"{0.__class__.__bases__[0]}".format("")',
        "note": "Dunder path inside a format string; invisible to AST Attribute checks.",
    },
]


def load_corpus(config=None):
    """Return PAYLOADS plus any config["extra_payloads"] (validated).

    Each extra payload must be a dict with string "id", "technique" and
    "code". Anything else fails fast with a clear ValueError instead of
    breaking halfway through a probe run.
    """
    corpus = list(PAYLOADS)
    for payload in (config or {}).get("extra_payloads") or []:
        if not isinstance(payload, dict):
            raise ValueError(f"extra payload must be a dict, got {payload!r}")
        for field in ("id", "technique", "code"):
            if not isinstance(payload.get(field), str) or not payload[field]:
                raise ValueError(
                    f"extra payload needs a non-empty string {field!r}: {payload!r}"
                )
        corpus.append(payload)
    return corpus
