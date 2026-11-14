"""Static analyzer for SandboxEscapeFinder (George Mason / Simin Chen, Task 6).

One idea per function, on purpose: Chen's README says the review will ask
you to explain every line, so each detector is a short, named check over the
AST — no regex matching, no clever one-liners.

Technique classes (each is one detector below):
  1. subclasses_traversal  — ().__class__.__bases__[0].__subclasses__()
  2. dunder_class_access   — __class__ / __bases__ / __mro__ attribute access
  3. globals_closure_access — __globals__ / __closure__ / __code__ access
  4. builtins_restoration  — __builtins__ / __import__ access
  5. dynamic_exec          — eval() / exec() / compile() calls
  6. frame_introspection   — sys._getframe, inspect.currentframe, f_locals/f_globals
  7. format_string_access  — dunder paths inside a str.format() template,
                             e.g. "{0.__class__}".format("") — no AST Attribute
                             node exists, so this detector parses the template
                             with string.Formatter instead (added after the
                             first probe run showed the other six missing X03).
"""

import ast
import string

TECHNIQUES = (
    "subclasses_traversal",
    "dunder_class_access",
    "globals_closure_access",
    "builtins_restoration",
    "dynamic_exec",
    "frame_introspection",
    "format_string_access",
)

_DUNDER_CLASS = {"__class__", "__bases__", "__mro__"}
_GLOBALS_ATTRS = {"__globals__", "__closure__", "__code__", "__func__"}
_FRAME_ATTRS = {"f_locals", "f_globals", "f_code", "__traceback__"}
# Any of these inside a format field (e.g. "{0.__class__}") is suspicious.
_FORMAT_DUNDER = (
    _DUNDER_CLASS
    | _GLOBALS_ATTRS
    | {"__subclasses__", "__builtins__", "__import__", "__base__"}
)


class StaticAnalyzer:
    """Scan Python source and return one finding per suspicious AST node."""

    def __init__(self, config=None):
        config = config or {}
        # config example: {"enabled": ["subclasses_traversal", ...], "seed": 0}
        # An empty/absent "enabled" list means: all detectors on.
        self.enabled = set(config.get("enabled") or TECHNIQUES)

    def scan(self, source_code):
        """Return list[dict]: technique, lineno, col_offset, node, snippet."""
        tree = ast.parse(source_code)
        findings = []
        for node in ast.walk(tree):
            technique = self._classify(node)
            if technique is not None and technique in self.enabled:
                findings.append(
                    {
                        "technique": technique,
                        "lineno": node.lineno,
                        "col_offset": node.col_offset,
                        "node": type(node).__name__,
                        "snippet": ast.get_source_segment(source_code, node) or "",
                    }
                )
        return findings

    def _classify(self, node):
        # Attribute access is where most escape tricks live:
        #   x.__subclasses__(), f.__globals__, obj.__class__
        if isinstance(node, ast.Attribute):
            if node.attr == "__subclasses__":
                return "subclasses_traversal"
            if node.attr in _DUNDER_CLASS:
                return "dunder_class_access"
            if node.attr in _GLOBALS_ATTRS:
                return "globals_closure_access"
            if node.attr in _FRAME_ATTRS:
                return "frame_introspection"
            if node.attr == "__builtins__":
                return "builtins_restoration"
        # Bare names: __builtins__, __import__
        if isinstance(node, ast.Name):
            if node.id in ("__builtins__", "__import__"):
                return "builtins_restoration"
        # Calls: eval/exec/compile, sys._getframe, inspect.currentframe
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in ("eval", "exec", "compile"):
                return "dynamic_exec"
            if isinstance(func, ast.Attribute):
                if func.attr in ("_getframe", "currentframe", "getframe"):
                    return "frame_introspection"
        # Format strings: "{0.__class__}".format("") carries a dunder path
        # inside a plain string, so none of the Attribute checks above can
        # see it. Parse the template properly (not a substring search) and
        # flag dunder components of any field name. Malformed templates
        # raise ValueError from parse(); they are not our concern here.
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            try:
                fields = string.Formatter().parse(node.value)
            except ValueError:
                return None
            for _, field_name, _, _ in fields:
                if not field_name:
                    continue
                parts = field_name.replace("[", ".").replace("]", "").split(".")
                if any(part in _FORMAT_DUNDER for part in parts):
                    return "format_string_access"
        return None
