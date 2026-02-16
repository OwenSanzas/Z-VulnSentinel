"""Fuzzer entry parser — extracts library function calls from fuzzer source code.

Uses tree-sitter for C/C++ parsing. Fuzzer harness code is typically simple
(direct calls, no function pointers), so tree-sitter precision is sufficient.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Try tree-sitter, fall back to regex
_USE_TREE_SITTER = False
try:
    import tree_sitter_c as tsc
    from tree_sitter import Language, Parser

    _C_LANGUAGE = Language(tsc.language())
    _USE_TREE_SITTER = True
except ImportError:
    logger.info("tree-sitter-c not available, using regex-based parsing")

# Regex fallback: match function calls like `func_name(...)` or `func_name (`
_CALL_RE = re.compile(r"\b([a-zA-Z_]\w*)\s*\(")
# Regex for function definitions: `type func_name(...)  {`
_FUNC_DEF_RE = re.compile(
    r"^[a-zA-Z_][\w\s\*]*?\b([a-zA-Z_]\w*)\s*\([^)]*\)\s*\{",
    re.MULTILINE,
)


class FuzzerEntryParser:
    """
    Parse fuzzer source files to extract library function calls.

    For each fuzzer, identifies which library functions are called from
    LLVMFuzzerTestOneInput and its helper functions (recursive expansion).
    """

    def parse(
        self,
        fuzzer_sources: dict[str, list[str]],
        library_functions: set[str],
        project_path: str,
    ) -> dict[str, list[str]]:
        """
        Parse all fuzzer sources and return library function calls.

        Args:
            fuzzer_sources: {fuzzer_name: [source_files]} from work order.
            library_functions: Set of all library function names (from SVF).
            project_path: Project root for resolving relative paths.

        Returns:
            {fuzzer_name: [called_library_function_names]}
        """
        result: dict[str, list[str]] = {}
        root = Path(project_path)

        for fuzzer_name, source_files in fuzzer_sources.items():
            # Collect all function definitions and calls from this fuzzer's files
            all_defs: dict[str, set[str]] = {}  # {func_name: {called_functions}}
            all_defined: set[str] = set()

            for src_file in source_files:
                src_path = root / src_file
                if not src_path.exists():
                    logger.warning("Fuzzer source not found: %s", src_path)
                    continue

                content = src_path.read_text(errors="replace")
                defs, calls = self._extract_functions_and_calls(content)

                for func_name, called in zip(defs, calls):
                    all_defs[func_name] = called
                    all_defined.add(func_name)

            # Recursively expand: start from LLVMFuzzerTestOneInput,
            # follow calls to fuzzer-internal helpers, collect library function calls
            lib_calls = self._expand_calls(
                entry="LLVMFuzzerTestOneInput",
                func_defs=all_defs,
                fuzzer_defined=all_defined,
                library_functions=library_functions,
            )

            result[fuzzer_name] = sorted(lib_calls)
            logger.info(
                "Fuzzer '%s': %d library functions called",
                fuzzer_name,
                len(lib_calls),
            )

        return result

    def _expand_calls(
        self,
        entry: str,
        func_defs: dict[str, set[str]],
        fuzzer_defined: set[str],
        library_functions: set[str],
    ) -> set[str]:
        """
        Recursively expand calls from entry function.
        Only keeps calls that are in library_functions.
        Follows calls to fuzzer-internal helpers.
        """
        lib_calls: set[str] = set()
        visited: set[str] = set()
        stack = [entry]

        while stack:
            func = stack.pop()
            if func in visited:
                continue
            visited.add(func)

            called = func_defs.get(func, set())
            for callee in called:
                if callee in library_functions:
                    lib_calls.add(callee)
                elif callee in fuzzer_defined and callee not in visited:
                    # Internal helper, follow it
                    stack.append(callee)

        return lib_calls

    def _extract_functions_and_calls(
        self, content: str
    ) -> tuple[list[str], list[set[str]]]:
        """
        Extract function definitions and their call sites.

        Returns:
            (func_names, calls_per_func) — parallel lists.
        """
        if _USE_TREE_SITTER:
            return self._extract_with_tree_sitter(content)
        return self._extract_with_regex(content)

    def _extract_with_tree_sitter(
        self, content: str
    ) -> tuple[list[str], list[set[str]]]:
        """Use tree-sitter for accurate parsing."""
        parser = Parser(_C_LANGUAGE)
        tree = parser.parse(content.encode())

        func_names: list[str] = []
        calls_per_func: list[set[str]] = []

        for node in self._walk_tree(tree.root_node):
            if node.type == "function_definition":
                name = self._get_func_name(node)
                if name:
                    calls = self._get_call_expressions(node)
                    func_names.append(name)
                    calls_per_func.append(calls)

        return func_names, calls_per_func

    def _walk_tree(self, node):
        """Yield all nodes in the tree (top-level only for function defs)."""
        yield node
        for child in node.children:
            yield from self._walk_tree(child)

    def _get_func_name(self, func_node) -> str | None:
        """Extract function name from a function_definition node."""
        declarator = func_node.child_by_field_name("declarator")
        if not declarator:
            return None

        # Navigate through pointer_declarator, parenthesized_declarator
        while declarator.type in ("pointer_declarator", "parenthesized_declarator"):
            found = False
            for child in declarator.children:
                if child.type in (
                    "function_declarator",
                    "pointer_declarator",
                    "parenthesized_declarator",
                    "identifier",
                ):
                    declarator = child
                    found = True
                    break
            if not found:
                break

        if declarator.type == "function_declarator":
            for child in declarator.children:
                if child.type == "identifier":
                    return child.text.decode()
        elif declarator.type == "identifier":
            return declarator.text.decode()

        return None

    def _get_call_expressions(self, node) -> set[str]:
        """Collect all function call names within a subtree."""
        calls: set[str] = set()
        self._collect_calls(node, calls)
        return calls

    def _collect_calls(self, node, calls: set[str]) -> None:
        if node.type == "call_expression":
            func = node.child_by_field_name("function")
            if func and func.type == "identifier":
                calls.add(func.text.decode())
        for child in node.children:
            self._collect_calls(child, calls)

    def _extract_with_regex(
        self, content: str
    ) -> tuple[list[str], list[set[str]]]:
        """Regex fallback for when tree-sitter is not available."""
        # Find function definitions and their bodies
        func_names: list[str] = []
        calls_per_func: list[set[str]] = []

        # Simple approach: split by top-level function definitions
        # Find all function definitions
        defs = list(_FUNC_DEF_RE.finditer(content))
        if not defs:
            return [], []

        for i, m in enumerate(defs):
            func_name = m.group(1)
            # Get function body using brace-counting for accurate boundary
            brace_pos = content.find("{", m.start())
            if brace_pos == -1:
                continue
            # Count braces to find matching closing brace
            depth = 1
            pos = brace_pos + 1
            limit = len(content)
            while pos < limit and depth > 0:
                ch = content[pos]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                pos += 1
            body = content[brace_pos + 1 : pos - 1]

            # Find all calls in body
            calls = set()
            for call_match in _CALL_RE.finditer(body):
                callee = call_match.group(1)
                # Filter out C keywords
                if callee not in {
                    "if",
                    "for",
                    "while",
                    "switch",
                    "return",
                    "sizeof",
                    "typeof",
                    "alignof",
                    "__attribute__",
                    "defined",
                }:
                    calls.add(callee)

            func_names.append(func_name)
            calls_per_func.append(calls)

        return func_names, calls_per_func
