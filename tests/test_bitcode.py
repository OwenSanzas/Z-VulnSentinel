"""Tests for BitcodeGenerator — unit tests for .ll parsing, no Docker needed."""

from __future__ import annotations

from pathlib import Path

from z_code_analyzer.build.bitcode import BitcodeGenerator

# Minimal LLVM IR .ll content with DISubprogram and DIFile metadata
SAMPLE_LL = """
; ModuleID = 'library.bc'
source_filename = "library.bc"

define void @foo() !dbg !10 {
  ret void
}

define i32 @bar(i32 %x) !dbg !20 {
  ret i32 %x
}

!0 = !{i32 2, !"Debug Info Version", i32 3}
!1 = !DIFile(filename: "src/foo.c", directory: "/src/myproject")
!2 = !DIFile(filename: "src/bar.c", directory: "/src/myproject")
!10 = distinct !DISubprogram(name: "foo", linkageName: "foo", scope: !1, file: !1, line: 10, type: !11)
!11 = !DISubroutineType(types: !12)
!12 = !{null}
!20 = distinct !DISubprogram(name: "bar", linkageName: "_Z3bari", scope: !2, file: !2, line: 25, type: !11)
"""

# .ll with static function renamed (init -> init.1)
SAMPLE_LL_RENAMED = """
!1 = !DIFile(filename: "lib/a.c", directory: "/src/proj")
!10 = distinct !DISubprogram(name: "init", linkageName: "init.1", scope: !1, file: !1, line: 5, type: !11)
!11 = !DISubroutineType(types: !12)
!12 = !{null}
"""


class TestLLParsing:
    def test_parse_basic(self, tmp_path: Path):
        ll_file = tmp_path / "library.ll"
        ll_file.write_text(SAMPLE_LL)

        metas = BitcodeGenerator._parse_ll_debug_info(ll_file, "/src/myproject")
        assert len(metas) == 2

        by_name = {m.original_name: m for m in metas}
        assert "foo" in by_name
        assert "bar" in by_name

        foo = by_name["foo"]
        assert foo.file_path == "src/foo.c"
        assert foo.line == 10
        assert foo.ir_name == "foo"

        bar = by_name["bar"]
        assert bar.file_path == "src/bar.c"
        assert bar.line == 25
        assert bar.ir_name == "_Z3bari"

    def test_parse_renamed_function(self, tmp_path: Path):
        ll_file = tmp_path / "library.ll"
        ll_file.write_text(SAMPLE_LL_RENAMED)

        metas = BitcodeGenerator._parse_ll_debug_info(ll_file, "/src/proj")
        assert len(metas) == 1
        m = metas[0]
        assert m.original_name == "init"
        assert m.ir_name == "init.1"
        assert m.file_path == "lib/a.c"
        assert m.line == 5

    def test_parse_empty(self, tmp_path: Path):
        ll_file = tmp_path / "empty.ll"
        ll_file.write_text("; empty module")
        metas = BitcodeGenerator._parse_ll_debug_info(ll_file, "/tmp")
        assert len(metas) == 0


class TestEnrichFromSource:
    """Test _enrich_from_source — reads actual C files to populate end_line/content."""

    def test_basic_enrichment(self, tmp_path: Path):
        """end_line and content are populated from source file."""
        from z_code_analyzer.models.build import FunctionMeta

        # Create a source file
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "foo.c").write_text(
            "// header\n"
            "int foo(int x) {\n"       # line 2
            "    if (x > 0) {\n"
            "        return x;\n"
            "    }\n"
            "    return 0;\n"
            "}\n"                       # line 7
            "\n"
            "void bar() {\n"           # line 9
            "    foo(42);\n"
            "}\n"                       # line 11
        )

        metas = [
            FunctionMeta(ir_name="foo", original_name="foo", file_path="src/foo.c", line=2),
            FunctionMeta(ir_name="bar", original_name="bar", file_path="src/foo.c", line=9),
        ]

        BitcodeGenerator._enrich_from_source(metas, str(tmp_path))

        assert metas[0].end_line == 7
        assert metas[0].content.startswith("int foo(int x) {")
        assert metas[0].content.endswith("}")

        assert metas[1].end_line == 11
        assert "foo(42);" in metas[1].content

    def test_missing_source_file(self, tmp_path: Path):
        """No crash when source file doesn't exist."""
        from z_code_analyzer.models.build import FunctionMeta

        metas = [
            FunctionMeta(ir_name="f", original_name="f", file_path="missing.c", line=1),
        ]
        BitcodeGenerator._enrich_from_source(metas, str(tmp_path))
        assert metas[0].end_line == 0
        assert metas[0].content == ""

    def test_external_function_skipped(self, tmp_path: Path):
        """Functions with no file_path are skipped."""
        from z_code_analyzer.models.build import FunctionMeta

        metas = [
            FunctionMeta(ir_name="malloc", original_name="malloc", file_path="", line=0),
        ]
        BitcodeGenerator._enrich_from_source(metas, str(tmp_path))
        assert metas[0].end_line == 0


class TestFindFunctionEnd:
    """Test _find_function_end — brace-counting logic."""

    def test_simple_function(self):
        lines = [
            "void f() {",   # 0
            "    return;",
            "}",             # 2
        ]
        assert BitcodeGenerator._find_function_end(lines, 0) == 2

    def test_nested_braces(self):
        lines = [
            "int foo(int x) {",      # 0
            "    if (x) {",
            "        return 1;",
            "    }",
            "    return 0;",
            "}",                      # 5
        ]
        assert BitcodeGenerator._find_function_end(lines, 0) == 5

    def test_brace_in_comment_ignored(self):
        lines = [
            "void f() {",            # 0
            "    // { not counted",
            "    return;",
            "}",                      # 3
        ]
        assert BitcodeGenerator._find_function_end(lines, 0) == 3

    def test_function_signature_on_separate_line(self):
        lines = [
            "void f()",              # 0
            "{",                      # 1
            "    return;",
            "}",                      # 3
        ]
        assert BitcodeGenerator._find_function_end(lines, 0) == 3
