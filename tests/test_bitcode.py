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
