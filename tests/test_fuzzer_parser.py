"""Tests for FuzzerEntryParser — no Docker needed."""

from __future__ import annotations

from pathlib import Path

from z_code_analyzer.build.fuzzer_parser import FuzzerEntryParser

# Sample fuzzer source
SIMPLE_FUZZER = """\
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    lib_init();
    lib_process(data, size);
    lib_cleanup();
    return 0;
}
"""

# Fuzzer with internal helper
FUZZER_WITH_HELPER = """\
static void setup_context(const uint8_t *data, size_t size) {
    lib_create_context();
    lib_set_data(data, size);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    setup_context(data, size);
    lib_run();
    return 0;
}
"""

# Fuzzer calling non-library functions (should be ignored)
FUZZER_WITH_STDLIB = """\
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *buf = malloc(size);
    memcpy(buf, data, size);
    lib_parse(buf, size);
    free(buf);
    return 0;
}
"""


class TestFuzzerEntryParser:
    def test_simple_fuzzer(self, tmp_path: Path):
        src = tmp_path / "fuzz.c"
        src.write_text(SIMPLE_FUZZER)

        parser = FuzzerEntryParser()
        result = parser.parse(
            fuzzer_sources={"fuzz1": ["fuzz.c"]},
            library_functions={"lib_init", "lib_process", "lib_cleanup", "other_func"},
            project_path=str(tmp_path),
        )

        assert "fuzz1" in result
        assert set(result["fuzz1"]) == {"lib_init", "lib_process", "lib_cleanup"}

    def test_fuzzer_with_helper(self, tmp_path: Path):
        src = tmp_path / "fuzz.c"
        src.write_text(FUZZER_WITH_HELPER)

        parser = FuzzerEntryParser()
        result = parser.parse(
            fuzzer_sources={"fuzz1": ["fuzz.c"]},
            library_functions={"lib_create_context", "lib_set_data", "lib_run"},
            project_path=str(tmp_path),
        )

        assert "fuzz1" in result
        calls = set(result["fuzz1"])
        # Should follow setup_context helper and find lib_create_context, lib_set_data
        # Exact set comparison ensures no internal helpers leak through
        assert calls == {"lib_create_context", "lib_set_data", "lib_run"}

    def test_stdlib_calls_filtered(self, tmp_path: Path):
        src = tmp_path / "fuzz.c"
        src.write_text(FUZZER_WITH_STDLIB)

        parser = FuzzerEntryParser()
        result = parser.parse(
            fuzzer_sources={"fuzz1": ["fuzz.c"]},
            library_functions={"lib_parse"},
            project_path=str(tmp_path),
        )

        assert result["fuzz1"] == ["lib_parse"]

    def test_multiple_fuzzers(self, tmp_path: Path):
        fuzz1 = tmp_path / "fuzz1.c"
        fuzz1.write_text(
            "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { lib_a(); return 0; }"
        )
        fuzz2 = tmp_path / "fuzz2.c"
        fuzz2.write_text(
            "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { lib_b(); return 0; }"
        )

        parser = FuzzerEntryParser()
        result = parser.parse(
            fuzzer_sources={"fuzz_a": ["fuzz1.c"], "fuzz_b": ["fuzz2.c"]},
            library_functions={"lib_a", "lib_b"},
            project_path=str(tmp_path),
        )

        assert result["fuzz_a"] == ["lib_a"]
        assert result["fuzz_b"] == ["lib_b"]

    def test_missing_source_file(self, tmp_path: Path):
        parser = FuzzerEntryParser()
        result = parser.parse(
            fuzzer_sources={"fuzz1": ["nonexistent.c"]},
            library_functions={"lib_a"},
            project_path=str(tmp_path),
        )
        assert result["fuzz1"] == []

    def test_no_entry_function(self, tmp_path: Path):
        src = tmp_path / "fuzz.c"
        src.write_text("void some_other_func() { lib_a(); }")

        parser = FuzzerEntryParser()
        result = parser.parse(
            fuzzer_sources={"fuzz1": ["fuzz.c"]},
            library_functions={"lib_a"},
            project_path=str(tmp_path),
        )
        # No LLVMFuzzerTestOneInput found, so no calls expanded
        assert result["fuzz1"] == []
