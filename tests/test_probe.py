"""Tests for ProjectProbe — no Docker needed."""

from __future__ import annotations

from pathlib import Path

from z_code_analyzer.probe import ProjectProbe


class TestProjectProbe:
    def test_c_project(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.c").write_text("int main() { return 0; }")
        (tmp_path / "src" / "util.c").write_text("void util() {}")
        (tmp_path / "src" / "util.h").write_text("#pragma once")
        (tmp_path / "Makefile").write_text("all: main")

        probe = ProjectProbe()
        info = probe.probe(str(tmp_path))

        assert info.language_profile.primary_language == "c"
        assert info.build_system == "make"
        assert len(info.source_files) == 3

    def test_cpp_project(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.cpp").write_text("int main() {}")
        (tmp_path / "src" / "app.cc").write_text("void app() {}")
        (tmp_path / "src" / "app.h").write_text("")
        (tmp_path / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.10)")

        probe = ProjectProbe()
        info = probe.probe(str(tmp_path))

        assert info.language_profile.primary_language == "cpp"
        assert info.build_system == "cmake"

    def test_autotools_project(self, tmp_path: Path):
        (tmp_path / "configure.ac").write_text("AC_INIT")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "lib.c").write_text("")

        probe = ProjectProbe()
        info = probe.probe(str(tmp_path))

        assert info.build_system == "autotools"

    def test_unknown_build_system(self, tmp_path: Path):
        (tmp_path / "foo.c").write_text("")

        probe = ProjectProbe()
        info = probe.probe(str(tmp_path))

        assert info.build_system == "unknown"

    def test_empty_directory(self, tmp_path: Path):
        probe = ProjectProbe()
        info = probe.probe(str(tmp_path))

        assert info.language_profile.primary_language == "unknown"
        assert len(info.source_files) == 0

    def test_nonexistent_path(self):
        probe = ProjectProbe()
        import pytest

        with pytest.raises(FileNotFoundError):
            probe.probe("/nonexistent/path")

    def test_skips_git_dir(self, tmp_path: Path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config.c").write_text("")  # Should be skipped
        (tmp_path / "src.c").write_text("")

        probe = ProjectProbe()
        info = probe.probe(str(tmp_path))

        assert len(info.source_files) == 1

    def test_loc_estimate(self, tmp_path: Path):
        (tmp_path / "main.c").write_text("int main() {\n  return 0;\n}\n")

        probe = ProjectProbe()
        info = probe.probe(str(tmp_path))

        assert info.estimated_loc == 3

    def test_diff_files_passthrough(self, tmp_path: Path):
        (tmp_path / "a.c").write_text("")
        probe = ProjectProbe()
        info = probe.probe(str(tmp_path), diff_files=["a.c"])
        assert info.diff_files == ["a.c"]
