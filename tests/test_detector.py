"""Tests for BuildCommandDetector — pure logic, no Docker needed."""

from __future__ import annotations

from pathlib import Path

from z_code_analyzer.build.detector import BuildCommandDetector


class TestBuildCommandDetector:
    def test_user_provided_script(self, tmp_path: Path):
        script = tmp_path / "build.sh"
        script.write_text("#!/bin/bash\nmake")
        detector = BuildCommandDetector()
        result = detector.detect(str(tmp_path), build_script="build.sh")
        assert result is not None
        assert result.source == "user"
        assert result.build_system == "custom"
        assert result.confidence == 1.0

    def test_auto_detect_cmake(self, tmp_path: Path):
        (tmp_path / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.10)")
        detector = BuildCommandDetector()
        result = detector.detect(str(tmp_path))
        assert result is not None
        assert result.build_system == "cmake"
        assert result.source == "auto_detect"
        assert "cmake" in result.commands[0]

    def test_auto_detect_autotools_configure_ac(self, tmp_path: Path):
        (tmp_path / "configure.ac").write_text("AC_INIT")
        detector = BuildCommandDetector()
        result = detector.detect(str(tmp_path))
        assert result is not None
        assert result.build_system == "autotools"
        assert "autoreconf" in result.commands[0]

    def test_auto_detect_autotools_configure(self, tmp_path: Path):
        (tmp_path / "configure").write_text("#!/bin/sh")
        detector = BuildCommandDetector()
        result = detector.detect(str(tmp_path))
        assert result is not None
        assert result.build_system == "autotools"

    def test_auto_detect_meson(self, tmp_path: Path):
        (tmp_path / "meson.build").write_text("project('test')")
        detector = BuildCommandDetector()
        result = detector.detect(str(tmp_path))
        assert result is not None
        assert result.build_system == "meson"

    def test_auto_detect_makefile(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text("all:\n\tgcc -o main main.c")
        detector = BuildCommandDetector()
        result = detector.detect(str(tmp_path))
        assert result is not None
        assert result.build_system == "make"

    def test_cmake_takes_priority_over_makefile(self, tmp_path: Path):
        (tmp_path / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.10)")
        (tmp_path / "Makefile").write_text("all:")
        detector = BuildCommandDetector()
        result = detector.detect(str(tmp_path))
        assert result is not None
        assert result.build_system == "cmake"

    def test_no_build_system(self, tmp_path: Path):
        detector = BuildCommandDetector()
        result = detector.detect(str(tmp_path))
        assert result is None

    def test_user_script_not_found(self, tmp_path: Path):
        detector = BuildCommandDetector()
        # Falls through to auto-detect (which also finds nothing)
        result = detector.detect(str(tmp_path), build_script="nonexistent.sh")
        assert result is None

    def test_detect_build_system_only(self, tmp_path: Path):
        (tmp_path / "CMakeLists.txt").write_text("")
        detector = BuildCommandDetector()
        assert detector.detect_build_system(str(tmp_path)) == "cmake"

    def test_detect_build_system_unknown(self, tmp_path: Path):
        detector = BuildCommandDetector()
        assert detector.detect_build_system(str(tmp_path)) == "unknown"
