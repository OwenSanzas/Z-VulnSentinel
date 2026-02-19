"""Tests for BuildScriptLocator — pure filesystem logic, no Docker needed."""

from __future__ import annotations

from pathlib import Path

import pytest

from z_code_analyzer.build.locator import BuildScriptLocator


@pytest.fixture
def locator():
    return BuildScriptLocator()


class TestLocateStandardLayout:
    """Standard oss-fuzz layout: projects/<name>/build.sh"""

    def test_exact_match(self, tmp_path: Path, locator: BuildScriptLocator):
        proj = tmp_path / "projects" / "curl"
        proj.mkdir(parents=True)
        build_sh = proj / "build.sh"
        build_sh.write_text("#!/bin/bash\necho hello")

        result = locator.locate(str(tmp_path), "curl")
        assert result == str(build_sh)

    def test_case_insensitive(self, tmp_path: Path, locator: BuildScriptLocator):
        proj = tmp_path / "projects" / "LibPNG"
        proj.mkdir(parents=True)
        build_sh = proj / "build.sh"
        build_sh.write_text("#!/bin/bash")

        result = locator.locate(str(tmp_path), "libpng")
        assert result == str(build_sh)

    def test_no_build_sh_in_project_dir(self, tmp_path: Path, locator: BuildScriptLocator):
        proj = tmp_path / "projects" / "curl"
        proj.mkdir(parents=True)
        # Directory exists but no build.sh
        (proj / "Dockerfile").write_text("FROM ubuntu")

        result = locator.locate(str(tmp_path), "curl")
        assert result is None

    def test_no_projects_dir(self, tmp_path: Path, locator: BuildScriptLocator):
        result = locator.locate(str(tmp_path), "curl")
        assert result is None


class TestLocateRootBuildSh:
    """Single-project repos with build.sh at root (AIXCC style)."""

    def test_root_build_sh(self, tmp_path: Path, locator: BuildScriptLocator):
        build_sh = tmp_path / "build.sh"
        build_sh.write_text("#!/bin/bash\nmake all")

        result = locator.locate(str(tmp_path), "myproject")
        assert result == str(build_sh)

    def test_projects_dir_takes_priority_over_root(
        self, tmp_path: Path, locator: BuildScriptLocator
    ):
        # Both root and projects/<name>/build.sh exist — projects/ wins
        (tmp_path / "build.sh").write_text("#!/bin/bash\nroot")

        proj = tmp_path / "projects" / "curl"
        proj.mkdir(parents=True)
        proj_build = proj / "build.sh"
        proj_build.write_text("#!/bin/bash\nproject")

        result = locator.locate(str(tmp_path), "curl")
        assert result == str(proj_build)


class TestLocateNotFound:
    """Cases where no build.sh can be found."""

    def test_empty_dir(self, tmp_path: Path, locator: BuildScriptLocator):
        assert locator.locate(str(tmp_path), "nonexistent") is None

    def test_wrong_project_name(self, tmp_path: Path, locator: BuildScriptLocator):
        proj = tmp_path / "projects" / "openssl"
        proj.mkdir(parents=True)
        (proj / "build.sh").write_text("#!/bin/bash")

        assert locator.locate(str(tmp_path), "curl") is None


class TestGenerateOssfuzzNativeConfig:
    """Test BitcodeGenerator._generate_ossfuzz_native_config."""

    def test_generates_config(self, tmp_path: Path):
        from z_code_analyzer.build.bitcode import BitcodeGenerator

        # Set up fuzz tooling with build.sh
        tooling = tmp_path / "fuzz_tooling"
        proj = tooling / "projects" / "curl"
        proj.mkdir(parents=True)
        (proj / "build.sh").write_text("#!/bin/bash\nmake")

        project_path = str(tmp_path / "curl")
        output_dir = str(tmp_path / "output")
        Path(output_dir).mkdir()

        result = BitcodeGenerator._generate_ossfuzz_native_config(
            project_path, str(tooling), output_dir
        )

        assert result is not None
        config = Path(result).read_text()
        assert 'PROJECT_NAME="curl"' in config
        assert 'BUILD_MODE="ossfuzz-native"' in config
        assert 'OSSFUZZ_BUILD_SH="/src/fuzz_tooling/projects/curl/build.sh"' in config

    def test_returns_none_when_no_build_sh(self, tmp_path: Path):
        from z_code_analyzer.build.bitcode import BitcodeGenerator

        tooling = tmp_path / "fuzz_tooling"
        tooling.mkdir()
        output_dir = str(tmp_path / "output")
        Path(output_dir).mkdir()

        result = BitcodeGenerator._generate_ossfuzz_native_config(
            str(tmp_path / "curl"), str(tooling), output_dir
        )
        assert result is None
