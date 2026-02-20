"""Tests for the dependency scanner engine."""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from vulnsentinel.engines.dependency_scanner.models import ScanResult, ScannedDependency
from vulnsentinel.engines.dependency_scanner.parsers.cargo_toml import CargoTomlParser
from vulnsentinel.engines.dependency_scanner.parsers.cmake_find import CMakeFindPackageParser
from vulnsentinel.engines.dependency_scanner.parsers.conan import ConanParser
from vulnsentinel.engines.dependency_scanner.parsers.git_submodule import (
    GitSubmoduleParser,
)
from vulnsentinel.engines.dependency_scanner.parsers.go_mod import GoModParser
from vulnsentinel.engines.dependency_scanner.parsers.maven_pom import MavenPomParser
from vulnsentinel.engines.dependency_scanner.parsers.pip_requirements import (
    PipRequirementsParser,
)
from vulnsentinel.engines.dependency_scanner.parsers.pyproject_toml import (
    PyprojectTomlParser,
)
from vulnsentinel.engines.dependency_scanner.parsers.vcpkg_json import VcpkgJsonParser
from vulnsentinel.engines.dependency_scanner.registry import (
    PARSER_REGISTRY,
    discover_manifests,
)
from vulnsentinel.engines.dependency_scanner.scanner import DependencyScanner


# ── helpers ──────────────────────────────────────────────────────────────


def _dep(name: str, **overrides) -> dict:
    defaults = {
        "library_name": name,
        "library_repo_url": None,
        "constraint_expr": None,
        "resolved_version": None,
        "source_file": "requirements.txt",
        "detection_method": "pip-requirements",
    }
    defaults.update(overrides)
    return defaults


# ── Parser registry ──────────────────────────────────────────────────────


class TestRegistry:
    def test_all_parsers_registered(self):
        expected = {
            "pip-requirements",
            "git-submodule",
            "go-mod",
            "cargo-toml",
            "maven-pom",
            "pyproject-toml",
            "conan",
            "vcpkg",
            "cmake-find-package",
        }
        assert expected.issubset(set(PARSER_REGISTRY.keys()))

    def test_discover_manifests_finds_requirements(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==2.0\n")
        matches = discover_manifests(tmp_path)
        methods = [p.detection_method for p, _ in matches]
        assert "pip-requirements" in methods

    def test_discover_manifests_finds_gitmodules(self, tmp_path):
        (tmp_path / ".gitmodules").write_text(
            '[submodule "sub"]\n\turl = https://github.com/org/sub\n\tpath = sub\n'
        )
        matches = discover_manifests(tmp_path)
        methods = [p.detection_method for p, _ in matches]
        assert "git-submodule" in methods

    def test_discover_manifests_empty_repo(self, tmp_path):
        assert discover_manifests(tmp_path) == []

    def test_discover_manifests_subdirectory_pattern(self, tmp_path):
        req_dir = tmp_path / "requirements"
        req_dir.mkdir()
        (req_dir / "dev.txt").write_text("pytest\n")
        matches = discover_manifests(tmp_path)
        files = [str(f.name) for _, f in matches]
        assert "dev.txt" in files

    def test_discover_go_mod(self, tmp_path):
        (tmp_path / "go.mod").write_text("module example.com/m\ngo 1.21\n")
        matches = discover_manifests(tmp_path)
        methods = [p.detection_method for p, _ in matches]
        assert "go-mod" in methods

    def test_discover_cargo_toml(self, tmp_path):
        (tmp_path / "Cargo.toml").write_text("[package]\nname = \"x\"\n")
        matches = discover_manifests(tmp_path)
        methods = [p.detection_method for p, _ in matches]
        assert "cargo-toml" in methods

    def test_discover_pom_xml(self, tmp_path):
        (tmp_path / "pom.xml").write_text("<project></project>\n")
        matches = discover_manifests(tmp_path)
        methods = [p.detection_method for p, _ in matches]
        assert "maven-pom" in methods

    def test_discover_pyproject_toml(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[project]\nname = \"x\"\n")
        matches = discover_manifests(tmp_path)
        methods = [p.detection_method for p, _ in matches]
        assert "pyproject-toml" in methods

    def test_discover_conanfile(self, tmp_path):
        (tmp_path / "conanfile.txt").write_text("[requires]\nzlib/1.2.13\n")
        matches = discover_manifests(tmp_path)
        methods = [p.detection_method for p, _ in matches]
        assert "conan" in methods

    def test_discover_vcpkg_json(self, tmp_path):
        (tmp_path / "vcpkg.json").write_text('{"dependencies":["zlib"]}')
        matches = discover_manifests(tmp_path)
        methods = [p.detection_method for p, _ in matches]
        assert "vcpkg" in methods

    def test_discover_cmakelists(self, tmp_path):
        (tmp_path / "CMakeLists.txt").write_text("find_package(ZLIB REQUIRED)\n")
        matches = discover_manifests(tmp_path)
        methods = [p.detection_method for p, _ in matches]
        assert "cmake-find-package" in methods


# ── PipRequirementsParser ────────────────────────────────────────────────


class TestPipRequirementsParser:
    @pytest.fixture
    def parser(self):
        return PipRequirementsParser()

    def test_basic_pinned(self, parser, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("flask==2.3.1\n")
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "flask"
        assert deps[0].constraint_expr == "==2.3.1"
        assert deps[0].resolved_version == "2.3.1"

    def test_range_constraint(self, parser, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("requests>=2.28,<3.0\n")
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "requests"
        assert deps[0].constraint_expr == ">=2.28,<3.0"
        assert deps[0].resolved_version is None

    def test_no_version(self, parser, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("black\n")
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "black"
        assert deps[0].constraint_expr is None
        assert deps[0].resolved_version is None

    def test_skips_comments_and_blanks(self, parser, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("# comment\n\nflask==1.0\n  \n")
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1

    def test_skips_option_lines(self, parser, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("-r base.txt\n--index-url https://pypi.org\n-e ./local\nflask\n")
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "flask"

    def test_compatible_release(self, parser, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("django~=4.2\n")
        deps = parser.parse(f, f.read_text())
        assert deps[0].constraint_expr == "~=4.2"
        assert deps[0].resolved_version is None

    def test_not_equal(self, parser, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("foo!=1.0\n")
        deps = parser.parse(f, f.read_text())
        assert deps[0].constraint_expr == "!=1.0"
        assert deps[0].resolved_version is None

    def test_multiple_deps(self, parser, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("flask==2.0\nrequests>=1.0\nblack\n")
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 3

    def test_source_file_is_filename(self, parser, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("flask\n")
        deps = parser.parse(f, f.read_text())
        assert deps[0].source_file == "requirements.txt"
        assert deps[0].detection_method == "pip-requirements"

    def test_hyphen_and_dot_in_name(self, parser, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("my-package.extra==1.0\n")
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_name == "my-package.extra"

    def test_repo_url_is_none(self, parser, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("flask==1.0\n")
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_repo_url is None


# ── GitSubmoduleParser ───────────────────────────────────────────────────


class TestGitSubmoduleParser:
    @pytest.fixture
    def parser(self):
        return GitSubmoduleParser()

    def test_single_submodule(self, parser, tmp_path):
        f = tmp_path / ".gitmodules"
        f.write_text(
            '[submodule "mylib"]\n'
            "\tpath = vendor/mylib\n"
            "\turl = https://github.com/org/mylib.git\n"
        )
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "mylib"
        assert deps[0].library_repo_url == "https://github.com/org/mylib.git"
        assert deps[0].constraint_expr is None
        assert deps[0].resolved_version is None

    def test_multiple_submodules(self, parser, tmp_path):
        f = tmp_path / ".gitmodules"
        f.write_text(
            '[submodule "a"]\n'
            "\turl = https://github.com/org/a.git\n"
            "\tpath = a\n"
            '[submodule "b"]\n'
            "\turl = https://github.com/org/b\n"
            "\tpath = b\n"
        )
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 2
        names = {d.library_name for d in deps}
        assert names == {"a", "b"}

    def test_url_without_git_suffix(self, parser, tmp_path):
        f = tmp_path / ".gitmodules"
        f.write_text(
            '[submodule "x"]\n'
            "\turl = https://github.com/org/x\n"
            "\tpath = x\n"
        )
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_name == "x"

    def test_source_file_is_filename(self, parser, tmp_path):
        f = tmp_path / ".gitmodules"
        f.write_text(
            '[submodule "z"]\n'
            "\turl = https://github.com/org/z\n"
            "\tpath = z\n"
        )
        deps = parser.parse(f, f.read_text())
        assert deps[0].source_file == ".gitmodules"
        assert deps[0].detection_method == "git-submodule"

    def test_empty_file(self, parser, tmp_path):
        f = tmp_path / ".gitmodules"
        f.write_text("")
        deps = parser.parse(f, f.read_text())
        assert deps == []

    def test_section_without_url_is_skipped(self, parser, tmp_path):
        f = tmp_path / ".gitmodules"
        f.write_text('[submodule "orphan"]\n\tpath = orphan\n')
        deps = parser.parse(f, f.read_text())
        assert deps == []


# ── GoModParser ──────────────────────────────────────────────────────────


class TestGoModParser:
    @pytest.fixture
    def parser(self):
        return GoModParser()

    def test_require_block(self, parser, tmp_path):
        f = tmp_path / "go.mod"
        f.write_text(
            "module example.com/myproject\n\n"
            "go 1.21\n\n"
            "require (\n"
            "\tgithub.com/gin-gonic/gin v1.9.1\n"
            "\tgithub.com/go-sql-driver/mysql v1.7.1\n"
            ")\n"
        )
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 2
        assert deps[0].library_name == "github.com/gin-gonic/gin"
        assert deps[0].constraint_expr == "v1.9.1"
        assert deps[0].resolved_version == "1.9.1"
        assert deps[0].library_repo_url == "https://github.com/gin-gonic/gin"

    def test_single_require_line(self, parser, tmp_path):
        f = tmp_path / "go.mod"
        f.write_text(
            "module example.com/m\n\n"
            "go 1.21\n\n"
            "require github.com/pkg/errors v0.9.1\n"
        )
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "github.com/pkg/errors"
        assert deps[0].resolved_version == "0.9.1"

    def test_skips_indirect(self, parser, tmp_path):
        f = tmp_path / "go.mod"
        f.write_text(
            "module example.com/m\n\n"
            "require (\n"
            "\tgithub.com/direct/dep v1.0.0\n"
            "\tgithub.com/indirect/dep v2.0.0 // indirect\n"
            ")\n"
        )
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "github.com/direct/dep"

    def test_github_repo_url(self, parser, tmp_path):
        f = tmp_path / "go.mod"
        f.write_text(
            "module m\nrequire github.com/stretchr/testify v1.8.4\n"
        )
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_repo_url == "https://github.com/stretchr/testify"

    def test_gitlab_repo_url(self, parser, tmp_path):
        f = tmp_path / "go.mod"
        f.write_text(
            "module m\nrequire gitlab.com/org/repo v0.1.0\n"
        )
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_repo_url == "https://gitlab.com/org/repo"

    def test_non_github_module_url_is_none(self, parser, tmp_path):
        f = tmp_path / "go.mod"
        f.write_text(
            "module m\nrequire golang.org/x/text v0.14.0\n"
        )
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_repo_url is None

    def test_subpackage_url_truncated(self, parser, tmp_path):
        """github.com/org/repo/v2/sub → https://github.com/org/repo"""
        f = tmp_path / "go.mod"
        f.write_text(
            "module m\nrequire github.com/org/repo/v2 v2.3.0\n"
        )
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_repo_url == "https://github.com/org/repo"

    def test_pseudo_version(self, parser, tmp_path):
        f = tmp_path / "go.mod"
        f.write_text(
            "module m\nrequire github.com/org/repo v0.0.0-20231215172524-abc123\n"
        )
        deps = parser.parse(f, f.read_text())
        assert deps[0].constraint_expr == "v0.0.0-20231215172524-abc123"
        assert deps[0].resolved_version == "0.0.0-20231215172524-abc123"

    def test_empty_go_mod(self, parser, tmp_path):
        f = tmp_path / "go.mod"
        f.write_text("module m\ngo 1.21\n")
        deps = parser.parse(f, f.read_text())
        assert deps == []

    def test_source_file_and_method(self, parser, tmp_path):
        f = tmp_path / "go.mod"
        f.write_text("module m\nrequire github.com/a/b v1.0.0\n")
        deps = parser.parse(f, f.read_text())
        assert deps[0].source_file == "go.mod"
        assert deps[0].detection_method == "go-mod"


# ── CargoTomlParser ──────────────────────────────────────────────────────


class TestCargoTomlParser:
    @pytest.fixture
    def parser(self):
        return CargoTomlParser()

    def test_simple_version(self, parser, tmp_path):
        f = tmp_path / "Cargo.toml"
        f.write_text('[dependencies]\nserde = "1.0"\n')
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "serde"
        assert deps[0].constraint_expr == "1.0"
        assert deps[0].library_repo_url is None

    def test_table_version_with_features(self, parser, tmp_path):
        f = tmp_path / "Cargo.toml"
        f.write_text(
            "[dependencies]\n"
            'tokio = { version = "1.35", features = ["full"] }\n'
        )
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_name == "tokio"
        assert deps[0].constraint_expr == "1.35"

    def test_git_dependency(self, parser, tmp_path):
        f = tmp_path / "Cargo.toml"
        f.write_text(
            "[dependencies]\n"
            'my-crate = { git = "https://github.com/org/my-crate.git" }\n'
        )
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_name == "my-crate"
        assert deps[0].library_repo_url == "https://github.com/org/my-crate.git"
        assert deps[0].constraint_expr is None

    def test_git_dependency_with_version(self, parser, tmp_path):
        f = tmp_path / "Cargo.toml"
        f.write_text(
            "[dependencies]\n"
            'foo = { git = "https://github.com/org/foo", version = "0.5" }\n'
        )
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_repo_url == "https://github.com/org/foo"
        assert deps[0].constraint_expr == "0.5"

    def test_dev_dependencies(self, parser, tmp_path):
        f = tmp_path / "Cargo.toml"
        f.write_text('[dev-dependencies]\ncriterion = "0.5"\n')
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "criterion"

    def test_build_dependencies(self, parser, tmp_path):
        f = tmp_path / "Cargo.toml"
        f.write_text('[build-dependencies]\ncc = "1.0"\n')
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "cc"

    def test_all_sections_combined(self, parser, tmp_path):
        f = tmp_path / "Cargo.toml"
        f.write_text(
            "[dependencies]\n"
            'serde = "1.0"\n\n'
            "[dev-dependencies]\n"
            'tokio-test = "0.4"\n\n'
            "[build-dependencies]\n"
            'cc = "1.0"\n'
        )
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 3
        names = {d.library_name for d in deps}
        assert names == {"serde", "tokio-test", "cc"}

    def test_caret_version(self, parser, tmp_path):
        """Cargo default: ^1.0 means >=1.0.0 <2.0.0"""
        f = tmp_path / "Cargo.toml"
        f.write_text('[dependencies]\nfoo = "^1.2.3"\n')
        deps = parser.parse(f, f.read_text())
        assert deps[0].constraint_expr == "^1.2.3"

    def test_tilde_version(self, parser, tmp_path):
        f = tmp_path / "Cargo.toml"
        f.write_text('[dependencies]\nbar = "~1.2"\n')
        deps = parser.parse(f, f.read_text())
        assert deps[0].constraint_expr == "~1.2"

    def test_wildcard_version(self, parser, tmp_path):
        f = tmp_path / "Cargo.toml"
        f.write_text('[dependencies]\nbaz = "1.*"\n')
        deps = parser.parse(f, f.read_text())
        assert deps[0].constraint_expr == "1.*"

    def test_exact_version(self, parser, tmp_path):
        f = tmp_path / "Cargo.toml"
        f.write_text('[dependencies]\nqux = "=1.2.3"\n')
        deps = parser.parse(f, f.read_text())
        assert deps[0].constraint_expr == "=1.2.3"

    def test_empty_cargo_toml(self, parser, tmp_path):
        f = tmp_path / "Cargo.toml"
        f.write_text("[package]\nname = \"x\"\nversion = \"0.1.0\"\n")
        deps = parser.parse(f, f.read_text())
        assert deps == []

    def test_source_file_and_method(self, parser, tmp_path):
        f = tmp_path / "Cargo.toml"
        f.write_text('[dependencies]\na = "1"\n')
        deps = parser.parse(f, f.read_text())
        assert deps[0].source_file == "Cargo.toml"
        assert deps[0].detection_method == "cargo-toml"


# ── MavenPomParser ───────────────────────────────────────────────────────


class TestMavenPomParser:
    @pytest.fixture
    def parser(self):
        return MavenPomParser()

    def test_basic_dependency(self, parser, tmp_path):
        f = tmp_path / "pom.xml"
        f.write_text(
            "<project>\n"
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>org.springframework</groupId>\n"
            "      <artifactId>spring-core</artifactId>\n"
            "      <version>5.3.20</version>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>\n"
        )
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "org.springframework:spring-core"
        assert deps[0].constraint_expr == "5.3.20"
        assert deps[0].resolved_version == "5.3.20"

    def test_namespaced_pom(self, parser, tmp_path):
        f = tmp_path / "pom.xml"
        f.write_text(
            '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>com.google.guava</groupId>\n"
            "      <artifactId>guava</artifactId>\n"
            "      <version>32.1.2-jre</version>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>\n"
        )
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "com.google.guava:guava"
        assert deps[0].resolved_version == "32.1.2-jre"

    def test_multiple_dependencies(self, parser, tmp_path):
        f = tmp_path / "pom.xml"
        f.write_text(
            "<project>\n"
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>junit</groupId>\n"
            "      <artifactId>junit</artifactId>\n"
            "      <version>4.13.2</version>\n"
            "    </dependency>\n"
            "    <dependency>\n"
            "      <groupId>org.slf4j</groupId>\n"
            "      <artifactId>slf4j-api</artifactId>\n"
            "      <version>2.0.9</version>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>\n"
        )
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 2

    def test_no_version(self, parser, tmp_path):
        """Managed dependencies may omit version."""
        f = tmp_path / "pom.xml"
        f.write_text(
            "<project>\n"
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>org.example</groupId>\n"
            "      <artifactId>managed</artifactId>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>\n"
        )
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].constraint_expr is None
        assert deps[0].resolved_version is None

    def test_property_version_placeholder(self, parser, tmp_path):
        """${property} versions are kept as-is (we don't resolve properties)."""
        f = tmp_path / "pom.xml"
        f.write_text(
            "<project>\n"
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>org.example</groupId>\n"
            "      <artifactId>prop-ver</artifactId>\n"
            "      <version>${spring.version}</version>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>\n"
        )
        deps = parser.parse(f, f.read_text())
        assert deps[0].constraint_expr == "${spring.version}"
        assert deps[0].resolved_version == "${spring.version}"

    def test_version_range(self, parser, tmp_path):
        """Maven version ranges like [1.0,2.0)."""
        f = tmp_path / "pom.xml"
        f.write_text(
            "<project>\n"
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>org.example</groupId>\n"
            "      <artifactId>ranged</artifactId>\n"
            "      <version>[1.0,2.0)</version>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>\n"
        )
        deps = parser.parse(f, f.read_text())
        assert deps[0].constraint_expr == "[1.0,2.0)"

    def test_empty_pom(self, parser, tmp_path):
        f = tmp_path / "pom.xml"
        f.write_text("<project></project>\n")
        deps = parser.parse(f, f.read_text())
        assert deps == []

    def test_repo_url_is_none(self, parser, tmp_path):
        f = tmp_path / "pom.xml"
        f.write_text(
            "<project>\n"
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>g</groupId>\n"
            "      <artifactId>a</artifactId>\n"
            "      <version>1</version>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>\n"
        )
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_repo_url is None

    def test_source_file_and_method(self, parser, tmp_path):
        f = tmp_path / "pom.xml"
        f.write_text(
            "<project><dependencies>"
            "<dependency><groupId>g</groupId><artifactId>a</artifactId>"
            "<version>1</version></dependency>"
            "</dependencies></project>"
        )
        deps = parser.parse(f, f.read_text())
        assert deps[0].source_file == "pom.xml"
        assert deps[0].detection_method == "maven-pom"

    def test_invalid_xml(self, parser, tmp_path):
        f = tmp_path / "pom.xml"
        f.write_text("not valid xml <<>>\n")
        deps = parser.parse(f, f.read_text())
        assert deps == []


# ── PyprojectTomlParser ──────────────────────────────────────────────────


class TestPyprojectTomlParser:
    @pytest.fixture
    def parser(self):
        return PyprojectTomlParser()

    def test_pinned_version(self, parser, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text(
            "[project]\n"
            'name = "myapp"\n'
            'dependencies = ["flask==2.3.1"]\n'
        )
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "flask"
        assert deps[0].constraint_expr == "==2.3.1"
        assert deps[0].resolved_version == "2.3.1"

    def test_range_constraint(self, parser, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text(
            "[project]\ndependencies = [\n"
            '  "requests>=2.28,<3.0",\n'
            "]\n"
        )
        deps = parser.parse(f, f.read_text())
        assert deps[0].constraint_expr == ">=2.28,<3.0"
        assert deps[0].resolved_version is None

    def test_compatible_release(self, parser, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text('[project]\ndependencies = ["django~=4.2"]\n')
        deps = parser.parse(f, f.read_text())
        assert deps[0].constraint_expr == "~=4.2"

    def test_no_version(self, parser, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text('[project]\ndependencies = ["black"]\n')
        deps = parser.parse(f, f.read_text())
        assert deps[0].constraint_expr is None

    def test_extras_ignored(self, parser, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text('[project]\ndependencies = ["uvicorn[standard]>=0.32"]\n')
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_name == "uvicorn"
        assert deps[0].constraint_expr == ">=0.32"

    def test_environment_marker_stripped(self, parser, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text(
            "[project]\n"
            "dependencies = [\n"
            '  "tomli>=2.0;python_version<\'3.11\'",\n'
            "]\n"
        )
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_name == "tomli"
        assert deps[0].constraint_expr == ">=2.0"

    def test_multiple_deps(self, parser, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text(
            "[project]\n"
            "dependencies = [\n"
            '  "flask>=2.0",\n'
            '  "sqlalchemy[asyncio]>=2.0",\n'
            '  "pydantic>=2.0",\n'
            "]\n"
        )
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 3

    def test_no_project_section(self, parser, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text("[build-system]\nrequires = [\"hatchling\"]\n")
        deps = parser.parse(f, f.read_text())
        assert deps == []

    def test_no_dependencies_key(self, parser, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text('[project]\nname = "x"\n')
        deps = parser.parse(f, f.read_text())
        assert deps == []

    def test_repo_url_is_none(self, parser, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text('[project]\ndependencies = ["flask"]\n')
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_repo_url is None

    def test_source_file_and_method(self, parser, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text('[project]\ndependencies = ["x"]\n')
        deps = parser.parse(f, f.read_text())
        assert deps[0].source_file == "pyproject.toml"
        assert deps[0].detection_method == "pyproject-toml"

    def test_not_equal(self, parser, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text('[project]\ndependencies = ["foo!=1.0"]\n')
        deps = parser.parse(f, f.read_text())
        assert deps[0].constraint_expr == "!=1.0"


# ── ConanParser ──────────────────────────────────────────────────────────


class TestConanParser:
    @pytest.fixture
    def parser(self):
        return ConanParser()

    def test_basic_requires(self, parser, tmp_path):
        f = tmp_path / "conanfile.txt"
        f.write_text("[requires]\nzlib/1.2.13\nopenssl/3.1.0\n")
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 2
        assert deps[0].library_name == "zlib"
        assert deps[0].constraint_expr == "==1.2.13"
        assert deps[0].resolved_version == "1.2.13"
        assert deps[1].library_name == "openssl"
        assert deps[1].resolved_version == "3.1.0"

    def test_with_user_channel(self, parser, tmp_path):
        f = tmp_path / "conanfile.txt"
        f.write_text("[requires]\nboost/1.83.0@myorg/stable\n")
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "boost"
        assert deps[0].resolved_version == "1.83.0"

    def test_skips_other_sections(self, parser, tmp_path):
        f = tmp_path / "conanfile.txt"
        f.write_text(
            "[requires]\nzlib/1.2.13\n\n"
            "[generators]\ncmake\n\n"
            "[options]\nzlib:shared=True\n"
        )
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "zlib"

    def test_skips_comments(self, parser, tmp_path):
        f = tmp_path / "conanfile.txt"
        f.write_text("[requires]\n# This is a comment\nzlib/1.2.13\n")
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1

    def test_empty_requires(self, parser, tmp_path):
        f = tmp_path / "conanfile.txt"
        f.write_text("[requires]\n\n[generators]\ncmake\n")
        deps = parser.parse(f, f.read_text())
        assert deps == []

    def test_no_requires_section(self, parser, tmp_path):
        f = tmp_path / "conanfile.txt"
        f.write_text("[generators]\ncmake\n")
        deps = parser.parse(f, f.read_text())
        assert deps == []

    def test_repo_url_is_none(self, parser, tmp_path):
        f = tmp_path / "conanfile.txt"
        f.write_text("[requires]\nzlib/1.2.13\n")
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_repo_url is None

    def test_source_file_and_method(self, parser, tmp_path):
        f = tmp_path / "conanfile.txt"
        f.write_text("[requires]\nzlib/1.0\n")
        deps = parser.parse(f, f.read_text())
        assert deps[0].source_file == "conanfile.txt"
        assert deps[0].detection_method == "conan"

    def test_prerelease_version(self, parser, tmp_path):
        f = tmp_path / "conanfile.txt"
        f.write_text("[requires]\nfmt/10.1.0-rc1\n")
        deps = parser.parse(f, f.read_text())
        assert deps[0].resolved_version == "10.1.0-rc1"

    def test_plus_in_name(self, parser, tmp_path):
        f = tmp_path / "conanfile.txt"
        f.write_text("[requires]\nlibxml2/2.11.5\n")
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_name == "libxml2"
        assert deps[0].resolved_version == "2.11.5"


# ── CMakeFindPackageParser ───────────────────────────────────────────────


class TestCMakeFindPackageParser:
    @pytest.fixture
    def parser(self):
        return CMakeFindPackageParser()

    def test_basic_find_package(self, parser, tmp_path):
        f = tmp_path / "CMakeLists.txt"
        f.write_text("find_package(ZLIB REQUIRED)\nfind_package(OpenSSL)\n")
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 2
        names = [d.library_name for d in deps]
        assert "ZLIB" in names
        assert "OpenSSL" in names

    def test_skips_builtin_tools(self, parser, tmp_path):
        f = tmp_path / "CMakeLists.txt"
        f.write_text(
            "find_package(Perl)\n"
            "find_package(Threads REQUIRED)\n"
            "find_package(PkgConfig)\n"
            "find_package(Python3)\n"
            "find_package(Doxygen)\n"
            "find_package(ZLIB REQUIRED)\n"
        )
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "ZLIB"

    def test_dedup_same_package(self, parser, tmp_path):
        """Same package with different COMPONENTS should appear once."""
        f = tmp_path / "CMakeLists.txt"
        f.write_text(
            'find_package(NGTCP2 REQUIRED COMPONENTS "wolfSSL")\n'
            'find_package(NGTCP2 REQUIRED COMPONENTS "ossl")\n'
            'find_package(NGTCP2 COMPONENTS "quictls")\n'
        )
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "NGTCP2"

    def test_curl_like_cmakelists(self, parser, tmp_path):
        """Realistic curl-like CMakeLists.txt."""
        f = tmp_path / "CMakeLists.txt"
        f.write_text(
            "find_package(Cares REQUIRED)\n"
            "find_package(Perl)\n"
            "find_package(Threads REQUIRED)\n"
            "find_package(OpenSSL REQUIRED)\n"
            "find_package(NGHTTP2)\n"
            "find_package(Libssh2)\n"
            "find_package(ZLIB)\n"
        )
        deps = parser.parse(f, f.read_text())
        names = {d.library_name for d in deps}
        assert names == {"Cares", "OpenSSL", "NGHTTP2", "Libssh2", "ZLIB"}
        assert "Perl" not in names
        assert "Threads" not in names

    def test_no_find_package(self, parser, tmp_path):
        f = tmp_path / "CMakeLists.txt"
        f.write_text("project(mylib)\nadd_library(mylib src.c)\n")
        deps = parser.parse(f, f.read_text())
        assert deps == []

    def test_case_insensitive_skip(self, parser, tmp_path):
        f = tmp_path / "CMakeLists.txt"
        f.write_text("find_package(THREADS REQUIRED)\nfind_package(ZLIB)\n")
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "ZLIB"

    def test_version_in_find_package_ignored(self, parser, tmp_path):
        """We don't extract version from find_package — it's a minimum version hint."""
        f = tmp_path / "CMakeLists.txt"
        f.write_text("find_package(OpenSSL 1.1.1 REQUIRED)\n")
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_name == "OpenSSL"
        assert deps[0].constraint_expr is None

    def test_repo_url_is_none(self, parser, tmp_path):
        f = tmp_path / "CMakeLists.txt"
        f.write_text("find_package(ZLIB)\n")
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_repo_url is None

    def test_source_file_and_method(self, parser, tmp_path):
        f = tmp_path / "CMakeLists.txt"
        f.write_text("find_package(ZLIB)\n")
        deps = parser.parse(f, f.read_text())
        assert deps[0].source_file == "CMakeLists.txt"
        assert deps[0].detection_method == "cmake-find-package"

    def test_indented_and_spaced(self, parser, tmp_path):
        f = tmp_path / "CMakeLists.txt"
        f.write_text("  find_package( OpenSSL  REQUIRED )\n")
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "OpenSSL"


# ── VcpkgJsonParser ──────────────────────────────────────────────────────


class TestVcpkgJsonParser:
    @pytest.fixture
    def parser(self):
        return VcpkgJsonParser()

    def test_string_dependencies(self, parser, tmp_path):
        f = tmp_path / "vcpkg.json"
        f.write_text('{"dependencies": ["zlib", "openssl", "curl"]}')
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 3
        names = [d.library_name for d in deps]
        assert names == ["zlib", "openssl", "curl"]
        assert all(d.constraint_expr is None for d in deps)

    def test_object_dependency_with_version(self, parser, tmp_path):
        f = tmp_path / "vcpkg.json"
        f.write_text(
            '{"dependencies": [{"name": "openssl", "version>=": "3.0"}]}'
        )
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 1
        assert deps[0].library_name == "openssl"
        assert deps[0].constraint_expr == ">=3.0"

    def test_mixed_string_and_object(self, parser, tmp_path):
        f = tmp_path / "vcpkg.json"
        f.write_text(
            '{"dependencies": ["zlib", {"name": "curl", "version>=": "7.0"}]}'
        )
        deps = parser.parse(f, f.read_text())
        assert len(deps) == 2
        assert deps[0].library_name == "zlib"
        assert deps[0].constraint_expr is None
        assert deps[1].library_name == "curl"
        assert deps[1].constraint_expr == ">=7.0"

    def test_object_with_version_field(self, parser, tmp_path):
        f = tmp_path / "vcpkg.json"
        f.write_text('{"dependencies": [{"name": "fmt", "version": "10.1.0"}]}')
        deps = parser.parse(f, f.read_text())
        assert deps[0].constraint_expr == ">=10.1.0"

    def test_no_dependencies_key(self, parser, tmp_path):
        f = tmp_path / "vcpkg.json"
        f.write_text('{"name": "myproject", "version": "1.0"}')
        deps = parser.parse(f, f.read_text())
        assert deps == []

    def test_empty_dependencies(self, parser, tmp_path):
        f = tmp_path / "vcpkg.json"
        f.write_text('{"dependencies": []}')
        deps = parser.parse(f, f.read_text())
        assert deps == []

    def test_invalid_json(self, parser, tmp_path):
        f = tmp_path / "vcpkg.json"
        f.write_text("not json {{{")
        deps = parser.parse(f, f.read_text())
        assert deps == []

    def test_object_missing_name_skipped(self, parser, tmp_path):
        f = tmp_path / "vcpkg.json"
        f.write_text('{"dependencies": [{"version>=": "1.0"}]}')
        deps = parser.parse(f, f.read_text())
        assert deps == []

    def test_repo_url_is_none(self, parser, tmp_path):
        f = tmp_path / "vcpkg.json"
        f.write_text('{"dependencies": ["zlib"]}')
        deps = parser.parse(f, f.read_text())
        assert deps[0].library_repo_url is None

    def test_source_file_and_method(self, parser, tmp_path):
        f = tmp_path / "vcpkg.json"
        f.write_text('{"dependencies": ["x"]}')
        deps = parser.parse(f, f.read_text())
        assert deps[0].source_file == "vcpkg.json"
        assert deps[0].detection_method == "vcpkg"


# ── Standalone scan ──────────────────────────────────────────────────────


class TestScan:
    def test_scan_mixed_manifests(self, tmp_path):
        # requirements.txt
        (tmp_path / "requirements.txt").write_text("flask==2.0\nrequests>=1.0\n")
        # .gitmodules
        (tmp_path / ".gitmodules").write_text(
            '[submodule "zlib"]\n'
            "\turl = https://github.com/madler/zlib.git\n"
            "\tpath = third_party/zlib\n"
        )

        scanner = DependencyScanner.__new__(DependencyScanner)
        deps = scanner.scan(tmp_path)

        names = {d.library_name for d in deps}
        assert "flask" in names
        assert "requests" in names
        assert "zlib" in names
        assert len(deps) == 3

    def test_scan_empty_repo(self, tmp_path):
        scanner = DependencyScanner.__new__(DependencyScanner)
        deps = scanner.scan(tmp_path)
        assert deps == []

    def test_scan_only_requirements(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("numpy==1.24\n")
        scanner = DependencyScanner.__new__(DependencyScanner)
        deps = scanner.scan(tmp_path)
        assert len(deps) == 1
        assert deps[0].library_name == "numpy"
        assert deps[0].library_repo_url is None

    def test_scan_only_gitmodules(self, tmp_path):
        (tmp_path / ".gitmodules").write_text(
            '[submodule "lib"]\n'
            "\turl = https://github.com/org/lib.git\n"
            "\tpath = lib\n"
        )
        scanner = DependencyScanner.__new__(DependencyScanner)
        deps = scanner.scan(tmp_path)
        assert len(deps) == 1
        assert deps[0].library_repo_url == "https://github.com/org/lib.git"

    def test_scan_source_file_relative_path(self, tmp_path):
        """source_file should be relative to repo root, not just filename."""
        req_dir = tmp_path / "requirements"
        req_dir.mkdir()
        (req_dir / "prod.txt").write_text("flask==2.0\n")

        scanner = DependencyScanner.__new__(DependencyScanner)
        deps = scanner.scan(tmp_path)
        assert len(deps) == 1
        assert deps[0].source_file == "requirements/prod.txt"

    def test_scan_root_file_source_path(self, tmp_path):
        """Root-level files should have just the filename as source_file."""
        (tmp_path / "requirements.txt").write_text("flask==1.0\n")

        scanner = DependencyScanner.__new__(DependencyScanner)
        deps = scanner.scan(tmp_path)
        assert deps[0].source_file == "requirements.txt"

    def test_scan_all_manifest_types(self, tmp_path):
        """Verify all 9 parsers work together in a single scan."""
        (tmp_path / "requirements.txt").write_text("flask==2.0\n")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["pydantic>=2.0"]\n'
        )
        (tmp_path / ".gitmodules").write_text(
            '[submodule "sub"]\n'
            "\turl = https://github.com/org/sub.git\n"
            "\tpath = sub\n"
        )
        (tmp_path / "go.mod").write_text(
            "module m\nrequire github.com/gin-gonic/gin v1.9.1\n"
        )
        (tmp_path / "Cargo.toml").write_text('[dependencies]\nserde = "1.0"\n')
        (tmp_path / "pom.xml").write_text(
            "<project><dependencies>"
            "<dependency><groupId>g</groupId><artifactId>a</artifactId>"
            "<version>1</version></dependency>"
            "</dependencies></project>"
        )
        (tmp_path / "conanfile.txt").write_text("[requires]\nzlib/1.2.13\n")
        (tmp_path / "vcpkg.json").write_text('{"dependencies":["curl"]}')
        (tmp_path / "CMakeLists.txt").write_text("find_package(OpenSSL REQUIRED)\n")

        scanner = DependencyScanner.__new__(DependencyScanner)
        deps = scanner.scan(tmp_path)

        methods = {d.detection_method for d in deps}
        assert methods == {
            "pip-requirements",
            "pyproject-toml",
            "git-submodule",
            "go-mod",
            "cargo-toml",
            "maven-pom",
            "conan",
            "vcpkg",
            "cmake-find-package",
        }
        assert len(deps) == 9


# ── Integrated mode ──────────────────────────────────────────────────────


def _fake_project(**overrides):
    """Create a fake Project-like object for mocking."""

    class FakeProject:
        id = overrides.get("id", uuid.uuid4())
        name = overrides.get("name", "test-project")
        repo_url = overrides.get("repo_url", "https://github.com/org/test")
        default_branch = overrides.get("default_branch", "main")
        auto_sync_deps = overrides.get("auto_sync_deps", True)
        pinned_ref = overrides.get("pinned_ref", None)
        last_scanned_at = overrides.get("last_scanned_at", None)

    return FakeProject()


def _fake_library(name: str, lib_id: uuid.UUID | None = None):
    class FakeLibrary:
        pass

    lib = FakeLibrary()
    lib.id = lib_id or uuid.uuid4()
    lib.name = name
    return lib


class TestRunIntegrated:
    @pytest.fixture
    def scanner_deps(self):
        project_dao = AsyncMock()
        dep_dao = AsyncMock()
        library_service = AsyncMock()
        scanner = DependencyScanner(project_dao, dep_dao, library_service)
        return scanner, project_dao, dep_dao, library_service

    @pytest.mark.anyio
    async def test_run_skips_disabled_project(self, scanner_deps):
        scanner, project_dao, dep_dao, library_service = scanner_deps
        project = _fake_project(auto_sync_deps=False)
        project_dao.get_by_id.return_value = project
        session = AsyncMock()

        result = await scanner.run(session, project.id)

        assert result.skipped is True
        assert result.synced_count == 0
        assert result.deleted_count == 0
        library_service.upsert.assert_not_called()

    @pytest.mark.anyio
    async def test_run_full_pipeline(self, scanner_deps, tmp_path):
        scanner, project_dao, dep_dao, library_service = scanner_deps
        project = _fake_project()
        project_dao.get_by_id.return_value = project
        project_dao.update.return_value = project

        # Prepare a fake repo dir with .gitmodules
        (tmp_path / ".gitmodules").write_text(
            '[submodule "zlib"]\n'
            "\turl = https://github.com/madler/zlib.git\n"
            "\tpath = third_party/zlib\n"
        )

        zlib_id = uuid.uuid4()
        fake_lib = _fake_library("zlib", zlib_id)
        library_service.upsert.return_value = fake_lib

        dep_dao.batch_upsert.return_value = [AsyncMock()]  # 1 upserted row
        dep_dao.delete_stale_scanner_deps.return_value = 0

        session = AsyncMock()

        with patch(
            "vulnsentinel.engines.dependency_scanner.scanner.shallow_clone",
            return_value=tmp_path,
        ):
            result = await scanner.run(session, project.id)

        assert result.skipped is False
        assert result.synced_count == 1
        assert result.deleted_count == 0
        assert len(result.scanned) == 1
        assert result.scanned[0].library_name == "zlib"

        library_service.upsert.assert_called_once_with(
            session,
            name="zlib",
            repo_url="https://github.com/madler/zlib.git",
        )
        dep_dao.batch_upsert.assert_called_once()
        dep_dao.delete_stale_scanner_deps.assert_called_once_with(
            session, project.id, {zlib_id}
        )
        project_dao.update.assert_called_once()

    @pytest.mark.anyio
    async def test_run_separates_resolved_and_unresolved(self, scanner_deps, tmp_path):
        scanner, project_dao, dep_dao, library_service = scanner_deps
        project = _fake_project()
        project_dao.get_by_id.return_value = project
        project_dao.update.return_value = project

        # Mix: requirements.txt (unresolved — no repo_url) + .gitmodules (resolved)
        (tmp_path / "requirements.txt").write_text("flask==2.0\n")
        (tmp_path / ".gitmodules").write_text(
            '[submodule "lib"]\n'
            "\turl = https://github.com/org/lib\n"
            "\tpath = lib\n"
        )

        lib_id = uuid.uuid4()
        library_service.upsert.return_value = _fake_library("lib", lib_id)
        dep_dao.batch_upsert.return_value = [AsyncMock()]
        dep_dao.delete_stale_scanner_deps.return_value = 0

        session = AsyncMock()

        with patch(
            "vulnsentinel.engines.dependency_scanner.scanner.shallow_clone",
            return_value=tmp_path,
        ):
            result = await scanner.run(session, project.id)

        # flask is unresolved (no repo_url), lib is resolved
        assert len(result.unresolved) == 1
        assert result.unresolved[0].library_name == "flask"
        assert result.synced_count == 1

    @pytest.mark.anyio
    async def test_run_project_not_found(self, scanner_deps):
        scanner, project_dao, dep_dao, library_service = scanner_deps
        project_dao.get_by_id.return_value = None
        session = AsyncMock()

        with pytest.raises(ValueError, match="not found"):
            await scanner.run(session, uuid.uuid4())

    @pytest.mark.anyio
    async def test_run_dedup_same_library_across_manifests(self, scanner_deps, tmp_path):
        """Same library in two manifests should produce one dep_row, not crash."""
        scanner, project_dao, dep_dao, library_service = scanner_deps
        project = _fake_project()
        project_dao.get_by_id.return_value = project
        project_dao.update.return_value = project

        # Same library referenced in both .gitmodules and Cargo.toml (git dep)
        (tmp_path / ".gitmodules").write_text(
            '[submodule "mylib"]\n'
            "\turl = https://github.com/org/mylib.git\n"
            "\tpath = mylib\n"
        )
        (tmp_path / "Cargo.toml").write_text(
            "[dependencies]\n"
            'mylib = { git = "https://github.com/org/mylib.git" }\n'
        )

        lib_id = uuid.uuid4()
        library_service.upsert.return_value = _fake_library("mylib", lib_id)
        dep_dao.batch_upsert.return_value = [AsyncMock()]
        dep_dao.delete_stale_scanner_deps.return_value = 0

        session = AsyncMock()

        with patch(
            "vulnsentinel.engines.dependency_scanner.scanner.shallow_clone",
            return_value=tmp_path,
        ):
            result = await scanner.run(session, project.id)

        # batch_upsert should receive exactly 1 row (deduped), not 2
        dep_dao.batch_upsert.assert_called_once()
        rows = dep_dao.batch_upsert.call_args[0][1]
        assert len(rows) == 1
        assert rows[0]["library_id"] == lib_id

    @pytest.mark.anyio
    async def test_run_uses_pinned_ref(self, scanner_deps, tmp_path):
        scanner, project_dao, dep_dao, library_service = scanner_deps
        project = _fake_project(pinned_ref="v1.0.0")
        project_dao.get_by_id.return_value = project
        project_dao.update.return_value = project

        # Empty repo — no manifests found
        dep_dao.batch_upsert.return_value = []
        dep_dao.delete_stale_scanner_deps.return_value = 0

        session = AsyncMock()

        with patch(
            "vulnsentinel.engines.dependency_scanner.scanner.shallow_clone",
            return_value=tmp_path,
        ) as mock_clone:
            await scanner.run(session, project.id)

        # Verify pinned_ref was passed to shallow_clone
        mock_clone.assert_called_once()
        call_args = mock_clone.call_args
        assert call_args[0][1] == "v1.0.0"
