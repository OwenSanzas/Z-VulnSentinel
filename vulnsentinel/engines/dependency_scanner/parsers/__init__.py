"""Manifest parsers — auto-registered on import."""

from vulnsentinel.engines.dependency_scanner.parsers import (
    cargo_toml,  # noqa: F401
    cmake_find,  # noqa: F401
    conan,  # noqa: F401
    foundry_toml,  # noqa: F401
    git_submodule,  # noqa: F401
    go_mod,  # noqa: F401
    gradle_build,  # noqa: F401
    maven_pom,  # noqa: F401
    pip_requirements,  # noqa: F401
    pyproject_toml,  # noqa: F401
    vcpkg_json,  # noqa: F401
)
