"""Parser for Maven pom.xml files."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from vulnsentinel.engines.dependency_scanner.models import ScannedDependency
from vulnsentinel.engines.dependency_scanner.registry import register_parser

_NS = "{http://maven.apache.org/POM/4.0.0}"


_PROP_RE = re.compile(r"\$\{([^}]+)\}")


def _resolve_props(value: str, props: dict[str, str]) -> str:
    """Replace ${property} placeholders with values from <properties>."""

    def _replace(m: re.Match) -> str:
        key = m.group(1)
        return props.get(key, m.group(0))  # keep original if not found

    return _PROP_RE.sub(_replace, value)


def _text(element: ET.Element | None) -> str | None:
    if element is None:
        return None
    return element.text.strip() if element.text else None


class MavenPomParser:
    detection_method = "maven-pom"
    file_patterns = ["**/pom.xml"]

    def parse(self, file_path: Path, content: str) -> list[ScannedDependency]:
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return []

        # Collect <properties> for ${...} substitution
        props = self._extract_properties(root)

        deps: list[ScannedDependency] = []

        # Try both namespaced and non-namespaced
        for ns in (_NS, ""):
            for dep_el in root.iter(f"{ns}dependency"):
                group_id = _text(dep_el.find(f"{ns}groupId"))
                artifact_id = _text(dep_el.find(f"{ns}artifactId"))
                version = _text(dep_el.find(f"{ns}version"))

                if not artifact_id:
                    continue

                # Resolve ${property} placeholders
                if version:
                    version = _resolve_props(version, props)

                name = f"{group_id}:{artifact_id}" if group_id else artifact_id

                deps.append(
                    ScannedDependency(
                        library_name=name,
                        library_repo_url=None,
                        constraint_expr=version,
                        resolved_version=version,
                        source_file=file_path.name,
                        detection_method=self.detection_method,
                    )
                )

        return deps

    @staticmethod
    def _extract_properties(root: ET.Element) -> dict[str, str]:
        """Extract <properties> key-value pairs from the POM root."""
        props: dict[str, str] = {}
        for ns in (_NS, ""):
            props_el = root.find(f"{ns}properties")
            if props_el is not None:
                for child in props_el:
                    # Strip namespace from tag name
                    tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if child.text:
                        props[tag] = child.text.strip()
        return props


register_parser(MavenPomParser())
