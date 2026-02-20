"""Parser for Maven pom.xml files."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from vulnsentinel.engines.dependency_scanner.models import ScannedDependency
from vulnsentinel.engines.dependency_scanner.registry import register_parser

_NS = "{http://maven.apache.org/POM/4.0.0}"


def _text(element: ET.Element | None) -> str | None:
    if element is None:
        return None
    return element.text.strip() if element.text else None


class MavenPomParser:
    detection_method = "maven-pom"
    file_patterns = ["pom.xml"]

    def parse(self, file_path: Path, content: str) -> list[ScannedDependency]:
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return []

        deps: list[ScannedDependency] = []

        # Try both namespaced and non-namespaced
        for ns in (_NS, ""):
            for dep_el in root.iter(f"{ns}dependency"):
                group_id = _text(dep_el.find(f"{ns}groupId"))
                artifact_id = _text(dep_el.find(f"{ns}artifactId"))
                version = _text(dep_el.find(f"{ns}version"))

                if not artifact_id:
                    continue

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


register_parser(MavenPomParser())
