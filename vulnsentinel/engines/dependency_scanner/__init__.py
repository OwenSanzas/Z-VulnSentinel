"""Dependency scanner engine — detect project dependencies from manifests."""

from vulnsentinel.engines.dependency_scanner.models import ScannedDependency, ScanResult
from vulnsentinel.engines.dependency_scanner.scanner import DependencyScanner, scan

__all__ = ["DependencyScanner", "ScanResult", "ScannedDependency", "scan"]
