"""Dependency scanner engine — detect project dependencies from manifests."""

from vulnsentinel.engines.dependency_scanner.models import ScanResult, ScannedDependency
from vulnsentinel.engines.dependency_scanner.scanner import DependencyScanner

__all__ = ["DependencyScanner", "ScanResult", "ScannedDependency"]
