"""Custom exceptions for Z-Code-Analyzer-Station."""


class AnalyzerError(Exception):
    """Base exception for all analyzer errors."""


class AmbiguousFunctionError(AnalyzerError):
    """Raised when a function name matches multiple functions and no file_path is given."""

    def __init__(self, name: str, matching_files: list[str]):
        self.name = name
        self.matching_files = matching_files
        super().__init__(
            f"Ambiguous function '{name}' found in {len(matching_files)} files: "
            f"{matching_files}. Provide file_path to disambiguate."
        )


class SnapshotNotFoundError(AnalyzerError):
    """Raised when a referenced snapshot does not exist."""


class BackendNotFoundError(AnalyzerError):
    """Raised when no suitable backend is found for a language."""


class BuildError(AnalyzerError):
    """Raised when project build fails."""


class BitcodeError(AnalyzerError):
    """Raised when bitcode generation or linking fails."""


class SVFError(AnalyzerError):
    """Raised when SVF analysis fails."""
