"""Abstract base class interface for sqlilab security audit reporters."""

from abc import ABC, abstractmethod

from sqlilab.models.query import QueryAuditResult


class BaseReporter(ABC):
    """Abstract reporter producing formatted audit output."""

    @abstractmethod
    def generate(self, result: QueryAuditResult) -> str:
        """Render a single QueryAuditResult into the designated output format string."""

    @abstractmethod
    def generate_batch(self, results: list[QueryAuditResult]) -> str:
        """Render a list of QueryAuditResults into the designated output format string."""
