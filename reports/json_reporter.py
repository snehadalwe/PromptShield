"""JSON Report Generator for PromptShield.

Exports scan results to structured JSON for CI/CD and automated ingestion.
"""

from pathlib import Path
from promptshield.scoring.models import ScanSummary


class JsonReporter:
    """Generates machine-readable JSON reports."""

    @staticmethod
    def generate(summary: ScanSummary, output_path: Path) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        json_data = summary.model_dump_json(indent=2)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_data)

        return output_path
