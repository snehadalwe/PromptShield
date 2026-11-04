"""Attack Library Loader.

Loads, parses, and validates all audit test case YAML files.
"""

import os
from pathlib import Path
from typing import Optional
import yaml
from promptshield.attacks.models import AttackCase, Severity, OWASPMapping


class AttackLoader:
    """Discovers and parses audit test cases stored in YAML format."""

    def __init__(self, attacks_dir: Optional[Path] = None) -> None:
        if attacks_dir is None:
            # Default to current directory's attack folder
            self.attacks_dir = Path(__file__).parent
        else:
            self.attacks_dir = Path(attacks_dir)

    def load_all(self, category: Optional[str] = None) -> list[AttackCase]:
        """Loads all YAML test cases from the attacks directory."""
        cases: list[AttackCase] = []

        if not self.attacks_dir.exists():
            return cases

        # Iterate over all .yaml and .yml files in the attacks folder
        for file_path in sorted(self.attacks_dir.glob("*.yaml")) + sorted(self.attacks_dir.glob("*.yml")):
            loaded = self.load_file(file_path)
            cases.extend(loaded)

        if category and category.lower() != "all":
            filter_val = category.strip().lower()
            cases = [c for c in cases if c.category.lower() == filter_val or c.id.lower() == filter_val]

        return cases

    def load_file(self, file_path: Path) -> list[AttackCase]:
        """Parses a single YAML file into validated AttackCase objects."""
        cases: list[AttackCase] = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or not isinstance(data, list):
                return cases

            for item in data:
                try:
                    case = AttackCase(**item)
                    cases.append(case)
                except Exception as err:
                    print(f"[!] Warning: Skipping invalid attack case in {file_path.name}: {err}")
        except Exception as err:
            print(f"[!] Error loading attack file {file_path}: {err}")

        return cases

    def list_categories(self) -> list[str]:
        """Returns unique categories available in the library."""
        all_cases = self.load_all()
        return sorted(list(set(c.category for c in all_cases)))
