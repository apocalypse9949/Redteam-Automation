"""
MITRE ATT&CK Navigator Layer Exporter.
Exports engagement results as an ATT&CK Navigator JSON layer for visualization.
"""

import json
from pathlib import Path
from typing import Any

from redteam.core.attack_lifecycle import Engagement, StepStatus
from redteam.mitre.attack_map import ATTACK_TECHNIQUES


class NavigatorExporter:
    """Exports MITRE ATT&CK Navigator layers from engagement data."""

    NAVIGATOR_VERSION = "4.9"
    ATT_CK_VERSION = "14"

    # Color palette for technique scores
    COLORS = {
        0: "#ffffff",   # Not used
        1: "#66b1ff",   # Attempted but failed
        2: "#ffeb3b",   # Partially successful
        3: "#ff9800",   # Successful
        4: "#f44336",   # Critical finding
    }

    def export(self, engagement: Engagement, output_dir: Path) -> Path:
        """
        Export engagement as an ATT&CK Navigator layer JSON.

        Args:
            engagement: Completed engagement data.
            output_dir: Directory to write the layer file.

        Returns:
            Path to the generated JSON file.
        """
        techniques = self._build_technique_list(engagement)

        layer = {
            "name": f"RedTeam: {engagement.name}",
            "versions": {
                "attack": self.ATT_CK_VERSION,
                "navigator": self.NAVIGATOR_VERSION,
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": f"Attack techniques used in engagement {engagement.id}",
            "filters": {
                "platforms": ["Windows", "Linux", "macOS", "Network"]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
                "showAggregateScores": False,
                "countUnscored": False,
            },
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": list(self.COLORS.values()),
                "minValue": 0,
                "maxValue": 4,
            },
            "legendItems": [
                {"label": "Not Used", "color": self.COLORS[0]},
                {"label": "Attempted", "color": self.COLORS[1]},
                {"label": "Partial Success", "color": self.COLORS[2]},
                {"label": "Successful", "color": self.COLORS[3]},
                {"label": "Critical", "color": self.COLORS[4]},
            ],
            "metadata": [
                {"name": "engagement_id", "value": engagement.id},
                {"name": "start_time", "value": engagement.start_time},
                {"name": "end_time", "value": engagement.end_time or "In Progress"},
            ],
            "links": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
        }

        output_path = output_dir / "mitre_navigator_layer.json"
        with open(output_path, "w") as f:
            json.dump(layer, f, indent=2)

        return output_path

    def _build_technique_list(self, engagement: Engagement) -> list[dict]:
        """Build the techniques list with scores and comments."""
        technique_data: dict[str, dict] = {}

        for step in engagement.attack_steps:
            tid = step.technique_id
            if not tid or tid not in ATTACK_TECHNIQUES:
                continue

            if tid not in technique_data:
                technique_data[tid] = {
                    "techniqueID": tid,
                    "tactic": ATTACK_TECHNIQUES[tid]["tactic"].lower().replace(" ", "-"),
                    "score": 0,
                    "color": "",
                    "comment": "",
                    "enabled": True,
                    "metadata": [],
                    "links": [],
                    "showSubtechniques": False,
                }

            entry = technique_data[tid]

            # Score based on step status
            if step.status == StepStatus.SUCCESS:
                score = 4 if step.severity.value in ["critical", "high"] else 3
            elif step.status == StepStatus.FAILED:
                score = 1
            elif step.status == StepStatus.ERROR:
                score = 1
            else:
                score = 2

            entry["score"] = max(entry["score"], score)
            entry["color"] = self.COLORS.get(entry["score"], self.COLORS[0])

            # Build comment
            comment = f"[{step.status.value.upper()}] {step.action}"
            if entry["comment"]:
                entry["comment"] += f"\n{comment}"
            else:
                entry["comment"] = comment

            entry["metadata"].append({
                "name": "step_id",
                "value": step.id,
            })

        return list(technique_data.values())
