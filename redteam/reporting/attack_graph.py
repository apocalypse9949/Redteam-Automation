"""
Attack Graph Builder.
Generates attack path visualizations using NetworkX.

Exports to JSON (for D3.js), DOT (for Graphviz), and PNG.
"""

import json
import logging
from pathlib import Path
from typing import Any

import networkx as nx

from redteam.core.attack_lifecycle import Engagement, AttackPhase, StepStatus


logger = logging.getLogger("redteam.reporting.attack_graph")

# Phase colors for visualization
PHASE_COLORS = {
    AttackPhase.INIT: "#6c757d",
    AttackPhase.RECON: "#17a2b8",
    AttackPhase.SCANNING: "#007bff",
    AttackPhase.ENUMERATION: "#6610f2",
    AttackPhase.EXPLOITATION: "#dc3545",
    AttackPhase.PRIV_ESCALATION: "#fd7e14",
    AttackPhase.LATERAL_MOVEMENT: "#e83e8c",
    AttackPhase.PERSISTENCE: "#ffc107",
    AttackPhase.CREDENTIAL_ACCESS: "#20c997",
    AttackPhase.EXFILTRATION: "#343a40",
    AttackPhase.REPORTING: "#28a745",
    AttackPhase.COMPLETE: "#6c757d",
}


class AttackGraphBuilder:
    """Builds attack path graphs from engagement data."""

    def build_and_export(self, engagement: Engagement, output_dir: Path) -> Path:
        """
        Build the attack graph and export to multiple formats.
        
        Returns:
            Path to the JSON export file.
        """
        G = self._build_graph(engagement)

        # Export as JSON for D3.js
        json_path = output_dir / "attack_graph.json"
        self._export_json(G, json_path, engagement)

        # Export as DOT for Graphviz
        dot_path = output_dir / "attack_graph.dot"
        self._export_dot(G, dot_path)

        # Try to export as PNG
        try:
            png_path = output_dir / "attack_graph.png"
            self._export_png(G, png_path)
        except Exception as e:
            logger.warning(f"PNG export failed (matplotlib may not be available): {e}")

        logger.info(f"Attack graph exported to {output_dir}")
        return json_path

    def _build_graph(self, engagement: Engagement) -> nx.DiGraph:
        """Build a directed graph from attack steps."""
        G = nx.DiGraph()

        # Add attacker node
        G.add_node("attacker", label="Attacker", type="attacker",
                    color="#dc3545", phase="init")

        # Add target nodes
        for ip, target in engagement.targets.items():
            status = "compromised" if target.compromised else "discovered"
            color = "#dc3545" if target.compromised else "#17a2b8"
            G.add_node(ip, label=f"{ip}\n{target.os}",
                       type="target", status=status, color=color,
                       os=target.os, access_level=target.access_level)

        # Add attack step edges
        prev_node = "attacker"
        phases_seen = set()

        for step in engagement.attack_steps:
            if step.status in [StepStatus.SUCCESS, StepStatus.ERROR]:
                step_id = f"{step.module}_{step.id}"
                G.add_node(step_id,
                           label=f"{step.technique_name or step.module}\n{step.action[:40]}",
                           type="step",
                           phase=step.phase.value,
                           technique_id=step.technique_id,
                           status=step.status.value,
                           severity=step.severity.value,
                           color=PHASE_COLORS.get(step.phase, "#6c757d"))

                # Connect to target
                if step.target and step.target in G.nodes:
                    G.add_edge(step_id, step.target,
                               label=step.technique_id,
                               phase=step.phase.value)

                # Connect from previous phase or attacker
                if step.phase not in phases_seen:
                    G.add_edge(prev_node, step_id,
                               label=step.phase.value,
                               phase=step.phase.value)
                    phases_seen.add(step.phase)

                prev_node = step_id

        return G

    def _export_json(self, G: nx.DiGraph, path: Path, engagement: Engagement):
        """Export graph as JSON for D3.js force-directed visualization."""
        nodes = []
        for node_id, data in G.nodes(data=True):
            nodes.append({
                "id": node_id,
                "label": data.get("label", node_id),
                "type": data.get("type", "unknown"),
                "color": data.get("color", "#6c757d"),
                "phase": data.get("phase", ""),
                "status": data.get("status", ""),
                "severity": data.get("severity", ""),
                "technique_id": data.get("technique_id", ""),
            })

        links = []
        for source, target, data in G.edges(data=True):
            links.append({
                "source": source,
                "target": target,
                "label": data.get("label", ""),
                "phase": data.get("phase", ""),
            })

        graph_data = {
            "nodes": nodes,
            "links": links,
            "metadata": {
                "engagement_id": engagement.id,
                "name": engagement.name,
                "total_steps": len(engagement.attack_steps),
                "total_targets": len(engagement.targets),
                "compromised": len(engagement.get_compromised_targets()),
                "techniques_used": list(engagement.mitre_techniques_used),
            },
        }

        with open(path, "w") as f:
            json.dump(graph_data, f, indent=2)

    def _export_dot(self, G: nx.DiGraph, path: Path):
        """Export graph as DOT format for Graphviz."""
        lines = ["digraph AttackGraph {"]
        lines.append('  rankdir=LR;')
        lines.append('  bgcolor="#1a1a2e";')
        lines.append('  node [style=filled, fontcolor=white, fontname="Helvetica"];')
        lines.append('  edge [fontcolor="#aaaaaa", fontname="Helvetica", fontsize=10];')
        lines.append("")

        for node_id, data in G.nodes(data=True):
            label = data.get("label", node_id).replace("\n", "\\n")
            color = data.get("color", "#6c757d")
            shape = "doublecircle" if data.get("type") == "attacker" else \
                    "box" if data.get("type") == "target" else "ellipse"
            safe_id = node_id.replace("-", "_").replace(".", "_")
            lines.append(f'  {safe_id} [label="{label}", fillcolor="{color}", shape={shape}];')

        lines.append("")

        for source, target, data in G.edges(data=True):
            label = data.get("label", "")
            safe_source = source.replace("-", "_").replace(".", "_")
            safe_target = target.replace("-", "_").replace(".", "_")
            lines.append(f'  {safe_source} -> {safe_target} [label="{label}"];')

        lines.append("}")

        with open(path, "w") as f:
            f.write("\n".join(lines))

    def _export_png(self, G: nx.DiGraph, path: Path):
        """Export graph as PNG image using matplotlib."""
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(1, 1, figsize=(20, 12))
        fig.patch.set_facecolor("#1a1a2e")
        ax.set_facecolor("#1a1a2e")

        pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

        # Draw nodes
        node_colors = [G.nodes[n].get("color", "#6c757d") for n in G.nodes()]
        node_sizes = [2000 if G.nodes[n].get("type") == "target" else
                      2500 if G.nodes[n].get("type") == "attacker" else 1200
                      for n in G.nodes()]

        nx.draw_networkx_nodes(G, pos, node_color=node_colors,
                                node_size=node_sizes, alpha=0.9, ax=ax)

        # Draw edges
        nx.draw_networkx_edges(G, pos, edge_color="#555555",
                                arrows=True, arrowsize=20,
                                connectionstyle="arc3,rad=0.1", ax=ax)

        # Draw labels
        labels = {n: G.nodes[n].get("label", n).split("\n")[0] for n in G.nodes()}
        nx.draw_networkx_labels(G, pos, labels, font_size=8,
                                 font_color="white", ax=ax)

        ax.set_title("Attack Path Graph", fontsize=16, color="white", pad=20)
        ax.axis("off")

        plt.tight_layout()
        plt.savefig(path, dpi=150, bbox_inches="tight",
                    facecolor="#1a1a2e", edgecolor="none")
        plt.close()

        logger.info(f"Attack graph PNG saved to {path}")
