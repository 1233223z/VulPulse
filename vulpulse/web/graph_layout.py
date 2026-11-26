"""Deterministic SVG layout for the vulnerability relationship graph."""

from __future__ import annotations

import math
from dataclasses import dataclass

from vulpulse.graph import GraphNode, VulnGraph

WIDTH = 1000
HEIGHT = 700
CENTER_X = WIDTH / 2
CENTER_Y = HEIGHT / 2

_RING_SPECS: dict[str, tuple[float, float]] = {
    "source": (90.0, math.pi / 2),
    "product": (165.0, -math.pi / 2),
    "cwe": (235.0, 0.0),
    "vulnerability": (305.0, math.pi),
}
_RADII = {
    "vulnerability": 20.0,
    "product": 15.0,
    "cwe": 13.0,
    "source": 12.0,
}


@dataclass(frozen=True)
class LayoutNode:
    id: str
    type: str
    label: str
    tooltip: str
    url: str | None
    risk_level: str | None
    x: float
    y: float
    radius: float
    center: bool
    css_class: str


@dataclass(frozen=True)
class LayoutEdge:
    source: str
    target: str
    kind: str
    x1: float
    y1: float
    x2: float
    y2: float
    css_class: str


@dataclass(frozen=True)
class GraphLayout:
    nodes: list[LayoutNode]
    edges: list[LayoutEdge]
    width: int
    height: int


def _shorten(value: str, limit: int) -> str:
    value = value.strip()
    return value if len(value) <= limit else f"{value[: limit - 1]}…"


def _tooltip(node: GraphNode) -> str:
    if node.type == "vulnerability":
        details = [f"Vulnerability {node.label}"]
        title = node.metadata.get("title")
        if title:
            details.append(str(title))
        if node.risk_score is not None:
            details.append(f"risk {node.risk_score:.1f} ({node.risk_level or 'unscored'})")
        return " · ".join(details)
    if node.type == "product":
        return f"Product {node.label}"
    if node.type == "cwe":
        name = node.metadata.get("name")
        return f"Weakness {node.label}" + (f" · {name}" if name else "")
    return f"Source {node.label}"


def layout_graph(graph: VulnGraph) -> GraphLayout:
    positions: dict[str, tuple[float, float]] = {}
    nodes: list[LayoutNode] = []

    for node in graph.nodes:
        if node.id == graph.center:
            x, y = CENTER_X, CENTER_Y
            radius = 32.0
            center = True
        else:
            radius_spec, start_angle = _RING_SPECS.get(node.type, (305.0, 0.0))
            peers = [
                peer for peer in graph.nodes if peer.id != graph.center and peer.type == node.type
            ]
            index = next(
                (position for position, peer in enumerate(peers) if peer.id == node.id),
                0,
            )
            angle = start_angle + (2 * math.pi * index / len(peers) if peers else 0)
            x = CENTER_X + radius_spec * math.cos(angle)
            y = CENTER_Y + radius_spec * math.sin(angle)
            radius = _RADII.get(node.type, 14.0)
            center = False

        positions[node.id] = (x, y)
        css_class = f"graph-node graph-node-{node.type}"
        if center:
            css_class += " graph-node-center"
        elif node.risk_level:
            css_class += f" graph-risk-{node.risk_level}"
        nodes.append(
            LayoutNode(
                id=node.id,
                type=node.type,
                label=_shorten(node.label, 30 if center else 24),
                tooltip=_tooltip(node),
                url=node.url,
                risk_level=node.risk_level,
                x=round(x, 2),
                y=round(y, 2),
                radius=radius,
                center=center,
                css_class=css_class,
            )
        )

    edges: list[LayoutEdge] = []
    for edge in graph.edges:
        source = positions.get(edge.source)
        target = positions.get(edge.target)
        if source is None or target is None:
            continue
        edges.append(
            LayoutEdge(
                source=edge.source,
                target=edge.target,
                kind=edge.kind,
                x1=round(source[0], 2),
                y1=round(source[1], 2),
                x2=round(target[0], 2),
                y2=round(target[1], 2),
                css_class=f"graph-edge graph-edge-{edge.kind}",
            )
        )

    return GraphLayout(nodes=nodes, edges=edges, width=WIDTH, height=HEIGHT)
