"""Build a bounded vulnerability relationship graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import quote, urlencode

from sqlalchemy.ext.asyncio import AsyncSession

from vulpulse.db.models import Vulnerability
from vulpulse.db.repositories import VulnerabilityRepository

NodeType = Literal["vulnerability", "product", "cwe", "source"]
EdgeKind = Literal["affects", "classified_as", "reported_by"]


@dataclass(frozen=True)
class GraphNode:
    id: str
    type: NodeType
    label: str
    url: str | None = None
    risk_score: float | None = None
    risk_level: str | None = None
    severity: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    kind: EdgeKind


@dataclass(frozen=True)
class VulnGraph:
    center: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    truncated: bool


@dataclass(frozen=True)
class GraphResult:
    graph: VulnGraph
    vulnerability: Vulnerability


def _vulnerability_label(vulnerability: Vulnerability) -> str:
    return vulnerability.cve_id or vulnerability.title or f"VULN-{vulnerability.id}"


def _vulnerability_url(vulnerability: Vulnerability) -> str:
    return f"/vulns/{quote(vulnerability.cve_id or str(vulnerability.id), safe='')}"


def _vulnerability_node(vulnerability: Vulnerability, *, center: bool = False) -> GraphNode:
    return GraphNode(
        id=f"vuln:{vulnerability.id}",
        type="vulnerability",
        label=_vulnerability_label(vulnerability),
        url=_vulnerability_url(vulnerability),
        risk_score=vulnerability.risk_score,
        risk_level=vulnerability.risk_level,
        severity=vulnerability.severity,
        metadata={
            "cve_id": vulnerability.cve_id,
            "title": vulnerability.title,
            "center": center,
        },
    )


class GraphService:
    """Load a vulnerability and its immediate shared-context neighbourhood."""

    def __init__(self, session: AsyncSession) -> None:
        self.repository = VulnerabilityRepository(session)

    async def build(
        self,
        identifier: str,
        *,
        related_limit: int = 8,
        max_products: int = 8,
        max_cwes: int = 6,
        max_sources: int = 4,
    ) -> GraphResult | None:
        center = await self.repository.get_detail(identifier)
        if center is None:
            return None

        product_links = sorted(
            center.product_links,
            key=lambda link: (
                (link.product.vendor or "").casefold(),
                link.product.product.casefold(),
            ),
        )[:max_products]
        cwe_links = sorted(center.cwe_links, key=lambda link: link.cwe.id)[:max_cwes]
        source_records = sorted(
            center.source_records,
            key=lambda record: record.source.name.casefold(),
        )[:max_sources]
        truncated = (
            len(center.product_links) > len(product_links)
            or len(center.cwe_links) > len(cwe_links)
            or len(center.source_records) > len(source_records)
        )

        product_ids = [link.product_id for link in product_links]
        cwe_ids = [link.cwe_id for link in cwe_links]
        related: list[Vulnerability] = []
        if related_limit > 0 and (product_ids or cwe_ids):
            candidates = await self.repository.related_by_context(
                center.id,
                product_ids=product_ids,
                cwe_ids=cwe_ids,
                limit=related_limit + 1,
            )
            if len(candidates) > related_limit:
                truncated = True
            related = candidates[:related_limit]

        nodes: list[GraphNode] = [_vulnerability_node(center, center=True)]
        edges: list[GraphEdge] = []
        seen_nodes = {nodes[0].id}
        seen_edges: set[tuple[str, str, EdgeKind]] = set()

        def add_node(node: GraphNode) -> None:
            if node.id not in seen_nodes:
                seen_nodes.add(node.id)
                nodes.append(node)

        def add_edge(source: str, target: str, kind: EdgeKind) -> None:
            key = (source, target, kind)
            if key not in seen_edges:
                seen_edges.add(key)
                edges.append(GraphEdge(source=source, target=target, kind=kind))

        for product_link in product_links:
            product = product_link.product
            product_id = f"product:{product.id}"
            params = {"product": product.product}
            if product.vendor:
                params["vendor"] = product.vendor
            add_node(
                GraphNode(
                    id=product_id,
                    type="product",
                    label=(
                        f"{product.vendor} / {product.product}"
                        if product.vendor
                        else product.product
                    ),
                    url=f"/vulns?{urlencode(params)}",
                    metadata={
                        "vendor": product.vendor,
                        "product": product.product,
                        "version_range": product_link.version_range,
                    },
                )
            )
            add_edge(nodes[0].id, product_id, "affects")

        for cwe_link in cwe_links:
            cwe_id = f"cwe:{cwe_link.cwe.id}"
            add_node(
                GraphNode(
                    id=cwe_id,
                    type="cwe",
                    label=cwe_link.cwe.id,
                    metadata={"name": cwe_link.cwe.name},
                )
            )
            add_edge(nodes[0].id, cwe_id, "classified_as")

        for record in source_records:
            source_id = f"source:{record.source_id}"
            add_node(
                GraphNode(
                    id=source_id,
                    type="source",
                    label=record.source.name,
                    metadata={"kind": record.source.kind},
                )
            )
            add_edge(nodes[0].id, source_id, "reported_by")

        displayed_products = set(product_ids)
        displayed_cwes = set(cwe_ids)
        for candidate in related:
            candidate_id = f"vuln:{candidate.id}"
            add_node(_vulnerability_node(candidate))
            for product_link in candidate.product_links:
                if product_link.product_id in displayed_products:
                    add_edge(candidate_id, f"product:{product_link.product_id}", "affects")
            for cwe_link in candidate.cwe_links:
                if cwe_link.cwe_id in displayed_cwes:
                    add_edge(candidate_id, f"cwe:{cwe_link.cwe_id}", "classified_as")

        return GraphResult(
            graph=VulnGraph(
                center=nodes[0].id,
                nodes=nodes,
                edges=edges,
                truncated=truncated,
            ),
            vulnerability=center,
        )
