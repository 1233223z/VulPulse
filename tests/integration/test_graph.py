from __future__ import annotations

from httpx import AsyncClient

from vulpulse.db.repositories import VulnerabilityRepository
from vulpulse.db.session import Database
from vulpulse.timeutils import utcnow


async def add_related_vulnerability(db: Database) -> None:
    async with db.session() as session:
        repository = VulnerabilityRepository(session)
        related, _ = await repository.upsert(
            "cve:CVE-2024-0003",
            cve_id="CVE-2024-0003",
            title="Related Struts issue",
            description="A second Struts vulnerability.",
            severity="high",
            risk_score=70.0,
            risk_level="high",
            published_at=utcnow(),
        )
        product = await repository.get_or_create_product("apache", "struts")
        await repository.link_product(related, product)
        cwe = await repository.get_or_create_cwe("CWE-79")
        await repository.link_cwe(related, cwe)
        await session.commit()


async def test_graph_api_includes_center_context(client: AsyncClient) -> None:
    response = await client.get("/api/v1/vulns/CVE-2024-0001/graph")

    assert response.status_code == 200
    data = response.json()
    assert data["center"].startswith("vuln:")
    assert data["truncated"] is False
    labels = {node["label"] for node in data["nodes"]}
    assert "apache / struts" in labels
    assert "CWE-79" in labels
    assert "nvd" in labels
    edge_kinds = {edge["kind"] for edge in data["edges"]}
    assert edge_kinds == {"affects", "classified_as", "reported_by"}


async def test_graph_api_includes_related_vulnerabilities(
    client: AsyncClient,
    db: Database,
) -> None:
    await add_related_vulnerability(db)

    response = await client.get("/api/v1/vulns/CVE-2024-0001/graph")

    assert response.status_code == 200
    data = response.json()
    labels = {node["label"] for node in data["nodes"]}
    assert "CVE-2024-0003" in labels
    related_id = next(node["id"] for node in data["nodes"] if node["label"] == "CVE-2024-0003")
    assert any(edge["source"] == related_id for edge in data["edges"])
    assert any(
        edge["source"] == related_id and edge["kind"] == "classified_as" for edge in data["edges"]
    )


async def test_graph_api_respects_related_limit(
    client: AsyncClient,
    db: Database,
) -> None:
    await add_related_vulnerability(db)

    response = await client.get("/api/v1/vulns/CVE-2024-0001/graph", params={"related": 0})

    assert response.status_code == 200
    labels = {node["label"] for node in response.json()["nodes"]}
    assert "CVE-2024-0003" not in labels


async def test_graph_api_not_found(client: AsyncClient) -> None:
    response = await client.get("/api/v1/vulns/CVE-9999-9999/graph")

    assert response.status_code == 404


async def test_graph_web_page(client: AsyncClient) -> None:
    response = await client.get("/vulns/CVE-2024-0001/graph")

    assert response.status_code == 200
    assert "Relationship graph" in response.text
    assert "apache / struts" in response.text
    assert "CWE-79" in response.text
    assert "nvd" in response.text
    assert "<svg" in response.text
    assert "graph-node-center" in response.text


async def test_graph_web_page_without_relations(client: AsyncClient) -> None:
    response = await client.get("/vulns/CVE-2024-0002/graph")

    assert response.status_code == 200
    assert "No related products" in response.text
    assert "No related vulnerabilities" in response.text


async def test_graph_web_page_not_found(client: AsyncClient) -> None:
    response = await client.get("/vulns/CVE-9999-9999/graph")

    assert response.status_code == 404
