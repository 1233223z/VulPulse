from __future__ import annotations

import gzip

from vulpulse.enrich.epss import decode_scores, parse_scores

CSV_TEXT = """#model_version:v2024.01.01,score_date:2024-01-01T00:00:00Z
cve,epss,percentile
CVE-2024-0001,0.42,0.97
CVE-2024-0002,0.01,0.50
CVE-2024-9999,0.90,0.99
"""


def test_parse_scores_filters_to_wanted_cves() -> None:
    rows = list(parse_scores(CSV_TEXT, {"CVE-2024-0001", "CVE-2024-0002"}))

    assert len(rows) == 2
    assert rows[0] == {
        "b_cve_id": "CVE-2024-0001",
        "b_epss_score": 0.42,
        "b_epss_percentile": 0.97,
    }
    assert rows[1]["b_cve_id"] == "CVE-2024-0002"


def test_parse_scores_skips_invalid_values() -> None:
    text = "cve,epss,percentile\nCVE-2024-0001,not-a-number,0.5\n"

    assert list(parse_scores(text, {"CVE-2024-0001"})) == []


def test_decode_scores_handles_gzip_and_plain_text() -> None:
    encoded = CSV_TEXT.encode()

    assert decode_scores(gzip.compress(encoded)) == CSV_TEXT
    assert decode_scores(encoded) == CSV_TEXT
