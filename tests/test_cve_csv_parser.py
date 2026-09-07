import csv

import pytest

from src.ingestion.cve_csv_parser import parse_cve_csv


FIELDS = [
    "cve_id", "published_date", "cisa_kev", "base_score", "base_severity",
    "attack_vector", "attack_complexity", "impacted_vendor", "impacted_products",
    "vulnerable_versions", "cwe_number", "cwe_description", "ssvc_decision",
]


def test_parse_cve_csv_limit_and_metadata(tmp_path):
    path = tmp_path / "cves.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for index in range(3):
            writer.writerow({
                "cve_id": f"CVE-2026-{index:04d}", "published_date": "2026-01-01",
                "cisa_kev": "True", "base_score": "9.8", "base_severity": "critical",
                "attack_vector": "NETWORK", "attack_complexity": "LOW",
                "impacted_vendor": "Example Controls", "impacted_products": "Example PLC",
                "vulnerable_versions": "1.0", "cwe_number": "CWE-78",
                "cwe_description": "Command injection", "ssvc_decision": "Act",
            })

    chunks = parse_cve_csv(str(path), limit=2)

    assert len(chunks) == 2
    assert chunks[0]["metadata"]["source"] == "CISA_VULNRICHMENT"
    assert chunks[0]["metadata"]["known_exploited"] is True
    assert chunks[0]["metadata"]["severity"] == "CRITICAL"
    assert "Example PLC" in chunks[0]["text"]


def test_parse_cve_csv_rejects_missing_columns(tmp_path):
    path = tmp_path / "invalid.csv"
    path.write_text("cve_id\nCVE-2026-0001\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing required columns"):
        parse_cve_csv(str(path))
