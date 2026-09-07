import csv

from src.ingestion.cve_cleaner import score_cve, select_high_value_cves


FIELDS = [
    "cve_id", "published_date", "updated_date", "cisa_kev", "base_score",
    "base_severity", "attack_vector", "attack_complexity", "impacted_vendor",
    "impacted_products", "vulnerable_versions", "cwe_number", "cwe_description",
    "ssvc_decision",
]


def _row(**overrides):
    row = {
        "cve_id": "CVE-2026-12345", "published_date": "2026-01-01",
        "updated_date": "2026-02-01", "cisa_kev": "False", "base_score": "9.8",
        "base_severity": "CRITICAL", "attack_vector": "NETWORK",
        "attack_complexity": "LOW", "impacted_vendor": "Siemens",
        "impacted_products": "SIMATIC PLC", "vulnerable_versions": "<2.0",
        "cwe_number": "CWE-78", "cwe_description": "Command injection",
        "ssvc_decision": "Act",
    }
    row.update(overrides)
    return row


def test_score_cve_rewards_explainable_ot_signals():
    scored = score_cve(_row(), reference_year=2026)
    assert scored.score >= 80
    assert "ics_vendor" in scored.reasons
    assert "ics_terminology" in scored.reasons
    assert "ssvc_act" in scored.reasons


def test_selector_scans_all_rows_and_drops_generic_cves(tmp_path):
    path = tmp_path / "cves.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerow(_row(cve_id="CVE-2026-10001", impacted_vendor="Generic Web Co", impacted_products="Web portal"))
        writer.writerow(_row(cve_id="CVE-2026-10002", impacted_vendor="Rockwell Automation", impacted_products="ControlLogix PLC"))
    selected, report = select_high_value_cves(str(path), limit=10, reference_year=2026)
    assert [item.row["cve_id"] for item in selected] == ["CVE-2026-10002"]
    assert report["source_rows"] == 2
    assert report["selected_rows"] == 1
