from pathlib import Path
from typing import Any, Dict, List, Optional

from src.ingestion.cve_cleaner import as_bool, clean_value, select_high_value_cves


def _clean(value: Optional[str], max_chars: int = 4000) -> str:
    return clean_value(value, max_chars=max_chars)


def parse_cve_csv(
    filepath: str,
    limit: int = 2000,
    strategy: str = "high_value",
    min_score: int = 45,
) -> List[Dict[str, Any]]:
    """Convert quality-ranked CISA Vulnrichment records to RAG chunks."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"CVE CSV file not found at {filepath}")
    if limit <= 0:
        return []

    chunks: List[Dict[str, Any]] = []
    if strategy != "high_value":
        raise ValueError("Only the 'high_value' CVE selection strategy is supported")
    selected, _ = select_high_value_cves(filepath, limit=limit, min_score=min_score)
    for item in selected:
        row = item.row
        cve_id = _clean(row.get("cve_id"), 64)
        vendor = _clean(row.get("impacted_vendor"), 500)
        products = _clean(row.get("impacted_products"), 1500)
        versions = _clean(row.get("vulnerable_versions"), 2000)
        severity = _clean(row.get("base_severity"), 32).upper()
        cwe = _clean(row.get("cwe_number"), 128)
        cwe_description = _clean(row.get("cwe_description"), 2500)
        kev = as_bool(row.get("cisa_kev"))
        ssvc = _clean(row.get("ssvc_decision"), 64)

        text = (
            f"CISA Vulnrichment record {cve_id}\n"
            f"Vendor: {vendor}\nProducts: {products}\nVulnerable versions: {versions}\n"
            f"CVSS: {_clean(row.get('base_score'), 16)} ({severity})\n"
            f"Attack vector: {_clean(row.get('attack_vector'), 64)}; "
            f"attack complexity: {_clean(row.get('attack_complexity'), 64)}\n"
            f"CWE: {cwe} - {cwe_description}\n"
            f"Known Exploited Vulnerability: {kev}\nSSVC decision: {ssvc}"
        )
        chunks.append({
            "text": text,
            "metadata": {
                "source": "CISA_VULNRICHMENT",
                "cve": cve_id,
                "vendor": vendor,
                "products": products,
                "severity": severity,
                "cvss_score": _clean(row.get("base_score"), 16),
                "cwe_id": cwe,
                "known_exploited": kev,
                "ssvc_decision": ssvc,
                "published_date": _clean(row.get("published_date"), 32),
                "updated_date": _clean(row.get("updated_date"), 32),
                "quality_score": item.score,
                "quality_reasons": ";".join(item.reasons),
                "chunk_type": "cve_record",
            },
        })
    return chunks
