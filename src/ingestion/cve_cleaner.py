"""Quality-aware selection for the CISA Vulnrichment CSV export.

The upstream file is a broad CVE corpus.  SecureOps is an OT/ICS assistant, so
indexing the first N physical rows produces an old and mostly irrelevant sample.
This module scans the complete CSV, removes unusable/duplicate rows, assigns an
explainable quality score, and keeps only records with an OT/ICS signal.
"""

from __future__ import annotations

import csv
import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


CSV_FIELD_LIMIT = 2_147_483_647
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Deliberately specific names. Broad vendors such as Microsoft or Cisco are not
# sufficient by themselves to classify a vulnerability as industrial.
ICS_VENDORS = {
    "abb", "advantech", "allen-bradley", "automationdirect", "aveva",
    "beckhoff", "codesys", "danelec", "delta electronics", "emerson",
    "festo", "ge digital", "ge industrial", "ge vernova", "hitachi energy",
    "honeywell", "inductive automation", "johnson controls", "kuka",
    "mitsubishi electric", "moxa", "omron", "phoenix contact", "pro-face",
    "prosoft technology", "rockwell automation", "schneider electric",
    "schweitzer engineering laboratories", "sel", "siemens", "trane",
    "weintek", "yokogawa",
}

ICS_TERMS = {
    "bacnet", "building automation", "codesys", "control system", "dcs",
    "distributed control system", "ethernet/ip", "factorytalk", "firmware",
    "hmi", "human machine interface", "industrial automation",
    "industrial control", "industrial edge", "modbus", "operational technology",
    "opc ua", "plc", "process control", "profinet", "programmable logic",
    "remote terminal unit", "rtu", "safety instrumented", "scada",
    "simatic", "substation", "telecontrol",
}

MISSING_VALUES = {"", "n/a", "na", "none", "null", "unknown", "nan"}


def clean_value(value: Any, max_chars: int = 4000, missing: str = "Unknown") -> str:
    text = " ".join(str(value or "").split())
    return missing if text.lower() in MISSING_VALUES else text[:max_chars]


def as_bool(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def _parse_year(value: Any) -> Optional[int]:
    match = re.match(r"(\d{4})", str(value or ""))
    return int(match.group(1)) if match else None


def _has_phrase(text: str, phrase: str) -> bool:
    if len(phrase) <= 3:
        return re.search(rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])", text) is not None
    return phrase in text


def industrial_signals(row: Mapping[str, Any]) -> Tuple[List[str], List[str]]:
    vendor = clean_value(row.get("impacted_vendor"), missing="").lower()
    searchable = " ".join(
        clean_value(row.get(field), missing="").lower()
        for field in ("impacted_vendor", "impacted_products", "cwe_description")
    )
    vendors = sorted(v for v in ICS_VENDORS if _has_phrase(vendor, v))
    terms = sorted(t for t in ICS_TERMS if _has_phrase(searchable, t))
    return vendors, terms


@dataclass(frozen=True)
class ScoredCVE:
    row: Dict[str, str]
    score: int
    reasons: Tuple[str, ...]


def score_cve(row: Mapping[str, Any], reference_year: Optional[int] = None) -> ScoredCVE:
    """Score one record using auditable, deterministic criteria (0-100)."""
    reference_year = reference_year or datetime.now(timezone.utc).year
    normalized = {str(k): "" if v is None else str(v) for k, v in row.items()}
    vendors, terms = industrial_signals(row)
    reasons: List[str] = []
    score = 0

    if vendors:
        score += 35
        reasons.append("ics_vendor")
    if terms:
        score += min(25, 10 + 5 * min(len(terms), 3))
        reasons.append("ics_terminology")
    if as_bool(row.get("cisa_kev")):
        score += 15
        reasons.append("known_exploited")

    severity = clean_value(row.get("base_severity"), 32, "").upper()
    severity_points = {"CRITICAL": 12, "HIGH": 8, "MEDIUM": 3, "LOW": 0}
    score += severity_points.get(severity, 0)
    if severity in severity_points:
        reasons.append(f"severity_{severity.lower()}")

    if clean_value(row.get("attack_vector"), 32, "").upper() in {"NETWORK", "ADJACENT_NETWORK"}:
        score += 5
        reasons.append("remotely_reachable")

    ssvc = clean_value(row.get("ssvc_decision"), 32, "").lower()
    if ssvc == "act":
        score += 8
        reasons.append("ssvc_act")
    elif ssvc == "attend":
        score += 5
        reasons.append("ssvc_attend")

    complete_fields = ("impacted_vendor", "impacted_products", "vulnerable_versions", "cwe_number")
    completeness = sum(bool(clean_value(row.get(field), missing="")) for field in complete_fields)
    score += completeness * 2
    if completeness == len(complete_fields):
        reasons.append("complete_record")

    year = _parse_year(row.get("published_date"))
    if year is not None:
        age = max(0, reference_year - year)
        if age <= 2:
            score += 7
            reasons.append("recent_2y")
        elif age <= 5:
            score += 4
            reasons.append("recent_5y")

    return ScoredCVE(normalized, min(score, 100), tuple(reasons))


def select_high_value_cves(
    filepath: str,
    limit: int = 2000,
    min_score: int = 45,
    reference_year: Optional[int] = None,
) -> Tuple[List[ScoredCVE], Dict[str, Any]]:
    """Scan all rows and return the highest-value OT/ICS records plus statistics."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"CVE CSV file not found at {filepath}")
    if limit <= 0:
        return [], {"source_rows": 0, "selected_rows": 0}

    csv.field_size_limit(CSV_FIELD_LIMIT)
    source_rows = invalid_rows = duplicate_rows = generic_rows = 0
    best_by_cve: Dict[str, ScoredCVE] = {}
    required = {"cve_id", "impacted_vendor", "impacted_products", "base_severity"}

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = required.difference(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CVE CSV is missing required columns: {', '.join(sorted(missing))}")
        for row in reader:
            source_rows += 1
            cve_id = clean_value(row.get("cve_id"), 64, "").upper()
            if not CVE_PATTERN.match(cve_id):
                invalid_rows += 1
                continue
            scored = score_cve(row, reference_year=reference_year)
            # OT relevance is mandatory; severity alone cannot admit generic CVEs.
            if not ({"ics_vendor", "ics_terminology"} & set(scored.reasons)) or scored.score < min_score:
                generic_rows += 1
                continue
            previous = best_by_cve.get(cve_id)
            if previous is not None:
                duplicate_rows += 1
            if previous is None or (scored.score, row.get("updated_date", "")) > (
                previous.score,
                previous.row.get("updated_date", ""),
            ):
                best_by_cve[cve_id] = scored

    selected = sorted(
        best_by_cve.values(),
        key=lambda item: (
            item.score,
            item.row.get("published_date", ""),
            item.row.get("cve_id", ""),
        ),
        reverse=True,
    )[:limit]

    severity = Counter(clean_value(x.row.get("base_severity"), 32).upper() for x in selected)
    years = Counter(str(_parse_year(x.row.get("published_date")) or "Unknown") for x in selected)
    vendors = Counter(clean_value(x.row.get("impacted_vendor"), 200) for x in selected)
    report: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": path.name,
        "strategy": "full_scan_ot_relevance_then_quality_rank",
        "minimum_score": min_score,
        "requested_limit": limit,
        "source_rows": source_rows,
        "invalid_rows": invalid_rows,
        "duplicate_rows": duplicate_rows,
        "excluded_non_ot_or_low_quality": generic_rows,
        "eligible_unique_rows": len(best_by_cve),
        "selected_rows": len(selected),
        "known_exploited_selected": sum(as_bool(x.row.get("cisa_kev")) for x in selected),
        "severity_distribution": dict(severity.most_common()),
        "publication_year_distribution": dict(sorted(years.items(), reverse=True)),
        "top_vendors": dict(vendors.most_common(15)),
        "score": {
            "minimum": min((x.score for x in selected), default=0),
            "maximum": max((x.score for x in selected), default=0),
            "average": round(sum(x.score for x in selected) / len(selected), 2) if selected else 0,
        },
    }
    return selected, report


def write_clean_dataset(
    selected: Sequence[ScoredCVE],
    report: Mapping[str, Any],
    csv_output: str,
    json_report_output: str,
    markdown_report_output: Optional[str] = None,
) -> None:
    csv_path = Path(csv_output)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(selected[0].row) if selected else ["cve_id"]
    fieldnames += ["quality_score", "quality_reasons"]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in selected:
            writer.writerow({**item.row, "quality_score": item.score, "quality_reasons": ";".join(item.reasons)})

    report_path = Path(json_report_output)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    if markdown_report_output:
        md_path = Path(markdown_report_output)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# CVE data quality report",
            "",
            f"Generated: `{report.get('generated_at', '')}`",
            "",
            "| Measure | Value |",
            "|---|---:|",
            f"| Source rows scanned | {report.get('source_rows', 0)} |",
            f"| Invalid rows | {report.get('invalid_rows', 0)} |",
            f"| Duplicate rows | {report.get('duplicate_rows', 0)} |",
            f"| Excluded non-OT/low-quality rows | {report.get('excluded_non_ot_or_low_quality', 0)} |",
            f"| Eligible unique OT rows | {report.get('eligible_unique_rows', 0)} |",
            f"| Selected rows | {report.get('selected_rows', 0)} |",
            f"| Selected KEV rows | {report.get('known_exploited_selected', 0)} |",
            f"| Mean quality score | {report.get('score', {}).get('average', 0)} |",
            "",
            "The selector requires an explicit OT/ICS signal and then ranks records by "
            "KEV status, CVSS severity, network reachability, SSVC decision, metadata "
            "completeness, and publication recency.",
        ]
        md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
