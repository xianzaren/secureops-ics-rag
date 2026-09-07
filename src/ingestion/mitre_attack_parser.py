"""Parser for the official MITRE ATT&CK for ICS Excel workbook."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List

import pandas as pd


ENTITY_SHEETS = (
    "techniques",
    "tactics",
    "software",
    "groups",
    "campaigns",
    "assets",
    "mitigations",
    "datacomponents",
    "analytics",
    "detectionstrategies",
)


def _text(value: Any, max_chars: int = 12_000) -> str:
    if pd.isna(value):
        return ""
    text = str(value).replace("\ufffd", "'")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_chars]


def _entity_chunk(row: Dict[str, Any], entity_type: str, version: str) -> Dict[str, Any]:
    attack_id = _text(row.get("ID"), 64)
    name = _text(row.get("name"), 500)
    description = _text(row.get("description"))
    fields = [
        f"# MITRE ATT&CK for ICS {entity_type.title()}: {name}",
        f"- ATT&CK ID: {attack_id}",
    ]
    for label, key in (
        ("Tactics", "tactics"),
        ("Platforms", "platforms"),
        ("Sectors", "sectors"),
        ("Aliases", "aliases"),
        ("Type", "type"),
        ("First seen", "first seen"),
        ("Last seen", "last seen"),
    ):
        value = _text(row.get(key), 2000)
        if value:
            fields.append(f"- {label}: {value}")
    if description:
        fields.extend(("", "## Description", description))
    url = _text(row.get("url"), 1000)
    if url:
        fields.append(f"\nReference: {url}")
    return {
        "text": "\n".join(fields),
        "metadata": {
            "source": "MITRE_ATTACK_ICS",
            "attack_id": attack_id or "Unknown",
            "title": name or "Unknown",
            "entity_type": entity_type,
            "tactics": _text(row.get("tactics"), 1000) or "Unknown",
            "url": url or "Unknown",
            "version": version,
            "chunk_type": "attack_entity",
        },
    }


def parse_mitre_attack_xlsx(filepath: str) -> List[Dict[str, Any]]:
    """Create entity and relationship chunks from an ATT&CK for ICS workbook."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"MITRE ATT&CK workbook not found at {filepath}")

    workbook = pd.ExcelFile(path)
    version_match = re.search(r"v(\d+(?:\.\d+)?)", path.name, re.IGNORECASE)
    version = version_match.group(1) if version_match else "Unknown"
    chunks: List[Dict[str, Any]] = []

    for sheet in ENTITY_SHEETS:
        if sheet not in workbook.sheet_names:
            continue
        frame = pd.read_excel(workbook, sheet_name=sheet)
        entity_type = sheet[:-1] if sheet.endswith("s") else sheet
        for row in frame.to_dict("records"):
            if _text(row.get("ID")) and _text(row.get("name")):
                chunks.append(_entity_chunk(row, entity_type, version))

    if "relationships" in workbook.sheet_names:
        relationships = pd.read_excel(workbook, sheet_name="relationships")
        for row in relationships.to_dict("records"):
            source_id = _text(row.get("source ID"), 64)
            target_id = _text(row.get("target ID"), 64)
            if not source_id or not target_id:
                continue
            source_name = _text(row.get("source name"), 500)
            target_name = _text(row.get("target name"), 500)
            mapping = _text(row.get("mapping type"), 100)
            description = _text(row.get("mapping description"), 6000)
            text = (
                "# MITRE ATT&CK for ICS Relationship\n"
                f"- Source: {source_id} — {source_name}\n"
                f"- Relationship: {mapping}\n"
                f"- Target: {target_id} — {target_name}"
            )
            if description:
                text += f"\n\n## Mapping description\n{description}"
            chunks.append({
                "text": text,
                "metadata": {
                    "source": "MITRE_ATTACK_ICS",
                    "attack_id": source_id,
                    "related_attack_id": target_id,
                    "title": f"{source_name} {mapping} {target_name}",
                    "entity_type": "relationship",
                    "tactics": "Unknown",
                    "url": "Unknown",
                    "version": version,
                    "chunk_type": "attack_relationship",
                },
            })

    return chunks
