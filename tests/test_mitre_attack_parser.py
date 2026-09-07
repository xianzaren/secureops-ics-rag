from src.ingestion.mitre_attack_parser import parse_mitre_attack_xlsx


def test_parse_official_mitre_workbook():
    chunks = parse_mitre_attack_xlsx("doc/ics-attack-v19.1.xlsx")
    technique = next(chunk for chunk in chunks if chunk["metadata"].get("attack_id") == "T0830")
    assert technique["metadata"]["source"] == "MITRE_ATTACK_ICS"
    assert technique["metadata"]["version"] == "19.1"
    assert "Adversary-in-the-Middle" in technique["text"]
    assert any(chunk["metadata"]["entity_type"] == "relationship" for chunk in chunks)
