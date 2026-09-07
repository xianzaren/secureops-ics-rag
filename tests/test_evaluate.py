from src.evaluate import completion_rank, ranking_metrics


def _chunk(source, **metadata):
    return {"text": "evidence", "metadata": {"source": source, **metadata}}


def test_exact_identifier_relevance():
    case = {"expected_sources": ["CISA_CSAF"], "expected_identifiers": ["ICSA-1"]}
    chunks = [_chunk("CISA_CSAF", advisory_id="ICSA-2"), _chunk("CISA_CSAF", advisory_id="ICSA-1")]
    metrics = ranking_metrics(chunks, case, 10)
    assert metrics["hit@10"] == 1.0
    assert metrics["mrr@10"] == 0.5


def test_cross_document_hit_requires_every_source():
    case = {"expected_sources": ["NIST_SP_800-82_R3", "MITRE_ATTACK_ICS"]}
    incomplete = [_chunk("NIST_SP_800-82_R3")]
    complete = [_chunk("NIST_SP_800-82_R3"), _chunk("MITRE_ATTACK_ICS")]
    assert ranking_metrics(incomplete, case, 10)["hit@10"] == 0.0
    assert ranking_metrics(incomplete, case, 10)["source_coverage@10"] == 0.5
    assert completion_rank(complete, case, 10) == 2
    assert ranking_metrics(complete, case, 10)["mrr@10"] == 0.5
