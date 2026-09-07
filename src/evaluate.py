"""Reproducible retrieval and optional answer-generation evaluation."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import statistics
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.generation import SecureOpsGenerator
from src.retrieval import SecureOpsRetriever


IDENTIFIER_FIELDS = ("advisory_id", "cve", "attack_id", "related_attack_id")


def _expected_sources(case: Mapping[str, Any]) -> List[str]:
    values = case.get("expected_sources")
    if values:
        return [str(value) for value in values]
    source = str(case.get("ground_truth_source", "NONE"))
    return [] if source == "NONE" else [source]


def is_relevant(chunk: Mapping[str, Any], case: Mapping[str, Any]) -> bool:
    metadata = chunk.get("metadata", {})
    sources = _expected_sources(case)
    if sources and metadata.get("source") not in sources:
        return False
    expected_ids = {str(value).lower() for value in case.get("expected_identifiers", [])}
    if not expected_ids:
        return bool(sources)
    actual_ids = {
        str(metadata.get(field, "")).lower()
        for field in IDENTIFIER_FIELDS
        if metadata.get(field)
    }
    return bool(expected_ids & actual_ids)


def completion_rank(chunks: Sequence[Mapping[str, Any]], case: Mapping[str, Any], k: int) -> Optional[int]:
    """Rank where all required evidence is available; None means incomplete."""
    expected_sources = set(_expected_sources(case))
    if len(expected_sources) > 1:
        first_by_source: Dict[str, int] = {}
        for rank, chunk in enumerate(chunks[:k], 1):
            source = str(chunk.get("metadata", {}).get("source", ""))
            if source in expected_sources and source not in first_by_source:
                first_by_source[source] = rank
        return max(first_by_source.values()) if set(first_by_source) == expected_sources else None
    return next((rank for rank, chunk in enumerate(chunks[:k], 1) if is_relevant(chunk, case)), None)


def ranking_metrics(chunks: Sequence[Mapping[str, Any]], case: Mapping[str, Any], k: int) -> Dict[str, float]:
    relevance = [1 if is_relevant(chunk, case) else 0 for chunk in chunks[:k]]
    expected_sources = set(_expected_sources(case))
    retrieved_sources = {
        str(chunk.get("metadata", {}).get("source", ""))
        for chunk in chunks[:k]
    }
    source_coverage = len(expected_sources & retrieved_sources) / len(expected_sources) if expected_sources else 0.0
    # A cross-document question counts as a hit only when every required source
    # is present. Single-source/exact-ID questions retain the usual semantics.
    hit = float(any(relevance) and source_coverage == 1.0)
    complete_at = completion_rank(chunks, case, k)
    reciprocal_rank = 1.0 / complete_at if complete_at else 0.0
    dcg = sum(value / math.log2(rank + 1) for rank, value in enumerate(relevance, 1))
    relevant_retrieved = sum(relevance)
    ideal_count = min(max(relevant_retrieved, 1), k) if hit else 0
    idcg = sum(1.0 / math.log2(rank + 1) for rank in range(1, ideal_count + 1))
    return {
        f"hit@{k}": hit,
        f"mrr@{k}": reciprocal_rank,
        f"ndcg@{k}": dcg / idcg if idcg else 0.0,
        f"source_coverage@{k}": source_coverage,
    }


def keyword_coverage(chunks: Sequence[Mapping[str, Any]], keywords: Sequence[str]) -> float:
    if not keywords:
        return 0.0
    context = " ".join(str(chunk.get("text", "")) for chunk in chunks).lower()
    return sum(str(keyword).lower() in context for keyword in keywords) / len(keywords)


def _mean(values: Iterable[float]) -> float:
    values = list(values)
    return statistics.fmean(values) if values else 0.0


def _summarize(rows: Sequence[Mapping[str, Any]], strategy: str, k: int) -> Dict[str, float]:
    answerable = [row for row in rows if row["answerable"]]
    return {
        f"hit@{k}": round(_mean(row[strategy][f"hit@{k}"] for row in answerable), 4),
        f"mrr@{k}": round(_mean(row[strategy][f"mrr@{k}"] for row in answerable), 4),
        f"ndcg@{k}": round(_mean(row[strategy][f"ndcg@{k}"] for row in answerable), 4),
        f"source_coverage@{k}": round(_mean(row[strategy][f"source_coverage@{k}"] for row in answerable), 4),
        "context_keyword_coverage": round(_mean(row[strategy]["keyword_coverage"] for row in answerable), 4),
        "mean_latency_ms": round(_mean(row[strategy]["latency_ms"] for row in rows), 2),
        "p95_latency_ms": round(
            sorted(row[strategy]["latency_ms"] for row in rows)[max(0, math.ceil(len(rows) * 0.95) - 1)],
            2,
        ) if rows else 0.0,
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _render_markdown(report: Mapping[str, Any]) -> str:
    run = report["run"]
    baseline = report["aggregate"]["dense"]
    hybrid = report["aggregate"]["hybrid"]
    k = run["top_k"]
    lines = [
        "# SecureOps RAG evaluation report",
        "",
        "> Generated from a real index by `python -m src.evaluate`; no metric is manually filled in.",
        "",
        "## Run manifest",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Timestamp (UTC) | `{run['timestamp_utc']}` |",
        f"| Evaluation cases | {run['case_count']} |",
        f"| Indexed chunks | {run['indexed_chunks']} |",
        f"| Top-k | {k} |",
        f"| Dataset SHA-256 | `{run['dataset_sha256']}` |",
        f"| Python | `{run['python']}` |",
        f"| Generation evaluation | {run['generation_mode']} |",
        "",
        "## Aggregate retrieval results",
        "",
        "| Metric | Dense baseline | Hybrid + RRF + reranker | Delta |",
        "|---|---:|---:|---:|",
    ]
    for metric in (f"hit@{k}", f"mrr@{k}", f"ndcg@{k}", f"source_coverage@{k}", "context_keyword_coverage"):
        lines.append(f"| {metric} | {baseline[metric]:.4f} | {hybrid[metric]:.4f} | {hybrid[metric] - baseline[metric]:+.4f} |")
    lines.extend([
        f"| mean_latency_ms | {baseline['mean_latency_ms']:.2f} | {hybrid['mean_latency_ms']:.2f} | {hybrid['mean_latency_ms'] - baseline['mean_latency_ms']:+.2f} |",
        f"| p95_latency_ms | {baseline['p95_latency_ms']:.2f} | {hybrid['p95_latency_ms']:.2f} | {hybrid['p95_latency_ms'] - baseline['p95_latency_ms']:+.2f} |",
        "",
        "Retrieval metrics exclude unanswerable safety cases. Hybrid latency includes dense and sparse retrieval, RRF, and cross-encoder reranking.",
        "",
        "## Results by category (hybrid)",
        "",
        "| Category | Cases | Hit@k | MRR@k | nDCG@k |",
        "|---|---:|---:|---:|---:|",
    ])
    for category, values in sorted(report["by_category"].items()):
        lines.append(f"| {category} | {values['cases']} | {values['hit']:.4f} | {values['mrr']:.4f} | {values['ndcg']:.4f} |")
    lines.extend(("", "## Per-case results", "", "| ID | Category | Dense hit | Hybrid hit | Hybrid rank |", "|---|---|---:|---:|---:|"))
    for row in report["cases"]:
        if not row["answerable"]:
            lines.append(f"| {row['id']} | {row['category']} | n/a | n/a | n/a |")
            continue
        rank = row["hybrid"]["first_relevant_rank"] or "—"
        lines.append(f"| {row['id']} | {row['category']} | {int(row['dense'][f'hit@{k}'])} | {int(row['hybrid'][f'hit@{k}'])} | {rank} |")
    generation = report.get("generation")
    lines.extend(("", "## Generation results", ""))
    if generation:
        lines.extend((
            f"- Answer keyword coverage: {generation['answer_keyword_coverage']:.4f}",
            f"- Honest-rejection accuracy: {generation['honest_rejection_accuracy']:.4f}",
            f"- Evaluated answers: {generation['evaluated_answers']}",
        ))
    else:
        lines.append("Not run. Use `--with-generation` with a configured API key; retrieval scores above are measured, not simulated.")
    return "\n".join(lines) + "\n"


def run_evaluation(
    qa_path: str = "data/evaluation_qa.json",
    db_path: str = "chroma_db",
    collection_name: str = "secureops_assistant",
    report_output: str = "reports/evaluation_report.md",
    json_output: str = "reports/evaluation_report.json",
    top_k: int = 10,
    with_generation: bool = False,
    retriever: Optional[Any] = None,
    generator: Optional[Any] = None,
) -> Dict[str, Any]:
    qa_file = Path(qa_path)
    qa_pairs = json.loads(qa_file.read_text(encoding="utf-8"))
    retriever = retriever or SecureOpsRetriever(db_path=db_path, collection_name=collection_name)
    generator = generator or (SecureOpsGenerator() if with_generation else None)
    if with_generation and not getattr(generator, "_has_client", False):
        raise RuntimeError("--with-generation requires DEEPSEEK_API_KEY")

    rows: List[Dict[str, Any]] = []
    generation_rows: List[Dict[str, Any]] = []
    for index, case in enumerate(qa_pairs, 1):
        question = case["question"]
        answerable = bool(case.get("answerable", case.get("ground_truth_source") != "NONE"))
        print(f"[{index}/{len(qa_pairs)}] {case['id']}: {question}")
        started = time.perf_counter()
        dense_chunks = retriever.dense_search(question, top_k=top_k)
        dense_latency = (time.perf_counter() - started) * 1000
        started = time.perf_counter()
        hybrid_chunks = retriever.retrieve(question, k=top_k)
        hybrid_latency = (time.perf_counter() - started) * 1000

        row: Dict[str, Any] = {
            "id": case["id"], "category": case["category"], "question": question,
            "answerable": answerable, "expected_sources": _expected_sources(case),
            "expected_identifiers": case.get("expected_identifiers", []),
        }
        for name, chunks, latency in (("dense", dense_chunks, dense_latency), ("hybrid", hybrid_chunks, hybrid_latency)):
            metrics = ranking_metrics(chunks, case, top_k) if answerable else {
                f"hit@{top_k}": 0.0, f"mrr@{top_k}": 0.0, f"ndcg@{top_k}": 0.0,
                f"source_coverage@{top_k}": 0.0,
            }
            relevant_rank = completion_rank(chunks, case, top_k)
            row[name] = {
                **metrics,
                "keyword_coverage": keyword_coverage(chunks, case.get("expected_keywords", [])),
                "latency_ms": round(latency, 2), "first_relevant_rank": relevant_rank,
                "retrieved": [{
                    "source": chunk.get("metadata", {}).get("source"),
                    "identifier": next((chunk.get("metadata", {}).get(field) for field in IDENTIFIER_FIELDS if chunk.get("metadata", {}).get(field)), None),
                } for chunk in chunks[:top_k]],
            }
        rows.append(row)

        if with_generation:
            answer, confidence, _ = generator.generate_answer(question, hybrid_chunks)
            answer_lower = answer.lower()
            keywords = case.get("expected_keywords", [])
            coverage = sum(str(keyword).lower() in answer_lower for keyword in keywords) / len(keywords) if keywords else 0.0
            rejection = "don't have enough information" in answer_lower or "not enough information" in answer_lower
            generation_rows.append({"id": case["id"], "answerable": answerable, "coverage": coverage, "rejected": rejection, "confidence": confidence})

    aggregate = {name: _summarize(rows, name, top_k) for name in ("dense", "hybrid")}
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row["answerable"]:
            grouped[row["category"]].append(row)
    by_category = {
        category: {
            "cases": len(items),
            "hit": round(_mean(item["hybrid"][f"hit@{top_k}"] for item in items), 4),
            "mrr": round(_mean(item["hybrid"][f"mrr@{top_k}"] for item in items), 4),
            "ndcg": round(_mean(item["hybrid"][f"ndcg@{top_k}"] for item in items), 4),
        } for category, items in grouped.items()
    }
    generation_summary = None
    if generation_rows:
        answerable_rows = [row for row in generation_rows if row["answerable"]]
        rejection_rows = [row for row in generation_rows if not row["answerable"]]
        generation_summary = {
            "evaluated_answers": len(generation_rows),
            "answer_keyword_coverage": round(_mean(row["coverage"] for row in answerable_rows), 4),
            "honest_rejection_accuracy": round(_mean(float(row["rejected"]) for row in rejection_rows), 4),
            "cases": generation_rows,
        }
    report: Dict[str, Any] = {
        "run": {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(), "case_count": len(qa_pairs),
            "indexed_chunks": retriever.collection.count() if hasattr(retriever, "collection") else len(getattr(retriever, "texts", [])),
            "top_k": top_k, "dataset_path": str(qa_file), "dataset_sha256": _sha256(qa_file),
            "python": platform.python_version(), "platform": platform.platform(),
            "generation_mode": "live_api" if with_generation else "not_run",
        },
        "aggregate": aggregate, "by_category": by_category,
        "generation": generation_summary, "cases": rows,
    }
    json_path, markdown_path = Path(json_output), Path(report_output)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    print(f"Wrote measured reports to {markdown_path} and {json_path}")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qa", default="data/evaluation_qa.json")
    parser.add_argument("--db", default=os.getenv("RAG_DB_PATH", "chroma_db"))
    parser.add_argument("--collection", default="secureops_assistant")
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--markdown", default="reports/evaluation_report.md")
    parser.add_argument("--json", dest="json_output", default="reports/evaluation_report.json")
    parser.add_argument("--with-generation", action="store_true")
    args = parser.parse_args()
    run_evaluation(args.qa, args.db, args.collection, args.markdown, args.json_output, args.top_k, args.with_generation)


if __name__ == "__main__":
    main()
