# SecureOps RAG evaluation report

> Generated from a real index by `python -m src.evaluate`; no metric is manually filled in.

## Run manifest

| Field | Value |
|---|---|
| Timestamp (UTC) | `2026-09-07T09:14:00.611880+00:00` |
| Evaluation cases | 36 |
| Indexed chunks | 8403 |
| Top-k | 10 |
| Dataset SHA-256 | `a11521e86fcda63328cb4d19f255be8759b6c5de55776ae964adabacf673acb9` |
| Python | `3.11.16` |
| Generation evaluation | not_run |

## Aggregate retrieval results

| Metric | Dense baseline | Hybrid + RRF + reranker | Delta |
|---|---:|---:|---:|
| hit@10 | 0.8125 | 0.9375 | +0.1250 |
| mrr@10 | 0.7396 | 0.8229 | +0.0833 |
| ndcg@10 | 0.7795 | 0.8789 | +0.0994 |
| source_coverage@10 | 0.9219 | 0.9688 | +0.0469 |
| context_keyword_coverage | 0.7646 | 0.8490 | +0.0844 |
| mean_latency_ms | 31.46 | 1143.89 | +1112.43 |
| p95_latency_ms | 41.17 | 1581.22 | +1540.05 |

Retrieval metrics exclude unanswerable safety cases. Hybrid latency includes dense and sparse retrieval, RRF, and cross-encoder reranking.

## Results by category (hybrid)

| Category | Cases | Hit@k | MRR@k | nDCG@k |
|---|---:|---:|---:|---:|
| CISA_CSAF | 8 | 1.0000 | 0.8250 | 0.8802 |
| CROSS_DOCUMENT | 4 | 0.5000 | 0.1000 | 0.5000 |
| MITRE_ATTACK_ICS | 8 | 1.0000 | 0.9167 | 0.9003 |
| NIST_CSF_2.0 | 6 | 1.0000 | 1.0000 | 0.9913 |
| NIST_SP_800-82 | 6 | 1.0000 | 1.0000 | 0.9889 |

## Per-case results

| ID | Category | Dense hit | Hybrid hit | Hybrid rank |
|---|---|---:|---:|---:|
| NIST82-01 | NIST_SP_800-82 | 1 | 1 | 1 |
| NIST82-02 | NIST_SP_800-82 | 1 | 1 | 1 |
| NIST82-03 | NIST_SP_800-82 | 1 | 1 | 1 |
| NIST82-04 | NIST_SP_800-82 | 1 | 1 | 1 |
| NIST82-05 | NIST_SP_800-82 | 1 | 1 | 1 |
| NIST82-06 | NIST_SP_800-82 | 1 | 1 | 1 |
| CSF20-01 | NIST_CSF_2.0 | 1 | 1 | 1 |
| CSF20-02 | NIST_CSF_2.0 | 1 | 1 | 1 |
| CSF20-03 | NIST_CSF_2.0 | 0 | 1 | 1 |
| CSF20-04 | NIST_CSF_2.0 | 1 | 1 | 1 |
| CSF20-05 | NIST_CSF_2.0 | 1 | 1 | 1 |
| CSF20-06 | NIST_CSF_2.0 | 1 | 1 | 1 |
| CSAF-01 | CISA_CSAF | 1 | 1 | 1 |
| CSAF-02 | CISA_CSAF | 1 | 1 | 2 |
| CSAF-03 | CISA_CSAF | 1 | 1 | 1 |
| CSAF-04 | CISA_CSAF | 1 | 1 | 1 |
| CSAF-05 | CISA_CSAF | 1 | 1 | 1 |
| CSAF-06 | CISA_CSAF | 0 | 1 | 10 |
| CSAF-07 | CISA_CSAF | 1 | 1 | 1 |
| CSAF-08 | CISA_CSAF | 1 | 1 | 1 |
| ATTACK-01 | MITRE_ATTACK_ICS | 1 | 1 | 1 |
| ATTACK-02 | MITRE_ATTACK_ICS | 1 | 1 | 3 |
| ATTACK-03 | MITRE_ATTACK_ICS | 1 | 1 | 1 |
| ATTACK-04 | MITRE_ATTACK_ICS | 1 | 1 | 1 |
| ATTACK-05 | MITRE_ATTACK_ICS | 1 | 1 | 1 |
| ATTACK-06 | MITRE_ATTACK_ICS | 1 | 1 | 1 |
| ATTACK-07 | MITRE_ATTACK_ICS | 0 | 1 | 1 |
| ATTACK-08 | MITRE_ATTACK_ICS | 1 | 1 | 1 |
| CROSS-01 | CROSS_DOCUMENT | 1 | 0 | — |
| CROSS-02 | CROSS_DOCUMENT | 0 | 1 | 5 |
| CROSS-03 | CROSS_DOCUMENT | 0 | 0 | — |
| CROSS-04 | CROSS_DOCUMENT | 0 | 1 | 5 |
| SAFE-01 | HONEST_REJECTION | n/a | n/a | n/a |
| SAFE-02 | HONEST_REJECTION | n/a | n/a | n/a |
| SAFE-03 | HONEST_REJECTION | n/a | n/a | n/a |
| SAFE-04 | HONEST_REJECTION | n/a | n/a | n/a |

## Generation results

Not run. Use `--with-generation` with a configured API key; retrieval scores above are measured, not simulated.
