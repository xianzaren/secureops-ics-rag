# Data layout

| Path | Purpose | Git policy |
|---|---|---|
| `cve_combined.csv` | Raw CISA Vulnrichment export (119,864 rows in the current local snapshot) | Ignored; reproducible input |
| `processed/cve_high_value.csv` | Top 2,000 quality-ranked OT/ICS CVEs | Commit |
| `evaluation_qa.json` | 36-case, source-grounded benchmark | Commit |
| `uploads/` | Runtime user uploads | Ignored |

Rebuild the processed dataset and audit report with:

```powershell
python scripts/prepare_data.py --input data/cve_combined.csv --limit 2000
```

The selector does not use physical CSV order. It scans the complete export,
requires an explicit OT/ICS vendor or terminology signal, removes invalid and
duplicate identifiers, then ranks records using KEV, severity, network attack
surface, SSVC, field completeness, and recency. Each output row includes
`quality_score` and `quality_reasons`.

The evaluation set is intentionally separate from the knowledge corpus. It
contains exact advisory/ATT&CK identifiers where possible and includes
unanswerable questions to measure honest rejection when generation evaluation is
enabled.
