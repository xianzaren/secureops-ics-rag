# CVE data quality report

Generated: `2026-09-07T08:14:28.167633+00:00`

| Measure | Value |
|---|---:|
| Source rows scanned | 119864 |
| Invalid rows | 0 |
| Duplicate rows | 0 |
| Excluded non-OT/low-quality rows | 117164 |
| Eligible unique OT rows | 2700 |
| Selected rows | 2000 |
| Selected KEV rows | 36 |
| Mean quality score | 63.25 |

The selector requires an explicit OT/ICS signal and then ranks records by KEV status, CVSS severity, network reachability, SSVC decision, metadata completeness, and publication recency.
