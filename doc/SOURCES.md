# Knowledge source manifest

| Source | Local artifact | Version/snapshot | Indexed content | Evaluation role |
|---|---|---|---|---|
| CISA CSAF Security Advisories | `cisa_csaf/*.json` | CSAF 2.0, local 2026 snapshot (200 advisories) | Overview, vulnerability/CVE, remediation, recommended practice | Exact advisory ID and CVE retrieval |
| NIST SP 800-82 Rev. 3 | `NIST.SP.800-82r3.pdf` | Final, September 2023 | Page-aware OT security guidance | Topic and page-context retrieval |
| NIST CSF 2.0 | `NIST Cybersecurity Framework(CSF) 2.0.pdf` | NIST CSWP 29, February 2024 | Functions, categories, profiles, tiers | Framework concept retrieval |
| MITRE ATT&CK for ICS | `ics-attack-v19.1.xlsx` | v19.1 | Techniques, tactics, mitigations, assets, groups, software, detection data, relationships | Exact ATT&CK ID retrieval |
| CISA Vulnrichment export | `../data/cve_combined.csv` | Local snapshot | Quality-ranked OT/ICS CVE records | Supplemental CVE retrieval |

## Canonical upstream locations

- CISA CSAF: <https://github.com/cisagov/CSAF>
- NIST SP 800-82 Rev. 3: <https://doi.org/10.6028/NIST.SP.800-82r3>
- NIST CSF 2.0: <https://doi.org/10.6028/NIST.CSWP.29>
- MITRE ATT&CK data and tools: <https://attack.mitre.org/resources/attack-data-and-tools/>
- MITRE ATT&CK for ICS matrix: <https://attack.mitre.org/matrices/ics/>

The project keeps provenance and source identifiers in chunk metadata. Before
public redistribution, review the current upstream terms and preserve the
required attribution. CISA advisories may include verbatim vendor republications,
which remain identified as CISA CSAF records rather than project-authored text.
