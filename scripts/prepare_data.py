"""Build the reproducible high-value CVE subset and its quality report."""

import argparse
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.ingestion.cve_cleaner import select_high_value_cves, write_clean_dataset


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="data/cve_combined.csv")
    parser.add_argument("--output", default="data/processed/cve_high_value.csv")
    parser.add_argument("--limit", type=int, default=2000)
    parser.add_argument("--min-score", type=int, default=45)
    parser.add_argument("--json-report", default="reports/data_quality_report.json")
    parser.add_argument("--markdown-report", default="reports/data_quality_report.md")
    args = parser.parse_args()
    selected, report = select_high_value_cves(args.input, args.limit, args.min_score)
    write_clean_dataset(selected, report, args.output, args.json_report, args.markdown_report)
    print(f"Selected {len(selected)} high-value OT CVEs from {report['source_rows']} source rows.")
    print(f"Dataset: {args.output}")
    print(f"Quality report: {args.markdown_report}")


if __name__ == "__main__":
    main()
