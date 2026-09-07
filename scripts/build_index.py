"""Non-interactive index builder for local and Docker workflows."""

import argparse
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.indexing import build_index


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true", help="Index only representative PDF pages")
    parser.add_argument("--db", default=os.getenv("RAG_DB_PATH", "chroma_db"))
    parser.add_argument("--cve-limit", type=int, default=int(os.getenv("CVE_LIMIT", "2000")))
    args = parser.parse_args()
    _, chunks = build_index(
        csaf_dir="doc/cisa_csaf",
        csf_pdf_path="doc/NIST Cybersecurity Framework(CSF) 2.0.pdf",
        nist_pdf_path="doc/NIST.SP.800-82r3.pdf",
        db_path=args.db,
        limit_pdf_pages=args.quick,
        upload_dir=os.getenv("RAG_UPLOAD_DIR", "data/uploads"),
        cve_csv_path=os.getenv("CVE_CSV_PATH", "data/processed/cve_high_value.csv"),
        cve_limit=args.cve_limit,
        mitre_xlsx_path=os.getenv("MITRE_XLSX_PATH", "doc/ics-attack-v19.1.xlsx"),
    )
    print(f"Index build complete: {chunks} chunks")


if __name__ == "__main__":
    main()
