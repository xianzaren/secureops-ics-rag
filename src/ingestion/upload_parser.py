from pathlib import Path
from typing import Any, Dict, List

from src.ingestion.pdf_parser import parse_pdf_to_chunks


def parse_text_to_chunks(filepath: str, max_words: int = 400) -> List[Dict[str, Any]]:
    """Parse a UTF-8 text file into bounded, source-attributed chunks."""
    path = Path(filepath)
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []

    words = text.split()
    chunks = []
    for index in range(0, len(words), max_words):
        body = " ".join(words[index:index + max_words])
        chunks.append({
            "text": f"Source: USER_UPLOAD | File: {path.name}\n\n{body}",
            "metadata": {
                "source": "USER_UPLOAD",
                "filename": path.name,
                "chunk_type": "uploaded_text",
                "chunk_index": index // max_words,
            },
        })
    return chunks


def parse_upload_dir(upload_dir: str) -> List[Dict[str, Any]]:
    """Parse supported user documents already accepted by the API."""
    directory = Path(upload_dir)
    if not directory.exists():
        return []

    chunks: List[Dict[str, Any]] = []
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix == ".pdf":
            pdf_chunks = parse_pdf_to_chunks(str(path), "USER_UPLOAD")
            for chunk in pdf_chunks:
                chunk["metadata"]["filename"] = path.name
            chunks.extend(pdf_chunks)
        elif suffix == ".txt":
            chunks.extend(parse_text_to_chunks(str(path)))
    return chunks
