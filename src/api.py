import os
import threading
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from src.generation import SecureOpsGenerator
from src.indexing import build_index
from src.query_rewrite import rewrite_query
from src.retrieval import SecureOpsRetriever

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("RAG_DB_PATH", str(BASE_DIR / "chroma_db")))
UPLOAD_DIR = Path(os.getenv("RAG_UPLOAD_DIR", str(BASE_DIR / "data" / "uploads")))
CVE_CSV_PATH = Path(os.getenv("CVE_CSV_PATH", str(BASE_DIR / "data" / "processed" / "cve_high_value.csv")))
CVE_LIMIT = max(0, int(os.getenv("CVE_LIMIT", "2000")))
MITRE_XLSX_PATH = Path(os.getenv("MITRE_XLSX_PATH", str(BASE_DIR / "doc" / "ics-attack-v19.1.xlsx")))
ALLOWED_SUFFIXES = {".pdf", ".txt"}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_UPLOAD_FILES = 3

app = FastAPI(title="SecureOps RAG API", version="1.0.0")
origins = [value.strip() for value in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",") if value.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

retriever = None
generator = None
model_lock = threading.Lock()
index_lock = threading.Lock()


class AskRequest(BaseModel):
    query: str = Field(min_length=2, max_length=2000)
    vendor: Optional[str] = Field(default=None, max_length=100)
    severity: Optional[str] = Field(default=None, max_length=30)
    source: Optional[str] = Field(default=None, max_length=100)


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/api/status")
def system_status():
    return {
        "index_ready": DB_PATH.exists() and (DB_PATH / "bm25_index.pkl").exists(),
        "generator_configured": bool(os.getenv("DEEPSEEK_API_KEY")),
        "allowed_upload_types": sorted(ALLOWED_SUFFIXES),
        "cve_dataset_ready": CVE_CSV_PATH.exists(),
        "cve_record_limit": CVE_LIMIT,
        "mitre_dataset_ready": MITRE_XLSX_PATH.exists(),
    }


def get_models():
    global retriever, generator
    if retriever is None or generator is None:
        with model_lock:
            if retriever is None:
                retriever = SecureOpsRetriever(db_path=str(DB_PATH))
            if generator is None:
                generator = SecureOpsGenerator()
    return retriever, generator


def retrieve_for_request(req: AskRequest):
    r, g = get_models()
    query = req.query.strip()
    queries = [query]
    for candidate in rewrite_query(query):
        text = candidate["text"].strip()
        if text.lower() not in {item.lower() for item in queries}:
            queries.append(text)
    results = r.retrieve(queries, k=5, vendor=req.vendor, severity=req.severity, source=req.source)
    return g, queries, results


@app.post("/api/ask")
def ask_question(req: AskRequest):
    g, queries, retrieved = retrieve_for_request(req)
    answer, confidence, cited = g.generate_answer(req.query.strip(), retrieved)
    return {"answer": answer, "confidence": confidence, "cited": cited, "expanded_queries": queries}


@app.post("/api/ask_stream")
def ask_question_stream(req: AskRequest):
    g, queries, retrieved = retrieve_for_request(req)

    def stream_generator():
        import json
        yield f"__EXPANDED_QUERIES__:{json.dumps(queries)}\n\n"
        yield from g.generate_answer_stream(req.query.strip(), retrieved)

    return StreamingResponse(stream_generator(), media_type="text/plain; charset=utf-8")


@app.post("/api/upload")
def upload_files(files: List[UploadFile] = File(...)):
    if not files or len(files) > MAX_UPLOAD_FILES:
        raise HTTPException(status_code=400, detail=f"Upload between 1 and {MAX_UPLOAD_FILES} files.")
    if not index_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="An index rebuild is already running.")

    try:
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        prepared = []
        for upload in files:
            original_name = upload.filename or ""
            safe_name = Path(original_name).name
            suffix = Path(safe_name).suffix.lower()
            if not safe_name or safe_name != original_name or suffix not in ALLOWED_SUFFIXES:
                raise HTTPException(status_code=400, detail=f"Unsupported or unsafe filename: {original_name}")
            content = upload.file.read(MAX_UPLOAD_BYTES + 1)
            if len(content) > MAX_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail=f"File {safe_name} exceeds 5 MB.")
            prepared.append((safe_name, content))

        for safe_name, content in prepared:
            destination = (UPLOAD_DIR / safe_name).resolve()
            if destination.parent != UPLOAD_DIR.resolve():
                raise HTTPException(status_code=400, detail="Unsafe upload path.")
            destination.write_bytes(content)

        build_index(
            csaf_dir=str(BASE_DIR / "doc" / "cisa_csaf"),
            csf_pdf_path=str(BASE_DIR / "doc" / "NIST Cybersecurity Framework(CSF) 2.0.pdf"),
            nist_pdf_path=str(BASE_DIR / "doc" / "NIST.SP.800-82r3.pdf"),
            db_path=str(DB_PATH),
            upload_dir=str(UPLOAD_DIR),
            cve_csv_path=str(CVE_CSV_PATH),
            cve_limit=CVE_LIMIT,
            mitre_xlsx_path=str(MITRE_XLSX_PATH),
        )

        global retriever, generator
        retriever = None
        generator = None
        return {"status": "success", "indexed_uploads": [name for name, _ in prepared]}
    finally:
        index_lock.release()
