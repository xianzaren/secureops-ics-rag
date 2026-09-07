import os
import re
import pickle
from typing import List, Tuple, Optional
import chromadb
from sentence_transformers import SentenceTransformer
from src.ingestion.csaf_parser import parse_all_csaf_dir
from src.ingestion.pdf_parser import parse_pdf_to_chunks
from src.ingestion.upload_parser import parse_upload_dir
from src.ingestion.cve_csv_parser import parse_cve_csv
from src.ingestion.mitre_attack_parser import parse_mitre_attack_xlsx


def get_torch_device() -> str:
    """Determine the preferred device for PyTorch models.

    Environment variables take precedence:
    - RAG_DEVICE
    - TORCH_DEVICE
    - PYTORCH_DEVICE

    If none are set, GPU is used only when PyTorch reports CUDA is available.
    """
    for env_key in ("RAG_DEVICE", "TORCH_DEVICE", "PYTORCH_DEVICE"):
        device = os.getenv(env_key, "").strip().lower()
        if device in ("cpu", "cuda"):
            return device

    try:
        import torch
        if torch.cuda.is_available():
            return "cuda"
    except Exception:
        pass
    return "cpu"

# Special tokenizer for BM25 to preserve security terms (CVEs, PR.AC codes, etc.)
def tokenize_text(text: str) -> List[str]:
    """
    Tokenize text by converting to lowercase and extracting words including hyphens and periods.
    Preserves terms like 'cve-2026-42941', 'nist.sp.800-82r3', 'pr.ac'
    """
    return re.findall(r'[a-zA-Z0-9]+(?:[\-\.][a-zA-Z0-9]+)*', text.lower())

def get_embedding_model(model_name: Optional[str] = None) -> SentenceTransformer:
    """
    Load the SentenceTransformer model with device fallback.
    """
    model_name = model_name or os.getenv("RAG_EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5")
    device = get_torch_device()
    print(f"Loading embedding model: {model_name} on {device}...")
    try:
        return SentenceTransformer(model_name, device=device)
    except Exception as exc:
        if device != "cpu":
            print(f"[Warning] Failed to load embedding model on {device}; falling back to CPU. Error: {exc}")
            return SentenceTransformer(model_name, device="cpu")
        raise

def build_index(
    csaf_dir: str,
    csf_pdf_path: str,
    nist_pdf_path: str,
    db_path: str = "chroma_db",
    collection_name: str = "secureops_assistant",
    model_name: Optional[str] = None,
    limit_pdf_pages: bool = False,
    upload_dir: Optional[str] = None,
    cve_csv_path: Optional[str] = None,
    cve_limit: int = 2000,
    mitre_xlsx_path: Optional[str] = None,
    embedding_model=None,
) -> Tuple[int, int]:
    """
    Main function to parse all documents, embed them with BGE, 
    and save them to ChromaDB and BM25 index.
    Returns (num_documents, num_chunks).
    """
    # 1. Parse all document sources to collect chunks
    all_chunks = []
    
    # Ingest CSAF JSONs
    print("Ingesting CSAF JSON files...")
    if os.path.exists(csaf_dir):
        csaf_chunks = parse_all_csaf_dir(csaf_dir)
        all_chunks.extend(csaf_chunks)
        print(f"CSAF Ingestion complete. Created {len(csaf_chunks)} chunks.")
    else:
        print(f"CSAF directory not found: {csaf_dir}")
        
    # Ingest CSF 2.0 PDF
    print("Ingesting NIST CSF 2.0 PDF...")
    if os.path.exists(csf_pdf_path):
        # If limiting pages (e.g. for fast tests), parse pages 0-4. Otherwise parse all pages.
        pages = [i for i in range(5)] if limit_pdf_pages else None
        csf_chunks = parse_pdf_to_chunks(csf_pdf_path, "NIST_CSF_2.0", pages=pages)
        all_chunks.extend(csf_chunks)
        print(f"CSF PDF Ingestion complete. Created {len(csf_chunks)} chunks.")
    else:
        print(f"CSF PDF path not found: {csf_pdf_path}")
        
    # Ingest NIST SP 800-82 PDF
    print("Ingesting NIST SP 800-82 Rev 3 PDF...")
    if os.path.exists(nist_pdf_path):
        # If limiting pages (e.g. for fast tests), parse pages 140-145. Otherwise parse all.
        pages = [i for i in range(140, 146)] if limit_pdf_pages else None
        nist_chunks = parse_pdf_to_chunks(nist_pdf_path, "NIST_SP_800-82_R3", pages=pages)
        all_chunks.extend(nist_chunks)
        print(f"NIST SP 800-82 Ingestion complete. Created {len(nist_chunks)} chunks.")
    else:
        print(f"NIST SP 800-82 path not found: {nist_pdf_path}")
        
    if upload_dir:
        upload_chunks = parse_upload_dir(upload_dir)
        all_chunks.extend(upload_chunks)
        print(f"User upload ingestion complete. Created {len(upload_chunks)} chunks.")

    if cve_csv_path and os.path.exists(cve_csv_path):
        cve_chunks = parse_cve_csv(cve_csv_path, limit=cve_limit)
        all_chunks.extend(cve_chunks)
        print(f"CISA Vulnrichment ingestion complete. Created {len(cve_chunks)} chunks.")

    if mitre_xlsx_path and os.path.exists(mitre_xlsx_path):
        mitre_chunks = parse_mitre_attack_xlsx(mitre_xlsx_path)
        all_chunks.extend(mitre_chunks)
        print(f"MITRE ATT&CK for ICS ingestion complete. Created {len(mitre_chunks)} chunks.")

    if not all_chunks:
        print("No chunks found to index.")
        return 0, 0
        
    print(f"Total chunks gathered: {len(all_chunks)}")
    
    # 2. Initialize ChromaDB and write vectors
    os.makedirs(db_path, exist_ok=True)
    chroma_client = chromadb.PersistentClient(path=db_path)
    
    # Delete collection if it already exists to avoid duplicate accumulation
    try:
        chroma_client.delete_collection(name=collection_name)
        print(f"Deleted existing ChromaDB collection: {collection_name}")
    except Exception:
        pass
        
    collection = chroma_client.create_collection(name=collection_name)
    
    # Load model and embed
    model = embedding_model or get_embedding_model(model_name)
    
    texts = [chunk["text"] for chunk in all_chunks]
    metadatas = [chunk["metadata"] for chunk in all_chunks]
    ids = [f"doc_{i}" for i in range(len(all_chunks))]
    
    print("Generating dense embeddings (this may take a few moments)...")
    embedding_batch_size = max(1, int(os.getenv("RAG_EMBED_BATCH_SIZE", "32")))
    embeddings = model.encode(
        texts,
        batch_size=embedding_batch_size,
        show_progress_bar=True,
        normalize_embeddings=True,
    )
    
    # Add to ChromaDB in batches to prevent payload size errors
    batch_size = 500
    for i in range(0, len(all_chunks), batch_size):
        end = min(i + batch_size, len(all_chunks))
        collection.add(
            ids=ids[i:end],
            embeddings=embeddings[i:end].tolist(),
            metadatas=metadatas[i:end],
            documents=texts[i:end]
        )
    print("Successfully populated ChromaDB vector store.")
    
    # 3. Build and serialize BM25 index
    print("Building BM25 sparse index...")
    from rank_bm25 import BM25Okapi
    
    tokenized_corpus = [tokenize_text(text) for text in texts]
    bm25_model = BM25Okapi(tokenized_corpus)
    
    bm25_data = {
        "bm25": bm25_model,
        "texts": texts,
        "metadatas": metadatas,
        "ids": ids
    }
    
    bm25_path = os.path.join(db_path, "bm25_index.pkl")
    with open(bm25_path, "wb") as f:
        pickle.dump(bm25_data, f)
    print(f"BM25 index successfully saved to {bm25_path}")
    
    return len(all_chunks), len(all_chunks)
