from __future__ import annotations

import hashlib
from pathlib import Path
from typing import List, Optional

import chromadb
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import PyPDFLoader


def _sha1_text(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()


def _sha1_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha1()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def iter_pdfs(data_path: Path, pattern: str = "*.pdf") -> List[Path]:
    return sorted(data_path.glob(pattern))


def load_and_chunk_pdf(
    pdf_path: Path,
    splitter: RecursiveCharacterTextSplitter,
) -> List[tuple[str, dict]]:
    """Return a list of (chunk_text, metadata) pairs for all chunks in the PDF."""
    loader = PyPDFLoader(str(pdf_path))
    pages = loader.load()
    docs = splitter.split_documents(pages)

    out: List[tuple[str, dict]] = []
    for i, doc in enumerate(docs):
        meta = dict(doc.metadata or {})
        meta.update(
            {
                "source": pdf_path.name,
                "page": meta.get("page"),
                "chunk_index": i,
            }
        )
        out.append((doc.page_content, meta))
    return out


def ingest_dir_pdfs(
    *,
    source: str,
    data_path: Path,
    chroma_path: Path,
    collection_name: Optional[str] = None,
    glob_pattern: str = "*.pdf",
    chunk_size: int = 700,
    chunk_overlap: int = 100,
    batch_size: int = 64,
    reset_collection: bool = False,
) -> int:
    """
    Ingest PDFs from a directory into a ChromaDB collection.

    - source: logical domain name (e.g. 'regulatory_technical', 'academic_institutional')
    - data_path: input directory (e.g. data/raw/<source>)
    - chroma_path: ChromaDB persistence directory
    - collection_name: target collection name (defaults to source)
    - reset_collection: drop the existing collection before ingesting
    Returns the final document count in the collection.
    """
    if not data_path.exists():
        raise FileNotFoundError(f"Data directory not found: {data_path}")

    pdfs = iter_pdfs(data_path, pattern=glob_pattern)
    if not pdfs:
        raise FileNotFoundError(f"No PDFs found in: {data_path} (pattern={glob_pattern})")

    collection = collection_name or source

    chroma_client = chromadb.PersistentClient(path=str(chroma_path))

    if reset_collection:
        try:
            chroma_client.delete_collection(name=collection)
        except Exception:
            pass

    col = chroma_client.get_or_create_collection(name=collection)

    splitter = RecursiveCharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)

    for pdf_path in pdfs:
        pdf_hash = _sha1_file(pdf_path)
        chunks = load_and_chunk_pdf(pdf_path, splitter)

        docs_batch: List[str] = []
        ids_batch: List[str] = []
        metas_batch: List[dict] = []

        for chunk_text, meta in chunks:
            chunk_hash = _sha1_text(chunk_text)
            page = meta.get("page", -1)
            chunk_index = meta.get("chunk_index", -1)

            # Stable ID combining domain, filename, file hash, and chunk position — survives re-ingestion.
            doc_id = f"{source}:{pdf_path.name}:{pdf_hash}:p{page}:c{chunk_index}:{chunk_hash}"

            meta = dict(meta)
            meta.update(
                {
                    "dataset": source,
                    "pdf_hash": pdf_hash,
                    "chunk_size": chunk_size,
                    "chunk_overlap": chunk_overlap,
                    "path": str(pdf_path),
                    "collection": collection,
                }
            )

            docs_batch.append(chunk_text)
            ids_batch.append(doc_id)
            metas_batch.append(meta)

            if len(docs_batch) >= batch_size:
                _safe_upsert(col, ids_batch, docs_batch, metas_batch)
                docs_batch, ids_batch, metas_batch = [], [], []

        if docs_batch:
            _safe_upsert(col, ids_batch, docs_batch, metas_batch)

    return int(col.count())


def _safe_upsert(collection, ids: List[str], docs: List[str], metas: List[dict]) -> None:
    """
    Upsert documents tolerating ChromaDB API differences across versions.
    Uses collection.upsert() when available; falls back to add() skipping existing IDs.
    """
    # Deduplicate IDs within the batch before upserting.
    seen = set()
    ids2, docs2, metas2 = [], [], []
    for j, (i, d, m) in enumerate(zip(ids, docs, metas)):
        if i in seen:
            i = f"{i}__dup{j}"
        seen.add(i)
        ids2.append(i)
        docs2.append(d)
        metas2.append(m)
    ids, docs, metas = ids2, docs2, metas2

    if hasattr(collection, "upsert"):
        collection.upsert(ids=ids, documents=docs, metadatas=metas)
        return

    try:
        collection.add(ids=ids, documents=docs, metadatas=metas)
    except Exception:
        existing = set()
        try:
            got = collection.get(ids=ids, include=[])
            existing = set(got.get("ids", []) or [])
        except Exception:
            existing = set()

        keep = [(i, d, m) for i, d, m in zip(ids, docs, metas) if i not in existing]
        if keep:
            ids3, docs3, metas3 = zip(*keep)
            collection.add(ids=list(ids3), documents=list(docs3), metadatas=list(metas3))
