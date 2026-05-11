from __future__ import annotations

from pathlib import Path
from typing import Optional

from settings import get_settings
from ingestion.generic_dir import ingest_dir_pdfs

def run_source(
    source: str,
    *,
    input_dir: Optional[Path] = None,
    collection: Optional[str] = None,
    reset: bool = False,
) -> int:
    """Ingest all PDFs from data/raw/<source> into ChromaDB."""
    s = get_settings()

    resolved_input = (input_dir or (s.data_dir / source)).resolve()
    if not resolved_input.exists():
        raise FileNotFoundError(f"Input directory not found: {resolved_input}")

    chroma_path = (s.project_root / "chroma_db").resolve()

    return ingest_dir_pdfs(
        source=source,
        data_path=resolved_input,
        chroma_path=chroma_path,
        collection_name=collection or source,
        reset_collection=reset,
    )

