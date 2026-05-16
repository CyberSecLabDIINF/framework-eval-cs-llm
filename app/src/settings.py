from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

def _default_project_root() -> Path:
    """Logical project root inside the container; maps to /root/proyecto_tesis."""
    return Path("/root/proyecto_tesis")


class Settings(BaseSettings):
    """
    Central configuration for the security evaluation lab.

    Values are loaded from (in order of precedence):
      1) environment variables
      2) an optional .env file
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Runtime mode ---
    env: Literal["dev", "prod", "lab"] = Field(default="lab", description="Execution mode")

    # --- Service ports ---
    rag_port: int = Field(default=8000, description="Unprotected RAG API port")
    shield_port: int = Field(default=8001, description="Protected Shield API port")

    rag_base_url: Optional[str] = Field(
        default=None,
        description="Base URL override for the RAG endpoint (e.g. http://rag_api:8000)",
    )

    shield_base_url: Optional[str] = Field(
        default=None,
        description="Base URL override for the Shield endpoint (e.g. http://shield_api:8001)",
    )

    # --- Evaluation target ---
    target: Literal["unprotected", "protected"] = Field(
        default="unprotected",
        description="Active evaluation scenario: unprotected (RAG only) or protected (RAG + LLM Guard)",
    )

    dataset_tag: str = Field(
        default="default",
        description="Knowledge domain label used in run IDs (e.g. regulatory_technical, academic_institutional)",
    )

    # --- Base paths ---
    project_root: Path = Field(default_factory=_default_project_root)
    app_dir: Path = Field(default=None, description="Path to /app")
    data_dir: Path = Field(default=None, description="Path to /data")
    artifacts_dir: Path = Field(default=None, description="Path to /artifacts")
    garak_runs_dir: Path = Field(default=None, description="Garak internal run cache directory (written by the runner process)")
    chroma_db_path: Optional[Path] = Field(default=None, description="Path to ChromaDB persistent storage")

    # --- JSON config files ---
    config_dir: Path = Field(default=None, description="Path to /app/config")
    owasp_suites_path: Path = Field(default=None, description="Path to owasp_suites.json")
    garak_rest_base_path: Path = Field(default=None, description="Path to garak_rest_base.json")

    # --- Derived endpoint URLs ---
    rag_url: str = Field(default="", description="RAG base URL")
    shield_url: str = Field(default="", description="Shield base URL")
    rag_generate_url: str = Field(default="", description="RAG /generate endpoint")
    shield_generate_url: str = Field(default="", description="Shield /generate endpoint")
    rag_health_url: str = Field(default="", description="RAG /health endpoint")
    shield_health_url: str = Field(default="", description="Shield /health endpoint")

    # --- Artifact subdirectories ---
    runs_dir: Path = Field(default=None, description="Root directory for all run outputs")
    latency_dir: Path = Field(default=None, description="CSV latency logs directory (legacy)")
    reports_dir: Path = Field(default=None, description="Aggregated reports directory (legacy)")

    # --- Garak REST security header ---
    rest_api_key_env: str = Field(
        default="REST_API_KEY",
        description="Environment variable name that Garak's RestGenerator reads for the API key header",
    )

    def model_post_init(self, __context) -> None:
        """Derive all paths and endpoint URLs after environment/env-file values are loaded."""
        if self.app_dir is None:
            self.app_dir = self.project_root / "app"

        if self.data_dir is None:
            self.data_dir = self.project_root / "data"

        if self.artifacts_dir is None:
            self.artifacts_dir = self.project_root / "artifacts"

        if self.runs_dir is None:
            self.runs_dir = self.artifacts_dir / "runs"

        if self.config_dir is None:
            self.config_dir = self.app_dir / "config"

        if self.owasp_suites_path is None:
            self.owasp_suites_path = self.config_dir / "global" / "owasp_suites.json"

        if self.garak_rest_base_path is None:
            self.garak_rest_base_path = self.config_dir / "global" / "garak_rest_base.json"

        if self.garak_runs_dir is None:
            self.garak_runs_dir = Path("/root/.local/share/garak/garak_runs")

        if self.chroma_db_path is None:
            self.chroma_db_path = self.project_root / "chroma_db"

        DEFAULT_RAG = f"http://rag_api:{self.rag_port}"
        DEFAULT_SHIELD = f"http://shield_api:{self.shield_port}"

        self.rag_url = (self.rag_base_url or DEFAULT_RAG).rstrip("/")
        self.shield_url = (self.shield_base_url or DEFAULT_SHIELD).rstrip("/")

        self.rag_generate_url = f"{self.rag_url}/generate"
        self.shield_generate_url = f"{self.shield_url}/generate"

        self.rag_health_url = f"{self.rag_url}/health"
        self.shield_health_url = f"{self.shield_url}/health"

        if self.reports_dir is None:
            self.reports_dir = self.artifacts_dir / "reports"

        if self.latency_dir is None:
            self.latency_dir = self.artifacts_dir / "latency"

    def get_rag_config_path(self, dataset_tag: str) -> Path:
        return self.config_dir / "domains" / dataset_tag / "rag.json"

    def get_legitimate_prompts_path(self, dataset_tag: str) -> Path:
        return self.config_dir / "domains" / dataset_tag / "legitimate_prompts.json"

    def get_verification_queries_path(self, dataset_tag: str) -> Path:
        return self.config_dir / "domains" / dataset_tag / "verification_queries.json"

    def target_generate_url(self, target: Optional[Literal["unprotected", "protected"]] = None) -> str:
        """Return the /generate endpoint for the requested evaluation scenario."""
        t = target or self.target
        return self.shield_generate_url if t == "protected" else self.rag_generate_url

    def target_health_url(self, target: Optional[Literal["unprotected", "protected"]] = None) -> str:
        """Return the /health endpoint for the requested evaluation scenario."""
        t = target or self.target
        return self.shield_health_url if t == "protected" else self.rag_health_url

    def ensure_dirs(self) -> None:
        """Create artifact output directories if they do not exist."""
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.latency_dir.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the singleton Settings instance, creating artifact directories on first call.

    Usage::

        from settings import get_settings
        s = get_settings()
    """
    s = Settings()
    s.ensure_dirs()
    return s
