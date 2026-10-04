"""Safe file upload and artifact storage abstraction."""

import os
import re
import hashlib
from abc import ABC, abstractmethod
from typing import Tuple
from fastapi import HTTPException

from app.core.config import settings


class ArtifactStorage(ABC):
    """Abstract interface for artifact storage."""

    @abstractmethod
    def store(self, filename: str, content: bytes) -> Tuple[str, str, int]:
        """Store content and return (stored_file_path, sha256, size_bytes)."""
        pass


class LocalArtifactStorage(ArtifactStorage):
    """Local disk artifact storage implementation with security validation."""

    def __init__(self, upload_dir: str = settings.UPLOAD_DIR, max_upload_size: int | None = None):
        self.upload_dir = os.path.abspath(upload_dir)
        self.max_upload_size = max_upload_size if max_upload_size is not None else settings.MAX_UPLOAD_SIZE
        os.makedirs(self.upload_dir, exist_ok=True)

    def sanitize_filename(self, filename: str) -> str:
        """Sanitize raw filename to prevent path traversal and shell injection."""
        base = os.path.basename(filename)
        # Remove any non-alphanumeric except dots, dashes, underscores
        clean = re.sub(r"[^a-zA-Z0-9.\-_]", "_", base)
        if not clean or clean.startswith("."):
            clean = "artifact.eml"
        return clean

    def store(self, filename: str, content: bytes) -> Tuple[str, str, int]:
        """Validate, hash, and safely store file content."""
        size = len(content)
        if size > self.max_upload_size:
            raise HTTPException(
                status_code=400,
                detail=f"File size {size} exceeds max allowed {self.max_upload_size} bytes",
            )

        safe_name = self.sanitize_filename(filename)
        sha256 = hashlib.sha256(content).hexdigest()

        # Unique safe target path using SHA256 prefix
        target_filename = f"{sha256[:16]}_{safe_name}"
        target_path = os.path.abspath(os.path.join(self.upload_dir, target_filename))

        # Security check: Ensure target path remains inside upload_dir (prevent path traversal)
        if os.path.commonpath((target_path, self.upload_dir)) != self.upload_dir:
            raise HTTPException(status_code=400, detail="Invalid target file path")

        with open(target_path, "wb") as f:
            f.write(content)

        return target_path, sha256, size
