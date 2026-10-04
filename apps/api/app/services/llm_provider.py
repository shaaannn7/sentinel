"""Bounded LLM provider abstraction for evidence-only analysis."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

import httpx

from app.core.config import settings


class LLMUnavailableError(RuntimeError):
    """Raised when AI enrichment is unavailable."""


class BaseLLM(ABC):
    @abstractmethod
    def get_response(self, prompt: str) -> str:
        """Return a response for a constructed evidence-only prompt."""


class MockLLM(BaseLLM):
    def get_response(self, prompt: str) -> str:
        agent = next(
            (name for name in ("header", "url", "content", "correlation", "report") if f"AGENT: {name}" in prompt),
            "unknown",
        )
        responses: dict[str, dict[str, Any]] = {
            "header": {"assessment": "Mock header assessment.", "findings": [], "confidence": 0},
            "url": {"assessment": "Mock URL assessment.", "findings": [], "confidence": 0},
            "content": {"assessment": "Mock content assessment.", "signals": [], "confidence": 0},
            "correlation": {"assessment": "Mock correlation assessment.", "relationships": [], "confidence": 0},
            "report": {"summary": "AI mock enrichment completed.", "recommendations": [], "confidence": 0},
            "unknown": {},
        }
        return json.dumps(responses[agent])


class OpenAILLM(BaseLLM):
    """OpenAI-compatible JSON client with no tools enabled."""

    def get_response(self, prompt: str) -> str:
        if not settings.LLM_API_KEY:
            raise LLMUnavailableError("LLM API key is not configured")
        try:
            response = httpx.post(
                settings.LLM_API_URL.rstrip("/") + "/chat/completions",
                headers={"Authorization": f"Bearer {settings.LLM_API_KEY}"},
                json={
                    "model": settings.LLM_MODEL,
                    "messages": [
                        {"role": "system", "content": "Return JSON only. Do not use tools."},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0,
                    "tools": [],
                },
                timeout=settings.LLM_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, IndexError, TypeError) as exc:
            raise LLMUnavailableError("LLM request failed or returned an invalid response") from exc


class LLMProvider:
    """Select a configured backend; never silently turn provider failure into AI output."""

    def __init__(self) -> None:
        provider = settings.LLM_PROVIDER.lower()
        if provider == "mock" and settings.LLM_MOCK_ENABLED:
            self.backend: BaseLLM = MockLLM()
            self.available = True
        elif provider in {"openai", "openai-compatible"}:
            self.backend = OpenAILLM()
            self.available = bool(settings.LLM_API_KEY)
        else:
            self.backend = MockLLM()
            self.available = False

    def get_response(self, prompt: str) -> str:
        if not self.available:
            raise LLMUnavailableError("AI enrichment unavailable")
        return self.backend.get_response(prompt)
