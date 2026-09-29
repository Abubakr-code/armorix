"""Local model client (Ollama) — loopback only, so source code never leaves the machine."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlparse

DEFAULT_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen2.5-coder:1.5b"
LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}


class AIUnavailable(RuntimeError):
    pass


class LocalAI:
    """Talks to either Ollama (/api/generate) or Armorix's bundled llama.cpp server (/v1/chat/completions)."""

    def __init__(self, url: str | None = None, model: str | None = None, timeout: float = 180, backend: str = "ollama"):
        self.backend = backend
        self.url = (url or os.environ.get("ARMORIX_OLLAMA") or DEFAULT_URL).rstrip("/")
        self.model = model or os.environ.get("ARMORIX_MODEL") or DEFAULT_MODEL
        self.timeout = timeout
        host = urlparse(self.url).hostname or ""
        if host not in LOOPBACK and os.environ.get("ARMORIX_ALLOW_REMOTE_AI") != "1":
            # The whole product promise is "code never leaves the machine".
            raise AIUnavailable(f"refusing non-local model endpoint {self.url} (set ARMORIX_ALLOW_REMOTE_AI=1 to override)")

    def _post(self, path: str, payload: dict) -> dict:
        req = urllib.request.Request(self.url + path, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read())

    def check(self) -> None:
        if self.backend == "llamacpp":
            try:
                with urllib.request.urlopen(self.url + "/health", timeout=3) as resp:
                    if json.loads(resp.read()).get("status") != "ok":
                        raise AIUnavailable("local AI engine is still loading the model")
            except (urllib.error.URLError, OSError, ValueError) as exc:
                raise AIUnavailable(f"local AI engine not reachable at {self.url}") from exc
            return
        try:
            with urllib.request.urlopen(self.url + "/api/tags", timeout=3) as resp:
                names = {m["name"] for m in json.loads(resp.read()).get("models", [])}
        except (urllib.error.URLError, OSError) as exc:
            raise AIUnavailable(f"local AI engine not reachable at {self.url} — is `ollama serve` running?") from exc
        if self.model not in names and f"{self.model}:latest" not in names:
            raise AIUnavailable(f"model {self.model} not installed — run: ollama pull {self.model}")

    def generate(self, prompt: str, max_tokens: int = 700, json_mode: bool = False) -> str:
        if self.backend == "llamacpp":
            payload = {
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0, "max_tokens": max_tokens, "repeat_penalty": 1.05, "stream": False,
            }
            if json_mode:
                payload["response_format"] = {"type": "json_object"}
            data = self._post("/v1/chat/completions", payload)
            return (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "keep_alive": "10m",
            # Deterministic and bounded: small models can loop forever without a cap.
            "options": {"temperature": 0, "num_predict": max_tokens, "repeat_penalty": 1.05, "num_ctx": 4096},
        }
        if json_mode:
            payload["format"] = "json"
        return self._post("/api/generate", payload).get("response", "")
