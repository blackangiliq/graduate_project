"""LLM providers: where the AI review, the deep scan and the rule learning get their model.

Three client types share one interface (check, models, chat_json):

  * OllamaClient        (sca/ai/llm.py)   a model on this computer - nothing leaves it
  * OpenAICompatClient                    any server that speaks the OpenAI chat-completions
                                          format: OpenAI, Google Gemini, OpenRouter, Groq,
                                          DeepSeek, Mistral, LM Studio, vLLM, ...
  * AnthropicClient                       the Claude API

PRIVACY: with a cloud provider the code snippets under review are sent to that provider.
Secrets found by the secrets engine are masked first. Use Ollama (or another local server)
when the code must not leave the machine.

The API key is read from the environment or from the .env file in the project folder
(which is git-ignored). It is never written to the scan database or to reports.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .llm import DEFAULT_MODEL, LLMError, OllamaClient, parse_json_object

ROOT = Path(__file__).resolve().parent.parent.parent

PRESETS: Dict[str, Dict[str, str]] = {
    "ollama": {"label": "Ollama (local, private)", "kind": "ollama",
               "base_url": "http://localhost:11434", "key_env": ""},
    "openai": {"label": "OpenAI API", "kind": "openai",
               "base_url": "https://api.openai.com/v1", "key_env": "OPENAI_API_KEY"},
    "anthropic": {"label": "Anthropic API (Claude)", "kind": "anthropic",
                  "base_url": "https://api.anthropic.com", "key_env": "ANTHROPIC_API_KEY"},
    "gemini": {"label": "Google Gemini API", "kind": "openai",
               "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
               "key_env": "GEMINI_API_KEY"},
    "openrouter": {"label": "OpenRouter", "kind": "openai",
                   "base_url": "https://openrouter.ai/api/v1", "key_env": "OPENROUTER_API_KEY"},
    "groq": {"label": "Groq", "kind": "openai",
             "base_url": "https://api.groq.com/openai/v1", "key_env": "GROQ_API_KEY"},
    "deepseek": {"label": "DeepSeek", "kind": "openai",
                 "base_url": "https://api.deepseek.com/v1", "key_env": "DEEPSEEK_API_KEY"},
    "mistral": {"label": "Mistral", "kind": "openai",
                "base_url": "https://api.mistral.ai/v1", "key_env": "MISTRAL_API_KEY"},
    "custom": {"label": "Other OpenAI-compatible server", "kind": "openai",
               "base_url": "http://localhost:1234/v1", "key_env": ""},
}
RETRY_STATUS = {429, 500, 502, 503, 529}


def is_local_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".local")


def http_json(method: str, url: str, headers: Optional[Dict[str, str]] = None,
              payload: Optional[Dict[str, Any]] = None, timeout: int = 60) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            value = json.loads(response.read().decode("utf-8", "replace") or "{}")
            return value if isinstance(value, dict) else {"data": value}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        message = body[:300]
        try:
            parsed = json.loads(body)
            error = parsed.get("error", parsed) if isinstance(parsed, dict) else parsed
            if isinstance(error, list) and error:
                error = error[0].get("error", error[0])
            if isinstance(error, dict):
                message = str(error.get("message") or error)[:300]
            elif isinstance(error, str):
                message = error[:300]
        except ValueError:
            pass
        failure = LLMError("HTTP %d: %s" % (exc.code, message))
        failure.status = exc.code
        try:
            failure.retry_after = float(exc.headers.get("Retry-After", ""))
        except (TypeError, ValueError):
            failure.retry_after = 0.0
        raise failure from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        failure = LLMError("request failed: %s" % exc)
        failure.status = 0
        raise failure from None


class _ApiClient:
    """Shared behaviour of the cloud clients."""
    kind = "api"
    backoff = 2.0          # seconds; multiplied by the attempt number
    max_wait = 30.0

    def __init__(self, base_url: str, api_key: str, model: str, timeout: int = 180,
                 name: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = (api_key or "").strip()
        self.model = (model or "").strip()
        self.timeout = timeout
        self.name = name or self.kind
        self.requests = 0

    @property
    def label(self) -> str:
        return "%s/%s" % (self.name, self.model)

    @property
    def is_local(self) -> bool:
        return is_local_url(self.base_url)

    def _headers(self) -> Dict[str, str]:
        raise NotImplementedError

    def _models_url(self) -> str:
        raise NotImplementedError

    def models(self) -> List[str]:
        try:
            data = http_json("GET", self._models_url(), self._headers(), timeout=15)
        except LLMError:
            return []
        items = data.get("data") or data.get("models") or []
        names = [str(m.get("id") or m.get("name") or "") for m in items if isinstance(m, dict)]
        return sorted(n for n in names if n)

    def check(self) -> Tuple[bool, str]:
        """(ready, message). Does one cheap request to verify the address and the key."""
        if not self.api_key and not self.is_local:
            return False, "no API key is set"
        if not self.model:
            return False, "no model is selected"
        try:
            http_json("GET", self._models_url(), self._headers(), timeout=15)
        except LLMError as exc:
            status = getattr(exc, "status", 0)
            if status in (401, 403):
                return False, "the API key was rejected (%s)" % exc
            if status == 0:
                return False, "cannot reach %s (%s)" % (self.base_url, exc)
            # 404/405: the server has no model list; chat may still work
        return True, "ready"

    def _post(self, url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        last: Optional[LLMError] = None
        for attempt in range(3):
            self.requests += 1
            try:
                return http_json("POST", url, self._headers(), payload, self.timeout)
            except LLMError as exc:
                last = exc
                if getattr(exc, "status", 0) not in RETRY_STATUS or attempt == 2:
                    raise
                wait = getattr(exc, "retry_after", 0.0) or self.backoff * (attempt + 1)
                time.sleep(min(wait, self.max_wait))
        raise last or LLMError("request failed")


class OpenAICompatClient(_ApiClient):
    kind = "openai"

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        return headers

    def _models_url(self) -> str:
        return self.base_url + "/models"

    def chat_json(self, system: str, user: str) -> Dict[str, Any]:
        base = {"model": self.model,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}]}
        # Not every server accepts every option, so fall back step by step on HTTP 400.
        variants = [
            dict(base, temperature=0, response_format={"type": "json_object"}),
            dict(base, temperature=0),
            base,
        ]
        for index, payload in enumerate(variants):
            try:
                data = self._post(self.base_url + "/chat/completions", payload)
                break
            except LLMError as exc:
                if getattr(exc, "status", 0) in (400, 422) and index < len(variants) - 1:
                    continue
                raise
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise LLMError("unexpected response format from %s" % self.name) from None
        if isinstance(content, list):   # some servers return a list of text parts
            content = "".join(str(part.get("text", "")) for part in content
                              if isinstance(part, dict))
        return parse_json_object(str(content or ""))


class AnthropicClient(_ApiClient):
    kind = "anthropic"
    max_tokens = 4096

    def _headers(self) -> Dict[str, str]:
        return {"Content-Type": "application/json", "x-api-key": self.api_key,
                "anthropic-version": os.environ.get("SCA_ANTHROPIC_VERSION", "2023-06-01")}

    def _models_url(self) -> str:
        return self.base_url + "/v1/models"

    def chat_json(self, system: str, user: str) -> Dict[str, Any]:
        url = self.base_url + "/v1/messages"
        # No sampling parameters are sent: recent API versions reject them.
        payload = {"model": self.model, "max_tokens": self.max_tokens, "system": system,
                   "messages": [{"role": "user", "content": user}]}
        try:
            data = self._post(url, payload)
        except LLMError as exc:
            if getattr(exc, "status", 0) != 400:
                raise
            # fall back to a request without the top-level system field
            payload = {"model": self.model, "max_tokens": self.max_tokens,
                       "messages": [{"role": "user", "content": system + "\n\n" + user}]}
            data = self._post(url, payload)
        blocks = data.get("content") or []
        text = "".join(str(b.get("text", "")) for b in blocks
                       if isinstance(b, dict) and b.get("type") == "text")
        return parse_json_object(text)


# ------------------------------------------------------------------ configuration
@dataclass
class LLMConfig:
    preset: str = "ollama"
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    timeout: int = 180

    def resolved_base_url(self) -> str:
        return self.base_url or PRESETS.get(self.preset, PRESETS["custom"])["base_url"]


def make_client(config: LLMConfig):
    preset = PRESETS.get(config.preset, PRESETS["custom"])
    base_url = config.resolved_base_url()
    if preset["kind"] == "ollama":
        return OllamaClient(base_url, config.model or DEFAULT_MODEL, config.timeout)
    if preset["kind"] == "anthropic":
        return AnthropicClient(base_url, config.api_key, config.model, config.timeout,
                               name=config.preset)
    return OpenAICompatClient(base_url, config.api_key, config.model, config.timeout,
                              name=config.preset)


def env_file() -> Path:
    override = os.environ.get("SCA_ENV_FILE")
    return Path(override) if override else ROOT / ".env"


def read_env_file() -> Dict[str, str]:
    values: Dict[str, str] = {}
    path = env_file()
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def load_config() -> LLMConfig:
    """Settings from the environment, then from the .env file, then the defaults."""
    stored = read_env_file()

    def get(name: str) -> str:
        return os.environ.get(name) or stored.get(name, "")

    preset = (get("SCA_LLM_PROVIDER") or "ollama").lower()
    if preset not in PRESETS:
        preset = "custom"
    api_key = get("SCA_LLM_API_KEY")
    key_env = PRESETS[preset]["key_env"]
    if not api_key and key_env:
        api_key = get(key_env)
    return LLMConfig(preset=preset, base_url=get("SCA_LLM_BASE_URL"), api_key=api_key,
                     model=get("SCA_LLM_MODEL"))


def save_config(config: LLMConfig) -> Path:
    """Write the settings to the .env file (other lines in the file are kept)."""
    path = env_file()
    new = {"SCA_LLM_PROVIDER": config.preset, "SCA_LLM_BASE_URL": config.base_url,
           "SCA_LLM_API_KEY": config.api_key, "SCA_LLM_MODEL": config.model}
    lines: List[str] = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.split("=", 1)[0].strip() not in new:
                lines.append(line)
    lines += ["%s=%s" % (key, value) for key, value in new.items() if value]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)      # readable by the owner only (no effect on Windows)
    except OSError:
        pass
    return path
