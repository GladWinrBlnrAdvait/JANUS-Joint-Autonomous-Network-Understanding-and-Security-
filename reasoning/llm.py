"""
LLM access: a small interface plus a JSON-with-retry helper.

The rest of the layer depends only on `LLMClient.complete(system, user)`, so
the provider can be swapped (or faked in tests) without touching anything else.
"""

import json
import os
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from reasoning.decisionlog import DecisionLog, sha256_text


class LLMError(RuntimeError):
    pass


class ReasoningError(RuntimeError):
    """The model never produced a valid, schema-conforming answer."""


class LLMClient:
    model = "unknown"

    def complete(self, system: str, user: str) -> str:
        raise NotImplementedError


class ScriptedLLM(LLMClient):
    """Returns pre-set replies in order. For tests; records every prompt it saw."""
    model = "scripted"

    def __init__(self, replies: List[str]):
        self.replies = list(replies)
        self.calls: List[Dict[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append({"system": system, "user": user})
        if not self.replies:
            raise LLMError("ScriptedLLM has no replies left")
        return self.replies.pop(0)


class AnthropicClient(LLMClient):
    """Plain-HTTPS client for the Anthropic Messages API (no SDK dependency).
    Key from ANTHROPIC_API_KEY; model from JANUS_LLM_MODEL. Not exercised by the
    offline tests: verify with a real key before relying on it."""

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None,
                 max_tokens: int = 4000, timeout: int = 120):
        self.model = model or os.environ.get("JANUS_LLM_MODEL", "claude-sonnet-5-5")
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise LLMError("ANTHROPIC_API_KEY is not set")
        self.max_tokens, self.timeout = max_tokens, timeout

    def complete(self, system: str, user: str) -> str:
        body = json.dumps({"model": self.model, "max_tokens": self.max_tokens,
                           "system": system,
                           "messages": [{"role": "user", "content": user}]}).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages", data=body, method="POST",
            headers={"content-type": "application/json", "x-api-key": self.api_key,
                     "anthropic-version": "2023-06-01"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except (urllib.error.URLError, TimeoutError) as exc:
            raise LLMError(f"LLM request failed: {exc}") from exc
        return "".join(b.get("text", "") for b in data.get("content", [])
                       if b.get("type") == "text")


def extract_json(text: str) -> Dict[str, Any]:
    """Pull the JSON object out of a reply, tolerating code fences and chatter."""
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("reply contains no JSON object")
    try:
        obj = json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise ValueError(f"reply is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError("reply JSON must be an object")
    return obj


def call_json(llm: LLMClient, log: DecisionLog, stage: str, finding_id: str,
              system: str, user: str, parse: Callable[[Dict[str, Any]], Any],
              max_retries: int = 2):
    """
    Ask for JSON, parse it with `parse` (which raises ValueError on any schema
    problem), and on failure retry with the error spelled out. Every attempt is
    logged. Raises ReasoningError when attempts are exhausted.
    """
    prompt, last_error = user, None
    for attempt in range(1, max_retries + 2):
        raw = llm.complete(system, prompt)
        try:
            result = parse(extract_json(raw))
        except ValueError as exc:
            last_error = str(exc)
            log.record(stage, finding_id, attempt=attempt, model=llm.model,
                       prompt_sha256=sha256_text(system + prompt), raw_response=raw,
                       outcome="rejected", error=last_error)
            prompt = (user + "\n\nYour previous reply was rejected: " + last_error +
                      "\nReturn corrected JSON only.")
            continue
        log.record(stage, finding_id, attempt=attempt, model=llm.model,
                   prompt_sha256=sha256_text(system + prompt), raw_response=raw,
                   outcome="accepted")
        return result
    raise ReasoningError(f"{stage} failed after {max_retries + 1} attempts: {last_error}")
