"""Model gateway: one OpenAI-compatible interface for every open-weight model
(Groq, OpenRouter, Ollama). Identical parameters for all models keeps the
benchmark fair."""
import json
import os
import re
import threading
import time

import requests

from .config import STRUCTURED_OUTPUT, LLM_MIN_INTERVAL, LLM_TEMPERATURE, LLM_TIMEOUT, MODELS, PROVIDERS

_rate_lock = threading.Lock()
_last_call = {"t": 0.0}


class LLMError(Exception):
    pass


def model_info(model_key):
    if model_key not in MODELS:
        raise LLMError(f"Unknown model '{model_key}'. Add it to config/models.json")
    return MODELS[model_key]


def is_mock(model_key):
    return model_info(model_key)["provider"] == "mock"


def chat(model_key, messages, temperature=None, max_tokens=4000, schema=None):
    """Send a chat completion. Returns (text, latency_seconds)."""
    info = model_info(model_key)
    provider = PROVIDERS[info["provider"]]
    headers = {"Content-Type": "application/json"}
    if provider["key_env"]:
        key = os.getenv(provider["key_env"])
        if not key:
            raise LLMError(f"Missing {provider['key_env']} in .env")
        headers["Authorization"] = f"Bearer {key}"
    body = {
        "model": info["model"],
        "messages": messages,
        "temperature": LLM_TEMPERATURE if temperature is None else temperature,
        "max_tokens": max_tokens,
    }
    if schema and STRUCTURED_OUTPUT:
        body["response_format"] = schema

    with _rate_lock:  # simple client-side rate limiting for free tiers
        wait = LLM_MIN_INTERVAL - (time.time() - _last_call["t"])
        if wait > 0:
            time.sleep(wait)
        _last_call["t"] = time.time()

    t0 = time.time()
    for attempt in range(3):
        try:
            r = requests.post(f"{provider['base_url']}/chat/completions",
                              headers=headers, json=body, timeout=LLM_TIMEOUT)
        except requests.RequestException as e:
            if attempt == 2:
                raise LLMError(f"Network error calling {info['model']}: {e}")
            time.sleep(2 * (attempt + 1))
            continue
        if r.status_code == 429 or r.status_code >= 500:
            if attempt == 2:
                raise LLMError(f"HTTP {r.status_code} from provider: {r.text[:200]}")
            try:
                delay = float(r.headers.get("retry-after") or 0)
            except ValueError:
                delay = 0
            time.sleep(min(max(delay, 3 * (attempt + 1)), 30))
            continue
        if r.status_code == 400 and "response_format" in body:
            body.pop("response_format")  # model/provider lacks structured output: retry plain
            continue
        if r.status_code != 200:
            raise LLMError(f"HTTP {r.status_code} from provider: {r.text[:300]}")
        data = r.json()
        text = (data.get("choices") or [{}])[0].get("message", {}).get("content") or ""
        return text, round(time.time() - t0, 3)
    raise LLMError("Retries exhausted")


_THINK_RE = re.compile(r"<think>.*?</think>", re.S | re.I)


def extract_json(text):
    """Parse the first JSON object in a model reply (handles <think> blocks and
    ``` fences). Raises ValueError if none is found."""
    if not text:
        raise ValueError("empty response")
    cleaned = _THINK_RE.sub("", text).strip()
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.M).strip()
    try:
        obj = json.loads(cleaned)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    start = cleaned.find("{")
    while start != -1:
        depth = 0
        in_str = esc = False
        for i in range(start, len(cleaned)):
            ch = cleaned[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(cleaned[start:i + 1])
                        if isinstance(obj, dict):
                            return obj
                    except json.JSONDecodeError:
                        break
                    break
        start = cleaned.find("{", start + 1)
    raise ValueError("no JSON object found in response")
