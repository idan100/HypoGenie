"""
Central LLM client factory.
Reads config/models.yaml and .env from the project root.
All modules should use get_client() / get_model() from here.
"""

import os
import sys
import yaml
from pathlib import Path

# Always load .env from the project root (two levels up from src/)
_project_root = Path(__file__).parent.parent
_env_path = _project_root / ".env"
if _env_path.exists():
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=str(_env_path), override=False)

# Load config/models.yaml
_config_path = _project_root / "config" / "models.yaml"
_config: dict = {}
if _config_path.exists():
    with open(_config_path) as f:
        _config = yaml.safe_load(f) or {}

_DEFAULT_PROVIDER = _config.get("default_provider", "anthropic")
_ANTHROPIC_MODEL = _config.get("anthropic", {}).get("model", "claude-haiku-4-5")
_OPENAI_MODEL = _config.get("openai", {}).get("model", "gpt-4o-mini")

_anthropic_client = None
_openai_client = None


def get_provider(override: str | None = None) -> str:
    """Return provider: env override → config default."""
    return (
        override
        or os.environ.get("HYPOGENIE_PROVIDER")
        or _DEFAULT_PROVIDER
    )


def get_model(provider: str, role_env: str | None = None) -> str:
    """
    Return the model ID for the given provider.
    role_env: optional env-var name to check first (e.g. 'GAP_FINDER_MODEL').
    """
    if role_env:
        v = os.environ.get(role_env)
        if v:
            return v
    if provider == "anthropic":
        return os.environ.get("HYPOGENIE_ANTHROPIC_MODEL", _ANTHROPIC_MODEL)
    return os.environ.get("HYPOGENIE_OPENAI_MODEL", _OPENAI_MODEL)


def get_client(provider: str | None = None):
    """Return (provider_name, client) for the given (or default) provider."""
    prov = get_provider(provider)
    global _anthropic_client, _openai_client
    if prov == "anthropic":
        if _anthropic_client is None:
            import anthropic
            _anthropic_client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
        return ("anthropic", _anthropic_client)
    else:
        if _openai_client is None:
            from openai import OpenAI
            _openai_client = OpenAI()  # reads OPENAI_API_KEY from env
        return ("openai", _openai_client)


def call_llm(
    system: str,
    user: str,
    provider: str | None = None,
    role_env: str | None = None,
    max_tokens: int = 4096,
    json_mode: bool = True,
) -> str:
    """
    Make a single LLM call (no tool loop). Checks cache; writes cache on hit.
    """
    import cache as _cache_mod
    prov, client = get_client(provider)
    model = get_model(prov, role_env)

    cached = _cache_mod.get(prov, model, system, user)
    if cached is not None:
        return cached

    if prov == "anthropic":
        resp = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        result = resp.content[0].text
    else:
        kwargs = dict(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            max_tokens=max_tokens,
        )
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        resp = client.chat.completions.create(**kwargs)
        result = resp.choices[0].message.content

    _cache_mod.put(prov, model, system, user, result)
    return result
