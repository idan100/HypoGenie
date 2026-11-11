"""
Central LLM client factory.
Reads config/models.yaml and .env from the project root.
All modules should use get_client() / get_model() from here.
"""

import os
import sys
import threading
import yaml
from pathlib import Path

# Import run_id lazily to avoid circular issues; modules may import us at module level.
def _run_id() -> str:
    try:
        from run_context import run_id
        return run_id
    except Exception:
        return "?"

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

# ── Token tracking ─────────────────────────────────────────────────────────────
# Cost per 1 million tokens (input, output) in USD.
# Prefix-matched: longest matching prefix wins.
_PRICING: list[tuple[str, float, float]] = [
    ("claude-opus",    15.00, 75.00),
    ("claude-sonnet",   3.00, 15.00),
    ("claude-haiku",    0.80,  4.00),
    ("claude-3-5",      3.00, 15.00),   # catch-all for claude-3-5-* sonnet variants
    ("claude-3-haiku",  0.25,  1.25),
    ("gpt-4o-mini",     0.15,  0.60),
    ("gpt-4o",          5.00, 15.00),
    ("gpt-4-turbo",    10.00, 30.00),
    ("gpt-3.5",         0.50,  1.50),
]

def _price_per_token(model: str) -> tuple[float, float]:
    """Return (input_cost_per_token, output_cost_per_token) in USD."""
    m = model.lower()
    for prefix, inp_per_m, out_per_m in _PRICING:
        if m.startswith(prefix):
            return inp_per_m / 1_000_000, out_per_m / 1_000_000
    return 0.0, 0.0  # unknown model — no cost estimate

_token_lock = threading.Lock()
_token_log: dict[str, dict] = {}


def track_usage(module: str, provider: str, model: str,
                input_tokens: int, output_tokens: int) -> None:
    """Accumulate token usage for a module. Thread-safe."""
    inp_rate, out_rate = _price_per_token(model)
    cost = input_tokens * inp_rate + output_tokens * out_rate
    with _token_lock:
        if module not in _token_log:
            _token_log[module] = {
                "calls": 0, "input_tokens": 0, "output_tokens": 0,
                "cost_usd": 0.0, "model": model, "provider": provider,
            }
        entry = _token_log[module]
        entry["calls"] += 1
        entry["input_tokens"] += input_tokens
        entry["output_tokens"] += output_tokens
        entry["cost_usd"] = round(entry["cost_usd"] + cost, 6)
        entry["model"] = model      # keep last model used for this module
        entry["provider"] = provider


def get_token_log() -> dict:
    """Return a copy of the token log with grand totals."""
    with _token_lock:
        log = {k: dict(v) for k, v in _token_log.items()}
    total_input  = sum(v["input_tokens"]  for v in log.values())
    total_output = sum(v["output_tokens"] for v in log.values())
    total_cost   = round(sum(v["cost_usd"] for v in log.values()), 6)
    return {
        "total_input_tokens":  total_input,
        "total_output_tokens": total_output,
        "total_tokens":        total_input + total_output,
        "total_cost_usd":      total_cost,
        "by_module":           log,
    }


def reset_token_log() -> None:
    with _token_lock:
        _token_log.clear()


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
        print(f"  [llm_client:{_run_id()}] cache hit ({prov}/{model})")
        return cached

    if prov == "anthropic":
        resp = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        result = resp.content[0].text
        track_usage(
            role_env or "unknown", prov, model,
            resp.usage.input_tokens, resp.usage.output_tokens,
        )
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
        if resp.usage:
            track_usage(
                role_env or "unknown", prov, model,
                resp.usage.prompt_tokens, resp.usage.completion_tokens,
            )

    print(f"  [llm_client:{_run_id()}] call ({prov}/{model}, {len(user)} chars)")
    _cache_mod.put(prov, model, system, user, result)
    return result
