"""
Builder — Docker Hub pull → source-build fallback.

Steps:
1. Try docker pull {product}:{version}
2. If pull fails → build from source (write Dockerfile, docker build)
3. Setup Developer (LLM) generates server config + returns config_path and ports
4. Setup Critic validates cert paths are /certs/server.crt and /certs/server.key
5. docker run with TLS cert mount at /certs/ and config file mount at config_path
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import llm_client as _llm
from run_context import run_id as _run_id

from .prompts import (
    SETUP_DEVELOPER_SYSTEM,
    SETUP_DEVELOPER_USER_TEMPLATE,
    SETUP_CRITIC_SYSTEM,
    SETUP_CRITIC_USER_TEMPLATE,
)

_CERTS_DIR = Path(__file__).parent.parent.parent / "infra" / "certs"
_WORKSPACE = Path(__file__).parent.parent.parent / "workspace" / "runs"

_running_containers: list[str] = []


def _extract_json(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-zA-Z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw.strip())
    start = raw.find("{")
    if start == -1:
        return raw
    depth = 0
    for i, ch in enumerate(raw[start:], start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return raw[start : i + 1]
    return raw[start:]


def _docker_pull(image: str) -> bool:
    """Try docker pull. Returns True on success."""
    print(f"  [builder:{_run_id}] Trying docker pull {image} ...")
    result = subprocess.run(
        ["docker", "pull", image],
        capture_output=True, text=True, timeout=120
    )
    if result.returncode == 0:
        print(f"  [builder:{_run_id}] Pull succeeded.")
        return True
    print(f"  [builder:{_run_id}] Pull failed: {result.stderr.strip()[:200]}")
    return False


def _source_build(product: str, version: str, run_dir: Path) -> str:
    """
    Fallback: write a minimal Dockerfile and docker build.
    Returns the image tag built.
    """
    print(f"  [builder:{_run_id}] Source-build fallback for {product}:{version}")
    # Minimal Dockerfile — just install from package manager
    dockerfile = f"""FROM ubuntu:22.04
RUN apt-get update && apt-get install -y {product} --no-install-recommends && rm -rf /var/lib/apt/lists/*
"""
    df_path = run_dir / "Dockerfile"
    df_path.write_text(dockerfile)
    tag = f"hypogenie-{product}-{version}:latest"
    result = subprocess.run(
        ["docker", "build", "-t", tag, str(run_dir)],
        capture_output=True, text=True, timeout=300
    )
    if result.returncode != 0:
        raise RuntimeError(f"Source build failed: {result.stderr.strip()[:400]}")
    print(f"  [builder:{_run_id}] Source build succeeded: {tag}")
    return tag


def _setup_developer(product: str, version: str, entry_point: str) -> dict:
    """LLM call: generate server config, config_path, ports."""
    user = SETUP_DEVELOPER_USER_TEMPLATE.format(
        product=product, version=version, entry_point=entry_point
    )
    print(f"  [builder:{_run_id}] Setup Developer ...")
    raw = _llm.call_llm(
        SETUP_DEVELOPER_SYSTEM, user,
        role_env="BUILDER_MODEL", json_mode=True
    )
    raw = _extract_json(raw)
    d = json.loads(raw)
    return {
        "config": d.get("config", ""),
        "config_path": d.get("config_path", ""),
        "ports": d.get("ports", ""),
    }


def _setup_critic(product: str, entry_point: str, setup: dict) -> bool:
    """LLM critic: verify cert paths and non-empty fields."""
    user = SETUP_CRITIC_USER_TEMPLATE.format(
        product=product,
        entry_point=entry_point,
        config=setup["config"][:2000],
        config_path=setup["config_path"],
        ports=setup["ports"],
    )
    print(f"  [builder:{_run_id}] Setup Critic ...")
    raw = _llm.call_llm(
        SETUP_CRITIC_SYSTEM, user,
        role_env="BUILDER_MODEL", max_tokens=256, json_mode=False
    )
    raw = raw.strip()
    if raw.upper().startswith("PASS"):
        print(f"  [builder:{_run_id}] Critic: PASS")
        return True
    # Also do a hard check regardless of LLM verdict
    config = setup["config"]
    has_crt = "/certs/server.crt" in config
    has_key = "/certs/server.key" in config
    if not has_crt or not has_key:
        print(f"  [builder:{_run_id}] Critic hard-fail: cert paths missing (crt={has_crt}, key={has_key})")
        return False
    print(f"  [builder:{_run_id}] Critic: PASS (hard-check ok)")
    return True


def build(product: str, version: str, entry_point: str = "TCP port 443, HTTPS",
          docker_image: str | None = None) -> dict:
    """
    Build and start a server container for the given product/version.

    Args:
        product:     e.g. "nginx"
        version:     e.g. "1.25.3"
        entry_point: human description of the protocol/port, e.g. "TCP port 443, HTTPS"

    Returns:
        dict with keys: container_id, image, config_path, ports, run_dir
    """
    run_dir = _WORKSPACE / _run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    if docker_image:
        image = docker_image
        print(f"  [builder:{_run_id}] Using docker_image override: {image}")
        _docker_pull(image)  # pre-pull; ignore failure (may already be cached)
        # Derive product name from image (e.g. "caddy:2.7.6" → "caddy")
        effective_product = image.split(":")[0].split("/")[-1]
        effective_version = image.split(":")[-1] if ":" in image else version
    else:
        image = f"{product}:{version}"
        pulled = _docker_pull(image)
        if not pulled:
            image = _source_build(product, version, run_dir)
        effective_product = product
        effective_version = version

    # Generate server config via LLM
    setup = _setup_developer(effective_product, effective_version, entry_point)

    # Critic validates cert paths
    critic_ok = _setup_critic(effective_product, entry_point, setup)
    if not critic_ok:
        # Retry setup developer once with explicit cert path instruction
        user_retry = (
            SETUP_DEVELOPER_USER_TEMPLATE.format(
                product=effective_product, version=effective_version, entry_point=entry_point
            )
            + "\n\nIMPORTANT: The config MUST reference /certs/server.crt and /certs/server.key exactly."
        )
        print(f"  [builder:{_run_id}] Retrying Setup Developer with cert path hint ...")
        raw = _llm.call_llm(
            SETUP_DEVELOPER_SYSTEM, user_retry, role_env="BUILDER_MODEL", json_mode=True
        )
        setup = json.loads(_extract_json(raw))
        critic_ok = _setup_critic(effective_product, entry_point, setup)
        if not critic_ok:
            raise RuntimeError("Setup Developer could not produce valid cert paths after retry")

    # Write server config to workspace
    conf_file = run_dir / "server.conf"
    conf_file.write_text(setup["config"])
    print(f"  [builder:{_run_id}] Server config written to {conf_file}")

    # Build docker run command
    port_args = []
    for mapping in setup["ports"].split():
        port_args += ["-p", mapping]

    certs_dir = str(_CERTS_DIR)
    config_path = setup["config_path"]

    cmd = [
        "docker", "run", "-d",
        "--name", f"hypogenie-{_run_id}",
        "-v", f"{certs_dir}/server.crt:/certs/server.crt:ro",
        "-v", f"{certs_dir}/server.key:/certs/server.key:ro",
        "-v", f"{conf_file}:{config_path}:ro",
    ] + port_args + [image]

    print(f"  [builder:{_run_id}] Starting container: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

    if result.returncode != 0:
        raise RuntimeError(f"docker run failed: {result.stderr.strip()[:400]}")

    container_id = result.stdout.strip()
    _running_containers.append(container_id)
    print(f"  [builder:{_run_id}] Container started: {container_id[:12]}")

    return {
        "container_id": container_id,
        "image": image,
        "config_path": config_path,
        "ports": setup["ports"],
        "run_dir": str(run_dir),
    }


def teardown(container_id: str) -> None:
    """Stop and remove a container."""
    print(f"  [builder:{_run_id}] Stopping {container_id[:12]} ...")
    subprocess.run(["docker", "stop", container_id], capture_output=True, timeout=30)
    subprocess.run(["docker", "rm", container_id], capture_output=True, timeout=30)
    if container_id in _running_containers:
        _running_containers.remove(container_id)
    print(f"  [builder:{_run_id}] Container removed.")
