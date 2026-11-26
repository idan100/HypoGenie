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
    DOCKERFILE_DEVELOPER_SYSTEM,
    DOCKERFILE_DEVELOPER_USER_TEMPLATE,
    DOCKERFILE_FIX_SYSTEM,
    DOCKERFILE_FIX_USER_TEMPLATE,
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


def _port_args(ports_str: str) -> list[str]:
    """Convert a ports string like '443:443/tcp 443:443/udp' to ['-p', '443:443/tcp', ...]
    Tolerates LLM responses that include '-p' flags in the string itself."""
    args = []
    for token in ports_str.split():
        if token.startswith("-"):
            continue  # skip any -p flags the LLM added
        args += ["-p", token]
    return args


def _image_exists_locally(image: str) -> bool:
    """Return True if the image is present in the local Docker image store."""
    r = subprocess.run(["docker", "image", "inspect", image],
                       capture_output=True, text=True)
    return r.returncode == 0


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


def _dockerfile_build(product: str, version: str, entry_point: str,
                      protocol: str, repo_url: str, run_dir: Path) -> tuple[str, dict]:
    """
    LLM-driven source build: generate Dockerfile + app files, then docker build.
    Returns (image_tag, setup_dict) where setup_dict has config_path and ports.
    """
    print(f"  [builder:{_run_id}] LLM Dockerfile build for {product}@{version} ...")
    user = DOCKERFILE_DEVELOPER_USER_TEMPLATE.format(
        product=product, version=version, entry_point=entry_point,
        protocol=protocol, repo_url=repo_url,
    )
    raw = _llm.call_llm(
        DOCKERFILE_DEVELOPER_SYSTEM, user,
        role_env="BUILDER_MODEL", max_tokens=4096, json_mode=True
    )
    d = json.loads(_extract_json(raw))

    dockerfile = d.get("dockerfile", "")
    app_files = d.get("app_files", {})
    config_path = d.get("config_path", "")
    ports = d.get("ports", "443:443/tcp")

    if not dockerfile:
        raise RuntimeError("LLM returned empty Dockerfile")

    def _write_files(df: str, files: dict) -> None:
        (run_dir / "Dockerfile").write_text(df)
        for fname, fcontent in files.items():
            dest = run_dir / fname
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(fcontent)

    _write_files(dockerfile, app_files)

    tag = f"hypogenie-{product}-{version}:latest".replace("/", "-").lower()
    for attempt in range(3):
        result = subprocess.run(
            ["docker", "build", "-t", tag, str(run_dir)],
            capture_output=True, text=True, timeout=600
        )
        if result.returncode == 0:
            break
        # Combine stdout+stderr: compilation errors typically appear in stdout
        build_error = (result.stdout + "\n" + result.stderr).strip()
        if attempt == 2:
            raise RuntimeError(f"Source build failed:\n{build_error[:600]}")
        print(f"  [builder:{_run_id}] Build attempt {attempt+1} failed — asking LLM to fix ...")
        app_files_text = "\n\n".join(
            f"{fname}:\n{content}" for fname, content in app_files.items()
        ) or "(none)"
        fix_user = DOCKERFILE_FIX_USER_TEMPLATE.format(
            build_error=build_error[-3000:],  # tail: most relevant errors are at end
            dockerfile=dockerfile,
            app_files_text=app_files_text,
        )
        raw = _llm.call_llm(
            DOCKERFILE_FIX_SYSTEM, fix_user,
            role_env="BUILDER_FIX_MODEL", max_tokens=4096, json_mode=True
        )
        d2 = json.loads(_extract_json(raw))
        dockerfile = d2.get("dockerfile", dockerfile)
        app_files = d2.get("app_files", app_files)
        config_path = d2.get("config_path", config_path)
        ports = d2.get("ports", ports)
        _write_files(dockerfile, app_files)

    print(f"  [builder:{_run_id}] Source build succeeded: {tag}")
    return tag, {"config_path": config_path, "ports": ports}


def _setup_developer(product: str, version: str, entry_point: str,
                     server_config_hint: str = "") -> dict:
    """LLM call: generate server config, config_path, ports."""
    user = SETUP_DEVELOPER_USER_TEMPLATE.format(
        product=product, version=version, entry_point=entry_point
    )
    if server_config_hint.strip():
        user += (
            "\n\nThe YAML hypothesis provides the following server configuration hint. "
            "Use it as a base and extend it as needed (keep all directives present, "
            "add cert paths and any required fields):\n\n"
            f"```\n{server_config_hint.strip()}\n```"
        )
    print(f"  [builder:{_run_id}] Setup Developer ...")
    raw = _llm.call_llm(
        SETUP_DEVELOPER_SYSTEM, user,
        role_env="BUILDER_MODEL", json_mode=True
    )
    raw = _extract_json(raw)
    try:
        d = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        print(f"  [builder:{_run_id}] Setup Developer returned non-JSON — using empty config defaults.")
        d = {}
    return {
        "config": d.get("config", ""),
        "config_path": d.get("config_path", ""),
        "ports": d.get("ports", ""),
        "env_vars": d.get("env_vars", {}),
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
    # Hard check: if config is empty, the image handles certs internally — no cert paths expected
    config = setup["config"]
    if not config.strip():
        print(f"  [builder:{_run_id}] Critic: PASS (no config — image handles certs internally)")
        return True
    has_crt = "/certs/server.crt" in config
    has_key = "/certs/server.key" in config
    if not has_crt or not has_key:
        print(f"  [builder:{_run_id}] Critic hard-fail: cert paths missing (crt={has_crt}, key={has_key})")
        return False
    print(f"  [builder:{_run_id}] Critic: PASS (hard-check ok)")
    return True


def build(product: str, version: str, entry_point: str = "TCP port 443, HTTPS",
          docker_image: str | None = None, protocol: str = "HTTP/2",
          repo_url: str = "", server_config_hint: str = "",
          services: list | None = None) -> dict:
    """
    Build and start a server container (or multi-container environment) for the
    given product/version.

    When `services` is a non-empty list of ServiceSpec objects, delegates to
    _build_multi() which creates a Docker bridge network, starts all supporting
    services first, then starts the role='target' service with ports exposed.
    docker_image and server_config_hint are ignored in that case.

    Returns:
        dict with keys: container_id, image, config_path, ports, run_dir,
        and optionally aux_container_ids and network_name for multi-container runs.
    """
    if services:
        return _build_multi(services, protocol, entry_point, product, version, repo_url)

    run_dir = _WORKSPACE / _run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    if docker_image:
        image = docker_image
        print(f"  [builder:{_run_id}] Using docker_image override: {image}")
        if _image_exists_locally(image):
            print(f"  [builder:{_run_id}] Image found in local store — skipping pull.")
        elif _docker_pull(image):
            pass  # _docker_pull already prints success
        else:
            # Image not local and pull failed → source-build, then retag to the requested name
            print(f"  [builder:{_run_id}] Pull failed and image not local — falling back to source build ...")
            image, source_setup = _dockerfile_build(
                product, version, entry_point, protocol, repo_url, run_dir
            )
            # Retag built image to the requested docker_image name so callers
            # that use the name for restart find the same image.
            subprocess.run(["docker", "tag", image, docker_image], capture_output=True)
            image = docker_image
            if not source_setup.get("config_path"):
                port_args = _port_args(source_setup["ports"])
                cmd = [
                    "docker", "run", "-d",
                    "--name", f"hypogenie-{_run_id}",
                    "--cpus", "1",
                    "--add-host=host.docker.internal:host-gateway",
                    "-v", f"{_CERTS_DIR}/server.crt:/certs/server.crt:ro",
                    "-v", f"{_CERTS_DIR}/server.key:/certs/server.key:ro",
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
                    "config_path": "",
                    "ports": source_setup["ports"],
                    "run_dir": str(run_dir),
                }
        # Derive product name from image (e.g. "caddy:2.7.6" → "caddy")
        effective_product = image.split(":")[0].split("/")[-1]
        effective_version = image.split(":")[-1] if ":" in image else version
    else:
        image = f"{product}:{version}"
        pulled = _docker_pull(image)
        if not pulled:
            image, source_setup = _dockerfile_build(
                product, version, entry_point, protocol, repo_url, run_dir
            )
            # Source build already generated config_path + ports — use them directly
            # but still run Setup Developer to generate the actual config file content
            # (unless config_path is empty, meaning the app handles config internally)
            if not source_setup.get("config_path"):
                # App handles config internally — skip config file mount
                conf_file = run_dir / "server.conf"
                conf_file.write_text("")
                port_args = _port_args(source_setup["ports"])
                cmd = [
                    "docker", "run", "-d",
                    "--name", f"hypogenie-{_run_id}",
                    "--cpus", "1",
                    "--add-host=host.docker.internal:host-gateway",
                    "-v", f"{_CERTS_DIR}/server.crt:/certs/server.crt:ro",
                    "-v", f"{_CERTS_DIR}/server.key:/certs/server.key:ro",
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
                    "config_path": "",
                    "ports": source_setup["ports"],
                    "run_dir": str(run_dir),
                }
        effective_product = product
        effective_version = version

    # Generate server config via LLM
    setup = _setup_developer(effective_product, effective_version, entry_point,
                             server_config_hint=server_config_hint)

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
    # For QUIC/HTTP3 targets the server binds the same port number on both TCP
    # and UDP (TCP for HTTPS fallback / ALPN, UDP for QUIC datagrams).  If only
    # the UDP mapping was returned by the Setup Developer, add the matching TCP
    # mapping so the container can accept connections on both transports.
    raw_ports = setup["ports"]
    if protocol.upper().startswith("QUIC"):
        existing = set(raw_ports.split())
        extras = []
        for m in list(existing):
            if m.endswith("/udp"):
                tcp_equiv = m[:-4] + "/tcp"
                if tcp_equiv not in existing:
                    extras.append(tcp_equiv)
        if extras:
            raw_ports = raw_ports + " " + " ".join(extras)
    port_args = _port_args(raw_ports)

    certs_dir = str(_CERTS_DIR)
    config_path = setup["config_path"]
    env_vars = setup.get("env_vars", {})

    cmd = [
        "docker", "run", "-d",
        "--name", f"hypogenie-{_run_id}",
        "--cpus", "1",
        "--add-host=host.docker.internal:host-gateway",
        "-v", f"{certs_dir}/server.crt:/certs/server.crt:ro",
        "-v", f"{certs_dir}/server.key:/certs/server.key:ro",
    ]
    for k, v in env_vars.items():
        cmd += ["-e", f"{k}={v}"]
    if config_path:
        cmd += ["-v", f"{conf_file}:{config_path}:ro"]
    cmd += port_args + [image]

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
        "env_vars": env_vars,
    }


def _stop_container(container_id: str) -> None:
    subprocess.run(["docker", "stop", container_id], capture_output=True, timeout=30)
    subprocess.run(["docker", "rm",   container_id], capture_output=True, timeout=30)
    if container_id in _running_containers:
        _running_containers.remove(container_id)


def teardown(container_info: "dict | str") -> None:
    """Stop and remove container(s) and any shared Docker network.

    Accepts either a container_id string (backward compat) or the dict
    returned by build() / _build_multi(), which may include aux_container_ids
    and a network_name to remove.
    """
    if isinstance(container_info, str):
        print(f"  [builder:{_run_id}] Stopping {container_info[:12]} ...")
        _stop_container(container_info)
        print(f"  [builder:{_run_id}] Container removed.")
        return

    primary = container_info.get("container_id")
    if primary:
        print(f"  [builder:{_run_id}] Stopping primary {primary[:12]} ...")
        _stop_container(primary)

    for aux_id in container_info.get("aux_container_ids", []):
        print(f"  [builder:{_run_id}] Stopping aux container {aux_id[:12]} ...")
        _stop_container(aux_id)

    network = container_info.get("network_name")
    if network:
        print(f"  [builder:{_run_id}] Removing network {network} ...")
        subprocess.run(["docker", "network", "rm", network],
                       capture_output=True, timeout=30)

    print(f"  [builder:{_run_id}] Teardown complete.")


# ── multi-container build ─────────────────────────────────────────────────────

def _start_aux_service(svc, network_name: str) -> str:
    """Pull and start a non-target service on the shared Docker network.

    svc is a ServiceSpec (or any object with .name, .docker_image, .command,
    .env_vars attributes).  Returns the container_id.
    """
    image = svc.docker_image
    if _image_exists_locally(image):
        print(f"  [builder:{_run_id}] Aux image {image} found locally.")
    elif not _docker_pull(image):
        raise RuntimeError(
            f"Cannot pull aux service image {image!r} for service {svc.name!r}"
        )

    cmd = [
        "docker", "run", "-d",
        "--name",     f"hypogenie-{_run_id}-{svc.name}",
        "--hostname", svc.name,
        "--network",  network_name,
        "--add-host=host.docker.internal:host-gateway",
    ]
    for k, v in svc.env_vars.items():
        cmd += ["-e", f"{k}={v}"]
    cmd.append(image)
    if svc.command:
        cmd += list(svc.command)

    print(f"  [builder:{_run_id}] Starting aux '{svc.name}': {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(
            f"docker run failed for aux service {svc.name!r}: "
            f"{result.stderr.strip()[:400]}"
        )
    cid = result.stdout.strip()
    print(f"  [builder:{_run_id}] Aux '{svc.name}' started: {cid[:12]}")
    return cid


def _build_multi(services: list, protocol: str, entry_point: str,
                 product: str, version: str, repo_url: str) -> dict:
    """Build and start a multi-container environment described by a services list.

    Exactly one service must have role='target'; all others are started first
    (so backends are ready when the target proxy connects).  Only the target
    has its ports exposed to the host and is CPU-constrained to 1 core.
    Returns the same dict shape as build() plus aux_container_ids and network_name.
    """
    import time as _time

    run_dir = _WORKSPACE / _run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # Create an isolated bridge network for this run
    network_name = f"hypogenie-net-{_run_id}"
    r = subprocess.run(
        ["docker", "network", "create", network_name],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"Failed to create Docker network {network_name!r}: {r.stderr.strip()}"
        )
    print(f"  [builder:{_run_id}] Created network: {network_name}")

    target_svc = next(s for s in services if s.role == "target")
    aux_svcs   = [s for s in services if s.role != "target"]

    aux_container_ids: list[str] = []

    # Start supporting services before the target so they're reachable on DNS
    for svc in aux_svcs:
        cid = _start_aux_service(svc, network_name)
        aux_container_ids.append(cid)
        _running_containers.append(cid)

    if aux_container_ids:
        _time.sleep(1)  # give backends a moment to bind their ports

    # Resolve target image
    image = target_svc.docker_image
    effective_product = image.split(":")[0].split("/")[-1]
    effective_version = image.split(":")[-1] if ":" in image else version

    if _image_exists_locally(image):
        print(f"  [builder:{_run_id}] Target image {image} found locally.")
    elif not _docker_pull(image):
        print(f"  [builder:{_run_id}] Pull failed — falling back to source build ...")
        image, _ = _dockerfile_build(
            effective_product, effective_version, entry_point, protocol, repo_url, run_dir
        )

    # Generate server config for the target via LLM
    setup = _setup_developer(
        effective_product, effective_version, entry_point,
        server_config_hint=target_svc.server_config,
    )
    critic_ok = _setup_critic(effective_product, entry_point, setup)
    if not critic_ok:
        user_retry = (
            SETUP_DEVELOPER_USER_TEMPLATE.format(
                product=effective_product, version=effective_version,
                entry_point=entry_point,
            )
            + "\n\nIMPORTANT: The config MUST reference /certs/server.crt and /certs/server.key exactly."
        )
        print(f"  [builder:{_run_id}] Retrying Setup Developer with cert path hint ...")
        raw = _llm.call_llm(
            SETUP_DEVELOPER_SYSTEM, user_retry,
            role_env="BUILDER_MODEL", json_mode=True,
        )
        setup = json.loads(_extract_json(raw))
        if not _setup_critic(effective_product, entry_point, setup):
            raise RuntimeError("Setup Developer could not produce valid cert paths after retry")

    conf_file = run_dir / "server.conf"
    conf_file.write_text(setup["config"])
    print(f"  [builder:{_run_id}] Target config written to {conf_file}")

    # Build docker run for target — same QUIC TCP+UDP port dedup as single-container path
    raw_ports = setup["ports"]
    if protocol.upper().startswith("QUIC"):
        existing = set(raw_ports.split())
        extras = [m[:-4] + "/tcp" for m in existing
                  if m.endswith("/udp") and m[:-4] + "/tcp" not in existing]
        if extras:
            raw_ports = raw_ports + " " + " ".join(extras)
    port_args = _port_args(raw_ports)

    config_path = setup["config_path"]
    env_vars    = {**setup.get("env_vars", {}), **target_svc.env_vars}

    cmd = [
        "docker", "run", "-d",
        "--name",     f"hypogenie-{_run_id}-{target_svc.name}",
        "--hostname", target_svc.name,
        "--network",  network_name,
        "--cpus",     "1",
        "--add-host=host.docker.internal:host-gateway",
        "-v", f"{str(_CERTS_DIR)}/server.crt:/certs/server.crt:ro",
        "-v", f"{str(_CERTS_DIR)}/server.key:/certs/server.key:ro",
    ]
    for k, v in env_vars.items():
        cmd += ["-e", f"{k}={v}"]
    if config_path:
        cmd += ["-v", f"{conf_file}:{config_path}:ro"]
    cmd += port_args + [image]
    if target_svc.command:
        cmd += list(target_svc.command)

    print(f"  [builder:{_run_id}] Starting target container: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"docker run failed for target: {result.stderr.strip()[:400]}")

    container_id = result.stdout.strip()
    _running_containers.append(container_id)
    print(f"  [builder:{_run_id}] Target container started: {container_id[:12]}")

    return {
        "container_id":      container_id,
        "image":             image,
        "config_path":       config_path,
        "ports":             setup["ports"],
        "run_dir":           str(run_dir),
        "env_vars":          env_vars,
        "aux_container_ids": aux_container_ids,
        "network_name":      network_name,
    }
