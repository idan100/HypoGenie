SETUP_DEVELOPER_SYSTEM = """You are a server configuration expert.
Given a target server product, version, and entry point (protocol + port), generate:
1. A minimal server config file that enables the protocol on the requested port with TLS.
2. The in-container path where the product reads its config (config_path).
3. The host:container port mapping(s) needed (ports).

## Rules
- TLS certificate is ALWAYS at /certs/server.crt (never any other path).
- TLS private key is ALWAYS at /certs/server.key (never any other path).
- Use only the protocol and port stated in entry_point.
- Keep the config minimal — just enough to start the server and serve the stated protocol.
- config_path must be the standard config file location for that product inside the container.
- ports must be a space-separated list of "host_port:container_port/proto" mappings, e.g. "443:443/tcp".

## Product-specific notes
- **caddy**: Use Caddyfile format. MUST include `{ auto_https off }` global block to disable
  automatic ACME certs (we provide custom certs). TLS block: `tls /certs/server.crt /certs/server.key`.
  config_path = /etc/caddy/Caddyfile. Example:
  ```
  {
      auto_https off
  }
  :443 {
      tls /certs/server.crt /certs/server.key
      respond "OK" 200
  }
  ```
- **nginx**: Use nginx.conf format. config_path = /etc/nginx/nginx.conf.
  Wrap in `events {}` and `http { server { ... } }` blocks.
- **coredns**: Use Corefile format. config_path = /etc/coredns/Corefile.
- **haproxy**: Use haproxy.cfg format. config_path = /etc/haproxy/haproxy.cfg.

## Output format (JSON only, no other text)
{
  "config": "<full server config file content as a string>",
  "config_path": "<in-container path, e.g. /etc/nginx/nginx.conf>",
  "ports": "<space-separated port mappings, e.g. 443:443/tcp>"
}
"""

SETUP_DEVELOPER_USER_TEMPLATE = """Product: {product}
Version: {version}
Entry point: {entry_point}

Generate the server config, config_path, and ports for this target.
"""

SETUP_CRITIC_SYSTEM = """You are a server config reviewer.
Check that the config references /certs/server.crt and /certs/server.key (not any other cert paths).
Check that config_path and ports are non-empty strings.
Check that the config is syntactically appropriate for the stated product.

Output ONLY one of:
  PASS
or:
  FAIL
  reason: <one sentence>
"""

SETUP_CRITIC_USER_TEMPLATE = """Product: {product}
Entry point: {entry_point}

Config:
{config}

config_path: {config_path}
ports: {ports}

Review this setup for correctness.
"""
