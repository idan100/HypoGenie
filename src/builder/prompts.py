DOCKERFILE_DEVELOPER_SYSTEM = """You are a Docker and server-setup expert.
Given a target library/project, version, and entry point, generate:
1. A Dockerfile that builds a minimal server application using exactly that library version.
2. Any application source files needed (e.g. a Go main.go, a Python server.py, etc.).
3. The in-container config path (config_path) for the server config — or empty string if none needed.
4. The host:container port mapping(s).

## Rules
- Use the EXACT library version requested (pin it via go.mod, requirements.txt, etc.).
- TLS certificate is ALWAYS at /certs/server.crt and /certs/server.key inside the container.
  Mount them from outside — do NOT bake certs into the image.
- Keep the server handler minimal but NOT instant: do some real work (write a response body,
  read the request body, sleep 1ms) so goroutines/handlers hold resources long enough for
  timing attacks to be meaningful.
- For Go libraries: use golang:1.21.0-alpine as build base; build a static binary.
  IMPORTANT for Go: do NOT copy go.sum into the image (it will be incomplete). Instead:
  1. COPY only go.mod (not go.sum)
  2. RUN go mod tidy   (generates go.sum and downloads all deps — requires network at build time)
  3. COPY main.go (or other .go files)
  4. RUN go build
  Do NOT use "go mod download" before "go mod tidy".
- For Python libraries: use python:3.11-slim; install the exact version.
- For Python/Twisted HTTP/2 servers: install twisted[tls] and h2 packages.
  NEVER import twisted.web.http2 directly — it is a private module.
  CRITICAL: NEVER use reactor.listenSSL() for HTTP/2 — that transport does NOT expose
  negotiatedProtocol, so Twisted falls back to HTTP/1.1 and ignores the h2 ALPN result.
  ALWAYS use TLSMemoryBIOFactory + reactor.listenTCP() instead. Use this pattern:
    from twisted.internet import reactor
    from twisted.internet.ssl import CertificateOptions
    from twisted.protocols.tls import TLSMemoryBIOFactory
    from twisted.web.server import Site
    from twisted.web import resource
    from OpenSSL.crypto import load_certificate, load_privatekey, FILETYPE_PEM
    with open('/certs/server.crt','rb') as f: cert = load_certificate(FILETYPE_PEM, f.read())
    with open('/certs/server.key','rb') as f: key  = load_privatekey(FILETYPE_PEM, f.read())
    # CRITICAL: use acceptableProtocols (NOT alpnProtocols) for ALPN
    ssl_ctx = CertificateOptions(certificate=cert, privateKey=key,
                                 acceptableProtocols=[b'h2', b'http/1.1'])
    tls_factory = TLSMemoryBIOFactory(ssl_ctx, isClient=False, wrappedFactory=Site(RootResource()))
    reactor.listenTCP(8443, tls_factory)
    reactor.run()
  TLSMemoryBIOFactory exposes negotiatedProtocol on the transport, which Twisted's HTTP
  layer reads to activate HTTP/2 (H2Connection) instead of HTTP/1.1 (HTTPChannel).
  pem package is optional; use OpenSSL.crypto for cert loading.
- For Elixir/Bandit HTTP/1.1 servers: Bandit 1.11.x requires Elixir ~> 1.17.
  ALWAYS use elixir:1.17-otp-27-alpine (or debian) as the build base image.
  NEVER use elixir:1.15 or older — Bandit 1.11.x is incompatible with Elixir < 1.17.
  Use {bandit, "~> 1.11"} in mix.exs deps to pin to 1.11.x, NOT "~> 1.0".
  ALWAYS use mix release for packaging (NOT mix escript.build — that breaks OTP apps).
  Proper structure:
    mix.exs: deps [{:bandit, "~> 1.11"}, {:plug, "~> 1.14"}], app [{mod: {App, []}}]
    lib/app.ex: use Application; def start(_,_) do Bandit.start_link(plug: MyPlug, port: 4000) end
    lib/my_plug.ex: use Plug.Router; plug :match; plug :dispatch; get "/" do send_resp(conn, 200, "ok") end
  For multi-stage Dockerfile: build stage uses elixir:1.17-otp-27-alpine, runtime stage
  copies _build/prod/rel/<app>/ and launches with bin/<app> start.
  EXPOSE 4000 and ports = "4000:4000/tcp".
- For Java/Netty HTTP/2 servers: use maven:3.9.6-eclipse-temurin-21 for build.
  IMPORTANT Netty HTTP/2 API (4.x): use Http2FrameCodecBuilder and Http2MultiplexHandler.
  Do NOT extend Http2ConnectionHandler or implement Http2FrameListener directly — those
  constructors changed and the listener interface has onUnknownFrame() that must be
  implemented. NEVER use SelfSignedCertificate — it requires BouncyCastle and may
  fail on many JDK versions. ALWAYS load TLS certs from /certs/server.crt and
  /certs/server.key (they are mounted into the container):
    File certFile = new File("/certs/server.crt");
    File keyFile  = new File("/certs/server.key");
  The correct pipeline pattern is:
    SslContext ssl = SslContextBuilder.forServer(certFile, keyFile)
        .sslProvider(SslProvider.JDK)   // IMPORTANT: force JDK SSL; tcnative is NOT available
        .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
        .applicationProtocolConfig(new ApplicationProtocolConfig(
            Protocol.ALPN, SelectorFailureBehavior.NO_ADVERTISE,
            SelectedListenerFailureBehavior.ACCEPT, ApplicationProtocolNames.HTTP_2))
        .build();
    // In the channel pipeline:
    pipeline.addLast(ssl.newHandler(ch.alloc()));
    pipeline.addLast(new ApplicationProtocolNegotiationHandler(ApplicationProtocolNames.HTTP_2) {
        protected void configurePipeline(ChannelHandlerContext ctx, String protocol) {
            ctx.pipeline().addLast(Http2FrameCodecBuilder.forServer().build());
            ctx.pipeline().addLast(new Http2MultiplexHandler(new ChildChannelHandler()));
        }
    });
  ChildChannelHandler extends SimpleChannelInboundHandler<Http2HeadersFrame> and
  reads the stream, writes a DATA response, and closes.
  pom.xml should use <netty.version>VERSION</netty.version> with netty-all artifact.
- config_path: return the path where a server config would be mounted, or "" if the
  application code already handles all configuration.
- ports: space-separated "host:container/proto" mappings, e.g. "443:443/tcp".

## Output format (JSON only, no other text)
{
  "dockerfile": "<full Dockerfile content as a string>",
  "app_files": {
    "<filename>": "<file content>"
  },
  "config_path": "<in-container path or empty string>",
  "ports": "<space-separated port mappings>"
}
"""

DOCKERFILE_DEVELOPER_USER_TEMPLATE = """Library/product: {product}
Version: {version}
Entry point: {entry_point}
Protocol: {protocol}
Repo URL: {repo_url}

Generate a Dockerfile and application files to run a TLS server for this target.
The server should use exactly the library version stated above and serve the stated protocol.
"""

DOCKERFILE_FIX_SYSTEM = """You are a Docker and server-setup expert.
You previously generated a Dockerfile and application files, but the Docker build failed.
Fix ONLY the compilation/build errors shown. Keep the same overall structure and logic.
For Java/Netty: NEVER use SelfSignedCertificate — always load from File("/certs/server.crt")
and File("/certs/server.key"). ALWAYS call .sslProvider(SslProvider.JDK) on SslContextBuilder
(tcnative is NOT available). NEVER pass a boolean where Http2Headers is expected; use
new DefaultHttp2Headers() as the headers argument in DefaultHttp2HeadersFrame constructor.
For Python/Twisted HTTP/2: NEVER use reactor.listenSSL() — it doesn't expose negotiatedProtocol.
ALWAYS use TLSMemoryBIOFactory + reactor.listenTCP():
  from twisted.protocols.tls import TLSMemoryBIOFactory
  tls_factory = TLSMemoryBIOFactory(ssl_ctx, isClient=False, wrappedFactory=Site(root))
  reactor.listenTCP(8443, tls_factory)
For Elixir/Bandit: ALWAYS use elixir:1.17-otp-27-alpine, {bandit, "~> 1.11"}, mix release.
NEVER use elixir:1.15 or escript.build.
Return the corrected files in the same JSON format as before.

## Output format (JSON only, no other text)
{
  "dockerfile": "<full Dockerfile content as a string>",
  "app_files": {
    "<filename>": "<file content>"
  },
  "config_path": "<in-container path or empty string>",
  "ports": "<space-separated port mappings>"
}
"""

DOCKERFILE_FIX_USER_TEMPLATE = """The following Docker build failed with this error:

--- BUILD ERROR ---
{build_error}
---

Here are the files that were generated:

Dockerfile:
{dockerfile}

App files:
{app_files_text}

Fix the errors and return corrected files in the same JSON format.
"""

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
  HTTP/2 AND HTTP/3 (QUIC) are both enabled automatically when TLS is configured — do NOT add a
  `protocols` directive (it does not exist). This applies for protocol=HTTP/2, protocol=QUIC,
  and protocol=HTTP/3: use the SAME Caddyfile template for all.
  config_path = /etc/caddy/Caddyfile. Use EXACTLY this template (do not add other directives):
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
  For HTTP/2 with TLS use this template:
  ```
  events {}
  http {
      server {
          listen 443 ssl http2;
          ssl_certificate     /certs/server.crt;
          ssl_certificate_key /certs/server.key;
          ssl_protocols       TLSv1.2 TLSv1.3;
          location / { return 200 "ok"; }
      }
  }
  ```
- **httpd** / **apache/httpd** (httpd:*): Use httpd.conf format.
  config_path = /usr/local/apache2/conf/httpd.conf.
  To enable HTTP/2 with TLS, use EXACTLY this template (do not include AllowOverride or .htaccess):
  ```
  ServerName localhost
  LoadModule mpm_event_module modules/mod_mpm_event.so
  LoadModule http2_module modules/mod_http2.so
  LoadModule ssl_module modules/mod_ssl.so
  LoadModule unixd_module modules/mod_unixd.so
  LoadModule authz_core_module modules/mod_authz_core.so
  LoadModule mime_module modules/mod_mime.so
  LoadModule log_config_module modules/mod_log_config.so
  TypesConfig /dev/null
  User daemon
  Group daemon
  Protocols h2 http/1.1
  Listen 443
  <VirtualHost *:443>
      SSLEngine on
      SSLCertificateFile    /certs/server.crt
      SSLCertificateKeyFile /certs/server.key
      SSLProtocol           TLSv1.2 TLSv1.3
      Protocols             h2 http/1.1
      <Location />
          Require all granted
      </Location>
  </VirtualHost>
  ```
  ports = "443:443/tcp".
- **coredns**: Use Corefile format. IMPORTANT notes:
  1. config_path = /home/nonroot/Corefile (CoreDNS Docker image working directory is
     /home/nonroot; it looks for Corefile relative to that directory at startup.
     Mount at /home/nonroot/Corefile — NOT at /Corefile or /etc/coredns/).
  2. The standard `coredns/coredns` Docker image does NOT include the `doh` plugin.
     Do NOT use `doh`. Do NOT use `grpc` as a server listener.
  3. To serve DNS-over-TLS, the zone prefix MUST start with `tls://` — without it
     CoreDNS ignores the `tls` directive and listens as plain TCP DNS (probe will fail).
     Use the port number from entry_point (e.g. `tls://.:853` for port 853).
  4. Use the built-in `erratic` plugin as the backend INSTEAD of `forward . 8.8.8.8`.
     `erratic` responds to all queries with NOERROR (no external DNS dependency) and
     accepts a `delay` parameter to hold each query goroutine for a fixed duration.
     This makes tests reliable in isolated environments and deterministic under load.
     Use `erratic { delay 5s }` for goroutine/memory accumulation attacks.
     Use `erratic` (no delay) for latency or connection-count attacks.
  For DNS-over-TLS goroutine-exhaustion tests (dos_class=memory), use `erratic { delay 1 5s }`
  to delay every query by 5 seconds, holding handler goroutines long enough for accumulation.
  (`delay AMOUNT DURATION` = delay 1 out of AMOUNT queries by DURATION; `delay 1 5s` = every query.)
  For other tests, use `erratic` (no delay) for fast responses.
  ```
  tls://.:853 {
      tls /certs/server.crt /certs/server.key
      erratic {
          delay 1 5s
      }
      log
      errors
  }
  ```
- **haproxy**: Use haproxy.cfg format. config_path = /etc/haproxy/haproxy.cfg.
- **grpcgo-server** (hypogenie/grpcgo-server:*): Custom gRPC-Go image. Handles all configuration
  internally (TLS certs mounted at /certs/). Return config_path = "" and config = "".
  ports = "443:443/tcp".
- **hypogenie-net-v*** (hypogenie-net-v*:*): Custom Go HTTP/2 server built from golang.org/x/net.
  Handles all configuration internally (TLS certs mounted at /certs/). Return config_path = "" and config = "".
  ports = "443:443/tcp".
- **http3-server** (hypogenie/http3-server:*): Custom HTTP/3 server. Handles all configuration
  internally (TLS certs mounted at /certs/). Return config_path = "" and config = "".
  ports = "443:443/udp".
- **postgres** (postgres:*): Official PostgreSQL Docker image. IMPORTANT:
  1. The image requires initialization env vars. Set env_vars = {"POSTGRES_PASSWORD": "hypogenie",
     "POSTGRES_HOST_AUTH_METHOD": "trust"} so the server starts and allows unauthenticated connections.
  2. Do NOT mount config inside /var/lib/postgresql/data/ — this is PGDATA and the mount
     prevents initdb from running. Use config_path = "" (no custom config file mount).
  3. Set config = "" (no config file needed; defaults are fine for exploit testing).
  4. ports = "5432:5432/tcp".
- **rabbitmq** (rabbitmq:*): Official RabbitMQ Docker image.
  1. Set env_vars = {"RABBITMQ_DEFAULT_USER": "guest", "RABBITMQ_DEFAULT_PASS": "guest"}.
  2. Use config_path = "" unless you need custom rabbitmq.conf (then /etc/rabbitmq/rabbitmq.conf).
  3. ports = "5672:5672/tcp" for AMQP; "1883:1883/tcp" for MQTT.
- **emqx** (emqx/emqx:*): Official EMQX MQTT broker Docker image.
  1. No password needed by default. Set env_vars = {} unless overriding config.
  2. Use config_path = "" (EMQX uses environment variable overrides for config).
  3. ports = "1883:1883/tcp" for MQTT; "8883:8883/tcp" for MQTT/TLS.
- **openlitespeed** (litespeedtech/openlitespeed:*): Official OpenLiteSpeed Docker image.
  1. The image ships with a complete, working httpd_config.conf that already enables QUIC/HTTP3
     on port 443 (TCP + UDP) and LSPHP. DO NOT mount a custom config — the image's startup
     script writes required sections at runtime (errorlog, tuning, etc.) and replacing
     httpd_config.conf causes startup failure.
  2. Set config = "" and config_path = "" (no config file mount).
  3. ports = "443:443/tcp 443:443/udp" (OLS binds the same port for both HTTPS/HTTP2 and QUIC).
- **envoy** / **envoyproxy/envoy** (envoyproxy/envoy:*): Official Envoy Proxy Docker image.
  1. config_path = /etc/envoy/envoy.yaml
  2. Use YAML format (Envoy bootstrap v3 API). DO NOT add `alpn_protocols` anywhere in the
     TLS config — it is NOT a valid field in DownstreamTlsContext or CommonTlsContext in
     Envoy v1.x; Envoy negotiates h2 automatically when codec_type is HTTP2.
  3. For TLS + HTTP/2, use exactly this filter_chain structure:
     ```
     filter_chains:
     - transport_socket:
         name: envoy.transport_sockets.tls
         typed_config:
           "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
           common_tls_context:
             tls_certificates:
             - certificate_chain: { filename: "/certs/server.crt" }
               private_key: { filename: "/certs/server.key" }
             alpn_protocols: ["h2"]
       filters:
       - name: envoy.filters.network.http_connection_manager
         typed_config:
           "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
           codec_type: HTTP2
           stat_prefix: ingress_http
           route_config:
             name: local_route
             virtual_hosts:
             - name: local_service
               domains: ["*"]
               routes:
               - match: { prefix: "/" }
                 direct_response: { status: 200, body: { inline_string: "ok" } }
     ```
  4. Always include an admin block: `admin: { address: { socket_address: { address: 0.0.0.0, port_value: 9901 } } }`
  5. Set ports to whatever the entry_point states (e.g. "10000:10000/tcp").

## Output format (JSON only, no other text)
{
  "config": "<full server config file content as a string, or empty string>",
  "config_path": "<in-container path, e.g. /etc/nginx/nginx.conf, or empty string>",
  "ports": "<space-separated port mappings, e.g. 443:443/tcp>",
  "env_vars": {"KEY": "VALUE"}
}
"""

SETUP_DEVELOPER_USER_TEMPLATE = """Product: {product}
Version: {version}
Entry point: {entry_point}

Generate the server config, config_path, and ports for this target.
"""

SETUP_CRITIC_SYSTEM = """You are a server config reviewer.
If config is non-empty: check that it references /certs/server.crt and /certs/server.key (not any other cert paths), and that it is syntactically appropriate for the product.
If config is empty (config_path is also empty): this is valid for images that handle config internally (postgres, rabbitmq, emqx, grpcgo-server, http3-server) — PASS immediately.
Check that ports is a non-empty string.

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
