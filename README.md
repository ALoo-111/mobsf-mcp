# MobSF MCP Server

A production-oriented [Model Context Protocol](https://modelcontextprotocol.io/) server for **authorized Android APK security analysis through MobSF**. An AI agent can validate an APK locally, upload it to the configured MobSF backend, start static analysis, retrieve normalized findings and scorecards, collect bounded source evidence, and optionally request dynamic analysis when a supported runtime is available.

> This project is an orchestration layer. It does not execute APK contents on the MCP host, does not embed MobSF, and does not prove malware or exploitability from heuristic findings alone.

## Architecture

```text
AI agent / MCP host
        |
        | MCP over stdio or Streamable HTTP
        v
+-----------------------+
|       MobSF MCP       |
|                       |
|  APK validation       |
|  Local hashes         |
|  REST client          |
|  Static orchestration |
|  Evidence retrieval   |
|  Report normalization |
|  Dynamic capability   |
+-----------+-----------+
            |
            | X-Mobsf-Api-Key from environment
            v
+-----------------------+
| Configured MobSF      |
| existing or Compose   |
+-----------------------+
```

The server uses the official MobSF API documentation as the endpoint source of truth. The current documented static workflow includes upload, scan, scan logs, report JSON, scorecard, search, source viewing, comparison, and PDF report generation.[^1] The official MobSF repository describes the platform as supporting static analysis for APK, IPA, APPX, and source code, with dynamic analysis available only where an Android or iOS runtime is configured.[^2]

## Features

| Capability | Behavior |
| --- | --- |
| `analyze_apk` | High-level upload, scan, report, scorecard, finding normalization, and optional source evidence workflow |
| Low-level tools | Upload, scan, scan status, report, scorecard, search, source, compare, PDF, and dynamic analysis |
| Normalized output | Stable application metadata, hashes, risk summary, findings, permissions, components, URLs, libraries, secrets, evidence, and limitations |
| Safety | Extension, size, regular-file, ZIP/APK signature, temporary-data, response-size, timeout, and TLS controls |
| Dynamic analysis | Explicitly reports disabled, unsupported, or failed status instead of fabricating results |
| MCP resources | Cached report, findings, metadata, and scorecard under `analysis://{scan_hash}/...` |
| Transports | Stdio by default; Streamable HTTP when `MCP_TRANSPORT=streamable-http` |

## Requirements

Python 3.11 or newer, a running MobSF instance or authorized MobSF service, and an MCP-compatible host are required. The project uses the official Python MCP SDK v2, whose documented server model is based on `MCPServer`, typed tool functions, resource templates, and `mcp.run()`.[^3] [^4]

## Installation

```bash
git clone https://github.com/ALoo-111/mobsf-mcp.git
cd mobsf-mcp
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
```

The API key is intentionally not part of the repository. For local development, set it in the process environment or in a local `.env` file that is ignored by Git:

```bash
export MOBSF_URL=https://mobsf.live
export MOBSF_API_KEY='<set-this-locally-or-in-your-deployment-secret-store>'
```

Never commit `.env`, APK samples, reports, or API keys. The production runtime reads `MOBSF_URL` and `MOBSF_API_KEY` from environment variables at startup; the application does not provide a fallback key.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `MOBSF_URL` | `https://mobsf.live` in deployment; local default is `http://127.0.0.1:8000` | Existing MobSF base URL |
| `MOBSF_API_KEY` | empty | API key supplied at runtime; never logged |
| `MOBSF_TIMEOUT` | `300` | MobSF request timeout in seconds |
| `MOBSF_VERIFY_TLS` | `true` | TLS certificate verification |
| `MAX_APK_SIZE_MB` | `500` | Maximum accepted APK size |
| `MAX_RESPONSE_BYTES` | `52428800` | Maximum MobSF response body size |
| `SOURCE_CONTEXT_LINES` | `3` | Lines of source context around a finding |
| `MAX_SOURCE_BYTES` | `65536` | Maximum returned source evidence size |
| `ENABLE_DYNAMIC_ANALYSIS` | `false` | Whether dynamic calls may be attempted |
| `DYNAMIC_ANALYSIS_TIMEOUT` | `600` | Reserved dynamic-analysis timeout |
| `MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http` |
| `MCP_HOST` | `127.0.0.1` | Streamable HTTP bind address |
| `MCP_PORT` | `8001` | Streamable HTTP port |

The configured API key is sent using `X-Mobsf-Api-Key`, which is one of the authentication headers documented by MobSF.[^1] The value is never printed, logged, included in structured errors, or committed.

## Deployment environment variables

For GitHub-based deployment on Render or Replit, configure the following values in the platform’s environment/secrets settings rather than committing them:

| Variable | Required | Deployment value |
| --- | --- | --- |
| `MOBSF_URL` | Yes | `https://mobsf.live` or the URL of an authorized self-hosted MobSF instance |
| `MOBSF_API_KEY` | Yes | The MobSF API key stored as a platform secret |
| `MOBSF_TIMEOUT` | No | `300` |
| `MOBSF_VERIFY_TLS` | No | `true` |
| `ENABLE_DYNAMIC_ANALYSIS` | No | `false` unless the backend has a supported dynamic environment |
| `MAX_APK_SIZE_MB` | No | `500` |

Render can use the included `render.yaml`; mark `MOBSF_API_KEY` as a secret when prompted. Replit can use the included `.replit`; add `MOBSF_API_KEY` through Replit Secrets. The MCP server should be exposed over Streamable HTTP in hosted environments, while stdio is intended for local MCP hosts.

## Running

For a local MCP host, use stdio:

```bash
source .venv/bin/activate
mobsf-mcp
```

For Streamable HTTP:

```bash
MCP_TRANSPORT=streamable-http MCP_HOST=0.0.0.0 MCP_PORT=8001 mobsf-mcp
```

The official SDK documents Streamable HTTP as the current HTTP transport and exposes the MCP endpoint at `/mcp` by default.[^4]

## Docker deployment

The included `Dockerfile` runs the MCP server without bundling MobSF. Pass the runtime configuration through the deployment environment:

```bash
docker build -t mobsf-mcp .
docker run --rm -p 8001:8001 \\
  -e MOBSF_URL=https://mobsf.live \\
  -e MOBSF_API_KEY='<provided-by-your-secret-store>' \\
  -e MOBSF_VERIFY_TLS=true \\
  -e MCP_TRANSPORT=streamable-http \\
  -e MCP_HOST=0.0.0.0 \\
  -e MCP_PORT=8001 \\
  mobsf-mcp
```

Do not put the real key in a Dockerfile, shell history, Compose file, or repository. Use the platform’s secret injection mechanism.

## Docker Compose

The Compose file includes an optional local MobSF service. To use it:

```bash
cp .env.example .env
docker compose up --build
```

To use an existing MobSF service, remove or comment out the `mobsf` service and set `MOBSF_URL` and `MOBSF_API_KEY` in the environment. The MCP image contains only the orchestration server; it does not include MobSF or Android tooling.

## MCP tools

The high-level tool is:

```text
analyze_apk(
  apk_path,
  include_source_evidence=true,
  include_raw_report=false,
  enable_dynamic=false,
)
```

The low-level tools are `mobsf_upload`, `mobsf_scan`, `mobsf_scan_status`, `mobsf_report`, `mobsf_scorecard`, `mobsf_search`, `mobsf_source`, `mobsf_compare`, `mobsf_download_report`, and `mobsf_dynamic_analysis`.

A successful normalized report includes an application block, local hashes, security score and risk level, findings grouped by normalized severity, permissions, components, URLs and domains, certificates, libraries, native libraries, secrets, network security, webviews, cryptography, Firebase, trackers, source evidence, dynamic-analysis status, limitations, and recommended fix priorities. Raw MobSF data is available only when explicitly requested.

## Static versus dynamic analysis

**Static analysis** requires only the APK and a reachable MobSF backend. **Dynamic analysis** requires a MobSF deployment with a compatible Android runtime or device environment. The server defaults dynamic analysis to disabled, and any unavailable endpoint is reported as unsupported rather than treated as a successful analysis.

The intended use is authorized security review, debugging, DevSecOps, and malware-analysis research. The server deliberately does not add persistence, credential theft, evasion, exploitation, or arbitrary command execution against applications.

## Testing and quality checks

The normal test suite uses mocked HTTP responses and does not require a live MobSF service:

```bash
make check
```

Additional checks are:

```bash
make format
make docker-build
```

A live integration check can be performed separately by setting `MOBSF_URL`, `MOBSF_API_KEY`, and an authorized test backend. For the current `mobsf.live` Cloudflare challenge, run the redacted diagnostic from the deployed service environment:

```bash
python scripts/diagnose_mobsf_api.py
```

The diagnostic tests the documented raw header forms plus non-production comparison variants, prints only redacted request/response metadata, and never prints API keys, cookies, CSRF tokens, or full response bodies. The provider-side evidence and allowlisting request is documented in [`docs/cloudflare-provider-request.md`](docs/cloudflare-provider-request.md). This repository validation run uses mocked HTTP responses because live credentials and an APK are deployment inputs, not repository contents. Do not place production credentials in test fixtures or commit them.

## HTTP transport backends

The MCP uses an interchangeable transport factory selected by `HTTP_CLIENT_BACKEND`:

| Backend | Configuration | Purpose |
|---|---|---|
| `requests` | Default; set `HTTP_CLIENT_BACKEND=requests` | Synchronous requests session executed off the event loop |
| `httpx` | `HTTP_CLIENT_BACKEND=httpx`; set `HTTP_CLIENT_HTTP2=true` to enable HTTP/2 | Native async transport used in production and tests |
| `curl_cffi` | Install `.[transport]`, then set `HTTP_CLIENT_BACKEND=curl_cffi` | Optional ordinary curl-compatible transport for interoperability diagnostics |

All backends expose the same request interface and normalize responses to `httpx.Response`. The `curl_cffi` adapter intentionally does not use browser impersonation, JA3 spoofing, challenge solving, clearance cookies, or proxy rotation. None of these transports can guarantee access through a Cloudflare managed challenge; a 403 HTML challenge remains an upstream provider policy result and must be resolved by the provider.

## Troubleshooting authentication

At startup, the server logs only the configured MobSF URL and a boolean `api_key_configured` value; it never logs the API key. The client sends the raw runtime value in the documented `X-Mobsf-Api-Key` header and does not add a `Bearer` prefix. The startup probe uses `GET /api/v1/scans?page=1&page_size=1`, which is the documented recent-scans endpoint.

If this request returns HTTP 401 or 403, verify that the deployment has a non-empty `MOBSF_API_KEY`, that the key belongs to the configured `MOBSF_URL`, and that the hosted MobSF instance accepts API access for that key. The official MobSF source protects `/api/` routes with a dedicated API middleware that compares the raw key against the configured instance key and returns HTTP 401 for a mismatch; web routes such as `/tasks` use Django session login and CSRF protection instead. A browser cookie or `X-CSRFToken` is therefore not a substitute for REST API authentication. A 403 from a hosted endpoint should be investigated as an upstream edge/service rejection or hosted-instance policy issue, not silently worked around with browser credentials. The server preserves only a sanitized JSON error or response content type for diagnosis, never the response body or credential.

## Security notes

APK files are untrusted input. The server validates the path, extension, regular-file status, size, ZIP signature, and common APK members before upload. It calculates MD5, SHA-1, and SHA-256 locally without executing the file. It does not shell out with an APK-derived command, log APK contents, log API keys, or automatically run APK commands on the host.

MobSF findings are evidence for review, not automatic proof of a vulnerability or malicious behavior. The normalized report preserves the original severity when available and uses cautious language in its limitations so an AI agent can distinguish detection from verified impact.

## License

MIT for this orchestration project. MobSF itself remains separately licensed under GPL-3.0.[^2]

## References

[^1]: [MobSF API Docs](https://mobsf.live/api_docs)
[^2]: [MobSF official GitHub repository](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
[^3]: [MCP Python SDK documentation](https://py.sdk.modelcontextprotocol.io/)
[^4]: [MCP Python SDK: Running your server](https://py.sdk.modelcontextprotocol.io/run/)
