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

Set `MOBSF_API_KEY` in `.env` or in the process environment. **Never commit `.env`, APK samples, reports, or API keys.**

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `MOBSF_URL` | `http://127.0.0.1:8000` | Existing MobSF base URL |
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

The configured API key is sent using `X-Mobsf-Api-Key`, which is one of the authentication headers documented by MobSF.[^1]

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

A live integration check can be performed separately by setting `MOBSF_URL`, `MOBSF_API_KEY`, and an authorized test backend. Do not place production credentials in test fixtures or commit them.

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
