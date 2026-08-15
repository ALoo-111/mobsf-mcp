# Provider Request: Permit MobSF REST API Traffic from Render

## Summary

We operate a REST-only MCP integration at `https://mobsf-mcp.onrender.com`. It calls the documented MobSF endpoint `https://mobsf.live/api/v1/scans?page=1&page_size=1` with an API key supplied at runtime. The current request is blocked by Cloudflare before it reaches the MobSF REST authentication middleware.

The requested change is a provider-side Cloudflare configuration change for the documented REST API path. No browser session, cookie, CSRF token, browser automation, fingerprint impersonation, or proxy rotation is part of the requested solution.

## Evidence

The same current `/api_docs` reference credential was used only in memory and was never written to logs or this document. Four raw-header variants were tested against the live endpoint through a resolved Cloudflare edge. Every variant returned the same challenge response:

| Variant | Method and path | Status | Content type | Server | Cloudflare signal | Body classification |
|---|---|---:|---|---|---|---|
| `X-Mobsf-Api-Key: <redacted>` | `GET /api/v1/scans?page=1&page_size=1` | 403 | `text/html; charset=UTF-8` | `cloudflare` | `cf-mitigated: challenge` | HTML, marker `Just a moment` |
| `Authorization: <redacted>` | `GET /api/v1/scans?page=1&page_size=1` | 403 | `text/html; charset=UTF-8` | `cloudflare` | `cf-mitigated: challenge` | HTML, marker `Just a moment` |
| `Authorization: Bearer <redacted>` | `GET /api/v1/scans?page=1&page_size=1` | 403 | `text/html; charset=UTF-8` | `cloudflare` | `cf-mitigated: challenge` | HTML, marker `Just a moment` |
| `X-API-Key: <redacted>` | `GET /api/v1/scans?page=1&page_size=1` | 403 | `text/html; charset=UTF-8` | `cloudflare` | `cf-mitigated: challenge` | HTML, marker `Just a moment` |

Representative Cloudflare Ray IDs from the probes were `a2b62991b91aa5b3-TIA`, `a2b6299e4aa4bd99-TIA`, `a2b629ad0ac5a5b3-TIA`, and `a2b629bb2f2a5f50-TIA`. These identify the edge requests and can help the provider locate the events in Cloudflare logs.

The response is Cloudflare HTML, not the MobSF JSON error body. The current official MobSF REST middleware accepts raw `X-Mobsf-Api-Key` and raw `Authorization`, and returns HTTP 401 JSON for an API-key mismatch. The observed Cloudflare HTML 403 therefore occurs before MobSF REST authentication is reached.

## Failing request pattern

The production request is:

```http
GET /api/v1/scans?page=1&page_size=1 HTTP/1.1
Host: mobsf.live
Accept: application/json
X-Mobsf-Api-Key: <runtime API key>
User-Agent: python-http-client
```

The exact source egress IP is controlled by Render, not by the MCP application. Render reports this service as a Python web service in the **Oregon** region on the **Free** plan, using the `main` branch of `ALoo-111/mobsf-mcp`. The service has automatic deploys enabled.

## Expected successful pattern

The provider should allow the request to reach the MobSF application unchanged:

```http
GET /api/v1/scans?page=1&page_size=1 HTTP/1.1
Host: mobsf.live
Accept: application/json
X-Mobsf-Api-Key: <runtime API key>
```

A successful response should be MobSF JSON with HTTP 200. An invalid key should produce the MobSF JSON unauthorized response, normally HTTP 401. A Cloudflare challenge page must not be returned for this API route.

## Requested provider-side configuration

Please apply one of the following provider-controlled changes, in order of preference:

1. Create a Cloudflare rule for `/api/v1/*` that permits service-to-service API requests carrying the MobSF API-key header and skips the browser managed challenge/bot challenge for these routes. Keep API-key authentication enforced at the MobSF application layer.
2. Allowlist the Render service’s outbound CIDR ranges for the service’s Oregon region, while retaining the MobSF API-key check. The exact current CIDR list must be copied from Render Dashboard → the `mobsf-mcp` service → **Connect** → **Outbound**; Render’s public documentation states that the ranges are region-specific and shared by services in the same region.[1]
3. If stable source IPs are required, provision a dedicated Render outbound IP set for the Oregon service and allowlist its three assigned IPv4 addresses. Render documents dedicated outbound IP sets as a paid Pro-or-higher feature; the addresses are assigned by Render and must be copied from the workspace’s Dedicated IPs page or API.[2]

Please do not disable API-key authentication globally. The desired state is Cloudflare challenge bypass for the API route or approved Render egress, followed by normal MobSF REST authentication.

## Render egress information

The service metadata available through the Render API identifies the region as `oregon`, but does not return the current shared outbound CIDR list. Render’s official documentation instructs the service owner to obtain the exact ranges from the service’s Dashboard **Connect → Outbound** view.[1] No CIDRs are guessed in this request. If the provider requires a fixed list, use dedicated outbound IPs and provide the three assigned addresses after provisioning.[2]

## Verification command

After the provider-side change, run the following from the Render service environment. It prints only status, selected Cloudflare headers, and a bounded response prefix; never print the API key or full credential-bearing headers:

```bash
python scripts/diagnose_mobsf_api.py
```

The expected result for `x-mobsf-api-key` is HTTP 200 with a JSON body classification. The `authorization-raw` form should be tested only for compatibility; the MCP production client uses `X-Mobsf-Api-Key`.

A minimal direct test, with the secret supplied by the deployment secret store, is:

```bash
curl --fail-with-body --silent --show-error \
  -H 'Accept: application/json' \
  -H "X-Mobsf-Api-Key: ${MOBSF_API_KEY}" \
  'https://mobsf.live/api/v1/scans?page=1&page_size=1'
```

## Security requirements

Do not send browser cookies, CSRF tokens, or session identifiers to the MCP. Do not place the API key in tickets, screenshots, logs, source code, or this request. The provider should use the Cloudflare Ray IDs above to locate the challenge events and should confirm that the exemption applies only to the REST API route or approved Render egress, not to the entire site.

## References

[1]: https://render.com/docs/outbound-ip-addresses — Render outbound IP ranges and Dashboard retrieval instructions
[2]: https://render.com/docs/dedicated-ips — Render dedicated outbound IP sets
[3]: https://mobsf.live/api_docs — MobSF REST API documentation
[4]: https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/MobSF/views/api/api_middleware.py — Official MobSF REST authentication middleware
