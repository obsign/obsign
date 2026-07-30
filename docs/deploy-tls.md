# TLS in front of the gateway

The Streamable HTTP transport speaks plain HTTP, deliberately: the gateway's
dependency list is part of the product, and a TLS stack (rustls or an OpenSSL
binding, dozens of crates either way) would swell the tree an auditor must
read for a job a reverse proxy already does well. But identity travels in the
`Authorization: Bearer` header of every request, and a bearer token readable
on the wire is an identity anyone on the path can replay. **SSO tokens must
never cross a network in clear.**

The pattern: the gateway listens where TLS ends. Same host as the TLS
terminator, bound to loopback — or the same private container network, with
no published port. Any reverse proxy that honours the contract below works;
the nginx and Caddy configurations in this page were run against the gateway
(nginx 1.27, Caddy 2.11) and passed the full MCP flow: session open, filtered
`tools/list`, arbitrated `tools/call`, SSE stream, `DELETE`.

## The contract

1. **Never expose the plain port.** `--http 127.0.0.1:8080` on a shared
   host; in compose, no `ports:` entry on the gateway — the proxy joins its
   network and is the only service published.
2. **Pass `Authorization` and `Mcp-Session-Id` through untouched.** nginx
   and Caddy both do by default.
3. **Upstream requests carry `Content-Length`.** The gateway's parser is
   strict: chunked transfer encoding is refused (411). nginx's default
   request buffering absorbs a chunked client request and re-sends it with
   `Content-Length` — keep `proxy_request_buffering` at its default (`on`).
4. **Do not buffer responses.** The GET stream is server-sent events; a
   proxy that spools the response delivers notifications only when the
   session dies. `proxy_buffering off` (nginx), `flush_interval -1` (Caddy).
5. **Read timeout longer than the slowest tool.** A POSTed `tools/call`
   produces no bytes until the tool answers — the gateway sets no timeout of
   its own, so the proxy's is the one that fires. The SSE stream is safe at
   any setting above 15 s (the gateway writes a keep-alive comment at that
   interval); size the timeout for the tools.
6. **The `Origin` allowlist names the public origin.** The proxy passes
   `Origin` through and the gateway's DNS-rebinding check compares it
   verbatim, so browser-based clients need
   `--allowed-origin https://mcp.example.com` — the TLS origin, not the
   loopback one. Non-browser MCP clients send no `Origin` and pass.

The gateway caps request bodies at 4 MiB; matching the cap at the proxy
(`client_max_body_size 4m`) refuses oversized bodies before they cross.

## nginx

```nginx
server {
    listen 443 ssl;
    server_name mcp.example.com;

    ssl_certificate     /etc/nginx/certs/mcp.example.com.pem;
    ssl_certificate_key /etc/nginx/certs/mcp.example.com.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location = /mcp {
        proxy_pass http://127.0.0.1:8080;

        # The gateway speaks HTTP/1.1 with Content-Length bodies only.
        proxy_http_version 1.1;
        proxy_set_header Connection "";

        # SSE: deliver events as they are written, do not spool.
        proxy_buffering off;

        # Must outlast the slowest tool call (contract point 5).
        proxy_read_timeout 300s;

        # The gateway caps request bodies at 4 MiB; match it.
        client_max_body_size 4m;
    }

    location / { return 404; }
}
```

`location = /mcp` is exact-match on purpose: the gateway serves one endpoint,
and everything else has no business reaching it.

## Caddy

Caddy obtains and renews the certificate itself (ACME) and needs to be told
almost nothing else — its defaults already stream SSE-shaped responses and
set no read timeout:

```caddy
mcp.example.com {
	reverse_proxy 127.0.0.1:8080 {
		# SSE: flush each event immediately.
		flush_interval -1
	}
}
```

For a lab without a public name, `tls internal` inside the site block issues
a certificate from Caddy's local CA.

## In compose

The gateway loses its `ports:` entry entirely — the proxy is the only
service that listens on the host:

```yaml
services:
  gateway:
    image: my-gateway            # extends ghcr.io/obsign/obsign-proxy
    command: ["obsign-proxy", "...", "--http", "0.0.0.0:8080",
              "--allowed-origin", "https://mcp.example.com", "--", "..."]
    # no ports: — reachable only on the compose network

  tls:
    image: nginx:1.27-alpine
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    ports:
      - "443:443"
```

with `proxy_pass http://gateway:8080;` in the nginx config.

## mTLS

Where the client population is machines rather than browsers, the proxy can
also require a client certificate (`ssl_verify_client on` under nginx,
`tls { client_auth }` under Caddy). That authenticates the *channel*; the
bearer token remains the identity the log attributes acts to. mTLS narrows
who can present a token, it does not replace one.

## What TLS is not

TLS protects the token and the traffic in transit. It is not part of the
evidence story: what makes the log provable is the signature chain in the
WAL and the ledger's seal, neither of which involves the transport. A pack
sealed from a session that ran over plain HTTP verifies identically — the
channel protects the identity from leaking, it does not make the log true.

## Checking a deployment

Four probes, each pinned to one contract point:

```bash
BASE=https://mcp.example.com/mcp
TOKEN=...   # a valid SSO token
SID=$(curl -si "$BASE" -H "Authorization: Bearer $TOKEN" \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
      | tr -d '\r' | awk 'tolower($1)=="mcp-session-id:" {print $2}')

# 2/5 — token passes through, SSE unbuffered: a ": keep-alive" comment
# must appear within ~15 s. Silence means the proxy is spooling the stream.
curl -N --max-time 20 "$BASE" -H "Authorization: Bearer $TOKEN" \
     -H "Mcp-Session-Id: $SID" -H 'Accept: text/event-stream'

# No token → the *gateway's* 401 (WWW-Authenticate: Bearer), proving the
# proxy did not answer in its place.
curl -si "$BASE" -H 'Content-Type: application/json' -d '{}'

# 6 — a hostile Origin → 403 from the gateway, through the proxy.
curl -s -o /dev/null -w '%{http_code}\n' "$BASE" \
     -H "Authorization: Bearer $TOKEN" -H 'Origin: https://evil.example' \
     -H 'Content-Type: application/json' -d '{}'

# 3 — a chunked request → 200: the proxy buffered it into Content-Length.
# A 411 means requests are being relayed chunked; restore request buffering.
curl -s -o /dev/null -w '%{http_code}\n' "$BASE" \
     -H "Authorization: Bearer $TOKEN" -H 'Transfer-Encoding: chunked' \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
```

And the plain port must not answer from outside the host:
`curl http://mcp.example.com:8080/mcp` timing out is the correct result.
