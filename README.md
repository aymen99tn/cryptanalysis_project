# TLS 1.3 Document Server

Secure document retrieval server in C++17 using OpenSSL 3 and SQLite. The server listens on TCP port 8080, enforces TLS 1.3 with AEAD ciphers, and serves documents from a local SQLite store via a minimal text protocol.

## Prerequisites

- OpenSSL 3.x and headers
- SQLite3 and headers
- g++ with C++17 support

Example (Ubuntu/Debian):

```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev libsqlite3-dev
```

## Build

```bash
make
```

## Run

```bash
./server
```

Environment variables:
- `TLS_CERT` (default `cert.pem`)
- `TLS_KEY` (default `key.pem`)
- `DOC_DB` (default `data/documents.db`)

## Generate self-signed credentials

Use lab-only certs; do not reuse in production.

```bash
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=localhost"
```

Point the server to alternate paths with `TLS_CERT`/`TLS_KEY` if desired.

## Protocol

Single request per connection:
- Request: `GET <id>\n`
- Success: `OK <mime> <len>\n` followed by `len` bytes of content
- Errors: `ERR <reason>\n` (e.g., `request_too_long`, `unsupported_command`, `missing_id`, `not_found`)

## TLS Policy

- TLS 1.3 only; compression and renegotiation disabled
- Ciphersuites: `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`
- Ephemeral (EC)DHE for forward secrecy
- Self-signed certs for lab use; client must load the issuing CA for authentication

## Data Store

SQLite database at `DOC_DB`; server seeds a sample document on startup if empty. Parent directories are created automatically.

To inspect the seeded content:

```bash
sqlite3 data/documents.db 'SELECT id, mime, length(content) FROM documents;'
```

## Quick Test (openssl client)

```bash
openssl s_client -connect 127.0.0.1:8080 -tls1_3 -servername localhost -CAfile cert.pem <<'EOF'
GET readme
EOF
```

Expect a negotiated TLS 1.3 cipher and an `OK` header with MIME/length, followed by the payload. For TLS 1.2 clients, the server should reject the handshake (`protocol version` alert).

## Development Notes

- Logging: handshake result (protocol/cipher) and errors are emitted to stdout/stderr; keep output concise.
- Resource management: sockets, SSL objects, and SQLite statements are freed on all paths to avoid leaks.
- Limits: request line capped at 1024 bytes; one request per connection; no mTLS or rate limiting in this lab build.

## TODOs

- Decide whether to add client authentication (mTLS) or rate limiting for robustness.
- Collect real handshake/timing metrics for inclusion in the report.
- Improve diagrams in the report to match ACM formatting.
