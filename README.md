# oauth-kid-test

OAuth test client that verifies JWKS `kid` matching in AT Protocol PDS implementations.

Signs `client_assertion` with key-2 from a two-key JWKS — passes if the PDS looks up by `kid`, fails if it grabs `keys[0]`.

## Setup

```bash
uv sync
```

## Run

```bash
CLIENT_HOST=oauth-test.glados.computer uv run python3 app.py
```

Replace `CLIENT_HOST` with your domain. The app listens on port 9999 and must be reachable by the PDS at `https://<CLIENT_HOST>/`.

Keys are auto-generated in `keys/` on first run and reused on subsequent runs.

## How it works

1. Exposes a client metadata endpoint and JWKS with two keys (key-1 at index 0, key-2 at index 1)
2. Signs `client_assertion` with key-2, putting `kid: "key-2"` in the JWT header
3. If the PDS looks up by `kid` → finds key-2 → signature verified → PASS
4. If the PDS grabs `keys[0]` → gets key-1 → wrong key → FAIL
