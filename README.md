# oauth-kid-test

OAuth test client that verifies JWKS `kid` matching in AT Protocol PDS implementations.

Signs `client_assertion` with key-2 from a two-key JWKS — passes if the PDS looks up by `kid`, fails if it grabs `keys[0]`.

## Setup

```bash
uv sync
```

## Run

The app listens on port 9999 and must be reachable by the PDS at `https://<CLIENT_HOST>/`.

### With a domain

```bash
CLIENT_HOST=oauth-test.mycooldomain.at PDS_HOST=mycoolpds.at uv run python3 app.py
```

### With ngrok (easiest)

```bash
ngrok http 9999
CLIENT_HOST=<ngrok-domain> PDS_HOST=mycoolpds.at uv run python3 app.py
```

