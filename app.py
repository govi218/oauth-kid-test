#!/usr/bin/env python3
"""OAuth test client that verifies JWKS kid matching.

Uses private_key_jwt with a JWKS containing 2 keys.
The client_assertion is signed with key-2 (not key-1).
If the PDS looks up by kid -> key-2 -> PASS.
If the PDS grabs keys[0] -> key-1 -> FAIL.

Usage:
  CLIENT_HOST=oauth-test.glados.computer uv run python3 app.py
"""

import json
import os
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlencode, parse_qs, urlparse

from authlib.jose import JsonWebKey, jwt
from authlib.common.security import generate_token
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import requests

PDS_HOST = os.environ.get("PDS_HOST", "pds2.glados.computer")
PDS_BASE = f"https://{PDS_HOST}"
CLIENT_HOST = os.environ.get("CLIENT_HOST", "oauth-test.glados.computer")
CLIENT_BASE = f"https://{CLIENT_HOST}"
REDIRECT_URI = f"{CLIENT_BASE}/callback"
LISTEN_PORT = 9999
SCOPE = "atproto transition:generic"
KEYS_DIR = Path(__file__).parent / "keys"


# --- Key management ---

def _save_pem(name, key):
    KEYS_DIR.mkdir(exist_ok=True)
    pem = key.get_private_key().private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    (KEYS_DIR / name).write_bytes(pem)


def _load_pem(name, kid):
    pem = (KEYS_DIR / name).read_bytes()
    return JsonWebKey.import_key(pem, options={"kid": kid})


def load_or_generate_keys():
    if (KEYS_DIR / "key1.pem").exists():
        print(f"Loaded keys from {KEYS_DIR}")
        return _load_pem("key1.pem", "key-1"), _load_pem("key2.pem", "key-2"), _load_pem("dpop.pem", "dpop")
    key1 = JsonWebKey.generate_key("EC", "P-256", options={"kid": "key-1"}, is_private=True)
    key2 = JsonWebKey.generate_key("EC", "P-256", options={"kid": "key-2"}, is_private=True)
    dpop = JsonWebKey.generate_key("EC", "P-256", options={"kid": "dpop"}, is_private=True)
    _save_pem("key1.pem", key1)
    _save_pem("key2.pem", key2)
    _save_pem("dpop.pem", dpop)
    print(f"Generated new keys -> {KEYS_DIR}")
    return key1, key2, dpop


key1, key2, dpop_key = load_or_generate_keys()

JWKS = {"keys": [
    json.loads(key1.as_json(is_private=False)),
    json.loads(key2.as_json(is_private=False)),
]}

CLIENT_METADATA = {
    "client_id": f"{CLIENT_BASE}/oauth/client-metadata.json",
    "client_name": "kid Matching Test",
    "client_uri": CLIENT_BASE,
    "redirect_uris": [REDIRECT_URI],
    "scope": SCOPE,
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "private_key_jwt",
    "token_endpoint_auth_signing_alg": "ES256",
    "jwks_uri": f"{CLIENT_BASE}/oauth/jwks.json",
    "application_type": "web",
    "dpop_bound_access_tokens": True,
}


# --- OAuth helpers (based on bluesky cookbook) ---

flows = {}  # {state: {code_verifier, dpop_nonce, dpop_key_json}}


def make_client_assertion(authserver_url):
    """Sign with key-2. If the PDS grabs keys[0] (key-1), this fails."""
    return jwt.encode(
        {"alg": "ES256", "kid": key2["kid"]},
        {"iss": CLIENT_METADATA["client_id"],
         "sub": CLIENT_METADATA["client_id"],
         "aud": authserver_url,
         "jti": generate_token(),
         "iat": int(time.time()),
         "exp": int(time.time()) + 60},
        key2,
    ).decode("utf-8")


def make_dpop(method, url, nonce=None, dpop_priv=None):
    if dpop_priv is None:
        dpop_priv = dpop_key
    dpop_pub = json.loads(dpop_priv.as_json(is_private=False))
    body = {"jti": generate_token(), "htm": method, "htu": url,
            "iat": int(time.time()), "exp": int(time.time()) + 30}
    if nonce:
        body["nonce"] = nonce
    return jwt.encode(
        {"typ": "dpop+jwt", "alg": "ES256", "jwk": dpop_pub},
        body, dpop_priv,
    ).decode("utf-8")


def is_dpop_nonce_error(resp):
    if resp.status_code not in (400, 401):
        return False
    if "use_dpop_nonce" in resp.headers.get("WWW-Authenticate", "").lower():
        return True
    try:
        return resp.json().get("error") == "use_dpop_nonce"
    except Exception:
        return False


def auth_post(url, data, authserver_url, nonce=None, dpop_priv=None):
    """POST with client_assertion + DPoP, handling nonce retry."""
    data = {**data,
            "client_id": CLIENT_METADATA["client_id"],
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": make_client_assertion(authserver_url)}
    headers = {"DPoP": make_dpop("POST", url, nonce, dpop_priv)}
    resp = requests.post(url, data=data, headers=headers, timeout=120)
    if is_dpop_nonce_error(resp):
        nonce = resp.headers.get("DPoP-Nonce", "")
        headers["DPoP"] = make_dpop("POST", url, nonce, dpop_priv)
        resp = requests.post(url, data=data, headers=headers, timeout=120)
    return resp, nonce


def start_flow(login_hint=None):
    meta = requests.get(f"{PDS_BASE}/.well-known/oauth-authorization-server", timeout=30).json()
    authserver_url = meta["issuer"]

    state = generate_token()
    verifier = generate_token(48)
    challenge = create_s256_code_challenge(verifier)

    # Generate a per-flow DPoP key
    flow_dpop = JsonWebKey.generate_key("EC", "P-256", options={"kid": "dpop"}, is_private=True)

    par_data = {"response_type": "code", "code_challenge": challenge,
                "code_challenge_method": "S256", "state": state,
                "redirect_uri": REDIRECT_URI, "scope": SCOPE}
    if login_hint:
        par_data["login_hint"] = login_hint

    resp, nonce = auth_post(meta["pushed_authorization_request_endpoint"], par_data,
                            authserver_url, nonce="", dpop_priv=flow_dpop)
    if resp.status_code not in (200, 201):
        raise Exception(f"PAR failed: {resp.status_code} {resp.text}")

    flows[state] = {"code_verifier": verifier, "dpop_nonce": nonce,
                    "dpop_key_json": flow_dpop.as_json(is_private=True)}

    params = {"request_uri": resp.json()["request_uri"],
              "client_id": CLIENT_METADATA["client_id"]}
    return f"{meta['authorization_endpoint']}?{urlencode(params)}"


def exchange_code(code, state):
    st = flows.get(state)
    if not st:
        raise Exception("unknown state")

    meta = requests.get(f"{PDS_BASE}/.well-known/oauth-authorization-server", timeout=30).json()
    authserver_url = meta["issuer"]
    flow_dpop = JsonWebKey.import_key(json.loads(st["dpop_key_json"]))

    data = {"redirect_uri": REDIRECT_URI, "grant_type": "authorization_code",
            "code": code, "code_verifier": st["code_verifier"]}

    resp, _ = auth_post(meta["token_endpoint"], data, authserver_url,
                        nonce=st.get("dpop_nonce"), dpop_priv=flow_dpop)
    if resp.status_code != 200:
        raise Exception(f"Token exchange failed: {resp.status_code} {resp.text}")
    return resp.json()


# --- HTTP server ---

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/oauth/client-metadata.json":
            self._json(200, CLIENT_METADATA)
        elif path == "/oauth/jwks.json":
            self._json(200, JWKS)
        elif path == "/callback":
            self._callback()
        elif path == "/start":
            self._start()
        else:
            self._index()

    def _json(self, code, data):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, code, html):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def _index(self):
        self._html(200, """<!DOCTYPE html>
<html><head><title>kid Matching Test</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:600px;margin:40px auto;padding:0 20px;color:#111}
  h1{font-size:1.3em}
  .info{background:#f5f5f5;border-radius:8px;padding:16px;margin:16px 0}
  .key{font-family:monospace;font-size:.85em;background:#e8e8e8;padding:2px 6px;border-radius:4px}
  button{background:#2563eb;color:#fff;border:none;padding:10px 24px;border-radius:6px;font-size:1em;cursor:pointer}
  button:hover{background:#1d4ed8}
  input{border:1px solid #ccc;padding:8px;border-radius:6px;width:100%;box-sizing:border-box;margin:4px 0}
  label{font-size:.85em;color:#555}
</style></head>
<body>
<h1>kid Matching Test</h1>
<p>OAuth client with <code>private_key_jwt</code> and a JWKS containing 2 keys.
The <code>client_assertion</code> is signed with <strong>key-2</strong>.</p>
<div class="info">
  <strong>key-1</strong> <span class="key">JWKS index 0</span> &mdash; not used for signing<br>
  <strong>key-2</strong> <span class="key">JWKS index 1</span> &mdash; signs client_assertion
</div>
<p>PDS looks up by <code>kid</code> &rarr; key-2 &rarr; PASS.<br>
PDS grabs <code>keys[0]</code> &rarr; key-1 &rarr; FAIL.</p>
<label>Login hint (optional)</label>
<input id="hint" placeholder="burner.pds2.glados.computer">
<button onclick="start()">Sign In</button>
<script>
function start(){
  const h=document.getElementById('hint').value.trim();
  location.href='/start'+(h?'?login_hint='+encodeURIComponent(h):'');
}
</script>
</body></html>""")

    def _start(self):
        try:
            hint = parse_qs(urlparse(self.path).query).get("login_hint", [None])[0]
            url = start_flow(login_hint=hint)
            self.send_response(303)
            self.send_header("Location", url)
            self.end_headers()
        except Exception as e:
            self._html(500, f"<h1>Error</h1><pre>{e}</pre>")

    def _callback(self):
        params = parse_qs(urlparse(self.path).query)

        if "error" in params:
            err = params["error"][0]
            desc = params.get("error_description", [""])[0]
            self._html(400, f"<h1>OAuth Error</h1><pre>{err}: {desc}</pre>")
            return

        code = params.get("code", [None])[0]
        state = params.get("state", [None])[0]

        if not code or not state or state not in flows:
            self._html(400, "<h1>Error</h1><p>Missing or invalid state/code</p>")
            return

        iss = params.get("iss", [None])[0]
        if iss and iss != PDS_BASE:
            self._html(400, f"<h1>Error</h1><p>iss mismatch: expected {PDS_BASE}, got {iss}</p>")
            return

        try:
            tokens = exchange_code(code, state)
            self._html(200, f"""<h1 style="color:#16a34a">PASS</h1>
<p>PDS correctly looked up <strong>key-2</strong> by <code>kid</code>. Signature verified.</p>
<pre>{json.dumps(tokens, indent=2)}</pre>
<p><a href="/">Back</a></p>""")
        except Exception as e:
            self._html(400, f"""<h1 style="color:#dc2626">FAIL</h1>
<pre>{e}</pre>
<p>PDS likely grabbed <code>keys[0]</code> (key-1) instead of looking up by <code>kid</code> (key-2).</p>
<p><a href="/">Back</a></p>""")


if __name__ == "__main__":
    print(f"Client ID: {CLIENT_METADATA['client_id']}")
    print(f"JWKS: {[k['kid'] for k in JWKS['keys']]}")
    print(f"Signing with: key-2")
    print(f"Listening on :{LISTEN_PORT}")
    from socketserver import ThreadingMixIn
    class ThreadedServer(ThreadingMixIn, HTTPServer): pass
    ThreadedServer(("127.0.0.1", LISTEN_PORT), Handler).serve_forever()
