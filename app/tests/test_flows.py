"""Every provider's flow against a real Twin over TLS, the way the broker, Chrome and the gateway
drive it: discovery and registration (DCR), consent, token, MCP, refresh, rotation.
python -m unittest"""
import base64
import hashlib
import http.client
import json
import secrets
import ssl
import tempfile
import unittest
import urllib.parse
from pathlib import Path

from owltwin_app.config import scan
from owltwin_app.tls import ensure_certs
from owltwin_app.twin import TwinRegistry, TwinState, free_port, start_tls_server

PROVIDERS = Path(__file__).resolve().parents[2] / "providers"
CTX = ssl._create_unverified_context()
REDIRECT = "http://localhost:33000/r/oauth/callback"
fails = []


def req(port, method, host, path, body=None, headers=None, form=False):
    h = {"Host": host, **(headers or {})}
    data = None
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body)
            h["Content-Type"] = "application/json"
    c = http.client.HTTPSConnection("127.0.0.1", port, context=CTX, timeout=5)
    try:
        c.request(method, path, body=data, headers=h)
        with c.getresponse() as r:
            raw = r.read().decode()
            status, resp_headers = r.status, dict(r.getheaders())
    finally:
        c.close()
    try:
        js = json.loads(raw)
    except Exception:
        js = None
    return status, js, resp_headers


def rpc(method, id, params=None):
    msg = {"jsonrpc": "2.0", "id": id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def basic(username, secret):
    return "Basic " + base64.b64encode(f"{username}:{secret}".encode()).decode()


def split(url):
    return urllib.parse.urlsplit(url)


def with_query(url, params):
    return url.path + "?" + urllib.parse.urlencode(params)


def check(name, cond, what):
    if not cond:
        fails.append(f"{name}: {what}")


def mcp(name, p, sp, host, path, auth):
    headers = {"Authorization": auth}
    st, js, _ = req(sp, "POST", host, path, rpc("initialize", 1, {}), headers)
    ok = st == 200 and js["result"]["serverInfo"]["name"] == p.mcp_server_name
    check(name, ok, f"MCP initialize {st}")

    st, js, _ = req(sp, "POST", host, path, rpc("tools/list", 2), headers)
    n_tools = len(js["result"]["tools"]) if js else "?"
    check(name, st == 200 and n_tools == len(p.tools), f"tools/list {n_tools} tools")

    tool = p.tools[0]["name"]
    call = rpc("tools/call", 3, {"name": tool, "arguments": {}})
    st, js, _ = req(sp, "POST", host, path, call, headers)
    check(name, st == 200 and "content" in js["result"], f"tools/call {tool}")


def discover_and_register(name, p, sp):
    """Broker side of a dynamic provider: PRM, AS metadata, DCR."""
    res = split(p.resource)
    # Broker: RFC 9728 at the resource host, path-aware.
    prm_path = "/.well-known/oauth-protected-resource" + res.path.rstrip("/")
    s, js, _ = req(sp, "GET", res.hostname, prm_path)
    if p.protected_resource:
        as_url = js and js["authorization_servers"][0]
        check(name, s == 200 and js["resource"] == p.resource, f"PRM 200 → {as_url}")
        issuer = split(js["authorization_servers"][0])
    else:
        check(name, s == 404, "no PRM (404), broker falls back to the origin")
        issuer = split(f"https://{res.hostname}")

    meta_path = "/.well-known/oauth-authorization-server" + issuer.path.rstrip("/")
    s, meta, _ = req(sp, "GET", issuer.hostname, meta_path)
    reg_url = meta and meta.get("registration_endpoint")
    check(name, s == 200 and reg_url, f"AS metadata 200, register at {reg_url}")

    supported = meta["token_endpoint_auth_methods_supported"]
    method = "none" if "none" in supported else "client_secret_post"
    reg = split(meta["registration_endpoint"])
    registration = {
        "client_name": "Samsara",
        "redirect_uris": [REDIRECT],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": method,
    }
    s, cl, _ = req(sp, "POST", reg.hostname, reg.path, registration)
    got_method = cl and cl.get("token_endpoint_auth_method")
    check(name, s == 201 and cl.get("client_id"), f"register {method} → {got_method}")

    cid, secret = cl["client_id"], cl.get("client_secret", "")
    az, tk = split(meta["authorization_endpoint"]), split(meta["token_endpoint"])
    return cid, secret, az, tk


def oauth_flow(name, p, st_, bp, sp):
    if p.mode == "dynamic":
        cid, secret, az, tk = discover_and_register(name, p, sp)
        resource = p.resource
    else:
        cid, secret, resource = p.client_id, st_.client_secret, ""
        authorize_path = p.endpoints["authorize"].render(tenant=p.tenant)
        az = split(f"https://{p.browser_hosts[0]}{authorize_path}")
        google = "oauth2.googleapis.com"
        token_host = google if google in p.server_hosts else p.server_hosts[0]
        tk = split(f"https://{token_host}{p.endpoints['token'].render(tenant=p.tenant)}")

    # Chrome: consent page, then Allow.
    ver = secrets.token_urlsafe(32)
    ch = base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b"=").decode()
    q = {
        "response_type": "code",
        "client_id": cid,
        "redirect_uri": REDIRECT,
        "state": "st1",
        "scope": "x",
        "code_challenge": ch,
        "code_challenge_method": "S256",
    }
    if resource:
        q["resource"] = resource
    referer = {"Referer": "https://localhost:33000/"}
    s, _, _ = req(bp, "GET", az.hostname, with_query(az, q), headers=referer)
    check(name, s == 200, f"Chrome: consent page {s}")
    s, _, hd = req(bp, "GET", az.hostname, with_query(az, {**q, "decision": "approve"}))
    loc = hd.get("Location", "")
    code = dict(urllib.parse.parse_qsl(split(loc).query)).get("code")
    check(name, s == 302 and code, "Allow → 302 code")

    # Gateway: code exchange.
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "code_verifier": ver,
        "client_id": cid,
    }
    if secret:
        form["client_secret"] = secret
    if resource:
        form["resource"] = resource
    s, tok, _ = req(sp, "POST", tk.hostname, tk.path, form, form=True)
    check(name, s == 200 and tok.get("access_token"), f"token exchange {s}")

    # MCP with the token, then with a bad one.
    if p.mode == "dynamic":
        mcp_host = split(p.resource).hostname
    else:
        mcp_hosts = (h for h in p.server_hosts if "mcp" in h or "workiq" in h)
        mcp_host = next(mcp_hosts, p.server_hosts[0])
    mcp_path = p.endpoints["mcp"].render(tenant=p.tenant)
    mcp(name, p, sp, mcp_host, mcp_path, "Bearer " + tok["access_token"])
    bad_auth = {"Authorization": "Bearer nope"}
    s, js, hd = req(sp, "POST", mcp_host, mcp_path, rpc("tools/list", 9), bad_auth)
    challenge = hd.get("WWW-Authenticate", "")
    expect_prm = p.mode == "dynamic" and p.protected_resource
    check(name, s == 401 and ("resource_metadata" in challenge) == expect_prm,
          f"bad token → 401, challenge {challenge[:60]}")

    # Refresh, then rotate and refresh again.
    rf = {"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": cid}
    if secret:
        rf["client_secret"] = secret
    if resource:
        rf["resource"] = resource
    s, tok2, _ = req(sp, "POST", tk.hostname, tk.path, rf, form=True)
    check(name, s == 200, f"refresh {s}")
    st_.rotate_secret()
    if tok2.get("refresh_token"):
        rf["refresh_token"] = tok2["refresh_token"]
    s, js, _ = req(sp, "POST", tk.hostname, tk.path, rf, form=True)
    check(name, s == 401 and js["error"] == "invalid_client",
          f"after Rotate/Delete: refresh {s} {js and js.get('error')}")

    if p.mode == "dynamic":
        stranger = {**q, "client_id": "someone-else"}
        s, _, _ = req(bp, "GET", az.hostname, with_query(az, stranger))
        check(name, s == 400, "unregistered client_id → consent page rejects (400)")
        cid2 = st_.current_client()[0] if st_.current_client() else None
        if cid2:
            wrong_resource = {**q, "client_id": cid2, "resource": "https://evil.test/mcp"}
            s, _, _ = req(bp, "GET", az.hostname, with_query(az, wrong_resource))
            check(name, s == 400, "wrong resource → 400")


def api_flow(name, p, st_, sp):
    host, path = p.server_hosts[0], p.endpoints["mcp"].render(tenant=p.tenant)
    good = basic(p.api_key["username"], st_.api_secret)
    mcp(name, p, sp, host, path, good)
    check(name, st_.connection()["connected"], "connection shows Working")

    bad = basic(p.api_key["username"], "wrong")
    s, _, _ = req(sp, "POST", host, path, rpc("tools/list", 1), {"Authorization": bad})
    check(name, s == 401, "wrong token → 401")

    st_.rotate_secret()
    s, _, _ = req(sp, "POST", host, path, rpc("tools/list", 1), {"Authorization": good})
    reason = st_.exchanges[-1].reason
    check(name, s == 401 and "rotated" in reason, f"old token after rotate → 401 ({reason})")


class Twin:
    def __init__(self, p):
        d = Path(tempfile.mkdtemp())
        _ca, crt, key = ensure_certs(d, p.all_hosts)
        self.st = TwinState(p, lambda: None)
        self.bp, self.sp = free_port(), free_port()
        self.srvs = [
            start_tls_server(self.st, "127.0.0.1", self.bp, str(crt), str(key), "browser"),
            start_tls_server(self.st, "127.0.0.1", self.sp, str(crt), str(key), "server"),
        ]

    def close(self):
        for s in self.srvs:
            s.shutdown()
            s.server_close()


class Twins:
    """One Twin for every provider at once, as a session runs it."""

    def __init__(self, providers):
        d = Path(tempfile.mkdtemp())
        hosts = sorted({h for p in providers for h in p.all_hosts})
        _ca, crt, key = ensure_certs(d, hosts)
        self.reg = TwinRegistry(providers, lambda: None)
        self.bp, self.sp = free_port(), free_port()
        self.srvs = [
            start_tls_server(self.reg, "127.0.0.1", self.bp, str(crt), str(key), "browser"),
            start_tls_server(self.reg, "127.0.0.1", self.sp, str(crt), str(key), "server"),
        ]

    def close(self):
        for s in self.srvs:
            s.shutdown()
            s.server_close()


class FlowTest(unittest.TestCase):
    def test_all_providers_at_once(self):
        """Every flow again, with all connectors served by one Twin: shared hosts (Google's token
        endpoint, mcp.atlassian.com, login.microsoftonline.com) must reach the right connector."""
        providers = [e.provider for e in scan(PROVIDERS)]
        self.assertTrue(all(providers))
        t = Twins(providers)
        try:
            for p in providers:
                st = t.reg.states[p.id]
                with self.subTest(provider=p.id):
                    fails.clear()
                    if p.mode == "api_key":
                        api_flow(p.id, p, st, t.sp)
                    else:
                        oauth_flow(p.id, p, st, t.bp, t.sp)
                    self.assertEqual(fails, [])
            stray = [
                (e.provider, e.method, e.host, e.path) for e in t.reg.log.all() if e.candidates
            ]
            self.assertEqual(stray, [], "requests the Twin could not attribute")
        finally:
            t.close()

    def test_unknown_token_revoke_is_ambiguous(self):
        by_id = {e.provider.id: e.provider for e in scan(PROVIDERS)}
        t = Twins([by_id["gmail"], by_id["google-calendar"]])
        try:
            rev = by_id["gmail"].endpoints.get("revoke")
            self.assertIsNotNone(rev)
            host = "oauth2.googleapis.com"
            req(t.sp, "POST", host, rev.template, {"token": "nope"}, form=True)
            last = t.reg.log.all()[-1]
            self.assertEqual(sorted(last.candidates), ["gmail", "google-calendar"])
        finally:
            t.close()


    def test_every_provider(self):
        for e in scan(PROVIDERS):
            p = e.provider
            with self.subTest(provider=e.file.name):
                self.assertIsNotNone(p, e.error)
                fails.clear()
                t = Twin(p)
                try:
                    if p.mode == "api_key":
                        api_flow(p.id, p, t.st, t.sp)
                    else:
                        oauth_flow(p.id, p, t.st, t.bp, t.sp)
                    st2 = TwinState(p, lambda: None)
                    st2.restore(json.loads(json.dumps(t.st.snapshot())))
                    same_secret = st2.connection()["secret"] == t.st.connection()["secret"]
                    check(p.id, same_secret, "snapshot/restore")
                finally:
                    t.close()
                self.assertEqual(fails, [])

    def test_large_mcp_call_is_parsed_whole(self):
        p = next(e.provider for e in scan(PROVIDERS) if e.file.name == "atlassian.yaml")
        t = Twin(p)
        try:
            auth = {"Authorization": basic(p.api_key["username"], t.st.api_secret)}
            args = {"name": p.tools[0]["name"], "arguments": {"code": "x" * 60000}}
            path = p.endpoints["mcp"].template
            s, js, _ = req(t.sp, "POST", p.server_hosts[0], path, rpc("tools/call", 1, args), auth)
            last = t.st.exchanges[-1]
            self.assertEqual(s, 200, last.reason)
            self.assertIn("content", js["result"])
            self.assertLessEqual(len(last.req_body), 20000)   # the log still keeps a cut copy
            self.assertFalse(hasattr(last, "_raw"))
        finally:
            t.close()


if __name__ == "__main__":
    unittest.main()
