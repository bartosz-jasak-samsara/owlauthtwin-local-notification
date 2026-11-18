"""The vendor Twin: OAuth 2.1 (authorize, token, refresh, revoke) and MCP over
Streamable HTTP, driven by one provider YAML. Every exchange is recorded."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import http.server
import json
import secrets
import socket
import ssl
import threading
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .config import Provider
from .templating import render as render_template

REDACT_HEADERS = {"cookie"}

# Local Samsara builds its OAuth callback from url_base plus DEVBOX_INDEX*10000,
# which is often unset (or out of range) on a devbox, so the port can point at
# the wrong tunnel. The Twin is the page that sends Chrome to the callback, so
# it sends Chrome to the port Agent Studio was actually opened on. Only loopback
# hosts and only this path are touched; the token step still compares against
# the redirect_uri the backend sent.
LOOPBACK = {"localhost", "127.0.0.1", "::1"}
CALLBACK_PATH = "/r/oauth/callback"
PORT_PARAM = "owltwin_port"   # carried from the first authorize request to Allow/Deny

# Request headers worth repeating in the curl command of an exchange.
CURL_HEADERS = (
    "content-type", "authorization", "accept", "mcp-session-id", "mcp-protocol-version",
)

CLIENT_AUTH_FAILED = {
    "error": "invalid_client",
    "error_description": "Client authentication failed",
}


def loopback_port(url: str) -> int:
    """Port of a loopback http(s) origin, 0 for anything else."""
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port or 0
    except ValueError:
        return 0
    is_loopback = u.scheme in ("http", "https") and (u.hostname or "") in LOOPBACK
    return port if is_loopback and 0 < port < 65536 else 0


def fix_callback(redirect: str, port: int) -> tuple[str, str]:
    """Returns the URL to send Chrome to and, when it differs, a note saying why."""
    try:
        u = urllib.parse.urlsplit(redirect)
        current = u.port
    except ValueError:
        return redirect, ""
    if not port or (u.hostname or "") not in LOOPBACK or u.path != CALLBACK_PATH or current == port:
        return redirect, ""
    host = f"[{u.hostname}]" if ":" in (u.hostname or "") else u.hostname
    fixed = urllib.parse.urlunsplit((u.scheme, f"{host}:{port}", u.path, u.query, u.fragment))
    note = (
        f"redirect_uri uses port {current or 'none'}, but Agent Studio is on {port}. "
        f"The Twin sent Chrome to :{port}; the token step still expects the original redirect_uri."
    )
    return fixed, note


def fill_values(p: Provider, value: Any) -> Any:
    """Fills {tenant}, {client.id} and the like in every string of a parsed value, so a secret with
    quotes or backslashes cannot break the JSON around it."""
    if isinstance(value, str):
        return p.fill(value)
    if isinstance(value, list):
        return [fill_values(p, v) for v in value]
    if isinstance(value, dict):
        return {fill_values(p, k): fill_values(p, v) for k, v in value.items()}
    return value


def pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def basic_auth(username: str, secret: str) -> str:
    return "Basic " + base64.b64encode(f"{username}:{secret}".encode()).decode()


def tail(value: str, n: int = 4) -> str:
    return "…" + value[-n:] if value else "(empty)"


@dataclass
class Exchange:
    id: int
    ts: float
    listener: str              # browser | server
    method: str
    host: str
    path: str
    query: dict[str, str]
    req_headers: dict[str, str]
    req_body: str
    kind: str = "other"         # authorize | token | refresh | revoke | mcp | other
    detail: dict[str, Any] = field(default_factory=dict)
    status: int = 0
    resp_headers: dict[str, str] = field(default_factory=dict)
    resp_body: str = ""
    ok: bool = False
    reason: str = ""            # plain-language explanation of a rejection
    injected: bool = False
    duration_ms: int = 0
    provider: str = ""          # the connector (provider id) the request belongs to
    # Connectors it could belong to when nothing in the request told them apart (else empty).
    candidates: list[str] = field(default_factory=list)

    @property
    def actor(self) -> str:
        if self.listener == "browser":
            return "browser"
        if self.listener == "panel":
            return "you"
        actors = {
            "token": "product → token",
            "refresh": "product → token",
            "revoke": "product → token",
            "register": "product → token",
            "discovery": "product → token",
            "mcp": "agent → MCP",
        }
        return actors.get(self.kind, "devbox")

    def summary(self) -> str:
        if self.kind == "mcp":
            m = self.detail.get("rpc", "")
            return f"{m} {self.detail.get('tool', '')}".strip()
        if self.kind in ("token", "refresh"):
            return self.detail.get("grant_type", "")
        if self.kind == "authorize":
            return self.detail.get("decision") or "consent page"
        return ""

    def curl(self) -> str:
        url = f"https://{self.host}{self.path}"
        if self.query:
            url += "?" + urllib.parse.urlencode(self.query)
        parts = [f"curl -k -X {self.method} '{url}'"]
        for k, v in self.req_headers.items():
            if k.lower() in CURL_HEADERS:
                parts.append(f"  -H '{k}: {v}'")
        if self.req_body:
            parts.append("  --data '" + self.req_body.replace("'", "'\\''") + "'")
        return " \\\n".join(parts)


class ExchangeLog:
    """Activity: every request to the Twin, for all connectors, newest last."""

    LIMIT = 2000

    def __init__(self, on_change: Callable[[], None]):
        self.lock = threading.RLock()
        self.on_change = on_change
        self.items: list[Exchange] = []
        self._next_id = 1

    def new(self, **kw: Any) -> Exchange:
        with self.lock:
            ex = Exchange(id=self._next_id, ts=time.time(), **kw)
            self._next_id += 1
            return ex

    def add(self, ex: Exchange) -> None:
        with self.lock:
            self.items.append(ex)
            if len(self.items) > self.LIMIT:
                self.items = self.items[-self.LIMIT:]
        self.on_change()

    def all(self) -> list[Exchange]:
        with self.lock:
            return list(self.items)


class TwinState:
    def __init__(
        self, provider: Provider, on_change: Callable[[], None], log: ExchangeLog | None = None,
    ):
        self.lock = threading.RLock()
        self.provider = provider
        self.on_change = on_change
        self.client_secret = provider.client_secret
        self.previous_secret: str | None = None
        # DCR: clients Samsara registered at /register, by client_id (newest last).
        self.clients: dict[str, dict[str, Any]] = {}
        # API key: the token the gateway must send, and when it last got in with it.
        self.api_secret = provider.api_key.get("secret", "")
        self.previous_api_secret: str | None = None
        self.api_ok_at = 0.0
        self.auth_codes: dict[str, dict[str, Any]] = {}
        self.access_tokens: dict[str, dict[str, Any]] = {}
        self.refresh_tokens: dict[str, dict[str, Any]] = {}
        # Shared with the other connectors' states in a TwinRegistry.
        self.log = log or ExchangeLog(on_change)
        self.last_code_exchange = 0.0   # when an authorization code last became tokens
        # Agent Studio port of the session's devbox, used when Chrome sends no Referer.
        self.callback_port_fallback = 0
        # Faults to inject: kind -> list of (status, json_body, headers)
        self.faults: dict[str, list[tuple[int, dict[str, Any], dict[str, str]]]] = {}

    # Persistence: secrets and tokens survive an owltwin restart, so a connector
    # connected in Agent Studio keeps working. Exchanges are not kept.
    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "client_secret": self.client_secret,
                "previous_secret": self.previous_secret,
                "access_tokens": self.access_tokens,
                "refresh_tokens": self.refresh_tokens,
                "clients": self.clients,
                "api_secret": self.api_secret,
                "previous_api_secret": self.previous_api_secret,
                "api_ok_at": self.api_ok_at,
            }

    def restore(self, snap: dict[str, Any]) -> None:
        with self.lock:
            self.client_secret = snap.get("client_secret") or self.client_secret
            self.previous_secret = snap.get("previous_secret")
            self.access_tokens = dict(snap.get("access_tokens") or {})
            self.refresh_tokens = dict(snap.get("refresh_tokens") or {})
            self.clients = dict(snap.get("clients") or {})
            self.api_secret = snap.get("api_secret") or self.api_secret
            self.previous_api_secret = snap.get("previous_api_secret")
            self.api_ok_at = float(snap.get("api_ok_at") or 0.0)

    @property
    def exchanges(self) -> list[Exchange]:
        """This connector's part of Activity, oldest first."""
        pid = self.provider.id
        return [e for e in self.log.all() if e.provider == pid]

    def new_exchange(self, **kw: Any) -> Exchange:
        kw.setdefault("provider", self.provider.id)
        return self.log.new(**kw)

    def record(self, ex: Exchange) -> None:
        ex.provider = ex.provider or self.provider.id
        self.log.add(ex)

    def take_fault(self, kind: str):
        with self.lock:
            queue = self.faults.get(kind)
            if queue:
                return queue.pop(0)
        return None

    def current_client(self) -> tuple[str, dict[str, Any]] | None:
        """The newest DCR client, the one Samsara uses for new connections."""
        with self.lock:
            return next(reversed(self.clients.items()), None) if self.clients else None

    def issue_tokens(self, scope: str, refresh_token: str | None = None, client_id: str = "",
                     resource: str = "") -> dict[str, Any]:
        p = self.provider
        ttl = int(p.oauth["access_token_ttl"])
        prefix = p.token_prefix
        at = f"{prefix}-at-{secrets.token_hex(8)}"
        with self.lock:
            self.access_tokens[at] = {
                "scope": scope,
                "expires_at": time.time() + ttl,
                "client_id": client_id,
                "resource": resource,
            }
            body: dict[str, Any] = {
                "access_token": at,
                "token_type": "Bearer",
                "expires_in": str(ttl) if p.oauth["expires_in_as_string"] else ttl,
                "scope": scope,
            }
            if refresh_token is None or p.oauth["rotate_refresh_token"]:
                rt = f"{prefix}-rt-{secrets.token_hex(8)}"
                self.refresh_tokens[rt] = {
                    "scope": scope,
                    "revoked": False,
                    "client_id": client_id,
                    "resource": resource,
                }
                if refresh_token and refresh_token in self.refresh_tokens:
                    self.refresh_tokens[refresh_token]["revoked"] = True
                    self.refresh_tokens[refresh_token]["replaced_by"] = rt
                body["refresh_token"] = rt
            return body

    # Twin actions from the panel. Each one is logged to Activity. ---------
    def note(self, text: str) -> None:
        ex = self.new_exchange(
            listener="panel", method="", host="", path="", query={}, req_headers={}, req_body="",
            kind="action", detail={"text": text}, ok=True,
        )
        self.record(ex)

    def rotate_secret(self) -> str:
        p = self.provider
        if p.mode == "api_key":
            with self.lock:
                self.previous_api_secret = self.api_secret
                self.api_secret = f"{p.token_prefix}-api-token-{secrets.token_hex(6)}"
                self.api_ok_at = 0.0
            self.note(
                f"You rotated the API token to {self.api_secret}. The gateway's next MCP call "
                "with the old one gets 401 until the token is updated in Agent Studio."
            )
            return self.api_secret
        if p.mode == "dynamic":
            cur = self.current_client()
            if not cur:
                self.note(
                    "No client is registered yet, so there is no secret to rotate. Connect first."
                )
                return ""
            cid, c = cur
            with self.lock:
                if c["auth"] == "none":
                    # A public client has no secret: the closest real event is the server
                    # dropping the registration.
                    del self.clients[cid]
                    if p.oauth["revoke_tokens_on_secret_rotation"]:
                        self._revoke_locked()
                    text = (
                        f"You deleted client registration {cid} (a public client has no secret). "
                        "Samsara's next refresh gets invalid_client; it should register again and "
                        "ask you to reconnect."
                    )
                else:
                    c["previous_secret"] = c["secret"]
                    c["secret"] = f"{p.token_prefix}-secret-{secrets.token_hex(6)}"
                    if p.oauth["revoke_tokens_on_secret_rotation"]:
                        self._revoke_locked()
                    text = (
                        f"You rotated the secret of client {cid} to {c['secret']}. Samsara still "
                        "holds the old one, so its next refresh gets invalid_client; it should "
                        "register again and ask you to reconnect."
                    )
            self.note(text)
            return cid
        with self.lock:
            self.previous_secret = self.client_secret
            prefix = p.client_id.split("-")[0]
            self.client_secret = f"{prefix}-secret-{secrets.token_hex(6)}"
            revoked = bool(self.provider.oauth["revoke_tokens_on_secret_rotation"])
            if revoked:
                self._revoke_locked()
        if revoked:
            outcome = "Issued tokens were revoked, as this provider does."
        else:
            outcome = "Issued tokens stay valid, as this provider does."
        self.note(f"You rotated the client secret to {self.client_secret}. {outcome}")
        return self.client_secret

    def expire_access_tokens(self) -> int:
        if self.provider.mode == "api_key":
            self.note(
                "This connector uses an API token, not OAuth: there are no access tokens to "
                "expire. Rotate the token instead."
            )
            return 0
        now = time.time()
        n = 0
        with self.lock:
            for rec in self.access_tokens.values():
                if rec["expires_at"] > now:
                    rec["expires_at"] = now
                    n += 1
        self.note(
            f"You expired {n} access token(s). The next MCP call gets 401 until Samsara refreshes."
        )
        return n

    def _revoke_locked(self) -> None:
        self.access_tokens.clear()
        for rec in self.refresh_tokens.values():
            rec["revoked"] = True

    def revoke_all(self) -> None:
        if self.provider.mode == "api_key":
            self.note(
                "This connector uses an API token, not OAuth: there are no tokens to revoke. "
                "Rotate the token instead."
            )
            return
        with self.lock:
            self._revoke_locked()
        self.note(
            "You revoked all tokens. Samsara's next refresh gets invalid_grant, "
            "so the connector must reconnect."
        )

    def connection(self) -> dict[str, Any]:
        """What the Twin knows about the connector's connection."""
        now = time.time()
        with self.lock:
            live_rt = [k for k, v in self.refresh_tokens.items() if not v.get("revoked")]
            ats = sorted(self.access_tokens.items(), key=lambda kv: kv[1]["expires_at"])
            at = ats[-1] if ats else None
            token_times = [e.ts for e in self.exchanges if e.kind == "token" and e.ok]
            first_token = min(token_times, default=0.0)
            p = self.provider
            out = {
                "mode": p.mode,
                "connected": bool(live_rt),
                "refresh_token": live_rt[-1] if live_rt else "",
                "access_token": at[0] if at else "",
                "access_left": max(0, int(at[1]["expires_at"] - now)) if at else 0,
                "since": first_token,
                "client_id": p.client_id,
                "secret": self.client_secret,
                "previous_secret": self.previous_secret,
                "revoked": bool(self.refresh_tokens) and not live_rt,
            }
            if p.mode == "dynamic":
                cur = next(reversed(self.clients.items()), None) if self.clients else None
                if cur:
                    cid, client = cur
                    out.update(
                        client_id=cid,
                        secret=client.get("secret") or "none (public client)",
                        previous_secret=client.get("previous_secret"),
                    )
                else:
                    out.update(client_id="", secret="", previous_secret=None)
                out["clients"] = len(self.clients)
            if p.mode == "api_key":
                out.update(
                    connected=self.api_ok_at > 0, since=self.api_ok_at,
                    secret=self.api_secret, previous_secret=self.previous_api_secret,
                    revoked=False,
                )
            return out


class TwinRegistry:
    """One TwinState per connector, sharing one Activity log; routes each request to its state.

    Hosts are shared (Google's token endpoint serves Gmail and Calendar, mcp.atlassian.com serves
    both Atlassian connectors), so a request is told apart by what it carries, in this order:
    host and endpoint, client_id (query, form or Basic), a token the Twin issued, the auth scheme
    (Basic = API token). What is still undecided goes to the connector shown in the panel and is
    marked ambiguous in Activity.
    """

    def __init__(
        self, providers: list[Provider], on_change: Callable[[], None],
        active: Callable[[], str] | None = None,
    ):
        self.log = ExchangeLog(on_change)
        self.states = {p.id: TwinState(p, on_change, self.log) for p in providers}
        self.active = active or (lambda: next(iter(self.states)))

    @classmethod
    def of(cls, state: TwinState) -> TwinRegistry:
        """A registry around one existing state (tests, single-connector servers)."""
        reg = cls.__new__(cls)
        reg.log = state.log
        reg.states = {state.provider.id: state}
        reg.active = lambda: state.provider.id
        return reg

    def get(self, pid: str) -> TwinState | None:
        return self.states.get(pid)

    def _fallback(self, cands: list[TwinState]) -> TwinState:
        active = self.states.get(self.active())
        return active if active in cands else cands[0]

    def route(
        self, listener: str, method: str, host: str, path: str, query: dict[str, str],
        headers: Any, body: str,
    ) -> tuple[TwinState, list[str]]:
        """The state for a request, and the candidates when it stayed ambiguous."""
        states = list(self.states.values())
        if len(states) == 1:
            return states[0], []

        def hosts(p: Provider) -> list[str]:
            return p.browser_hosts if listener == "browser" else p.server_hosts

        cands = [st for st in states if host in hosts(st.provider)]
        cands = cands or [st for st in states if host in st.provider.all_hosts]
        if not cands:
            return self.states.get(self.active()) or states[0], []

        def narrow(keep: Callable[[TwinState], bool]) -> None:
            nonlocal cands
            if len(cands) > 1:
                cands = [st for st in cands if keep(st)] or cands

        discovery = method == "GET" and path.startswith("/.well-known/oauth-")
        narrow(lambda st: (discovery and st.provider.mode == "dynamic") or any(
            ep.match(method, path, host) is not None for ep in st.provider.endpoints.values()
        ))
        auth = headers.get("Authorization", "") or ""
        form = (
            dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
            if body and not body.lstrip().startswith(("{", "[")) else {}
        )
        basic_user = ""
        if auth.startswith("Basic "):
            with contextlib.suppress(ValueError):
                decoded = base64.b64decode(auth[6:]).decode("utf-8", "replace")
                basic_user = decoded.partition(":")[0]
        cid = query.get("client_id") or form.get("client_id") or basic_user
        if cid:
            narrow(lambda st: cid == st.provider.client_id or cid in st.clients)
        tokens = [t for t in (
            auth.removeprefix("Bearer ") if auth.startswith("Bearer ") else "",
            form.get("refresh_token", ""), form.get("token", ""),
        ) if t]
        if tokens:
            def knows(st: TwinState) -> bool:
                with st.lock:
                    return any(t in st.access_tokens or t in st.refresh_tokens for t in tokens)

            narrow(knows)
        if auth.startswith("Basic "):
            narrow(lambda st: st.provider.mode == "api_key")
        elif auth.startswith("Bearer "):
            narrow(lambda st: st.provider.mode != "api_key")
        if len(cands) == 1:
            return cands[0], []
        return self._fallback(cands), [st.provider.id for st in cands]


class DualStackServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address) -> None:  # noqa: ANN001
        return  # aborted TLS handshakes and resets are normal with browsers


class TwinHandler(http.server.BaseHTTPRequestHandler):
    registry: TwinRegistry
    state: TwinState   # the request's connector, set by _route
    listener: str = "server"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    # Recording ------------------------------------------------------------
    def _begin(self, body: bytes) -> Exchange:
        parsed = urllib.parse.urlsplit(self.path)
        headers = {
            k: "<redacted>" if k.lower() in REDACT_HEADERS else v for k, v in self.headers.items()
        }
        ex = self.registry.log.new(
            listener=self.listener,
            method=self.command,
            host=(self.headers.get("Host") or "").split(":")[0].lower(),
            path=parsed.path,
            query=dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)),
            req_headers=headers,
            req_body=body.decode("utf-8", "replace")[:20000],
        )
        ex._t0 = time.monotonic()  # type: ignore[attr-defined]
        # req_body is cut to 20 000 characters for the log; requests are parsed from the whole body.
        ex._raw = body.decode("utf-8", "replace")  # type: ignore[attr-defined]
        self.state, ex.candidates = self.registry.route(
            self.listener, ex.method, ex.host, ex.path, ex.query, self.headers, ex._raw,
        )
        ex.provider = self.state.provider.id
        return ex

    def _send(
        self, ex: Exchange, status: int, body: str, ctype: str,
        headers: dict[str, str] | None = None, ok: bool | None = None, reason: str = "",
    ) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        hdrs = {"Content-Type": ctype, "Content-Length": str(len(raw)), "Cache-Control": "no-store"}
        hdrs.update(headers or {})
        ex.status = status
        ex.resp_headers = hdrs
        if ctype.startswith("application/json"):
            ex.resp_body = body[:20000]
        else:
            ex.resp_body = f"<html, {len(raw)} bytes>"
        ex.ok = (200 <= status < 400) if ok is None else ok
        ex.reason = reason
        ex.duration_ms = int((time.monotonic() - ex._t0) * 1000)  # type: ignore[attr-defined]
        ex.__dict__.pop("_raw", None)   # the full body is not kept in Activity
        # Logged before the response goes out: once a client has its answer, Activity has it too.
        self.state.record(ex)
        for k, v in hdrs.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def _json(
        self, ex: Exchange, status: int, data: Any, headers: dict[str, str] | None = None,
        **kw: Any,
    ) -> None:
        self._send(ex, status, json.dumps(data, indent=2), "application/json", headers, **kw)

    def _html(self, ex: Exchange, status: int, body: str, **kw: Any) -> None:
        self._send(ex, status, body, "text/html; charset=utf-8", **kw)

    def _redirect(self, ex: Exchange, location: str, **kw: Any) -> None:
        self._send(ex, 302, "", "text/plain", {"Location": location}, **kw)

    def _read_body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n > 0 else b""

    # Routing --------------------------------------------------------------
    def do_GET(self) -> None:
        self._dispatch(b"")

    def do_POST(self) -> None:
        self._dispatch(self._read_body())

    def do_DELETE(self) -> None:
        ex = self._begin(self._read_body())
        ex.kind = "mcp"
        ex.detail = {"rpc": "session close"}
        self._send(ex, 200, "", "text/plain")

    def _dispatch(self, body: bytes) -> None:
        ex = self._begin(body)
        p = self.state.provider
        if ex.host not in p.all_hosts:
            where = f"{p.id}.yaml" if len(self.registry.states) == 1 else "any connector"
            self._json(ex, 421, {"error": "misdirected_request"}, ok=False,
                       reason=f"{ex.host} is not a host of {where}")
            return
        allowed = p.browser_hosts if self.listener == "browser" else p.server_hosts
        if ex.host not in allowed:
            self._json(ex, 421, {"error": "misdirected_request"}, ok=False,
                       reason=f"{ex.host} is not listed under hosts.{self.listener} in {p.id}.yaml")
            return
        is_discovery = self.command == "GET" and ex.path.startswith("/.well-known/oauth-")
        if p.mode == "dynamic" and is_discovery:
            return self._metadata(ex)
        for name, ep in p.endpoints.items():
            params = ep.match(self.command, ex.path, ex.host)
            if params is None:
                continue
            tenant = params.get("tenant")
            if tenant is not None and tenant != p.tenant:
                ex.kind = name
                self._json(ex, 404, {"error": "unknown_tenant"}, ok=False,
                           reason=f"Tenant '{tenant}' does not exist; the Twin knows '{p.tenant}'")
                return
            if name == "authorize":
                return self._authorize(ex)
            if name == "token":
                return self._token(ex)
            if name == "revoke":
                return self._revoke(ex)
            if name == "register" and p.mode == "dynamic":
                return self._register(ex)
            if name == "mcp":
                return self._mcp(ex)
        self._json(ex, 404, {"error": "not_found", "path": ex.path}, ok=False,
                   reason=f"No endpoint in {p.id}.yaml matches {self.command} {ex.path}")

    # Discovery and registration (DCR) -------------------------------------
    def _metadata(self, ex: Exchange) -> None:
        """RFC 9728 protected-resource and RFC 8414 server metadata, at the path-aware well-known
        URLs."""
        p = self.state.provider
        ex.kind = "discovery"
        res = urllib.parse.urlsplit(p.resource)
        iss = urllib.parse.urlsplit(p.issuer)
        prm = "/.well-known/oauth-protected-resource" + res.path.rstrip("/")
        asm = "/.well-known/oauth-authorization-server" + iss.path.rstrip("/")
        if ex.path.startswith("/.well-known/oauth-protected-resource"):
            ex.detail = {"what": "protected-resource metadata"}
            if not p.protected_resource:
                self._json(
                    ex, 404, {"error": "not_found"}, ok=True,
                    reason=(
                        "No protected-resource metadata, like the real server; "
                        "the broker uses the resource origin as issuer"
                    ),
                )
                return
            if ex.host != res.hostname or ex.path != prm:
                self._json(ex, 404, {"error": "not_found"}, ok=False,
                           reason=f"Protected-resource metadata is at https://{res.hostname}{prm}")
                return
            self._json(ex, 200, {
                "resource": p.resource,
                "authorization_servers": [p.issuer],
                "bearer_methods_supported": ["header"],
            })
            return
        ex.detail = {"what": "authorization server metadata"}
        # asm itself starts with /.well-known/oauth-authorization-server.
        if ex.host != iss.hostname or ex.path != asm:
            self._json(ex, 404, {"error": "not_found"}, ok=False,
                       reason=f"Authorization server metadata is at https://{iss.hostname}{asm}")
            return
        meta = {
            "issuer": p.issuer,
            "authorization_endpoint": p.url("authorize"),
            "token_endpoint": p.url("token"),
            "registration_endpoint": p.url("register"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": p.auth_methods,
        }
        if "revoke" in p.endpoints:
            meta["revocation_endpoint"] = p.url("revoke")
        self._json(ex, 200, meta)

    def _register(self, ex: Exchange) -> None:
        """RFC 7591 dynamic client registration."""
        st, p = self.state, self.state.provider
        ex.kind = "register"
        try:
            meta = json.loads(ex._raw or "{}")
        except json.JSONDecodeError:
            meta = None
        if not isinstance(meta, dict):
            self._json(
                ex, 400, {"error": "invalid_client_metadata"}, ok=False,
                reason="Body is not a JSON object",
            )
            return
        asked = str(meta.get("token_endpoint_auth_method") or "client_secret_basic")
        redirects = meta.get("redirect_uris")
        ex.detail = {"asked": asked, "client_name": str(meta.get("client_name", ""))}
        why = ""
        redirects_ok = (
            isinstance(redirects, list)
            and bool(redirects)
            and all(isinstance(r, str) and r for r in redirects)
        )
        if not redirects_ok:
            why = "redirect_uris must be a non-empty list"
        elif asked not in p.auth_methods:
            supported = ", ".join(p.auth_methods)
            why = (
                f"token_endpoint_auth_method '{asked}' is not supported; "
                f"the server takes {supported}"
            )
        elif "authorization_code" not in (meta.get("grant_types") or ["authorization_code"]):
            why = "grant_types must include authorization_code"
        if why:
            error = {"error": "invalid_client_metadata", "error_description": why}
            self._json(ex, 400, error, ok=False, reason=why)
            return
        method = p.registers_as or asked
        cid = f"{p.token_prefix}-dcr-{secrets.token_hex(6)}"
        rec: dict[str, Any] = {
            "auth": method,
            "redirect_uris": list(redirects),
            "created": time.time(),
            "secret": "",
        }
        body: dict[str, Any] = {
            "client_id": cid,
            "client_id_issued_at": int(time.time()),
            "client_name": meta.get("client_name", ""),
            "redirect_uris": redirects,
            "grant_types": meta.get("grant_types") or ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": method,
        }
        if method != "none":
            rec["secret"] = f"{p.token_prefix}-secret-{secrets.token_hex(6)}"
            body.update(client_secret=rec["secret"], client_secret_expires_at=0)
        with st.lock:
            st.clients[cid] = rec
        ex.detail.update(client_id=cid, registered=method)
        self._json(ex, 201, body)

    # OAuth ----------------------------------------------------------------
    def _authorize(self, ex: Exchange) -> None:
        p, q = self.state.provider, ex.query
        ex.kind = "authorize"
        decision = q.get("decision", "")
        ex.detail = {
            "decision": {"approve": "allowed", "deny": "denied"}.get(decision, ""),
            "client_id": q.get("client_id", ""),
            "redirect_uri": q.get("redirect_uri", ""),
        }
        problems = []
        if q.get("response_type", "code") != "code":
            problems.append(f"response_type is '{q.get('response_type')}', expected 'code'")
        if p.mode == "dynamic":
            c = self.state.clients.get(q.get("client_id", ""))
            if c is None:
                problems.append(
                    f"client_id '{q.get('client_id', '')}' is not registered here; "
                    "Samsara must register it first (DCR)"
                )
            elif q.get("redirect_uri") and q["redirect_uri"] not in c["redirect_uris"]:
                problems.append(
                    f"redirect_uri '{q['redirect_uri']}' is not one this client registered"
                )
            if q.get("resource") and q["resource"] != p.resource:
                problems.append(
                    f"resource '{q['resource']}' is not this server; expected '{p.resource}'"
                )
        elif q.get("client_id") != p.client_id:
            problems.append(
                f"client_id '{q.get('client_id', '')}' is not registered; expected '{p.client_id}'"
            )
        if not q.get("redirect_uri"):
            problems.append("redirect_uri is missing")
        if p.oauth["require_state"] and not q.get("state"):
            problems.append("state is missing")
        has_pkce = q.get("code_challenge_method") == "S256" and q.get("code_challenge")
        if p.oauth["pkce"] == "S256" and not has_pkce:
            problems.append("PKCE S256 code_challenge is missing")
        if problems:
            page = consent_page(p, q, error=problems, host=ex.host)
            self._html(ex, 400, page, ok=False, reason="; ".join(problems))
            return
        redirect = q["redirect_uri"]
        state = q.get("state", "")
        if not decision:
            # First hit comes from Agent Studio, so its Referer carries the port Chrome uses.
            referer = self.headers.get("Referer", "")
            port = loopback_port(referer) or self.state.callback_port_fallback
        elif q.get(PORT_PARAM, "").isdigit():
            port = int(q[PORT_PARAM])
        else:
            port = self.state.callback_port_fallback
        target, fix = fix_callback(redirect, port)
        if fix:
            ex.detail["callback_fix"] = fix
            ex.detail["sent_to"] = target
        sep = "&" if "?" in target else "?"
        quoted_state = urllib.parse.quote(state)
        if decision == "deny":
            self._redirect(
                ex, f"{target}{sep}error=access_denied&state={quoted_state}",
                reason="You denied access on the consent page",
            )
            return
        if decision == "approve":
            code = "code_" + secrets.token_urlsafe(18)
            with self.state.lock:
                self.state.auth_codes[code] = {
                    "redirect_uri": redirect,
                    "challenge": q.get("code_challenge", ""),
                    "scope": q.get("scope", ""),
                    "expires_at": time.time() + 300,
                    "client_id": q.get("client_id", ""),
                    "resource": q.get("resource", ""),
                }
            quoted_code = urllib.parse.quote(code)
            self._redirect(ex, f"{target}{sep}code={quoted_code}&state={quoted_state}")
            return
        consent_query = {**q, PORT_PARAM: str(port)} if port else q
        self._html(ex, 200, consent_page(
            p, consent_query, sends_to=target if fix else "", host=ex.host,
        ))

    def _client_ok(self, ex: Exchange, form: dict[str, str]) -> bool:
        st, p = self.state, self.state.provider
        cid = form.get("client_id", "")
        if not cid and self.headers.get("Authorization", "").startswith("Basic "):
            ex.reason = "Client sent HTTP Basic auth; this provider expects client_secret_post"
            self._json(ex, 401, {"error": "invalid_client"}, ok=False, reason=ex.reason)
            return False
        if p.mode == "dynamic":
            c = st.clients.get(cid)
            if c is None:
                self._json(
                    ex, 401, {"error": "invalid_client"}, ok=False,
                    reason=f"client_id '{cid}' is not registered (or its registration was deleted)",
                )
                return False
            if c["auth"] != "none":
                got = form.get("client_secret", "")
                if got != c["secret"]:
                    if got and got == c.get("previous_secret"):
                        why = "the old secret, rotated earlier"
                    else:
                        why = "not the current secret"
                    self._json(
                        ex, 401, CLIENT_AUTH_FAILED, ok=False,
                        reason=f"Secret {tail(got)} is {why} ({tail(c['secret'])})",
                    )
                    return False
            return True
        if cid != p.client_id:
            self._json(ex, 401, {"error": "invalid_client"}, ok=False,
                       reason=f"client_id '{cid}' is not registered; expected '{p.client_id}'")
            return False
        if p.client_auth == "client_secret_post":
            got = form.get("client_secret", "")
            if got != st.client_secret:
                if got and got == st.previous_secret:
                    why = "the old secret, rotated earlier"
                else:
                    why = "not the current secret"
                self._json(
                    ex, 401, CLIENT_AUTH_FAILED, ok=False,
                    reason=f"Secret {tail(got)} is {why} ({tail(st.client_secret)})",
                )
                return False
        return True

    def _token(self, ex: Exchange) -> None:
        st = self.state
        form = dict(urllib.parse.parse_qsl(ex._raw, keep_blank_values=True))
        grant = form.get("grant_type", "")
        ex.kind = "refresh" if grant == "refresh_token" else "token"
        ex.detail = {"grant_type": grant}
        fault = st.take_fault(ex.kind)
        if fault:
            ex.injected = True
            status, data, headers = fault
            self._json(ex, status, data, headers, ok=False, reason="Injected by OwlAuth Twin")
            return
        if not self._client_ok(ex, form):
            return
        if grant == "authorization_code":
            with st.lock:
                rec = st.auth_codes.pop(form.get("code", ""), None)
            redirect_uri = form.get("redirect_uri", "")
            verifier = form.get("code_verifier", "")
            resource = form.get("resource")
            pkce_required = st.provider.oauth["pkce"] == "S256"
            dynamic = st.provider.mode == "dynamic"
            why = ""
            if rec is None:
                why = "authorization code is unknown or already used"
            elif rec["expires_at"] < time.time():
                why = "authorization code expired"
            elif rec["redirect_uri"] != redirect_uri:
                why = (
                    "redirect_uri differs from authorize "
                    f"({redirect_uri} vs {rec['redirect_uri']})"
                )
            elif pkce_required and pkce_s256(verifier) != rec["challenge"]:
                why = "PKCE code_verifier does not match the code_challenge"
            elif dynamic and rec.get("client_id") and rec["client_id"] != form.get("client_id"):
                why = "authorization code was issued to another client"
            elif rec.get("resource") and resource and resource != rec["resource"]:
                why = f"resource differs from authorize ({resource} vs {rec['resource']})"
            if why:
                error = {"error": "invalid_grant", "error_description": why}
                self._json(ex, 400, error, ok=False, reason=why)
                return
            granted_resource = rec.get("resource") or form.get("resource", "")
            body = st.issue_tokens(
                rec["scope"], client_id=form.get("client_id", ""), resource=granted_resource
            )
            if granted_resource:
                ex.detail["resource"] = granted_resource
            st.last_code_exchange = time.time()
            ex.detail["expires_in"] = body["expires_in"]
            self._json(ex, 200, body)
            return
        if grant == "refresh_token":
            rt = form.get("refresh_token", "")
            with st.lock:
                rec = st.refresh_tokens.get(rt)
            if rec is None or rec["revoked"]:
                if rec is None:
                    why = "refresh token is unknown"
                elif rec.get("replaced_by"):
                    why = "refresh token was replaced by a newer one"
                else:
                    why = "refresh token is revoked"
                error = {"error": "invalid_grant", "error_description": why}
                self._json(ex, 400, error, ok=False, reason=why)
                return
            if rec.get("client_id") and rec["client_id"] != form.get("client_id"):
                why = "refresh token was issued to another client"
                error = {"error": "invalid_grant", "error_description": why}
                self._json(ex, 400, error, ok=False, reason=why)
                return
            body = st.issue_tokens(
                rec["scope"], refresh_token=rt,
                client_id=rec.get("client_id", ""), resource=rec.get("resource", ""),
            )
            ex.detail["rotated"] = "refresh_token" in body
            self._json(ex, 200, body)
            return
        self._json(
            ex, 400, {"error": "unsupported_grant_type"}, ok=False,
            reason=f"grant_type '{grant}' is not supported",
        )

    def _revoke(self, ex: Exchange) -> None:
        ex.kind = "revoke"
        form = dict(urllib.parse.parse_qsl(ex._raw, keep_blank_values=True))
        tok = form.get("token", "")
        with self.state.lock:
            if tok in self.state.refresh_tokens:
                self.state.refresh_tokens[tok]["revoked"] = True
            self.state.access_tokens.pop(tok, None)
        self._json(ex, 200, {})

    # MCP ------------------------------------------------------------------
    def _mcp(self, ex: Exchange) -> None:
        st, p = self.state, self.state.provider
        ex.kind = "mcp"
        try:
            msg = json.loads(ex._raw or "{}")
        except json.JSONDecodeError:
            self._json(ex, 400, {"error": "invalid_json"}, ok=False, reason="Body is not JSON")
            return
        method = msg.get("method", "") if isinstance(msg, dict) else ""
        params = (msg.get("params") or {}) if isinstance(msg, dict) else {}
        ex.detail = {"rpc": method}
        if method == "tools/call":
            ex.detail["tool"] = params.get("name", "")
        fault = st.take_fault("mcp")
        if fault:
            ex.injected = True
            status, data, headers = fault
            self._json(ex, status, data, headers, ok=False, reason="Injected by OwlAuth Twin")
            return
        auth = self.headers.get("Authorization", "")
        if p.mode == "api_key":
            if not self._api_key_ok(ex, auth):
                return
        else:
            if not self._bearer_ok(ex, auth):
                return
        self._mcp_answer(ex, msg, method, params)

    def _api_key_ok(self, ex: Exchange, auth: str) -> bool:
        st, p = self.state, self.state.provider
        k = p.api_key
        previous = st.previous_api_secret
        if k["scheme"] == "basic":
            want = basic_auth(k["username"], st.api_secret)
            old = basic_auth(k["username"], previous) if previous else None
        else:
            want = f"Bearer {st.api_secret}"
            old = f"Bearer {previous}" if previous else None
        if auth == want:
            st.api_ok_at = st.api_ok_at or time.time()
            return True
        if not auth:
            why = "No Authorization header sent"
        elif old and auth == old:
            why = "The API token was rotated; the gateway still sends the old one"
        elif k["scheme"] == "basic" and auth.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth[6:]).decode("utf-8", "replace")
                user, _, secret = decoded.partition(":")
            except ValueError:
                user = ""
                secret = ""
            if user != k["username"]:
                why = f"Username '{user}' is not '{k['username']}'"
            else:
                why = f"API token {tail(secret)} is not the current one ({tail(st.api_secret)})"
        else:
            why = f"Expected {k['scheme'].title()} auth, got '{auth.split(' ')[0]}'"
        challenge = {"WWW-Authenticate": f'{k["scheme"].title()} realm="{p.id}"'}
        self._json(ex, 401, {"error": "unauthorized"}, challenge, ok=False, reason=why)
        return False

    def _bearer_ok(self, ex: Exchange, auth: str) -> bool:
        st, p = self.state, self.state.provider
        tok = auth.removeprefix("Bearer ") if auth.startswith("Bearer ") else ""
        with st.lock:
            rec = st.access_tokens.get(tok)
        challenge = 'Bearer error="invalid_token"'
        if p.mode == "dynamic" and p.protected_resource:
            res = urllib.parse.urlsplit(p.resource)
            metadata_url = f"https://{res.hostname}/.well-known/oauth-protected-resource{res.path}"
            challenge += f', resource_metadata="{metadata_url}"'
        headers = {"WWW-Authenticate": challenge}
        if not tok or rec is None or rec["expires_at"] <= time.time():
            if not tok:
                why = "No Bearer token sent"
            elif rec is None:
                why = f"Token {tail(tok)} is unknown or revoked"
            else:
                why = f"Token {tail(tok)} expired {int(time.time() - rec['expires_at'])} s earlier"
            self._json(ex, 401, {"error": "invalid_token"}, headers, ok=False, reason=why)
            return False
        if p.mode == "dynamic" and rec.get("resource") and rec["resource"] != p.resource:
            self._json(
                ex, 401, {"error": "invalid_token"}, headers, ok=False,
                reason=f"Token {tail(tok)} is for resource {rec['resource']}, not {p.resource}",
            )
            return False
        return True

    def _mcp_answer(self, ex: Exchange, msg: dict, method: str, params: dict) -> None:
        p = self.state.provider
        mid = msg.get("id")
        if method == "initialize":
            result = {
                "protocolVersion": params.get("protocolVersion", "2025-11-25"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": p.mcp_server_name, "version": "1.0.0"},
            }
            session = {"Mcp-Session-Id": "sess-" + secrets.token_hex(6)}
            self._json(ex, 200, {"jsonrpc": "2.0", "id": mid, "result": result}, session)
            return
        if method.startswith("notifications/"):
            self._send(ex, 202, "", "text/plain")
            return
        if method == "tools/list":
            tools = [
                {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "inputSchema": t.get("input_schema") or {"type": "object"},
                }
                for t in p.tools
            ]
            self._json(ex, 200, {"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}})
            return
        if method == "tools/call":
            tool = next((t for t in p.tools if t["name"] == params.get("name")), None)
            if tool is None:
                name = params.get("name")
                content = [{"type": "text", "text": f"Unknown tool {name}"}]
                result = {"isError": True, "content": content}
                self._json(
                    ex, 200, {"jsonrpc": "2.0", "id": mid, "result": result},
                    ok=False, reason=f"Tool '{name}' is not in {p.id}.yaml",
                )
                return
            result = fill_values(p, tool.get("result") or {})
            result = {"query": params.get("arguments") or {}, **result}
            content = [{"type": "text", "text": json.dumps(result)}]
            self._json(ex, 200, {"jsonrpc": "2.0", "id": mid, "result": {"content": content}})
            return
        error = {"code": -32601, "message": f"Method {method} not found"}
        self._json(
            ex, 200, {"jsonrpc": "2.0", "id": mid, "error": error},
            ok=False, reason=f"MCP method {method} is not implemented by the Twin",
        )


def consent_page(
    p: Provider, q: dict[str, str], error: list[str] | None = None, armed: str | None = None,
    sends_to: str = "", host: str = "",
) -> str:
    """The sign-in page Chrome sees (templates/consent.html), or the list of reasons the request
    is invalid. host is the vendor host Chrome asked for (the Twin answers in its place)."""
    vendor = " ".join(p.name.replace("connector", "").split())
    scope = q.get("scope", "")
    scopes = [
        {"full": s, "short": s.rstrip("/").rsplit("/", 1)[-1] or s} for s in scope.split()
    ]
    redirect = q.get("redirect_uri", "")
    hue = int(hashlib.sha256(p.id.encode()).hexdigest()[:4], 16) % 360
    return render_template(
        "consent.html",
        name=p.name, vendor=vendor, monogram=(vendor[:1] or "?").upper(), hue=hue, logo=p.logo,
        host=host or (p.browser_hosts[0] if p.browser_hosts else ""),
        kind=p.kind_label, tenant="" if p.tenant == "default" else p.tenant,
        title=p.consent_title, file=p.path.name,
        armed=armed or "", errors=error or [],
        client_id=q.get("client_id", ""), redirect_uri=redirect,
        returns_to=urllib.parse.urlsplit(redirect).netloc or redirect,
        sends_to=sends_to.split("?")[0], scope=scope or "(default)", scopes=scopes,
        state=q.get("state", ""),
        pkce=q.get("code_challenge_method", "") if q.get("code_challenge") else "",
        approve=urllib.parse.urlencode({**q, "decision": "approve"}),
        deny=urllib.parse.urlencode({**q, "decision": "deny"}),
    )


def start_tls_server(
    twin: TwinState | TwinRegistry, host: str, port: int, cert: str, key: str, listener: str,
) -> DualStackServer:
    registry = twin if isinstance(twin, TwinRegistry) else TwinRegistry.of(twin)
    attrs = {"registry": registry, "listener": listener}
    handler = type(f"TwinHandler_{listener}", (TwinHandler,), attrs)
    srv = DualStackServer((host, port), handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, name=f"twin-{listener}", daemon=True).start()
    return srv


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
