"""Provider YAML loading and validation (owltwin lint)."""

from __future__ import annotations

import hashlib
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Hosts the Twin must never answer for: company sign-in and shared identity
# providers. Matching is on the host itself and every parent domain.
BLOCKED_SUFFIXES = (
    "okta.com",
    "oktapreview.com",
    "okta-emea.com",
    "accounts.google.com",
    "google.com",
    "googleapis.com",
    "login.microsoftonline.com",
    "login.windows.net",
    "login.live.com",
    "microsoft.com",
    "zscaler.net",
    "zscalertwo.net",
    "zscloud.net",
    "samsara.com",
    "samsara.net",
    "samsaradev.io",
)

# Google and Microsoft sign-in and API hosts. Blocked like the rest unless a provider lists the
# host under `idp_hosts:`. Then the devbox side answers for it all session, and Chrome only while
# you switch "Intercept Google/Microsoft sign-in" on in the panel. Okta, Zscaler and Samsara stay
# blocked.
IDP_SUFFIXES = (
    "accounts.google.com",
    "google.com",
    "googleapis.com",
    "login.microsoftonline.com",
    "login.windows.net",
    "login.live.com",
    "microsoft.com",
)

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
ENDPOINT_RE = re.compile(r"^(GET|POST) (/\S*)$")
# Endpoints each kind of provider must have:
#   oauth + static client (Workday, Gmail, Entra): a client Samsara already knows.
#   oauth + dynamic client (monday, Ramp, ...): the broker discovers the server and registers
#     itself (DCR).
#   api_key (Atlassian): no OAuth at all, the gateway sends the API token on every MCP call.
REQUIRED_ENDPOINTS = {
    "static": ("authorize", "token", "mcp"),
    "dynamic": ("authorize", "token", "register", "mcp"),
    "api_key": ("mcp",),
}
OAUTH_ENDPOINTS = ("authorize", "token", "register", "revoke")


class LintError(Exception):
    def __init__(self, path: Path, problems: list[str]):
        super().__init__(f"{path.name}: " + "; ".join(problems))
        self.path = path
        self.problems = problems


def blocked_reason(host: str, idp: frozenset = frozenset()) -> str | None:
    for suffix in BLOCKED_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            if host in idp and suffix in IDP_SUFFIXES:
                return None
            hint = " (list it under idp_hosts to allow it)" if suffix in IDP_SUFFIXES else ""
            return (
                f"{host} is a shared or company host ({suffix}); "
                f"the Twin never answers for it{hint}"
            )
    return None


@dataclass
class Endpoint:
    method: str
    template: str
    regex: re.Pattern[str]
    host: str = ""        # set for DCR providers: the endpoint answers on this host only

    def match(self, method: str, path: str, host: str = "") -> dict[str, str] | None:
        if method != self.method or (self.host and host and host != self.host):
            return None
        m = self.regex.fullmatch(path)
        return m.groupdict() if m else None

    def render(self, **values: str) -> str:
        out = self.template
        for k, v in values.items():
            out = out.replace("{" + k + "}", v)
        return out


def _compile_endpoint(spec: str) -> Endpoint:
    m = ENDPOINT_RE.fullmatch(spec.strip())
    if not m:
        raise ValueError(f"endpoint must look like 'GET /path/{{tenant}}', got {spec!r}")
    method, template = m.group(1), m.group(2)
    pattern = ""
    for part in re.split(r"(\{[a-z_]+\})", template):
        if part.startswith("{") and part.endswith("}"):
            pattern += f"(?P<{part[1:-1]}>[^/]+)"
        else:
            pattern += re.escape(part)
    return Endpoint(method, template, re.compile(pattern))


@dataclass
class Provider:
    path: Path
    raw: dict[str, Any]
    digest: str
    id: str
    name: str
    browser_hosts: list[str]
    server_hosts: list[str]
    tenant: str
    client_id: str
    client_secret: str
    client_auth: str
    endpoints: dict[str, Endpoint]
    oauth: dict[str, Any]
    tools: list[dict[str, Any]]
    mcp_server_name: str
    consent_title: str
    test_prompt: str = ""
    # Google/Microsoft hosts; Chrome reaches them only while switched on.
    idp_hosts: list[str] = field(default_factory=list)
    agent_studio: list[dict[str, str]] = field(default_factory=list)
    mode: str = "static"              # static | dynamic | api_key (see REQUIRED_ENDPOINTS)
    # DCR: what the broker discovers. resource is the catalog's endpoint URL; issuer the
    # authorization server.
    resource: str = ""
    issuer: str = ""
    # Serves RFC 9728 metadata; without it the broker uses the resource origin.
    protected_resource: bool = True
    auth_methods: list[str] = field(default_factory=list)   # token_endpoint_auth_methods_supported
    # The method the server really registers, when it differs from the request.
    registers_as: str = ""
    # api_key: the credential the gateway must send.
    api_key: dict[str, str] = field(default_factory=dict)
    logo: str = ""                    # https URL of the vendor's logo, for the consent page

    @property
    def all_hosts(self) -> list[str]:
        return sorted(set(self.browser_hosts) | set(self.server_hosts))

    @property
    def token_prefix(self) -> str:
        return (self.client_id.split("-")[0] if self.client_id else self.id.split("-")[0])[:16]

    @property
    def kind_label(self) -> str:
        labels = {
            "static": "OAuth, fixed client",
            "dynamic": "OAuth, DCR",
            "api_key": "API token",
        }
        return labels[self.mode]

    def url(self, name: str) -> str:
        """Absolute URL of an OAuth endpoint, as the discovery metadata names it."""
        ep = self.endpoints[name]
        host = ep.host or urllib.parse.urlsplit(self.issuer).hostname
        return f"https://{host}{ep.render(tenant=self.tenant)}"

    def fill(self, text: str) -> str:
        return (
            text.replace("{tenant}", self.tenant)
            .replace("{TENANT}", self.tenant.upper())
            .replace("{client.id}", self.client_id)
            .replace("{client.secret}", self.client_secret)
            .replace("{api_key.username}", self.api_key.get("username", ""))
            .replace("{api_key.secret}", self.api_key.get("secret", ""))
        )


def _hosts(value: Any, where: str, problems: list[str], idp: frozenset = frozenset()) -> list[str]:
    if not isinstance(value, list) or not value:
        problems.append(f"{where} must be a non-empty list of host names")
        return []
    out = []
    for h in value:
        h = str(h).strip().lower()
        if "*" in h:
            problems.append(f"{where}: {h} uses a wildcard; list each host")
            continue
        if not HOST_RE.match(h):
            problems.append(f"{where}: {h} is not a valid host name")
            continue
        reason = blocked_reason(h, idp)
        if reason:
            problems.append(f"{where}: {reason}")
            continue
        out.append(h)
    return out


def load_provider(path: Path) -> Provider:
    text = path.read_text()
    digest = hashlib.sha256(text.encode()).hexdigest()[:4]
    problems: list[str] = []
    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        raise LintError(path, [f"YAML syntax: {e}"]) from e
    if not isinstance(raw, dict):
        raise LintError(path, ["top level must be a mapping"])
    if raw.get("schema") != 1:
        problems.append("schema: must be 1")
    pid = str(raw.get("id") or "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", pid):
        problems.append("id: lower-case letters, digits and '-'")
    hosts = raw.get("hosts") or {}
    idp = frozenset(str(h).strip().lower() for h in (raw.get("idp_hosts") or []))
    # An API-token connector never sends Chrome to the vendor, so it may leave hosts.browser out.
    if raw.get("api_key") and not hosts.get("browser"):
        browser: list[str] = []
    else:
        browser = _hosts(hosts.get("browser"), "hosts.browser", problems, idp)
    server = _hosts(hosts.get("server"), "hosts.server", problems, idp)
    for h in sorted(idp - set(browser) - set(server)):
        problems.append(f"idp_hosts: {h} is not under hosts.browser or hosts.server")
    client = raw.get("client") or {}
    api_key = raw.get("api_key")
    if api_key:
        mode = "api_key"
    elif client.get("registration") == "dynamic":
        mode = "dynamic"
    else:
        mode = "static"
    if client.get("registration", "static") not in ("static", "dynamic"):
        problems.append("client.registration: static or dynamic")
    auth = client.get("auth", "client_secret_post")
    if mode == "static":
        if not client.get("id"):
            problems.append("client.id is required")
        if auth not in ("client_secret_post", "none"):
            problems.append(
                "client.auth: client_secret_post or none (the broker supports only these)"
            )
        if auth == "client_secret_post" and not client.get("secret"):
            problems.append("client.secret is required with client_secret_post")
    methods = [str(m) for m in (client.get("auth_methods") or ["none", "client_secret_post"])]
    registers_as = str(client.get("registers_as") or "")
    if mode == "dynamic":
        if client.get("id") or client.get("secret"):
            problems.append(
                "client.id and client.secret come from registration with "
                "registration: dynamic; remove them"
            )
        for m in methods + ([registers_as] if registers_as else []):
            if m not in ("none", "client_secret_post", "client_secret_basic"):
                problems.append(f"client: auth method {m!r} is not one the Twin knows")
    if mode == "api_key":
        scheme = api_key.get("scheme", "basic") if isinstance(api_key, dict) else None
        if scheme not in ("basic", "bearer") or not api_key.get("secret"):
            problems.append("api_key: needs scheme (basic or bearer) and secret")
        elif scheme == "basic" and not api_key.get("username"):
            problems.append("api_key.username is required with scheme basic")
    disc = raw.get("discovery") or {}
    resource = str(disc.get("resource") or "")
    issuer = str(disc.get("issuer") or "")
    protected = bool(disc.get("protected_resource", True))
    res_host = urllib.parse.urlsplit(resource).hostname or ""
    iss_host = urllib.parse.urlsplit(issuer).hostname or ""
    if mode == "dynamic":
        if not resource.startswith("https://") or not res_host:
            problems.append("discovery.resource: the catalog entry's https endpoint URL")
        if not protected:
            # Without RFC 9728 metadata the broker takes the resource origin as the issuer.
            issuer = f"https://{res_host}"
            iss_host = res_host
        if not issuer.startswith("https://") or not iss_host:
            problems.append("discovery.issuer: the authorization server's https URL")
        discovery_hosts = (
            (res_host, "resource", "server", server),
            (iss_host, "issuer", "server", server),
            (iss_host, "issuer", "browser", browser),
        )
        for h, what, side_name, side in discovery_hosts:
            if h and h not in side:
                problems.append(f"discovery.{what}: {h} must be under hosts.{side_name}")
    endpoints: dict[str, Endpoint] = {}
    for name, spec in (raw.get("endpoints") or {}).items():
        try:
            endpoints[name] = _compile_endpoint(str(spec))
        except ValueError as e:
            problems.append(f"endpoints.{name}: {e}")
            continue
        if mode == "dynamic":
            if name == "mcp":
                endpoints[name].host = res_host
            elif name in OAUTH_ENDPOINTS:
                endpoints[name].host = iss_host
            else:
                endpoints[name].host = ""
    mcp_path = urllib.parse.urlsplit(resource).path
    if (
        mode == "dynamic" and "mcp" in endpoints and resource
        and endpoints["mcp"].template != mcp_path
    ):
        problems.append(f"endpoints.mcp: must be the path of discovery.resource ({mcp_path})")
    for name in REQUIRED_ENDPOINTS[mode]:
        if name not in endpoints and f"endpoints.{name}" not in " ".join(problems):
            problems.append(f"endpoints.{name} is required")
    oauth = {
        "pkce": "S256",
        "require_state": True,
        "access_token_ttl": 3600,
        "expires_in_as_string": False,
        "rotate_refresh_token": False,
        "revoke_tokens_on_secret_rotation": False,
        **(raw.get("oauth") or {}),
    }
    if oauth["pkce"] not in ("S256", "none"):
        problems.append("oauth.pkce: S256 or none")
    mcp = raw.get("mcp") or {}
    tools = mcp.get("tools") or []
    if not isinstance(tools, list) or not all(isinstance(t, dict) and t.get("name") for t in tools):
        problems.append("mcp.tools: list of tools, each with a name")
        tools = []
    # logo: the catalog entry's LogoUrl (entries.go), shown on the consent page. Optional.
    logo = str(raw.get("logo") or "").strip()
    if logo:
        lhost = urllib.parse.urlsplit(logo).hostname or ""
        if not logo.startswith("https://") or not lhost:
            problems.append("logo: an https:// URL")
        # Only an image: Google and Microsoft hosts are fine, company hosts are not.
        elif reason := blocked_reason(lhost, frozenset([lhost])):
            problems.append(f"logo: {reason}")
    if problems:
        raise LintError(path, problems)
    consent = raw.get("consent") or {}
    p = Provider(
        path=path,
        raw=raw,
        digest=digest,
        id=pid,
        name=str(raw.get("name") or pid),
        browser_hosts=browser,
        server_hosts=server,
        tenant=str(raw.get("tenant") or "default"),
        client_id=str(client.get("id") or ""),
        client_secret=str(client.get("secret") or ""),
        client_auth=auth,
        endpoints=endpoints,
        oauth=oauth,
        tools=tools,
        mcp_server_name=str(mcp.get("server_name") or f"{pid}-twin-mcp"),
        consent_title=str(consent.get("title") or f"Allow Samsara to access {pid}?"),
        logo=logo,
    )
    p.idp_hosts = sorted(idp & set(browser))
    p.mode = mode
    p.resource = resource
    p.issuer = issuer
    p.protected_resource = protected
    p.auth_methods = methods
    p.registers_as = registers_as
    if mode == "api_key":
        p.api_key = {
            "scheme": str(api_key.get("scheme", "basic")),
            "username": str(api_key.get("username") or ""),
            "secret": str(api_key["secret"]),
        }
        p.client_auth = "api_key"
    agent_studio = raw.get("agent_studio") or []
    p.agent_studio = [
        {"label": str(r.get("label")), "value": p.fill(str(r.get("value")))} for r in agent_studio
    ]
    p.consent_title = p.fill(p.consent_title)
    tool = tools[0]["name"] if tools else "a tool"
    test_prompt = raw.get("test_prompt")
    if not test_prompt:
        test_prompt = f"Use {p.name.split()[0]} ({tool}) to answer: what can you find?"
    p.test_prompt = p.fill(str(test_prompt))
    return p


@dataclass
class ProviderEntry:
    file: Path
    provider: Provider | None
    error: LintError | None


def scan(providers_dir: Path) -> list[ProviderEntry]:
    out = []
    for f in sorted(providers_dir.glob("*.yaml")):
        try:
            out.append(ProviderEntry(f, load_provider(f), None))
        except LintError as e:
            out.append(ProviderEntry(f, None, e))
    return out
