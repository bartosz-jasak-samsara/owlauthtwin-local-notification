"""OwlAuth Twin app: one session = one devbox + the Twin for every valid connector.

The Twin answers for all connectors at once (an agent may use two in one chat); the panel shows
one of them at a time, the one you switch to. A session is Full stack (OwlAuth Twin also sets up
and runs the projects) or Twin only (the Twin and the route to it; your env stays as it is).

A session has two phases. Setup runs the steps (Mac, Devbox, Projects) until
every one is done, then the session switches to Running by itself and stays
there; from then on the same checks keep running and show up in the health bar.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shlex
import socket
import subprocess
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import devbox_link, macproxy
from .config import LintError, Provider, ProviderEntry, load_provider, scan
from .devbox import Devbox, DevboxList
from .proxy import start_proxy
from .tls import ensure_certs
from .twin import TwinRegistry, TwinState, free_port, start_tls_server

ROOT = Path(__file__).resolve().parents[2]
APP_NAME = "OwlAuth Twin"

# The AWS profile and region the backend runs with on the devbox. Unset: the devbox's own defaults
# (its ~/.aws/config and the repo's .envrc).
AWS_PROFILE = os.environ.get("OWLTWIN_AWS_PROFILE", "").strip()
AWS_REGION = os.environ.get("OWLTWIN_AWS_REGION", "").strip()
# DD_DOGSTATSD_DISABLE_FORK_SUPPORT: datadogpy's after-fork hook logs at DEBUG in the child that
# becomes `docker run` for the code sandbox; if another thread held the logging lock at the fork,
# that child hangs before exec and the chat waits forever after session_load. The parent still
# sends metrics.
AGENTS_RUN = (
    "DD_DOGSTATSD_DISABLE_FORK_SUPPORT=1 "
    "direnv exec . make server AGENT=ml/claude_core PORT=8000"
)
AGENTS_CMD = f"cd ~/co/aiml-agents/agent-platform && {AGENTS_RUN}"
# The step `devbox provision` asks for after cloning aiml-agents; its last part (populate_envrc.py)
# writes the dev secrets, LITELLM_API_KEY among them, to .envrc.local. Backend's own setup.sh is
# not run: it asks questions and rewrites the AWS config, and a devbox gets it at first boot.
SETUP_RUN = "./bin/setup.sh"
IDP_MINUTES = 10  # Chrome's Google/Microsoft sign-in goes back to the real hosts after this
# Seconds after typing a command into a tmux pane before an idle pane counts as stopped.
START_GRACE = 10
# direnv exec loads the repo's .envrc (PATH with taskrunner-localdev) without relying on the shell
# hook; `env` after it makes these values win over anything .envrc sets.
BACKEND_SERVICES = (
    "ucvserver agentconnectorservice agentservice agentchatworker "
    "agentstudiogqlservice notificationeventingestionservice "
    "inboxnotificationworker"
)
# The profile backend's bin/setup.sh writes to .envrc.local for DevEco devboxes. Without that line
# .envrc's AWS_DEFAULT_PROFILE=readonly names no profile, the SDK finds no credentials and
# taskrunner stops with "unable to get caller identity", which reads like an expired AWS session.
FALLBACK_AWS_PROFILE = "devecosystemreadonly"
_BACKEND_ENV = (
    "SSL_CERT_FILE=$HOME/.owltwin/combined-ca.pem "
    + (f"AWS_REGION={shlex.quote(AWS_REGION)} AWS_DEFAULT_REGION={shlex.quote(AWS_REGION)} "
       if AWS_REGION else "")
    + "FC_USE_DEV_OVERRIDES=1 USE_VITE_DEVPROXY=false "
)
if AWS_PROFILE:
    BACKEND_CMD = (
        "cd ~/co/backend && direnv exec ~/co/backend env " + _BACKEND_ENV
        + f"AWS_PROFILE={shlex.quote(AWS_PROFILE)} AWS_DEFAULT_PROFILE={shlex.quote(AWS_PROFILE)} "
        + f"taskrunner-localdev {BACKEND_SERVICES}"
    )
else:
    # The repo's profile when ~/co/backend/.aws/config has it, else the DevEco one.
    _PICK = (
        'p=${AWS_PROFILE:-$AWS_DEFAULT_PROFILE}; '
        'if ! aws configure list-profiles 2>/dev/null | grep -qxF "$p"; then '
        'echo "AWS profile ${p:-(none)} is not in $AWS_CONFIG_FILE: '
        f'using {FALLBACK_AWS_PROFILE}"; '
        f'p={FALLBACK_AWS_PROFILE}; fi; '
        'exec env AWS_PROFILE="$p" AWS_DEFAULT_PROFILE="$p" ' + _BACKEND_ENV
        + f"taskrunner-localdev {BACKEND_SERVICES}"
    )
    BACKEND_CMD = "cd ~/co/backend && direnv exec ~/co/backend bash -c " + shlex.quote(_PICK)
# claude_core runs code in a sandbox; the e2b dev key is mocked locally, so use local Docker
# instead.
SANDBOX_CFG_CMD = (
    f'f={devbox_link.LOCAL_YAML}; if [ -e "$f" ]; then '
    'echo "$f exists: add agent_config.sandbox_client.provider: local_docker to it"; '
    "else printf 'agent_config:\\n  sandbox_client:\\n    provider: local_docker\\n' > \"$f\" "
    "&& echo written; fi"
)
SANDBOX_IMG_CMD = (
    "direnv exec ~/co/aiml-agents/agent-platform "
    "make -C ~/co/aiml-agents/agent-platform/sandbox-templates build-local-sandbox-images"
)


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def mac_port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def no_devbox() -> bool:
    return os.environ.get("OWLTWIN_NO_DEVBOX") == "1"


@dataclass
class Step:
    key: str
    group: str  # Mac | Devbox | Projects
    title: str
    state: str = "pending"  # pending | running | ok | fail | needs_you | skipped
    detail: str = ""
    took: str = ""
    command: str = ""  # shown with a copy button when the step needs you
    # A page to open instead (for example the AWS sign-in), shown as a button.
    link: str = ""
    link_label: str = ""
    # "agents" | "backend": a project you started yourself; the card offers Take over.
    takeover: str = ""


MODES = ("full", "twin_only")
FLAGS_OFF = "Off: OwlAuth Twin sets no flags. Your env decides what Agent Studio shows."


@dataclass
class FlagConfig:
    """Agent Studio feature flags OwlAuth Twin turns on for an org (local overrides), if enabled."""

    enabled: bool = True
    org: int = devbox_link.DEFAULT_ORG
    names: list[str] = field(default_factory=lambda: list(devbox_link.DEFAULT_FLAGS))

    def to_json(self) -> dict:
        return {"enabled": self.enabled, "org": self.org, "names": list(self.names)}

    @classmethod
    def from_json(cls, d: dict | None, mode: str = "full") -> FlagConfig:
        d = d if isinstance(d, dict) else {}
        try:
            org = int(d.get("org", devbox_link.DEFAULT_ORG))
        except (TypeError, ValueError):
            org = devbox_link.DEFAULT_ORG
        names = d.get("names")
        if not isinstance(names, list):
            names = list(devbox_link.DEFAULT_FLAGS)
        return cls(
            enabled=bool(d.get("enabled", mode == "full")), org=org,
            names=[str(n) for n in names if str(n).strip()],
        )


def flag_name_ok(name: str) -> bool:
    return bool(name) and len(name) <= 120 and all(c.isalnum() or c in "-_." for c in name)


def parse_flags(enabled: bool, org: str, names: list[str]) -> FlagConfig | str:
    """Flag settings from a form, or what is wrong with them."""
    org = (org or "").strip() or str(devbox_link.DEFAULT_ORG)
    if not org.isdigit() or len(org) > 18:
        return "Org ID must be a number"
    names = list(dict.fromkeys(n.strip() for n in names if n.strip()))
    bad = [n for n in names if not flag_name_ok(n)]
    if bad:
        return f"Not a flag name: {bad[0][:60]}"
    return FlagConfig(enabled=enabled, org=int(org), names=names)


def flags_detail(f: FlagConfig) -> str:
    if not f.enabled:
        return FLAGS_OFF
    return f"org {f.org}: local override of {', '.join(f.names) or 'no flags'}"


@dataclass
class Session:
    devbox: Devbox
    twins: TwinRegistry
    active: str  # the connector the panel shows (provider id)
    browser_port: int
    server_port: int
    mode: str = "full"  # full | twin_only
    flags: FlagConfig = field(default_factory=FlagConfig)
    started_at: float = field(default_factory=time.time)
    steps: list[Step] = field(default_factory=list)
    tunnel: devbox_link.ReverseTunnel | None = None
    servers: list = field(default_factory=list)
    link: devbox_link.LinkStatus | None = None
    route_applied: bool = False
    running_since: float = 0.0  # set once, when every step is done
    actions: dict = field(default_factory=dict)  # automation key -> when it last started
    inflight: set = field(default_factory=set)  # automation keys running right now
    errors: dict = field(default_factory=dict)  # automation key -> last error
    notes: dict = field(default_factory=dict)  # step key -> extra line for its OK detail
    progress: dict = field(default_factory=dict)  # automation key -> last output line
    direnv_ok: bool = False  # the repos' .envrc files are approved
    sso_url: str = ""  # AWS sign-in page (code filled in) while it waits for you
    sso_done_at: float = 0.0  # when the last AWS sign-in finished
    # When a check last found the devbox's AWS session working although a window said otherwise.
    sso_ok_at: float = 0.0
    # Since when Chrome's Google/Microsoft sign-in goes to the Twin (0 = off), and for which
    # connector's sign-in hosts.
    idp_on_at: float = 0.0
    idp_for: str = ""
    flags_applied_at: float = 0.0  # when the flag overrides were last written
    flags_applied_org: int = 0
    # /etc/machine-id of the devbox: a new devbox can get the alias of a deleted one.
    machine_id: str = ""

    @property
    def provider(self) -> Provider:
        return self.twin.provider

    @property
    def twin(self) -> TwinState:
        return self.twins.states.get(self.active) or next(iter(self.twins.states.values()))

    @property
    def providers(self) -> list[Provider]:
        return [st.provider for st in self.twins.states.values()]

    @property
    def server_hosts(self) -> list[str]:
        return sorted({h for p in self.providers for h in p.server_hosts})

    @property
    def idp_hosts(self) -> list[str]:
        """Sign-in hosts Chrome sends to the Twin now (only while Intercept is on)."""
        st = self.twins.get(self.idp_for)
        return list(st.provider.idp_hosts) if self.idp_on_at and st else []

    def idp_on_for(self, p: Provider) -> bool:
        return bool(set(p.idp_hosts) & set(self.idp_hosts))

    @property
    def phase(self) -> str:
        return "running" if self.running_since else "setup"

    def step(self, key: str) -> Step:
        return next(st for st in self.steps if st.key == key)

    @property
    def problems(self) -> list[Step]:
        return [st for st in self.steps if st.state not in ("ok", "skipped")]


class App:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.providers_dir = Path(os.environ.get("OWLTWIN_PROVIDERS", ROOT / "providers"))
        default_state_dir = Path.home() / ".local/state/owltwin"
        self.state_dir = Path(os.environ.get("OWLTWIN_STATE_DIR", default_state_dir))
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.panel_port = env_int("OWLTWIN_PORT", 18200)
        self.proxy_port = env_int("OWLTWIN_PROXY_PORT", 18201)
        self.session: Session | None = None
        # While Stop cleans up in the background: {"alias", "mode", "since"}. Start waits for it.
        self.stopping: dict[str, Any] | None = None
        self.stop_error = ""  # what the last Stop could not undo, shown on Setup
        self._stopper: threading.Thread | None = None
        self.version = 0
        self.changed = threading.Condition()
        self.devboxes = DevboxList(self.bump)  # the Setup page updates live when the list arrives
        self.devboxes.refresh()
        self.proxy = start_proxy(self.proxy_port, self._browser_hosts, self._browser_port)
        # After a hard kill or a reboot the Mac PAC still points at this app. Put it back now that
        # the proxy port is ours (so this is not a second copy), before any session sets it again.
        with contextlib.suppress(Exception):
            macproxy.restore(self.state_dir / "proxy-saved.json")
        self._idp_retry_at = 0.0
        threading.Thread(target=self._ticker, name="ticker", daemon=True).start()

    # Persistence -----------------------------------------------------------
    # One saved session per devbox, kept until you forget it: Stop and closing the app keep it,
    # so the Twin still knows the tokens and DCR clients the devbox's UCV stored.
    @property
    def sessions_dir(self) -> Path:
        return self.state_dir / "sessions"

    def session_path(self, alias: str) -> Path | None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", alias or ""):
            return None
        return self.sessions_dir / f"{alias}.json"

    def _migrate_session_file(self) -> None:
        """session.json (one session for the whole Mac) becomes sessions/<alias>.json."""
        old = self.state_dir / "session.json"
        if not old.exists():
            return
        with contextlib.suppress(OSError, ValueError):
            data = json.loads(old.read_text())
            alias = str(data.get("devbox", "")) if isinstance(data, dict) else ""
            path = self.session_path(alias)
            if path and not path.exists():
                self._write_json(path, data)
        old.unlink(missing_ok=True)

    @staticmethod
    def _write_json(path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        tmp.chmod(0o600)
        tmp.replace(path)

    def save_session(self) -> None:
        s = self.session
        if not s:
            return
        path = self.session_path(s.devbox.alias)
        if not path:
            return
        data = {
            "v": 3,
            "saved_at": time.time(),
            "devbox": s.devbox.alias,
            "machine_id": s.machine_id,
            "devbox_name": s.devbox.name,
            "devbox_region": s.devbox.region,
            "provider_file": s.provider.path.name,  # the connector shown
            "provider_id": s.provider.id,
            "mode": s.mode,
            "flags": s.flags.to_json(),
            "route_applied": s.route_applied,
            "twins": {pid: st.snapshot() for pid, st in s.twins.states.items()},
        }
        self._write_json(path, data)

    @staticmethod
    def _read_session(path: Path) -> dict | None:
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or not data.get("devbox") or not data.get("provider_file"):
            return None
        if "twins" not in data:  # v1: one connector
            data["twins"] = {data.get("provider_id", ""): data.get("twin") or {}}
        if data.get("mode") not in MODES:
            data["mode"] = "full"
        return data

    def saved_sessions(self) -> dict[str, dict]:
        """Every saved session, by devbox alias."""
        self._migrate_session_file()
        out = {}
        for path in sorted(self.sessions_dir.glob("*.json")):
            data = self._read_session(path)
            if data and path.stem == data["devbox"]:
                out[data["devbox"]] = data
        return out

    def saved_session(self, alias: str) -> dict | None:
        self._migrate_session_file()
        path = self.session_path(alias)
        return self._read_session(path) if path else None

    def last_session(self) -> dict | None:
        """The session saved most recently, on any devbox. Setup picks its devbox first."""
        saved = self.saved_sessions().values()
        return max(saved, key=lambda d: float(d.get("saved_at", 0)), default=None)

    def session_mismatch(self, data: dict, machine_id: str = "") -> str:
        """Why the devbox now behind this alias is not the one the session was saved on, or ""."""
        alias = data["devbox"]
        dbx = self.devboxes.get(alias)
        was, now = data.get("devbox_name") or "", dbx.name if dbx else ""
        other_name = bool(was and now and was != now)
        saved_id = data.get("machine_id") or ""
        other_id = bool(saved_id and machine_id and saved_id != machine_id)
        if not (other_name or other_id):
            return ""
        names = f" ({was} → {now})" if other_name else ""
        return (
            f"{alias} is a different devbox now{names}: the saved session belongs to one that "
            "was deleted, and its tokens are not in this devbox's UCV. Forget it, then start a "
            "new session."
        )

    def resume_session(self, alias: str = "") -> str:
        """Continue a devbox's saved session: same mode, flags and shown connector; every
        connector's Twin secrets and tokens kept."""
        data = self.saved_session(alias) if alias else self.last_session()
        if not data:
            return f"No saved session for {alias or 'any devbox'}"
        flags = FlagConfig.from_json(data.get("flags"), data["mode"])
        return self.start_session(
            data["devbox"], data["provider_file"], snapshot=data, mode=data["mode"], flags=flags,
        )

    def forget_session(self, alias: str) -> str:
        """Deletes a devbox's saved session and, in the background, the flag overrides it set.
        Nothing else on the devbox changes (its Dynamo keeps the connections)."""
        s = self.session
        if s and s.devbox.alias == alias:
            return f"The session on {alias} is running: Stop it first"
        path = self.session_path(alias)
        data = self.saved_session(alias)
        if not path or not data:
            return f"No saved session for {alias}"
        path.unlink(missing_ok=True)
        flags = FlagConfig.from_json(data.get("flags"), data["mode"])
        dbx = self.devboxes.get(alias)
        if flags.enabled and dbx and dbx.ssh_ok and not no_devbox():
            names = list(dict.fromkeys([*flags.names, *devbox_link.DEFAULT_FLAGS]))
            threading.Thread(
                target=devbox_link.remove_overrides, args=(alias, flags.org, names),
                name="forget-flags", daemon=True,
            ).start()
        self.bump()
        return ""

    # Helpers ---------------------------------------------------------------
    def bump(self) -> None:
        with self.changed:
            self.version += 1
            self.changed.notify_all()

    def _browser_hosts(self) -> list[str]:
        s = self.session
        if not s:
            return []
        idp = {h for p in s.providers for h in p.idp_hosts}
        on = set(s.idp_hosts)
        return sorted({h for p in s.providers for h in p.browser_hosts if h not in idp or h in on})

    def set_idp(self, on: bool) -> str:
        """Switches this provider's Google/Microsoft sign-in hosts in Chrome to the Twin, or back.

        A new PAC URL makes macOS and Chrome load the PAC again at once.
        """
        s = self.session
        if not s:
            return "No session"
        if on and not s.provider.idp_hosts:
            return "This provider has no Google or Microsoft sign-in hosts"
        if on and s.idp_on_at and s.idp_for == s.active:
            return ""
        if not on and not s.idp_on_at:
            return ""
        before = (s.idp_on_at, s.idp_for)
        hosts = s.provider.idp_hosts if on else s.idp_hosts
        # The PAC is built from these, so set them first.
        s.idp_on_at, s.idp_for = (time.time(), s.active) if on else (0.0, "")
        twin = s.twin if on else (s.twins.get(before[1]) or s.twin)
        try:
            macproxy.enable(self.pac_url, self.state_dir / "proxy-saved.json")
        except Exception as e:  # noqa: BLE001
            s.idp_on_at, s.idp_for = before  # macOS kept the old PAC: say what Chrome still does
            twin.note(f"Could not switch the Mac proxy: {e}")
            self.bump()
            return str(e)
        verb = "Intercepting" if on else "Stopped intercepting"
        twin.note(f"{verb} Chrome's sign-in: {', '.join(hosts)}")
        self.bump()
        return ""

    def set_active(self, pid: str) -> None:
        """Which connector the panel shows. Changes nothing in the Twin."""
        s = self.session
        if s and pid in s.twins.states and pid != s.active:
            s.active = pid
            self.save_session()
            self.bump()

    def _browser_port(self) -> int:
        s = self.session
        return s.browser_port if s else 1

    @property
    def pac_url(self) -> str:
        return f"http://127.0.0.1:{self.panel_port}/owltwin.pac?v={int(time.time())}"

    def provider_entries(self) -> list[ProviderEntry]:
        return scan(self.providers_dir)

    def _on_twin_change(self) -> None:
        if self.session:
            self.save_session()
        self.bump()

    def _set(
        self, s: Session, key: str, state: str, detail: str = "", took: str = "",
        command: str = "", link: str = "", link_label: str = "", takeover: str = "",
    ) -> None:
        st = s.step(key)
        current = (st.state, st.detail, st.command, st.link, st.takeover)
        wanted = (state, detail, command, link, takeover)
        if current != wanted or took:
            st.state = state
            st.detail = detail
            st.command = command
            st.link = link
            st.link_label = link_label
            st.takeover = takeover
            if took:
                st.took = took
            self._maybe_running(s)
            self.bump()

    def _maybe_running(self, s: Session) -> None:
        if not s.running_since and not s.problems:
            s.running_since = time.time()

    def _ticker(self) -> None:
        """Keeps the checks live.

        Tunnel every second, devbox every 5 s in Setup and 20 s in Running.
        """
        last_link = 0.0
        while True:
            time.sleep(1)
            s = self.session
            if s and s.idp_on_at and time.time() >= self._idp_retry_at:
                # Switch back after the connection is made, or after IDP_MINUTES.
                timed_out = time.time() - s.idp_on_at > IDP_MINUTES * 60
                on = set(s.idp_hosts)
                connected = any(
                    st.last_code_exchange > s.idp_on_at
                    for st in s.twins.states.values() if on & set(st.provider.idp_hosts)
                )
                if (timed_out or connected) and self.set_idp(False):
                    # Failed: Activity says why; try again later.
                    self._idp_retry_at = time.time() + 30
            if not s or no_devbox():
                continue
            if s.tunnel and s.step("tunnel").state in ("ok", "fail"):
                if s.tunnel.up:
                    self._set(s, "tunnel", "ok", self._tunnel_detail(s))
                elif s.step("tunnel").state == "ok" or s.tunnel.attempt > 1:
                    why = f" ({s.tunnel.last_error})" if s.tunnel.last_error else ""
                    self._set(s, "tunnel", "fail", f"reconnecting, attempt {s.tunnel.attempt}{why}")
            every = 20 if s.phase == "running" else 5
            if s.step("ssh").state == "ok" and time.time() - last_link > every:
                last_link = time.time()
                threading.Thread(target=self.refresh_link, args=(s,), daemon=True).start()

    @staticmethod
    def _tunnel_detail(s: Session) -> str:
        return f"devbox 127.0.0.1:{devbox_link.REMOTE_PORT} → Mac :{s.server_port}"

    # Session lifecycle -----------------------------------------------------
    def start_session(
        self, alias: str, provider_file: str, snapshot: dict | None = None, mode: str = "full",
        flags: FlagConfig | None = None, forget: bool = False,
    ) -> str:
        """Starts the Twin for every valid connector; provider_file is the one shown first.

        snapshot continues a saved session. A new one on a devbox that has a saved session needs
        forget=True: it replaces that session (Start new session… asks first)."""
        if self.stopping:
            where = self.stopping["alias"]
            return f"Still stopping the last session on {where}; start again once that is done"
        dbx = self.devboxes.get(alias)
        if dbx is None:
            return f"{alias} is not running"
        if mode not in MODES:
            return "Unknown mode"
        saved = self.saved_session(alias)
        if saved and not snapshot and not forget:
            return (
                f"{alias} has a saved session: Continue it, or Start new session to replace it"
            )
        machine_id = "" if no_devbox() else devbox_link.machine_id(alias)
        if snapshot and (why := self.session_mismatch(snapshot, machine_id)):
            return why
        path = self.providers_dir / provider_file
        if path.parent != self.providers_dir or not path.exists():
            return "Unknown provider file"
        try:
            first = load_provider(path)
        except LintError as e:
            return f"{e}. Fix the file (owltwin lint shows every problem) and try again."
        providers = {first.id: first}
        for e in self.provider_entries():
            if e.provider and e.provider.id not in providers:
                providers[e.provider.id] = e.provider
        self.stop_session()
        hosts = sorted({h for p in providers.values() for h in p.all_hosts})
        _ca, crt, key = ensure_certs(self.state_dir / "certs", hosts)
        twins = TwinRegistry(list(providers.values()), self._on_twin_change)
        saved = (snapshot or {}).get("twins") or {}
        for pid, st in twins.states.items():
            st.callback_port_fallback = dbx.frontend_port
            if isinstance(saved.get(pid), dict):
                st.restore(saved[pid])
        browser_port = free_port()
        server_port = env_int("OWLTWIN_SERVER_PORT", 18443)
        servers = []
        try:
            for port, kind in ((browser_port, "browser"), (server_port, "server")):
                servers.append(start_tls_server(twins, "127.0.0.1", port, str(crt), str(key), kind))
        except OSError as e:
            for srv in servers:
                srv.shutdown()
                srv.server_close()
            return (
                f"The Twin could not listen on 127.0.0.1:{server_port} ({e.strerror or e}). "
                "Another OwlAuth Twin may be running; close it, or set OWLTWIN_SERVER_PORT."
            )
        s = Session(
            devbox=dbx, twins=twins, active=first.id, mode=mode,
            flags=flags or FlagConfig(enabled=mode == "full"),
            browser_port=browser_port, server_port=server_port, servers=servers,
        )
        twins.active = lambda: s.active
        s.machine_id = machine_id or (snapshot or {}).get("machine_id", "")
        s.steps = self._steps(s)
        with self.lock:
            self.session = s
        reapply = bool(snapshot and snapshot.get("route_applied"))
        threading.Thread(target=self._run_setup, args=(s, reapply), daemon=True).start()
        self.save_session()
        self.bump()
        return ""

    @staticmethod
    def _flags_step(s: Session) -> Step:
        group = "Projects" if s.mode == "full" else "Feature flags"
        return Step("flags", group, "Agent Studio access", detail=flags_detail(s.flags))

    def _steps(self, s: Session) -> list[Step]:
        dbx = s.devbox
        steps = [
            Step("certs", "Mac", "Twin certificate", "ok",
                 "Local CA in owltwin's state folder, not in the keychain", "0 s"),
            Step("pac", "Mac", "Mac proxy", detail="Chrome sends only Twin hosts to OwlAuth Twin"),
            Step("ssh", "Devbox", f"{dbx.alias} reachable over ssh"),
            Step("tunnel", "Devbox", "Tunnel",
                 detail="ssh -R from the devbox to the Twin on this Mac"),
            Step("route", "Devbox", "Devbox → Twin",
                 detail="Hosts, forwarder on :443 and the Twin CA on the devbox"),
        ]
        if s.mode == "twin_only":
            return steps + ([self._flags_step(s)] if s.flags.enabled else [])
        return steps + [
            Step("setup", "Projects", "aiml-agents setup",
                 detail="bin/setup.sh: tools and the dev secrets in .envrc.local"),
            Step("agents", "Projects", "aiml-agents", detail="ml/claude_core on :8000"),
            Step("sandbox", "Projects", "Code sandbox",
                 detail="claude_core runs code in local Docker"),
            Step("backend", "Projects", "backend", detail="taskrunner with the Twin CA"),
            Step("callback", "Projects", "OAuth callback",
                 detail="/r/oauth/callback served by the local cloudserver"),
            self._flags_step(s),
            Step("studio", "Projects", "Agent Studio",
                 detail=f"https://localhost:{dbx.frontend_port or '?'}"),
        ]

    def _run_setup(self, s: Session, reapply_route: bool = False) -> None:
        t0 = time.time()
        self._set(s, "pac", "running", "Pointing the Mac proxy at OwlAuth Twin…")
        try:
            changed = macproxy.enable(self.pac_url, self.state_dir / "proxy-saved.json")
            if macproxy.disabled():
                self._set(s, "pac", "skipped", "OWLTWIN_NO_SYSTEM_PROXY=1: system proxy left alone")
            else:
                detail = (
                    f"Only Twin hosts go to OwlAuth Twin ({', '.join(changed)}). "
                    "Everything else is unchanged."
                )
                self._set(s, "pac", "ok", detail, f"{time.time() - t0:.0f} s")
        except Exception as e:  # noqa: BLE001
            self._set(s, "pac", "fail", str(e))
        if self.session is not s:
            # Cancelled while the proxy was being set: put it back unless a new session owns it now.
            if self.session is None:
                with contextlib.suppress(Exception):
                    macproxy.restore(self.state_dir / "proxy-saved.json")
            return
        if no_devbox():
            for key in [st.key for st in s.steps if st.group != "Mac"]:
                self._set(s, key, "skipped", "OWLTWIN_NO_DEVBOX=1: devbox left alone")
            return
        self._set(s, "ssh", "running", "Connecting…")
        self.refresh_link(s)
        if not (s.link and s.link.reachable):
            self._set(s, "ssh", "fail", s.link.detail if s.link else "ssh failed")
            return
        if self.session is not s:
            return  # cancelled while ssh was checked: start nothing for it
        self._set(s, "ssh", "ok", "", f"{time.time() - t0:.0f} s")
        s.tunnel = devbox_link.ReverseTunnel(s.devbox.alias, s.server_port)
        self._set(s, "tunnel", "running", "Connecting…")
        for _ in range(20):
            time.sleep(0.5)
            if s.tunnel.up or self.session is not s:
                break
        if self.session is not s:
            # Cancelled meanwhile; stop_session may have run before the tunnel existed.
            s.tunnel.stop()
            return
        if s.tunnel.up:
            self._set(s, "tunnel", "ok", self._tunnel_detail(s))
        else:
            why = s.tunnel.last_error or "ssh -R did not come up; retrying in the background"
            self._set(s, "tunnel", "fail", why)
        self.refresh_link(s)
        link = s.link
        if reapply_route and link and link.reachable and self.session is s and not link.hosts_ok:
            self.apply_route()  # you approved this change before the restart

    def refresh_link(self, s: Session) -> None:
        if no_devbox():
            return
        s.link = link = devbox_link.status(s.devbox.alias, s.server_hosts, s.flags.org)
        if self.session is not s:
            return
        if not link.reachable:
            if s.step("ssh").state == "ok":
                self._set(s, "ssh", "fail", link.detail or "ssh failed")
            return
        if s.step("ssh").state == "fail":
            self._set(s, "ssh", "ok")
        self._drive(s, link)

    # Automation ------------------------------------------------------------
    # Start session is your one go-ahead: from here OwlAuth Twin changes the devbox
    # and starts the projects itself, in its own tmux session (owltwin-run). It never
    # stops a process it did not start; those cases still show a command to copy.
    def _once(self, s: Session, key: str, cooldown: float, fn, *args) -> bool:
        """Runs fn in the background unless it is running or ran less than `cooldown` s ago."""
        with self.lock:
            if key in s.inflight or time.time() - s.actions.get(key, 0) < cooldown:
                return False
            s.actions[key] = time.time()
            s.inflight.add(key)

        def run() -> None:
            try:
                fn(*args)
            except Exception as e:  # noqa: BLE001
                s.errors[key] = str(e)[:300]
            finally:
                with self.lock:
                    s.inflight.discard(key)
                if self.session is s:
                    self.recheck()

        threading.Thread(target=run, name=f"auto-{key}", daemon=True).start()
        return True

    def _since(self, s: Session, key: str) -> str:
        t = s.actions.get(key)
        return f" · {int(time.time() - t)} s" if t else ""

    def _start(self, s: Session, key: str, window: str, cwd: str, cmd: str) -> None:
        err = devbox_link.run_in_window(s.devbox.alias, window, cwd, cmd)
        if err:
            s.errors[key] = err
        else:
            # The keys are typed; the shell starts the command a moment later.
            s.actions[f"typed-{key}"] = time.time()

    def _provision(self, s: Session) -> None:
        """Clones missing repos with the devbox CLI on this Mac (idempotent)."""
        log = self.state_dir / f"provision-{s.devbox.alias}.log"
        runs = []
        if s.link and not s.link.agents_repo:
            runs.append(["devbox", "provision", s.devbox.alias, "--template", "aiml-agents"])
        if s.link and not s.link.backend_repo:
            runs.append(["devbox", "provision", s.devbox.alias])
        with log.open("w") as f:
            for argv in runs:
                f.write("$ " + " ".join(argv) + "\n")
                f.flush()
                proc = subprocess.Popen(
                    argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True,
                )
                for line in proc.stdout or []:
                    f.write(line)
                    f.flush()
                    if line.strip():
                        s.progress["repos"] = line.strip()[:200]
                        self.bump()
                if proc.wait() != 0:
                    command = " ".join(argv)
                    s.errors["repos"] = f"{command} exited with {proc.returncode}; log: {log}"
                    return
                s.link = devbox_link.status(s.devbox.alias, s.server_hosts, s.flags.org)

    def _connect(self, s: Session) -> None:
        r = subprocess.run(
            ["devbox", "connect", s.devbox.alias],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            output = r.stderr or r.stdout or "devbox connect failed"
            s.errors["studio"] = output.strip().splitlines()[-1][:200]

    def _direnv(self, s: Session) -> None:
        err = devbox_link.direnv_allow(s.devbox.alias)
        if err:
            s.errors["direnv"] = err
        else:
            s.direnv_ok = True

    def _direnv_ready(self, s: Session, key: str) -> bool:
        """Approves .envrc once before the first start; shows that on the step meanwhile."""
        if s.direnv_ok:
            return True
        if "direnv" in s.errors:
            self._set(s, key, "fail", s.errors["direnv"])
        else:
            self._once(s, "direnv", 30, self._direnv, s)
            self._set(s, key, "running", "Approving the repos' .envrc (direnv allow)")
        return False

    def _sso(self, link: devbox_link.LinkStatus, window: str) -> bool:
        return window in link.sso and link.windows.get(window, "") in devbox_link.SHELLS

    def _drive(self, s: Session, link: devbox_link.LinkStatus) -> None:
        profile = f" --profile {shlex.quote(AWS_PROFILE)}" if AWS_PROFILE else ""
        sso_cmd = f"aws sso login{profile}"
        # Route: hosts, forwarder and CA. Applied on its own; port 443 taken by someone else is the
        # only stop.
        if s.step("route").state != "running":
            if link.hosts_ok and link.forward_ok and link.ca_ok:
                self._set(s, "route", "ok", "Hosts, forwarder on :443 and the Twin CA are in place")
            elif link.port443_owner and not link.forward_ok:
                owner = link.port443_owner[:160]
                self._set(s, "route", "fail", "Port 443 on the devbox is taken: " + owner)
            elif s.step("tunnel").state == "ok" and self._once(s, "route", 60, self.apply_route):
                detail = "Changing the devbox: /etc/hosts lines, forwarder on :443, Twin CA"
                self._set(s, "route", "running", detail)
        if s.mode == "twin_only":
            # Your env: only watched (the health bar shows what runs without the Twin CA).
            if any(st.key == "flags" for st in s.steps):
                self._flags(s, link)
            return

        # Repos: cloned with `devbox provision` on this Mac.
        repos_ok = link.agents_repo and link.backend_repo
        if not repos_ok:
            if "repos" in s.errors:
                step = "agents" if not link.agents_repo else "backend"
                self._set(s, step, "fail", s.errors["repos"])
            else:
                self._once(s, "repos", 3600, self._provision, s)
                what = "aiml-agents" if not link.agents_repo else "backend"
                detail = f"Cloning {what} with devbox provision{self._since(s, 'repos')}"
                if s.progress.get("repos"):
                    detail += f" · {s.progress['repos']}"
                self._set(s, "agents" if not link.agents_repo else "backend", "running", detail)
        if not link.agents_repo:
            for key in ("sandbox", "setup"):
                self._set(s, key, "pending", "Waits for the aiml-agents repo")
            if link.backend_repo:
                self._backend(s, link, sso_cmd)
                self._callback_studio(s, link)
                self._flags(s, link)
            return
        if not link.backend_repo:
            self._set(s, "agents", "pending", "Waits for the backend repo")
            self._set(s, "sandbox", "pending", "Waits for the backend repo")
            self._set(s, "setup", "pending", "Waits for the backend repo")
            for key in ("callback", "flags", "studio"):
                self._set(s, key, "pending", "Waits for the backend repo")
            return

        self._setup(s, link, sso_cmd)
        self._sandbox(s, link)
        self._backend(s, link, sso_cmd)
        self._agents(s, link, sso_cmd)
        self._callback_studio(s, link)
        self._flags(s, link)

    def _flags(self, s: Session, link: devbox_link.LinkStatus) -> None:
        """Agent Studio access.

        The local backend asks production LaunchDarkly, where the org is not targeted, so the org
        gets a local override (the same rows the feature_flag_overrides panel writes).
        """
        f = s.flags
        if not f.enabled or not f.names:
            self._set(s, "flags", "skipped", FLAGS_OFF if not f.enabled else "No flags listed")
            return
        org, flags = f.org, f.names
        missing = [n for n in flags if n not in link.overrides]
        if not missing:
            self._set(s, "flags", "ok", f"org {org}: {', '.join(flags)} on (local override)")
        elif "flags" in s.errors:
            detail = f"Could not add the local override for org {org}: {s.errors['flags']}"
            self._set(s, "flags", "fail", detail)
        elif not link.ddb_ok:
            detail = (
                "Waits for the backend: taskrunner starts dynamodb-local with the overrides table"
            )
            self._set(s, "flags", "pending", detail)
        else:
            self._once(s, "flags", 60, self._write_overrides, s)
            detail = (
                f"Turning on {', '.join(missing)} for org {org} in the local feature flag "
                "overrides; the backend picks them up within a minute"
            )
            self._set(s, "flags", "running", detail)

    def _write_overrides(self, s: Session) -> None:
        org, names = s.flags.org, list(s.flags.names)
        err = devbox_link.ensure_overrides(s.devbox.alias, org, names)
        if err:
            s.errors["flags"] = err
        else:
            s.flags_applied_at, s.flags_applied_org = time.time(), org

    def update_flags(self, flags: FlagConfig) -> None:
        """Session settings: new flag settings, applied in the background by the usual checks."""
        s = self.session
        if not s:
            return
        with self.lock:
            s.flags = flags
            s.errors.pop("flags", None)
            s.actions.pop("flags", None)
            if flags.enabled and not any(st.key == "flags" for st in s.steps):
                s.steps.append(self._flags_step(s))
            elif any(st.key == "flags" for st in s.steps):
                st = s.step("flags")
                st.detail = flags_detail(s.flags)
                st.state = "pending"
        self.save_session()
        self.bump()
        self.recheck()

    def remove_flags(self, org: int) -> None:
        """Session settings: takes the org's direct overrides off again (in the background)."""
        s = self.session
        if not s or no_devbox():
            return
        names = list(dict.fromkeys([*s.flags.names, *devbox_link.DEFAULT_FLAGS]))

        def run() -> None:
            err = devbox_link.remove_overrides(s.devbox.alias, org, names)
            if err:
                s.twin.note(f"Could not remove the overrides for org {org}: {err}")
            else:
                s.twin.note(f"Removed the local overrides of {', '.join(names)} for org {org}")
                if s.flags_applied_org == org:
                    s.flags_applied_at = 0.0
            self.recheck()

        threading.Thread(target=run, name="remove-flags", daemon=True).start()

    def _setup(self, s: Session, link: devbox_link.LinkStatus, sso_cmd: str) -> None:
        if link.agents_secrets:
            self._set(s, "setup", "ok", "bin/setup.sh done: .envrc.local has the dev secrets")
            return
        self._run_window(s, link, "setup", "~/co/aiml-agents", SETUP_RUN, "bin/setup.sh", sso_cmd)

    def _sandbox(self, s: Session, link: devbox_link.LinkStatus) -> None:
        if not link.sandbox_cfg:
            if "sandbox_cfg" in s.errors:
                detail = f"Could not write local.yaml: {s.errors['sandbox_cfg']}"
                self._set(s, "sandbox", "fail", detail)
            else:
                self._once(s, "sandbox_cfg", 30, self._write_cfg, s)
                detail = (
                    "Writing claude_core local.yaml: sandbox in local Docker "
                    "(the e2b dev key is mocked)"
                )
                self._set(s, "sandbox", "running", detail)
        elif not link.docker_ok:
            detail = "Docker does not answer for your user on the devbox (docker info failed)."
            self._set(s, "sandbox", "fail", detail)
        elif not link.sandbox_images:
            win = link.windows.get("sandbox", "")
            stopped = "sandbox" in s.actions and "sandbox" not in s.inflight
            if win in devbox_link.SHELLS and stopped:
                why = link.errs.get("sandbox") or link.tails.get("sandbox", "")
                if self._reblocked(s, link, "sandbox"):
                    return
                detail = (
                    f"Image build stopped: {why or 'see tmux owltwin-run:sandbox'}. "
                    "Check again builds them again."
                )
                self._set(s, "sandbox", "fail", detail)
            elif self._direnv_ready(s, "sandbox"):
                self._once(
                    s, "sandbox", 3600, self._start,
                    s, "sandbox", "sandbox", "~/co/aiml-agents", SANDBOX_IMG_CMD,
                )
                detail = (
                    f"Building the local sandbox images (once){self._since(s, 'sandbox')} "
                    "· tmux owltwin-run:sandbox"
                )
                self._set(s, "sandbox", "running", detail)
        else:
            note = f" · {s.notes['sandbox']}" if s.notes.get("sandbox") else ""
            self._set(s, "sandbox", "ok", "local Docker, images built" + note)

    def _write_cfg(self, s: Session) -> None:
        err = devbox_link.write_sandbox_config(s.devbox.alias)
        if err == "merged":
            s.notes["sandbox"] = (
                "local.yaml existed: set provider: local_docker in it "
                "(copy at local.yaml.owltwin-backup)"
            )
        elif err:
            s.errors["sandbox_cfg"] = err

    def _backend(self, s: Session, link: devbox_link.LinkStatus, sso_cmd: str) -> None:
        if not link.ca_ok:
            detail = "Waits for the Twin CA on the devbox (Devbox → Twin)"
            self._set(s, "backend", "pending", detail)
            return
        if link.redis_agents and not link.redis_backend:
            self._redis_clash(s, link)
            return
        needs_restart = link.backend == "noca" or link.devproxy
        if link.backend == "ok" and not link.devproxy:
            fails = link.task_fails.get("backend", [])
            window = " · tmux owltwin-run:backend" if link.backend_ours else ""
            note = ""
            if fails:
                note = f" · taskrunner task failed, services run: {', '.join(fails[:3])}"
            self._set(s, "backend", "ok", "taskrunner with the Twin CA" + window + note)
            return
        if needs_restart and not link.backend_ours:
            why = "without the Twin CA" if link.backend == "noca" else "with USE_VITE_DEVPROXY=true"
            detail = (
                f"A backend you started yourself runs {why}. OwlAuth Twin stops it only "
                "if you click Take over, then starts its own in owltwin-run:backend."
            )
            self._set(s, "backend", "needs_you", detail, takeover="backend")
            return
        self._run_window(
            s, link, "backend", "~/co/backend", BACKEND_CMD, "taskrunner", sso_cmd,
            force=needs_restart and link.backend_ours,
        )

    def _redis_clash(self, s: Session, link: devbox_link.LinkStatus) -> None:
        """aiml-agents' redis7 holds :6380, so the backend's Redis cannot start.

        Hand the port to the backend.
        """
        if "redis" in s.errors:
            detail = (
                f"Could not hand :6380 to the backend's Redis: {s.errors['redis']}. "
                "Check again tries once more."
            )
            self._set(s, "backend", "fail", detail)
        elif link.agents_ok and not link.agents_ours:
            detail = (
                "The aiml-agents you started yourself runs its own Redis (redis7) on :6380, "
                "so the backend's Redis can't start. Take over stops yours; OwlAuth Twin then "
                "hands :6380 to the backend and starts its own aiml-agents."
            )
            self._set(s, "backend", "needs_you", detail, takeover="agents")
        else:
            self._once(s, "redis", 120, self._free_redis, s, link.agents_ok)
            restart = " and restarting aiml-agents" if link.agents_ok else ""
            detail = (
                "aiml-agents' Redis (redis7) holds :6380, so the backend's Redis can't start. "
                "Handing the port to the backend's Redis" + restart
            )
            self._set(s, "backend", "running", detail)

    def _free_redis(self, s: Session, restart_agents: bool) -> None:
        err = devbox_link.free_redis(s.devbox.alias)
        if err:
            s.errors["redis"] = err
        elif restart_agents:
            err = devbox_link.run_in_window(
                s.devbox.alias, "agents", "~/co/aiml-agents/agent-platform", AGENTS_RUN
            )
            if err:
                s.errors["agents"] = err

    def _agents(self, s: Session, link: devbox_link.LinkStatus, sso_cmd: str) -> None:
        if not link.agents_secrets:
            # Without LITELLM_API_KEY, claude_core starts fine and every chat then hangs with no
            # error.
            detail = (
                "Waits for aiml-agents setup: no LITELLM_API_KEY in .envrc.local yet, "
                "so chat would hang"
            )
            self._set(s, "agents", "pending", detail)
            return
        stale = link.sandbox_stale or link.env_stale
        if link.agents_ok and not stale:
            window = " · tmux owltwin-run:agents" if link.agents_ours else ""
            self._set(s, "agents", "ok", "ml/claude_core on :8000" + window)
            return
        if not link.sandbox_cfg:
            detail = "Waits for the sandbox config, so it starts with local Docker"
            self._set(s, "agents", "pending", detail)
            return
        if not link.agents_ok and not link.redis_backend:
            # make server reuses a Redis on :6380 and starts its own only when none answers, which
            # then blocks the backend's. So it starts after the backend's Redis is up.
            detail = "Waits for the backend's Redis on :6380, which aiml-agents shares"
            self._set(s, "agents", "pending", detail)
            return
        if link.agents_ok and stale and not link.agents_ours:
            if link.sandbox_stale:
                why = "local.yaml, so it still uses e2b"
            else:
                why = ".envrc.local, so it has no LITELLM_API_KEY and chat hangs"
            detail = (
                f"The aiml-agents you started yourself predates {why}. "
                "Take over stops it and starts OwlAuth Twin's own in owltwin-run:agents."
            )
            self._set(s, "agents", "needs_you", detail, takeover="agents")
            return
        self._run_window(
            s, link, "agents", "~/co/aiml-agents/agent-platform", AGENTS_RUN, "make server",
            sso_cmd,
            force=link.agents_ok and stale and link.agents_ours,
        )

    def _reblocked(self, s: Session, link: devbox_link.LinkStatus, key: str) -> bool:
        """A start that died on a blocked .envrc: approve again and start once more, on its own."""
        blocked = "is blocked" in link.errs.get(key, "")
        recently = time.time() - s.actions.get(f"reblock-{key}", 0) < 300
        if not blocked or recently:
            return False
        with self.lock:
            s.actions[f"reblock-{key}"] = time.time()
            s.actions.pop(key, None)
            s.actions.pop("direnv", None)
            s.direnv_ok = False
        detail = "The repo's .envrc was blocked; approving it and starting again"
        self._set(s, key, "running", detail)
        return True

    def _run_window(
        self, s: Session, link: devbox_link.LinkStatus, key: str, cwd: str, cmd: str, what: str,
        sso_cmd: str, force: bool = False,
    ) -> None:
        """Starts a project in owltwin-run:<key> and then only watches it.

        A long first build is never interrupted.
        """
        pane = link.windows.get(key)
        running = pane is not None and pane not in devbox_link.SHELLS
        tail = link.tails.get(key, "")
        sso = self._sso(link, key)
        if sso and key in s.inflight:
            self._set(s, key, "running", f"Signed in to AWS; starting {what} again")
            return
        started = key in s.actions and key not in s.inflight
        if not running and started and s.sso_done_at > s.actions[key]:
            # Signed in to AWS after this pane last started and it has stopped: start it again
            # (the restart also clears its old output).
            sso = False
            force = True
            s.actions.pop(key, None)
        if sso and s.sso_ok_at and s.actions.get(key, 0) > s.sso_ok_at:
            # Started again after a check found the AWS session working, and it stopped on the
            # same kind of error: a sign-in will not fix it, so say what it printed.
            why = link.errs.get(key) or tail or "no output"
            detail = (
                f"{what} gets no AWS credentials although the devbox's AWS sign-in works: "
                f"{why[:200]}. Logs: tmux attach -t owltwin-run. Check again starts it again."
            )
            self._set(s, key, "fail", detail)
        elif sso:
            self._aws_signin(s, key)
        elif key in s.errors:
            self._set(s, key, "fail", s.errors[key])
        elif running and not force:
            last_line = f" · {tail[:120]}" if tail else ""
            detail = f"{what} is starting{self._since(s, key)} · tmux owltwin-run:{key}" + last_line
            self._set(s, key, "running", detail)
        elif (
            started and not force and not tail and not link.errs.get(key)
            and time.time() - s.actions.get(f"typed-{key}", 0) < START_GRACE
        ):
            # tmux send-keys returns before the shell runs the command: an idle, still empty pane
            # right after it is not a stop. Once the command printed something (an error), it is.
            self._set(s, key, "running", f"Starting {what} in tmux owltwin-run:{key}")
        elif started and not force:
            if self._reblocked(s, link, key):
                return
            why = link.errs.get(key) or tail or "no output"
            detail = (
                f"{what} stopped: {why[:200]}. Logs: tmux attach -t owltwin-run. "
                "Check again starts it again."
            )
            self._set(s, key, "fail", detail)
        elif not self._direnv_ready(s, key):
            return
        else:
            if self._once(s, key, 30, self._start, s, key, key, cwd, cmd):
                self._set(s, key, "running", f"Starting {what} in tmux owltwin-run:{key}")

    def _aws_signin(self, s: Session, key: str) -> None:
        """The devbox's AWS session expired.

        OwlAuth Twin starts the sign-in and opens its page for you.
        """
        if "sso" in s.errors:
            detail = (
                f"The AWS sign-in did not finish ({s.errors['sso']}). Check again opens it again."
            )
            self._set(s, key, "fail", detail)
            return
        self._once(s, "sso", 15, self._sso_login, s)
        if s.sso_url:
            detail = (
                "The AWS session on the devbox expired. OwlAuth Twin opened the AWS sign-in in "
                "your browser with the code filled in: confirm it there and this continues on "
                "its own."
            )
            self._set(
                s, key, "needs_you", detail,
                link=s.sso_url, link_label="Open the AWS sign-in again",
            )
        else:
            detail = "The AWS session on the devbox expired: starting the AWS sign-in"
            self._set(s, key, "running", detail)

    def _sso_login(self, s: Session) -> None:
        def on_url(url: str) -> None:
            s.sso_url = url
            self.bump()
            if not os.environ.get("OWLTWIN_NO_BROWSER"):
                webbrowser.open(url)

        if devbox_link.sso_signed_in(s.devbox.alias):
            # The session works (the window's error only looks like an expired session, or you
            # signed in elsewhere): no sign-in, and the windows that stopped on it start again.
            s.sso_done_at = s.sso_ok_at = time.time()
            return
        err = devbox_link.sso_login(s.devbox.alias, on_url)
        s.sso_url = ""
        if err:
            s.errors["sso"] = err
        else:
            s.sso_done_at = time.time()

    def _callback_studio(self, s: Session, link: devbox_link.LinkStatus) -> None:
        if link.devproxy:
            detail = (
                "The dashboard runs with USE_VITE_DEVPROXY=true, so /r/oauth/callback goes to the "
                "shared devproxy, not your ucvserver."
            )
            self._set(s, "callback", "fail", detail)
        elif link.cloudserver_ok:
            self._set(s, "callback", "ok", "local cloudserver on :3030")
        else:
            detail = "Waits for the backend: taskrunner starts cloudserver on :3030"
            self._set(s, "callback", "pending", detail)
        alias = s.devbox.alias
        port = s.devbox.frontend_port
        if not port:
            detail = (
                f"No Agent Studio port for {alias}: devbox list gives no dashboard URL "
                "and the N3000 rule overflows above index 6."
            )
            self._set(s, "studio", "fail", detail)
        elif not link.dashboard_ok:
            detail = "Waits for the backend: taskrunner starts the dashboard on :3000"
            self._set(s, "studio", "pending", detail)
        elif mac_port_open(port):
            self._set(s, "studio", "ok", f"https://localhost:{port}")
        elif "studio" in s.errors:
            detail = f"devbox connect {alias} failed: {s.errors['studio']}"
            self._set(s, "studio", "fail", detail)
        else:
            self._once(s, "studio", 60, self._connect, s)
            detail = f"Opening the tunnel to localhost:{port} (devbox connect {alias})"
            self._set(s, "studio", "running", detail)

    def take_over(self, what: str) -> None:
        """You clicked Take over.

        Stop the project you started yourself, then the usual steps start ours.
        """
        s = self.session
        if not s or not s.devbox or what not in ("agents", "backend"):
            return
        # The card that offered it.
        key = next((st.key for st in s.steps if st.takeover == what), what)
        project = "backend" if what == "backend" else "aiml-agents"
        detail = f"Stopping the {project} you started (TERM, then KILL after 15 s)"
        self._set(s, key, "running", detail)

        def run() -> None:
            err = devbox_link.stop_own(s.devbox.alias, what)
            if err:
                self._set(s, key, "fail", f"Could not stop it: {err}")
                return
            self.recheck(retry=True)

        threading.Thread(target=run, daemon=True).start()

    def recheck(self, retry: bool = False) -> None:
        s = self.session
        if s:
            if retry:
                # "Check again": forget cooldowns and errors, so every automatic step runs again.
                with self.lock:
                    s.actions = {k: v for k, v in s.actions.items() if k in s.inflight}
                    s.errors.clear()
                    s.direnv_ok = False
            threading.Thread(target=self.refresh_link, args=(s,), daemon=True).start()

    def apply_route(self) -> str:
        s = self.session
        if not s:
            return "No session"
        ca = (self.state_dir / "certs" / "ca.pem").read_text()
        self._set(s, "route", "running", "Changing the devbox…")
        err = devbox_link.up(s.devbox.alias, s.server_hosts, ca)
        if err:
            self._set(s, "route", "fail", err)
            return err
        s.route_applied = True
        self.save_session()
        self._set(s, "route", "pending", "Checking…")
        self.refresh_link(s)
        return ""

    def request_stop(self) -> None:
        """Stop from the panel. Returns at once: the cleanup runs in the background while the panel
        shows Stopping, and Start waits for it. Another click meanwhile does nothing."""
        with self.lock:
            s = self.session
            if self.stopping or not s:
                return
            alias = s.devbox.alias if s.devbox else "this Mac"
            self.stopping = {"alias": alias, "mode": s.mode, "since": time.time()}
            self.stop_error = ""
            self._stopper = threading.Thread(target=self._stop_bg, name="stop", daemon=True)
            self._stopper.start()
        self.bump()

    def _stop_bg(self) -> None:
        try:
            err = self.stop_session()
        except Exception as e:  # noqa: BLE001  shown on Setup; Stop must always finish
            err = str(e) or type(e).__name__
        with self.lock:
            where = (self.stopping or {}).get("alias", "the devbox")
            self.stopping = None
            self.stop_error = f"Stop could not clean up {where}: {err}" if err else ""
        self.bump()

    def stop_session(self) -> str:
        """Stops everything this session runs, on the devbox and on this Mac. Its saved session
        stays (Forget removes it), so Continue gets the Twin's tokens back.
        Returns what could not be undone on the devbox, or ""."""
        t = self._stopper
        if t and t is not threading.current_thread() and t.is_alive():
            t.join()  # closing the app mid-Stop: let that Stop finish first
        self.save_session()
        with self.lock:
            s = self.session
            self.session = None
        if not s:
            return ""
        self.bump()  # the panel leaves Running now, not after the devbox answered
        if s.tunnel:
            s.tunnel.stop()
        err = ""
        if s.devbox and not no_devbox():
            # Closing the app or Stop leaves nothing running on the devbox: route, forwarder and
            # owltwin-run. Twin only never started anything there, so only the route goes.
            if s.mode == "twin_only":
                err = devbox_link.route_down(s.devbox.alias)
            else:
                err = devbox_link.down(s.devbox.alias)
        for srv in s.servers:
            srv.shutdown()  # waits for serve_forever to return (at most its 0.5 s poll)
            srv.server_close()
        with contextlib.suppress(Exception):
            macproxy.restore(self.state_dir / "proxy-saved.json")
        self.bump()
        return err

    # Twin actions ----------------------------------------------------------
    def twin_action(self, name: str) -> None:
        s = self.session
        if not s:
            return
        actions = {
            "expire": s.twin.expire_access_tokens,
            "rotate": s.twin.rotate_secret,
            "revoke": s.twin.revoke_all,
        }
        actions[name]()
