"""Panel HTTP server and pages (server-rendered, live via long-poll).

One address, "/". What it shows follows the session:
  no session          → Setup: pick a devbox and a provider
  session in setup    → Setup: the steps, on the same page
  session running     → Running: paste values, Activity, request detail

The HTML is in templates/ (Jinja2, autoescaped). This module builds the view-models they print:
plain dicts and lists, never HTML. The HTTP side is a small Flask app (create_app) served by
Werkzeug's threaded server (serve).
"""

from __future__ import annotations

import json
import socket
import time
import urllib.parse
from collections.abc import Callable
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, redirect, request
from werkzeug.serving import BaseWSGIServer, WSGIRequestHandler, make_server

from . import devbox_link
from .app import (
    APP_NAME,
    FLAGS_OFF,
    IDP_MINUTES,
    MODES,
    App,
    FlagConfig,
    Session,
    Step,
    parse_flags,
)
from .config import IDP_SUFFIXES
from .proxy import pac_script
from .templating import render as render_template
from .twin import Exchange

STATIC = Path(__file__).parent / "static"


def ago(ts: float) -> str:
    m = int((time.time() - ts) // 60)
    if m < 1:
        return "just now"
    if m < 60:
        return f"{m} min"
    return f"{m // 60} h {m % 60:02d} min"


def btn(action: str, label: str, cls: str = "btn") -> dict[str, str]:
    """A POST button, as the _ui.html post_btn macro prints it."""
    return {"action": action, "label": label, "cls": cls}


# Page shell -----------------------------------------------------------------
# Short name for the health bar and the status line, per step.
SHORT = {
    "pac": "Mac proxy",
    "tunnel": "Tunnel",
    "route": "Devbox → Twin",
    "agents": "aiml-agents",
    "backend": "backend",
    "ssh": "ssh",
    "certs": "Twin certificate",
    "sandbox": "sandbox",
    "callback": "callback",
    "flags": "access",
    "setup": "aiml-agents setup",
    "studio": "Agent Studio",
}
DOWN = {
    "pac": "Mac proxy off",
    "tunnel": "tunnel down",
    "route": "devbox not pointing at the Twin",
    "agents": "aiml-agents down",
    "backend": "backend down",
    "ssh": "devbox unreachable",
    "certs": "certificate missing",
    "sandbox": "no code sandbox",
    "callback": "OAuth callback not local",
    "flags": "no Agent Studio access",
    "setup": "aiml-agents not set up",
    "studio": "Agent Studio unreachable",
}


def top_vm(s: Session | None, stopping: dict[str, Any] | None = None) -> dict[str, str] | None:
    if not s:
        if stopping:
            where = f"{stopping['alias']} · {MODE_LABEL.get(stopping['mode'], '')}"
            return {"state": "stopping", "where": where, "settings": ""}
        return None
    where = f"{s.devbox.alias} · {MODE_LABEL[s.mode]}"
    info = session_info(s)
    if s.phase == "setup":
        return {"state": "setup", "where": where, "settings": "", "info": info}
    if s.problems:
        p = s.problems[0]
        down = DOWN.get(p.key, p.title)
        return {"state": "down", "where": where, "down": down, "settings": "", "info": info}
    ago_ = ago(s.running_since)
    return {"state": "ok", "where": where, "ago": ago_, "settings": "", "info": info}


def session_info(s: Session) -> dict[str, Any]:
    """The top bar's Session popover: where things run and how to look at them."""
    d = s.devbox
    info: dict[str, Any] = {
        "devbox": f"{d.alias} · {d.name} · {d.region}",
        "mode": MODE_LABEL[s.mode],
        "attach": "",
        "windows": [],
    }
    if s.mode == "twin_only":
        return info
    info["attach"] = f"ssh {d.alias} -t tmux attach -t {devbox_link.RUN_SESSION}"
    link = s.link
    for key, what, ours, ok in (
        ("setup", "repos, sandbox image, sign-ins", True, True),
        ("backend", "taskrunner", link.backend_ours if link else True,
         bool(link.backend) if link else False),
        ("agents", "aiml-agents :8000", link.agents_ours if link else True,
         link.agents_ok if link else False),
    ):
        note = what if ours or not ok else f"{what}, yours: runs outside owltwin-run"
        info["windows"].append({"name": key, "note": note, "ours": ours or not ok})
    return info


def page(title: str, template: str, ctx: dict[str, Any]) -> str:
    """The whole document: base.html with the page template inside #live.

    X-Fragment requests get the page template alone (see create_app).
    """
    return render_template("base.html", title=title, page_template=template, **ctx)


# Setup: pick ----------------------------------------------------------------
def devbox_vm(d: Any, pick: str | None) -> dict[str, Any]:
    if d.ssh_ok:
        studio = (d.dashboard or f"https://localhost:{d.frontend_port}/").rstrip("/")
        sub = f"Agent Studio at {studio} · {d.region}"
    else:
        sub = "ssh fails · run devbox doctor"
    return {
        "alias": d.alias,
        "label": d.label,
        "ok": d.ssh_ok,
        "checked": d.alias == pick,
        "sub": sub,
    }


def provider_vm(e: Any, checked: bool) -> dict[str, Any]:
    if not e.provider:
        problems = e.error.problems if e.error else []
        return {
            "ok": False,
            "file": e.file.name,
            "stem": e.file.stem,
            "problems": len(problems),
            "first_problem": problems[0] if problems else "",
        }
    p = e.provider
    tenant = f" · tenant {p.tenant}" if p.tenant != "default" else ""
    tools = f"{len(p.tools)} tool" + ("" if len(p.tools) == 1 else "s")
    return {
        "ok": True,
        "file": e.file.name,
        "name": p.name,
        "checked": checked,
        "sub": f"{e.file.name} · {p.kind_label}{tenant} · {tools}",
    }


def pick_vm(app: App, error: str = "") -> dict[str, Any]:
    dl = app.devboxes
    with dl.lock:
        items = list(dl.items)
        loading = dl.loading
        list_error = dl.error
    last = app.last_session()
    up = {d.alias for d in items if d.ssh_ok}
    first_up = next((d.alias for d in items if d.ssh_ok), None)
    pick = last["devbox"] if last and last["devbox"] in up else first_up
    devboxes = [devbox_vm(d, pick) for d in items]

    entries = app.provider_entries()
    valid = {e.file.name: e.provider for e in entries if e.provider}
    last_file = last["provider_file"] if last and last["provider_file"] in valid else ""
    first_valid = next(iter(valid), "")
    checked_file = last_file or first_valid
    providers = [provider_vm(e, e.file.name == checked_file) for e in entries]

    cont = None
    mode = "full"
    flags = FlagConfig()
    if last:
        pfile = last["provider_file"]
        saved_at = time.localtime(float(last.get("saved_at", 0)))
        mode = last.get("mode") if last.get("mode") in MODES else "full"
        flags = FlagConfig.from_json(last.get("flags"), mode)
        name = valid[pfile].name if pfile in valid else pfile
        cont = {
            "alias": last["devbox"],
            "provider": name,
            "summary": " · ".join(
                [last["devbox"], MODE_LABEL[mode], short_name(name), flags_summary(flags)]
            ),
            "up": last["devbox"] in up,
            "saved": time.strftime("%H:%M", saved_at),
        }
    first_name = short_name(valid[checked_file].name) if checked_file in valid else "?"
    start_summary = " · ".join(
        [pick or "no devbox", MODE_LABEL[mode], f"{first_name} first", flags_summary(flags)]
    )
    stopping = app.stopping
    return {
        "top": top_vm(None, stopping),
        "app_name": APP_NAME,
        "error": error,
        "stopping": stopping_vm(stopping),
        "stop_error": "" if stopping else app.stop_error,
        "loading": loading,
        # The very first devbox list is on its way: a loader instead of a form with nothing to pick.
        "first_load": loading and not items and not list_error,
        "devboxes": devboxes,
        "list_msg": list_error or "No running devbox. Start one with: devbox start <name>",
        "providers": providers,
        "valid_count": len(valid),
        "mode": mode,
        "flags": flags_vm(flags),
        "flags_off": FLAGS_OFF,
        "start_summary": start_summary,
        "providers_dir": str(app.providers_dir).replace(str(Path.home()), "~"),
        "cont": cont,
        "can_start": bool(first_up) and not stopping,
    }


def stopping_vm(stopping: dict[str, Any] | None) -> str:
    """The Setup notice while Stop cleans up: Start waits for it."""
    if not stopping:
        return ""
    mode = stopping["mode"]
    what = "the route" if mode == "twin_only" else "the route and owltwin-run"
    return (
        f"Stopping the last session on {stopping['alias']}: removing {what}, then restoring "
        "the Mac proxy. Start session works once that is done."
    )


MODE_LABEL = {"full": "Full stack", "twin_only": "Twin only"}


def short_name(name: str) -> str:
    """"monday.com connector" → "monday.com"."""
    return name.removesuffix(" connector").replace(" connector (", " (")


def flags_summary(f: FlagConfig) -> str:
    return f"flags for org {f.org}" if f.enabled and f.names else "no flags"


def flags_vm(f: FlagConfig, sheet: bool = False) -> dict[str, Any]:
    """The flag card. In Session settings (sheet) rows say "on", and app.js marks what Apply
    would change."""
    names = list(dict.fromkeys([*f.names, *devbox_link.DEFAULT_FLAGS]))
    rows = []
    for n in names:
        on = n in f.names
        state = "on" if sheet and f.enabled and on else ""
        rows.append({"name": n, "on": on, "state": state, "chg": False})
    return {"enabled": f.enabled, "org": f.org, "sheet": sheet, "flags": rows}


def render_pick(app: App, error: str = "") -> str:
    return render_template("pick.html", **pick_vm(app, error))


# Setup: steps ---------------------------------------------------------------
FAILED = {
    "pac": "The Mac proxy could not be set",
    "ssh": "Can't reach the devbox over ssh",
    "tunnel": "The tunnel to the devbox did not come up",
    "route": "Couldn't point the devbox at the Twin",
    "sandbox": "Docker is not available on the devbox",
    "callback": "The OAuth callback goes to the shared devproxy",
    "flags": "Agent Studio access could not be turned on",
    "setup": "aiml-agents setup did not finish",
    "studio": "No Agent Studio port for this devbox",
}


def needs_you_title(s: Session, st: Step) -> str:
    alias = s.devbox.alias
    if st.key == "backend" and st.state == "fail":
        return f"Restart the backend on {alias}"
    titles = {
        "route": f"Allow changes on {alias}",
        "agents": f"Start aiml-agents on {alias}",
        "backend": f"Start the backend on {alias}",
        "sandbox": f"Set up the code sandbox on {alias}",
        "callback": "Wait for cloudserver",
        "flags": "Turn on Agent Studio access",
        "setup": f"Set up aiml-agents on {alias}",
        "studio": "Open Agent Studio's tunnel",
    }
    return titles.get(st.key, st.title)


def needs_you_vm(s: Session, st: Step) -> dict[str, Any]:
    """The one thing you have to do now, on top of the checklist."""
    if st.link:
        buttons = []   # a page to open (the AWS sign-in): one click, nothing to copy
    elif st.takeover:
        # A project you started yourself: stopped only on this click.
        buttons = [
            btn(f"/takeover/{st.takeover}", "Take over", "btn btn-primary"),
            btn("/recheck", "Check again"),
        ]
    elif st.key == "route" and st.state != "fail":
        buttons = [btn("/route", "Allow and continue", "btn btn-primary")]
    else:
        buttons = [btn("/recheck", "Check again")]
    failed = st.state == "fail"
    title = needs_you_title(s, st)
    return {
        "failed": failed,
        "title": FAILED.get(st.key, title) if failed else title,
        "detail": st.detail,
        "command": st.command,
        "link": st.link,
        "link_label": st.link_label or "Open",
        "buttons": buttons,
        "hint": bool(st.command or st.link),
    }


STEP_CLASS = {"running": "now", "needs_you": "now", "fail": "bad", "pending": "pend"}


def steps_vm(s: Session) -> list[dict[str, Any]]:
    out = []
    group = ""
    for st in s.steps:
        out.append({
            "group_start": st.group != group,
            "group": st.group,
            "cls": STEP_CLASS.get(st.state, ""),
            "state": st.state,
            # A step that waits for another one ("Waits for the backend…") gets a slow, quiet
            # spinner: it will start by itself. A plain pending step has not been checked yet.
            "icon": "waiting" if st.state == "pending" and st.detail else st.state,
            "title": st.title,
            "detail": st.detail,
            "took": st.took,
            "command": st.command if st.command and st.state != "ok" else "",
        })
        group = st.group
    return out


def steps_ctx(s: Session, from_running: bool) -> dict[str, Any]:
    you = next((st for st in s.steps if st.state in ("needs_you", "fail")), None)
    card = needs_you_vm(s, you) if you and not from_running else None
    done = sum(1 for st in s.steps if st.state in ("ok", "skipped"))
    return {
        "top": top_vm(s),
        "app_name": APP_NAME,
        "from_running": from_running,
        "alias": s.devbox.alias,
        "done": done,
        "pct": round(100 * done / len(s.steps)) if s.steps else 0,
        # The bar turns red while a step failed or waits for you, so a stop shows at a glance;
        # while a step runs, a light sweep over it shows that something is happening.
        "prog_cls": (
            "bad" if you and you.state == "fail" else "you" if you
            else "busy" if any(st.state == "running" for st in s.steps) else ""
        ),
        "total": len(s.steps),
        "took": int(time.time() - s.started_at),
        "card": card,
        "steps": steps_vm(s),
        "twin_only": s.mode == "twin_only",
        "flags_on": s.flags.enabled,
        # Twin only: notes about your env (None = not checked yet, or Full stack).
        "obs": obs_vm(s),
        "obs_ok": "agentconnectors and ucvserver: not running, or running with the Twin CA",
    }


def obs_vm(s: Session) -> list[dict[str, str]] | None:
    if s.mode != "twin_only" or not (s.link and s.link.reachable):
        return None
    no_ca = env_no_ca(s)
    if not no_ca:
        return []
    verb = "runs" if len(no_ca) == 1 else "run"
    return [{"title": f"{' and '.join(no_ca)} {verb} without the Twin CA"}]


def render_steps(app: App, s: Session, from_running: bool = False) -> str:
    return render_template("steps.html", **steps_ctx(s, from_running))


# Running --------------------------------------------------------------------
def health_group(name: str) -> dict[str, Any]:
    return {"tag": "", "group": name, "sep": False}


HEALTH_SEPARATOR = {"tag": "", "group": "", "sep": True}


def google_ms(host: str) -> bool:
    """A Google or Microsoft host (the devbox's gcloud and az use them too)."""
    return host.endswith(".microsoft") or any(
        host == x or host.endswith("." + x) for x in IDP_SUFFIXES
    )


def note_item(label: str, detail: str, cls: str, hm: str = "") -> dict[str, Any]:
    return {
        "tag": "", "group": "", "sep": False, "bad": False, "note": cls, "detail": detail,
        "label": label, "hm": hm, "suffix": "", "icon": "note",
    }


def health_vm(s: Session) -> list[dict[str, Any]]:
    keys = {st.key for st in s.steps}

    def item(key: str, hm: str = "") -> dict[str, Any]:
        st = s.step(key)
        bad = st.state in ("fail", "needs_you")
        suffix = ""
        if bad and key == "tunnel" and st.detail:
            suffix = f" · {st.detail.split(' (')[0]}"
        return {
            "tag": "",
            "group": "",
            "sep": False,
            "bad": bad,
            "note": "",
            "detail": st.detail,
            "label": SHORT[key],
            "hm": hm,
            "suffix": suffix,
            "icon": "fail" if st.state == "needs_you" else st.state,
        }

    out: list[dict[str, Any]] = []
    if s.mode == "twin_only":
        out += [{"group": "", "sep": False, "tag": "Twin only"}, HEALTH_SEPARATOR]
    out += [health_group("Twin"), item("pac"), item("tunnel"), item("route")]
    gm = [h for h in s.server_hosts if google_ms(h)]
    if gm:
        detail = (
            f"Google and Microsoft hosts on {s.devbox.alias} go to the Twin ({', '.join(gm)}); "
            "gcloud and az there won't sign in until Stop."
        )
        out.append(note_item("Google/Microsoft → Twin", detail, "inf"))
    flags = "flags" in keys and s.flags.enabled
    if s.mode == "full":
        # The two terminals OwlAuth Twin runs stay in the bar; the rest sits behind "+N", except a
        # step that broke or waits for you, which comes out next to them.
        rest = [
            item("sandbox", "docker"),
            item("callback", ":3030"),
            *([item("flags", f"org {s.flags.org}")] if flags else []),
            item("studio", f":{s.devbox.frontend_port or '?'}"),
        ]
        out += [
            HEALTH_SEPARATOR,
            health_group("Projects"),
            item("agents", ":8000"),
            item("backend", "taskrunner"),
            *[h for h in rest if h["bad"]],
        ]
        hidden = [h for h in rest if not h["bad"]]
        if hidden:
            out.append(more_item(hidden))
        return out
    if flags:
        org = f"org {s.flags.org}"
        out += [HEALTH_SEPARATOR, health_group("Feature flags"), item("flags", org)]
    no_ca = env_no_ca(s)
    if no_ca:
        detail = (
            f"{' and '.join(no_ca)} {'was' if len(no_ca) == 1 else 'were'} started without "
            "SSL_CERT_FILE=~/.owltwin/combined-ca.pem. Checked every 20 s."
        )
        out += [HEALTH_SEPARATOR, health_group("Your env")]
        out += [note_item(n, detail, "nt", "no Twin CA") for n in no_ca]
    return out


def more_item(items: list[dict[str, Any]]) -> dict[str, Any]:
    """"+N" in the health bar: the steps behind it, with one icon for all of them."""
    icons = {h["icon"] for h in items}
    icon = "running" if "running" in icons else "pending" if icons - {"ok", "skipped"} else "ok"
    names = ", ".join(h["label"] for h in items)
    return {"tag": "", "group": "", "sep": False, "more": {
        "label": f"+{len(items)}", "icon": icon, "items": items, "title": names,
    }}


def env_no_ca(s: Session) -> list[str]:
    """Twin only: your services that run without the Twin CA (watched, never changed)."""
    link = s.link
    return list(link.no_ca) if link and link.reachable else []


BANNER = {
    "tunnel": "The backend can't reach the Twin",
    "route": "The devbox no longer points at the Twin",
    "agents": "aiml-agents is not running",
    "backend": "The backend is not running",
    "pac": "The Mac proxy is off",
    "ssh": "The devbox is unreachable",
    "sandbox": "Chat can't run code: the sandbox is not ready",
    "callback": "The OAuth callback won't reach your ucvserver",
    "flags": "Agent Studio says access required: the org has no local flag override",
    "studio": "Agent Studio is unreachable from this Mac",
}


def banner_vm(s: Session) -> dict[str, Any] | None:
    p = next((st for st in s.problems if st.state in ("fail", "needs_you")), None)
    if not p:
        return None
    if p.takeover:
        buttons = [btn(f"/takeover/{p.takeover}", "Take over", "btn btn-primary")]
    elif p.key == "route" and p.state == "needs_you":
        buttons = [btn("/route", "Allow and continue", "btn btn-primary")]
    else:
        buttons = [btn("/recheck", "Check again")]
    if p.key == "backend" and p.state == "fail":
        title = "The backend runs without the Twin CA"
    else:
        title = BANNER.get(p.key, p.title)
    return {"title": title, "detail": p.detail, "command": p.command, "buttons": buttons}


MCP_WORDS = {
    "initialize": "Agent opened an MCP session",
    "tools/list": "Agent asked for the tool list",
}


def describe(e: Exchange) -> str:
    """What happened, in words a tester reads at a glance."""
    d = e.detail
    if e.kind == "action":
        return d.get("text", "")
    if e.kind == "authorize":
        decision = d.get("decision")
        if decision == "allowed":
            return "You clicked Allow"
        if decision == "denied":
            return "You clicked Deny"
        return "Chrome opened the Twin sign-in page"
    if e.kind in ("token", "refresh"):
        grant = d.get("grant_type", "")
        if grant == "authorization_code":
            return "Samsara traded the code for a token"
        if grant == "refresh_token":
            return "Samsara refreshed the token"
        return f"Token request ({grant or 'no grant_type'})"
    if e.kind == "revoke":
        return "Samsara revoked a token"
    if e.kind == "discovery":
        return f"Samsara read the {d.get('what', 'metadata')}"
    if e.kind == "register":
        if d.get("client_id"):
            return f"Samsara registered an OAuth client ({d.get('registered')})"
        return "Samsara tried to register an OAuth client"
    if e.kind == "mcp":
        rpc = d.get("rpc", "")
        if rpc == "tools/call":
            return f"Agent called {d.get('tool', '')}"
        return MCP_WORDS.get(rpc, f"MCP {rpc}".strip())
    return f"{e.method} {e.path}"


def who(e: Exchange) -> str:
    return e.actor.replace("product", "Samsara")


FILTERS = [
    ("all", "All"),
    ("browser", "Browser"),
    ("token", "Token"),
    ("mcp", "MCP"),
    ("problems", "Problems"),
]
TOKEN_KINDS = ("token", "refresh", "revoke", "register", "discovery")


def matches(e: Exchange, f: str) -> bool:
    if f == "browser":
        return e.listener == "browser"
    if f == "token":
        return e.kind in TOKEN_KINDS
    if f == "mcp":
        return e.kind == "mcp"
    if f == "problems":
        return e.kind != "action" and not e.ok
    return True


SCOPES = ("all", "this")
DEFAULTS = {"f": "all", "scope": "this"}


def qs(q: dict[str, str], **changes: Any) -> str:
    """A link to "/" that keeps the page's state (connector, filter, scope, detail), with changes.

    None drops a key; defaults are left out.
    """
    out = {k: v for k, v in q.items() if k in ("c", "f", "scope", "ex", "settings")}
    for k, v in changes.items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = str(v)
    out = {k: v for k, v in out.items() if v and DEFAULTS.get(k) != v}
    return "/" + ("?" + urllib.parse.urlencode(out) if out else "")


def act_vm(
    e: Exchange, sel: int | None, q: dict[str, str], names: dict[str, str],
) -> dict[str, Any]:
    key = f"{e.id}-{int(e.ts * 1000)}"
    tm = time.strftime("%H:%M:%S", time.localtime(e.ts))
    amb = bool(e.candidates)
    pv = "ambiguous" if amb else names.get(e.provider, e.provider)
    if e.kind == "action":
        return {"note": True, "key": key, "tm": tm, "text": describe(e), "pv": pv, "amb": False}
    bad = not e.ok
    fix = ""
    if e.detail.get("sent_to"):
        verb = "sent" if e.detail.get("decision") else "will send"
        port = urllib.parse.urlsplit(e.detail["sent_to"]).port
        fix = f"Callback port fixed: {verb} Chrome to :{port}"
    # A row of another connector also switches the side panel to it; an ambiguous one does not.
    switch = {} if amb or not e.provider else {"c": e.provider}
    return {
        "note": False,
        "key": key,
        "tm": tm,
        "text": describe(e),
        "pv": pv,
        "amb": amb,
        "bad": bad,
        "on": e.id == sel,
        "who": who(e),
        "injected": e.injected,
        "method": e.method,
        "path": f"{e.host}{e.path}" if e.host else e.path,
        "why": e.reason if e.reason and bad else "",
        "fix": fix,
        "status": e.status or "–",
        "st_cls": "err" if e.status >= 400 or bad else "ok",
        "href": qs(q, ex=e.id, **switch),
    }


def studio_url(s: Session) -> str:
    port = s.devbox.frontend_port
    return f"https://localhost:{port}/" if port else (s.devbox.dashboard or "#")


def conn_status(mode: str, c: dict[str, Any]) -> dict[str, Any]:
    """The Connection box's status line, and the token lines when connected."""
    since = time.strftime("%H:%M:%S", time.localtime(c["since"])) if c["since"] else ""
    out: dict[str, Any] = {"dot": "", "bold": "", "rest": "", "access": None, "refresh": ""}
    if mode == "api_key":
        if c["connected"]:
            out.update(dot="ok", bold="Working", rest=f" · first MCP call {since}")
        else:
            out.update(rest="No MCP call with the current token yet")
    elif c["connected"]:
        left = c["access_left"]
        access = {
            "token": c["access_token"][:12],
            "until": int(time.time()) + left,
            "left": f"{left // 60}:{left % 60:02d}",
        }
        out.update(
            dot="ok", bold="Connected", rest=f" since {since}" if since else "",
            access=access, refresh=c["refresh_token"][:12],
        )
    elif c["revoked"]:
        out.update(dot="bad", bold="Tokens revoked", rest=" · Samsara must reconnect")
    else:
        out.update(rest="Not connected yet")
    return out


def conn_rows(mode: str, c: dict[str, Any]) -> list[dict[str, str]]:
    """The Connection box's client and secret rows."""
    rows = []
    if mode == "dynamic" and c["client_id"]:
        rows.append({"k": "Client", "cls": "m", "v": f"{c['client_id']} · registered"})
        rows.append({"k": "Client secret", "cls": "m", "v": c["secret"]})
    elif mode == "dynamic":
        rows.append({"k": "Client", "cls": "m muted", "v": "not registered yet"})
    else:
        label = "API token" if mode == "api_key" else "Client secret"
        rows.append({"k": label, "cls": "m", "v": f"{c['secret']} · current"})
    if c["previous_secret"]:
        old = f"{c['previous_secret']} · rejected"
        rows.append({"k": "Old secret", "cls": "m muted", "v": old})
    return rows


def conn_vm(s: Session) -> dict[str, Any]:
    """The Connection box: status line, tokens, client and secrets."""
    c = s.twin.connection()
    mode = s.provider.mode
    out = conn_status(mode, c)
    out["rows"] = conn_rows(mode, c)
    registered = mode == "dynamic" and bool(c.get("client_id"))
    out["public_client"] = registered and c["secret"].startswith("none")
    return out


NOTHING_TO_PASTE = "Nothing to paste: click Connect."
NOTHING_TO_PASTE_DCR = (
    "Nothing to paste: click Connect. "
    "Samsara finds the Twin and registers a client on its own (DCR)."
)


def rail_vm(s: Session, q: dict[str, str]) -> list[dict[str, Any]]:
    """The connector switcher: one row per connector the Twin stands in for."""
    last: dict[str, Exchange] = {}
    for e in s.twins.log.all():
        if e.kind != "action" and e.provider and not e.candidates:
            last[e.provider] = e
    out = []
    for pid, st in s.twins.states.items():
        p = st.provider
        c = st.connection()
        e = last.get(pid)
        dot, line, bad = "", "Not connected", False
        if c["connected"]:
            since = f" · {ago(c['since'])}" if c["since"] else ""
            dot, line = "ok", ("Working" if p.mode == "api_key" else "Connected") + since
        elif c["revoked"]:
            dot, line = "rev", "Tokens revoked"
        if e and not e.ok and e.status >= 400:
            dot, line, bad = "bad", f"{describe(e)} · {e.status}", True
        out.append({
            "id": pid, "name": short_name(p.name), "dot": dot, "line": line, "bad": bad,
            "on": pid == s.active, "href": qs(q, c=pid, ex=None),
        })
    return out


def side_vm(s: Session) -> dict[str, Any]:
    p = s.provider
    t = s.twin

    def live(r: dict) -> str:
        # Values the Twin can change while running: the client secret and the API token.
        if r["label"] == "secret" and p.mode == "static":
            return t.client_secret
        if r["label"] == "API token" and p.mode == "api_key":
            return t.api_secret
        return r["value"]

    conn = conn_vm(s)
    if p.mode == "api_key":
        actions = [btn("/twin/rotate", "Rotate API token")]
    else:
        rotate = "Delete client registration" if conn["public_client"] else "Rotate secret"
        actions = [
            btn("/twin/expire", "Expire access token"),
            btn("/twin/rotate", rotate),
            btn("/twin/revoke", "Revoke tokens"),
        ]
    idp = None
    if p.idp_hosts:
        # Google/Microsoft sign-in: Chrome reaches the Twin for these hosts only while this is on.
        left = 0
        if s.idp_on_at:
            seconds = IDP_MINUTES * 60 - (time.time() - s.idp_on_at)
            left = max(0, int(seconds) // 60)
        on = s.idp_on_for(p)
        idp = {"on": on, "hosts": ", ".join(p.idp_hosts), "left": left if on else 0}
    return {
        "paste": [{"label": r["label"], "value": live(r)} for r in p.agent_studio],
        "nothing": NOTHING_TO_PASTE_DCR if p.mode == "dynamic" else NOTHING_TO_PASTE,
        "studio_url": studio_url(s),
        "idp": idp,
        "prompt": p.test_prompt,
        "conn": conn,
        "actions": actions,
    }


def pretty(body: str) -> str:
    try:
        return json.dumps(json.loads(body), indent=2)
    except ValueError:
        if ("=" in body and "&" in body) or body.startswith("grant_type"):
            pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
            return "\n".join(f"{k}={v}" for k, v in pairs)
        return body


SHOWN_HEADERS = ("authorization", "content-type", "mcp-session-id", "user-agent")


def amb_vm(s: Session, e: Exchange) -> list[dict[str, str]] | None:
    """What the Twin checked for a request it could not attribute (the drawer's kv rows)."""
    if not e.candidates:
        return None
    names = [short_name(st.provider.name) for pid, st in s.twins.states.items()
             if pid in e.candidates]
    form = dict(urllib.parse.parse_qsl(e.req_body, keep_blank_values=True))
    cid = e.query.get("client_id") or form.get("client_id", "")
    auth = next((v for k, v in e.req_headers.items() if k.lower() == "authorization"), "")
    sent_token = auth.startswith("Bearer ") or form.get("token") or form.get("refresh_token")
    return [
        {"k": "Host", "v": f"{e.host}: {' or '.join(names)}"},
        {"k": "client_id", "v": f"{cid} (no connector has it)" if cid else "none in the request"},
        {"k": "Token", "v": "not found" if sent_token else "none in the request"},
    ]


def drawer_vm(s: Session, ex_id: int | None, q: dict[str, str]) -> dict[str, Any] | None:
    if not ex_id:
        return None
    e = next((x for x in s.twins.log.all() if x.id == ex_id and x.kind != "action"), None)
    if not e:
        return None
    fix = e.detail.get("callback_fix", "")
    headers = [f"{k}: {v}" for k, v in e.req_headers.items() if k.lower() in SHOWN_HEADERS]
    query = "\n".join(f"{k}={v}" for k, v in e.query.items())
    req = pretty(e.req_body) if e.req_body else query
    return {
        "method": e.method,
        "path": f"{e.host}{e.path}",
        "who": who(e),
        "close": qs(q, ex=None),
        "amb": amb_vm(s, e),
        "reason": e.reason,
        "fix": fix,
        "sent_to": e.detail.get("sent_to", "").split("?")[0] if fix else "",
        "host": e.host,
        "status": e.status,
        "duration_ms": e.duration_ms,
        "headers": "\n".join(headers),
        "request": req,
        "response": pretty(e.resp_body),
        "curl": e.curl(),
        "resp_body": e.resp_body,
    }


MAX_ACTIVITY = 200


def settings_vm(s: Session) -> dict[str, Any]:
    """Session settings: read-only devbox and mode, the flag card, Apply and Remove."""
    applied = ""
    if s.flags_applied_at:
        tm = time.strftime("%H:%M", time.localtime(s.flags_applied_at))
        applied = f"Last applied {tm} · org {s.flags_applied_org}."
    return {
        "devbox": s.devbox.label,
        "mode": MODE_LABEL[s.mode],
        "flags": flags_vm(s.flags, sheet=True),
        "flags_off": FLAGS_OFF,
        "applied": applied,
        "org": s.flags.org,
        "close": "",
    }


def running_vm(s: Session, q: dict[str, str]) -> dict[str, Any]:
    f = q.get("f", "all") if q.get("f") in dict(FILTERS) else "all"
    scope = q.get("scope") if q.get("scope") in SCOPES else "this"
    ex_id = int(q["ex"]) if q.get("ex", "").isdigit() else None
    exs = s.twins.log.all() if scope == "all" else s.twin.exchanges
    counts = {k: sum(1 for e in exs if matches(e, k)) for k, _ in FILTERS}
    chips = [
        {
            "label": label,
            "count": counts[k],
            "on": k == f,
            "err": k == "problems" and bool(counts[k]),
            "href": qs(q, f=k, ex=None),
        }
        for k, label in FILTERS
    ]
    scopes = [
        {"label": "All connectors", "on": scope == "all", "href": qs(q, scope="all", ex=None)},
        {"label": "Current connector", "on": scope == "this", "href": qs(q, scope="this", ex=None)},
    ]
    names = {pid: short_name(st.provider.name) for pid, st in s.twins.states.items()}
    shown = [e for e in reversed(exs) if matches(e, f)][:MAX_ACTIVITY]
    rail = rail_vm(s, q)
    top = top_vm(s)
    if top:
        top["settings"] = qs(q, settings=1)
    settings = None
    if q.get("settings"):
        settings = settings_vm(s)
        settings["close"] = qs(q, settings=None)
    return {
        "top": top,
        "app_name": APP_NAME,
        "health": health_vm(s),
        "side": side_vm(s),
        "rail": rail,
        "current": next(r for r in rail if r["on"]),
        "scopes": scopes,
        "chips": chips,
        "banner": banner_vm(s),
        "acts": [act_vm(e, ex_id, q, names) for e in shown],
        "any_activity": bool(exs),
        "connector": short_name(s.provider.name),
        "drawer": drawer_vm(s, ex_id, q),
        "settings": settings,
    }


def render_running(app: App, s: Session, q: dict[str, str]) -> str:
    return render_template("running.html", **running_vm(s, q))


View = tuple[str, dict[str, Any], str]   # template, its view-model, page title


def view(app: App, q: dict[str, str], error: str = "") -> View:
    """Which page "/" shows now, with its view-model."""
    s = app.session
    if not s or error:
        return "pick.html", pick_vm(app, error), f"Setup · {APP_NAME}"
    if s.phase == "setup":
        return "steps.html", steps_ctx(s, False), f"Setup · {APP_NAME}"
    if q.get("view") == "setup":
        return "steps.html", steps_ctx(s, True), f"Setup details · {APP_NAME}"
    # ?c= picks the connector the panel shows; it changes nothing in the Twin.
    if q.get("c") and q["c"] != s.active:
        app.set_active(q["c"])
    q = {**q, "c": s.active}
    mark = "✗ " if s.problems else "● "
    return "running.html", running_vm(s, q), f"{mark}Running · {APP_NAME}"


def render(app: App, q: dict[str, str]) -> tuple[str, str]:
    """The fragment inside #live and the title, as an X-Fragment request gets them."""
    template, ctx, title = view(app, q)
    return render_template(template, **ctx), title


# HTTP ----------------------------------------------------------------------
LOCAL_HOSTS = ("127.0.0.1", "localhost")


def is_local(url: str) -> bool:
    return urllib.parse.urlsplit(url).hostname in LOCAL_HOSTS


def create_app(app: App) -> Flask:
    """The panel as a Flask app. Templates are rendered by templating.py, shared with twin.py."""
    panel = Flask(__name__, static_folder=str(STATIC), static_url_path="/static")

    def forbidden() -> Response:
        return Response("forbidden", 403, mimetype="text/plain")

    def see_other(where: str) -> Response:
        return redirect(where, code=303)

    def back() -> str:
        """Where a button sends you after it ran: the page it was on."""
        referer = request.headers.get("Referer") or "/"
        return referer if is_local(referer) else "/"

    def show(v: View) -> Response:
        template, ctx, title = v
        if request.headers.get("X-Fragment"):
            html = render_template(template, **ctx)
            return jsonify(html=html, title=title, v=app.version)
        return Response(page(title, template, ctx), mimetype="text/html")

    def with_session(action: Callable[[], object]) -> Response:
        if not app.session:
            return see_other("/")
        # Act on the connector of the page the button was on. Another panel tab that shows a
        # different connector switches the active one each time it refreshes.
        page = urllib.parse.urlsplit(back()).query
        c = urllib.parse.parse_qs(page).get("c", [""])[0]
        if c:
            app.set_active(c)
        action()
        return see_other(back())

    @panel.before_request
    def local_only() -> Response | None:
        # Only this Mac, by name: a DNS-rebinding page has some other Host.
        if request.host.split(":")[0] not in LOCAL_HOSTS:
            return forbidden()
        # Same-origin form posts only.
        origin = request.headers.get("Origin")
        if request.method == "POST" and origin and not is_local(origin):
            return forbidden()
        return None

    @panel.after_request
    def no_store(resp: Response) -> Response:
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @panel.get("/")
    def home() -> Response:
        if request.args.get("refresh"):
            app.devboxes.refresh()
            return see_other("/")   # live updates must not re-trigger the scan
        return show(view(app, request.args.to_dict()))

    @panel.get("/start")
    @panel.get("/setup")
    @panel.get("/test")
    def old_pages() -> Response:
        return see_other("/")

    @panel.get("/owltwin.pac")
    def pac() -> Response:
        script = pac_script(app._browser_hosts(), app.proxy_port)
        return Response(script, mimetype="application/x-ns-proxy-autoconfig")

    @panel.get("/api/wait")
    def wait() -> Response:
        since = request.args.get("v", "0")
        since_v = int(since) if since.isdigit() else 0
        with app.changed:
            if app.version <= since_v:
                app.changed.wait(timeout=25)
        return jsonify(v=app.version)

    @panel.post("/resume")
    def resume() -> Response:
        err = app.resume_session()
        return show(view(app, {}, err)) if err else see_other("/")

    def form_flags() -> FlagConfig | str:
        names = [*request.form.getlist("flag"), request.form.get("flag_add", "")]
        return parse_flags(request.form.get("flags") == "1", request.form.get("org", ""), names)

    @panel.post("/session")
    def start() -> Response:
        mode = request.form.get("mode", "full")
        flags = form_flags()
        if isinstance(flags, str):
            err = flags
        elif mode not in MODES:
            err = "Unknown mode"
        else:
            err = app.start_session(
                request.form.get("devbox", ""), request.form.get("provider", ""),
                mode=mode, flags=flags,
            )
        return show(view(app, {}, err)) if err else see_other("/")

    @panel.post("/settings/flags")
    def settings_flags() -> Response:
        flags = form_flags()
        if isinstance(flags, str):
            if app.session:
                app.session.twin.note(f"Flags not applied: {flags}")
            return see_other(back())
        return with_session(lambda: app.update_flags(flags))

    @panel.post("/settings/flags/remove")
    def settings_flags_remove() -> Response:
        org = request.form.get("org", "")
        return with_session(lambda: app.remove_flags(int(org)) if org.isdigit() else None)

    @panel.post("/stop")
    def stop() -> Response:
        app.request_stop()  # returns at once; Setup shows Stopping until the devbox is clean
        return see_other("/")

    @panel.post("/route")
    def route() -> Response:
        return with_session(app.apply_route)

    @panel.post("/recheck")
    def recheck() -> Response:
        return with_session(lambda: app.recheck(retry=True))

    @panel.post("/idp/<any(on, off):state>")
    def idp(state: str) -> Response:
        return with_session(lambda: app.set_idp(state == "on"))

    @panel.post("/takeover/<any(agents, backend):project>")
    def takeover(project: str) -> Response:
        return with_session(lambda: app.take_over(project))

    @panel.post("/twin/<any(expire, rotate, revoke):action>")
    def twin_action(action: str) -> Response:
        return with_session(lambda: app.twin_action(action))

    return panel


class QuietHandler(WSGIRequestHandler):
    """No access log: the panel long-polls every few seconds."""

    def log(self, type: str, message: str, *args: Any) -> None:
        return


def serve(app: App) -> BaseWSGIServer:
    """The panel server; the caller runs serve_forever in a thread.

    The socket is bound here so a port in use raises OSError (EADDRINUSE) for __main__ to explain,
    instead of Werkzeug printing and exiting.
    """
    sock = socket.create_server(("127.0.0.1", app.panel_port))
    try:
        srv = make_server(
            "127.0.0.1", app.panel_port, create_app(app),
            threaded=True, request_handler=QuietHandler, fd=sock.fileno(),
        )
    finally:
        sock.close()   # make_server works on its own duplicate of the socket
    srv.daemon_threads = True
    return srv
