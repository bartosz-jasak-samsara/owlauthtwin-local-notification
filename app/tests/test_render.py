"""Panel and consent rendering, the panel's routes, and auto-escaping. python -m unittest"""

import dataclasses
import html.parser
import threading
import time
import types
import unittest
from pathlib import Path

from owltwin_app import twin as twin_mod
from owltwin_app import web
from owltwin_app.app import Session, Step
from owltwin_app.config import scan
from owltwin_app.devbox import Devbox
from owltwin_app.twin import TwinRegistry, TwinState

PROVIDERS = Path(__file__).resolve().parents[2] / "providers"
ENTRIES = scan(PROVIDERS)
BY_FILE = {e.file.name: e for e in ENTRIES}
EVIL = '<script>alert("x")</script> & "q" \'s'
STEPS = [
    ("certs", "Mac"),
    ("pac", "Mac"),
    ("ssh", "Devbox"),
    ("tunnel", "Devbox"),
    ("route", "Devbox"),
    ("setup", "Projects"),
    ("agents", "Projects"),
    ("sandbox", "Projects"),
    ("backend", "Projects"),
    ("callback", "Projects"),
    ("flags", "Projects"),
    ("studio", "Projects"),
]


class Tags(html.parser.HTMLParser):
    """Collects (tag, attrs) and text so tests can assert on structure, not on whitespace."""

    def __init__(self, text: str):
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.text: list[str] = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def handle_data(self, data):
        self.text.append(data)

    def find(self, tag: str, **attrs: str) -> list[dict[str, str | None]]:
        found = []
        for name, a in self.tags:
            if name == tag and all(a.get(k) == v for k, v in attrs.items()):
                found.append(a)
        return found

    def with_attr(self, attr: str) -> list[dict[str, str | None]]:
        return [a for _, a in self.tags if attr in a]

    def has_class(self, cls: str) -> bool:
        return any(cls in (a.get("class") or "").split() for _, a in self.tags)

    @property
    def all_text(self) -> str:
        return "".join(self.text)


def devbox(alias: str = "devbox-1", ok: bool = True) -> Devbox:
    return Devbox(
        index=1, name=f"box{alias[-1]}", alias=alias, region="example-region",
        ssh_ok=ok, dashboard="https://localhost:1/",
    )


class FakeApp:
    """What web.py reads from App, plus a record of the actions the routes asked for."""

    def __init__(self, items=(), loading=False, error="", last=None, ents=None, session=None):
        self.devboxes = types.SimpleNamespace(
            lock=threading.Lock(), items=list(items), loading=loading, error=error,
            refresh=lambda: self.calls.append("refresh"),
        )
        self.session = session
        self.providers_dir = PROVIDERS
        self.proxy_port = 18201
        self.version = 7
        self.changed = threading.Condition()
        self.calls: list[str] = []
        self.start_error = ""
        self.stopping = None
        self.stop_error = ""
        self._last = last
        self._ents = ENTRIES if ents is None else ents

    def last_session(self):
        return self._last

    def provider_entries(self):
        return self._ents

    def _browser_hosts(self):
        return ["auth.monday.com"]

    def start_session(self, devbox_alias, provider_file, mode="full", flags=None):
        f = f" flags={flags.org}:{','.join(flags.names)}" if flags and flags.enabled else ""
        self.calls.append(f"start {devbox_alias} {provider_file} {mode}{f}")
        return self.start_error

    def set_active(self, pid):
        if self.session and pid in self.session.twins.states:
            self.session.active = pid

    def update_flags(self, flags):
        self.calls.append(f"flags {flags.enabled} {flags.org} {','.join(flags.names)}")

    def remove_flags(self, org):
        self.calls.append(f"remove flags {org}")

    def resume_session(self):
        self.calls.append("resume")
        return ""

    def request_stop(self):
        self.calls.append("stop")

    def apply_route(self):
        self.calls.append("route")

    def recheck(self, retry=False):
        self.calls.append(f"recheck retry={retry}")

    def set_idp(self, on):
        self.calls.append(f"idp {on}")

    def take_over(self, project):
        self.calls.append(f"takeover {project}")

    def twin_action(self, action):
        self.calls.append(f"twin {action}")


def session(
    pfile: str, states=None, running: bool = True, others=(), mode="full", **step_extra,
) -> Session:
    """A session showing pfile; `others` are more connectors the Twin stands in for."""
    p = BY_FILE[pfile].provider
    twins = TwinRegistry([p, *(BY_FILE[o].provider for o in others)], lambda: None)
    s = Session(
        devbox=devbox(), twins=twins, active=p.id, mode=mode,
        browser_port=1, server_port=2, started_at=time.time() - 42,
    )
    twins.active = lambda: s.active
    states = states or {}
    s.steps = [
        Step(key, group, f"Title {key}", states.get(key, "ok"), f"detail of {key}", "3 s")
        for key, group in STEPS
    ]
    for key, extra in step_extra.items():
        for attr, v in extra.items():
            setattr(s.step(key), attr, v)
    if running:
        s.running_since = time.time() - 600
    return s


EXCHANGE_FIELDS = ("listener", "method", "host", "path", "query", "req_headers", "req_body")


def add_ex(t: TwinState, **kw):
    """An exchange as the Twin records it: new_exchange's fields, then the outcome fields."""
    fields = {
        "listener": "server",
        "method": "POST",
        "host": "mcp.monday.com",
        "path": "/mcp",
        "query": {},
        "req_headers": {"Content-Type": "application/json"},
        "req_body": '{"a":1}',
    }
    fields.update({k: v for k, v in kw.items() if k in EXCHANGE_FIELDS})
    ex = t.new_exchange(**fields)
    for k, v in kw.items():
        if k not in EXCHANGE_FIELDS:
            setattr(ex, k, v)
    t.record(ex)
    return ex


def activity(s: Session) -> None:
    """A note and three exchanges (authorize, a failed token call, an MCP call), all with EVIL."""
    t = s.twin
    t.note("You rotated " + EVIL)
    add_ex(
        t, kind="authorize", listener="browser", method="GET",
        host="auth.monday.com", path="/mcp/authorize", query={"client_id": EVIL}, req_body="",
        ok=True, status=200,
        detail={
            "decision": "",
            "sent_to": "http://localhost:33000/r/oauth/callback?code=1",
            "callback_fix": EVIL,
        },
    )
    add_ex(
        t, kind="token", host="auth.monday.com", path="/mcp/token",
        req_body="grant_type=authorization_code&code=" + EVIL,
        detail={"grant_type": "authorization_code"},
        ok=False, status=401, reason=EVIL, resp_body='{"error": "invalid_client"}',
    )
    add_ex(
        t, kind="mcp", detail={"rpc": "tools/call", "tool": EVIL},
        ok=True, status=200, injected=True, resp_body='{"x": "<b>"}',
    )


def running(pfile: str, prep=None, q=None, **kw) -> tuple[Tags, str, str]:
    s = session(pfile, **kw)
    if prep:
        prep(s)
    body, title = web.render(FakeApp(session=s), q or {})
    return Tags(body), body, title


def assert_escaped(tc: unittest.TestCase, body: str) -> None:
    """EVIL went in somewhere; it must come out as text, never as markup or a broken attribute.

    The one script a full page has is the panel's own app.js.
    """
    tc.assertNotIn("<script>", body)
    tc.assertNotIn('alert("x")', body)
    tc.assertIn("&lt;script&gt;", body)
    scripts = [a.get("src") for a in Tags(body).find("script")]
    tc.assertTrue(all(src == "/static/app.js" for src in scripts), scripts)


class PickTest(unittest.TestCase):
    def test_devboxes_and_providers(self):
        bad = types.SimpleNamespace(
            file=Path("bad.yaml"), provider=None,
            error=types.SimpleNamespace(problems=[EVIL, "two"]),
        )
        boxes = [devbox("devbox-1"), devbox("devbox-2", ok=False)]
        body = web.render_pick(FakeApp(boxes, ents=ENTRIES + [bad]))
        t = Tags(body)
        self.assertEqual(len(t.find("form", action="/session", method="post")), 1)
        devs = [a["value"] for a in t.find("input", type="radio", name="devbox")]
        self.assertIn("devbox-1", devs)
        provs = {a["value"] for a in t.find("input", type="radio", name="provider")}
        self.assertTrue({"workday.yaml", "monday.yaml", "atlassian.yaml"} <= provs)
        self.assertNotIn("bad.yaml", provs)   # a provider that does not lint cannot be picked
        self.assertIn("bad.yaml", t.all_text)
        assert_escaped(self, body)

    def test_loading_error_and_last_session(self):
        last = {
            "devbox": "devbox-1",
            "provider_file": "monday.yaml",
            "saved_at": time.time() - 3600,
        }
        body = web.render_pick(FakeApp(loading=True, error=EVIL, last=last), EVIL)
        assert_escaped(self, body)
        self.assertTrue(Tags(body).find("button", formaction="/resume"))

    def test_first_devbox_list_shows_a_loader(self):
        t = Tags(web.render_pick(FakeApp(loading=True)))
        self.assertIn("Looking for running devboxes", t.all_text)
        self.assertFalse(t.find("input", type="radio"))      # nothing to pick yet
        self.assertFalse(t.find("button", type="submit"))
        t = Tags(web.render_pick(FakeApp([devbox()], loading=True)))   # Refresh keeps the form
        self.assertTrue(t.find("input", type="radio", name="devbox"))

    def test_stopping_blocks_start(self):
        last = {"devbox": "devbox-1", "provider_file": "monday.yaml", "saved_at": time.time()}
        app = FakeApp([devbox()], last=last)
        app.stopping = {"alias": "devbox-1", "mode": "full", "since": time.time()}
        t = Tags(web.render_pick(app))
        self.assertIn("Stopping", t.all_text)
        self.assertIn("Stopping the last session on devbox-1", t.all_text)
        self.assertFalse(t.find("form", action="/stop"))     # nothing left to click twice
        for b in t.find("button", type="submit"):
            if b.get("formaction") == "/resume" or "formaction" not in b:
                self.assertIn("disabled", b)
        app.stopping, app.stop_error = None, f"Stop could not clean up devbox-1: {EVIL}"
        body = web.render_pick(app)
        assert_escaped(self, body)
        self.assertIn("Stop could not clean up devbox-1", Tags(body).all_text)


class StepsTest(unittest.TestCase):
    def test_needs_you_card(self):
        states = {"route": "needs_you", "agents": "running", "backend": "pending"}
        command = "sudo x\nsudo y " + EVIL
        s = session("workday.yaml", states, running=False, route={"command": command})
        body = web.render_steps(None, s)
        t = Tags(body)
        self.assertTrue(t.has_class("youcard"), "needs_you card is shown")
        copies = [a["data-copy"] for a in t.with_attr("data-copy")]
        self.assertIn(command, copies)   # the attribute round-trips the exact command
        assert_escaped(self, body)
        self.assertTrue(t.find("form", action="/route", method="post"))

    def test_fail_card(self):
        s = session(
            "workday.yaml", {"backend": "fail"}, running=False,
            backend={"detail": EVIL, "takeover": "backend"},
        )
        body = web.render_steps(None, s)
        t = Tags(body)
        self.assertTrue(t.has_class("youcard"))
        self.assertIn(EVIL, t.all_text)
        self.assertTrue(t.find("form", action="/takeover/backend", method="post"))
        assert_escaped(self, body)

    def test_setup_details_view(self):
        body, title = web.render(FakeApp(session=session("workday.yaml")), {"view": "setup"})
        self.assertIn("Setup details", title)
        self.assertFalse(Tags(body).has_class("youcard"))


def dcr_connected(s: Session) -> None:
    s.twin.clients["monday-dcr-1"] = {
        "auth": "client_secret_post",
        "secret": "sec" + EVIL,
        "previous_secret": "",
        "redirect_uris": [],
        "created": time.time(),
    }
    s.twin.issue_tokens("s", client_id="monday-dcr-1")
    activity(s)


class RunningTest(unittest.TestCase):
    def test_health_keeps_two_terminals_and_hides_the_rest(self):
        def labels(items):
            return [h.get("label") for h in items if "label" in h]

        h = web.health_vm(session("gmail.yaml"))
        self.assertEqual(labels(h)[-2:], ["aiml-agents", "backend"])
        more = h[-1]["more"]
        self.assertEqual(more["label"], f"+{len(more['items'])}")
        self.assertIn("sandbox", labels(more["items"]))
        self.assertEqual(more["icon"], "ok")
        # A step that broke comes out of "+N", next to the terminals.
        h = web.health_vm(session("gmail.yaml", {"sandbox": "fail", "callback": "running"}))
        self.assertIn("sandbox", labels(h))
        self.assertNotIn("sandbox", labels(h[-1]["more"]["items"]))
        self.assertEqual(h[-1]["more"]["icon"], "running")

    def test_static_connected(self):
        t, _, title = running("workday.yaml", lambda s: s.twin.issue_tokens("s"))
        self.assertTrue(title.startswith("● Running"))
        self.assertTrue(t.find("form", action="/twin/rotate", method="post"))
        self.assertTrue(t.find("form", action="/twin/revoke", method="post"))

    def test_dynamic_activity_filters_drawer(self):
        t, body, _ = running("monday.yaml", dcr_connected, {"ex": "2"})
        self.assertIn("monday-dcr-1", t.all_text)
        filters = [a["href"] for a in t.find("a") if "f=" in (a.get("href") or "")]
        self.assertIn("/?c=monday&f=problems", filters)
        self.assertEqual(len(t.with_attr("data-ex")), 4)   # the note and three exchanges
        self.assertTrue(t.has_class("drawer"))
        # ex=2 is the authorize exchange (the note is 1).
        self.assertIn("Request · auth.monday.com", t.all_text)
        assert_escaped(self, body)

        t, _, _ = running("monday.yaml", dcr_connected, {"f": "token"})
        rows = t.with_attr("data-ex")
        self.assertEqual(len(rows), 1)
        self.assertIn("ex=", rows[0]["href"])
        self.assertIn("f=token", rows[0]["href"])
        self.assertFalse(t.has_class("drawer"))

    def test_api_key(self):
        t, _, _ = running("atlassian.yaml", lambda s: setattr(s.twin, "api_ok_at", time.time() - 5))
        self.assertTrue(t.find("form", action="/twin/rotate", method="post"))
        self.assertFalse(t.find("form", action="/twin/revoke", method="post"))
        copies = [a["data-copy"] for a in t.with_attr("data-copy")]
        self.assertIn("atl-api-token-v1", copies)

    def test_banner_problem(self):
        _, body, title = running(
            "workday.yaml", states={"tunnel": "fail"}, tunnel={"detail": EVIL},
        )
        self.assertTrue(title.startswith("✗"))
        assert_escaped(self, body)


class ConsentTest(unittest.TestCase):
    def test_consent_escapes_request_fields(self):
        p = BY_FILE["workday.yaml"].provider
        q = {
            "client_id": EVIL,
            "redirect_uri": "http://localhost:3000/cb?x=" + EVIL,
            "state": "s&t",
            "scope": "",
        }
        body = twin_mod.consent_page(
            p, q, sends_to="http://localhost:3000/cb?x=1", armed="Armed " + EVIL,
        )
        assert_escaped(self, body)
        t = Tags(body)
        links = [a["href"] for a in t.find("a")]
        self.assertTrue(any("decision=approve" in h for h in links))
        self.assertTrue(any("decision=deny" in h for h in links))
        self.assertTrue(all("<" not in h for h in links))
        self.assertIn(EVIL, t.all_text)
        self.assertIn(p.consent_title, t.all_text)

    def test_consent_errors(self):
        p = BY_FILE["workday.yaml"].provider
        body = twin_mod.consent_page(p, {"client_id": EVIL}, error=[EVIL, "PKCE missing"])
        assert_escaped(self, body)
        self.assertIn("PKCE missing", Tags(body).all_text)

    def test_yaml_fields_escaped(self):
        p = BY_FILE["workday.yaml"].provider
        evil = dataclasses.replace(p, consent_title=EVIL, name=EVIL)
        body = twin_mod.consent_page(evil, {"client_id": "c", "redirect_uri": "r", "state": "s"})
        assert_escaped(self, body)
        self.assertIn(EVIL, Tags(body).all_text)

    def test_yaml_fields_escaped_in_panel(self):
        s = session("workday.yaml")
        s.twin.provider = dataclasses.replace(s.provider, name=EVIL, test_prompt=EVIL)
        body, _ = web.render(FakeApp(session=s), {})
        assert_escaped(self, body)


LOCAL = {"Host": "127.0.0.1:18200"}


class PanelRoutesTest(unittest.TestCase):
    def client(self, app: FakeApp):
        return web.create_app(app).test_client()

    def test_full_page(self):
        r = self.client(FakeApp([devbox()])).get("/", headers=LOCAL)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.content_type.startswith("text/html"))
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        body = r.get_data(as_text=True)
        self.assertTrue(body.lower().startswith("<!doctype html>"))
        t = Tags(body)
        self.assertEqual(len(t.find("div", id="live")), 1)
        self.assertTrue(t.find("script", src="/static/app.js"))
        self.assertTrue(t.find("form", action="/session", method="post"))

    def test_fragment(self):
        c = self.client(FakeApp([devbox()]))
        r = c.get("/", headers={**LOCAL, "X-Fragment": "1"})
        self.assertEqual(r.content_type, "application/json")
        data = r.get_json()
        self.assertEqual(data["v"], 7)
        self.assertIn("Setup", data["title"])
        self.assertNotIn("<!doctype", data["html"].lower())
        self.assertNotIn('id="live"', data["html"])
        self.assertTrue(Tags(data["html"]).find("form", action="/session", method="post"))
        full = c.get("/", headers=LOCAL).get_data(as_text=True)
        self.assertIn(data["html"].strip()[:200], full)   # the fragment is what #live holds

    def test_static_and_pac(self):
        c = self.client(FakeApp())
        r = c.get("/static/app.js", headers=LOCAL)
        self.assertEqual(r.status_code, 200)
        self.assertIn("javascript", r.content_type)
        r.close()
        self.assertEqual(c.get("/static/../web.py", headers=LOCAL).status_code, 404)
        r = c.get("/owltwin.pac", headers=LOCAL)
        self.assertEqual(r.content_type, "application/x-ns-proxy-autoconfig")
        self.assertIn("auth.monday.com", r.get_data(as_text=True))

    def test_wait_returns_version(self):
        r = self.client(FakeApp()).get("/api/wait?v=1", headers=LOCAL)
        self.assertEqual(r.get_json(), {"v": 7})

    def test_refresh_redirects(self):
        app = FakeApp()
        r = self.client(app).get("/?refresh=1", headers=LOCAL)
        self.assertEqual((r.status_code, r.headers["Location"]), (303, "/"))
        self.assertEqual(app.calls, ["refresh"])

    def test_host_and_origin_checks(self):
        app = FakeApp()
        c = self.client(app)
        self.assertEqual(c.get("/", headers={"Host": "evil.test"}).status_code, 403)
        self.assertEqual(c.get("/", headers={"Host": "localhost:18200"}).status_code, 200)
        r = c.post("/stop", headers={**LOCAL, "Origin": "https://evil.test"})
        self.assertEqual(r.status_code, 403)
        r = c.post("/stop", headers={**LOCAL, "Origin": "http://127.0.0.1:18200"})
        self.assertEqual(r.status_code, 303)
        self.assertEqual(app.calls, ["stop"])

    def test_session_start_and_error(self):
        app = FakeApp([devbox()])
        c = self.client(app)
        form = {"devbox": "devbox-1", "provider": "monday.yaml"}
        r = c.post("/session", data=form, headers=LOCAL)
        self.assertEqual((r.status_code, r.headers["Location"]), (303, "/"))
        self.assertEqual(app.calls, ["start devbox-1 monday.yaml full"])

        app.start_error = EVIL
        r = c.post("/session", data=form, headers=LOCAL)
        self.assertEqual(r.status_code, 200)
        assert_escaped(self, r.get_data(as_text=True))

    def test_session_actions(self):
        app = FakeApp(session=session("workday.yaml"))
        c = self.client(app)
        referer = {**LOCAL, "Referer": "http://127.0.0.1:18200/?f=token"}
        for path in ("/route", "/recheck", "/idp/on", "/idp/off", "/takeover/agents",
                     "/twin/expire", "/twin/rotate", "/twin/revoke"):
            r = c.post(path, headers=referer)
            self.assertEqual(r.status_code, 303, path)
            self.assertEqual(r.headers["Location"], "http://127.0.0.1:18200/?f=token", path)
        expected = [
            "route", "recheck retry=True", "idp True", "idp False", "takeover agents",
            "twin expire", "twin rotate", "twin revoke",
        ]
        self.assertEqual(app.calls, expected)

    def test_session_popover_says_how_to_attach_to_tmux(self):
        t, body, _ = running("workday.yaml")
        self.assertIn("ssh devbox-1 -t tmux attach -t owltwin-run", body)
        pop = body.split('aria-label="Session"')[1].split("</details>")[0]
        for window in ("setup", "backend", "agents"):
            self.assertIn(f'<span class="k">{window}</span>', pop)

    def test_actions_use_the_connector_of_their_page(self):
        # Another tab showing Gmail made it active; the button was clicked on Microsoft 365.
        s = session("gmail.yaml", others=("microsoft-365.yaml",))
        app = FakeApp(session=s)
        seen = []
        app.set_idp = lambda on: seen.append(s.active)
        ref = {**LOCAL, "Referer": "http://127.0.0.1:18200/?c=microsoft-365"}
        self.client(app).post("/idp/on", headers=ref)
        self.assertEqual(seen, ["microsoft-365"])

    def test_actions_reject_unknown_and_foreign_referer(self):
        app = FakeApp(session=session("workday.yaml"))
        c = self.client(app)
        self.assertEqual(c.post("/takeover/sshd", headers=LOCAL).status_code, 404)
        self.assertEqual(c.post("/twin/delete", headers=LOCAL).status_code, 404)
        r = c.post("/route", headers={**LOCAL, "Referer": "https://evil.test/x"})
        self.assertEqual(r.headers["Location"], "/")
        self.assertEqual(app.calls, ["route"])

    def test_actions_without_session(self):
        app = FakeApp()
        r = self.client(app).post("/twin/rotate", headers=LOCAL)
        self.assertEqual((r.status_code, r.headers["Location"]), (303, "/"))
        self.assertEqual(app.calls, [])



class AllConnectorsTest(unittest.TestCase):
    OTHERS = ("gmail.yaml", "google-calendar.yaml", "atlassian.yaml")

    def test_rail_scope_and_badges(self):
        def prep(s):
            add_ex(s.twin, kind="mcp", detail={"rpc": "tools/list"}, ok=True, status=200)
            g = s.twins.states["gmail"]
            add_ex(g, kind="mcp", host="gmailmcp.googleapis.com", path="/mcp/v1",
                   detail={"rpc": "tools/list"}, ok=True, status=200)
            amb = add_ex(g, kind="revoke", host="oauth2.googleapis.com", path="/revoke",
                         req_body="token=x", ok=False, status=400, reason="unknown " + EVIL)
            amb.candidates = ["gmail", "google-calendar"]

        t, body, _ = running("monday.yaml", prep, {"scope": "all"}, others=self.OTHERS)
        assert_escaped(self, body)
        rail = [a["href"] for a in t.find("a") if "pi" in (a.get("class") or "").split()]
        # one row per connector in the rail and again in the compact menu
        self.assertEqual(len(rail), 2 * 4)
        self.assertIn("/?scope=all&c=gmail", rail)
        self.assertTrue(t.has_class("pvb"))
        self.assertTrue(t.has_class("amb"))
        rows = {a["data-ex"]: a.get("href") for a in t.with_attr("data-ex")}
        hrefs = [h for h in rows.values() if h]
        # a Gmail row switches the side panel to Gmail; the ambiguous one keeps monday
        self.assertTrue(any("c=gmail" in h for h in hrefs))
        self.assertTrue(any("ex=3" in h and "c=monday" in h for h in hrefs))
        problems = next(a for a in t.find("a") if "f=problems" in (a.get("href") or ""))
        self.assertIsNotNone(problems)

        t, _, _ = running("monday.yaml", prep, others=self.OTHERS)   # default: this connector
        self.assertEqual(len(t.with_attr("data-ex")), 1)

    def test_ambiguous_drawer(self):
        def prep(s):
            amb = add_ex(s.twin, kind="revoke", host="oauth2.googleapis.com", path="/revoke",
                         req_body="token=x", ok=False, status=400)
            amb.candidates = ["gmail", "google-calendar"]

        t, _, _ = running("gmail.yaml", prep, {"ex": "1"}, others=("google-calendar.yaml",))
        text = t.all_text
        self.assertIn("Connector · ambiguous", text)
        self.assertIn("oauth2.googleapis.com: Gmail or Google Calendar", text)
        self.assertIn("none in the request", text)
        self.assertIn("not found", text)

    def test_switching_shows_other_connector(self):
        app = FakeApp(session=session("monday.yaml", others=self.OTHERS))
        body, _ = web.render(app, {"c": "atlassian"})
        self.assertEqual(app.session.active, "atlassian")
        copies = [a["data-copy"] for a in Tags(body).with_attr("data-copy")]
        self.assertIn("atl-api-token-v1", copies)
        web.render(app, {"c": "nope"})
        self.assertEqual(app.session.active, "atlassian")

    def test_google_ms_health_note(self):
        t, _, _ = running("monday.yaml", others=self.OTHERS)
        notes = [a for a in t.find("span") if "inf" in (a.get("class") or "").split()]
        self.assertEqual(len(notes), 1)
        self.assertIn("oauth2.googleapis.com", notes[0]["title"])
        self.assertIn("gcloud and az", notes[0]["title"])
        self.assertNotIn("socat", notes[0]["title"])

    def test_idp_intercept_follows_connector(self):
        s = session("gmail.yaml", others=("google-calendar.yaml", "monday.yaml"))
        s.idp_on_at, s.idp_for = time.time(), "gmail"
        self.assertTrue(web.side_vm(s)["idp"]["on"])
        s.active = "google-calendar"   # same Google sign-in hosts
        self.assertTrue(web.side_vm(s)["idp"]["on"])
        s.active = "monday"
        self.assertIsNone(web.side_vm(s)["idp"])

    def test_selected_scope_and_connector_are_marked(self):
        _, body, _ = running("monday.yaml", others=self.OTHERS, q={"scope": "this"})
        self.assertIn('role="tab" class="on" aria-selected="true">Current connector', body)
        self.assertIn('aria-current="true"', body)
        self.assertNotIn("&#34;", body)

    def test_settings_sheet(self):
        t, body, _ = running("monday.yaml", q={"settings": "1"})
        self.assertTrue(t.has_class("sheet"))
        self.assertTrue(t.find("form", action="/settings/flags", method="post"))
        self.assertTrue(t.find("form", action="/settings/flags/remove", method="post"))
        flags = {a["value"] for a in t.find("input", name="flag")}
        self.assertEqual(flags, {"agent-studio-enabled", "credits-experience-enabled"})
        self.assertIn("Remove overrides for org 205", t.all_text)
        t, _, _ = running("monday.yaml")
        self.assertFalse(t.has_class("sheet"))
        self.assertTrue([a for a in t.find("a") if a.get("href") == "/?c=monday&settings=1"])


class TwinOnlyTest(unittest.TestCase):
    def twin_only(self, no_ca=(), running_=False):
        from owltwin_app.devbox_link import LinkStatus

        s = session("monday.yaml", running=running_, mode="twin_only")
        s.steps = [st for st in s.steps if st.group in ("Mac", "Devbox")]
        s.flags.enabled = False
        s.link = LinkStatus(reachable=True, no_ca=list(no_ca))
        return s

    def test_steps_note_never_blocks(self):
        s = self.twin_only(("agentconnectors", "ucvserver"))
        t = Tags(web.render_steps(None, s))
        self.assertTrue(t.has_class("obs"))
        self.assertIn("agentconnectors and ucvserver run without the Twin CA", t.all_text)
        self.assertIn("Not in Twin only", t.all_text)
        self.assertIn("feature flags", t.all_text)
        self.assertFalse(s.problems)   # the note is not a step

    def test_running_health(self):
        s = self.twin_only(("ucvserver",), running_=True)
        body, _ = web.render(FakeApp(session=s), {})
        t = Tags(body)
        self.assertIn("Twin only", t.all_text)
        self.assertIn("Your env", t.all_text)
        self.assertFalse([1 for a in t.tags if "Projects" in str(a)])
        self.assertNotIn("aiml-agents", t.all_text)


class SetupFormTest(unittest.TestCase):
    def test_pick_has_modes_and_flags(self):
        t = Tags(web.render_pick(FakeApp([devbox()])))
        modes = [a["value"] for a in t.find("input", name="mode")]
        self.assertEqual(modes, ["full", "twin_only"])
        self.assertIn("checked", t.find("input", name="flags", type="checkbox")[0])
        self.assertEqual(t.find("input", name="org")[0]["value"], "205")
        self.assertIn("all 13 at once", t.all_text)

    def test_session_form(self):
        app = FakeApp([devbox()])
        c = web.create_app(app).test_client()
        form = {
            "devbox": "devbox-1", "provider": "gmail.yaml", "mode": "twin_only", "flags": "1",
            "org": "77", "flag": ["agent-studio-enabled"], "flag_add": "my-flag",
        }
        r = c.post("/session", data=form, headers=LOCAL)
        self.assertEqual(r.status_code, 303)
        started = "start devbox-1 gmail.yaml twin_only flags=77:agent-studio-enabled,my-flag"
        self.assertEqual(app.calls, [started])
        r = c.post("/session", data={**form, "org": "x;rm"}, headers=LOCAL)
        self.assertEqual(r.status_code, 200)
        self.assertIn("Org ID must be a number", r.get_data(as_text=True))
        r = c.post("/session", data={**form, "flag_add": "$(x)"}, headers=LOCAL)
        self.assertIn("Not a flag name", r.get_data(as_text=True))

    def test_settings_routes(self):
        app = FakeApp(session=session("monday.yaml"))
        c = web.create_app(app).test_client()
        c.post("/settings/flags", data={"flags": "1", "org": "9", "flag": "a-b"}, headers=LOCAL)
        c.post("/settings/flags", data={}, headers=LOCAL)
        c.post("/settings/flags/remove", data={"org": "9"}, headers=LOCAL)
        self.assertEqual(app.calls, ["flags True 9 a-b", "flags False 205 ", "remove flags 9"])

class ServeTest(unittest.TestCase):
    def test_port_in_use_raises(self):
        app = FakeApp()
        app.panel_port = 0
        srv = web.serve(app)
        try:
            app.panel_port = srv.server_address[1]
            with self.assertRaises(OSError):
                web.serve(app)
        finally:
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
