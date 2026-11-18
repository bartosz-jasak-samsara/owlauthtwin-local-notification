"""Pure-Python checks: provider lint, callback fix, PKCE, PAC, macOS proxy parsing.
python -m unittest"""
import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from owltwin_app import macproxy
from owltwin_app.config import LintError, blocked_reason, load_provider, scan
from owltwin_app.proxy import pac_script
from owltwin_app.twin import fill_values, fix_callback, pkce_s256

PROVIDERS = Path(__file__).resolve().parents[2] / "providers"


def write(text: str) -> Path:
    d = Path(tempfile.mkdtemp())
    (d / "p.yaml").write_text(text)
    return d / "p.yaml"


class ConfigTest(unittest.TestCase):
    def test_every_provider_lints(self):
        bad = {e.file.name: e.error.problems for e in scan(PROVIDERS) if e.error}
        self.assertEqual(bad, {})

    def test_blocked_hosts(self):
        self.assertIsNotNone(blocked_reason("samsara.okta.com"))
        self.assertIsNotNone(blocked_reason("accounts.google.com"))
        self.assertIsNone(blocked_reason("accounts.google.com", frozenset({"accounts.google.com"})))
        # Okta never passes, even when listed.
        self.assertIsNotNone(blocked_reason("x.okta.com", frozenset({"x.okta.com"})))
        self.assertIsNone(blocked_reason("mcp.monday.com"))

    def test_dcr_needs_resource_hosts(self):
        p = write("""schema: 1
id: x
hosts: {browser: [auth.x.test], server: [auth.x.test]}
client: {registration: dynamic}
discovery: {resource: "https://mcp.x.test/mcp", issuer: "https://auth.x.test"}
endpoints: {authorize: GET /a, token: POST /t, register: POST /r, mcp: POST /mcp}
""")
        with self.assertRaises(LintError) as cm:
            load_provider(p)
        wanted = "mcp.x.test must be under hosts.server"
        self.assertTrue(any(wanted in x for x in cm.exception.problems))

    def test_api_key_needs_no_browser_hosts(self):
        p = load_provider(write("""schema: 1
id: k
hosts: {server: [mcp.k.test]}
api_key: {scheme: basic, username: u, secret: s}
endpoints: {mcp: POST /mcp}
"""))
        self.assertEqual((p.mode, p.browser_hosts), ("api_key", []))


class TwinHelpersTest(unittest.TestCase):
    def test_fix_callback(self):
        url, note = fix_callback("http://localhost:3000/r/oauth/callback?x=1", 33000)
        self.assertEqual(url, "http://localhost:33000/r/oauth/callback?x=1")
        self.assertTrue(note)
        other = "https://example.test/r/oauth/callback"
        self.assertEqual(fix_callback(other, 33000), (other, ""))
        self.assertEqual(fix_callback("http://localhost:33000/r/oauth/callback", 33000)[1], "")

    def test_pkce(self):
        # S256 = base64url(sha256(verifier)) without padding: 43 characters.
        v = "verifier-" + "x" * 50
        got = pkce_s256(v)
        self.assertEqual(len(got), 43)
        self.assertNotIn("=", got)
        digest = hashlib.sha256(v.encode()).digest()
        self.assertEqual(got, base64.urlsafe_b64encode(digest).rstrip(b"=").decode())

    def test_fill_values_keeps_json_valid(self):
        p = load_provider(PROVIDERS / "workday.yaml")
        p.client_secret = 'a"b\\c'
        out = fill_values(p, {"s": "{client.secret}", "l": ["{tenant}"], "n": 1})
        self.assertEqual(out, {"s": 'a"b\\c', "l": ["acme"], "n": 1})


class PacTest(unittest.TestCase):
    def test_no_direct_fallback_for_twin_hosts(self):
        js = pac_script(["mcp.monday.com"], 18201)
        self.assertIn('host == "mcp.monday.com"', js)
        self.assertIn('return "PROXY 127.0.0.1:18201";', js)
        self.assertNotIn("PROXY 127.0.0.1:18201; DIRECT", js)
        self.assertIn("false", pac_script([], 1))


class MacProxyTest(unittest.TestCase):
    """networksetup is faked; the real Mac proxy is never touched."""

    OURS = {"url": "http://127.0.0.1:18200/owltwin.pac?v=1", "enabled": "Yes"}

    def run_restore(self, current: dict, saved_text: str | None):
        calls = []

        def ns(*args):
            calls.append(args)
            if args[0] == "-listallnetworkservices":
                return "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n"
            if args[0] == "-getautoproxyurl":
                return f"URL: {current['url']}\nEnabled: {current['enabled']}\n"
            return ""

        d = Path(tempfile.mkdtemp())
        f = d / "proxy-saved.json"
        if saved_text is not None:
            f.write_text(saved_text)
        with (mock.patch.object(macproxy, "_ns", ns),
              mock.patch.object(macproxy, "disabled", lambda: False)):
            macproxy.restore(f)
        self.assertFalse(f.exists())
        return [c for c in calls if c[0].startswith("-set")]

    def test_null_url_is_not_put_back(self):
        sets = self.run_restore(self.OURS, '{"Wi-Fi": {"url": "(null)", "enabled": false}}')
        self.assertEqual(sets, [("-setautoproxystate", "Wi-Fi", "off")])

    def test_previous_pac_is_put_back(self):
        saved = '{"Wi-Fi": {"url": "http://corp/proxy.pac", "enabled": true}}'
        sets = self.run_restore(self.OURS, saved)
        self.assertEqual(sets, [("-setautoproxyurl", "Wi-Fi", "http://corp/proxy.pac")])

    def test_corrupt_saved_file_turns_pac_off(self):
        sets = self.run_restore(self.OURS, '{"Wi-Fi": {"ur')
        self.assertEqual(sets, [("-setautoproxystate", "Wi-Fi", "off")])

    def test_other_pac_is_left_alone(self):
        sets = self.run_restore({"url": "http://corp/proxy.pac", "enabled": "Yes"}, None)
        self.assertEqual(sets, [])

    def test_null_reads_as_empty(self):
        with mock.patch.object(macproxy, "_ns", lambda *a: "URL: (null)\nEnabled: No\n"):
            self.assertEqual(macproxy._current("Wi-Fi"), {"url": "", "enabled": False})


if __name__ == "__main__":
    unittest.main()


def bare_app(state_dir: Path):
    """An App without its threads, proxy or devbox scan: only what the session logic reads."""
    import threading

    from owltwin_app.app import App

    a = App.__new__(App)
    a.lock = threading.RLock()
    a.state_dir = state_dir
    a.providers_dir = PROVIDERS
    a.version = 0
    a.changed = threading.Condition()
    a.session = None
    a.stopping = None
    a.stop_error = ""
    a._stopper = None
    return a


def make_session(mode="full", ids=("gmail", "google-calendar", "monday")):
    import time

    from owltwin_app.app import FlagConfig, Session
    from owltwin_app.devbox import Devbox
    from owltwin_app.twin import TwinRegistry

    by_id = {e.provider.id: e.provider for e in scan(PROVIDERS)}
    reg = TwinRegistry([by_id[i] for i in ids], lambda: None)
    dbx = Devbox(index=4, name="box1", alias="devbox-1", region="example-region", ssh_ok=True,
                 dashboard="")
    s = Session(
        devbox=dbx, twins=reg, active=ids[0], mode=mode,
        flags=FlagConfig(enabled=mode == "full"), browser_port=1, server_port=2,
        started_at=time.time(),
    )
    reg.active = lambda: s.active
    return s


class SessionLogicTest(unittest.TestCase):
    def test_session_json_v1_is_read(self):
        import json
        import time

        d = Path(tempfile.mkdtemp())
        a = bare_app(d)
        v1 = {"saved_at": time.time(), "devbox": "devbox-1", "provider_file": "gmail.yaml",
              "provider_id": "gmail", "route_applied": True, "twin": {"client_secret": "s1"}}
        (d / "session.json").write_text(json.dumps(v1))
        data = a.last_session()
        self.assertEqual(data["mode"], "full")
        self.assertEqual(data["twins"], {"gmail": {"client_secret": "s1"}})

    def test_session_json_v2_round_trip(self):
        d = Path(tempfile.mkdtemp())
        a = bare_app(d)
        s = make_session("twin_only")
        s.flags.org, s.flags.enabled = 77, True
        s.active = "google-calendar"
        s.twins.states["monday"].client_secret = "kept"
        a.session = s
        a.save_session()
        data = a.last_session()
        self.assertEqual((data["v"], data["mode"], data["provider_id"]),
                         (2, "twin_only", "google-calendar"))
        self.assertEqual(data["flags"]["org"], 77)
        self.assertEqual(data["twins"]["monday"]["client_secret"], "kept")
        self.assertEqual(set(data["twins"]), {"gmail", "google-calendar", "monday"})

    def test_steps_by_mode(self):
        a = bare_app(Path(tempfile.mkdtemp()))
        full = [st.key for st in a._steps(make_session("full"))]
        self.assertIn("backend", full)
        self.assertIn("flags", full)
        s = make_session("twin_only")
        self.assertEqual([st.key for st in a._steps(s)],
                         ["certs", "pac", "ssh", "tunnel", "route"])
        s.flags.enabled = True
        self.assertEqual(a._steps(s)[-1].key, "flags")

    def test_twin_only_drive_starts_nothing(self):
        from owltwin_app.devbox_link import LinkStatus

        a = bare_app(Path(tempfile.mkdtemp()))
        s = make_session("twin_only")
        s.steps = a._steps(s)
        a.session = s
        link = LinkStatus(reachable=True, hosts_ok=True, forward_ok=True, ca_ok=True,
                          agents_repo=False, backend_repo=False, no_ca=["ucvserver"])
        with mock.patch.object(a, "_once") as once:
            a._drive(s, link)
        once.assert_not_called()   # no provision, no tmux starts, no flags
        self.assertEqual(s.step("route").state, "ok")

    def test_flags_off_is_skipped(self):
        from owltwin_app.devbox_link import LinkStatus

        a = bare_app(Path(tempfile.mkdtemp()))
        s = make_session("full")
        s.flags.enabled = False
        s.steps = a._steps(s)
        a._flags(s, LinkStatus(reachable=True, ddb_ok=True))
        self.assertEqual(s.step("flags").state, "skipped")
        self.assertNotIn("flags", [st.key for st in s.problems])

    def test_stop_by_mode(self):
        from owltwin_app import app as app_mod

        for mode, called in (("twin_only", "route_down"), ("full", "down")):
            a = bare_app(Path(tempfile.mkdtemp()))
            a.session = make_session(mode)
            with mock.patch.object(app_mod.devbox_link, "route_down") as rd, \
                    mock.patch.object(app_mod.devbox_link, "down") as dn, \
                    mock.patch.object(app_mod.macproxy, "restore"), \
                    mock.patch.object(app_mod, "no_devbox", return_value=False):
                a.stop_session()
            self.assertEqual((rd.called, dn.called), (called == "route_down", called == "down"))

    def test_stop_runs_in_background_once(self):
        import threading
        import time

        from owltwin_app import app as app_mod

        for err in ("", "the devbox did not answer while stopping owltwin-run"):
            a = bare_app(Path(tempfile.mkdtemp()))
            a.session = make_session("full")
            gate = threading.Event()
            calls = []

            def down(alias, err=err, gate=gate, calls=calls):
                calls.append(alias)
                gate.wait(5)
                return err

            with mock.patch.object(app_mod.devbox_link, "down", side_effect=down), \
                    mock.patch.object(app_mod.macproxy, "restore"), \
                    mock.patch.object(app_mod, "no_devbox", return_value=False):
                a.request_stop()
                self.assertEqual(a.stopping["alias"], "devbox-1")
                for _ in range(50):   # the session goes at once, before the devbox answers
                    if calls:
                        break
                    time.sleep(0.02)
                self.assertIsNone(a.session)
                a.request_stop()      # a second click starts nothing
                self.assertIn("Still stopping", a.start_session("devbox-1", "gmail.yaml"))
                gate.set()
                a._stopper.join(5)
            self.assertEqual(calls, ["devbox-1"])
            self.assertIsNone(a.stopping)
            self.assertEqual(bool(a.stop_error), bool(err))
            if err:
                self.assertIn(err, a.stop_error)

    def test_pac_hosts_and_intercept(self):
        a = bare_app(Path(tempfile.mkdtemp()))
        s = make_session("full")
        a.session = s
        hosts = a._browser_hosts()
        self.assertIn("auth.monday.com", hosts)
        self.assertNotIn("accounts.google.com", hosts)   # only while Intercept is on
        s.idp_on_at, s.idp_for = 1.0, "google-calendar"
        self.assertIn("accounts.google.com", a._browser_hosts())

    def test_parse_flags(self):
        from owltwin_app.app import parse_flags

        f = parse_flags(True, " 12 ", ["a-b", "a-b", " ", "c.d"])
        self.assertEqual((f.org, f.names), (12, ["a-b", "c.d"]))
        self.assertIsInstance(parse_flags(True, "1; rm", []), str)
        self.assertIsInstance(parse_flags(True, "1", ["x'y"]), str)
        self.assertEqual(parse_flags(False, "", []).org, 205)


class SsoLoginScriptTest(unittest.TestCase):
    def test_picks_the_session_most_profiles_use(self):
        import subprocess

        from owltwin_app import devbox_link

        home = Path(tempfile.mkdtemp())
        (home / ".aws").mkdir()
        (home / ".aws/config").write_text(
            "[sso-session old]\nsso_region = r\n[sso-session new]\nsso_region = r\n"
            "[profile a]\nsso_session = new\n[profile b]\nsso_session = new\n"
        )
        script = "P=\n" + devbox_link.SSO_LOGIN.replace(
            "exec timeout 600 aws sso login", "echo picked")
        env = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
        out = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True,
                             timeout=10).stdout
        self.assertIn("picked --sso-session new ", out)


class OverridesScriptTest(unittest.TestCase):
    def run_script(self, fn, *args):
        from owltwin_app import devbox_link

        r = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(devbox_link, "rsh", return_value=r) as rsh:
            self.assertEqual(fn("devbox-1", *args), "")
        return rsh.call_args[0][1]

    def test_org_and_flags_reach_the_script(self):
        from owltwin_app import devbox_link

        script = self.run_script(devbox_link.ensure_overrides, 77, ["my-flag"])
        self.assertIn("ORGFLAGS#77", script)
        self.assertIn("DIRECT_ORG#77", script)
        self.assertIn("FLAG#my-flag", script)
        self.assertNotIn("205", script)
        script = self.run_script(devbox_link.remove_overrides, 77, ["my-flag"])
        self.assertIn("delete-item", script)
        self.assertIn("DIRECT_ORG#77", script)
        self.assertIn("ORGFLAGS#77", devbox_link.override_status(77))
