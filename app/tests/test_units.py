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

    def test_logo_must_be_https_and_not_a_company_host(self):
        base = """schema: 1
id: k
hosts: {server: [mcp.k.test]}
api_key: {scheme: basic, username: u, secret: s}
endpoints: {mcp: POST /mcp}
"""
        ok = load_provider(write(base + "logo: https://www.microsoft.com/favicon.ico\n"))
        self.assertEqual(ok.logo, "https://www.microsoft.com/favicon.ico")
        for bad in ("http://k.test/logo.png", "https://cdn.samsara.com/logo.png"):
            with self.assertRaises(LintError, msg=bad) as cm:
                load_provider(write(base + f"logo: {bad}\n"))
            self.assertTrue(any(x.startswith("logo:") for x in cm.exception.problems))


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

    def test_working_session_restarts_instead_of_signing_in(self):
        """A pane stopped on text that looks like an expired session, while the session works:
        no sign-in page, the pane starts again."""
        import time

        from owltwin_app import app as app_mod
        from owltwin_app.devbox_link import LinkStatus

        a = bare_app(Path(tempfile.mkdtemp()))
        s = make_session("full")
        s.steps = a._steps(s)
        a.session = s
        link = LinkStatus(reachable=True, windows={"backend": "zsh"}, sso={"backend"})
        s.actions = {"backend": time.time() - 120}   # this run started it, then it stopped
        # The check finds the session working: no sign-in page, the sign-in counts as done.
        with mock.patch.object(app_mod.devbox_link, "sso_signed_in", return_value=True), \
                mock.patch.object(app_mod.devbox_link, "sso_login") as login:
            a._sso_login(s)
        login.assert_not_called()
        self.assertGreater(s.sso_done_at, 0)
        with mock.patch.object(a, "_aws_signin") as signin, \
                mock.patch.object(a, "_direnv_ready", return_value=True), \
                mock.patch.object(a, "_once", return_value=True) as once:
            a._run_window(s, link, "backend", "~/co/backend", "cmd", "taskrunner", "")
        signin.assert_not_called()
        self.assertEqual(once.call_args.args[1], "backend")   # started again
        # Without a sign-in since, the same pane still asks for one.
        s.sso_done_at, s.sso_ok_at, s.actions = 0.0, 0.0, {"backend": time.time()}
        with mock.patch.object(a, "_aws_signin") as signin:
            a._run_window(s, link, "backend", "~/co/backend", "cmd", "taskrunner", "")
        signin.assert_called_once()

    def test_no_sign_in_loop_when_the_session_works(self):
        """Restarted after the check found AWS working and stopped on it again: a fail with what
        it printed, not one more sign-in."""
        import time

        from owltwin_app.devbox_link import LinkStatus

        a = bare_app(Path(tempfile.mkdtemp()))
        s = make_session("full")
        s.steps = a._steps(s)
        a.session = s
        s.sso_ok_at = s.sso_done_at = time.time() - 60
        s.actions = {"backend": time.time()}
        link = LinkStatus(reachable=True, windows={"backend": "zsh"}, sso={"backend"},
                          errs={"backend": "unable to get caller identity: NoCredentialProviders"})
        with mock.patch.object(a, "_aws_signin") as signin:
            a._run_window(s, link, "backend", "~/co/backend", "cmd", "taskrunner", "")
        signin.assert_not_called()
        st = s.step("backend")
        self.assertEqual(st.state, "fail")
        self.assertIn("NoCredentialProviders", st.detail)

    def test_backend_picks_a_profile_that_exists(self):
        import subprocess

        from owltwin_app import app as app_mod

        if app_mod.AWS_PROFILE:
            self.skipTest("OWLTWIN_AWS_PROFILE is set")
        pick = app_mod.BACKEND_CMD.split("bash -c ", 1)[1]
        bin_dir = Path(tempfile.mkdtemp())
        profiles = "local devecosystemreadonly other"
        scripts = {
            "aws": f"#!/bin/sh\nprintf '%s\\n' {profiles}\n",
            "taskrunner-localdev": '#!/bin/sh\necho "ran $AWS_PROFILE"\n',
        }
        for name, text in scripts.items():
            (bin_dir / name).write_text(text)
            (bin_dir / name).chmod(0o755)
        for default, want in (("readonly", "devecosystemreadonly"), ("other", "other")):
            env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": "/tmp",
                   "AWS_DEFAULT_PROFILE": default, "AWS_CONFIG_FILE": "c"}
            out = subprocess.run(f"bash -c {pick}", shell=True, env=env, capture_output=True,
                                 text=True, timeout=10).stdout
            self.assertIn(f"ran {want}", out)

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

    def test_check_uses_a_profile_of_that_session(self):
        import subprocess

        from owltwin_app import devbox_link

        home = Path(tempfile.mkdtemp())
        (home / ".aws").mkdir()
        (home / ".aws/config").write_text(
            "[sso-session old]\n[sso-session new]\n"
            "[profile x]\nregion = r\n[profile sso-a]\nsso_session = new\n"
            "[profile sso-b]\nsso_session = new\n"
        )
        script = "P=\n" + devbox_link.SSO_CHECK.replace(
            "exec timeout 30 aws sts get-caller-identity", "echo checked")
        env = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
        out = subprocess.run(["bash", "-c", script.replace(">/dev/null 2>&1", "")], env=env,
                             capture_output=True, text=True, timeout=10).stdout
        self.assertIn("checked --profile sso-a", out)


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


class LauncherTest(unittest.TestCase):
    def run_launcher(self, args: list[str], *, head_after: str = "aaaaaaa1", pull_rc: int = 0,
                     extra_env: dict[str, str] | None = None):
        import os
        import shutil
        import subprocess

        root = Path(tempfile.mkdtemp())
        (root / "app").mkdir()
        (root / ".git").mkdir()
        launcher = root / "owltwin"
        shutil.copy2(PROVIDERS.parent / "owltwin", launcher)
        launcher.chmod(0o755)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        log_file = root / "calls.log"
        head_file = root / "head"
        head_file.write_text("aaaaaaa1")

        git_stub = bin_dir / "git"
        git_stub.write_text(f"""#!/bin/sh
echo "git $*" >> "{log_file}"
case " $* " in
  *" rev-parse HEAD "*) cat "{head_file}" ;;
  *" pull "*)
    if [ "{pull_rc}" -ne 0 ]; then
      echo "fatal: could not fast-forward" >&2
      exit {pull_rc}
    fi
    printf '%s' "{head_after}" > "{head_file}"
    ;;
esac
""")
        git_stub.chmod(0o755)

        uv_stub = bin_dir / "uv"
        uv_stub.write_text(f'#!/bin/sh\necho "uv $*" >> "{log_file}"\n')
        uv_stub.chmod(0o755)

        env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(root)}
        if extra_env:
            env.update(extra_env)
        else:
            env.pop("OWLTWIN_NO_UPDATE", None)
        proc = subprocess.run([str(launcher), *args], env=env, capture_output=True, text=True,
                              timeout=10)
        calls = log_file.read_text().splitlines() if log_file.exists() else []
        os.chmod(launcher, 0o644)
        return proc, calls

    def test_default_serve_auto_updates(self):
        proc, calls = self.run_launcher(["--no-open"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(any("pull --ff-only" in c for c in calls))
        self.assertEqual(calls[-1], "uv run --quiet python -m owltwin_app serve --no-open")

    def test_updated_head_syncs_and_reexecs_once(self):
        proc, calls = self.run_launcher(["--no-open"], head_after="bbbbbbb2")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("owltwin: updated (aaaaaaa -> bbbbbbb)", proc.stdout)
        pulls = [c for c in calls if " pull " in c]
        self.assertEqual(len(pulls), 1)
        self.assertIn("uv sync --quiet --frozen --no-dev", calls)
        self.assertEqual(calls[-1], "uv run --quiet python -m owltwin_app serve --no-open")

    def test_no_update_flag_and_env_skip_pull(self):
        for args, env in ((["--no-update", "--no-open"], None),
                          (["--no-open"], {"OWLTWIN_NO_UPDATE": "1"})):
            proc, calls = self.run_launcher(args, extra_env=env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertFalse(any("pull" in c for c in calls))
            self.assertEqual(calls[-1], "uv run --quiet python -m owltwin_app serve --no-open")

    def test_failed_pull_warns_and_still_starts(self):
        proc, calls = self.run_launcher([], pull_rc=1)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("auto-update skipped", proc.stderr)
        self.assertEqual(calls[-1], "uv run --quiet python -m owltwin_app serve")

    def test_lint_does_not_auto_update(self):
        proc, calls = self.run_launcher(["lint", "gmail"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(any("pull" in c for c in calls))
        self.assertEqual(calls[-1], "uv run --quiet python -m owltwin_app lint gmail")

