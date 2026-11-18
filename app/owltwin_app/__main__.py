"""python -m owltwin_app [serve|lint]"""

from __future__ import annotations

import contextlib
import os
import signal
import sys
import threading
import time
import webbrowser

from .app import App
from .config import scan
from .web import serve


def lint(paths: list[str]) -> int:
    from .app import ROOT

    entries = scan(ROOT / "providers")
    if paths:
        entries = [e for e in entries if e.file.stem in paths or e.file.name in paths]
    bad = 0
    for e in entries:
        if e.provider:
            hosts = ", ".join(e.provider.all_hosts)
            print(f"ok    {e.file.name}  ({e.provider.name}, hosts: {hosts})")
        else:
            bad += 1
            print(f"error {e.file.name}")
            for p in e.error.problems if e.error else []:
                print(f"      - {p}")
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "serve"
    if cmd == "lint":
        return lint(argv[1:])
    if cmd != "serve":
        print("usage: owltwin_app [serve [--no-open] | lint [provider...]]", file=sys.stderr)
        return 2
    try:
        app = App()
        srv = serve(app)
    except OSError as e:
        if e.errno not in (48, 98):   # EADDRINUSE on macOS / Linux
            raise
        panel = os.environ.get("OWLTWIN_PORT", "18200")
        print(
            f"owltwin: a port is already in use ({e.strerror}). OwlAuth Twin may already be "
            f"running: open http://127.0.0.1:{panel}/ or close the other one. "
            "Ports: OWLTWIN_PORT (18200), OWLTWIN_PROXY_PORT (18201), OWLTWIN_SERVER_PORT (18443).",
            file=sys.stderr,
        )
        return 1
    url = f"http://127.0.0.1:{app.panel_port}/"
    print(f"OwlAuth Twin: {url}", flush=True)
    # A plain flag: Event.set() inside a signal handler can deadlock with the
    # Event.wait() it interrupts (both take the same lock in the main thread).
    stop = {"now": False}

    def shutdown(*_: object) -> None:
        stop["now"] = True

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGHUP, shutdown)   # the terminal window was closed
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    if "--no-open" not in argv:
        webbrowser.open(url)
    while not stop["now"]:  # short sleeps keep signal handlers responsive
        time.sleep(0.5)
    # Cleaning up waits for the devbox (up to 90 s if it hangs); a second Ctrl+C quits at once.
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    with contextlib.suppress(OSError):  # after SIGHUP the terminal is gone and printing fails
        print(
            "Stopping: restoring the Mac proxy, closing tunnels, "
            "stopping owltwin-run on the devbox…",
            flush=True,
        )
    app.stop_session(keep=True)
    srv.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
