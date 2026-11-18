"""Running devboxes, from `devbox list --json`. Read-only."""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
import urllib.parse
from dataclasses import dataclass


@dataclass
class Devbox:
    index: int
    name: str
    alias: str
    region: str
    ssh_ok: bool
    dashboard: str

    @property
    def label(self) -> str:
        return f"{self.alias} · {self.name}"

    @property
    def frontend_port(self) -> int:
        """Agent Studio port on the Mac.

        From `devbox list` when it gives one, else the N3000 rule (0 when that overflows).
        """
        try:
            port = urllib.parse.urlsplit(self.dashboard).port if self.dashboard else None
        except ValueError:
            port = None
        if port:
            return port
        guess = self.index * 10000 + 3000 if self.index else 3000
        return guess if guess < 65536 else 0


class DevboxList:
    """Fetched in the background: `devbox list` probes every box and takes a few seconds."""

    def __init__(self, on_change=None) -> None:
        self.on_change = on_change or (lambda: None)
        self.lock = threading.Lock()
        self.items: list[Devbox] = []
        self.error = ""
        self.loading = False
        self.loaded_at = 0.0

    def refresh(self, wait: bool = False) -> None:
        with self.lock:
            if self.loading:
                return
            self.loading = True
        self.on_change()
        t = threading.Thread(target=self._load, daemon=True)
        t.start()
        if wait:
            t.join()

    def _load(self) -> None:
        items: list[Devbox] = []
        error = ""
        if os.environ.get("OWLTWIN_FAKE_DEVBOXES") == "1":
            # Local UI work: canned list, no `devbox list`, nothing touches a devbox.
            time.sleep(1.5)
            items = [
                Devbox(1, "example-a", "devbox-1", "example-region", True, ""),
                Devbox(2, "example-b", "devbox-2", "example-region", True, ""),
                Devbox(3, "example-c", "devbox-3", "example-region", False, ""),
            ]
            self._store(items, "")
            return
        try:
            out = subprocess.run(
                ["devbox", "list", "--json"], capture_output=True, text=True, timeout=120
            )
            data = json.loads(out.stdout[out.stdout.index("{"):])
            for d in data.get("devboxes", []):
                if d.get("state") != "running":
                    continue
                items.append(Devbox(
                    index=int(d.get("index") or 0),
                    name=d.get("name", ""),
                    alias=d.get("alias", ""),
                    region=d.get("region", ""),
                    ssh_ok=d.get("ssh") == "ok",
                    dashboard=d.get("dashboard") or "",
                ))
        except FileNotFoundError:
            error = "The devbox CLI is not on PATH"
        except (ValueError, subprocess.TimeoutExpired) as e:
            error = f"devbox list failed: {e}"
        self._store(items, error)

    def _store(self, items: list[Devbox], error: str) -> None:
        with self.lock:
            self.items = items
            self.error = error
            self.loading = False
            self.loaded_at = time.time()
        self.on_change()

    def get(self, alias: str) -> Devbox | None:
        with self.lock:
            return next((d for d in self.items if d.alias == alias), None)
