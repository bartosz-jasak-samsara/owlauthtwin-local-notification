"""macOS automatic proxy (PAC) on/off with networksetup. No sudo needed.
The previous per-service setting is saved and restored on stop."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path


def disabled() -> bool:
    return os.environ.get("OWLTWIN_NO_SYSTEM_PROXY") == "1"


def _ns(*args: str) -> str:
    result = subprocess.run(["networksetup", *args], check=True, capture_output=True, text=True)
    return result.stdout


def services() -> list[str]:
    out = _ns("-listallnetworkservices").splitlines()[1:]
    return [s for s in out if s and not s.startswith("*")]


def _current(service: str) -> dict[str, str | bool]:
    out = _ns("-getautoproxyurl", service)
    url = re.search(r"^URL: (.*)$", out, re.M)
    enabled = re.search(r"^Enabled: (Yes|No)$", out, re.M)
    value = url.group(1).strip() if url else ""
    # A service that never had a PAC prints "URL: (null)": that is no URL, not one to put back.
    return {
        "url": "" if value == "(null)" else value,
        "enabled": bool(enabled and enabled.group(1) == "Yes"),
    }


def _load(saved_file: Path) -> dict:
    """The saved settings; a file cut short by a hard kill counts as none.

    Restore then just turns the PAC off.
    """
    try:
        data = json.loads(saved_file.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def enable(pac_url: str, saved_file: Path) -> list[str]:
    if disabled():
        return []
    saved = _load(saved_file)
    changed = []
    for s in services():
        cur = _current(s)
        if s not in saved and "owltwin" not in str(cur["url"]):
            saved[s] = cur
        _ns("-setautoproxyurl", s, pac_url)
        changed.append(s)
    saved_file.write_text(json.dumps(saved, indent=1))
    return changed


def restore(saved_file: Path, marker: str = "/owltwin.pac") -> None:
    if disabled():
        return
    saved = _load(saved_file)
    for s in services():
        cur = _current(s)
        if marker not in str(cur["url"]):
            continue
        prev = saved.get(s)
        if prev and prev.get("url") and prev["url"] != "(null)" and marker not in prev["url"]:
            _ns("-setautoproxyurl", s, str(prev["url"]))
            if not prev.get("enabled"):
                _ns("-setautoproxystate", s, "off")
        else:
            _ns("-setautoproxystate", s, "off")
    saved_file.unlink(missing_ok=True)


def status(marker: str = "/owltwin.pac") -> str:
    if disabled():
        return "skipped (OWLTWIN_NO_SYSTEM_PROXY=1)"
    on = [s for s in services() if marker in str(_current(s)["url"]) and _current(s)["enabled"]]
    return f"on for {', '.join(on)}" if on else "off"
