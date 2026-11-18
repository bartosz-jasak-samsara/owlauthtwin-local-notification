"""Jinja2 environment for every HTML page: the panel and the Twin's consent page.

Autoescape is on for .html templates, so request and YAML values are escaped where they are
printed. Python passes plain data (view-models); no HTML is built in Python."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

TEMPLATES = Path(__file__).parent / "templates"
FAVICON = Path(__file__).parent / "static" / "favicon.svg"

env = Environment(
    loader=FileSystemLoader(TEMPLATES),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
    # A misspelled view-model field fails loudly instead of rendering empty.
    undefined=StrictUndefined,
)
# Inlined as a data URI: the consent page is served by the Twin, which has no /static route.
env.globals["favicon"] = (
    "data:image/svg+xml;base64," + base64.b64encode(FAVICON.read_bytes()).decode()
)


def render(template: str, **ctx: Any) -> str:
    return env.get_template(template).render(**ctx)
