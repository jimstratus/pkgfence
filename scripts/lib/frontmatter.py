"""Single owner of the report frontmatter format (--- YAML --- block).

report.py BUILDS frontmatter, notify.py PARSES it — any format change must
keep this round-trip test green so the two can never drift (issue #18)."""
from io import StringIO
from typing import Any

from ruamel.yaml import YAML


def build_frontmatter(data: dict[str, Any]) -> str:
    """Render data as a ----delimited YAML block. Uses the round-trip
    dumper to preserve key insertion order (CLAUDE.md YAML gotcha)."""
    yaml = YAML(typ="rt")
    yaml.default_flow_style = False
    buf = StringIO()
    yaml.dump(data, buf)
    return "---\n" + buf.getvalue() + "---\n"


def parse_frontmatter(text: str) -> dict[str, Any]:
    """Parse the leading frontmatter block of a markdown document.
    Returns {} when there is no complete --- block."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            yaml = YAML(typ="safe")
            return yaml.load(StringIO("\n".join(lines[1:i]))) or {}
    return {}
