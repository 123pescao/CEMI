"""Tests for cemi.config."""
from __future__ import annotations

from cemi.config import get_template_env


def test_jinja2_autoescape_enabled() -> None:
    env = get_template_env()
    template = env.from_string("{{ value }}")
    result = template.render(value="<script>alert('xss')</script>")
    assert "<script>" not in result
    assert "&lt;script&gt;" in result
