"""
No page may load executable code from a third party.

The admin console and the team dashboard pulled in cdn.tailwindcss.com: a
just-in-time compiler that fetches and runs on every page load. Inspected on
a running instance it produced 38 CSS rules, all of them Tailwind's Preflight
reset and not one a utility class, because no page uses one. It was a remote
script with full DOM access, inside the admin UI of a secrets broker, in
exchange for a stylesheet that could be served locally.

Stylesheets and fonts from a known host are a smaller exposure than script,
so those are allowed by host; script must be same-origin.
"""
import re
from pathlib import Path
from urllib.parse import urlparse

import pytest

STATIC = Path(__file__).resolve().parent.parent / "static"
PAGES = sorted(STATIC.glob("*.html"))

SCRIPT_SRC = re.compile(r'<script[^>]*\ssrc\s*=\s*["\']([^"\']+)["\']', re.I)
LINK_HREF = re.compile(r'<link[^>]*\shref\s*=\s*["\']([^"\']+)["\']', re.I)

# Stylesheets and fonts may come from these; nothing else, and never script.
ALLOWED_STYLE_HOSTS = frozenset({"fonts.googleapis.com", "fonts.gstatic.com"})


def _host(url):
    """
    The host a URL actually resolves to, or None if it is same-origin.

    Compared whole, never as a substring: "fonts.googleapis.com" appears in
    "fonts.googleapis.com.example.net" and at the end of a path, and neither
    is the host these tests mean to allow.
    """
    if url.startswith("//"):
        url = "https:" + url
    elif not url.startswith(("http://", "https://")):
        return None
    return (urlparse(url).hostname or "").lower()


def test_there_are_pages_to_check():
    assert PAGES, f"no HTML found under {STATIC}"
    assert {p.name for p in PAGES} >= {"index.html", "dashboard.html"}


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_no_script_is_loaded_from_another_origin(page):
    remote = [src for src in SCRIPT_SRC.findall(page.read_text(encoding="utf-8")) if _host(src)]
    assert not remote, (
        f"{page.name} loads script from another origin: {remote}. "
        "Third-party script runs with full access to the page; vendor it instead."
    )


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_stylesheets_come_from_self_or_a_known_font_host(page):
    unexpected = [
        href for href in LINK_HREF.findall(page.read_text(encoding="utf-8"))
        if (h := _host(href)) and h not in ALLOWED_STYLE_HOSTS
    ]
    assert not unexpected, f"{page.name} loads a stylesheet from an unexpected host: {unexpected}"


@pytest.mark.parametrize("url,expected", [
    ("https://fonts.googleapis.com/css2?family=X", "fonts.googleapis.com"),
    ("//fonts.gstatic.com/s/x.woff2", "fonts.gstatic.com"),
    ("https://fonts.googleapis.com.example.net/x", "fonts.googleapis.com.example.net"),
    ("https://evil.example/?u=fonts.googleapis.com", "evil.example"),
    ("/static/admin.css", None),
    ("styles.css", None),
])
def test_host_extraction_is_not_a_substring_match(url, expected):
    """A look-alike host must not pass for the host it imitates."""
    assert _host(url) == expected


def test_tailwind_is_not_reintroduced():
    """
    Named explicitly: it is the one that was there, and it is easy to re-add.
    Matched on tags rather than on any mention, so the comment recording why
    it went does not trip it.
    """
    for page in PAGES:
        text = page.read_text(encoding="utf-8")
        refs = [
            u for u in SCRIPT_SRC.findall(text) + LINK_HREF.findall(text)
            if (h := _host(u)) and (h == "tailwindcss.com" or h.endswith(".tailwindcss.com"))
        ]
        assert not refs, f"{page.name} loads the Tailwind CDN again: {refs}"


def test_the_reset_the_cdn_supplied_is_served_locally():
    """
    Removing the CDN removed a reset the pages had come to depend on. It is
    replaced in-page rather than simply dropped.
    """
    for name in ("index.html", "dashboard.html"):
        text = (STATIC / name).read_text(encoding="utf-8")
        assert "Tailwind v3 Preflight" in text, f"{name} lost the reset the CDN used to supply"
        for rule in ("box-sizing: border-box", "border-collapse: collapse", "line-height: inherit"):
            assert rule in text, f"{name} is missing reset rule: {rule}"
