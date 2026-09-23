"""
No page may interpolate data into an event-handler attribute.

The admin console built handlers by string interpolation:

    onclick="delObj('${x(o.name)}')"

x() escapes for HTML, but a browser decodes an attribute value before it
compiles the JavaScript inside it, so &#x27; reached the parser as a real
quote. An object named  '-fetch(...)-'  closed the string and ran as code the
moment an admin opened the list, and object, registry, team and user names are
all chosen by users of the broker.

Handlers now name an entry in an ACTIONS map and pass their arguments as JSON
in data-args, which is read through dataset and parsed rather than compiled.
These tests fail if an interpolating handler reappears.
"""
import re
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parent.parent / "static"
PAGES = sorted(STATIC.glob("*.html"))
SCRIPTS = sorted((STATIC / "js").glob("*.js"))

# An on*= attribute whose value contains a ${...} template substitution.
INTERPOLATING_HANDLER = re.compile(r'\son[a-z]+\s*=\s*"[^"]*\$\{')

# Lines inside a comment explaining the bug are not markup.
COMMENT = re.compile(r'^\s*(//|/\*|\*)')


def _offending_lines(path):
    return [
        (n, line.strip())
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if INTERPOLATING_HANDLER.search(line) and not COMMENT.match(line)
    ]


def test_there_are_pages_to_check():
    """Guards the glob: a rename must not turn these into vacuous passes."""
    assert PAGES, f"no HTML found under {STATIC}"
    assert {p.name for p in PAGES} >= {"index.html", "dashboard.html"}


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_no_handler_attribute_interpolates_data(page):
    offending = _offending_lines(page)
    assert not offending, "\n".join(
        [f"{page.name} builds an event handler from interpolated data:"]
        + [f"  line {n}: {line[:120]}" for n, line in offending]
        + ["Pass the value in a data attribute and dispatch through ACTIONS instead."]
    )


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_no_handler_attribute_is_assembled_from_a_variable(page):
    """
    The other shape of the same bug: a handler's *source* passed as a value,
    as pager() and _policyBody() used to do, and recompiled by the browser.
    """
    text = page.read_text(encoding="utf-8")
    bad = re.findall(r'`\s*on[a-z]+="\$\{\w+\}"', text)
    assert not bad, f"{page.name} injects handler source: {bad}"


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_pages_carry_no_inline_script_or_style(page):
    """
    Inline script is what forces 'unsafe-inline' into script-src, and that is
    the directive that stops XSS. Page scripts and stylesheets are served
    from /static instead.
    """
    text = page.read_text(encoding="utf-8")
    assert "<style>" not in text, f"{page.name} has an inline <style> block"
    assert re.search(r"<script(?![^>]*\ssrc=)", text) is None, \
        f"{page.name} has an inline <script> block"


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_no_template_expression_is_left_in_static_markup(page):
    """
    act() and actOn() only run inside a template literal. Written into the
    page's own markup they are inert text, and the element silently loses its
    handler -- that is how the whole sidebar stopped navigating once. Static
    markup spells the attributes out.
    """
    leftovers = [
        (n, line.strip())
        for n, line in enumerate(page.read_text(encoding="utf-8").splitlines(), 1)
        if "${" in line
    ]
    assert not leftovers, "\n".join(
        [f"{page.name} contains template syntax that will never be evaluated:"]
        + [f"  line {n}: {line[:110]}" for n, line in leftovers]
    )


def _defined_actions():
    defined = set()
    for js in SCRIPTS:
        text = js.read_text(encoding="utf-8")
        for block in re.findall(r"Object\.assign\(ACTIONS,\s*\{(.*?)\n\}\);", text, re.S):
            defined |= set(re.findall(r"^\s+([A-Za-z_]\w*)\s*:", block, re.M))
    return defined


def test_every_action_named_in_markup_is_defined():
    """
    A data-act naming nothing is a dead control: it looks like a button and
    does nothing at all. Pages and scripts are checked together.
    """
    defined = _defined_actions()
    assert defined, "no ACTIONS entries found -- the parsing here has drifted"

    named = set()
    for path in list(PAGES) + list(SCRIPTS):
        text = path.read_text(encoding="utf-8")
        named |= set(re.findall(r'data-act(?:-\w+)?="([A-Za-z_]\w*)"', text))
        named |= set(re.findall(r"\bact\('([A-Za-z_]\w*)'", text))
        named |= set(re.findall(r"\bactOn\('\w+',\s*'([A-Za-z_]\w*)'", text))

    missing = sorted(named - defined)
    assert not missing, f"markup names actions that nothing defines: {missing}"


def test_the_dispatcher_only_reaches_named_actions():
    """
    data-act must resolve through the ACTIONS map. Looking the name up on
    window instead would let an attribute reach any global.
    """
    text = (STATIC / "js" / "actions.js").read_text(encoding="utf-8")
    assert "const ACTIONS = Object.create(null);" in text, "ACTIONS map missing"
    assert "ACTIONS[el.getAttribute(attr)]" in text, "dispatch no longer goes through ACTIONS"
    dispatcher = text.split("const ACTIONS")[1].split("Object.assign")[0]
    for forbidden in ("window[", "eval(", "new Function(", "innerHTML = el.dataset"):
        assert forbidden not in dispatcher, f"dispatcher uses {forbidden}"


def test_arguments_are_parsed_as_json_not_executed():
    text = (STATIC / "js" / "actions.js").read_text(encoding="utf-8")
    assert "JSON.parse(el.dataset.args)" in text
    assert "JSON.stringify(args)" in text
