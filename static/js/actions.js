/*
 * Shared action dispatch. Every page loads this before its own script.
 *
 * Handlers used to be written inline, with data interpolated into them:
 *
 *     onclick="delObj('${x(o.name)}')"
 *
 * x() escapes for HTML, but a browser decodes an attribute value before it
 * compiles the JavaScript inside it, so &#x27; reached the parser as a real
 * quote. An object named  '-fetch(...)-'  closed the string and ran as code
 * as soon as an admin opened the list. Object, registry, team and user names
 * are all chosen by users of the broker, so that was reachable by anyone who
 * could create one.
 *
 * An element now names an entry in ACTIONS and carries its arguments as JSON
 * in data-args: read back through dataset and parsed, never compiled. Because
 * data-act indexes ACTIONS rather than naming an expression, a crafted
 * attribute cannot reach an arbitrary global either.
 *
 * Keeping handlers out of attributes is also what lets the page be served
 * under a Content-Security-Policy with no 'unsafe-inline' in script-src.
 */

/** Escapes a value for interpolation into HTML. */
function x(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
}

function _args(args) {
  return args.length ? ` data-args="${x(JSON.stringify(args))}"` : '';
}

/** Attributes binding an element's click to ACTIONS[name], called with args. */
function act(name, ...args) { return `data-act="${name}"${_args(args)}`; }

/** As act(), for an event other than click. */
function actOn(event, name, ...args) { return `data-act-${event}="${name}"${_args(args)}`; }

const ACTIONS = Object.create(null);

// One listener per event type. closest() matches the innermost element, so a
// button inside a clickable row wins over the row without needing to stop
// propagation.
for (const ev of ['click', 'change', 'input', 'focus', 'keyup', 'keydown']) {
  const attr = ev === 'click' ? 'data-act' : `data-act-${ev}`;
  document.addEventListener(ev, e => {
    const el = e.target.closest(`[${attr}]`);
    if (!el) return;
    const fn = ACTIONS[el.getAttribute(attr)];
    if (!fn) return;
    let args = [];
    if (el.dataset.args) {
      try { args = JSON.parse(el.dataset.args); } catch { return; }
    }
    fn(args, el, e);
  }, ev === 'focus');   // focus does not bubble
}

Object.assign(ACTIONS, {
  // Marks an element whose clicks must not reach whatever sits behind it.
  stop: () => {},
  // Runs another action on Enter, for inputs that are not inside a <form>.
  submitOnEnter: ([action], el, e) => { if (e.key === 'Enter') ACTIONS[action]([], el, e); },
});
