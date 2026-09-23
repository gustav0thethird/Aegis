// ── Sidebar active state on scroll ──────────────────────────────────────────
const sections = document.querySelectorAll('.section[id]');
const sidebarLinks = document.querySelectorAll('.sidebar-link[href]');

const observer = new IntersectionObserver(entries => {
  entries.forEach(e => {
    if (e.isIntersecting) {
      const id = e.target.id;
      sidebarLinks.forEach(l => {
        l.classList.toggle('active', l.getAttribute('href') === '#' + id);
      });
    }
  });
}, { rootMargin: '-20% 0px -70% 0px' });

sections.forEach(s => observer.observe(s));

// ── Copy buttons ─────────────────────────────────────────────────────────────
document.querySelectorAll('pre').forEach(pre => {
  if (pre.classList.contains('response-body')) return;
  const btn = document.createElement('button');
  btn.className = 'copy-btn';
  btn.textContent = 'copy';
  btn.onclick = () => {
    navigator.clipboard.writeText(pre.querySelector('code')?.textContent || pre.textContent);
    btn.textContent = 'copied!';
    setTimeout(() => btn.textContent = 'copy', 1500);
  };
  pre.appendChild(btn);
});

// ── Endpoint accordion ──────────────────────────────────────────────────────
function toggleEndpoint(header) {
  const body = header.nextElementSibling;
  const open = body.classList.toggle('open');
  header.classList.toggle('open', open);
}

// ── API Companion ───────────────────────────────────────────────────────────
let _token = null;

// Try to pull token from sessionStorage
try {
  const s = JSON.parse(sessionStorage.getItem('aegis_session') || '{}');
  _token = s.token || null;
} catch (_) {}

function companionTab(tab) {
  document.querySelectorAll('.ctab').forEach((t, i) => {
    t.classList.toggle('active', t.textContent.toLowerCase().includes(tab));
  });
  document.getElementById('cp-panel-headers').classList.toggle('active', tab === 'headers');
  document.getElementById('cp-panel-body').classList.toggle('active', tab === 'body');
}

// Seed default headers
function buildDefaultHeaders() {
  const list = document.getElementById('cp-headers-list');
  list.innerHTML = '';
  const defaults = [
    ['Authorization', _token ? `Bearer ${_token}` : ''],
    ['Content-Type',  'application/json'],
  ];
  defaults.forEach(([k, v]) => addHeaderRow(k, v));
}

function addHeaderRow(key = '', value = '') {
  const list = document.getElementById('cp-headers-list');
  const row = document.createElement('div');
  row.className = 'header-row';
  row.innerHTML = `
    <input type="text" placeholder="Header-Name" value="${key}">
    <input type="text" placeholder="value" value="${value}">
    <button data-act="removeRow">×</button>
  `;
  list.appendChild(row);
}

function getHeaders() {
  const rows = document.querySelectorAll('#cp-headers-list .header-row');
  const h = {};
  rows.forEach(row => {
    const [k, v] = row.querySelectorAll('input');
    if (k.value.trim()) h[k.value.trim()] = v.value.trim();
  });
  return h;
}

async function companionSend() {
  const btn    = document.getElementById('cp-send');
  const method = document.getElementById('cp-method').value;
  const url    = document.getElementById('cp-url').value.trim();
  const body   = document.getElementById('cp-body').value.trim();

  btn.disabled    = true;
  btn.textContent = 'Sending…';

  const respPane = document.getElementById('cp-response');
  respPane.style.display = 'none';

  const start = Date.now();
  try {
    const opts = { method, headers: getHeaders() };
    if (body && method !== 'GET' && method !== 'DELETE') opts.body = body;

    const r   = await fetch(url, opts);
    const ms  = Date.now() - start;
    const txt = await r.text();

    let pretty = txt;
    try { pretty = JSON.stringify(JSON.parse(txt), null, 2); } catch (_) {}

    const pill = document.getElementById('cp-status-pill');
    pill.textContent = r.status;
    pill.className = 'status-pill ' + (r.status < 300 ? 'status-2xx' : r.status < 500 ? 'status-4xx' : 'status-5xx');

    document.getElementById('cp-time').textContent = `${ms}ms`;
    document.getElementById('cp-response-body').textContent = pretty;
    respPane.style.display = 'block';
  } catch (err) {
    const pill = document.getElementById('cp-status-pill');
    pill.textContent = 'Error';
    pill.className = 'status-pill status-5xx';
    document.getElementById('cp-time').textContent = '';
    document.getElementById('cp-response-body').textContent = err.message;
    respPane.style.display = 'block';
  } finally {
    btn.disabled    = false;
    btn.textContent = 'Send';
  }
}

function copyResponse() {
  const txt = document.getElementById('cp-response-body').textContent;
  navigator.clipboard.writeText(txt);
}

// Enter key on URL field sends
document.getElementById('cp-url').addEventListener('keydown', e => {
  if (e.key === 'Enter') companionSend();
});

// Init companion
buildDefaultHeaders();

Object.assign(ACTIONS, {
  toggleEndpoint: (_a, el) => toggleEndpoint(el),
  copyResponse:   () => copyResponse(),
  companionSend:  () => companionSend(),
  addHeaderRow:   () => addHeaderRow(),
  companionTab:   ([tab]) => companionTab(tab),
  removeRow:      (_a, el) => el.parentElement.remove(),
});
