async function login() {
  const u   = document.getElementById('u').value.trim();
  const p   = document.getElementById('p').value;
  const btn = document.getElementById('btn');
  const err = document.getElementById('err');

  if (!u || !p) return;

  btn.disabled    = true;
  btn.textContent = 'Signing in…';
  err.style.display = 'none';

  try {
    const r = await fetch('/api/login', {
      method:  'POST',
      headers: {'Content-Type': 'application/json'},
      body:    JSON.stringify({username: u, password: p}),
    });
    const d = await r.json();
    if (!r.ok) {
      err.textContent   = d.detail || 'Invalid credentials';
      err.style.display = 'block';
      return;
    }
    sessionStorage.setItem('aegis_session', JSON.stringify(d));
    window.location.href = d.role === 'admin' ? '/admin' : '/dashboard';
  } catch (e) {
    err.textContent   = 'Connection error';
    err.style.display = 'block';
  } finally {
    btn.disabled    = false;
    btn.textContent = 'Sign In';
  }
}

// If already logged in, redirect straight through
const saved = sessionStorage.getItem('aegis_session');
if (saved) {
  try {
    const s = JSON.parse(saved);
    if (s.token) {
      fetch('/api/me', {headers: {'Authorization': `Bearer ${s.token}`}})
        .then(r => r.ok ? r.json() : null)
        .then(me => { if (me) window.location.href = me.role === 'admin' ? '/admin' : '/dashboard'; })
        .catch(() => {});
    }
  } catch (_) {}
}

Object.assign(ACTIONS, {
  login: () => login(),
});
