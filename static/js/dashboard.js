const S = { token: null, username: null, role: null, teams: [], activeTeamId: null };

// ── Boot ──────────────────────────────────────────────────────────────────
(function boot() {
  const saved = sessionStorage.getItem('aegis_session');
  if (!saved) { window.location.href = '/login'; return; }

  let d;
  try { d = JSON.parse(saved); } catch (_) { window.location.href = '/login'; return; }

  fetch('/api/me', { headers: { 'Authorization': 'Bearer ' + d.token } })
    .then(r => {
      if (!r.ok) { sessionStorage.removeItem('aegis_session'); window.location.href = '/login'; return null; }
      return r.json();
    })
    .then(me => {
      if (!me) return;
      if (me.role === 'admin') { window.location.href = '/admin'; return; }

      S.token    = d.token;
      S.username = me.username;
      S.role     = me.role;

      document.getElementById('topbar-name').textContent = me.username;
      document.getElementById('main').style.display = 'block';
      loadTeam();
    })
    .catch(() => { window.location.href = '/login'; });
})();

// ── Tab switching ─────────────────────────────────────────────────────────
let activeTab = 'overview';
function switchTab(tab) {
  ['overview','webhooks','activity'].forEach(t => {
    document.getElementById('pane-' + t).style.display = t === tab ? '' : 'none';
    document.getElementById('tab-' + t).classList.toggle('dash-tab-active', t === tab);
  });
  activeTab = tab;
  if (tab === 'webhooks' && !S._whLoaded) loadWebhooks();
  if (tab === 'activity' && !S._actLoaded) loadActivity();
}

// ── Load team data ────────────────────────────────────────────────────────
async function loadTeam() {
  try {
    const r = await fetch('/api/my-teams', { headers: { 'Authorization': 'Bearer ' + S.token } });
    if (!r.ok) throw new Error(await r.text());
    const d = await r.json();
    S.teams = d.teams || [];
    S.activeTeamId = S.teams[0]?.id || null;
    render(S.teams);
  } catch (e) {
    showErr('Failed to load team data: ' + e.message);
    document.getElementById('content').innerHTML = '';
  }
}

function showErr(msg) {
  const b = document.getElementById('err-banner');
  b.textContent = msg;
  b.style.display = 'block';
}

function copyTeamId() {
  const val = document.getElementById('team-id-val').textContent;
  navigator.clipboard.writeText(val).then(() => flash('Team ID copied'));
}

// Copy-to-clipboard buttons carry their value in data-copy rather than in
// an inline handler: an attribute value is decoded by the HTML parser before
// any script in it is compiled, so an interpolated quote used to escape the
// string and run as code.
document.addEventListener('click', e => {
  const el = e.target.closest('[data-copy]');
  if (!el) return;
  navigator.clipboard.writeText(el.dataset.copy)
    .then(() => flash(el.dataset.copied || 'Copied'));
});

function flash(msg) {
  const el = Object.assign(document.createElement('div'), {
    textContent: msg,
    style: 'position:fixed;bottom:20px;right:20px;background:var(--surface-3);border:1px solid var(--border-hi);color:var(--text-1);font-size:12px;padding:8px 16px;border-radius:6px;z-index:9999;animation:fadeIn .15s ease'
  });
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 2500);
}

// ── Render overview ───────────────────────────────────────────────────────
function render(teams) {
  const now  = Date.now();
  const soon = 30 * 24 * 60 * 60 * 1000;

  const allRegs    = teams.flatMap(t => t.registries || []);
  const activeKeys = allRegs.filter(r => r.key_preview).length;
  const expiring   = allRegs.filter(r => {
    if (!r.expires_at) return false;
    const ms = new Date(r.expires_at).getTime() - now;
    return ms > 0 && ms < soon;
  }).length;

  if (teams.length === 1) {
    document.getElementById('team-heading').textContent = teams[0].name;
    const idRow = document.getElementById('team-id-row');
    idRow.style.display = 'flex';
    document.getElementById('team-id-val').textContent = teams[0].id;
  } else if (teams.length > 1) {
    document.getElementById('team-heading').textContent = 'My Teams';
    const badge = document.getElementById('team-badge');
    badge.textContent = teams.length;
    badge.style.display = 'inline-flex';
  }

  document.getElementById('stat-regs').textContent     = allRegs.length;
  document.getElementById('stat-keys').textContent     = activeKeys;
  document.getElementById('stat-expiring').textContent = expiring;
  document.getElementById('stat-requests').textContent = '…';
  document.getElementById('stats-row').style.display   = 'grid';

  // Load request count async
  if (S.activeTeamId) {
    fetch('/api/my-metrics?team_id=' + S.activeTeamId, { headers: { 'Authorization': 'Bearer ' + S.token } })
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (d) document.getElementById('stat-requests').textContent = d.requests?.total ?? '—';
      }).catch(() => {});
  }

  if (!allRegs.length) {
    document.getElementById('content').innerHTML =
      `<div class="card"><div class="empty-state">No registries assigned to your team yet.<br>Contact your administrator.</div></div>`;
    return;
  }

  document.getElementById('content').innerHTML = teams.map(team => {
    const regs = team.registries || [];
    if (!regs.length) return '';
    const header = teams.length > 1
      ? `<div style="margin-bottom:12px;">
           <div style="font-size:10px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--text-3);">${x(team.name)}</div>
           <div style="display:flex;align-items:center;gap:6px;margin-top:4px;">
             <code style="font-size:10px;color:var(--text-3);background:var(--surface-2);border:1px solid var(--border);border-radius:3px;padding:1px 6px;">${team.id}</code>
             <button data-copy="${x(team.id)}" data-copied="ID copied" style="background:none;border:1px solid var(--border);border-radius:3px;color:var(--text-3);cursor:pointer;font-size:9px;padding:1px 5px;font-family:'Fira Code',monospace;">copy</button>
           </div>
         </div>`
      : '';
    return header + regs.map(reg => buildRegCard(reg, now, soon)).join('');
  }).join('');
}

// ── Webhooks tab ──────────────────────────────────────────────────────────
const ALL_EVENTS = ['key.expiring_soon','key.rotated','key.revoked','policy.violated'];

async function loadWebhooks() {
  S._whLoaded = true;
  const tid = S.activeTeamId;
  if (!tid) {
    document.getElementById('wh-content').innerHTML = `<div class="empty-state">No team assigned.</div>`;
    return;
  }
  try {
    const r = await fetch('/api/my-webhook?team_id=' + tid, { headers: { 'Authorization': 'Bearer ' + S.token } });
    if (!r.ok) throw new Error(await r.text());
    const d = await r.json();
    renderWebhooks(d);
  } catch (e) {
    document.getElementById('wh-content').innerHTML = `<div class="empty-state" style="color:var(--danger)">Failed: ${x(e.message)}</div>`;
  }
}

function renderWebhooks(d) {
  const wh   = d.webhook || {};
  const notif = d.notifications || {};
  const inboundUrl = window.location.origin + d.inbound_url;

  document.getElementById('wh-content').innerHTML = `

    <!-- Inbound webhook URL -->
    <div class="wh-section">
      <div class="wh-section-hd">
        <div>
          <div style="font-size:13px;font-weight:600;color:var(--text-1)">Inbound Webhook</div>
          <div style="font-size:11px;color:var(--text-3);margin-top:2px">Auto-generated URL for your CI/CD to trigger Aegis actions (key rotation, ping)</div>
        </div>
      </div>
      <div class="wh-section-bd">
        <div style="font-size:11px;color:var(--text-3);margin-bottom:6px">POST to this URL with your signing secret as the Bearer token:</div>
        <div class="inbound-url-box">
          <code style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${x(inboundUrl)}</code>
          <button data-copy="${x(inboundUrl)}" data-copied="URL copied" style="background:none;border:1px solid var(--border-hi);border-radius:4px;color:var(--text-2);cursor:pointer;font-size:10px;padding:3px 8px;font-family:'Fira Code',monospace;white-space:nowrap;">Copy URL</button>
        </div>
        <div style="font-size:11px;color:var(--text-3);margin-top:10px">
          Supported actions: <code style="color:var(--text-2)">ping</code>, <code style="color:var(--text-2)">rotate_key</code><br>
          Requires signing secret to be set (see Outgoing Webhook section below).
        </div>
        <div style="margin-top:12px;background:var(--surface-2);border:1px solid var(--border);border-radius:5px;padding:10px 12px;font-size:11px;color:var(--text-3);">
          <div style="color:var(--text-2);margin-bottom:4px;font-weight:600;">Example — rotate a registry key from CI/CD:</div>
          <code style="color:var(--indigo-hi);display:block;white-space:pre-wrap;">curl -X POST ${x(inboundUrl)} \\
  -H "Authorization: Bearer &lt;signing_secret&gt;" \\
  -H "Content-Type: application/json" \\
  -d '{"action":"rotate_key","registry_id":"&lt;reg-uuid&gt;"}'</code>
        </div>
      </div>
    </div>

    <!-- Outgoing HTTP webhook -->
    <div class="wh-section">
      <div class="wh-section-hd">
        <div>
          <div style="font-size:13px;font-weight:600;color:var(--text-1)">Outgoing HTTP Webhook</div>
          <div style="font-size:11px;color:var(--text-3);margin-top:2px">Aegis POSTs signed events to your endpoint</div>
        </div>
        <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
          <span style="font-size:11px;color:var(--text-3)">Enabled</span>
          <input type="checkbox" id="wh-enabled" ${wh.enabled ? 'checked' : ''} style="accent-color:var(--indigo);width:14px;height:14px;">
        </label>
      </div>
      <div class="wh-section-bd">
        <div class="form-row">
          <span class="form-label">Endpoint URL</span>
          <input id="wh-url" class="form-input" placeholder="https://your-service.example.com/webhook" value="${x(wh.url||'')}">
        </div>
        <div class="form-row" style="align-items:start">
          <span class="form-label" style="padding-top:4px">Subscribe to</span>
          <div class="checkbox-row">
            ${ALL_EVENTS.map(e => `
              <div class="event-chip">
                <input type="checkbox" id="ev-${e}" value="${e}" ${(wh.events||[]).includes(e)?'checked':''}>
                <label for="ev-${e}">${e}</label>
              </div>`).join('')}
          </div>
        </div>
        <div class="form-row">
          <span class="form-label">HMAC Signing</span>
          <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
            <input type="checkbox" id="wh-signing" ${wh.signing_enabled?'checked':''} style="accent-color:var(--indigo);width:14px;height:14px;">
            <span style="font-size:11px;color:var(--text-2)">Sign requests (X-Aegis-Signature header)</span>
          </label>
        </div>
        <div class="form-row">
          <span class="form-label">Signing secret</span>
          <input id="wh-secret" class="form-input" type="password" placeholder="${wh.has_signing_secret ? '••••••••  (leave blank to keep)' : 'Auto-generated if signing enabled'}" value="">
        </div>
        <div class="form-row">
          <span class="form-label">Inbound token</span>
          <label style="display:flex;align-items:center;gap:6px">
            <input type="checkbox" id="wh-rotate-inbound">
            <span style="font-size:11px;color:var(--text-2)">
              ${wh.has_inbound_token ? 'Replace the token CI uses to call the inbound endpoint' : 'Generate a token for the inbound endpoint'}
              — shown once, then only its hash is kept
            </span>
          </label>
        </div>
        <div style="display:flex;gap:8px;margin-top:4px">
          <button class="btn btn-primary btn-sm" ${act('saveWebhook')}>Save Webhook</button>
          ${wh.id ? `<button class="btn btn-ghost btn-sm" ${act('deleteWebhook')}>Remove</button>` : ''}
        </div>
      </div>
    </div>

    <!-- Notification channels -->
    <div class="wh-section">
      <div class="wh-section-hd">
        <div>
          <div style="font-size:13px;font-weight:600;color:var(--text-1)">Notification Channels</div>
          <div style="font-size:11px;color:var(--text-3);margin-top:2px">Best-effort delivery — Slack, MS Teams, Discord</div>
        </div>
      </div>
      <div class="wh-section-bd">
        <div class="form-row">
          <span class="form-label" style="display:flex;align-items:center;gap:5px;">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="#e8b44e"><path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312zM15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z"/></svg>
            Slack
          </span>
          <input id="notif-slack" class="form-input" placeholder="https://hooks.slack.com/services/…" value="${x(notif.slack_webhook_url||'')}">
        </div>
        <div class="form-row">
          <span class="form-label" style="display:flex;align-items:center;gap:5px;">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="#5558AF"><path d="M24 12c0 6.627-5.373 12-12 12S0 18.627 0 12 5.373 0 12 0s12 5.373 12 12z"/><path fill="#fff" d="M10.154 13.5h-.677l-.247-.738H7.884L7.64 13.5H7l1.215-3.5h.725l1.214 3.5zm-1.106-1.284-.39-1.17-.39 1.17h.78zM14.077 13.5h-.63l-.03-.447c-.202.338-.544.507-.926.507-.917 0-1.463-.74-1.463-1.81 0-1.072.566-1.812 1.465-1.812.365 0 .694.152.895.44V10h.69v3.5zm-.69-1.75c0-.7-.283-1.122-.775-1.122-.492 0-.775.422-.775 1.122 0 .7.283 1.122.775 1.122.492 0 .775-.422.775-1.122zM16.077 13.5h-.69V10h.69v3.5zM17 13.5h-.69V10H17v3.5z"/></svg>
            MS Teams
          </span>
          <input id="notif-teams" class="form-input" placeholder="https://your-org.webhook.office.com/…" value="${x(notif.ms_teams_webhook_url||'')}">
        </div>
        <div class="form-row">
          <span class="form-label" style="display:flex;align-items:center;gap:5px;">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="#5865F2"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057.1 18.08.114 18.1.133 18.11a19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03z"/></svg>
            Discord
          </span>
          <input id="notif-discord" class="form-input" placeholder="https://discord.com/api/webhooks/…" value="${x(notif.discord_webhook_url||'')}">
        </div>
        <button class="btn btn-primary btn-sm" ${act('saveWebhook')}>Save Channels</button>
      </div>
    </div>
  `;
}

async function saveWebhook() {
  const tid = S.activeTeamId;
  const url     = document.getElementById('wh-url')?.value.trim();
  const enabled = document.getElementById('wh-enabled')?.checked ?? true;
  const signing = document.getElementById('wh-signing')?.checked ?? false;
  const secret  = document.getElementById('wh-secret')?.value.trim();
  const rotateInbound = document.getElementById('wh-rotate-inbound')?.checked ?? false;
  const events  = ALL_EVENTS.filter(e => document.getElementById('ev-'+e)?.checked);

  const body = {
    url: url || null,
    enabled,
    events,
    signing_enabled: signing,
    signing_secret: secret || null,
    rotate_inbound_token: rotateInbound,
    slack_webhook_url:    document.getElementById('notif-slack')?.value.trim() || null,
    ms_teams_webhook_url: document.getElementById('notif-teams')?.value.trim() || null,
    discord_webhook_url:  document.getElementById('notif-discord')?.value.trim() || null,
  };

  try {
    const r = await fetch('/api/my-webhook?team_id=' + tid, {
      method: 'PUT',
      headers: { 'Authorization': 'Bearer ' + S.token, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error((await r.json()).detail || await r.text());
    const saved = await r.json();
    if (saved.inbound_token) {
      // Shown once: only its hash is stored, so there is no way to display
      // it again. Same contract as an API key.
      showInboundToken(saved.inbound_token);
    } else {
      flash('Webhook settings saved');
    }
    S._whLoaded = false;
    loadWebhooks();
  } catch (e) {
    showErr('Save failed: ' + e.message);
  }
}

function showInboundToken(token) {
  const box = document.createElement('div');
  box.className = 'card';
  box.style.cssText = 'margin-top:10px;padding:12px;border:1px solid var(--accent)';
  const title = document.createElement('div');
  title.style.cssText = 'font-weight:600;margin-bottom:6px';
  title.textContent = 'New inbound token — copy it now';
  const note = document.createElement('div');
  note.style.cssText = 'font-size:11px;color:var(--text-2);margin-bottom:8px';
  note.textContent = 'Only its hash is stored, so this cannot be shown again. '
                   + 'Use it as the Bearer token when calling the inbound endpoint.';
  const value = document.createElement('code');
  value.style.cssText = 'display:block;word-break:break-all;user-select:all';
  value.textContent = token;
  box.append(title, note, value);
  const anchor = document.getElementById('wh-url')?.closest('.card') || document.body;
  anchor.appendChild(box);
}

async function deleteWebhook() {
  if (!confirm('Remove outgoing webhook?')) return;
  try {
    await fetch('/api/my-webhook?team_id=' + S.activeTeamId, {
      method: 'DELETE',
      headers: { 'Authorization': 'Bearer ' + S.token },
    });
    flash('Webhook removed');
    S._whLoaded = false;
    loadWebhooks();
  } catch (e) {
    showErr('Delete failed: ' + e.message);
  }
}

// ── Activity tab ──────────────────────────────────────────────────────────
async function loadActivity() {
  S._actLoaded = true;
  const tid = S.activeTeamId;
  if (!tid) {
    document.getElementById('act-content').innerHTML = `<div class="empty-state">No team assigned.</div>`;
    return;
  }
  try {
    const r = await fetch('/api/my-metrics?team_id=' + tid, { headers: { 'Authorization': 'Bearer ' + S.token } });
    if (!r.ok) throw new Error(await r.text());
    const d = await r.json();
    renderActivity(d);
  } catch (e) {
    document.getElementById('act-content').innerHTML = `<div class="empty-state" style="color:var(--danger)">Failed: ${x(e.message)}</div>`;
  }
}

function renderActivity(d) {
  const req = d.requests || {};
  const keys = d.keys || {};
  const recent = d.recent_audit || [];

  document.getElementById('act-content').innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:24px">
      <div class="stat-card accent-indigo">
        <div class="section-label">Total Requests</div>
        <div style="font-size:24px;font-weight:600;color:var(--text-1);margin:6px 0 4px">${req.total ?? 0}</div>
        <div style="font-size:11px;color:var(--text-3)">${req.success ?? 0} success · ${req.denied ?? 0} denied · ${req.error ?? 0} error</div>
      </div>
      <div class="stat-card accent-emerald">
        <div class="section-label">Active Keys</div>
        <div style="font-size:24px;font-weight:600;color:var(--success);margin:6px 0 4px">${keys.active ?? 0}</div>
        <div style="font-size:11px;color:var(--text-3)">${keys.expiring_soon ?? 0} expiring within 30 days</div>
      </div>
      <div class="stat-card accent-amber">
        <div class="section-label">Revoked Keys</div>
        <div style="font-size:24px;font-weight:600;color:var(--text-2);margin:6px 0 4px">${keys.revoked ?? 0}</div>
        <div style="font-size:11px;color:var(--text-3)">historical</div>
      </div>
    </div>

    <div class="card">
      <div style="padding:12px 16px;border-bottom:1px solid var(--border)">
        <div style="font-size:12px;font-weight:600;color:var(--text-1)">Recent API Activity</div>
      </div>
      ${recent.length ? `
        <div class="act-row act-hd">
          <div>Timestamp</div><div>Event</div><div>Outcome</div><div>Registry</div><div>Source IP</div>
        </div>
        ${recent.map(e => `
          <div class="act-row">
            <div style="color:var(--text-3)">${e.timestamp ? e.timestamp.replace('T',' ').slice(0,19) : '—'}</div>
            <div style="color:var(--text-2)">${x(e.event||'—')}</div>
            <div><span class="pill ${e.outcome==='success'?'pill-green':e.outcome==='denied'?'pill-red':'pill-amber'}">${x(e.outcome||'—')}</span></div>
            <div style="color:var(--text-2)">${x(e.registry_name||'—')}</div>
            <div style="color:var(--text-3)">${x(e.source_ip||'—')}</div>
          </div>`).join('')}
      ` : `<div class="empty-state">No activity yet.</div>`}
    </div>
  `;
}

function buildRegCard(reg, now, soon) {
  const objects = reg.objects || [];
  const isExpiring = reg.expires_at && (() => {
    const exp = new Date(reg.expires_at).getTime();
    return exp > now && exp - now < soon;
  })();
  const isExpired = reg.expires_at && new Date(reg.expires_at).getTime() < now;

  let expiryBadge = '';
  if (isExpired) {
    expiryBadge = `<span class="pill pill-red">Expired ${x(reg.expires_at.slice(0,10))}</span>`;
  } else if (isExpiring) {
    expiryBadge = `<span class="pill pill-amber">Expires ${x(reg.expires_at.slice(0,10))}</span>`;
  }

  const keyRow = reg.key_preview
    ? `<div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;flex-wrap:wrap">
         <span class="section-label" style="margin:0">API Key</span>
         <span class="key-token">
           <svg width="10" height="10" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
             <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
           </svg>
           ${x(reg.key_preview)}••••
         </span>
         <span style="font-size:10px;color:var(--text-3)">Preview only — full key provided at issuance</span>
         ${expiryBadge}
       </div>`
    : `<div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px">
         <svg width="12" height="12" fill="none" stroke="var(--text-3)" stroke-width="2" viewBox="0 0 24 24">
           <path d="M18.364 18.364A9 9 0 0 0 5.636 5.636m12.728 12.728A9 9 0 0 1 5.636 5.636m12.728 12.728L5.636 5.636"/>
         </svg>
         <span style="font-size:11px;color:var(--text-3)">No active key — contact your administrator</span>
       </div>`;

  const objectsBlock = objects.length
    ? `<table class="data-table">
         <thead>
           <tr>
             <th>Object</th>
             <th>Vendor</th>
             <th>Path</th>
           </tr>
         </thead>
         <tbody>
           ${objects.map(o => {
             // o can be a string (name only) or an object with fields
             if (typeof o === 'string') {
               return `<tr><td class="td-primary">${x(o)}</td><td>—</td><td>—</td></tr>`;
             }
             return `<tr>
               <td class="td-primary">${x(o.name || o)}</td>
               <td>${o.vendor ? `<span class="pill pill-indigo">${x(o.vendor)}</span>` : '—'}</td>
               <td style="font-size:11px;color:var(--text-3)">${x(o.path || '—')}</td>
             </tr>`;
           }).join('')}
         </tbody>
       </table>`
    : `<div class="empty-state" style="padding:20px">No objects in this registry.</div>`;

  return `
  <div class="card slide-up" style="margin-bottom:16px">
    <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid var(--border)">
      <div style="display:flex;align-items:center;gap:8px">
        <svg width="14" height="14" fill="none" stroke="var(--indigo-hi)" stroke-width="2" viewBox="0 0 24 24">
          <rect x="2" y="3" width="20" height="5" rx="1"/><rect x="2" y="10" width="20" height="5" rx="1"/><rect x="2" y="17" width="20" height="5" rx="1"/>
        </svg>
        <span style="font-size:13px;font-weight:600;color:var(--text-1)">${x(reg.name)}</span>
        <span class="badge-count">${objects.length} obj</span>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        ${!isExpired && !isExpiring && reg.expires_at ? `<span style="font-size:10px;color:var(--text-3)">exp ${reg.expires_at.slice(0,10)}</span>` : ''}
        ${reg.key_preview ? `<span class="pill pill-green">Active</span>` : `<span class="pill pill-red">No Key</span>`}
      </div>
    </div>
    ${keyRow}
    ${objectsBlock}
  </div>`;
}

// ── Escape HTML ───────────────────────────────────────────────────────────

// ── Sign out ──────────────────────────────────────────────────────────────
async function signOut() {
  try {
    await fetch('/api/logout', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + S.token }
    });
  } catch (_) {}
  sessionStorage.removeItem('aegis_session');
  window.location.href = '/login';
}

Object.assign(ACTIONS, {
  saveWebhook:   () => saveWebhook(),
  deleteWebhook: () => deleteWebhook(),
  copyTeamId:    () => copyTeamId(),
  signOut:       () => signOut(),
  switchTab:     ([tab]) => switchTab(tab),
});
