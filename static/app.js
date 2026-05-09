// ===================== STATE =====================
let USER = null;
let IN_SESSION_CHECK = false;
let CLIENTS = [];
let CLIENT_PREV = {};
let CLIENT_HISTORY = {}; // id -> array of recent (rx+tx)/s samples for sparkline
let ADMIN_TAB = 'general';
let SETUP_STEP = 1;
let SERVER_INFO = null;
const HISTORY_LEN = 14;

// ===================== HELPERS =====================
function $(id) { return document.getElementById(id); }
function $$(sel) { return document.querySelectorAll(sel); }

function showToast(msg, type) {
  const el = document.createElement('div');
  el.className = 'toast ' + (type || '');
  el.textContent = msg;
  $('toasts').appendChild(el);
  setTimeout(() => el.remove(), 5000);
}

function formatBytes(bytes, decimals = 1) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1000, sizes = ['B','KB','MB','GB','TB'];
  const i = Math.min(sizes.length - 1, Math.floor(Math.log(Math.abs(bytes)) / Math.log(k)));
  return (bytes / Math.pow(k, i)).toFixed(decimals) + ' ' + sizes[i];
}

function timeAgo(date) {
  if (!date) return 'never';
  const seconds = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
  if (seconds < 10) return 'just now';
  if (seconds < 60) return seconds + 's ago';
  const mins = Math.floor(seconds / 60);
  if (mins < 60) return mins + 'm ago';
  const hours = Math.floor(mins / 60);
  if (hours < 24) return hours + 'h ago';
  return Math.floor(hours / 24) + 'd ago';
}

function dateShort(d) {
  if (!d) return 'never';
  const dt = new Date(d);
  if (isNaN(dt)) return 'never';
  const now = new Date();
  const diffDays = Math.round((dt - now) / 86400000);
  if (diffDays > 0 && diffDays <= 30) return 'in ' + diffDays + 'd';
  if (diffDays < 0 && diffDays >= -30) return Math.abs(diffDays) + 'd ago';
  return dt.toISOString().slice(0, 10);
}

function isConnected(handshake) {
  if (!handshake) return false;
  return (Date.now() - new Date(handshake).getTime()) < 180000;
}

function esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function escJs(s) {
  if (s == null) return '';
  return String(s).replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/"/g,'\\"').replace(/\n/g,'\\n').replace(/\r/g,'\\r');
}

// Inline SVG sparkline from a values array. Returns empty string if not enough data.
function renderSpark(values, w = 60, h = 22, color) {
  if (!values || values.length < 2) {
    return `<svg class="peer-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><polyline fill="none" stroke="var(--fg-dim)" stroke-width="1.2" stroke-dasharray="2 3" points="0,${h/2} ${w},${h/2}"/></svg>`;
  }
  const max = Math.max(...values, 1);
  const points = values.map((v, i) => {
    const x = (i / (values.length - 1)) * w;
    const y = h - (v / max) * (h - 4) - 2;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  const stroke = color || 'var(--fg-soft)';
  return `<svg class="peer-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><polyline fill="none" stroke="${stroke}" stroke-width="1.4" points="${points}"/></svg>`;
}

// ===================== API =====================
async function api(method, path, body) {
  const opts = { method, credentials: 'include', headers: {} };
  if (body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const res = await fetch(path, opts);
  // 401 on the login endpoint itself is "wrong credentials" — let the caller see it.
  // 401 anywhere else is "session expired" — redirect to /login.
  const isLoginEndpoint = method === 'POST' && path === '/api/session';
  if (res.status === 401 && !isLoginEndpoint) {
    USER = null;
    if (!IN_SESSION_CHECK) navigate('/login');
    return null;
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || err.message || res.statusText);
  }
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) return res.json();
  return res.text();
}
const GET = (p) => api('GET', p);
const POST = (p, b) => api('POST', p, b);
const DEL = (p) => api('DELETE', p);

// ===================== ROUTING =====================
function navigate(hash) {
  window.location.hash = hash;
}

function route() {
  const hash = window.location.hash || '#/';
  const path = hash.slice(1);

  // Hide every page
  $$('.page').forEach(p => p.classList.remove('active'));

  if (path !== '/login' && path !== '/setup' && !path.startsWith('/setup') && !path.startsWith('/cnf')) {
    checkSession().then(ok => { if (ok) routeInternal(path); });
  } else {
    routeInternal(path);
  }
}

function routeInternal(path) {
  if (path === '/login') {
    // If no admin user exists yet, send them through the setup wizard first.
    GET('/api/information').then(info => {
      if (info && info.setupNeeded) {
        navigate('/setup');
        return;
      }
      $('page-login').classList.add('active');
      if (location.protocol !== 'https:' && location.hostname !== 'localhost') {
        $('insecure-warning').style.display = 'flex';
      }
    }).catch(() => {
      $('page-login').classList.add('active');
    });
  } else if (path === '/setup' || path.startsWith('/setup')) {
    $('page-setup').classList.add('active');
    loadSetup();
  } else if (path === '/') {
    $('page-clients').classList.add('active');
    renderNav();
    refreshClients();
  } else if (path.startsWith('/clients/')) {
    $('page-client-edit').classList.add('active');
    renderNav();
    const id = path.split('/')[2];
    loadClientEdit(id);
  } else if (path === '/me') {
    $('page-me').classList.add('active');
    renderNav();
    loadMe();
  } else if (path === '/admin') {
    $('page-admin').classList.add('active');
    renderNav();
    showAdminTab(ADMIN_TAB);
  } else {
    $('page-clients').classList.add('active');
    renderNav();
    refreshClients();
  }
}

window.addEventListener('hashchange', route);
window.addEventListener('load', route);

// Auto-inject tooltip chips on labels with title attribute
function injectTooltips() {
  setTimeout(() => {
    document.querySelectorAll('label[title], .field-label[title]').forEach(l => {
      if (!l.querySelector('.tip')) {
        const t = document.createElement('span');
        t.className = 'tip'; t.dataset.tip = l.title; t.textContent = '?';
        l.title = ''; l.appendChild(t);
      }
    });
  }, 50);
}
window.addEventListener('load', injectTooltips);

// ===================== AUTH =====================
async function checkSession() {
  IN_SESSION_CHECK = true;
  try {
    const data = await GET('/api/session');
    if (data && data.user) {
      IN_SESSION_CHECK = false;
      USER = data.user;
      // Background-fetch server info for sidebar pill
      if (!SERVER_INFO) GET('/api/information').then(i => { SERVER_INFO = i; renderNav(); }).catch(() => {});
      return true;
    }
  } catch(e) {}
  USER = null;
  if (window.location.hash !== '#/login') {
    try {
      const info = await GET('/api/information');
      if (info && info.setupNeeded) {
        IN_SESSION_CHECK = false;
        navigate('/setup');
        return false;
      }
    } catch(e) {}
  }
  IN_SESSION_CHECK = false;
  navigate('/login');
  return false;
}

async function doLogin(e) {
  e.preventDefault();
  const body = {
    username: $('login-user').value,
    password: $('login-pass').value,
    totp: $('login-totp').value || undefined,
    remember: $('login-remember').checked
  };
  try {
    const res = await POST('/api/session', body);
    if (res && res.status === 'TOTP_REQUIRED') {
      $('totp-group').style.display = 'flex';
      $('login-totp').focus();
      showToast('TOTP code required', 'error');
    } else if (res && res.user) {
      USER = res.user;
      navigate('/');
    }
  } catch(e) {
    showToast(e.message, 'error');
  }
}

async function doLogout() {
  await DEL('/api/session').catch(() => {});
  USER = null;
  navigate('/login');
}

function renderNav() {
  if (!USER) return;
  const path = window.location.hash.slice(1) || '/';
  let activeRoute = '/';
  if (path === '/me') activeRoute = '/me';
  else if (path === '/admin') activeRoute = '/admin';
  else if (path === '/' || path.startsWith('/clients/')) activeRoute = '/';

  document.querySelectorAll('[data-route]').forEach(el => {
    el.classList.toggle('is-active', el.dataset.route === activeRoute);
  });

  // Reveal admin link only for admins (role === 1)
  const isAdmin = USER.role === 1;
  $('side-admin-link').style.display = isAdmin ? '' : 'none';
  $('side-admin-label').style.display = isAdmin ? '' : 'none';

  // Sidebar peer count + active count
  $('side-peer-count').textContent = CLIENTS.length || '—';
  const active = CLIENTS.filter(c => isConnected(c.latestHandshakeAt)).length;
  $('side-peer-active').textContent = CLIENTS.length ? `${active} / ${CLIENTS.length}` : '— / —';

  // Server version pill
  if (SERVER_INFO && SERVER_INFO.currentRelease) {
    $('side-version').textContent = 'v' + SERVER_INFO.currentRelease;
  }
}

// ===================== CLIENTS =====================
let clientRefreshTimer = null;
let clientFilter = '';

async function refreshClients() {
  if (clientRefreshTimer) { clearTimeout(clientRefreshTimer); clientRefreshTimer = null; }
  try {
    const data = await GET('/api/client');
    if (!data) return;
    const now = Date.now();
    for (const c of data) {
      const prev = CLIENT_PREV[c.id];
      if (prev && prev.transferRx != null && c.transferRx != null && prev.ts) {
        const dt = Math.max(1, (now - prev.ts) / 1000);
        c.rxRate = Math.max(0, (c.transferRx - prev.transferRx) / dt);
        c.txRate = Math.max(0, (c.transferTx - prev.transferTx) / dt);
      }
      // Maintain history ring buffer
      const total = (c.rxRate || 0) + (c.txRate || 0);
      const hist = CLIENT_HISTORY[c.id] || [];
      hist.push(total);
      if (hist.length > HISTORY_LEN) hist.shift();
      CLIENT_HISTORY[c.id] = hist;
      CLIENT_PREV[c.id] = { transferRx: c.transferRx, transferTx: c.transferTx, ts: now };
    }
    CLIENTS = data;
    renderClients();
    renderNav();
  } catch(e) {
    if (USER) showToast(e.message, 'error');
  }
  // Only schedule next refresh if still on clients page
  if (window.location.hash === '#/' || window.location.hash === '' || window.location.hash === '#/clients') {
    clientRefreshTimer = setTimeout(refreshClients, 5000);
  }
}

(function wireClientSearch() {
  const el = $('client-search');
  if (!el) return;
  el.addEventListener('input', function() {
    clientFilter = this.value.toLowerCase();
    renderClients();
  });
})();

function renderStats() {
  const el = $('client-stats');
  if (!el) return;
  const total = CLIENTS.length;
  const active = CLIENTS.filter(c => isConnected(c.latestHandshakeAt)).length;
  const totalRxRate = CLIENTS.reduce((a, c) => a + (c.rxRate || 0), 0);
  const totalTxRate = CLIENTS.reduce((a, c) => a + (c.txRate || 0), 0);
  const totalThroughput = totalRxRate + totalTxRate;
  const lifetime = CLIENTS.reduce((a, c) => a + (c.transferRx || 0) + (c.transferTx || 0), 0);

  // Aggregate sparkline = sum across peers, last N samples
  const aggSpark = [];
  for (let i = 0; i < HISTORY_LEN; i++) {
    let sum = 0;
    for (const c of CLIENTS) {
      const h = CLIENT_HISTORY[c.id];
      if (h && h[h.length - HISTORY_LEN + i] != null) sum += h[h.length - HISTORY_LEN + i];
    }
    aggSpark.push(sum);
  }
  const validSpark = aggSpark.filter(v => v > 0).length >= 2;

  el.innerHTML = `
    <div class="stat">
      <div class="stat-label"><svg><use href="#i-users"/></svg> Active</div>
      <div class="stat-value">${active}<span class="unit"> / ${total}</span></div>
      <div class="stat-sub">${total - active} idle · last poll ${new Date().toLocaleTimeString()}</div>
    </div>
    <div class="stat">
      <div class="stat-label"><svg><use href="#i-zap"/></svg> Throughput</div>
      <div class="stat-value" style="display:flex;align-items:center;gap:10px">
        <span>${formatBytes(totalThroughput)}<span class="unit">/s</span></span>
        ${validSpark ? renderSpark(aggSpark, 56, 22, 'var(--accent)').replace('peer-spark', 'stat-spark').replace('class="stat-spark"', 'class="stat-spark" style="opacity:0.7;flex:0 0 auto"') : ''}
      </div>
      <div class="stat-sub"><span class="down">↓ ${formatBytes(totalRxRate)}/s</span> · ↑ ${formatBytes(totalTxRate)}/s</div>
    </div>
    <div class="stat">
      <div class="stat-label"><svg><use href="#i-server"/></svg> Lifetime transfer</div>
      <div class="stat-value">${formatBytes(lifetime, 1)}</div>
      <div class="stat-sub">across ${total} peer${total === 1 ? '' : 's'}</div>
    </div>
  `;
}

function renderClients() {
  $('clients-count').textContent = CLIENTS.length;
  renderStats();

  const el = $('client-list');
  let filtered = CLIENTS;
  if (clientFilter) {
    filtered = CLIENTS.filter(c =>
      (c.name || '').toLowerCase().includes(clientFilter) ||
      (c.ipv4Address || '').toLowerCase().includes(clientFilter) ||
      (c.ipv6Address || '').toLowerCase().includes(clientFilter)
    );
  }

  if (CLIENTS.length === 0) {
    el.innerHTML = `
      <div class="empty">
        <h3>No peers yet</h3>
        <p>Create your first peer to get started.</p>
        <div style="margin-top:14px"><button class="btn btn--primary" onclick="showCreateModal()"><svg><use href="#i-plus"/></svg> New peer</button></div>
      </div>`;
    return;
  }

  if (filtered.length === 0) {
    el.innerHTML = `
      <div class="tbl">
        <div class="tbl-head">
          <div></div><div>Peer</div><div>Address</div><div>Last seen</div><div>Throughput</div><div>Expires</div><div style="text-align:right">Actions</div>
        </div>
        <div style="padding:32px;text-align:center;color:var(--fg-mute);font-size:13px">No peers match "${esc(clientFilter)}"</div>
      </div>`;
    return;
  }

  const rows = filtered.map(c => {
    const online = isConnected(c.latestHandshakeAt);
    const enabled = c.enabled !== false;
    const expires = c.expiresAt ? dateShort(c.expiresAt) : 'never';
    const expiresSoon = c.expiresAt && (new Date(c.expiresAt) - Date.now()) < 7 * 86400000;
    const rxRate = c.rxRate ? formatBytes(c.rxRate) + '/s' : '—';
    const txRate = c.txRate ? formatBytes(c.txRate) + '/s' : '—';
    const lastSeen = timeAgo(c.latestHandshakeAt);
    const lastSeenFresh = c.latestHandshakeAt && (Date.now() - new Date(c.latestHandshakeAt).getTime()) < 60000;
    const sparkSvg = renderSpark(CLIENT_HISTORY[c.id] || []);

    const stateTag = !enabled ? '<span class="tag tag--neutral">disabled</span>'
                   : online ? '<span class="tag tag--ok">online</span>'
                   : '<span class="tag tag--neutral">idle</span>';

    const rowClass = !enabled ? 'tbl-row is-disabled' : 'tbl-row';

    const otlBlock = c.oneTimeLink ? `
      <div class="otl-bar">
        <svg><use href="#i-link"/></svg>
        <span class="otl-link">${esc(window.location.origin + '/cnf/' + c.oneTimeLink.oneTimeLink)}</span>
        <span>expires in</span>
        <span class="otl-countdown" id="otl-${c.id}">—</span>
        <button class="btn btn--quiet btn--sm" onclick="copyOTL(${c.id})"><svg><use href="#i-copy"/></svg> copy</button>
      </div>` : '';

    return `
      <div class="${rowClass}">
        <div><span class="dot ${online ? 'dot--on' : 'dot--off'}"></span></div>
        <div class="peer-name">
          <b onclick="navigate('/clients/${c.id}')">${esc(c.name)} ${stateTag}</b>
          <span>id ${c.id}${c.createdAt ? ' · created ' + new Date(c.createdAt).toISOString().slice(0,10) : ''}</span>
        </div>
        <div class="peer-addr">
          ${esc(c.ipv4Address || '—')}
          ${c.ipv6Address ? `<small>${esc(c.ipv6Address)}</small>` : ''}
        </div>
        <div class="peer-seen ${lastSeenFresh ? 'is-fresh' : ''}">${lastSeen}</div>
        <div class="peer-tx">
          <div class="peer-rate">
            <span class="down"><span class="arrow">↓</span>${rxRate}</span>
            <span class="up"><span class="arrow">↑</span>${txRate}</span>
          </div>
          ${sparkSvg}
        </div>
        <div class="peer-expiry ${expiresSoon ? 'is-soon' : ''}">${expires}</div>
        <div class="peer-actions">
          <label class="toggle ${enabled ? 'is-on' : ''}" title="${enabled ? 'Enabled' : 'Disabled'}" onclick="event.stopPropagation()">
            <input type="checkbox" ${enabled ? 'checked' : ''} onchange="toggleClient(${c.id}, this.checked)">
            <span class="toggle-track"></span>
          </label>
          <button class="btn btn--quiet btn--icon" title="QR code" onclick="showQR(${c.id})"><svg><use href="#i-qr"/></svg></button>
          <button class="btn btn--quiet btn--icon" title="Download config" onclick="downloadConfig(${c.id})"><svg><use href="#i-download"/></svg></button>
          <button class="btn btn--quiet btn--icon" title="One-time link" onclick="generateOTL(${c.id})"><svg><use href="#i-link"/></svg></button>
          <button class="btn btn--quiet btn--icon" title="Edit" onclick="navigate('/clients/${c.id}')"><svg><use href="#i-edit"/></svg></button>
        </div>
        ${otlBlock}
      </div>`;
  }).join('');

  el.innerHTML = `
    <div class="tbl">
      <div class="tbl-head">
        <div></div>
        <div>Peer</div>
        <div>Address</div>
        <div>Last seen</div>
        <div>Throughput</div>
        <div>Expires</div>
        <div style="text-align:right">Actions</div>
      </div>
      ${rows}
    </div>`;

  // Update OTL countdowns
  for (const c of CLIENTS) {
    if (c.oneTimeLink) {
      const cdEl = $('otl-' + c.id);
      if (cdEl) {
        const exp = new Date(c.oneTimeLink.expiresAt).getTime();
        const update = () => {
          if (!document.body.contains(cdEl)) return;
          const secs = Math.max(0, Math.floor((exp - Date.now()) / 1000));
          cdEl.textContent = Math.floor(secs/60) + ':' + String(secs%60).padStart(2,'0');
          if (secs > 0) setTimeout(update, 1000);
        };
        update();
      }
    }
  }
}

async function toggleClient(id, enabled) {
  try {
    await POST('/api/client/' + id + '/' + (enabled ? 'enable' : 'disable'));
    refreshClients();
  } catch(e) { showToast(e.message, 'error'); }
}

function showCreateModal() { $('modal-create').classList.add('active'); $('create-name').focus(); }
function closeModal(id) { $(id).classList.remove('active'); }

// Click on the dimmed backdrop (but not inside .modal) closes the modal.
document.addEventListener('click', (e) => {
  if (e.target.classList && e.target.classList.contains('modal-overlay') && e.target.classList.contains('active')) {
    e.target.classList.remove('active');
  }
});
// Escape closes whichever modal is open.
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-overlay.active').forEach(el => el.classList.remove('active'));
  }
});

async function createClient(e) {
  e.preventDefault();
  const body = { name: $('create-name').value };
  const expires = $('create-expires').value;
  if (expires) body.expiresAt = new Date(expires).toISOString();
  try {
    await POST('/api/client', body);
    closeModal('modal-create');
    $('create-name').value = '';
    $('create-expires').value = '';
    showToast('Peer created', 'success');
    refreshClients();
  } catch(e) { showToast(e.message, 'error'); }
}

async function showQR(id) {
  try {
    const svg = await GET('/api/client/' + id + '/qrcode.svg');
    $('qr-image').innerHTML = svg;
    $('qr-image').dataset.clientId = id;
    $('modal-qr').classList.add('active');
  } catch(e) { showToast(e.message, 'error'); }
}

async function copyQR() {
  const svg = $('qr-image').querySelector('svg');
  if (!svg) return;
  try {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const img = new Image();
    img.onload = () => {
      canvas.width = img.width || 256; canvas.height = img.height || 256;
      ctx.drawImage(img, 0, 0);
      canvas.toBlob(async blob => {
        try {
          await navigator.clipboard.write([new ClipboardItem({'image/png': blob})]);
          showToast('QR copied to clipboard', 'success');
        } catch(e) { showToast('Copy failed: ' + e.message, 'error'); }
      });
    };
    img.src = 'data:image/svg+xml;base64,' + btoa(new XMLSerializer().serializeToString(svg));
  } catch(e) { showToast(e.message, 'error'); }
}

function downloadQR() {
  const svg = $('qr-image').querySelector('svg');
  if (!svg) return;
  const blob = new Blob([new XMLSerializer().serializeToString(svg)], {type: 'image/svg+xml'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'qrcode.svg';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

function downloadConfig(id) {
  const a = document.createElement('a');
  a.href = '/api/client/' + id + '/configuration';
  a.download = '';
  a.click();
}

async function generateOTL(id) {
  try {
    await POST('/api/client/' + id + '/generateOneTimeLink');
    showToast('One-time link generated', 'success');
    refreshClients();
  } catch(e) { showToast(e.message, 'error'); }
}

async function copyOTL(id) {
  const c = CLIENTS.find(x => x.id === id);
  if (!c || !c.oneTimeLink) return;
  const url = window.location.origin + '/cnf/' + c.oneTimeLink.oneTimeLink;
  try {
    await navigator.clipboard.writeText(url);
    showToast('Link copied', 'success');
  } catch(e) { showToast('Copy failed: ' + e.message, 'error'); }
}

async function showConfig(id) {
  try {
    const config = await GET('/api/client/' + id + '/configuration');
    $('config-text').textContent = config;
    $('modal-config').classList.add('active');
  } catch(e) { showToast(e.message, 'error'); }
}

function copyConfig() {
  navigator.clipboard.writeText($('config-text').textContent)
    .then(() => showToast('Copied', 'success'))
    .catch(e => showToast('Copy failed: ' + e.message, 'error'));
}

// ===================== CLIENT EDIT =====================
async function loadClientEdit(id) {
  try {
    const c = await GET('/api/client/' + id);
    if (!c) return;
    $('edit-title').textContent = c.name || 'Edit peer';
    $('edit-crumb-name').textContent = c.name || ('peer #' + id);
    const online = isConnected(c.latestHandshakeAt);
    const stateTag = c.enabled === false
      ? '<span class="tag tag--neutral">disabled</span>'
      : online ? '<span class="tag tag--ok">online</span>'
               : '<span class="tag tag--neutral">idle</span>';
    $('edit-status').innerHTML = stateTag + ' <span class="mono" style="margin-left:6px;color:var(--fg-mute)">' + esc(c.ipv4Address || '') + '</span>';

    const expDate = c.expiresAt ? c.expiresAt.slice(0, 10) : '';
    const dnsStr = (c.dns || []).join(', ');
    const allowedStr = (c.allowedIps || []).join(', ');
    const handshakeStr = c.latestHandshakeAt ? timeAgo(c.latestHandshakeAt) : 'never';
    const handshakeAbs = c.latestHandshakeAt ? new Date(c.latestHandshakeAt).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : '';
    const totalTransfer = (c.transferRx || c.transferTx)
      ? `↓ ${formatBytes(c.transferRx || 0)} · ↑ ${formatBytes(c.transferTx || 0)}`
      : '— no transfer recorded —';

    const advsec = c.advancedSecurity == null ? 'auto' : (c.advancedSecurity ? 'on' : 'off');

    $('edit-form').innerHTML = `
      <div class="split" style="margin-top:8px">

        <div class="card">
          <div class="card-head">
            <div>
              <div class="card-title">General</div>
              <div class="card-sub">Identity, addressing, routing.</div>
            </div>
            <label class="toggle ${c.enabled === false ? '' : 'is-on'} toggle--lg" title="Enabled">
              <input type="checkbox" id="edit-enabled" ${c.enabled === false ? '' : 'checked'}>
              <span class="toggle-track"></span>
            </label>
          </div>
          <div class="card-body">
            <div class="stack">
              <div class="field">
                <label class="field-label" for="edit-name">Name</label>
                <input type="text" id="edit-name" value="${esc(c.name || '')}">
              </div>
              <div class="row">
                <div class="field" style="flex:1">
                  <label class="field-label" for="edit-ipv4">IPv4 address</label>
                  <input type="text" id="edit-ipv4" class="mono-input" value="${esc(c.ipv4Address || '')}">
                </div>
                <div class="field" style="flex:1">
                  <label class="field-label" for="edit-ipv6">IPv6 address</label>
                  <input type="text" id="edit-ipv6" class="mono-input" value="${esc(c.ipv6Address || '')}">
                </div>
              </div>
              <div class="field">
                <label class="field-label" for="edit-allowedips">Allowed IPs <span class="opt">on the peer</span></label>
                <input type="text" id="edit-allowedips" class="mono-input" value="${esc(allowedStr)}">
                <p class="field-help">Comma-separated. Default <span class="mono">0.0.0.0/0, ::/0</span> = full-tunnel.</p>
              </div>
              <div class="row">
                <div class="field" style="flex:1">
                  <label class="field-label" for="edit-dns">DNS servers</label>
                  <input type="text" id="edit-dns" class="mono-input" value="${esc(dnsStr)}">
                </div>
                <div class="field" style="flex:1">
                  <label class="field-label" for="edit-mtu">MTU</label>
                  <input type="number" id="edit-mtu" class="mono-input" value="${c.mtu || 1420}">
                </div>
              </div>
              <div class="row">
                <div class="field" style="flex:1">
                  <label class="field-label" for="edit-keepalive">Persistent keepalive</label>
                  <div class="input-wrap">
                    <input type="number" id="edit-keepalive" class="mono-input" value="${c.persistentKeepalive || 0}" style="padding-right:64px">
                    <span class="input-suffix">seconds</span>
                  </div>
                </div>
                <div class="field" style="flex:1">
                  <label class="field-label" for="edit-expires">Expires <span class="opt">optional</span></label>
                  <input type="date" id="edit-expires" value="${expDate}">
                </div>
              </div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-head">
            <div>
              <div class="card-title">Keys &amp; status</div>
              <div class="card-sub">Live wire stats and identity.</div>
            </div>
          </div>
          <div class="card-body">
            <div class="stack">
              ${c.publicKey ? `
              <div class="field">
                <label class="field-label">Public key</label>
                <div class="key-block">
                  <code>${esc(c.publicKey)}</code>
                  <div class="key-actions">
                    <button class="btn btn--quiet btn--icon" title="Copy" onclick="copyText('${escJs(c.publicKey)}')"><svg><use href="#i-copy"/></svg></button>
                  </div>
                </div>
                <p class="field-help">Derived from the peer's private key. Safe to share.</p>
              </div>` : ''}
              <div class="section-rule">Endpoint info</div>
              <dl class="kvl" style="grid-template-columns:140px 1fr">
                <dt>Latest handshake</dt>
                <dd><span class="mono ${online ? 'ok-text' : ''}">${handshakeStr}</span>${handshakeAbs ? `<span class="help mono">${handshakeAbs}</span>` : ''}</dd>
                ${c.endpoint ? `<dt>Latest endpoint</dt><dd><span class="mono">${esc(c.endpoint)}</span></dd>` : ''}
                <dt>Total transfer</dt>
                <dd><span class="mono">${totalTransfer}</span></dd>
              </dl>
              <div style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap">
                <button class="btn btn--ghost btn--sm" onclick="showQR(${id})"><svg><use href="#i-qr"/></svg> Show QR</button>
                <button class="btn btn--ghost btn--sm" onclick="showConfig(${id})"><svg><use href="#i-eye"/></svg> View config</button>
                <button class="btn btn--ghost btn--sm" onclick="downloadConfig(${id})"><svg><use href="#i-download"/></svg> Download .conf</button>
                <button class="btn btn--ghost btn--sm" onclick="generateOTL(${id})"><svg><use href="#i-link"/></svg> One-time link</button>
              </div>
            </div>
          </div>
        </div>

      </div>

      <div class="card" style="margin-top:18px">
        <div class="card-head">
          <div>
            <div class="card-title">AmneziaWG obfuscation</div>
            <div class="card-sub">Per-peer overrides. Leave blank to inherit server defaults.</div>
          </div>
        </div>
        <div class="card-body">
          <div class="split-3">
            <div class="field">
              <label class="field-label" for="edit-jc" title="Junk packets sent before each handshake initiation">Jc <span class="opt">junk count</span></label>
              <input type="number" id="edit-jc" class="mono-input" value="${c.jC == null ? '' : c.jC}" placeholder="inherit">
            </div>
            <div class="field">
              <label class="field-label" for="edit-jmin" title="Minimum junk packet size in bytes">Jmin <span class="opt">min bytes</span></label>
              <input type="number" id="edit-jmin" class="mono-input" value="${c.jMin == null ? '' : c.jMin}" placeholder="inherit">
            </div>
            <div class="field">
              <label class="field-label" for="edit-jmax" title="Maximum junk packet size in bytes">Jmax <span class="opt">max bytes</span></label>
              <input type="number" id="edit-jmax" class="mono-input" value="${c.jMax == null ? '' : c.jMax}" placeholder="inherit">
            </div>
          </div>
          <div class="field" style="margin-top:14px">
            <label class="field-label" for="edit-advsec" title="Per-peer AmneziaWG opt-in. 'On' = emit AdvancedSecurity = on; 'Off' = emit AdvancedSecurity = off; 'Auto' = let the kernel auto-detect from the H1 magic header on the first incoming handshake.">AdvancedSecurity</label>
            <select id="edit-advsec" style="max-width:280px">
              <option value="auto" ${advsec === 'auto' ? 'selected' : ''}>Auto (kernel detects)</option>
              <option value="on" ${advsec === 'on' ? 'selected' : ''}>On — force enable</option>
              <option value="off" ${advsec === 'off' ? 'selected' : ''}>Off — force disable</option>
            </select>
          </div>
        </div>
      </div>

      <div class="danger-zone" style="margin-top:18px">
        <div class="danger-zone-text">
          <b>Delete peer</b>
          <span>Removes <span class="mono">${esc(c.name || '')}</span> from <span class="mono">awg0</span>, revokes its keys, and frees the address. Cannot be undone.</span>
        </div>
        <button class="btn btn--danger" onclick="confirmDelete(${id}, '${escJs(c.name || '')}')"><svg><use href="#i-trash"/></svg> Delete peer</button>
      </div>

      <div class="save-bar">
        <span class="changed">Edits not saved</span>
        <div class="save-bar-spacer"></div>
        <button class="btn btn--ghost" onclick="loadClientEdit(${id})">Discard</button>
        <button class="btn btn--primary" onclick="saveClient(${id})">Save changes</button>
      </div>
    `;
    injectTooltips();
  } catch(e) { showToast(e.message, 'error'); }
}

function copyText(text) {
  navigator.clipboard.writeText(text)
    .then(() => showToast('Copied', 'success'))
    .catch(e => showToast('Copy failed: ' + e.message, 'error'));
}

async function saveClient(id) {
  const body = {
    name: $('edit-name').value,
    enabled: $('edit-enabled').checked,
    ipv4Address: $('edit-ipv4').value,
    ipv6Address: $('edit-ipv6').value,
    mtu: parseInt($('edit-mtu').value) || 1420,
    persistentKeepalive: parseInt($('edit-keepalive').value) || 0,
    dns: $('edit-dns').value.split(',').map(s => s.trim()).filter(Boolean),
    allowedIps: $('edit-allowedips').value.split(',').map(s => s.trim()).filter(Boolean),
    jC: $('edit-jc').value ? parseInt($('edit-jc').value) : null,
    jMin: $('edit-jmin').value ? parseInt($('edit-jmin').value) : null,
    jMax: $('edit-jmax').value ? parseInt($('edit-jmax').value) : null,
  };
  // AdvancedSecurity tri-state
  const advsec = $('edit-advsec').value;
  if (advsec === 'on') body.advancedSecurity = true;
  else if (advsec === 'off') body.advancedSecurity = false;
  else if (advsec === 'auto') body.advancedSecurity = null;
  const expires = $('edit-expires').value;
  body.expiresAt = expires ? new Date(expires).toISOString() : null;
  try {
    await POST('/api/client/' + id, body);
    showToast('Saved', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

function confirmDelete(id, name) {
  $('delete-confirm-btn').onclick = async () => {
    try {
      await DEL('/api/client/' + id);
      closeModal('modal-delete');
      showToast('Peer deleted', 'success');
      navigate('/');
    } catch(e) { showToast(e.message, 'error'); }
  };
  $('modal-delete').classList.add('active');
}

// ===================== ACCOUNT =====================
async function loadMe() {
  if (!USER) return;
  $('me-name').value = USER.name || '';
  $('me-email').value = USER.email || '';
  $('me-username').textContent = USER.username || USER.name || '—';
}

async function saveProfile(e) {
  e.preventDefault();
  try {
    await POST('/api/me', { name: $('me-name').value, email: $('me-email').value || null });
    // Reflect the new values in the cached USER object so the sidebar /
    // header doesn't show stale name until next checkSession.
    if (USER) {
      USER.name = $('me-name').value;
      USER.email = $('me-email').value || null;
    }
    showToast('Profile updated', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function changePassword(e) {
  e.preventDefault();
  try {
    await POST('/api/me/password', {
      currentPassword: $('pw-current').value,
      newPassword: $('pw-new').value,
      confirmPassword: $('pw-confirm').value
    });
    showToast('Password changed', 'success');
    $('pw-current').value = $('pw-new').value = $('pw-confirm').value = '';
  } catch(e) { showToast(e.message, 'error'); }
}

// ===================== ADMIN =====================
async function showAdminTab(tab, e) {
  if (e) e.preventDefault();
  ADMIN_TAB = tab;
  document.querySelectorAll('.admin-nav a').forEach(l => l.classList.toggle('active', l.dataset.tab === tab));

  const el = $('admin-content');
  el.innerHTML = '<div class="loading">Loading…</div>';

  try {
    if (tab === 'general') {
      const g = await GET('/api/admin/general');
      el.innerHTML = `
        <div class="card">
          <div class="card-head">
            <div>
              <div class="card-title">General</div>
              <div class="card-sub">Session policy and metrics endpoints.</div>
            </div>
          </div>
          <div class="card-body">
            <form onsubmit="saveAdminGeneral(event)">
              <div class="stack">
                <div class="field">
                  <label class="field-label" for="adm-session-timeout" title="How long admin sessions stay valid (seconds). Default: 3600 (1h)">Session timeout</label>
                  <div class="input-wrap" style="max-width:200px">
                    <input type="number" id="adm-session-timeout" class="mono-input" value="${g.sessionTimeout || 3600}" style="padding-right:72px">
                    <span class="input-suffix">seconds</span>
                  </div>
                </div>
                <div class="field" style="flex-direction:row;align-items:center;gap:12px">
                  <label class="toggle ${g.metricsPrometheus ? 'is-on' : ''}">
                    <input type="checkbox" id="adm-metrics-prom" ${g.metricsPrometheus ? 'checked' : ''}>
                    <span class="toggle-track"></span>
                  </label>
                  <div>
                    <label class="field-label" for="adm-metrics-prom" title="Expose /metrics in Prometheus text format">Prometheus metrics</label>
                    <p class="field-help mono">/metrics</p>
                  </div>
                </div>
                <div class="field" style="flex-direction:row;align-items:center;gap:12px">
                  <label class="toggle ${g.metricsJson ? 'is-on' : ''}">
                    <input type="checkbox" id="adm-metrics-json" ${g.metricsJson ? 'checked' : ''}>
                    <span class="toggle-track"></span>
                  </label>
                  <div>
                    <label class="field-label" for="adm-metrics-json" title="Expose /metrics.json with structured stats">JSON metrics</label>
                    <p class="field-help mono">/metrics.json</p>
                  </div>
                </div>
              </div>
              <div style="display:flex;justify-content:flex-end;margin-top:18px">
                <button class="btn btn--primary">Save changes</button>
              </div>
            </form>
          </div>
        </div>`;
    } else if (tab === 'config') {
      const uc = await GET('/api/admin/userconfig');
      el.innerHTML = `
        <div class="card">
          <div class="card-head">
            <div>
              <div class="card-title">Defaults for new peers</div>
              <div class="card-sub">Server endpoint and the values stamped into each new peer's config.</div>
            </div>
          </div>
          <div class="card-body">
            <form onsubmit="saveAdminConfig(event)">
              <div class="stack">
                <div class="row">
                  <div class="field" style="flex:2">
                    <label class="field-label" for="adm-host">Server hostname / IP</label>
                    <input type="text" id="adm-host" class="mono-input" value="${esc(uc.host || '')}">
                  </div>
                  <div class="field" style="flex:1">
                    <label class="field-label" for="adm-port">UDP port</label>
                    <input type="number" id="adm-port" class="mono-input" value="${uc.port || 51820}">
                  </div>
                </div>
                <div class="field">
                  <label class="field-label" for="adm-dns">Default DNS servers</label>
                  <input type="text" id="adm-dns" class="mono-input" value="${esc((uc.defaultDns || []).join(', '))}">
                  <p class="field-help">Comma-separated.</p>
                </div>
                <div class="field">
                  <label class="field-label" for="adm-allowedips">Default allowed IPs</label>
                  <input type="text" id="adm-allowedips" class="mono-input" value="${esc((uc.defaultAllowedIps || []).join(', '))}">
                  <p class="field-help">Full-tunnel: <span class="mono">0.0.0.0/0, ::/0</span>. LAN-only: your subnets.</p>
                </div>
                <div class="row">
                  <div class="field" style="flex:1">
                    <label class="field-label" for="adm-mtu">Default MTU</label>
                    <input type="number" id="adm-mtu" class="mono-input" value="${uc.defaultMtu || 1420}">
                  </div>
                  <div class="field" style="flex:1">
                    <label class="field-label" for="adm-keepalive">Default keepalive</label>
                    <div class="input-wrap">
                      <input type="number" id="adm-keepalive" class="mono-input" value="${uc.defaultPersistentKeepalive || 0}" style="padding-right:64px">
                      <span class="input-suffix">seconds</span>
                    </div>
                  </div>
                </div>
              </div>
              <div style="display:flex;justify-content:flex-end;margin-top:18px">
                <button class="btn btn--primary">Save defaults</button>
              </div>
            </form>
          </div>
        </div>`;
    } else if (tab === 'interface') {
      const iface = await GET('/api/admin/interface');
      el.innerHTML = `
        <div class="notice notice--warn" style="margin-bottom:14px">
          <svg><use href="#i-alert"/></svg>
          <div>Changing interface keys, ports, or AmneziaWG header magic <b>invalidates every existing peer config</b>. You'll need to redistribute QR codes or one-time links.</div>
        </div>
        <form onsubmit="saveAdminInterface(event)">
          <div class="card">
            <div class="card-head">
              <div>
                <div class="card-title">Interface basics</div>
                <div class="card-sub">Listening port, MTU, addressing.</div>
              </div>
            </div>
            <div class="card-body">
              <div class="stack">
                <div class="row">
                  <div class="field" style="flex:1">
                    <label class="field-label" for="adm-if-mtu" title="Maximum Transmission Unit for the VPN interface. Default: 1420">MTU</label>
                    <input type="number" id="adm-if-mtu" class="mono-input" value="${iface.mtu || 1420}">
                  </div>
                  <div class="field" style="flex:1">
                    <label class="field-label" for="adm-if-port" title="UDP port for AmneziaWG connections. Default: 51820">Port</label>
                    <input type="number" id="adm-if-port" class="mono-input" value="${iface.port || 51820}">
                  </div>
                  <div class="field" style="flex:1">
                    <label class="field-label" for="adm-if-device" title="Physical network interface to route traffic through">Device</label>
                    <input type="text" id="adm-if-device" class="mono-input" value="${esc(iface.device || 'eth0')}">
                  </div>
                </div>
                <div class="row">
                  <div class="field" style="flex:1">
                    <label class="field-label" for="adm-if-ipv4" title="IPv4 subnet for VPN clients. Server gets .1 address">IPv4 CIDR</label>
                    <input type="text" id="adm-if-ipv4" class="mono-input" value="${esc(iface.ipv4Cidr || '')}">
                  </div>
                  <div class="field" style="flex:1">
                    <label class="field-label" for="adm-if-ipv6" title="IPv6 subnet for VPN clients. Leave empty to disable IPv6">IPv6 CIDR</label>
                    <input type="text" id="adm-if-ipv6" class="mono-input" value="${esc(iface.ipv6Cidr || '')}">
                  </div>
                </div>
                <div class="field" style="flex-direction:row;align-items:center;gap:12px">
                  <label class="toggle ${iface.firewallEnabled ? 'is-on' : ''}">
                    <input type="checkbox" id="adm-if-firewall" ${iface.firewallEnabled ? 'checked' : ''}>
                    <span class="toggle-track"></span>
                  </label>
                  <div>
                    <label class="field-label" for="adm-if-firewall" title="Restrict each client to only access their allowed IPs via iptables rules. Requires iptables installed">Per-client firewall</label>
                    <p class="field-help">iptables rules per peer based on their allowed-IPs.</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div class="card" style="margin-top:18px">
            <div class="card-head">
              <div>
                <div class="card-title">AmneziaWG obfuscation</div>
                <div class="card-sub">Junk packets and header magic.</div>
              </div>
            </div>
            <div class="card-body">
              <div class="split-3">
                <div class="field">
                  <label class="field-label" for="adm-if-jc" title="Number of random junk packets sent before each handshake initiation (1-128). Recommended: 4-12">Jc <span class="opt">junk count</span></label>
                  <input type="number" id="adm-if-jc" class="mono-input" value="${iface.jC || 7}" min="1" max="128">
                </div>
                <div class="field">
                  <label class="field-label" for="adm-if-jmin" title="Minimum size in bytes for junk packets (0-1279)">Jmin <span class="opt">min bytes</span></label>
                  <input type="number" id="adm-if-jmin" class="mono-input" value="${iface.jMin || 10}" min="0" max="1279">
                </div>
                <div class="field">
                  <label class="field-label" for="adm-if-jmax" title="Maximum size in bytes for junk packets (1-1279). Must be > Jmin and < MTU">Jmax <span class="opt">max bytes</span></label>
                  <input type="number" id="adm-if-jmax" class="mono-input" value="${iface.jMax || 1000}" min="1" max="1279">
                </div>
                <div class="field">
                  <label class="field-label" for="adm-if-s1" title="Random padding bytes prepended to handshake initiation (0-1132). Recommended: 15-150">S1 <span class="opt">init pad</span></label>
                  <input type="number" id="adm-if-s1" class="mono-input" value="${iface.s1 || 128}" min="0" max="1132">
                </div>
                <div class="field">
                  <label class="field-label" for="adm-if-s2" title="Random padding bytes prepended to handshake response (0-1188). Must differ from S1+56">S2 <span class="opt">resp pad</span></label>
                  <input type="number" id="adm-if-s2" class="mono-input" value="${iface.s2 || 56}" min="0" max="1188">
                </div>
                <div class="field">
                  <label class="field-label" for="adm-if-s3" title="Random padding for cookie reply messages (0-1216). AmneziaWG 2.0 only">S3 <span class="opt">cookie pad</span></label>
                  <input type="number" id="adm-if-s3" class="mono-input" value="${iface.s3 == null ? '' : iface.s3}" min="0" max="1216" placeholder="—">
                </div>
                <div class="field">
                  <label class="field-label" for="adm-if-s4" title="Random padding for transport messages (0-32). AmneziaWG 2.0 only">S4 <span class="opt">transport pad</span></label>
                  <input type="number" id="adm-if-s4" class="mono-input" value="${iface.s4 == null ? '' : iface.s4}" min="0" max="32" placeholder="—">
                </div>
              </div>
              <div class="section-rule">Header magic <span style="margin-left:6px;font-weight:400;font-family:var(--font-mono);text-transform:none;letter-spacing:0;color:var(--fg-faint)">non-overlapping per-server values</span></div>
              <div class="split-3" style="grid-template-columns:repeat(4,1fr);gap:10px">
                <div class="field">
                  <label class="field-label" for="adm-if-h1" title="Magic header for handshake initiation packets. Single value or 'N-M' range. Must not overlap H2-H4">H1</label>
                  <input type="text" id="adm-if-h1" class="mono-input" value="${esc(iface.h1 || '')}">
                </div>
                <div class="field">
                  <label class="field-label" for="adm-if-h2" title="Magic header for handshake response packets. Must not overlap H1, H3, H4">H2</label>
                  <input type="text" id="adm-if-h2" class="mono-input" value="${esc(iface.h2 || '')}">
                </div>
                <div class="field">
                  <label class="field-label" for="adm-if-h3" title="Magic header for cookie reply packets. Must not overlap H1, H2, H4">H3</label>
                  <input type="text" id="adm-if-h3" class="mono-input" value="${esc(iface.h3 || '')}">
                </div>
                <div class="field">
                  <label class="field-label" for="adm-if-h4" title="Magic header for transport packets. Must not overlap H1-H3">H4</label>
                  <input type="text" id="adm-if-h4" class="mono-input" value="${esc(iface.h4 || '')}">
                </div>
              </div>
            </div>
          </div>

          <div class="card" style="margin-top:18px">
            <div class="card-head">
              <div>
                <div class="card-title">Init junk specs (I1-I5)</div>
                <div class="card-sub">Custom packets sent before handshake. Tag format: <span class="mono">&lt;b 0xHEX&gt;</span>=static bytes, <span class="mono">&lt;r N&gt;</span>=N random bytes, <span class="mono">&lt;rc N&gt;</span>=ASCII letters, <span class="mono">&lt;rd N&gt;</span>=digits, <span class="mono">&lt;t&gt;</span>=timestamp, <span class="mono">&lt;c&gt;</span>=counter.</div>
              </div>
            </div>
            <div class="card-body">
              <div class="stack">
                <div class="field">
                  <label class="field-label" for="adm-if-i1" title="Init junk spec — custom packet sent before handshake">I1</label>
                  <textarea id="adm-if-i1" rows="3">${esc(iface.i1 || '')}</textarea>
                </div>
                <div class="split">
                  <div class="field">
                    <label class="field-label" for="adm-if-i2" title="Second init junk spec">I2</label>
                    <textarea id="adm-if-i2" rows="2">${esc(iface.i2 || '')}</textarea>
                  </div>
                  <div class="field">
                    <label class="field-label" for="adm-if-i3" title="Third init junk spec">I3</label>
                    <textarea id="adm-if-i3" rows="2">${esc(iface.i3 || '')}</textarea>
                  </div>
                </div>
                <div class="split">
                  <div class="field">
                    <label class="field-label" for="adm-if-i4" title="Fourth init junk spec">I4</label>
                    <textarea id="adm-if-i4" rows="2">${esc(iface.i4 || '')}</textarea>
                  </div>
                  <div class="field">
                    <label class="field-label" for="adm-if-i5" title="Fifth init junk spec">I5</label>
                    <textarea id="adm-if-i5" rows="2">${esc(iface.i5 || '')}</textarea>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div class="save-bar">
            <span class="changed">Changes need a restart</span>
            <div class="save-bar-spacer"></div>
            <button type="button" class="btn btn--ghost" onclick="restartWG()"><svg><use href="#i-refresh"/></svg> Restart awg0</button>
            <button type="submit" class="btn btn--primary">Save changes</button>
          </div>
        </form>`;
    } else if (tab === 'hooks') {
      const hooks = await GET('/api/admin/hooks');
      el.innerHTML = `
        <div class="notice notice--warn" style="margin-bottom:14px">
          <svg><use href="#i-alert"/></svg>
          <div>Hooks run as root with <span class="mono">%i</span> substituted to the interface name. A bad command will fail interface bring-up.</div>
        </div>
        <div class="card">
          <div class="card-head">
            <div>
              <div class="card-title">Lifecycle hooks</div>
              <div class="card-sub">Shell commands AmneziaWG runs around interface up/down.</div>
            </div>
          </div>
          <div class="card-body">
            <form onsubmit="saveAdminHooks(event)">
              <div class="stack">
                <div class="field">
                  <label class="field-label" for="adm-hook-preup" title="Commands run BEFORE the AmneziaWG interface comes up. Template vars: {{device}} {{port}} {{ipv4Cidr}} {{ipv6Cidr}}">PreUp</label>
                  <textarea id="adm-hook-preup" rows="3" placeholder="(empty)">${esc(hooks.preUp || '')}</textarea>
                </div>
                <div class="field">
                  <label class="field-label" for="adm-hook-postup" title="Commands run AFTER the interface comes up. Default sets up NAT masquerading and firewall rules">PostUp</label>
                  <textarea id="adm-hook-postup" rows="4">${esc(hooks.postUp || '')}</textarea>
                </div>
                <div class="field">
                  <label class="field-label" for="adm-hook-predown" title="Commands run BEFORE the AmneziaWG interface goes down">PreDown</label>
                  <textarea id="adm-hook-predown" rows="3" placeholder="(empty)">${esc(hooks.preDown || '')}</textarea>
                </div>
                <div class="field">
                  <label class="field-label" for="adm-hook-postdown" title="Commands run AFTER the interface goes down. Default removes iptables NAT and forwarding rules">PostDown</label>
                  <textarea id="adm-hook-postdown" rows="4">${esc(hooks.postDown || '')}</textarea>
                </div>
              </div>
              <div style="display:flex;justify-content:flex-end;margin-top:18px;gap:10px">
                <button type="button" class="btn btn--ghost" onclick="restartWG()"><svg><use href="#i-refresh"/></svg> Save &amp; restart</button>
                <button type="submit" class="btn btn--primary">Save hooks</button>
              </div>
            </form>
          </div>
        </div>`;
    }
  } catch(err) {
    showToast(err.message, 'error');
    el.innerHTML = '<div class="empty"><h3>Could not load</h3><p>' + esc(err.message) + '</p></div>';
  }
  injectTooltips();

  // Live-bind toggle visual states
  document.querySelectorAll('.admin-content .toggle input[type="checkbox"]').forEach(input => {
    const wrap = input.closest('.toggle');
    if (!wrap) return;
    input.addEventListener('change', () => wrap.classList.toggle('is-on', input.checked));
  });
}

async function saveAdminGeneral(e) {
  e.preventDefault();
  try {
    await POST('/api/admin/general', {
      sessionTimeout: parseInt($('adm-session-timeout').value) || 3600,
      metricsPrometheus: $('adm-metrics-prom').checked,
      metricsJson: $('adm-metrics-json').checked
    });
    showToast('Saved', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function saveAdminConfig(e) {
  e.preventDefault();
  try {
    await POST('/api/admin/userconfig', {
      host: $('adm-host').value,
      port: parseInt($('adm-port').value) || 51820,
      defaultDns: $('adm-dns').value.split(',').map(s => s.trim()).filter(Boolean),
      defaultAllowedIps: $('adm-allowedips').value.split(',').map(s => s.trim()).filter(Boolean),
      defaultMtu: parseInt($('adm-mtu').value) || 1420,
      defaultPersistentKeepalive: parseInt($('adm-keepalive').value) || 0
    });
    showToast('Saved', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function saveAdminInterface(e) {
  e.preventDefault();
  // Validate AWG params (preserved from prior version)
  const jc = parseInt($('adm-if-jc').value) || 0;
  const jmin = parseInt($('adm-if-jmin').value) || 0;
  const jmax = parseInt($('adm-if-jmax').value) || 0;
  const s1 = parseInt($('adm-if-s1').value) || 0;
  const s2 = parseInt($('adm-if-s2').value) || 0;
  if (jc && (jc < 1 || jc > 128)) { showToast('Jc must be 1-128', 'error'); return; }
  if (jmin && (jmin < 0 || jmin > 1279)) { showToast('Jmin must be 0-1279', 'error'); return; }
  if (jmax && (jmax < 1 || jmax > 1279)) { showToast('Jmax must be 1-1279', 'error'); return; }
  if (jmax > 0 && jmin >= jmax) { showToast('Jmax must be > Jmin', 'error'); return; }
  if (s1 > 0 && s2 > 0 && s1 + 56 === s2) { showToast('S1 + 56 must not equal S2', 'error'); return; }
  const s3 = parseInt($('adm-if-s3').value) || 0;
  const s4 = parseInt($('adm-if-s4').value) || 0;
  if ($('adm-if-s3').value && (s3 < 0 || s3 > 1216)) { showToast('S3 must be 0-1216', 'error'); return; }
  if ($('adm-if-s4').value && (s4 < 0 || s4 > 32)) { showToast('S4 must be 0-32', 'error'); return; }
  // Validate H1-H4 non-overlap
  const h = [$('adm-if-h1').value, $('adm-if-h2').value, $('adm-if-h3').value, $('adm-if-h4').value];
  function parseRange(v) { const m = v.match(/^(\d+)(?:-(\d+))?$/); return m ? [parseInt(m[1]), parseInt(m[2] || m[1])] : null; }
  const ranges = h.map(parseRange).filter(Boolean);
  for (let i = 0; i < ranges.length; i++) {
    for (let j = i + 1; j < ranges.length; j++) {
      if (ranges[i] && ranges[j] && !(ranges[i][1] < ranges[j][0] || ranges[j][1] < ranges[i][0])) {
        showToast('Magic headers H' + (i + 1) + ' and H' + (j + 1) + ' overlap. They must not overlap.', 'error');
        return;
      }
    }
  }
  try {
    await POST('/api/admin/interface', {
      mtu: parseInt($('adm-if-mtu').value) || 1420,
      port: parseInt($('adm-if-port').value) || 51820,
      device: $('adm-if-device').value,
      ipv4Cidr: $('adm-if-ipv4').value,
      ipv6Cidr: $('adm-if-ipv6').value,
      firewallEnabled: $('adm-if-firewall').checked,
      jC: parseInt($('adm-if-jc').value) || 7,
      jMin: parseInt($('adm-if-jmin').value) || 10,
      jMax: parseInt($('adm-if-jmax').value) || 1279,
      s1: parseInt($('adm-if-s1').value) || 128,
      s2: parseInt($('adm-if-s2').value) || 56,
      s3: $('adm-if-s3').value ? parseInt($('adm-if-s3').value) : null,
      s4: $('adm-if-s4').value ? parseInt($('adm-if-s4').value) : null,
      h1: $('adm-if-h1').value,
      h2: $('adm-if-h2').value,
      h3: $('adm-if-h3').value,
      h4: $('adm-if-h4').value,
      i1: $('adm-if-i1').value,
      i2: $('adm-if-i2').value,
      i3: $('adm-if-i3').value,
      i4: $('adm-if-i4').value,
      i5: $('adm-if-i5').value
    });
    showToast('Saved', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function saveAdminHooks(e) {
  e.preventDefault();
  try {
    await POST('/api/admin/hooks', {
      preUp: $('adm-hook-preup').value,
      postUp: $('adm-hook-postup').value,
      preDown: $('adm-hook-predown').value,
      postDown: $('adm-hook-postdown').value
    });
    showToast('Saved', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function restartWG() {
  try {
    await POST('/api/admin/interface/restart');
    showToast('Interface restarted', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

// ===================== SETUP =====================
function setupGo(step) {
  SETUP_STEP = step;
  $('setup-step1').style.display = 'none';
  $('setup-step2').style.display = 'none';
  $('setup-step4').style.display = 'none';
  if (step === 1) $('setup-step1').style.display = 'block';
  if (step === 2) $('setup-step2').style.display = 'block';
  if (step === 4) $('setup-step4').style.display = 'block';
  updateSteps();
}

function updateSteps() {
  // Map SETUP_STEP (1, 2, 4) onto a 3-segment visual stepper
  const visualMap = { 1: 0, 2: 1, 4: 2 };
  const visual = visualMap[SETUP_STEP] != null ? visualMap[SETUP_STEP] : SETUP_STEP - 1;
  $$('#setup-steps .step').forEach((s, i) => {
    s.classList.remove('active', 'done');
    if (i < visual) s.classList.add('done');
    if (i === visual) s.classList.add('active');
  });
}

async function loadSetup() {
  try {
    const info = await GET('/api/information');
    if (!info || !info.setupNeeded) { navigate('/login'); return; }
  } catch(e) {}
  SETUP_STEP = 1;
  setupGo(1);
}

async function setupCreateUser(e) {
  e.preventDefault();
  try {
    await POST('/api/setup/2', {
      username: $('setup-user').value,
      password: $('setup-pass').value,
      confirmPassword: $('setup-pass2').value
    });
    showToast('Account created', 'success');
    setupGo(4);
  } catch(e) { showToast(e.message, 'error'); }
}

async function setupFinish(e) {
  e.preventDefault();
  try {
    await POST('/api/setup/4', {
      host: $('setup-host').value,
      port: parseInt($('setup-port').value) || 51820
    });
    showToast('Setup complete!', 'success');
    setTimeout(() => navigate('/login'), 1200);
  } catch(e) { showToast(e.message, 'error'); }
}
