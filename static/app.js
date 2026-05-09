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

// Inline SVG sparkline. Empty/short series renders a dim baseline.
// className lets callers swap sizing context (peer-spark = row, stat-spark = stats strip).
function renderSpark(values, w = 60, h = 22, color, className = 'peer-spark') {
  if (!values || values.length < 2) {
    return `<svg class="${className}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><polyline fill="none" stroke="var(--fg-dim)" stroke-width="1.2" stroke-dasharray="2 3" points="0,${h/2} ${w},${h/2}"/></svg>`;
  }
  const max = Math.max(...values, 1);
  const points = values.map((v, i) => {
    const x = (i / (values.length - 1)) * w;
    const y = h - (v / max) * (h - 4) - 2;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  const stroke = color || 'var(--fg-soft)';
  return `<svg class="${className}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><polyline fill="none" stroke="${stroke}" stroke-width="1.4" points="${points}"/></svg>`;
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
  } else if (path === '/xray') {
    $('page-xray').classList.add('active');
    renderNav();
    refreshXrayClients();
  } else if (path.startsWith('/xray/clients/')) {
    $('page-xray-edit').classList.add('active');
    renderNav();
    const id = path.split('/')[3];
    loadXrayClientEdit(id);
  } else {
    $('page-clients').classList.add('active');
    renderNav();
    refreshClients();
  }
}

window.addEventListener('hashchange', route);
window.addEventListener('load', route);

// Auto-inject tooltip chips on labels with title attribute.
// Restricted to .field-label[title]: a plain <label class="toggle" title="…"> is
// NOT a tooltip target — appending a ? chip lands in the toggle's visible track.
function injectTooltips() {
  setTimeout(() => {
    document.querySelectorAll('.field-label[title]').forEach(l => {
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
  else if (path === '/xray' || path.startsWith('/xray/')) activeRoute = '/xray';
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
        ${validSpark ? renderSpark(aggSpark, 56, 22, 'var(--accent)', 'stat-spark') : ''}
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
        <div class="empty-glyph"><svg><use href="#i-users"/></svg></div>
        <h3>No peers yet</h3>
        <p>Create your first peer and we'll generate keys, an address, and a config you can scan straight into AmneziaWG.</p>
        <div style="margin-top:18px"><button class="btn btn--primary" onclick="showCreateModal()"><svg><use href="#i-plus"/></svg> New peer</button></div>
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
    const lastSeenAge = c.latestHandshakeAt ? (Date.now() - new Date(c.latestHandshakeAt).getTime()) : Infinity;
    // 3-tier freshness: <60s green-pulse, <3min soft white, otherwise muted.
    const lastSeenClass = lastSeenAge < 60000 ? 'is-fresh' : lastSeenAge < 180000 ? 'is-recent' : '';
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
          <div class="peer-name-row">
            <button class="peer-name-link" onclick="navigate('/clients/${c.id}')">${esc(c.name)}</button>
            ${stateTag}
          </div>
          <span>id ${c.id}${c.createdAt ? ' · created ' + new Date(c.createdAt).toISOString().slice(0,10) : ''}</span>
        </div>
        <div class="peer-addr">
          ${esc(c.ipv4Address || '—')}
          ${c.ipv6Address ? `<small>${esc(c.ipv6Address)}</small>` : ''}
        </div>
        <div class="peer-seen ${lastSeenClass}">${lastSeen}</div>
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
    // Reload whichever page is showing this peer so the new link surfaces.
    if (window.location.hash.startsWith('#/clients/')) {
      loadClientEdit(id);
    } else {
      refreshClients();
    }
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
              <div class="card-sub">Identity, addressing, routing. Use the row toggle on the clients list to enable / disable.</div>
            </div>
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
              ${c.oneTimeLink ? `
              <div class="section-rule">Active one-time link</div>
              <div class="otl-bar" style="margin:0">
                <svg><use href="#i-link"/></svg>
                <span class="otl-link">${esc(window.location.origin + '/cnf/' + c.oneTimeLink.oneTimeLink)}</span>
                <span>expires in</span>
                <span class="otl-countdown" id="edit-otl-${id}">—</span>
                <button type="button" class="btn btn--quiet btn--sm" onclick="copyText('${escJs(window.location.origin + '/cnf/' + c.oneTimeLink.oneTimeLink)}')"><svg><use href="#i-copy"/></svg> copy</button>
              </div>` : ''}
              <div style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap">
                <button type="button" class="btn btn--ghost btn--sm" onclick="showQR(${id})"><svg><use href="#i-qr"/></svg> Show QR</button>
                <button type="button" class="btn btn--ghost btn--sm" onclick="showConfig(${id})"><svg><use href="#i-eye"/></svg> View config</button>
                <button type="button" class="btn btn--ghost btn--sm" onclick="downloadConfig(${id})"><svg><use href="#i-download"/></svg> Download .conf</button>
                <button type="button" class="btn btn--ghost btn--sm" onclick="generateOTL(${id})"><svg><use href="#i-link"/></svg> ${c.oneTimeLink ? 'Regenerate link' : 'One-time link'}</button>
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
          <div class="field" style="margin-top:14px">
            <label class="field-label" for="edit-extra" title="Free-form text appended verbatim to this peer's [Interface] block. Empty falls back to the admin default.">Additional config <span class="opt">overrides default</span></label>
            <textarea id="edit-extra" rows="3" placeholder="(inherit default)">${esc(c.additionalConfig || '')}</textarea>
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
  // additionalConfig is always sent (admins-only on the server side); empty
  // string clears the per-peer override and falls back to the UC default.
  body.additionalConfig = $('edit-extra').value;
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
                <div class="field field--inline">
                  <label class="toggle ${g.metricsPrometheus ? 'is-on' : ''}">
                    <input type="checkbox" id="adm-metrics-prom" ${g.metricsPrometheus ? 'checked' : ''}>
                    <span class="toggle-track"></span>
                  </label>
                  <div>
                    <label class="field-label" for="adm-metrics-prom" title="Expose /metrics in Prometheus text format">Prometheus metrics</label>
                    <p class="field-help"><span class="mono">/metrics</span></p>
                  </div>
                </div>
                <div class="field field--inline">
                  <label class="toggle ${g.metricsJson ? 'is-on' : ''}">
                    <input type="checkbox" id="adm-metrics-json" ${g.metricsJson ? 'checked' : ''}>
                    <span class="toggle-track"></span>
                  </label>
                  <div>
                    <label class="field-label" for="adm-metrics-json" title="Expose /metrics.json with structured stats">JSON metrics</label>
                    <p class="field-help"><span class="mono">/metrics.json</span></p>
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
                <div class="field">
                  <label class="field-label" for="adm-default-extra" title="Free-form text appended to the [Interface] block of every generated client .conf. Per-client override on the edit page.">Default additional client config</label>
                  <textarea id="adm-default-extra" class="mono-input" rows="3" placeholder="(empty — e.g. Table = off)">${esc(uc.defaultAdditionalConfig || '')}</textarea>
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
                <div class="field field--inline">
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
              <div class="split-4">
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

          <div class="card">
            <div class="card-head">
              <div>
                <div class="card-title">Additional server config</div>
                <div class="card-sub">Free-form text appended to the server <span class="mono">[Interface]</span> block. Useful for keys awg-quick understands but the UI doesn't model (e.g. <span class="mono">Table = off</span>, <span class="mono">FwMark</span>). Lines you write here are emitted verbatim — a typo will block interface bring-up.</div>
              </div>
            </div>
            <div class="card-body">
              <div class="field">
                <label class="field-label" for="adm-if-extra" title="Appended verbatim to the server [Interface] block">Additional config</label>
                <textarea id="adm-if-extra" rows="4" placeholder="(empty)">${esc(iface.additionalConfig || '')}</textarea>
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
    } else if (tab === 'xray') {
      const inbound = await GET('/api/admin/xray/inbound');
      const status = await GET('/api/admin/xray/status').catch(() => null);
      const candidates = await GET('/api/admin/xray/inbound/dest-candidates').catch(() => []);
      const candOptions = (candidates || []).map(c => `<option value="${esc(c)}:443">${esc(c)}</option>`).join('');
      const stateLabel = status ? (
        status.state === 'running' ? `<span class="pill pill--ok">Running · pid ${status.pid} · ${Math.round(status.uptime_seconds || 0)}s</span>`
        : status.state === 'crashed' ? `<span class="pill pill--err" title="${esc(status.last_error || '')}">Crashed × ${status.restart_attempts}</span>`
        : `<span class="pill" title="${esc(status.reason || '')}">${esc(status.reason || 'Disabled')}</span>`
      ) : '<span class="pill">unknown</span>';
      el.innerHTML = `
        <div class="notice notice--info" style="margin-bottom:14px">
          <svg><use href="#i-shield"/></svg>
          <div>VLESS + Reality + Vision over TCP/${inbound.port}. Vision splices the inner TLS so the wire pattern matches a single TLS session — needs a clean IP and a reachable <span class="mono">dest</span>. <a href="https://docs.amnezia.org/" target="_blank" rel="noopener">More on Reality</a></div>
        </div>
        <div style="margin-bottom:14px">
          Bundled Xray ${esc(inbound.xrayVersion || '?')} · supervisor: ${stateLabel}
        </div>
        <form onsubmit="saveXrayInbound(event)">
          <div class="card">
            <div class="card-head">
              <div>
                <div class="card-title">Reality inbound</div>
                <div class="card-sub">Single TCP/443 listener. Clients send ClientHello with SNI = the first server name; if it matches the dest's leaf cert, Xray transparently proxies to the real site.</div>
              </div>
              <label class="toggle ${inbound.enabled ? 'is-on' : ''}" title="Master switch — turning this off stops the supervisor and tears down /etc/wireguard/xray/server.json">
                <input type="checkbox" id="adm-xr-enabled" ${inbound.enabled ? 'checked' : ''}>
                <span class="toggle-track"><span class="toggle-thumb"></span></span>
                <span class="toggle-label">Enabled</span>
              </label>
            </div>
            <div class="card-body">
              <div class="stack">
                <div class="split">
                  <div class="field">
                    <label class="field-label" for="adm-xr-port" title="TCP port Xray listens on. 443 is the only port that's convincing camouflage; non-443 ports are Reality's #1 telltale.">Listen port</label>
                    <input type="number" id="adm-xr-port" class="mono-input" value="${inbound.port}">
                  </div>
                  <div class="field">
                    <label class="field-label" for="adm-xr-fp" title="uTLS fingerprint baked into share links. Chrome and Firefox are the most convincing — Safari and randomized are flagged by some DPI vendors.">Default fingerprint</label>
                    <select id="adm-xr-fp">
                      ${['chrome','firefox','safari','ios','android','edge','random'].map(f => `<option value="${f}" ${inbound.fingerprintDefault===f?'selected':''}>${f}</option>`).join('')}
                    </select>
                  </div>
                </div>
                <div class="field">
                  <label class="field-label" for="adm-xr-dest" title="The real upstream Xray fronts. Must terminate TLS 1.3 and present a cert whose SAN covers the SNI below. GitHub-related infra is intermittently blocked — pick something else.">Dest (host:port)</label>
                  <div style="display:flex;gap:8px">
                    <input type="text" id="adm-xr-dest" class="mono-input" value="${esc(inbound.dest)}" style="flex:1">
                    <select id="adm-xr-cand" onchange="if(this.value){$('adm-xr-dest').value=this.value;$('adm-xr-sni').value=this.value.split(':')[0]}">
                      <option value="">— pick from curated list —</option>
                      ${candOptions}
                    </select>
                    <button type="button" class="btn btn--ghost" onclick="probeXrayDest()">Probe</button>
                  </div>
                  <div class="sub" id="adm-xr-probe-result" style="margin-top:6px"></div>
                </div>
                <div class="field">
                  <label class="field-label" for="adm-xr-sni" title="SNI clients send. Must be a SAN on the dest's leaf cert. The first entry is canonical; additional names support multi-tenant CDNs.">Server names (one per line)</label>
                  <textarea id="adm-xr-sni" class="mono-input" rows="2">${esc((inbound.serverNames || []).join('\n'))}</textarea>
                </div>
                <div class="field">
                  <label class="field-label" title="x25519 keypair Reality uses to authenticate clients. Public key goes into share links; private key stays in the SQLite DB. Regenerating invalidates every existing peer's vless:// link.">Reality keypair</label>
                  <div style="display:flex;gap:10px;align-items:center">
                    <input type="text" class="mono-input" readonly value="${inbound.publicKey ? 'pbk: ' + esc(inbound.publicKey) : '(no keypair yet)'}" style="flex:1">
                    <button type="button" class="btn btn--ghost" onclick="regenerateXrayKeys()">${inbound.hasPrivateKey ? 'Regenerate' : 'Generate'}</button>
                  </div>
                </div>
                <div class="field">
                  <label class="field-label" for="adm-xr-extra" title="Free-form JSON object deep-merged into the inbound. Use for sniffing tweaks, fallbacks, or anything the UI doesn't model. Bad JSON will block the save.">Additional inbound config</label>
                  <textarea id="adm-xr-extra" class="mono-input" rows="3" placeholder='(empty — e.g. {"sniffing":{"routeOnly":false}})'>${esc(inbound.additionalConfig || '')}</textarea>
                </div>
              </div>
            </div>
          </div>
          <div class="save-bar">
            <span class="changed">Changes apply on save (SIGHUP — no peer drops)</span>
            <div class="save-bar-spacer"></div>
            <button type="button" class="btn btn--ghost" onclick="restartXray()"><svg><use href="#i-refresh"/></svg> Restart Xray</button>
            <button type="submit" class="btn btn--primary">Save changes</button>
          </div>
        </form>`;
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
      defaultPersistentKeepalive: parseInt($('adm-keepalive').value) || 0,
      defaultAdditionalConfig: $('adm-default-extra').value
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
      i5: $('adm-if-i5').value,
      additionalConfig: $('adm-if-extra').value
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
    s.classList.remove('is-active', 'is-done');
    if (i < visual) s.classList.add('is-done');
    if (i === visual) s.classList.add('is-active');
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

// ===================== XRAY (Browsing mode) =====================

let XRAY_REFRESH_TIMER = null;

async function refreshXrayClients() {
  if (XRAY_REFRESH_TIMER) { clearTimeout(XRAY_REFRESH_TIMER); XRAY_REFRESH_TIMER = null; }
  try {
    const list = await GET('/api/xray/clients');
    const status = await GET('/api/admin/xray/status').catch(() => null);
    renderXrayClients(list || [], status);
    $('xray-count').textContent = (list || []).length || '';
    $('side-xray-count').textContent = (list || []).length || '—';
  } catch(e) {
    if (USER) showToast(e.message, 'error');
  }
  // No live transfer rates for Xray (would need stats API); refresh
  // every 15s for status updates only.
  if (window.location.hash === '#/xray') {
    XRAY_REFRESH_TIMER = setTimeout(refreshXrayClients, 15000);
  }
}

function renderXrayClients(clients, status) {
  const list = $('xray-list');
  const empty = $('xray-empty');
  const isAdmin = USER && USER.role === 1;
  const createBtn = $('xray-create-btn');

  // Surface supervisor state in the top pill.
  const pill = $('xray-status-pill');
  if (status) {
    if (status.state === 'running') {
      pill.innerHTML = `<span class="pill pill--ok">Running · pid ${status.pid}</span>`;
    } else if (status.state === 'crashed') {
      pill.innerHTML = `<span class="pill pill--err" title="${esc(status.last_error || '')}">Crashed × ${status.restart_attempts}</span>`;
    } else {
      pill.innerHTML = `<span class="pill" title="${esc(status.reason || '')}">${esc(status.reason || 'Disabled')}</span>`;
    }
  } else {
    pill.textContent = '';
  }

  if (!clients.length) {
    list.innerHTML = '';
    empty.style.display = '';
    empty.innerHTML = isAdmin
      ? `<h3>No Browsing peers yet</h3>
         <p>Click <b>New peer</b> to issue your first <span class="mono">vless://</span> share. Reality keys must be generated on the <a onclick="navigate('/admin')">Admin → Inbound</a> tab first.</p>
         <div class="empty-help">
           <div class="empty-help-title">How users connect</div>
           <ol class="empty-help-list">
             <li>Issue a peer here → click the <span class="mono">vless://</span> button to copy the URL, or <span class="mono">QR</span> to show a code.</li>
             <li>User opens <b>Amnezia VPN</b> (iOS / Android / desktop), <b>v2rayN</b>, <b>v2rayNG</b>, <b>NekoBox</b>, <b>Hiddify</b>, <b>Streisand</b>, <b>Shadowrocket</b>, or <b>FoXray</b>.</li>
             <li>In their app, <span class="mono">+ Add server → Configuration file or text</span> (or <span class="mono">Scan QR</span>) → paste / scan.</li>
             <li>Connect. Their app marks the server as <i>third-party</i>; that's expected — peer management stays here.</li>
           </ol>
         </div>`
      : `<h3>No Browsing peers issued for your account</h3>
         <p>Ask an admin to create one.</p>`;
    if (createBtn) createBtn.style.display = isAdmin ? '' : 'none';
    return;
  }
  empty.style.display = 'none';
  if (createBtn) createBtn.style.display = isAdmin ? '' : 'none';

  list.innerHTML = clients.map(c => `
    <div class="peer-card ${c.enabled ? '' : 'is-disabled'}">
      <div class="peer-main">
        <div class="peer-name">
          <button class="peer-name-link" onclick="navigate('/xray/clients/${c.id}')">${esc(c.name)}</button>
          ${c.enabled ? '' : '<span class="pill">disabled</span>'}
        </div>
        <div class="peer-meta">
          <span class="mono">${esc(c.uuid.slice(0, 8))}…</span>
          <span style="color:var(--fg-faint)">·</span>
          <span title="Reality short-id (per-peer)">sid: ${esc(c.shortId)}</span>
        </div>
      </div>
      <div class="peer-actions">
        <button class="btn btn--quiet btn--icon" title="Copy vless:// share URL.&#10;&#10;Paste into:&#10;• Amnezia VPN — Add server → Configuration file or text&#10;• v2rayN / v2rayNG — server list → import URL/clipboard&#10;• Hiddify, NekoBox, Streisand, Shadowrocket, FoXray — same flow" onclick="copyXrayShare(${c.id})">vless://</button>
        <button class="btn btn--quiet btn--icon" title="QR code.&#10;&#10;Scan from inside:&#10;• Amnezia VPN — Add server → Scan QR&#10;• v2rayNG, Hiddify, NekoBox, Shadowrocket — server list → scan&#10;Or save the SVG and import as image" onclick="showXrayQr(${c.id}, '${escJs(c.name)}')">QR</button>
        ${isAdmin ? `<button class="btn btn--quiet btn--icon" title="Edit" onclick="navigate('/xray/clients/${c.id}')"><svg><use href="#i-edit"/></svg></button>` : ''}
      </div>
    </div>
  `).join('');
}

function showXrayCreateModal() {
  const name = prompt('Name for new Browsing peer:');
  if (!name || !name.trim()) return;
  POST('/api/xray/clients', { name: name.trim() })
    .then(() => { showToast('Peer created', 'success'); refreshXrayClients(); })
    .catch(e => showToast(e.message, 'error'));
}

async function copyXrayShare(id) {
  try {
    const resp = await fetch('/api/xray/clients/' + id + '/share', { credentials: 'same-origin' });
    if (!resp.ok) throw new Error(await resp.text() || resp.statusText);
    const url = await resp.text();
    await navigator.clipboard.writeText(url);
    showToast('vless:// URL copied', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function showXrayQr(id, name) {
  try {
    const resp = await fetch('/api/xray/clients/' + id + '/qrcode.svg', { credentials: 'same-origin' });
    if (!resp.ok) throw new Error(await resp.text() || resp.statusText);
    const svg = await resp.text();
    // Reuse the existing QR modal if present, else open a new window.
    const modal = $('modal-qr');
    if (modal) {
      $('modal-qr-title').textContent = 'QR for ' + name;
      $('modal-qr-body').innerHTML = svg;
      modal.classList.add('active');
    } else {
      const w = window.open('', '_blank', 'width=420,height=480');
      if (w) {
        w.document.write('<html><head><title>QR — ' + esc(name) + '</title></head><body style="margin:0;display:flex;align-items:center;justify-content:center;background:#111">' + svg + '</body></html>');
      }
    }
  } catch(e) { showToast(e.message, 'error'); }
}

async function loadXrayClientEdit(id) {
  $('xray-edit-crumb-name').textContent = 'Loading…';
  try {
    const c = await GET('/api/xray/clients/' + id);
    $('xray-edit-crumb-name').textContent = c.name;
    const isAdmin = USER && USER.role === 1;
    $('xray-edit-form').innerHTML = `
      <div class="card">
        <div class="card-head">
          <div>
            <div class="card-title">${esc(c.name)}</div>
            <div class="card-sub">UUID: <span class="mono">${esc(c.uuid)}</span> · shortId: <span class="mono">${esc(c.shortId)}</span></div>
          </div>
          <label class="toggle ${c.enabled ? 'is-on' : ''}">
            <input type="checkbox" id="xredit-enabled" ${c.enabled ? 'checked' : ''} ${isAdmin?'':'disabled'}>
            <span class="toggle-track"><span class="toggle-thumb"></span></span>
            <span class="toggle-label">Enabled</span>
          </label>
        </div>
        <div class="card-body">
          <div class="stack">
            <div class="field">
              <label class="field-label" for="xredit-name">Display name</label>
              <input type="text" id="xredit-name" value="${esc(c.name)}" ${isAdmin?'':'disabled'}>
            </div>
            <div class="field">
              <label class="field-label" for="xredit-expires" title="Optional expiry. After this time the peer is disabled and the supervisor reloads to drop the shortId.">Expires</label>
              <input type="datetime-local" id="xredit-expires" value="${c.expiresAt ? new Date(c.expiresAt).toISOString().slice(0,16) : ''}" ${isAdmin?'':'disabled'}>
            </div>
            <div class="field">
              <label class="field-label" for="xredit-extra" title="Free-form text appended to this peer's clients[] entry — typically empty. Server-only — clients don't see this.">Additional config (JSON, optional)</label>
              <textarea id="xredit-extra" rows="3" placeholder="(empty)" ${isAdmin?'':'disabled'}>${esc(c.additionalConfig || '')}</textarea>
            </div>
            <div class="field">
              <label class="field-label">Share with the user</label>
              <div class="share-help">
                <div class="share-option">
                  <div class="share-option-head">
                    <button class="btn btn--ghost btn--sm" type="button" onclick="copyXrayShare(${c.id})">Copy vless://</button>
                    <span class="share-tag">universal</span>
                  </div>
                  <div class="share-option-text">
                    Standard <span class="mono">vless://</span> URL. Paste into the user's app:
                    <ul>
                      <li><b>Amnezia VPN</b> (iOS / Android / desktop): <span class="mono">+ Add server → Configuration file or text → paste</span></li>
                      <li><b>v2rayN</b> (Windows): <span class="mono">Servers → Import bulk URL from clipboard</span></li>
                      <li><b>v2rayNG</b> (Android): <span class="mono">+ → Import config from clipboard</span></li>
                      <li><b>NekoBox / NekoRay, Hiddify, Streisand, Shadowrocket, FoXray</b>: same — import-from-clipboard</li>
                    </ul>
                  </div>
                </div>
                <div class="share-option">
                  <div class="share-option-head">
                    <button class="btn btn--ghost btn--sm" type="button" onclick="showXrayQr(${c.id}, '${escJs(c.name)}')">Show QR code</button>
                    <span class="share-tag">scan with phone</span>
                  </div>
                  <div class="share-option-text">
                    Same <span class="mono">vless://</span> URL encoded as a QR. Scan from the user's app:
                    <ul>
                      <li><b>Amnezia VPN</b>: <span class="mono">+ Add server → Scan QR</span></li>
                      <li><b>v2rayNG / NekoBox / Hiddify / Shadowrocket</b>: scan from server-list screen</li>
                    </ul>
                    Or save the SVG and import as image if the device has no camera.
                  </div>
                </div>
                <div class="share-option">
                  <div class="share-option-head">
                    <a class="btn btn--ghost btn--sm" href="/api/xray/clients/${c.id}/json" target="_blank" rel="noopener">Amnezia JSON</a>
                    <span class="share-tag">Amnezia VPN only</span>
                  </div>
                  <div class="share-option-text">
                    Native <span class="mono">server.json</span> in the format Amnezia VPN exports its own configs in.
                    Use this only when <span class="mono">vless://</span> import is failing on a particularly old build —
                    paste contents into <span class="mono">+ Add server → Configuration file or text</span>.
                    Other apps (v2rayN/Hiddify/etc.) won't accept this format.
                  </div>
                </div>
                <div class="share-note">
                  <svg><use href="#i-shield"/></svg>
                  Imported configs are marked <i>third-party</i> in the user's app — they connect, but can't manage the server. That's by design: peer creation lives here.
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      ${isAdmin ? `
      <div class="danger-zone" style="margin-top:18px">
        <div class="danger-zone-text">
          <b>Delete peer</b>
          <span>Removes <span class="mono">${esc(c.name)}</span>'s shortId and UUID. Existing clients with this share will fail with "client not found".</span>
        </div>
        <button class="btn btn--danger" onclick="confirmXrayDelete(${c.id}, '${escJs(c.name)}')"><svg><use href="#i-trash"/></svg> Delete peer</button>
      </div>
      <div class="save-bar">
        <span class="changed">Changes reload Xray (SIGHUP)</span>
        <div class="save-bar-spacer"></div>
        <button class="btn btn--ghost" onclick="loadXrayClientEdit(${c.id})">Discard</button>
        <button class="btn btn--primary" onclick="saveXrayClient(${c.id})">Save</button>
      </div>` : ''}
    `;
    injectTooltips();
  } catch(e) { showToast(e.message, 'error'); }
}

async function saveXrayClient(id) {
  const expires = $('xredit-expires').value;
  const body = {
    name: $('xredit-name').value,
    enabled: $('xredit-enabled').checked,
    expires_at: expires ? new Date(expires).toISOString() : null,
    additionalConfig: $('xredit-extra').value
  };
  try {
    await POST('/api/xray/clients/' + id, body);
    showToast('Saved', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

function confirmXrayDelete(id, name) {
  if (!confirm('Delete Browsing peer "' + name + '"? Their share URL will stop working immediately.')) return;
  DEL('/api/xray/clients/' + id)
    .then(() => { showToast('Peer deleted', 'success'); navigate('/xray'); })
    .catch(e => showToast(e.message, 'error'));
}

// --- Admin: Xray inbound -------------------------------------------------

async function saveXrayInbound(e) {
  e.preventDefault();
  const sni = $('adm-xr-sni').value.split('\n').map(s => s.trim()).filter(Boolean);
  if (!sni.length) { showToast('At least one server name is required', 'error'); return; }
  const body = {
    port: parseInt($('adm-xr-port').value) || 443,
    dest: $('adm-xr-dest').value.trim(),
    serverNames: sni,
    fingerprintDefault: $('adm-xr-fp').value,
    additionalConfig: $('adm-xr-extra').value,
    enabled: $('adm-xr-enabled').checked
  };
  try {
    await POST('/api/admin/xray/inbound', body);
    showToast('Saved', 'success');
    showAdminTab('xray');
  } catch(e) { showToast(e.message, 'error'); }
}

async function regenerateXrayKeys() {
  if (!confirm('Regenerate the Reality keypair? Every existing Browsing peer\'s vless:// link becomes invalid — you\'ll need to redistribute QR codes.')) return;
  try {
    const r = await POST('/api/admin/xray/inbound/regenerate-keys', {});
    showToast('Keypair generated; pbk: ' + (r.publicKey || '').slice(0, 16) + '…', 'success');
    showAdminTab('xray');
  } catch(e) { showToast(e.message, 'error'); }
}

async function probeXrayDest() {
  const dest = $('adm-xr-dest').value.trim();
  const sni = $('adm-xr-sni').value.split('\n').map(s => s.trim()).filter(Boolean)[0] || '';
  if (!dest || !sni) { showToast('Need both dest and a server name', 'error'); return; }
  const out = $('adm-xr-probe-result');
  out.textContent = 'Probing…';
  try {
    const r = await POST('/api/admin/xray/inbound/probe-dest', { dest, sni });
    const status = r.ok ? '<span class="pill pill--ok">OK</span>' : '<span class="pill pill--err">Reject</span>';
    const warn = (r.warnings || []).map(w => `<div style="color:var(--fg-warn)">⚠ ${esc(w)}</div>`).join('');
    out.innerHTML = `${status} TLS ${esc(r.tls_version)} · ALPN ${esc(r.alpn || 'none')} · ${r.rtt_ms}ms · SAN match: ${r.sni_matches_san ? 'yes' : 'no'}${warn ? '<br>' + warn : ''}`;
  } catch(e) {
    out.innerHTML = '<span class="pill pill--err">Probe failed</span> ' + esc(e.message);
  }
}

async function restartXray() {
  try {
    await POST('/api/admin/xray/restart', {});
    showToast('Xray restarted', 'success');
    showAdminTab('xray');
  } catch(e) { showToast(e.message, 'error'); }
}
