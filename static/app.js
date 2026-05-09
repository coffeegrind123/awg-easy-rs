// ===================== STATE =====================
let USER = null;
let IN_SESSION_CHECK = false;
let CLIENTS = [];
let CLIENT_PREV = {};
let ADMIN_TAB = 'general';
let SETUP_STEP = 1;
let TOTAL_STEPS = 4;

// ===================== HELPERS =====================
function $(id) { return document.getElementById(id); }
function $$(sel) { return document.querySelectorAll(sel); }

function showToast(msg, type) {
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = msg;
  $('toasts').appendChild(el);
  setTimeout(() => el.remove(), 5000);
}

function formatBytes(bytes, decimals = 1) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1000, sizes = ['B','KB','MB','GB','TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return (bytes / Math.pow(k, i)).toFixed(decimals) + ' ' + sizes[i];
}

function timeAgo(date) {
  if (!date) return 'Never';
  const seconds = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
  if (seconds < 60) return 'just now';
  const mins = Math.floor(seconds / 60);
  if (mins < 60) return mins + 'm ago';
  const hours = Math.floor(mins / 60);
  if (hours < 24) return hours + 'h ago';
  return Math.floor(hours / 24) + 'd ago';
}

function sanitize(str) {
  return str.replace(/[^a-zA-Z0-9_=+.-]/g, '-').substring(0, 32);
}

function isConnected(handshake) {
  if (!handshake) return false;
  return (Date.now() - new Date(handshake).getTime()) < 180000;
}

// ===================== API =====================
async function api(method, path, body) {
  const opts = { method, credentials: 'include', headers: {} };
  if (body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const res = await fetch(path, opts);
  if (res.status === 401) { USER = null; if (!IN_SESSION_CHECK) navigate('/login'); return null; }
  if (!res.ok) { const err = await res.json().catch(() => ({error: res.statusText})); throw new Error(err.error || err.message || res.statusText); }
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

  // Hide all pages
  $$('.page').forEach(p => p.classList.remove('active'));

  // Check auth first (skip for login, setup, and cnf routes)
  if (path !== '/login' && path !== '/setup' && !path.startsWith('/setup') && !path.startsWith('/cnf')) {
    checkSession().then(ok => {
      if (!ok) return;
      routeInternal(path);
    });
  } else {
    routeInternal(path);
  }
}

function routeInternal(path) {
  if (path === '/login') {
    $('header').style.display = 'none';
    $('page-login').classList.add('active');
    if (location.protocol !== 'https:' && location.hostname !== 'localhost') {
      $('insecure-warning').style.display = 'block';
    }
  } else if (path === '/setup' || path.startsWith('/setup')) {
    $('header').style.display = 'none';
    $('page-setup').classList.add('active');
    loadSetup();
  } else if (path === '/') {
    $('header').style.display = 'block';
    $('page-clients').classList.add('active');
    renderNav();
    refreshClients();
  } else if (path.startsWith('/clients/')) {
    $('header').style.display = 'block';
    $('page-client-edit').classList.add('active');
    renderNav();
    const id = path.split('/')[2];
    loadClientEdit(id);
  } else if (path === '/me') {
    $('header').style.display = 'block';
    $('page-me').classList.add('active');
    renderNav();
    loadMe();
  } else if (path === '/admin') {
    $('header').style.display = 'block';
    $('page-admin').classList.add('active');
    renderNav();
    showAdminTab(ADMIN_TAB);
  } else {
    $('header').style.display = 'block';
    $('page-clients').classList.add('active');
    renderNav();
    refreshClients();
  }
}

window.addEventListener('hashchange', route);
window.addEventListener('load', route);

// Auto-inject tooltip icons on labels with title attribute
function injectTooltips() {
  setTimeout(() => {
    document.querySelectorAll('label[title]').forEach(l => {
      if (!l.querySelector('.tip')) {
        const t = document.createElement('span');
        t.className = 'tip'; t.dataset.tip = l.title; t.textContent = '?';
        l.title = ''; l.appendChild(t);
      }
    });
  }, 100);
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
      return true;
    }
  } catch(e) {}
  USER = null;
  // Check if setup is needed before redirecting (but not from login page)
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
    remember: $('login-remember').checked
  };
  try {
    const res = await POST('/api/session', body);
    if (res && res.status === 'TOTP_REQUIRED') {
      $('totp-group').style.display = 'block';
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
  $('nav-links').innerHTML = `
    <a href="#/" onclick="navigate('/')">Clients</a>
    ${USER.role === 1 ? '<a href="#/admin" onclick="navigate(\'/admin\')">Admin</a>' : ''}
    <a href="#/me" onclick="navigate(\'/me\')">Account</a>
    <button onclick="toggleTheme()" title="Toggle theme">☀</button>
    <button onclick="doLogout()">Logout</button>
  `;
}

// ===================== THEME =====================
function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme');
  const next = cur === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
}
(function() {
  const saved = localStorage.getItem('theme');
  if (saved) document.documentElement.setAttribute('data-theme', saved);
})();

// ===================== CLIENTS =====================
let clientRefreshTimer = null;

async function refreshClients() {
  try {
    const data = await GET('/api/client');
    if (!data) return;
    // Compute transfer rates
    const now = Date.now();
    for (const c of data) {
      const prev = CLIENT_PREV[c.id];
      if (prev && prev.transferRx != null && c.transferRx != null) {
        c.rxRate = (c.transferRx - prev.transferRx) / 5;
        c.txRate = (c.transferTx - prev.transferTx) / 5;
      }
      CLIENT_PREV[c.id] = { ...c, ts: now };
    }
    CLIENTS = data;
    renderClients();
  } catch(e) { showToast(e.message, 'error'); }
  clientRefreshTimer = setTimeout(refreshClients, 5000);
}

let clientFilter = '';
$('client-search').addEventListener('input', function() {
  clientFilter = this.value.toLowerCase();
  renderClients();
});

function renderClients() {
  const el = $('client-list');
  let filtered = CLIENTS;
  if (clientFilter) filtered = CLIENTS.filter(c => c.name.toLowerCase().includes(clientFilter));

  if (CLIENTS.length === 0) {
    el.innerHTML = '<div class="empty"><h3>No clients yet</h3><p>Create your first client to get started.</p></div>';
    return;
  }

  el.innerHTML = filtered.map(c => {
    const online = isConnected(c.latestHandshakeAt);
    const expiresText = c.expiresAt ? new Date(c.expiresAt).toLocaleDateString() : 'Permanent';
    const rxRate = c.rxRate ? formatBytes(c.rxRate) + '/s' : '—';
    const txRate = c.txRate ? formatBytes(c.txRate) + '/s' : '—';

    return `<div class="card">
      <div class="card-header">
        <span class="status-dot ${online ? 'online' : 'offline'}"></span>
        <div style="flex:1">
          <div class="flex-between">
            <span class="card-title">${esc(c.name)}</span>
            <label class="toggle" onclick="event.stopPropagation()">
              <input type="checkbox" ${c.enabled ? 'checked' : ''} onchange="toggleClient(${c.id}, this.checked)">
              <span></span>
            </label>
          </div>
          <div class="text-sm text-muted">
            ${esc(c.ipv4Address || '—')} ${c.ipv6Address ? '| ' + esc(c.ipv6Address) : ''}
          </div>
          <div class="text-sm text-muted">
            Last seen: ${timeAgo(c.latestHandshakeAt)} · ${expiresText}
          </div>
          <div class="text-sm" style="margin-top:4px">
            ↓ ${txRate} · ↑ ${rxRate}
          </div>
          ${c.oneTimeLink ? `<div class="otl-box mono">${esc(c.oneTimeLink.oneTimeLink)} <span class="countdown" id="otl-${c.id}"></span></div>` : ''}
        </div>
      </div>
      <div class="flex gap-8 mt-8">
        <button class="btn btn-secondary btn-sm" onclick="navigate('/clients/${c.id}')">Edit</button>
        <button class="btn btn-secondary btn-sm" onclick="showQR(${c.id})">QR</button>
        <a class="btn btn-secondary btn-sm" href="/api/client/${c.id}/configuration" download>Download</a>
        <button class="btn btn-secondary btn-sm" onclick="generateOTL(${c.id})">Link</button>
      </div>
    </div>`;
  }).join('');

  // Update OTL countdowns
  for (const c of CLIENTS) {
    if (c.oneTimeLink) {
      const el = $('otl-' + c.id);
      if (el) {
        const exp = new Date(c.oneTimeLink.expiresAt).getTime();
        const update = () => {
          const secs = Math.max(0, Math.floor((exp - Date.now()) / 1000));
          el.textContent = Math.floor(secs/60) + ':' + String(secs%60).padStart(2,'0');
          if (secs > 0) setTimeout(update, 1000);
        };
        update();
      }
    }
  }
}

function esc(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
function escJs(s) { return s.replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/"/g,'\\"').replace(/\n/g,'\\n').replace(/\r/g,'\\r'); }

async function toggleClient(id, enabled) {
  try {
    await POST('/api/client/' + id + '/' + (enabled ? 'enable' : 'disable'));
    refreshClients();
  } catch(e) { showToast(e.message, 'error'); }
}

function showCreateModal() { $('modal-create').classList.add('active'); }
function closeModal(id) { $(id).classList.remove('active'); }

async function createClient(e) {
  e.preventDefault();
  const body = { name: $('create-name').value };
  const expires = $('create-expires').value;
  if (expires) body.expiresAt = new Date(expires).toISOString();
  try {
    await POST('/api/client', body);
    closeModal('modal-create');
    showToast('Client created', 'success');
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
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  const img = new Image();
  img.onload = () => {
    canvas.width = img.width; canvas.height = img.height;
    ctx.drawImage(img, 0, 0);
    canvas.toBlob(async blob => {
      await navigator.clipboard.write([new ClipboardItem({'image/png': blob})]);
      showToast('QR copied', 'success');
    });
  };
  img.src = 'data:image/svg+xml;base64,' + btoa(new XMLSerializer().serializeToString(svg));
}

function downloadQR() {
  const svg = $('qr-image').querySelector('svg');
  if (!svg) return;
  const blob = new Blob([new XMLSerializer().serializeToString(svg)], {type: 'image/svg+xml'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'qrcode.svg'; a.click();
}

async function generateOTL(id) {
  try {
    await POST('/api/client/' + id + '/generateOneTimeLink');
    showToast('One-time link generated', 'success');
    refreshClients();
  } catch(e) { showToast(e.message, 'error'); }
}

async function showConfig(id) {
  try {
    const config = await GET('/api/client/' + id + '/configuration');
    $('config-text').textContent = config;
    $('modal-config').classList.add('active');
  } catch(e) { showToast(e.message, 'error'); }
}

function copyConfig() {
  navigator.clipboard.writeText($('config-text').textContent);
  showToast('Copied', 'success');
}

// ===================== CLIENT EDIT =====================
async function loadClientEdit(id) {
  try {
    const c = await GET('/api/client/' + id);
    if (!c) return;
    $('edit-title').textContent = c.name;
    $('edit-form').innerHTML = `
      <div class="form-group"><label>Name</label><input type="text" id="edit-name" value="${esc(c.name||'')}"></div>
      <div class="grid-2">
        <div class="form-group"><label>IPv4 Address</label><input type="text" id="edit-ipv4" value="${esc(c.ipv4Address||'')}"></div>
        <div class="form-group"><label>IPv6 Address</label><input type="text" id="edit-ipv6" value="${esc(c.ipv6Address||'')}"></div>
      </div>
      <div class="form-group"><label>Enabled</label><label class="toggle"><input type="checkbox" id="edit-enabled" ${c.enabled?'checked':''}><span></span></label></div>
      <div class="form-group"><label>Expire Date</label><input type="date" id="edit-expires" value="${c.expiresAt ? c.expiresAt.slice(0,10) : ''}"></div>
      <div class="form-group"><label>DNS Servers (comma separated)</label><input type="text" id="edit-dns" value="${esc((c.dns||[]).join(', '))}"></div>
      <div class="grid-2">
        <div class="form-group"><label>MTU</label><input type="number" id="edit-mtu" value="${c.mtu||1420}"></div>
        <div class="form-group"><label>Persistent Keepalive</label><input type="number" id="edit-keepalive" value="${c.persistentKeepalive||0}"></div>
      </div>
      <div class="form-group"><label>Allowed IPs (comma separated)</label><input type="text" id="edit-allowedips" value="${esc((c.allowedIps||[]).join(', '))}"></div>
      <h4 class="mt-16 mb-8">AmneziaWG Obfuscation (per-client override)</h4>
      <div class="grid-2">
        <div class="form-group"><label>Jc</label><input type="number" id="edit-jc" value="${c.jC||''}"></div>
        <div class="form-group"><label>Jmin</label><input type="number" id="edit-jmin" value="${c.jMin||''}"></div>
      </div>
      <div class="form-group"><label>Jmax</label><input type="number" id="edit-jmax" value="${c.jMax||''}"></div>
      <div class="form-group">
        <label title="Per-peer AmneziaWG opt-in. 'On' = emit AdvancedSecurity = on; 'Off' = emit AdvancedSecurity = off; 'Auto' = omit and let the kernel auto-detect from the H1 magic header on the first incoming handshake.">AdvancedSecurity</label>
        <select id="edit-advsec">
          <option value="auto" ${c.advancedSecurity == null ? 'selected' : ''}>Auto (kernel detects)</option>
          <option value="on" ${c.advancedSecurity === true ? 'selected' : ''}>On</option>
          <option value="off" ${c.advancedSecurity === false ? 'selected' : ''}>Off</option>
        </select>
      </div>
      <div class="flex gap-8 mt-16">
        <button class="btn btn-primary" onclick="saveClient(${id})">Save</button>
        <button class="btn btn-secondary" onclick="showConfig(${id})">View Config</button>
        <a class="btn btn-secondary" href="/api/client/${id}/configuration" download>Download</a>
        <button class="btn btn-danger" onclick="confirmDelete(${id}, '${escJs(c.name||'')}')">Delete</button>
      </div>
    `;
  } catch(e) { showToast(e.message, 'error'); }
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
  // AdvancedSecurity: tri-state — only include in body when explicitly set
  // (so we don't tell the server to do anything when value is "auto" and
  // the column is already null).
  const advsec = $('edit-advsec').value;
  if (advsec === 'on') body.advancedSecurity = true;
  else if (advsec === 'off') body.advancedSecurity = false;
  else if (advsec === 'auto') body.advancedSecurity = null;
  const expires = $('edit-expires').value;
  if (expires) body.expiresAt = new Date(expires).toISOString();
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
      showToast('Deleted', 'success');
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
}

async function saveProfile(e) {
  e.preventDefault();
  try {
    await POST('/api/me', { name: $('me-name').value, email: $('me-email').value || null });
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
  const links = $$('.sidebar-nav a');
  links.forEach(l => l.classList.remove('active'));
  if (e && e.target) e.target.classList.add('active');

  const el = $('admin-content');
  el.innerHTML = '<div class="loading">Loading...</div>';

  try {
    if (tab === 'general') {
      const g = await GET('/api/admin/general');
      el.innerHTML = `
        <h3 class="mb-16">General Settings</h3>
        <form onsubmit="saveAdminGeneral(event)">
          <div class="form-group"><label>Session Timeout (seconds)</label><input type="number" id="adm-session-timeout" value="${g.sessionTimeout||3600}"></div>
          <div class="form-group"><label>Enable Prometheus Metrics</label><label class="toggle"><input type="checkbox" id="adm-metrics-prom" ${g.metricsPrometheus?'checked':''}><span></span></label></div>
          <div class="form-group"><label>Enable JSON Metrics</label><label class="toggle"><input type="checkbox" id="adm-metrics-json" ${g.metricsJson?'checked':''}><span></span></label></div>
          <button class="btn btn-primary">Save</button>
        </form>`;
    } else if (tab === 'config') {
      const uc = await GET('/api/admin/userconfig');
      el.innerHTML = `
        <h3 class="mb-16">Default Client Configuration</h3>
        <form onsubmit="saveAdminConfig(event)">
          <div class="form-group"><label>Server Hostname/IP</label><input type="text" id="adm-host" value="${esc(uc.host||'')}"></div>
          <div class="form-group"><label>Server Port</label><input type="number" id="adm-port" value="${uc.port||51820}"></div>
          <div class="form-group"><label>Default DNS (comma separated)</label><input type="text" id="adm-dns" value="${esc((uc.defaultDns||[]).join(', '))}"></div>
          <div class="form-group"><label>Default Allowed IPs (comma separated)</label><input type="text" id="adm-allowedips" value="${esc((uc.defaultAllowedIps||[]).join(', '))}"></div>
          <div class="grid-2">
            <div class="form-group"><label>Default MTU</label><input type="number" id="adm-mtu" value="${uc.defaultMtu||1420}"></div>
            <div class="form-group"><label>Default Keepalive</label><input type="number" id="adm-keepalive" value="${uc.defaultPersistentKeepalive||0}"></div>
          </div>
          <button class="btn btn-primary">Save</button>
        </form>`;
    } else if (tab === 'interface') {
      const iface = await GET('/api/admin/interface');
      el.innerHTML = `
        <h3 class="mb-16">Interface Configuration</h3>
        <form onsubmit="saveAdminInterface(event)">
          <div class="grid-2">
            <div class="form-group"><label title="Maximum Transmission Unit for the VPN interface. Default: 1420">MTU</label><input type="number" id="adm-if-mtu" value="${iface.mtu||1420}"></div>
            <div class="form-group"><label title="UDP port for AmneziaWG connections. Default: 51820">Port</label><input type="number" id="adm-if-port" value="${iface.port||51820}"></div>
          </div>
          <div class="form-group"><label title="Physical network interface to route traffic through. Default: eth0">Device</label><input type="text" id="adm-if-device" value="${esc(iface.device||'eth0')}"></div>
          <div class="grid-2">
            <div class="form-group"><label title="IPv4 subnet for VPN clients. Server gets .1 address">IPv4 CIDR</label><input type="text" id="adm-if-ipv4" value="${esc(iface.ipv4Cidr||'')}"></div>
            <div class="form-group"><label title="IPv6 subnet for VPN clients. Leave empty to disable IPv6">IPv6 CIDR</label><input type="text" id="adm-if-ipv6" value="${esc(iface.ipv6Cidr||'')}"></div>
          </div>
          <div class="form-group"><label title="Restrict each client to only access their allowed IPs via iptables rules. Requires iptables installed">Per-Client Firewall</label><label class="toggle"><input type="checkbox" id="adm-if-firewall" ${iface.firewallEnabled?'checked':''}><span></span></label></div>
          <h3 class="mb-16 mt-16">AmneziaWG Obfuscation Parameters</h3>
          <div class="grid-2">
            <div class="form-group"><label title="Number of random junk packets sent before each handshake initiation (1-128). Recommended: 4-12">Jc</label><input type="number" id="adm-if-jc" value="${iface.jC||7}" min="1" max="128"></div>
            <div class="form-group"><label title="Minimum size in bytes for junk packets (0-1279)">Jmin</label><input type="number" id="adm-if-jmin" value="${iface.jMin||10}" min="0" max="1279"></div>
          </div>
          <div class="form-group"><label title="Maximum size in bytes for junk packets (1-1279). Spec: Jmax < 1280; must be > Jmin and < MTU to avoid fragmentation">Jmax</label><input type="number" id="adm-if-jmax" value="${iface.jMax||1000}" min="1" max="1279"></div>
          <div class="grid-2">
            <div class="form-group"><label title="Random padding bytes prepended to handshake initiation messages (0-1132). Recommended: 15-150">S1</label><input type="number" id="adm-if-s1" value="${iface.s1||128}" min="0" max="1132"></div>
            <div class="form-group"><label title="Random padding bytes prepended to handshake response messages (0-1188). Recommended: 15-150. Must differ from S1+56">S2</label><input type="number" id="adm-if-s2" value="${iface.s2||56}" min="0" max="1188"></div>
          </div>
          <div class="grid-2">
            <div class="form-group"><label title="Random padding for cookie reply messages (0-1216). AmneziaWG 2.0 only">S3</label><input type="number" id="adm-if-s3" value="${iface.s3||''}" min="0" max="1216"></div>
            <div class="form-group"><label title="Random padding for transport/data messages (0-32). AmneziaWG 2.0 only">S4</label><input type="number" id="adm-if-s4" value="${iface.s4||''}" min="0" max="32"></div>
          </div>
          <div class="grid-2">
            <div class="form-group"><label title="Magic header for handshake initiation packets. Can be a single value or range 'N-M'. Must not overlap with H2-H4">H1</label><input type="text" id="adm-if-h1" value="${esc(iface.h1||'')}"></div>
            <div class="form-group"><label title="Magic header for handshake response packets. Must not overlap with H1,H3,H4">H2</label><input type="text" id="adm-if-h2" value="${esc(iface.h2||'')}"></div>
          </div>
          <div class="grid-2">
            <div class="form-group"><label title="Magic header for cookie reply packets. Must not overlap with H1,H2,H4">H3</label><input type="text" id="adm-if-h3" value="${esc(iface.h3||'')}"></div>
            <div class="form-group"><label title="Magic header for transport/data packets. Must not overlap with H1-H3">H4</label><input type="text" id="adm-if-h4" value="${esc(iface.h4||'')}"></div>
          </div>
          <div class="form-group"><label title="Init junk spec (I1) — custom packet sent before handshake. Tag format: <b 0xHEX>=static bytes, <r N>=N random bytes (1-1000), <rc N>=N random ASCII letters, <rd N>=N random digits, <t>=4-byte timestamp, <c>=packet counter">I1 (init spec)</label><textarea id="adm-if-i1" rows="4">${esc(iface.i1||'')}</textarea></div>
          <div class="grid-2">
            <div class="form-group"><label title="Second init junk spec. Same tag format as I1">I2</label><textarea id="adm-if-i2" rows="2">${esc(iface.i2||'')}</textarea></div>
          <div class="grid-2">
            <div class="form-group"><label title="Third init junk spec">I3</label><textarea id="adm-if-i3" rows="2">${esc(iface.i3||'')}</textarea></div>
            <div class="form-group"><label title="Fourth init junk spec">I4</label><textarea id="adm-if-i4" rows="2">${esc(iface.i4||'')}</textarea></div>
          </div>
          <div class="form-group"><label title="Fifth init junk spec">I5</label><textarea id="adm-if-i5" rows="2">${esc(iface.i5||'')}</textarea></div>
          <div class="grid-2">
            <div class="form-group"><label title="Additional junk string 1. Kernel module only">J1 (kmod)</label><input type="text" id="adm-if-j1" value="${esc(iface.j1||'')}"></div>
            <div class="form-group"><label title="Additional junk string 2. Kernel module only">J2 (kmod)</label><input type="text" id="adm-if-j2" value="${esc(iface.j2||'')}"></div>
          </div>
          <div class="grid-2">
            <div class="form-group"><label title="Additional junk string 3. Kernel module only">J3 (kmod)</label><input type="text" id="adm-if-j3" value="${esc(iface.j3||'')}"></div>
            <div class="form-group"><label title="Junk packet interval in seconds. 0 = disabled. Kernel module only">Itime (kmod)</label><input type="number" id="adm-if-itime" value="${iface.itime||0}"></div>
          </div>
          <div class="flex gap-8 mt-16">
            <button class="btn btn-primary">Save</button>
            <button type="button" class="btn btn-secondary" onclick="restartWG()">Restart Interface</button>
          </div>
        </form>`;
    } else if (tab === 'hooks') {
      const hooks = await GET('/api/admin/hooks');
      el.innerHTML = `
        <h3 class="mb-16">Interface Hooks</h3>
        <form onsubmit="saveAdminHooks(event)">
          <div class="form-group"><label title="Commands run BEFORE the AmneziaWG interface comes up. Leave empty unless using wg-quick hooks. Template vars: {{device}} {{port}} {{ipv4Cidr}} {{ipv6Cidr}}">PreUp</label><textarea id="adm-hook-preup" rows="3">${esc(hooks.preUp||'')}</textarea></div>
          <div class="form-group"><label title="Commands run AFTER the interface comes up. Default sets up NAT masquerading and firewall rules for client traffic forwarding">PostUp</label><textarea id="adm-hook-postup" rows="3">${esc(hooks.postUp||'')}</textarea></div>
          <div class="form-group"><label title="Commands run BEFORE the AmneziaWG interface goes down. Used to clean up PreUp rules">PreDown</label><textarea id="adm-hook-predown" rows="3">${esc(hooks.preDown||'')}</textarea></div>
          <div class="form-group"><label title="Commands run AFTER the interface goes down. Default removes iptables NAT and forwarding rules">PostDown</label><textarea id="adm-hook-postdown" rows="3">${esc(hooks.postDown||'')}</textarea></div>
          <button class="btn btn-primary">Save</button>
        </form>`;
    }
  } catch(e) { showToast(e.message, 'error'); el.innerHTML = '<p class="text-muted">Error loading data</p>'; }
  setTimeout(injectTooltips, 50);
}

async function saveAdminGeneral(e) {
  e.preventDefault();
  try {
    await POST('/api/admin/general', {
      sessionTimeout: parseInt($('adm-session-timeout').value)||3600,
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
      port: parseInt($('adm-port').value)||51820,
      defaultDns: $('adm-dns').value.split(',').map(s=>s.trim()).filter(Boolean),
      defaultAllowedIps: $('adm-allowedips').value.split(',').map(s=>s.trim()).filter(Boolean),
      defaultMtu: parseInt($('adm-mtu').value)||1420,
      defaultPersistentKeepalive: parseInt($('adm-keepalive').value)||0
    });
    showToast('Saved', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function saveAdminInterface(e) {
  e.preventDefault();
  // Validate AWG params
  const jc = parseInt($('adm-if-jc').value)||0;
  const jmin = parseInt($('adm-if-jmin').value)||0;
  const jmax = parseInt($('adm-if-jmax').value)||0;
  const s1 = parseInt($('adm-if-s1').value)||0;
  const s2 = parseInt($('adm-if-s2').value)||0;
  if (jc && (jc < 1 || jc > 128)) { showToast('Jc must be 1-128', 'error'); return; }
  if (jmin && (jmin < 0 || jmin > 1279)) { showToast('Jmin must be 0-1279', 'error'); return; }
  if (jmax && (jmax < 1 || jmax > 1279)) { showToast('Jmax must be 1-1279', 'error'); return; }
  if (jmax > 0 && jmin >= jmax) { showToast('Jmax must be > Jmin', 'error'); return; }
  if (s1 > 0 && s2 > 0 && s1 + 56 === s2) { showToast('S1 + 56 must not equal S2', 'error'); return; }
  const s3 = parseInt($('adm-if-s3').value) || 0;
  const s4 = parseInt($('adm-if-s4').value) || 0;
  if ($('adm-if-s3').value && (s3 < 0 || s3 > 1216)) { showToast('S3 must be 0-1216', 'error'); return; }
  if ($('adm-if-s4').value && (s4 < 0 || s4 > 32)) { showToast('S4 must be 0-32', 'error'); return; }
  // Validate H1-H4 are non-overlapping (if all present and numeric)
  const h = [$('adm-if-h1').value, $('adm-if-h2').value, $('adm-if-h3').value, $('adm-if-h4').value];
  function parseRange(v) { const m = v.match(/^(\d+)(?:-(\d+))?$/); return m ? [parseInt(m[1]), parseInt(m[2]||m[1])] : null; }
  const ranges = h.map(parseRange).filter(Boolean);
  for (let i = 0; i < ranges.length; i++) {
    for (let j = i+1; j < ranges.length; j++) {
      if (ranges[i] && ranges[j] && !(ranges[i][1] < ranges[j][0] || ranges[j][1] < ranges[i][0])) {
        showToast('Magic headers H'+(i+1)+' and H'+(j+1)+' overlap. They must not overlap.', 'error'); return;
      }
    }
  }
  try {
    await POST('/api/admin/interface', {
      mtu: parseInt($('adm-if-mtu').value)||1420,
      port: parseInt($('adm-if-port').value)||51820,
      device: $('adm-if-device').value,
      ipv4Cidr: $('adm-if-ipv4').value,
      ipv6Cidr: $('adm-if-ipv6').value,
      firewallEnabled: $('adm-if-firewall').checked,
      jC: parseInt($('adm-if-jc').value)||7,
      jMin: parseInt($('adm-if-jmin').value)||10,
      jMax: parseInt($('adm-if-jmax').value)||1279,
      s1: parseInt($('adm-if-s1').value)||128,
      s2: parseInt($('adm-if-s2').value)||56,
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
      j1: $('adm-if-j1').value,
      j2: $('adm-if-j2').value,
      j3: $('adm-if-j3').value,
      itime: parseInt($('adm-if-itime').value)||0
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
  const steps = $$('#setup-steps .step');
  steps.forEach((s, i) => {
    s.classList.remove('active', 'done');
    if (i + 1 < SETUP_STEP) s.classList.add('done');
    if (i + 1 === SETUP_STEP) s.classList.add('active');
  });
}

async function loadSetup() {
  // Check what step we're on from the server
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
      port: parseInt($('setup-port').value)||51820
    });
    showToast('Setup complete!', 'success');
    setTimeout(() => navigate('/login'), 1500);
  } catch(e) { showToast(e.message, 'error'); }
}
