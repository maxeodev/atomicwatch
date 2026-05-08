'use strict';

const TZ = 'Europe/Paris';

// ── State ────────────────────────────────────────────────────────────────────
let allAttacks   = [];
let allFwDrops   = [];
let map, markersLayer;
let chartTimeline;
let sortKey    = 'attempts';
let sortDir    = -1;
let filterText = '';
let filterStatus = '';
let fwSortKey  = 'ts';
let fwSortDir  = -1;
let fwFilter   = '';

// ── Boot ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  startClock();
  try { initMap(); } catch(e) { console.error('Map init failed', e); }
  try { initCharts(); } catch(e) { console.error('Charts init failed', e); }
  bindToolbar();
  bindFwToolbar();
  fetchAll();
  setInterval(fetchAll, 30000);
  try { initCowrie(); } catch(e) { console.error('Cowrie init failed', e); }
});

// ── Clock ─────────────────────────────────────────────────────────────────────
function startClock() {
  const el = document.getElementById('clock');
  const tick = () => {
    el.textContent = new Date().toLocaleTimeString('fr-FR', { hour12: false, timeZone: TZ });
  };
  tick();
  setInterval(tick, 1000);
}

// ── Fetch ─────────────────────────────────────────────────────────────────────
async function fetchAll() {
  try {
    const [summary, countries, timeline, attacks, fwSummary, usernames, campaigns] = await Promise.all([
      fetch('/api/stats/summary').then(r => { if (!r.ok) throw r; return r.json(); }),
      fetch('/api/stats/countries').then(r => { if (!r.ok) throw r; return r.json(); }),
      fetch('/api/stats/timeline').then(r => { if (!r.ok) throw r; return r.json(); }),
      fetch('/api/attacks?size=500').then(r => { if (!r.ok) throw r; return r.json(); }),
      fetch('/api/firewall/summary').then(r => r.ok ? r.json() : {total_drops: 0, enabled: false}).catch(() => ({total_drops: 0, enabled: false})),
      fetch('/api/stats/usernames').then(r => r.ok ? r.json() : []).catch(() => []),
      fetch('/api/stats/campaigns').then(r => r.ok ? r.json() : []).catch(() => []),
    ]);

    document.getElementById('loading').style.display = 'none';
    updateMetrics(summary, fwSummary);
    updateMap(countries);
    updateCountryList(countries.slice(0, 15));
    updateTimeline(timeline);
    allAttacks = attacks.items || [];
    renderTable();
    updateFirewall(fwSummary);
    renderUsernames(usernames);
    renderCampaigns(campaigns);

    const now = new Date().toLocaleTimeString('fr-FR', { hour12: false, timeZone: TZ });
    document.getElementById('update-tag').textContent = 'LAST SYNC ' + now;
  } catch(e) {
    console.error('Fetch error:', e);
    document.getElementById('update-tag').textContent = 'SYNC ERROR';
  }
}

// ── Metrics ───────────────────────────────────────────────────────────────────
function updateMetrics(s, fw) {
  set('m-total',     s.total_ips);
  // sous-titre dynamique: SSH seul si FW pas activé, SSH+FW sinon
  if (s.fw_ips > 0) {
    set('m-total-sub', `${s.ssh_ips} SSH + ${s.fw_ips} FW`);
  }
  set('m-banned',    s.banned_count);
  set('m-active',    s.active_count);
  set('m-countries', s.countries_count);
  set('m-attempts',  (s.total_attempts || 0).toLocaleString('fr-FR'));
  set('m-top',       (s.top_country_flag || '') + ' ' + (s.top_country || '—'));
  if (fw) {
    set('m-fw-drops', fw.enabled ? (fw.total_drops || 0).toLocaleString('fr-FR') : '—');
    set('m-fw-sub', fw.enabled ? `${fw.unique_ports || 0} ports ciblés` : 'logging désactivé');
  }
}

function set(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

// ── Map ────────────────────────────────────────────────────────────────────────
function initMap() {
  map = L.map('map', {
    zoomControl: true,
    attributionControl: false,
    minZoom: 1,
    maxZoom: 8,
  }).setView([25, 10], 2);

  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    maxZoom: 8,
    attribution: '© CartoDB © OSM'
  }).addTo(map);

  markersLayer = L.layerGroup().addTo(map);

  L.control.attribution({ position: 'bottomright', prefix: '' })
    .addAttribution('© CartoDB')
    .addTo(map);
}

function updateMap(countries) {
  if (!map) return;
  markersLayer.clearLayers();

  const valid = countries.filter(c => c.latitude !== 0 || c.longitude !== 0);
  document.getElementById('map-count').textContent = valid.length + ' ORIGINS';

  if (!valid.length) return;

  const maxCount = Math.max(...valid.map(c => c.attack_count), 1);

  valid.forEach(c => {
    const ratio = c.attack_count / maxCount;
    const radius = 5 + Math.sqrt(ratio) * 32;
    const color = ratio > 0.6 ? '#ff2d55' : ratio > 0.3 ? '#ff9f0a' : ratio > 0.1 ? '#00d4ff' : '#30d158';

    const circle = L.circleMarker([c.latitude, c.longitude], {
      radius,
      fillColor: color,
      color: color,
      weight: 1,
      opacity: 0.9,
      fillOpacity: 0.25,
    });

    const topIps = (c.top_ips || []).map(ip =>
      `<div style="color:#00d4ff;letter-spacing:0.5px">${ip}</div>`
    ).join('');

    circle.bindPopup(`
      <div style="font-family:'Share Tech Mono',monospace;min-width:180px;line-height:1.7">
        <div style="font-weight:700;color:#e2e8f0;margin-bottom:6px">${c.flag} ${c.country_name}</div>
        <div style="color:#ff2d55">⚡ ${c.attack_count.toLocaleString()} ATTEMPTS</div>
        <div style="color:#5d7a9a">◈ ${c.ip_count} IP${c.ip_count > 1 ? 's' : ''} DETECTED</div>
        <div style="margin-top:6px;color:#5d7a9a;font-size:10px">TOP IPs:</div>
        ${topIps}
      </div>
    `, { maxWidth: 240 });

    markersLayer.addLayer(circle);
  });
}

// ── Country list ──────────────────────────────────────────────────────────────
function updateCountryList(countries) {
  const container = document.getElementById('country-list');
  if (!countries.length) {
    container.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-dim);font-size:11px;letter-spacing:2px">NO GEO DATA</div>';
    return;
  }

  const max = Math.max(...countries.map(c => c.attack_count), 1);

  container.innerHTML = countries.map((c, i) => `
    <div class="country-row">
      <span class="country-rank">${i + 1}</span>
      <span class="country-flag">${c.flag}</span>
      <span class="country-name">${c.country_name}</span>
      <div class="country-bar-wrap">
        <div class="country-bar" style="width:${Math.round(c.attack_count / max * 100)}%"></div>
      </div>
      <span class="country-count">${c.attack_count}</span>
    </div>
  `).join('');
}

// ── Timeline ──────────────────────────────────────────────────────────────────
function initCharts() {
  Chart.defaults.color = '#5d7a9a';
  Chart.defaults.borderColor = 'rgba(26,51,86,0.4)';

  chartTimeline = new Chart(document.getElementById('chart-timeline'), {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        data: [],
        borderColor: '#00d4ff',
        backgroundColor: 'rgba(0,212,255,0.05)',
        fill: true,
        tension: 0.4,
        pointRadius: 0,
        pointHoverRadius: 4,
        pointHoverBackgroundColor: '#00d4ff',
        borderWidth: 1.5,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 400 },
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0b1629',
          borderColor: '#1a3356',
          borderWidth: 1,
          titleFont: { family: "'Share Tech Mono', monospace", size: 11 },
          bodyFont: { family: "'Share Tech Mono', monospace", size: 11 },
          callbacks: {
            title: items => items[0].label,
            label: item => ` ${item.formattedValue} ATTEMPTS`,
          }
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(26,51,86,0.3)', drawBorder: false },
          ticks: { font: { family: "'Share Tech Mono', monospace", size: 10 }, maxTicksLimit: 12, color: '#5d7a9a' }
        },
        y: {
          grid: { color: 'rgba(26,51,86,0.3)', drawBorder: false },
          ticks: { font: { family: "'Share Tech Mono', monospace", size: 10 }, color: '#5d7a9a' },
          beginAtZero: true,
        }
      }
    }
  });
}

function updateTimeline(timeline) {
  if (!chartTimeline) return;
  chartTimeline.data.labels = timeline.map(t => t.timestamp.slice(5, 16).replace('T', ' '));
  chartTimeline.data.datasets[0].data = timeline.map(t => t.count);
  chartTimeline.update('none');
}

// ── Table ─────────────────────────────────────────────────────────────────────
function bindToolbar() {
  document.getElementById('filter-text').addEventListener('input', e => {
    filterText = e.target.value.toLowerCase();
    renderTable();
  });
  document.getElementById('filter-status').addEventListener('change', e => {
    filterStatus = e.target.value;
    renderTable();
  });
  document.querySelectorAll('thead th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      if (sortKey === key) sortDir *= -1;
      else { sortKey = key; sortDir = -1; }
      document.querySelectorAll('thead th').forEach(t => { t.classList.remove('sorted'); t.textContent = t.textContent.replace(/[ ↑↓]$/, ''); });
      th.classList.add('sorted');
      th.textContent += sortDir === -1 ? ' ↓' : ' ↑';
      renderTable();
    });
  });
}

function renderTable() {
  let data = allAttacks.filter(d => {
    if (filterStatus && d.status !== filterStatus) return false;
    if (filterText) {
      const hay = [d.ip, d.country_name, d.attack_type, d.org || '', ...(d.tried_users || [])].join(' ').toLowerCase();
      if (!hay.includes(filterText)) return false;
    }
    return true;
  });

  data.sort((a, b) => {
    let va = a[sortKey] ?? '', vb = b[sortKey] ?? '';
    if (typeof va === 'string') va = va.toLowerCase();
    if (typeof vb === 'string') vb = vb.toLowerCase();
    return va < vb ? -sortDir : va > vb ? sortDir : 0;
  });

  const total = data.length;
  document.getElementById('table-count').textContent = total + ' ENTRIES';
  document.getElementById('rec-count').textContent = total + ' RECORDS';

  const tbody = document.getElementById('attacks-tbody');

  if (!total) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:40px;color:var(--text-dim);letter-spacing:2px">NO MATCHING RECORDS</td></tr>';
    return;
  }

  tbody.innerHTML = data.map(d => {
    const statusBadge = d.status === 'banned'
      ? '<span class="badge banned">■ BANNED</span>'
      : '<span class="badge active">◈ ACTIVE</span>';
    const usersArr = d.tried_users || [];
    const usersHtml = usersArr.length
      ? usersArr.slice(0, 4).map(u => `<span class="user-chip">${escHtml(u)}</span>`).join('')
        + (usersArr.length > 4 ? `<span class="user-chip more">+${usersArr.length - 4}</span>` : '')
      : '<span style="color:var(--text-dim)">—</span>';
    const asn = d.org ? `AS${d.asn} ${d.org}` : '—';
    const country = d.country_code !== 'XX'
      ? `<span class="td-flag">${d.flag}</span>${d.country_name}`
      : '<span style="color:var(--text-dim)">UNKNOWN</span>';

    return `<tr>
      <td><span class="td-ip clickable" onclick="openIpDetail('${escAttr(d.ip)}')">${escHtml(d.ip)}</span></td>
      <td><span class="td-attempts">${d.attempts.toLocaleString('fr-FR')}</span></td>
      <td><span class="badge type">${escHtml(d.attack_type)}</span></td>
      <td><div class="td-users-wrap">${usersHtml}</div></td>
      <td>${statusBadge}${d.in_honeypot ? ' <span class="badge honeypot">HP</span>' : ''}</td>
      <td><div class="td-country">${country}</div></td>
      <td><span class="td-asn" title="${escAttr(asn)}">${escHtml(asn)}</span></td>
      <td><span class="td-ts">${fmtDate(d.last_seen)}</span></td>
    </tr>`;
  }).join('');
}

// ── Firewall section ──────────────────────────────────────────────────────────
async function updateFirewall(summary) {
  const notice  = document.getElementById('fw-setup-notice');
  const content = document.getElementById('fw-content');
  set('fw-drop-count', summary.enabled ? (summary.total_drops || 0).toLocaleString('fr-FR') + ' DROPS' : '—');

  if (!summary.enabled) {
    notice.style.display  = 'flex';
    content.style.display = 'none';
    return;
  }

  notice.style.display  = 'none';
  content.style.display = 'block';

  try {
    const [ports, recent] = await Promise.all([
      fetch('/api/firewall/ports').then(r => r.json()),
      fetch('/api/firewall/recent?limit=500').then(r => r.json()),
    ]);
    renderFwPorts(ports);
    allFwDrops = recent;
    renderFwFiltered();
  } catch(e) {
    console.error('Firewall fetch error:', e);
  }
}

function bindFwToolbar() {
  const input = document.getElementById('fw-filter-text');
  if (input) {
    input.addEventListener('input', e => { fwFilter = e.target.value.toLowerCase(); renderFwFiltered(); });
  }
  document.querySelectorAll('th[data-fwsort]').forEach(th => {
    th.addEventListener('click', () => {
      const key = th.dataset.fwsort;
      if (fwSortKey === key) fwSortDir *= -1;
      else { fwSortKey = key; fwSortDir = -1; }
      document.querySelectorAll('th[data-fwsort]').forEach(t => {
        t.classList.remove('sorted');
        t.textContent = t.textContent.replace(/[ ↑↓]$/, '');
      });
      th.classList.add('sorted');
      th.textContent += fwSortDir === -1 ? ' ↓' : ' ↑';
      renderFwFiltered();
    });
  });
}

function renderFwFiltered() {
  let data = allFwDrops.filter(e => {
    if (!fwFilter) return true;
    const hay = [
      e.ip,
      String(e.dpt ?? ''),
      e.service,
      e.proto,
      e.country_name || '',
      e.country_code || '',
    ].join(' ').toLowerCase();
    return hay.includes(fwFilter);
  });

  data.sort((a, b) => {
    let va = a[fwSortKey] ?? '';
    let vb = b[fwSortKey] ?? '';
    if (typeof va === 'string') va = va.toLowerCase();
    if (typeof vb === 'string') vb = vb.toLowerCase();
    return va < vb ? -fwSortDir : va > vb ? fwSortDir : 0;
  });

  set('fw-rec-count', data.length.toLocaleString('fr-FR') + ' DROPS');
  renderFwTable(data);
}

function renderFwPorts(ports) {
  const el = document.getElementById('fw-ports-list');
  if (!ports.length) { el.innerHTML = '<div style="color:var(--text-dim);font-size:11px;padding:8px 0">Aucun drop enregistré</div>'; return; }
  const max = Math.max(...ports.map(p => p.count), 1);
  el.innerHTML = ports.map(p => `
    <div class="fw-port-item">
      <span class="fw-port-name">${escHtml(p.service)} <span style="color:var(--text-dim);font-size:10px">${p.proto}:${p.port ?? '?'}</span></span>
      <div class="fw-port-bar-wrap"><div class="fw-port-bar" style="width:${Math.round(p.count/max*100)}%"></div></div>
      <span class="fw-port-count">${p.count.toLocaleString('fr-FR')}</span>
    </div>
  `).join('');
}

function renderFwTable(events) {
  const tbody = document.getElementById('fw-tbody');
  if (!events.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:30px;color:var(--text-dim);letter-spacing:2px">AUCUN DROP</td></tr>';
    return;
  }
  tbody.innerHTML = events.map(e => {
    const country = e.country_code !== 'XX'
      ? `<span style="margin-right:6px">${e.flag}</span>${escHtml(e.country_name)}`
      : '<span style="color:var(--text-dim)">UNKNOWN</span>';
    return `<tr>
      <td><span class="td-ip">${escHtml(e.ip)}</span></td>
      <td><span style="color:var(--orange);font-family:var(--title);font-weight:700">${e.dpt ?? '—'}</span></td>
      <td><span class="badge type" style="color:var(--orange);border-color:rgba(255,159,10,0.2);background:rgba(255,159,10,0.08)">${escHtml(e.service)}</span></td>
      <td style="color:var(--text-dim);font-size:11px">${escHtml(e.proto)}</td>
      <td><div class="td-country">${country}</div></td>
      <td><span class="td-ts">${fmtDate(e.ts)}</span></td>
    </tr>`;
  }).join('');
}

// ── Modal IP Detail ───────────────────────────────────────────────────────────
let _modalCurrentIp = null;
let _traceMap = null;
let _traceMarkersLayer = null;
let _traceLoadedIp = null;
let _intelLoadedIp = null;

function openIpDetail(ip) {
  _modalCurrentIp = ip;
  document.getElementById('modal-ip').textContent = ip;
  document.getElementById('modal-body').innerHTML = '<div class="modal-loading">FETCHING DATA...</div>';
  document.getElementById('modal-body').style.display = 'block';
  document.getElementById('modal-trace-body').style.display = 'none';
  document.getElementById('modal-intel-body').style.display = 'none';
  document.getElementById('tab-events').classList.add('active');
  document.getElementById('tab-trace').classList.remove('active');
  document.getElementById('tab-intel').classList.remove('active');
  _intelLoadedIp = null;
  document.getElementById('ip-modal').style.display = 'flex';

  fetch(`/api/attacks/${encodeURIComponent(ip)}/events`)
    .then(r => { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(data => {
      const events = data.events || [];
      const attTypeBadge = `<span class="badge type">${escHtml(data.attack_type)}</span>`;
      const statusBadge  = data.status === 'banned'
        ? '<span class="badge banned">■ BANNED</span>'
        : '<span class="badge active">◈ ACTIVE</span>';

      const dateRange = (data.first_seen || data.last_seen)
        ? `<span style="font-size:10px;color:var(--text-dim)">${fmtDate(data.first_seen)} → ${fmtDate(data.last_seen)}</span>`
        : '';
      const meta = `
        <div class="modal-meta">
          <span style="color:var(--cyan)">${(data.attempts || 0).toLocaleString('fr-FR')} ATTEMPTS</span>
          ${attTypeBadge}
          ${statusBadge}
          ${dateRange}
          <span style="margin-left:auto;font-size:10px">${events.length} EVENT${events.length !== 1 ? 'S' : ''} (100 MAX)</span>
        </div>`;

      if (!events.length) {
        document.getElementById('modal-body').innerHTML = meta + '<div class="modal-empty">AUCUN ÉVÉNEMENT ENREGISTRÉ<br><span style="font-size:10px;opacity:.6">Les événements sont collectés par le timer systemd toutes les 2 min</span></div>';
        return;
      }

      const rows = events.map(e => `
        <div class="event-row">
          <span class="event-ts">${fmtDateFull(e.ts)}</span>
          <span class="event-user">${e.user ? '[' + escHtml(e.user) + ']' : ''}</span>
          <span class="event-msg">${escHtml(e.msg)}</span>
        </div>
      `).join('');

      document.getElementById('modal-body').innerHTML = meta + `<div class="event-list">${rows}</div>`;
    })
    .catch(() => {
      document.getElementById('modal-body').innerHTML = '<div class="modal-empty">ERREUR LORS DE LA RÉCUPÉRATION</div>';
    });
}

function switchModalTab(tab) {
  const evBody    = document.getElementById('modal-body');
  const trBody    = document.getElementById('modal-trace-body');
  const inBody    = document.getElementById('modal-intel-body');
  const tabEvents = document.getElementById('tab-events');
  const tabTrace  = document.getElementById('tab-trace');
  const tabIntel  = document.getElementById('tab-intel');

  evBody.style.display = 'none';
  trBody.style.display = 'none';
  inBody.style.display = 'none';
  tabEvents.classList.remove('active');
  tabTrace.classList.remove('active');
  tabIntel.classList.remove('active');

  if (tab === 'events') {
    evBody.style.display = 'block';
    tabEvents.classList.add('active');
  } else if (tab === 'trace') {
    trBody.style.display = 'block';
    tabTrace.classList.add('active');
    loadTraceroute(_modalCurrentIp);
  } else {
    inBody.style.display = 'block';
    tabIntel.classList.add('active');
    loadIntel(_modalCurrentIp);
  }
}

function loadTraceroute(ip) {
  if (!ip) return;
  if (_traceLoadedIp === ip) {
    if (_traceMap) setTimeout(() => _traceMap.invalidateSize(), 50);
    return;
  }
  document.getElementById('modal-hops').innerHTML = '';
  document.getElementById('modal-map').innerHTML = '';
  if (_traceMap) { _traceMap.remove(); _traceMap = null; _traceMarkersLayer = null; }

  document.getElementById('modal-hops').innerHTML =
    '<div class="modal-loading">RUNNING TRACEROUTE<span class="trace-dots">...</span></div>';

  fetch(`/api/attacks/${encodeURIComponent(ip)}/traceroute`)
    .then(r => { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(data => {
      _traceLoadedIp = ip;
      renderTraceroute(data);
    })
    .catch(err => {
      document.getElementById('modal-hops').innerHTML =
        `<div class="modal-empty">TRACEROUTE UNAVAILABLE<br><span style="font-size:10px;opacity:.6">${err.message}</span></div>`;
    });
}

function _createHopIcon(label, color) {
  const size = String(label).length > 2 ? 28 : 22;
  return L.divIcon({
    className: '',
    html: `<div style="background:${color};color:#fff;width:${size}px;height:${size}px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-family:'Share Tech Mono',monospace;font-size:9px;font-weight:700;border:2px solid rgba(255,255,255,0.5);box-shadow:0 0 8px ${color}88">${label}</div>`,
    iconSize: [size, size],
    iconAnchor: [size / 2, size / 2],
  });
}

function renderTraceroute(data) {
  const hops = data.hops || [];
  const maxlabGeo = data.maxlab_geo;

  // Init Leaflet map
  _traceMap = L.map('modal-map', {
    zoomControl: true,
    attributionControl: false,
    minZoom: 1,
    maxZoom: 12,
  }).setView([30, 0], 2);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    maxZoom: 12,
  }).addTo(_traceMap);
  _traceMarkersLayer = L.layerGroup().addTo(_traceMap);

  setTimeout(() => _traceMap.invalidateSize(), 50);

  const polyPoints = [];

  // Maxlab origin marker
  if (maxlabGeo && (maxlabGeo.latitude !== 0 || maxlabGeo.longitude !== 0)) {
    const m = L.marker([maxlabGeo.latitude, maxlabGeo.longitude], { icon: _createHopIcon('ME', '#30d158') });
    m.bindPopup(`<div style="font-family:'Share Tech Mono',monospace;line-height:1.6">MAXLAB<br>51.83.100.146<br>${escHtml(maxlabGeo.country_name || '')}</div>`);
    _traceMarkersLayer.addLayer(m);
    polyPoints.push([maxlabGeo.latitude, maxlabGeo.longitude]);
  }

  // Hop markers
  hops.forEach((hop, idx) => {
    const isLast = idx === hops.length - 1 && hop.ip !== '*';
    const color = isLast ? '#ff2d55' : '#ff9f0a';
    if (hop.geo) {
      const m = L.marker([hop.geo.latitude, hop.geo.longitude], { icon: _createHopIcon(hop.hop, color) });
      const rttStr = hop.rtt_ms !== null ? `${hop.rtt_ms.toFixed(1)} ms` : '—';
      m.bindPopup(`<div style="font-family:'Share Tech Mono',monospace;line-height:1.6">HOP ${hop.hop}<br>${escHtml(hop.ip)}<br>${rttStr}<br>${escHtml(hop.geo.flag || '')} ${escHtml(hop.geo.country_name || '')}<br><span style="font-size:10px;color:#999">${escHtml(hop.geo.org || '')}</span></div>`);
      _traceMarkersLayer.addLayer(m);
      polyPoints.push([hop.geo.latitude, hop.geo.longitude]);
    }
  });

  // Polyline
  if (polyPoints.length >= 2) {
    L.polyline(polyPoints, { color: '#00d4ff', weight: 2, opacity: 0.7, dashArray: '5, 7' })
      .addTo(_traceMarkersLayer);
    _traceMap.fitBounds(polyPoints, { padding: [30, 30], maxZoom: 8 });
  } else if (polyPoints.length === 1) {
    _traceMap.setView(polyPoints[0], 5);
  }

  // Hop table
  if (!hops.length) {
    document.getElementById('modal-hops').innerHTML =
      '<div class="modal-empty">AUCUN HOP RETOURNÉ</div>';
    return;
  }

  const geoCount = hops.filter(h => h.geo).length;
  const noMapMsg = polyPoints.length < 2
    ? `<div class="trace-nomatch">⚠ MOINS DE 2 POINTS GÉOLOCALISÉS — CARTE NON DISPONIBLE</div>` : '';

  const rows = hops.map(hop => {
    const isLast = hops.indexOf(hop) === hops.length - 1 && hop.ip !== '*';
    const ipStyle = isLast ? 'color:var(--red)' : hop.private ? 'color:var(--text-dim)' : 'color:var(--cyan)';
    const rtt = hop.rtt_ms !== null ? `${hop.rtt_ms.toFixed(1)} ms` : '<span class="hop-star">—</span>';
    let country = '—', org = '—';
    if (hop.ip === '*') {
      country = '<span class="hop-star">*</span>';
    } else if (hop.private) {
      country = '<span class="hop-private">PRIVATE</span>';
    } else if (hop.geo) {
      country = `${escHtml(hop.geo.flag || '')} ${escHtml(hop.geo.country_name || '—')}`;
      org = `<span style="font-size:10px;color:var(--text-dim)">${escHtml(hop.geo.org || '—')}</span>`;
    }
    return `<tr>
      <td class="hop-num">${hop.hop}</td>
      <td><span style="${ipStyle};font-family:var(--mono)">${escHtml(hop.ip)}</span>${isLast ? ' <span class="badge type" style="font-size:9px;padding:1px 5px">TARGET</span>' : ''}</td>
      <td>${rtt}</td>
      <td>${country}</td>
      <td>${org}</td>
    </tr>`;
  }).join('');

  document.getElementById('modal-hops').innerHTML = noMapMsg + `
    <table class="hop-table">
      <thead><tr>
        <th>HOP</th><th>IP</th><th>RTT</th><th>PAYS</th><th>ORG</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function closeModal() {
  document.getElementById('ip-modal').style.display = 'none';
}

document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

// ── Intel tab ─────────────────────────────────────────────────────────────────
function loadIntel(ip) {
  if (!ip) return;
  if (_intelLoadedIp === ip) return;
  const body = document.getElementById('modal-intel-body');
  body.innerHTML = '<div class="modal-loading">FETCHING INTEL...</div>';

  fetch(`/api/attacks/${encodeURIComponent(ip)}/intel`)
    .then(r => { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(data => {
      _intelLoadedIp = ip;
      renderIntel(data);
    })
    .catch(err => {
      body.innerHTML = `<div class="modal-empty">INTEL UNAVAILABLE<br><span style="font-size:10px;opacity:.6">${err.message}</span></div>`;
    });
}

function renderIntel(data) {
  const body = document.getElementById('modal-intel-body');

  const rdns = data.rdns
    ? `<div class="intel-rdns">${escHtml(data.rdns)}</div>`
    : `<div style="color:var(--text-dim);font-size:11px">AUCUN ENREGISTREMENT PTR</div>`;

  let rdapHtml = '<div style="color:var(--text-dim);font-size:11px">DONNÉES INDISPONIBLES</div>';
  if (data.rdap && Object.keys(data.rdap).length) {
    const r = data.rdap;
    const rows = [
      ['Bloc',   r.cidr   ? `${escHtml(r.range || '')} (${escHtml(r.name || '')})` : '—'],
      ['CIDR',   r.cidr   ? escHtml(r.cidr) : '—'],
      ['Org',    r.org    ? escHtml(r.org) : '—'],
      ['Pays',   r.country ? escHtml(r.country) : '—'],
      ['Abuse',  r.abuse_email ? `<span class="intel-abuse-email">${escHtml(r.abuse_email)}</span>` : '—'],
      ['Enreg.', r.registered ? escHtml(r.registered) : '—'],
    ];
    rdapHtml = rows.map(([l, v]) =>
      `<div class="intel-row"><span class="intel-label">${l}</span><span class="intel-value">${v}</span></div>`
    ).join('');
  }

  let honeypotHtml;
  const h = data.honeypot;
  if (h && h.seen) {
    const cmds = (h.commands || []).length
      ? (h.commands || []).slice(0, 5).map(c => `<div class="intel-cmd">$ ${escHtml(c)}</div>`).join('')
      : '';
    honeypotHtml = `
      <div class="intel-honeypot-warn">⚠ DÉTECTÉE DANS LE HONEYPOT</div>
      <div class="intel-row"><span class="intel-label">Sessions</span><span class="intel-value">${h.sessions}</span></div>
      <div class="intel-row"><span class="intel-label">Auth OK</span><span class="intel-value" style="color:var(--red)">${h.auth_ok}</span></div>
      <div class="intel-row"><span class="intel-label">Vu le</span><span class="intel-value">${fmtDate(h.first_seen)} → ${fmtDate(h.last_seen)}</span></div>
      ${cmds}`;
  } else {
    honeypotHtml = `<div style="color:var(--text-dim);font-size:11px">NON VUE DANS LE HONEYPOT</div>`;
  }

  body.innerHTML = `
    <div class="intel-section">── REVERSE DNS ──</div>
    <div style="padding:8px 16px 12px">${rdns}</div>
    <div class="intel-section">── RÉSEAU (RDAP) ──</div>
    <div style="padding:8px 16px 12px">${rdapHtml}</div>
    <div class="intel-section">── HONEYPOT ──</div>
    <div style="padding:8px 16px 12px">${honeypotHtml}</div>
  `;
}

// ── Usernames panel ───────────────────────────────────────────────────────────
function renderUsernames(data) {
  const body = document.getElementById('usernames-body');
  const count = document.getElementById('usernames-count');
  if (!body) return;
  if (!data || !data.length) {
    body.innerHTML = '<div style="padding:16px;color:var(--text-dim);font-size:11px;text-align:center;grid-column:1/-1">AUCUNE DONNÉE</div>';
    if (count) count.textContent = '0 ENTRIES';
    return;
  }
  if (count) count.textContent = data.length + ' ENTRIES';

  const max = data[0].count;
  const half = Math.ceil(data.length / 2);

  const renderItem = (d, rank) => {
    const filled = Math.round((d.count / max) * 14);
    const bar = `<span class="usr-bar-fill">${'█'.repeat(filled)}</span>${'▒'.repeat(14 - filled)}`;
    return `<div class="usr-row">
      <span class="usr-rank">#${String(rank + 1).padStart(2, '0')}</span>
      <span class="usr-name" title="${escAttr(d.username)}">${escHtml(d.username)}</span>
      <span class="usr-bar">${bar}</span>
      <span class="usr-count">${d.count}</span>
    </div>`;
  };

  body.innerHTML =
    `<div>${data.slice(0, half).map((d, i) => renderItem(d, i)).join('')}</div>` +
    `<div>${data.slice(half).map((d, i) => renderItem(d, i + half)).join('')}</div>`;
}

// ── Campaigns panel ───────────────────────────────────────────────────────────
function renderCampaigns(data) {
  const body = document.getElementById('campaigns-body');
  const count = document.getElementById('campaigns-count');
  if (!body) return;
  if (!data || !data.length) {
    body.innerHTML = '<div style="padding:16px;color:var(--text-dim);font-size:11px;text-align:center">AUCUNE CAMPAGNE DÉTECTÉE (< 2 IPs par /24)</div>';
    if (count) count.textContent = '0 SUBNETS';
    return;
  }
  if (count) count.textContent = data.length + ' SUBNETS';

  const rows = data.map(c => {
    const preview = (c.preview_ips || []).map(ip => `<span class="td-ip">${escHtml(ip)}</span>`).join(' ');
    return `<tr>
      <td><span style="color:var(--cyan);font-family:var(--mono)">${escHtml(c.subnet)}</span></td>
      <td style="color:var(--red);text-align:center">${c.ip_count}</td>
      <td style="text-align:right">${(c.total_attempts || 0).toLocaleString('fr-FR')}</td>
      <td><span class="td-flag">${escHtml(c.flag || '')}</span>${escHtml(c.country_name || '—')}</td>
      <td><span style="font-size:10px;color:var(--text-dim)">${escHtml(c.org || '—')}</span></td>
      <td style="font-size:10px">${preview}</td>
    </tr>`;
  }).join('');

  body.innerHTML = `
    <div class="table-wrap" style="max-height:300px">
      <table class="campaign-table">
        <thead><tr>
          <th>SUBNET /24</th><th>IPs</th><th>ATTEMPTS</th><th>PAYS</th><th>ORG</th><th>PREVIEW IPs</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

// ── Honeypot session list + terminal ──────────────────────────────────────────
const MAX_TERMINAL_LINES = 300;
let cowrieEs = null;
let selectedSession = null;
let cowrieSessionsData = [];
let _sessionRefreshTimer = null;

function initCowrie() {
  fetchCowrieSessions();
  setInterval(fetchCowrieSessions, 15_000);

  if (cowrieEs) cowrieEs.close();
  cowrieEs = new EventSource('/api/cowrie/stream');

  cowrieEs.onopen = () => {
    const el = document.getElementById('cowrie-status');
    if (el) { el.textContent = '● LIVE'; el.classList.add('live'); }
  };
  cowrieEs.onerror = () => {
    const el = document.getElementById('cowrie-status');
    if (el) { el.textContent = '○ RECONNECTING'; el.classList.remove('live'); }
  };

  cowrieEs.onmessage = e => {
    try {
      const ev = JSON.parse(e.data);
      if (ev.type === 'connected') return;
      // Debounce session list refresh (max 1 fois / 3s)
      clearTimeout(_sessionRefreshTimer);
      _sessionRefreshTimer = setTimeout(fetchCowrieSessions, 3000);
      // Append dans le terminal si la session est sélectionnée
      const sid = (ev.session || '').slice(0, 8);
      if (sid === selectedSession) {
        appendCowrieLine(formatCowrieEvent(ev));
        scrollTerminal();
      }
    } catch {}
  };
}

async function fetchCowrieSessions() {
  try {
    const [sessions, summary] = await Promise.all([
      fetch('/api/cowrie/sessions').then(r => r.json()),
      fetch('/api/cowrie/summary').then(r => r.json()),
    ]);
    cowrieSessionsData = sessions;
    renderSessionList();
    updateCowrieStats(summary);
  } catch {}
}

function renderSessionList() {
  const el = document.getElementById('cowrie-session-list');
  if (!el) return;

  if (!cowrieSessionsData.length) {
    el.innerHTML = '<div class="cowrie-no-session">AWAITING CONNECTIONS...</div>';
    return;
  }

  el.innerHTML = cowrieSessionsData.map(s => {
    const sel = s.session_id === selectedSession ? ' sel' : '';

    let iconClass, icon;
    if (s.login_ok)            { iconClass = 'ok';     icon = '▲'; }
    else if (s.status === 'closed') { iconClass = 'closed'; icon = '◉'; }
    else if (s.command_count > 0)   { iconClass = 'active'; icon = '●'; }
    else                            { iconClass = 'fail';   icon = '✗'; }

    const ts = s.start_time
      ? new Date(s.start_time).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: TZ })
      : '—';
    const cmdBadge = s.command_count  > 0 ? `<span class="cqr-badge cmd">${s.command_count} CMD</span>` : '';
    const dlBadge  = s.download_count > 0 ? `<span class="cqr-badge dl">${s.download_count} DL</span>`  : '';
    const cmdPrev  = s.commands_preview && s.commands_preview.length
      ? `<div class="cqr-cmd">$ ${escHtml(s.commands_preview[0])}</div>` : '';

    return `<div class="cowrie-qrow${sel}" onclick="selectCowrieSession('${escAttr(s.session_id)}')">
      <div class="cqr-icon ${iconClass}">${icon}</div>
      <div class="cqr-body">
        <div class="cqr-main">
          <span class="cqr-ip">${escHtml(s.src_ip || '?')}</span>
          <span class="cqr-time">${ts}</span>
          ${cmdBadge}${dlBadge}
        </div>
        ${cmdPrev}
      </div>
    </div>`;
  }).join('');
}

async function selectCowrieSession(sessionId) {
  selectedSession = sessionId;
  renderSessionList();

  const s = cowrieSessionsData.find(x => x.session_id === sessionId);
  const hdr = document.getElementById('cowrie-session-hdr');
  if (hdr && s) {
    const okPart   = s.login_ok ? '<span class="csh-ok">▲ AUTH OK</span>' : '<span class="csh-fail">✗ AUTH FAIL</span>';
    const cmdPart  = s.command_count  > 0 ? `<span class="csh-sep">·</span><span class="csh-cmds">${s.command_count} CMD</span>`   : '';
    const dlPart   = s.download_count > 0 ? `<span class="csh-sep">·</span><span class="csh-dl">${s.download_count} DL</span>`     : '';
    const timePart = s.start_time ? `<span class="csh-time">${fmtDateFull(s.start_time)}</span>` : '';
    hdr.innerHTML = `
      <span class="csh-sid">${escHtml(sessionId.slice(0, 8))}</span>
      <span class="csh-sep">·</span>
      <span class="csh-ip">${escHtml(s.src_ip || '?')}</span>
      <span class="csh-sep">·</span>
      ${okPart}${cmdPart}${dlPart}${timePart}
    `;
  }

  const term = document.getElementById('cowrie-terminal');
  term.innerHTML = '<div class="cowrie-boot">LOADING SESSION...</div>';

  try {
    const r = await fetch(`/api/cowrie/sessions/${encodeURIComponent(sessionId)}`);
    if (!r.ok) throw new Error(r.status);
    const events = await r.json();
    term.innerHTML = '';
    if (!events.length) {
      term.innerHTML = '<div class="cowrie-boot">CONNEXION SANS ÉVÉNEMENT DÉTAILLÉ</div>';
      return;
    }
    events.forEach(appendCowrieLine);
    scrollTerminal();
  } catch(err) {
    term.innerHTML = `<div class="cowrie-boot">SESSION INTROUVABLE (${err.message})</div>`;
  }
}

function formatCowrieEvent(e) {
  const LABELS = {
    'cowrie.session.connect':       { label: 'CONNECT',  kind: 'connect'  },
    'cowrie.login.failed':          { label: 'AUTH FAIL', kind: 'fail'    },
    'cowrie.login.success':         { label: '██ PIÉGÉ', kind: 'success'  },
    'cowrie.command.input':         { label: 'CMD',       kind: 'cmd'     },
    'cowrie.session.file_download': { label: 'DOWNLOAD',  kind: 'danger'  },
    'cowrie.session.closed':        { label: 'CLOSED',    kind: 'info'    },
  };
  const { label, kind } = LABELS[e.eventid] || { label: e.eventid?.split('.').pop() || '?', kind: 'info' };
  return { ts: e.timestamp, src_ip: e.src_ip, label, kind,
    username: e.username, password: e.password, input: e.input, url: e.url };
}

function appendCowrieLine(e) {
  const term = document.getElementById('cowrie-terminal');
  const kind = e.kind ?? 'info';

  const ICONS = { connect: '→', fail: '✗', success: '✓', cmd: '$', danger: '↓', info: '·', closed: '✕' };
  const icon = ICONS[kind] || '·';

  let msg = '';
  if (kind === 'success' && e.username) {
    msg = `<span class="ct-piege">▲ COMPROMIS</span> <span class="ct-cred ok">${escHtml(e.username)}</span><span class="ct-sep">/</span><span class="ct-cred ok">${escHtml(e.password || '?')}</span>`;
  } else if (e.username && e.password) {
    msg = `<span class="ct-cred">${escHtml(e.username)}</span><span class="ct-sep">/</span><span class="ct-cred">${escHtml(e.password)}</span>`;
  } else if (e.input) {
    msg = `<span class="ct-cmd">$ ${escHtml(e.input)}</span>`;
  } else if (e.url) {
    msg = `<span class="ct-url">↓ ${escHtml(e.url)}</span>`;
  } else if (e.version) {
    msg = `<span style="color:var(--text-dim)">${escHtml(e.version)}</span>`;
  } else if (e.label) {
    msg = `<span style="color:var(--text-dim);font-size:10px">${escHtml(e.label)}</span>`;
  }

  let ts = '—';
  if (e.ts) {
    try { ts = new Date(e.ts).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: TZ }); } catch {}
  }

  const line = document.createElement('div');
  line.className = `ct-line ${kind}`;
  line.innerHTML = `<span class="ct-ts">${ts}</span><span class="ct-icon ${kind}">${icon}</span><span class="ct-msg">${msg}</span>`;
  term.appendChild(line);

  while (term.children.length > MAX_TERMINAL_LINES) term.removeChild(term.firstChild);
}

function scrollTerminal() {
  const term = document.getElementById('cowrie-terminal');
  term.scrollTop = term.scrollHeight;
}

function updateCowrieStats(s) {
  if (!s || !s.enabled) return;
  set('cs-sessions', s.sessions   ?? '—');
  set('cs-ips',      s.unique_ips ?? '—');
  set('cs-piege',    s.logins_ok  ?? '—');
  set('cs-cmds',     s.commands   ?? '—');
  set('cs-dl',       s.downloads  ?? '—');
}

// ── Formatage dates ───────────────────────────────────────────────────────────
function fmtDate(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', timeZone: TZ })
      + ' ' + d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', timeZone: TZ });
  } catch { return iso.slice(0, 16); }
}

function fmtDateFull(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('fr-FR', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      timeZone: TZ,
    });
  } catch { return iso; }
}

// ── Utilitaires ───────────────────────────────────────────────────────────────
function escHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escAttr(str) {
  return escHtml(str);
}
