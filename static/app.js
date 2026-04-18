/* =====================================================
   ObserveX — workspace app.js
   ===================================================== */

const state = { bootstrap: null, records: [], charts: {} };
const $ = (id) => document.getElementById(id);

// ===== UTILS =====
function formatNumber(v) { return new Intl.NumberFormat().format(v || 0); }

function escapeHtml(v) {
  return String(v ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function badge(level) {
  return `<span class="level-badge level-${escapeHtml(level)}">${escapeHtml(level)}</span>`;
}

function toast(msg, isError = false) {
  const el = document.createElement('div');
  el.className = `floating-toast${isError ? ' error' : ''}`;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

// ===== NAV =====
function setActiveNav(sectionId) {
  document.querySelectorAll('.nav-link').forEach(b =>
    b.classList.toggle('active', b.dataset.section === sectionId));
  document.querySelectorAll('.content-section').forEach(s =>
    s.classList.toggle('active', s.id === sectionId));
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ===== THEME =====
function applyOrgTheme() {
  const org  = state.bootstrap?.organization;
  const user = state.bootstrap?.user;
  if (!org) return;

  document.documentElement.style.setProperty('--primary', org.theme_color || '#4f7cff');
  document.body.className = `theme-${org.theme_mode || 'white'}`;

  $('orgName').textContent  = org.name;
  $('orgLogo').textContent  = org.logo_text;
  $('orgSlug').textContent  = org.slug;
  $('currentUserName').textContent = user.name;
  $('currentUserRole').textContent = user.role;
  $('userOrgName').value    = org.name;

  const f = $('orgForm');
  if (f) {
    f.name.value       = org.name;
    f.slug.value       = org.slug;
    f.logo_text.value  = org.logo_text;
    f.theme_color.value = org.theme_color;
    f.theme_mode.value  = org.theme_mode || 'white';
    f.admin_only.checked = !!org.admin_only;
  }

  const isAdmin = user.role === 'admin';
  ['createUserBtn','saveOrgBtn','saveS3Btn','testS3Btn','saveApiBtn','testApiBtn','createJobBtn','createAlertBtn'].forEach(id => {
    const el = $(id); if (el) el.disabled = false;
  });
  if (!isAdmin) {
    ['createUserBtn','saveOrgBtn','saveS3Btn','saveApiBtn','createJobBtn','createAlertBtn'].forEach(id => {
      const el = $(id); if (el) el.disabled = true;
    });
    $('userResult').textContent = 'Only admins can create new accounts inside this organization.';
  }
}

// ===== CHART COLOURS =====
const LEVEL_COLORS = {
  error:   'rgba(248,113,113,0.85)',
  warn:    'rgba(251,191,36,0.85)',
  info:    'rgba(79,124,255,0.85)',
  success: 'rgba(52,211,153,0.85)',
  debug:   'rgba(148,163,184,0.75)',
};
const CHART_OPTS = {
  responsive: true,
  maintainAspectRatio: false,
  animation: { duration: 400 },
  plugins: { legend: { display: false } },
  scales: {
    x: { grid: { color: 'rgba(128,128,128,0.1)' }, ticks: { color: '#8da1c8', font: { size: 11 } } },
    y: { grid: { color: 'rgba(128,128,128,0.1)' }, ticks: { color: '#8da1c8', precision: 0, font: { size: 11 } } },
  },
};

function destroyChart(key) {
  if (state.charts[key]) { state.charts[key].destroy(); delete state.charts[key]; }
}

// ===== RENDER SUMMARY =====
function renderSummary() {
  const s = state.bootstrap?.summary || { totals: {}, levels: {}, source_breakdown: [], error_rate: 0 };
  $('metricLogs').textContent         = formatNumber(s.totals.logs || 0);
  $('metricUsers').textContent        = formatNumber(s.totals.users || 0);
  $('metricIntegrations').textContent = formatNumber(s.totals.integrations || 0);
  $('heroErrorRate').textContent      = `${s.error_rate || 0}%`;

  // Platform signals list
  const sl = $('sourceList');
  if (sl) {
    if (!s.source_breakdown?.length) {
      sl.innerHTML = '<div class="chart-empty" style="height:100px"><span class="chart-empty-icon">📡</span><span>Upload logs to see signals</span></div>';
    } else {
      sl.innerHTML = s.source_breakdown.map(item => `
        <div class="signal-card" style="display:flex;justify-content:space-between;align-items:center">
          <span style="font-size:13px;font-weight:600;color:var(--text)">${escapeHtml(item.source)}</span>
          <strong style="font-size:13px;color:var(--primary)">${formatNumber(item.count)}</strong>
        </div>
      `).join('');
    }
  }

  renderCharts(s);
}

// ===== CHARTS =====
function renderCharts(summary) {
  const levelData  = summary.levels || {};
  const sourceData = summary.source_breakdown || [];
  const hasLevels  = Object.values(levelData).some(v => v > 0);
  const hasSources = sourceData.length > 0;

  // Level bar chart
  const levelWrap  = document.querySelector('#overviewSection .chart-wrap');
  const levelEmpty = $('levelChartEmpty');
  destroyChart('levelChart');
  if (!hasLevels) {
    if (levelWrap)  levelWrap.style.display  = 'none';
    if (levelEmpty) levelEmpty.style.display = 'flex';
  } else {
    if (levelWrap)  levelWrap.style.display  = '';
    if (levelEmpty) levelEmpty.style.display = 'none';
    const keys   = Object.keys(levelData);
    const colors = keys.map(l => LEVEL_COLORS[l] || 'rgba(99,102,241,.8)');
    state.charts.levelChart = new Chart($('levelChart'), {
      type: 'bar',
      data: {
        labels: keys,
        datasets: [{ label: 'Logs', data: Object.values(levelData), backgroundColor: colors, borderRadius: 8, borderSkipped: false }],
      },
      options: { ...CHART_OPTS },
    });
  }

  // Source doughnut
  const sourceWrap  = document.querySelectorAll('#overviewSection .chart-wrap')[1];
  const sourceEmpty = $('sourceChartEmpty');
  destroyChart('sourceChart');
  if (!hasSources) {
    if (sourceWrap)  sourceWrap.style.display  = 'none';
    if (sourceEmpty) sourceEmpty.style.display = 'flex';
  } else {
    if (sourceWrap)  sourceWrap.style.display  = '';
    if (sourceEmpty) sourceEmpty.style.display = 'none';
    const dColors = sourceData.map((_, i) => `hsl(${(i * 47 + 210) % 360},65%,62%)`);
    state.charts.sourceChart = new Chart($('sourceChart'), {
      type: 'doughnut',
      data: {
        labels: sourceData.map(x => x.source),
        datasets: [{ data: sourceData.map(x => x.count), backgroundColor: dColors, borderWidth: 0, hoverOffset: 6 }],
      },
      options: {
        responsive: true, maintainAspectRatio: false, animation: { duration: 400 },
        plugins: { legend: { position: 'right', labels: { color: '#8da1c8', boxWidth: 12, padding: 10, font: { size: 11 } } } },
      },
    });
  }

  // Timeseries
  renderTimeseriesChart(summary.time_series || {});
}

function renderTimeseriesChart(buckets) {
  const tsWrap  = document.querySelector('.ts-chart-wrap');
  const tsEmpty = $('tsEmpty');
  destroyChart('timeseriesChart');

  const hours = Object.keys(buckets).sort();
  if (!hours.length) {
    if (tsWrap)  tsWrap.style.display  = 'none';
    if (tsEmpty) tsEmpty.style.display = 'flex';
    return;
  }
  if (tsWrap)  tsWrap.style.display  = '';
  if (tsEmpty) tsEmpty.style.display = 'none';

  const levels   = ['error','warn','info','success','debug'];
  const datasets = levels.map(level => ({
    label: level,
    data: hours.map(h => (buckets[h] || {})[level] || 0),
    backgroundColor: LEVEL_COLORS[level] || 'rgba(99,102,241,.6)',
    borderColor: 'transparent',
    borderRadius: 3,
    stack: 'logs',
  }));

  state.charts.timeseriesChart = new Chart($('timeseriesChart'), {
    type: 'bar',
    data: {
      labels: hours.map(h => h.replace('T',' ').replace(':00:00Z','')),
      datasets,
    },
    options: {
      responsive: true, maintainAspectRatio: false, animation: { duration: 300 },
      plugins: { legend: { position: 'bottom', labels: { color: '#8da1c8', boxWidth: 11, padding: 10, font: { size: 11 } } } },
      scales: {
        x: { stacked: true, grid: { color: 'rgba(128,128,128,0.08)' }, ticks: { color: '#8da1c8', maxTicksLimit: 12, maxRotation: 0, font: { size: 10 } } },
        y: { stacked: true, grid: { color: 'rgba(128,128,128,0.08)' }, ticks: { color: '#8da1c8', precision: 0, font: { size: 10 } } },
      },
    },
  });
}

async function refreshTimeseries() {
  const hours = parseInt($('timeseriesRange')?.value || '24', 10);
  const res = await fetch(`/api/logs/timeseries?hours=${hours}`);
  if (!res.ok) return;
  const data = await res.json();
  renderTimeseriesChart(data.buckets || {});
}

// ===== RENDER LISTS =====
function renderIntegrations() {
  const list  = $('integrationList');
  const items = state.bootstrap?.integrations || [];
  if (!items.length) { list.className = 'list-box empty-state'; list.textContent = 'No integrations saved yet.'; return; }
  list.className = 'list-box';
  list.innerHTML = items.map(item => `
    <div class="list-item">
      <div><strong>${escapeHtml(item.name)}</strong><div class="muted">${escapeHtml(item.kind?.toUpperCase())} · ${escapeHtml(item.status)}</div></div>
      <span class="pill info">configured</span>
    </div>`).join('');
}

function renderJobs() {
  const list  = $('jobsList');
  const items = state.bootstrap?.jobs || [];
  if (!items.length) { list.className = 'list-box empty-state'; list.textContent = 'No jobs configured yet.'; return; }
  list.className = 'list-box';
  list.innerHTML = items.map(item => `
    <div class="list-item">
      <div>
        <strong>${escapeHtml(item.name)}</strong>
        <div class="muted">${escapeHtml(item.source_type?.toUpperCase())} · ${escapeHtml(item.status)} · <code>${escapeHtml(item.schedule)}</code></div>
        <div class="muted">Last: ${escapeHtml(item.last_run_at || 'never')} · Next: ${escapeHtml(item.next_run_at || 'pending')}</div>
      </div>
      <button class="secondary-btn run-job-btn" data-job-id="${item.id}">▶ Run now</button>
    </div>`).join('');
}

function renderAlerts() {
  const list  = $('alertsList');
  const items = state.bootstrap?.alerts || [];
  if (!items.length) { list.className = 'list-box empty-state'; list.textContent = 'No alert rules yet.'; return; }
  list.className = 'list-box';
  list.innerHTML = items.map(item => `
    <div class="list-item">
      <div>
        <strong>${escapeHtml(item.name)}</strong>
        <div class="muted">${escapeHtml(item.severity?.toUpperCase())} · ${escapeHtml(item.channel)} · ${escapeHtml(item.status)}</div>
        <div class="muted">${escapeHtml(item.condition_text)}</div>
      </div>
      <span class="pill ${item.status === 'active' ? 'success' : 'info'}">${escapeHtml(item.status)}</span>
    </div>`).join('');
}

function renderUsers() {
  const list  = $('userList');
  const items = state.bootstrap?.users || [];
  if (!items.length) { list.className = 'list-box empty-state'; list.textContent = 'No users found.'; return; }
  list.className = 'list-box';
  list.innerHTML = items.map(item => `
    <div class="list-item">
      <div><strong>${escapeHtml(item.name)}</strong><div class="muted">${escapeHtml(item.email)} · ${escapeHtml(item.role)}</div></div>
      <span class="pill info">${escapeHtml(item.role)}</span>
    </div>`).join('');
}

function renderAudit() {
  const list  = $('auditList');
  const items = state.bootstrap?.audit || [];
  if (!items.length) { list.className = 'list-box empty-state'; list.textContent = 'No audit events yet.'; return; }
  list.className = 'list-box';
  list.innerHTML = items.map(item => `
    <div class="list-item">
      <div><strong>${escapeHtml(item.action)}</strong><div class="muted">${escapeHtml(item.target_type)} · ${escapeHtml(item.target_id || '—')}</div></div>
      <div class="muted" style="font-size:11px;white-space:nowrap">${escapeHtml((item.created_at || '').slice(0,19).replace('T',' '))}</div>
    </div>`).join('');
}

function renderApiKeys() {
  const list  = $('apiKeyList');
  if (!list) return;
  const items = state.bootstrap?.api_keys || [];
  if (!items.length) { list.className = 'list-box empty-state'; list.textContent = 'No API keys yet. Generate one above.'; return; }
  list.className = 'list-box';
  list.innerHTML = items.map(item => `
    <div class="key-row">
      <div class="key-row-meta">
        <span class="key-name">${escapeHtml(item.name)}</span>
        <span class="key-prefix">${escapeHtml(item.prefix)}••••••  ·  ${escapeHtml(item.status)}  ·  ${escapeHtml(item.created_by)}</span>
        <span class="key-prefix">${item.last_used_at ? 'Last used: ' + escapeHtml(item.last_used_at.slice(0,16).replace('T',' ')) : 'Never used'}</span>
      </div>
      ${item.status === 'active'
        ? `<button class="key-revoke" data-key-id="${item.id}">Revoke</button>`
        : '<span class="muted" style="font-size:11px">revoked</span>'}
    </div>`).join('');
}

function renderInvitations() {
  const list  = $('invitationList');
  if (!list) return;
  const items = state.bootstrap?.invitations || [];
  if (!items.length) { list.className = 'list-box empty-state'; list.textContent = 'No invites sent yet.'; return; }
  list.className = 'list-box';
  list.innerHTML = items.map(item => `
    <div class="list-item">
      <div><strong>${escapeHtml(item.email)}</strong><div class="muted">${escapeHtml(item.role)} · ${escapeHtml(item.status)}</div></div>
      <button class="secondary-btn copy-link-btn" data-copy="${window.location.origin}/accept-invite/${item.token}">Copy link</button>
    </div>`).join('');
}

function renderDashboards() {
  const list  = $('dashboardList');
  if (!list) return;
  const items = state.bootstrap?.saved_dashboards || [];
  if (!items.length) { list.className = 'list-box empty-state'; list.textContent = 'No saved dashboards yet.'; return; }
  list.className = 'list-box';
  list.innerHTML = items.map(item => `
    <div class="list-item">
      <div><strong>${escapeHtml(item.name)}</strong><div class="muted">Saved ${escapeHtml((item.created_at || '').slice(0,10))}</div></div>
      <span class="pill info">saved</span>
    </div>`).join('');
}

function renderRuns() {
  const list  = $('runList');
  if (!list) return;
  const items = state.bootstrap?.runs || [];
  if (!items.length) { list.className = 'list-box empty-state'; list.textContent = 'No ingestion runs yet.'; return; }
  list.className = 'list-box';
  list.innerHTML = items.map(item => `
    <div class="list-item">
      <div><strong>Job #${item.job_id}</strong><div class="muted">${escapeHtml(item.status)} · ${formatNumber(item.record_count)} records</div></div>
      <span class="muted" style="font-size:11px">${escapeHtml((item.created_at || '').slice(0,16).replace('T',' '))}</span>
    </div>`).join('');
}

// ===== BOOTSTRAP =====
async function fetchBootstrap() {
  const res = await fetch('/api/bootstrap');
  if (!res.ok) { if (res.status === 401) window.location.href = '/login'; return; }
  state.bootstrap = await res.json();
  applyOrgTheme();
  renderSummary();
  renderIntegrations();
  renderJobs();
  renderAlerts();
  renderUsers();
  renderAudit();
  renderApiKeys();
  renderInvitations();
  renderDashboards();
  renderRuns();
}

// ===== LOGS =====
async function fetchLogs() {
  const q       = $('searchInput')?.value?.trim() || '';
  const level   = $('levelFilter')?.value || 'all';
  const timeVal = $('timeFilter')?.value || '0';
  const params  = { q, level };

  if (timeVal === 'custom') {
    // Use explicit from/to timestamps
    const from = $('rangeFrom')?.value;
    const to   = $('rangeTo')?.value;
    if (from) params.from_ts = new Date(from).toISOString();
    if (to)   params.to_ts   = new Date(to).toISOString();
  } else if (timeVal && timeVal !== '0') {
    params.minutes = timeVal;
  }

  const res  = await fetch(`/api/logs?${new URLSearchParams(params)}`);
  const data = await res.json();
  state.records = data.records || [];
  renderRecords();
}

function renderRecords() {
  const el = $('recordsBody');
  if (!state.records.length) {
    const timeVal   = $('timeFilter')?.value || '0';
    const timeLabel = $('timeFilter')?.selectedOptions[0]?.text || '';
    const hasFilter = $('searchInput')?.value || $('levelFilter')?.value !== 'all' || timeVal !== '0';
    const hint = hasFilter
      ? `No records match your filters${timeVal !== '0' ? ` for <strong>${timeLabel}</strong>` : ''}.`
      : 'No matching records. Upload logs or use the Ingest API.';
    el.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:28px;color:var(--muted)">${hint}</td></tr>`;
    updateResultCount(0);
    return;
  }
  el.innerHTML = state.records.map(r => `
    <tr class="log-row" data-id="${r.id}">
      <td style="white-space:nowrap;font-size:12px">${escapeHtml((r.timestamp || '').slice(0,19).replace('T',' '))}</td>
      <td>${badge(r.level)}</td>
      <td>${escapeHtml(r.source || 'system')}</td>
      <td style="font-family:monospace;font-size:11px">${escapeHtml(r.event_id || '—')}</td>
      <td>${escapeHtml(r.message || '')}</td>
    </tr>`).join('');
  updateResultCount(state.records.length);
}

function updateResultCount(count) {
  let el = $('resultCount');
  if (!el) {
    el = document.createElement('span');
    el.id = 'resultCount';
    el.style.cssText = 'font-size:12px;color:var(--muted);margin-left:auto;white-space:nowrap';
    $('searchBtn')?.parentElement?.appendChild(el);
  }
  const timeVal = $('timeFilter')?.value || '0';
  let timeLabel = '';
  if (timeVal === 'custom') {
    const from = $('rangeFrom')?.value;
    const to   = $('rangeTo')?.value;
    if (from || to) timeLabel = `${from || '…'} → ${to || '…'}`;
  } else if (timeVal !== '0') {
    timeLabel = $('timeFilter')?.selectedOptions[0]?.text || '';
  }
  el.textContent = count
    ? `${count} record${count !== 1 ? 's' : ''}${timeLabel ? ` · ${timeLabel}` : ''}`
    : '';
}

async function showLogDetail(id) {
  const res  = await fetch(`/api/logs/${id}`);
  const data = await res.json();
  if (!res.ok) return;
  $('logMeta').innerHTML = `
    <div class="meta-item"><div class="small-label">Timestamp</div><strong>${escapeHtml(data.timestamp)}</strong></div>
    <div class="meta-item"><div class="small-label">Level</div><strong>${escapeHtml(data.level)}</strong></div>
    <div class="meta-item"><div class="small-label">Source</div><strong>${escapeHtml(data.source)}</strong></div>
    <div class="meta-item"><div class="small-label">Event ID</div><strong>${escapeHtml(data.event_id || '—')}</strong></div>`;
  $('logPayload').textContent = JSON.stringify(data.payload, null, 2);
  $('logModal').showModal();
}

// ===== UPLOAD =====
async function uploadFiles(files) {
  if (!files || !files.length) return;
  const statusEl = $('uploadStatus');
  if (statusEl) statusEl.textContent = `Uploading ${files.length} file(s)…`;
  toast(`Uploading ${files.length} file(s)…`);

  const fd = new FormData();
  Array.from(files).forEach(f => fd.append('files', f));
  const res  = await fetch('/api/upload', { method: 'POST', body: fd });
  const data = await res.json();

  if (!res.ok) {
    if (statusEl) statusEl.textContent = data.error || 'Upload failed.';
    return toast(data.error || 'Upload failed', true);
  }
  const skippedNote = data.skipped?.length ? ` (${data.skipped.length} file(s) skipped — binary/unsupported)` : '';
  if (statusEl) statusEl.textContent = `✓ ${data.files_uploaded} file(s) — ${formatNumber(data.summary.total)} records indexed.${skippedNote}`;
  if (data.skipped?.length) {
    data.skipped.forEach(s => toast(`⚠ Skipped: ${s}`, true));
  }
  await fetchBootstrap();
  await fetchLogs();
  toast(`✓ ${formatNumber(data.summary.total)} records indexed`);
  setActiveNav('logsSection');
}

// ===== FORM HELPERS =====
function objectFromForm(formId) { return Object.fromEntries(new FormData($(formId)).entries()); }
function parseJsonField(v) { if (!v) return {}; try { return JSON.parse(v); } catch { return null; } }
async function postJson(url, payload) {
  const res  = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  const data = await res.json();
  return { res, data };
}

// ===== ACTION HANDLERS =====
async function handleCreateUser() {
  const payload = objectFromForm('userForm');
  delete payload.organization_name;
  const { res, data } = await postJson('/api/users', payload);
  $('userResult').textContent = data.message || data.error || 'Done';
  if (!res.ok) return toast(data.error || 'Failed', true);
  $('userForm').reset();
  $('userOrgName').value = state.bootstrap.organization.name;
  await fetchBootstrap(); toast('User created');
}

async function handleSaveOrg() {
  const payload = objectFromForm('orgForm');
  payload.admin_only = $('orgForm').admin_only.checked;
  const { res, data } = await postJson('/api/org', payload);
  $('orgResult').textContent = data.message || data.error || 'Done';
  if (!res.ok) return toast(data.error || 'Failed', true);
  await fetchBootstrap(); toast('Organization settings updated');
}

async function handleSaveS3() {
  const payload = objectFromForm('s3Form');
  const { res, data } = await postJson('/api/integrations', { kind:'s3', name:payload.name, status:'configured', settings:payload });
  $('s3Result').textContent = data.message || data.error || 'Done';
  if (!res.ok) return toast(data.error || 'Failed', true);
  await fetchBootstrap(); toast('S3 integration saved');
}

async function handleTestS3() {
  const payload = objectFromForm('s3Form');
  const { data } = await postJson('/api/integrations/s3/test', payload);
  $('s3Result').textContent = data.message || 'Done';
  if (!data.success) return toast(data.message || 'S3 test failed', true);
  toast('S3 connection OK');
}

async function handleSaveApi() {
  const payload = objectFromForm('apiForm');
  const headers = parseJsonField(payload.headers);
  if (headers === null) { $('apiResult').textContent = 'Headers must be valid JSON.'; return toast('Invalid JSON headers', true); }
  const { res, data } = await postJson('/api/integrations', { kind:'api', name:payload.name, status:'configured', settings:{...payload, headers} });
  $('apiResult').textContent = data.message || data.error || 'Done';
  if (!res.ok) return toast(data.error || 'Failed', true);
  await fetchBootstrap(); toast('API integration saved');
}

async function handleTestApi() {
  const payload = objectFromForm('apiForm');
  const headers = parseJsonField(payload.headers);
  if (headers === null) { $('apiResult').textContent = 'Headers must be valid JSON.'; return toast('Invalid JSON', true); }
  const { data } = await postJson('/api/integrations/api/test', {...payload, headers});
  $('apiResult').textContent = data.message || 'Done';
  if (!data.success) return toast(data.message || 'API test failed', true);
  toast('API connection OK');
}

async function handleCreateJob() {
  const payload = objectFromForm('jobForm');
  const details = parseJsonField(payload.details);
  if (details === null) { $('jobResult').textContent = 'Details must be valid JSON.'; return toast('Invalid JSON', true); }
  payload.details = details;
  const { res, data } = await postJson('/api/jobs', payload);
  $('jobResult').textContent = data.message || data.error || 'Done';
  if (!res.ok) return toast(data.error || 'Failed', true);
  await fetchBootstrap(); toast('Job created');
}

async function handleRunJob(jobId) {
  const { res, data } = await postJson(`/api/jobs/${jobId}/run`, {});
  $('jobResult').textContent = data.message || data.error || 'Done';
  if (!res.ok) return toast(data.error || 'Failed', true);
  await fetchBootstrap(); await fetchLogs(); toast('Job queued successfully');
}

async function handleCreateAlert() {
  const payload = objectFromForm('alertForm');
  const { res, data } = await postJson('/api/alerts', payload);
  $('alertResult').textContent = data.message || data.error || 'Done';
  if (!res.ok) return toast(data.error || 'Failed', true);
  await fetchBootstrap(); toast('Alert created');
}

async function handleCreateApiKey() {
  const name = ($('apiKeyName')?.value || '').trim();
  if (!name) return toast('Key name is required', true);
  const { res, data } = await postJson('/api/keys', { name });
  $('apiKeyResult').textContent = data.message || data.error || 'Done';
  if (!res.ok) return toast(data.error || 'Failed', true);
  if ($('apiKeyName')) $('apiKeyName').value = '';
  const box = $('newKeyBox');
  if (box && data.key) {
    box.style.display = 'block';
    box.innerHTML = `<strong>⚠ Copy now — shown once only:</strong><br><br>${escapeHtml(data.key)}`;
  }
  await fetchBootstrap(); toast('API key created — copy it now!');
}

async function logout() {
  await fetch('/logout', { method: 'POST' });
  window.location.href = '/';
}

// ===== BIND EVENTS =====
function bindEvents() {
  // Nav
  document.querySelectorAll('.nav-link').forEach(btn =>
    btn.addEventListener('click', () => setActiveNav(btn.dataset.section)));
  document.querySelectorAll('[data-jump]').forEach(btn =>
    btn.addEventListener('click', () => setActiveNav(btn.dataset.jump)));

  // Log explorer
  $('searchBtn').addEventListener('click', fetchLogs);
  $('levelFilter').addEventListener('change', fetchLogs);
  $('timeFilter').addEventListener('change', () => {
    const tf  = $('timeFilter');
    const isCustom = tf.value === 'custom';
    const isActive = tf.value !== '0';
    tf.classList.toggle('active', isActive);
    const row = $('customRangeRow');
    if (row) row.style.display = isCustom ? 'block' : 'none';
    if (!isCustom) fetchLogs();   // immediate for preset; custom waits for Apply
  });

  // Custom range Apply / Clear buttons
  $('applyRangeBtn')?.addEventListener('click', () => {
    const from = $('rangeFrom')?.value;
    const to   = $('rangeTo')?.value;
    if (!from && !to) return toast('Please set at least one date/time', true);
    fetchLogs();
  });

  $('clearRangeBtn')?.addEventListener('click', () => {
    if ($('rangeFrom')) $('rangeFrom').value = '';
    if ($('rangeTo'))   $('rangeTo').value   = '';
    $('timeFilter').value = '0';
    $('timeFilter').classList.remove('active');
    const row = $('customRangeRow');
    if (row) row.style.display = 'none';
    fetchLogs();
  });
  $('searchInput').addEventListener('keydown', e => { if (e.key === 'Enter') fetchLogs(); });
  // Auto-refresh when search box is cleared (native ✕ or backspace to empty)
  $('searchInput').addEventListener('input', e => { if (!e.target.value) fetchLogs(); });
  // Close modal when clicking backdrop (outside the dialog box)
  $('logModal').addEventListener('click', e => { if (e.target === $('logModal')) $('logModal').close(); });
  $('recordsBody').addEventListener('click', e => {
    const row = e.target.closest('.log-row');
    if (row) showLogDetail(row.dataset.id);
  });

  // File input — shared, handles all file pickers
  const fileInput = $('logFileInput');
  if (fileInput) {
    fileInput.addEventListener('change', e => {
      if (e.target.files?.length) uploadFiles(e.target.files);
      e.target.value = ''; // reset so same file can be re-uploaded
    });
  }

  // DnD upload zone (overview quick-upload)
  const dnd = $('dndUploadZone');
  if (dnd) {
    dnd.addEventListener('click', () => fileInput?.click());
    dnd.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput?.click(); } });
    dnd.addEventListener('dragenter', e => { e.preventDefault(); e.stopPropagation(); dnd.classList.add('drag-active'); });
    dnd.addEventListener('dragover',  e => { e.preventDefault(); e.stopPropagation(); dnd.classList.add('drag-active'); });
    dnd.addEventListener('dragleave', e => { e.preventDefault(); e.stopPropagation(); dnd.classList.remove('drag-active'); });
    dnd.addEventListener('drop', e => {
      e.preventDefault(); e.stopPropagation();
      dnd.classList.remove('drag-active');
      const files = e.dataTransfer?.files;
      if (files?.length) uploadFiles(files);
    });
  }

  // Also: allow dropping anywhere on the page when overview is visible
  document.addEventListener('dragover',  e => e.preventDefault());
  document.addEventListener('drop', e => {
    if (e.target.closest('.dnd-upload-zone') || e.target.closest('input')) return;
    e.preventDefault();
    const files = e.dataTransfer?.files;
    if (files?.length) uploadFiles(files);
  });

  // Org / integrations / jobs / alerts / users
  $('createUserBtn').addEventListener('click', handleCreateUser);
  $('saveOrgBtn').addEventListener('click', handleSaveOrg);
  $('saveS3Btn').addEventListener('click', handleSaveS3);
  $('testS3Btn').addEventListener('click', handleTestS3);
  $('saveApiBtn').addEventListener('click', handleSaveApi);
  $('testApiBtn').addEventListener('click', handleTestApi);
  $('createJobBtn').addEventListener('click', handleCreateJob);
  $('createAlertBtn').addEventListener('click', handleCreateAlert);
  $('logoutBtn').addEventListener('click', logout);
  $('jobsList').addEventListener('click', e => {
    const btn = e.target.closest('.run-job-btn');
    if (btn) handleRunJob(btn.dataset.jobId);
  });

  // API Keys
  const apiKeyBtn = $('createApiKeyBtn');
  if (apiKeyBtn) apiKeyBtn.addEventListener('click', handleCreateApiKey);

  const apiKeyList = $('apiKeyList');
  if (apiKeyList) {
    apiKeyList.addEventListener('click', async e => {
      const btn = e.target.closest('.key-revoke');
      if (!btn) return;
      if (!confirm('Revoke this API key? It will stop working immediately.')) return;
      const { res, data } = await postJson(`/api/keys/${btn.dataset.keyId}`, {});
      // use DELETE method
      const r = await fetch(`/api/keys/${btn.dataset.keyId}`, { method: 'DELETE' });
      const d = await r.json();
      toast(d.message || d.error || 'Done', !r.ok);
      if (r.ok) await fetchBootstrap();
    });
  }

  // Timeseries range
  const tsRange = $('timeseriesRange');
  if (tsRange) tsRange.addEventListener('change', refreshTimeseries);

  // Copy invite links
  document.addEventListener('click', e => {
    const btn = e.target.closest('.copy-link-btn');
    if (btn) { navigator.clipboard.writeText(btn.dataset.copy || ''); toast('Copied!'); }
  });

  // Invite form
  const inviteForm = $('inviteForm');
  if (inviteForm) {
    inviteForm.addEventListener('submit', async e => {
      e.preventDefault();
      const payload = Object.fromEntries(new FormData(inviteForm).entries());
      const { res, data } = await postJson('/api/invitations', payload);
      const resultEl = $('inviteResult');
      if (!res.ok) {
        if (resultEl) resultEl.textContent = data.error || 'Failed to create invite.';
        return toast(data.error || 'Invite failed', true);
      }
      // Show invite link
      if (resultEl) resultEl.textContent = data.invite_url ? `Invite: ${data.invite_url}` : (data.message || 'Done');
      // Show email delivery status
      if (data.email_sent) {
        toast('✓ Invite created & email sent');
      } else if (!data.smtp_configured) {
        toast('⚠ Invite created — no SMTP configured, email NOT sent. Share the link above manually.', true);
      } else if (data.email_error) {
        toast(`⚠ Invite created but email failed: ${data.email_error}`, true);
      }
      await fetchBootstrap();
    });
  }

  // Save dashboard
  const saveDashBtn = $('saveDashboardBtn');
  if (saveDashBtn) {
    saveDashBtn.addEventListener('click', async () => {
      const name = ($('dashboardName')?.value || '').trim();
      if (!name) return toast('Dashboard name required', true);
      const payload = { name, config: { section: document.querySelector('.nav-link.active')?.dataset.section || 'overviewSection' } };
      const { res, data } = await postJson('/api/dashboards', payload);
      $('dashboardResult').textContent = data.message || data.error || 'Done';
      if (res.ok) { await fetchBootstrap(); toast('Dashboard saved'); }
    });
  }
}

// ===== INIT =====
(async function init() {
  bindEvents();
  await fetchBootstrap();
  await fetchLogs();
})();
