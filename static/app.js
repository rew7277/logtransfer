const state = {
  bootstrap: null,
  records: [],
  charts: {},
};

const $ = (id) => document.getElementById(id);

function formatNumber(value) {
  return new Intl.NumberFormat().format(value || 0);
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function badge(level) {
  return `<span class="level-badge level-${level}">${escapeHtml(level)}</span>`;
}

function toast(message, isError = false) {
  const box = document.createElement('div');
  box.className = `floating-toast ${isError ? 'error' : ''}`;
  box.textContent = message;
  document.body.appendChild(box);
  setTimeout(() => box.remove(), 2600);
}

function setActiveNav(sectionId) {
  document.querySelectorAll('.nav-link').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.section === sectionId);
  });
  document.querySelectorAll('.content-section').forEach((section) => {
    section.classList.toggle('active', section.id === sectionId);
  });
}

function applyOrgTheme() {
  const org = state.bootstrap?.organization;
  const user = state.bootstrap?.user;
  if (!org) return;
  document.documentElement.style.setProperty('--primary', org.theme_color || '#5b8cff');
  document.body.classList.remove('theme-black', 'theme-white', 'theme-green');
  document.body.classList.add(`theme-${org.theme_mode || 'white'}`);
  $('orgName').textContent = org.name;
  $('orgLogo').textContent = org.logo_text;
  $('orgSlug').textContent = org.slug;
  $('currentUserName').textContent = user.name;
  $('currentUserRole').textContent = user.role;
  $('userOrgName').value = org.name;

  const orgForm = $('orgForm');
  orgForm.name.value = org.name;
  orgForm.slug.value = org.slug;
  orgForm.logo_text.value = org.logo_text;
  orgForm.theme_color.value = org.theme_color;
  orgForm.theme_mode.value = org.theme_mode || 'white';
  orgForm.admin_only.checked = !!org.admin_only;

  const isAdmin = user.role === 'admin';
  ['createUserBtn', 'saveOrgBtn', 'saveS3Btn', 'testS3Btn', 'saveApiBtn', 'testApiBtn', 'createJobBtn', 'createAlertBtn'].forEach((id) => {
    const el = $(id);
    if (el) el.disabled = false;
  });
  if (!isAdmin) {
    ['createUserBtn', 'saveOrgBtn', 'saveS3Btn', 'saveApiBtn', 'createJobBtn', 'createAlertBtn'].forEach((id) => {
      const el = $(id);
      if (el) el.disabled = true;
    });
    $('userResult').textContent = 'Only admins can create new accounts inside this organization.';
  }
}

function renderSummary() {
  const summary = state.bootstrap?.summary || { totals: {}, levels: {}, source_breakdown: [], error_rate: 0 };
  $('metricLogs').textContent = formatNumber(summary.totals.logs || 0);
  $('metricUsers').textContent = formatNumber(summary.totals.users || 0);
  $('metricIntegrations').textContent = formatNumber(summary.totals.integrations || 0);
  $('heroErrorRate').textContent = `${summary.error_rate || 0}%`;

  const sourceList = $('sourceList');
  if (!summary.source_breakdown.length) {
    sourceList.className = 'list-box empty-state';
    sourceList.textContent = 'Upload logs to populate analytics.';
  } else {
    sourceList.className = 'list-box';
    sourceList.innerHTML = summary.source_breakdown.map(item => `
      <div class="list-item"><span>${escapeHtml(item.source)}</span><strong>${formatNumber(item.count)}</strong></div>
    `).join('');
  }

  renderCharts(summary);
}

const LEVEL_COLORS = {
  error: 'rgba(248,113,113,0.85)',
  warn: 'rgba(251,191,36,0.85)',
  info: 'rgba(79,124,255,0.85)',
  success: 'rgba(52,211,153,0.85)',
  debug: 'rgba(148,163,184,0.7)',
};

function renderCharts(summary) {
  const levelData = summary.levels || {};
  const sourceData = summary.source_breakdown || [];

  const levelCtx = $('levelChart');
  const sourceCtx = $('sourceChart');
  if (state.charts.levelChart) state.charts.levelChart.destroy();
  if (state.charts.sourceChart) state.charts.sourceChart.destroy();

  const levelKeys = Object.keys(levelData);
  const levelColors = levelKeys.map(l => LEVEL_COLORS[l] || 'rgba(99,102,241,0.8)');

  state.charts.levelChart = new Chart(levelCtx, {
    type: 'bar',
    data: {
      labels: levelKeys,
      datasets: [{
        label: 'Logs',
        data: Object.values(levelData),
        backgroundColor: levelColors,
        borderRadius: 10,
        borderSkipped: false,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#8da1c8' } },
        y: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#8da1c8', precision: 0 } },
      },
    },
  });

  const doughnutColors = sourceData.map((_, i) => `hsl(${(i * 47 + 210) % 360}, 70%, 65%)`);
  state.charts.sourceChart = new Chart(sourceCtx, {
    type: 'doughnut',
    data: {
      labels: sourceData.map(x => x.source),
      datasets: [{
        data: sourceData.map(x => x.count),
        backgroundColor: doughnutColors,
        borderWidth: 0,
        hoverOffset: 8,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'right', labels: { color: '#8da1c8', boxWidth: 14, padding: 10 } } },
    },
  });

  renderTimeseriesChart(summary.time_series || {});
}

function renderTimeseriesChart(buckets) {
  const ctx = $('timeseriesChart');
  if (!ctx) return;
  if (state.charts.timeseriesChart) state.charts.timeseriesChart.destroy();

  const hours = Object.keys(buckets).sort();
  if (!hours.length) {
    ctx.style.display = 'none';
    let placeholder = ctx.nextElementSibling;
    if (!placeholder || !placeholder.classList.contains('ts-empty')) {
      placeholder = document.createElement('div');
      placeholder.className = 'ts-empty';
      placeholder.textContent = 'No log data in this time window — upload logs or use the ingest API.';
      ctx.parentNode.insertBefore(placeholder, ctx.nextSibling);
    }
    return;
  }
  ctx.style.display = '';
  const sibling = ctx.nextElementSibling;
  if (sibling && sibling.classList.contains('ts-empty')) sibling.remove();

  const levels = ['error', 'warn', 'info', 'success', 'debug'];
  const datasets = levels.map(level => ({
    label: level,
    data: hours.map(h => (buckets[h] || {})[level] || 0),
    backgroundColor: LEVEL_COLORS[level] || 'rgba(99,102,241,0.5)',
    borderColor: (LEVEL_COLORS[level] || 'rgba(99,102,241,0.5)').replace('0.85', '1'),
    borderWidth: 1.5,
    borderRadius: 4,
    stack: 'logs',
  }));

  state.charts.timeseriesChart = new Chart(ctx, {
    type: 'bar',
    data: { labels: hours.map(h => h.replace('T', ' ').replace(':00:00Z', ':00')), datasets },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { color: '#8da1c8', boxWidth: 12, padding: 12 } } },
      scales: {
        x: { stacked: true, grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#8da1c8', maxTicksLimit: 12, maxRotation: 0 } },
        y: { stacked: true, grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#8da1c8', precision: 0 } },
      },
    },
  });
}

async function refreshTimeseries() {
  const sel = $('timeseriesRange');
  const hours = sel ? parseInt(sel.value, 10) : 24;
  const res = await fetch(`/api/logs/timeseries?hours=${hours}`);
  if (!res.ok) return;
  const data = await res.json();
  renderTimeseriesChart(data.buckets || {});
}

function renderIntegrations() {
  const list = $('integrationList');
  const items = state.bootstrap?.integrations || [];
  if (!items.length) {
    list.className = 'list-box empty-state';
    list.textContent = 'No integrations saved yet.';
    return;
  }
  list.className = 'list-box';
  list.innerHTML = items.map(item => `
    <div class="list-item">
      <div>
        <strong>${escapeHtml(item.name)}</strong>
        <div class="muted">${escapeHtml(item.kind.toUpperCase())} · ${escapeHtml(item.status)}</div>
      </div>
      <span class="pill">configured</span>
    </div>
  `).join('');
}

function renderJobs() {
  const list = $('jobsList');
  const items = state.bootstrap?.jobs || [];
  if (!items.length) {
    list.className = 'list-box empty-state';
    list.textContent = 'No jobs configured yet.';
    return;
  }
  list.className = 'list-box';
  list.innerHTML = items.map(item => `
    <div class="list-item stack-sm">
      <div>
        <strong>${escapeHtml(item.name)}</strong>
        <div class="muted">${escapeHtml(item.source_type.toUpperCase())} · ${escapeHtml(item.status)} · ${escapeHtml(item.schedule)}</div>
        <div class="muted">Last run: ${escapeHtml(item.last_run_at || 'never')} · Next: ${escapeHtml(item.next_run_at || 'pending')}</div>
      </div>
      <button class="secondary-btn run-job-btn" data-job-id="${item.id}">Run now</button>
    </div>
  `).join('');
}

function renderAlerts() {
  const list = $('alertsList');
  const items = state.bootstrap?.alerts || [];
  if (!items.length) {
    list.className = 'list-box empty-state';
    list.textContent = 'No alert rules configured yet.';
    return;
  }
  list.className = 'list-box';
  list.innerHTML = items.map(item => `
    <div class="list-item">
      <div>
        <strong>${escapeHtml(item.name)}</strong>
        <div class="muted">${escapeHtml(item.severity.toUpperCase())} · ${escapeHtml(item.channel)} · ${escapeHtml(item.status)}</div>
        <div class="muted top-gap-sm">${escapeHtml(item.condition_text)}</div>
      </div>
      <span class="pill">rule</span>
    </div>
  `).join('');
}

function renderUsers() {
  const list = $('userList');
  const items = state.bootstrap?.users || [];
  if (!items.length) {
    list.className = 'list-box empty-state';
    list.textContent = 'No users found.';
    return;
  }
  list.className = 'list-box';
  list.innerHTML = items.map(item => `
    <div class="list-item">
      <div>
        <strong>${escapeHtml(item.name)}</strong>
        <div class="muted">${escapeHtml(item.email)} · ${escapeHtml(item.role)}</div>
      </div>
      <span class="pill">user</span>
    </div>
  `).join('');
}

function renderAudit() {
  const list = $('auditList');
  const items = state.bootstrap?.audit || [];
  if (!items.length) {
    list.className = 'list-box empty-state';
    list.textContent = 'No audit events yet.';
    return;
  }
  list.className = 'list-box';
  list.innerHTML = items.map(item => `
    <div class="list-item stack-sm">
      <div>
        <strong>${escapeHtml(item.action)}</strong>
        <div class="muted">${escapeHtml(item.target_type)} · ${escapeHtml(item.target_id || '—')}</div>
      </div>
      <div class="muted">${escapeHtml(item.created_at)}</div>
    </div>
  `).join('');
}

function renderApiKeys() {
  const list = $('apiKeyList');
  if (!list) return;
  const items = state.bootstrap?.api_keys || [];
  if (!items.length) {
    list.className = 'list-box empty-state';
    list.textContent = 'No API keys yet. Generate one above.';
    return;
  }
  list.className = 'list-box';
  list.innerHTML = items.map(item => `
    <div class="key-row">
      <div class="key-row-meta">
        <span class="key-name">${escapeHtml(item.name)}</span>
        <span class="key-prefix">${escapeHtml(item.prefix)}••••••••  ·  ${escapeHtml(item.status)}  ·  by ${escapeHtml(item.created_by)}</span>
        <span class="key-prefix muted">${item.last_used_at ? 'Last used: ' + escapeHtml(item.last_used_at) : 'Never used'}</span>
      </div>
      ${item.status === 'active' ? `<button class="key-revoke" data-key-id="${item.id}">Revoke</button>` : '<span class="muted" style="font-size:12px">revoked</span>'}
    </div>
  `).join('');
}

async function fetchBootstrap() {
  const res = await fetch('/api/bootstrap');
  if (!res.ok) {
    if (res.status === 401) window.location.href = '/login';
    return;
  }
  state.bootstrap = await res.json();
  applyOrgTheme();
  renderSummary();
  renderIntegrations();
  renderJobs();
  renderAlerts();
  renderUsers();
  renderAudit();
  renderInvitations();
  renderDashboards();
  renderRuns();
  renderApiKeys();
}

function renderInvitations() {
  const list = $('invitationList');
  if (!list) return;
  const items = state.bootstrap?.invitations || [];
  if (!items.length) { list.className='list-box empty-state'; list.textContent='No invites sent yet.'; return; }
  list.className='list-box';
  list.innerHTML = items.map(item => `
    <div class="list-item">
      <div><strong>${escapeHtml(item.email)}</strong><div class="muted">${escapeHtml(item.role)} · ${escapeHtml(item.status)}</div></div>
      <button class="secondary-btn copy-link-btn" data-copy="${window.location.origin}/accept-invite/${item.token}">Copy invite</button>
    </div>
  `).join('');
}

function renderDashboards() {
  const list = $('dashboardList');
  if (!list) return;
  const items = state.bootstrap?.saved_dashboards || [];
  if (!items.length) { list.className='list-box empty-state'; list.textContent='No saved dashboards yet.'; return; }
  list.className='list-box';
  list.innerHTML = items.map(item => `<div class="list-item"><div><strong>${escapeHtml(item.name)}</strong><div class="muted">Saved ${escapeHtml(item.created_at)}</div></div><span class="pill">saved</span></div>`).join('');
}


async function fetchLogs() {
  const q = $('searchInput').value.trim();
  const level = $('levelFilter').value;
  const params = new URLSearchParams({ q, level });
  const res = await fetch(`/api/logs?${params.toString()}`);
  const data = await res.json();
  state.records = data.records || [];
  renderRecords();
}

function renderRecords() {
  const el = $('recordsBody');
  if (!state.records.length) {
    el.innerHTML = '<tr><td colspan="5" class="empty-cell">No matching records.</td></tr>';
    return;
  }
  el.innerHTML = state.records.map(record => `
    <tr class="log-row" data-id="${record.id}">
      <td>${escapeHtml(record.timestamp)}</td>
      <td>${badge(record.level)}</td>
      <td>${escapeHtml(record.source || 'system')}</td>
      <td>${escapeHtml(record.event_id || '—')}</td>
      <td>${escapeHtml(record.message || '')}</td>
    </tr>
  `).join('');
}

async function showLogDetail(id) {
  const res = await fetch(`/api/logs/${id}`);
  const data = await res.json();
  if (!res.ok) return;
  $('logMeta').innerHTML = `
    <div><span class="small-label">Timestamp</span><strong>${escapeHtml(data.timestamp)}</strong></div>
    <div><span class="small-label">Level</span><strong>${escapeHtml(data.level)}</strong></div>
    <div><span class="small-label">Source</span><strong>${escapeHtml(data.source)}</strong></div>
    <div><span class="small-label">Event ID</span><strong>${escapeHtml(data.event_id || '—')}</strong></div>
  `;
  $('logPayload').textContent = JSON.stringify(data.payload, null, 2);
  $('logModal').showModal();
}

async function uploadFiles(files) {
  const formData = new FormData();
  Array.from(files).forEach(file => formData.append('files', file));
  $('uploadStatus').textContent = `Parsing ${files.length} file(s) and storing them for this organization...`;
  const response = await fetch('/api/upload', { method: 'POST', body: formData });
  const data = await response.json();
  if (!response.ok) {
    $('uploadStatus').textContent = data.error || 'Upload failed.';
    toast(data.error || 'Upload failed', true);
    return;
  }
  $('uploadStatus').textContent = `Uploaded ${data.filename}. Parsed ${formatNumber(data.summary.total)} records.`;
  await fetchBootstrap();
  await fetchLogs();
  toast('Logs uploaded successfully');
  setActiveNav('logsSection');
}

function objectFromForm(formId) {
  return Object.fromEntries(new FormData($(formId)).entries());
}

function parseJsonField(value) {
  if (!value) return {};
  try { return JSON.parse(value); } catch { return null; }
}

async function postJson(url, payload) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  return { res, data };
}

async function handleCreateUser() {
  const payload = objectFromForm('userForm');
  delete payload.organization_name;
  const { res, data } = await postJson('/api/users', payload);
  $('userResult').textContent = data.message || data.error || 'Done';
  if (!res.ok) return toast(data.error || 'Failed to create user', true);
  $('userForm').reset();
  $('userOrgName').value = state.bootstrap.organization.name;
  await fetchBootstrap();
  toast('User created');
}

async function handleSaveOrg() {
  const payload = objectFromForm('orgForm');
  payload.admin_only = $('orgForm').admin_only.checked;
  const { res, data } = await postJson('/api/org', payload);
  $('orgResult').textContent = data.message || data.error || 'Done';
  if (!res.ok) return toast(data.error || 'Failed to save organization settings', true);
  await fetchBootstrap();
  toast('Organization settings updated');
}

async function handleSaveS3() {
  const payload = objectFromForm('s3Form');
  const { res, data } = await postJson('/api/integrations', { kind: 's3', name: payload.name, status: 'configured', settings: payload });
  $('s3Result').textContent = data.message || data.error || 'Done';
  if (!res.ok) return toast(data.error || 'Failed to save S3 integration', true);
  await fetchBootstrap();
  toast('S3 integration saved');
}

async function handleTestS3() {
  const payload = objectFromForm('s3Form');
  const { data } = await postJson('/api/integrations/s3/test', payload);
  $('s3Result').textContent = data.message || 'S3 tested';
  if (!data.success) return toast(data.message || 'S3 test failed', true);
  toast('S3 connection successful');
}

async function handleSaveApi() {
  const payload = objectFromForm('apiForm');
  const headers = parseJsonField(payload.headers);
  if (headers === null) {
    $('apiResult').textContent = 'Headers must be valid JSON.';
    return toast('Headers must be valid JSON', true);
  }
  const { res, data } = await postJson('/api/integrations', { kind: 'api', name: payload.name, status: 'configured', settings: { ...payload, headers } });
  $('apiResult').textContent = data.message || data.error || 'Done';
  if (!res.ok) return toast(data.error || 'Failed to save API integration', true);
  await fetchBootstrap();
  toast('API integration saved');
}

async function handleTestApi() {
  const payload = objectFromForm('apiForm');
  const headers = parseJsonField(payload.headers);
  if (headers === null) {
    $('apiResult').textContent = 'Headers must be valid JSON.';
    return toast('Headers must be valid JSON', true);
  }
  const { data } = await postJson('/api/integrations/api/test', { ...payload, headers });
  $('apiResult').textContent = data.message || 'API tested';
  if (!data.success) return toast(data.message || 'API test failed', true);
  toast('API connection successful');
}

async function handleCreateJob() {
  const payload = objectFromForm('jobForm');
  const details = parseJsonField(payload.details);
  if (details === null) {
    $('jobResult').textContent = 'Job details must be valid JSON.';
    return toast('Job details must be valid JSON', true);
  }
  payload.details = details;
  const { res, data } = await postJson('/api/jobs', payload);
  $('jobResult').textContent = data.message || data.error || 'Done';
  if (!res.ok) return toast(data.error || 'Failed to create job', true);
  await fetchBootstrap();
  toast('Job created');
}

async function handleRunJob(jobId) {
  const { res, data } = await postJson(`/api/jobs/${jobId}/run`, {});
  $('jobResult').textContent = data.message || data.error || 'Done';
  if (!res.ok) return toast(data.error || 'Failed to run job', true);
  await fetchBootstrap();
  await fetchLogs();
  toast('Job ran successfully');
}

async function handleCreateAlert() {
  const payload = objectFromForm('alertForm');
  const { res, data } = await postJson('/api/alerts', payload);
  $('alertResult').textContent = data.message || data.error || 'Done';
  if (!res.ok) return toast(data.error || 'Failed to create alert', true);
  await fetchBootstrap();
  toast('Alert created');
}

async function handleCreateApiKey() {
  const form = $('apiKeyForm');
  const name = (form?.name?.value || '').trim();
  if (!name) return toast('Key name is required', true);
  const { res, data } = await postJson('/api/keys', { name });
  $('apiKeyResult').textContent = data.message || data.error || 'Done';
  if (!res.ok) return toast(data.error || 'Failed to create API key', true);
  form.reset();
  const box = $('newKeyBox');
  if (box && data.key) {
    box.style.display = 'block';
    box.className = 'new-key-reveal';
    box.innerHTML = `<strong>Copy now — shown once only:</strong><br><br>${escapeHtml(data.key)}`;
  }
  await fetchBootstrap();
  toast('API key created — copy it now!');
}

async function logout() {
  await fetch('/logout', { method: 'POST' });
  window.location.href = '/';
}

function bindEvents() {
  document.querySelectorAll('.nav-link').forEach((btn) => {
    btn.addEventListener('click', () => setActiveNav(btn.dataset.section));
  });
  document.querySelectorAll('[data-jump]').forEach((btn) => {
    btn.addEventListener('click', () => setActiveNav(btn.dataset.jump));
  });

  $('searchBtn').addEventListener('click', fetchLogs);
  $('levelFilter').addEventListener('change', fetchLogs);
  $('searchInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') fetchLogs(); });
  $('recordsBody').addEventListener('click', (e) => {
    const row = e.target.closest('.log-row');
    if (row) showLogDetail(row.dataset.id);
  });
  $('logFileInput').addEventListener('change', (e) => {
    const files = e.target.files;
    if (files && files.length) uploadFiles(files);
  });

  const dnd = $('dndUploadZone');
  if (dnd) {
    ['dragenter','dragover'].forEach((evt)=>dnd.addEventListener(evt,(e)=>{e.preventDefault(); dnd.classList.add('drag-active');}));
    ['dragleave','drop'].forEach((evt)=>dnd.addEventListener(evt,(e)=>{e.preventDefault(); dnd.classList.remove('drag-active');}));
    dnd.addEventListener('drop', (e) => {
      const files = e.dataTransfer?.files;
      if (files && files.length) uploadFiles(files);
    });
    dnd.addEventListener('click', () => $('logFileInput').click());
    dnd.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('logFileInput').click(); }
    });
  }
  $('createUserBtn').addEventListener('click', handleCreateUser);
  $('saveOrgBtn').addEventListener('click', handleSaveOrg);
  $('saveS3Btn').addEventListener('click', handleSaveS3);
  $('testS3Btn').addEventListener('click', handleTestS3);
  $('saveApiBtn').addEventListener('click', handleSaveApi);
  $('testApiBtn').addEventListener('click', handleTestApi);
  $('createJobBtn').addEventListener('click', handleCreateJob);
  $('createAlertBtn').addEventListener('click', handleCreateAlert);
  $('logoutBtn').addEventListener('click', logout);
  $('jobsList').addEventListener('click', (e) => {
    const btn = e.target.closest('.run-job-btn');
    if (btn) handleRunJob(btn.dataset.jobId);
  });

  // API Keys
  const createApiKeyBtn = $('createApiKeyBtn');
  if (createApiKeyBtn) createApiKeyBtn.addEventListener('click', handleCreateApiKey);

  const apiKeyList = $('apiKeyList');
  if (apiKeyList) {
    apiKeyList.addEventListener('click', async (e) => {
      const btn = e.target.closest('.key-revoke');
      if (!btn) return;
      if (!confirm('Revoke this API key? This cannot be undone.')) return;
      const keyId = btn.dataset.keyId;
      const res = await fetch(`/api/keys/${keyId}`, { method: 'DELETE' });
      const data = await res.json();
      toast(data.message || data.error || 'Done', !res.ok);
      if (res.ok) await fetchBootstrap();
    });
  }

  // Time-series range selector
  const tsRange = $('timeseriesRange');
  if (tsRange) tsRange.addEventListener('change', refreshTimeseries);
}

(async function init() {
  bindEvents();
  await fetchBootstrap();
  await fetchLogs();
})();


document.addEventListener('click', (event) => {
  const btn = event.target.closest('.copy-link-btn');
  if (btn) { navigator.clipboard.writeText(btn.dataset.copy || ''); toast('Invite link copied'); }
});

window.addEventListener('DOMContentLoaded', () => {
  const inviteForm = $('inviteForm');
  if (inviteForm) inviteForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(inviteForm).entries());
    const res = await fetch('/api/invitations', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    const data = await res.json();
    $('inviteResult').textContent = data.invite_url ? `Invite created: ${data.invite_url}` : (data.message || data.error || 'Done');
    if (res.ok) await fetchBootstrap();
  });
  const saveBtn = $('saveDashboardBtn');
  if (saveBtn) saveBtn.addEventListener('click', async () => {
    const name = ($('dashboardName')?.value || '').trim();
    const payload = {name, config:{section: document.querySelector('.nav-link.active')?.dataset.section || 'overviewSection'}};
    const res = await fetch('/api/dashboards', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    const data = await res.json();
    $('dashboardResult').textContent = data.message || data.error || 'Done';
    if (res.ok) await fetchBootstrap();
  });
});
