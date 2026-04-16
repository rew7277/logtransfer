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
  if (!org) return;
  document.documentElement.style.setProperty('--primary', org.theme_color || '#5b8cff');
  $('orgName').textContent = org.name;
  $('orgLogo').textContent = org.logo_text;
  $('orgSlug').textContent = org.slug;
  $('adminModeBadge').textContent = `Admin-only: ${org.admin_only ? 'On' : 'Off'}`;
  $('subdomainHint').textContent = org.subdomain_hint;
  $('orgForm').name.value = org.name;
  $('orgForm').slug.value = org.slug;
  $('orgForm').logo_text.value = org.logo_text;
  $('orgForm').theme_color.value = org.theme_color;
  $('orgForm').admin_only.checked = !!org.admin_only;
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

function renderCharts(summary) {
  const levelData = summary.levels || {};
  const sourceData = summary.source_breakdown || [];

  const levelCtx = $('levelChart');
  const sourceCtx = $('sourceChart');
  if (state.charts.levelChart) state.charts.levelChart.destroy();
  if (state.charts.sourceChart) state.charts.sourceChart.destroy();

  state.charts.levelChart = new Chart(levelCtx, {
    type: 'bar',
    data: { labels: Object.keys(levelData), datasets: [{ label: 'Logs', data: Object.values(levelData) }] },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
  });

  state.charts.sourceChart = new Chart(sourceCtx, {
    type: 'doughnut',
    data: { labels: sourceData.map(x => x.source), datasets: [{ data: sourceData.map(x => x.count) }] },
    options: { responsive: true, maintainAspectRatio: false }
  });
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

async function fetchBootstrap() {
  const res = await fetch('/api/bootstrap');
  if (!res.ok) {
    if (res.status === 401) window.location.href = '/';
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

async function uploadFile(file) {
  const formData = new FormData();
  formData.append('file', file);
  $('uploadStatus').textContent = `Parsing ${file.name} and storing it for this organization...`;
  const response = await fetch('/api/upload', { method: 'POST', body: formData });
  const data = await response.json();
  if (!response.ok) {
    $('uploadStatus').textContent = data.error || 'Upload failed.';
    return;
  }
  $('uploadStatus').textContent = `${data.filename} parsed successfully and stored in the database.`;
  await fetchBootstrap();
  await fetchLogs();
  setActiveNav('logsSection');
}

async function testS3() {
  const payload = Object.fromEntries(new FormData($('s3Form')).entries());
  $('s3Result').textContent = 'Testing S3 connection...';
  const response = await fetch('/api/integrations/s3/test', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  const data = await response.json();
  $('s3Result').textContent = data.success
    ? `${data.message}${data.objects?.length ? ` Sample: ${data.objects.map(o => o.key).join(', ')}` : ''}`
    : data.message;
}

async function testApi() {
  const payload = Object.fromEntries(new FormData($('apiForm')).entries());
  try {
    payload.headers = payload.headers ? JSON.parse(payload.headers) : {};
  } catch {
    $('apiResult').textContent = 'Headers must be valid JSON.';
    return;
  }
  $('apiResult').textContent = 'Testing API connection...';
  const response = await fetch('/api/integrations/api/test', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  const data = await response.json();
  $('apiResult').textContent = data.success
    ? `${data.message} Status ${data.status_code}. Preview: ${data.preview || 'No response body.'}`
    : data.message;
}

async function saveIntegration(kind, formId, resultId) {
  const payload = Object.fromEntries(new FormData($(formId)).entries());
  if (kind === 'api') {
    try { payload.headers = payload.headers ? JSON.parse(payload.headers) : {}; }
    catch { $(resultId).textContent = 'Headers must be valid JSON before saving.'; return; }
  }
  const res = await fetch('/api/integrations', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind, name: payload.name, status: 'configured', settings: payload }),
  });
  const data = await res.json();
  $(resultId).textContent = data.message || data.error || 'Integration saved.';
  await fetchBootstrap();
}

async function saveJob() {
  const payload = Object.fromEntries(new FormData($('jobForm')).entries());
  try { payload.details = payload.details ? JSON.parse(payload.details) : {}; }
  catch { $('jobResult').textContent = 'Job details must be valid JSON.'; return; }
  const res = await fetch('/api/jobs', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  const data = await res.json();
  $('jobResult').textContent = data.message || data.error || 'Job created.';
  await fetchBootstrap();
}

async function runJob(id) {
  const res = await fetch(`/api/jobs/${id}/run`, { method: 'POST' });
  const data = await res.json();
  $('jobResult').textContent = data.message || data.error || 'Job run completed.';
  await fetchBootstrap();
  await fetchLogs();
}

async function saveAlert() {
  const payload = Object.fromEntries(new FormData($('alertForm')).entries());
  const res = await fetch('/api/alerts', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  const data = await res.json();
  $('alertResult').textContent = data.message || data.error || 'Alert created.';
  await fetchBootstrap();
}

async function createUser() {
  const payload = Object.fromEntries(new FormData($('userForm')).entries());
  const res = await fetch('/api/users', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  const data = await res.json();
  $('userResult').textContent = data.message || data.error || 'User created.';
  if (res.ok) $('userForm').reset();
  await fetchBootstrap();
}

async function saveOrg() {
  const payload = Object.fromEntries(new FormData($('orgForm')).entries());
  payload.admin_only = $('orgForm').admin_only.checked;
  const res = await fetch('/api/org', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  const data = await res.json();
  $('orgResult').textContent = data.message || data.error || 'Organization saved.';
  await fetchBootstrap();
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

  $('logoutBtn').addEventListener('click', logout);
  $('searchBtn').addEventListener('click', fetchLogs);
  $('levelFilter').addEventListener('change', fetchLogs);
  $('logFileInput').addEventListener('change', (e) => {
    const file = e.target.files?.[0];
    if (file) uploadFile(file);
  });
  $('testS3Btn').addEventListener('click', testS3);
  $('saveS3Btn').addEventListener('click', () => saveIntegration('s3', 's3Form', 's3Result'));
  $('testApiBtn').addEventListener('click', testApi);
  $('saveApiBtn').addEventListener('click', () => saveIntegration('api', 'apiForm', 'apiResult'));
  $('createJobBtn').addEventListener('click', saveJob);
  $('createAlertBtn').addEventListener('click', saveAlert);
  $('createUserBtn').addEventListener('click', createUser);
  $('saveOrgBtn').addEventListener('click', saveOrg);
  $('closeModalBtn').addEventListener('click', () => $('logModal').close());

  document.addEventListener('click', (e) => {
    const row = e.target.closest('.log-row');
    if (row) showLogDetail(row.dataset.id);
    const runBtn = e.target.closest('.run-job-btn');
    if (runBtn) runJob(runBtn.dataset.jobId);
  });
}

(async function init() {
  bindEvents();
  await fetchBootstrap();
  await fetchLogs();
})();
