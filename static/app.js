const state = {
  bootstrap: null,
  records: [],
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
}

function applyOrgTheme() {
  const org = state.bootstrap?.organization;
  if (!org) return;
  document.documentElement.style.setProperty('--primary', org.theme_color || '#5b8cff');
  $('orgName').textContent = org.name;
  $('orgLogo').textContent = org.logo_text;
  $('orgSlug').textContent = org.slug;
  $('orgForm').name.value = org.name;
  $('orgForm').logo_text.value = org.logo_text;
  $('orgForm').theme_color.value = org.theme_color;
}

function renderSummary() {
  const summary = state.bootstrap?.summary || { totals: {}, levels: {}, source_breakdown: [], error_rate: 0 };
  $('metricLogs').textContent = formatNumber(summary.totals.logs || 0);
  $('metricIntegrations').textContent = formatNumber(summary.totals.integrations || 0);
  $('metricJobs').textContent = formatNumber(summary.totals.jobs || 0);
  $('metricAlerts').textContent = formatNumber(summary.totals.alerts || 0);
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
    <div class="list-item">
      <div>
        <strong>${escapeHtml(item.name)}</strong>
        <div class="muted">${escapeHtml(item.source_type.toUpperCase())} · ${escapeHtml(item.status)} · ${escapeHtml(item.schedule)}</div>
      </div>
      <span class="pill">job</span>
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
    <tr>
      <td>${escapeHtml(record.timestamp)}</td>
      <td>${badge(record.level)}</td>
      <td>${escapeHtml(record.source || 'system')}</td>
      <td>${escapeHtml(record.event_id || '—')}</td>
      <td>${escapeHtml(record.message || '')}</td>
    </tr>
  `).join('');
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
  state.bootstrap.summary = data.dashboard;
  renderSummary();
  await fetchLogs();
}

async function testS3() {
  const payload = Object.fromEntries(new FormData($('s3Form')).entries());
  $('s3Result').textContent = 'Testing S3 connection...';
  const response = await fetch('/api/integrations/s3/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
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
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  $('apiResult').textContent = data.success
    ? `${data.message} Status ${data.status_code}. Preview: ${data.preview || 'No response body.'}`
    : data.message;
}

async function saveIntegration(kind, formId, resultId) {
  const payload = Object.fromEntries(new FormData($(formId)).entries());
  if (kind === 'api') {
    try {
      payload.headers = payload.headers ? JSON.parse(payload.headers) : {};
    } catch {
      $(resultId).textContent = 'Headers must be valid JSON before saving.';
      return;
    }
  }
  const res = await fetch('/api/integrations', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind, name: payload.name, status: 'configured', settings: payload }),
  });
  const data = await res.json();
  $(resultId).textContent = data.message || 'Integration saved.';
  await fetchBootstrap();
}

async function saveJob() {
  const payload = Object.fromEntries(new FormData($('jobForm')).entries());
  try {
    payload.details = payload.details ? JSON.parse(payload.details) : {};
  } catch {
    $('jobResult').textContent = 'Job details must be valid JSON.';
    return;
  }
  const res = await fetch('/api/jobs', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  const data = await res.json();
  $('jobResult').textContent = data.message || 'Job created.';
  $('jobForm').reset();
  await fetchBootstrap();
}

async function saveAlert() {
  const payload = Object.fromEntries(new FormData($('alertForm')).entries());
  const res = await fetch('/api/alerts', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  const data = await res.json();
  $('alertResult').textContent = data.message || 'Alert created.';
  await fetchBootstrap();
}

async function saveOrg() {
  const payload = Object.fromEntries(new FormData($('orgForm')).entries());
  const res = await fetch('/api/org', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  const data = await res.json();
  $('orgResult').textContent = data.message || 'Organization updated.';
  await fetchBootstrap();
}

async function logout() {
  await fetch('/logout', { method: 'POST' });
  window.location.href = '/';
}

window.addEventListener('DOMContentLoaded', async () => {
  document.querySelectorAll('.nav-link').forEach(btn => {
    btn.addEventListener('click', () => {
      document.getElementById(btn.dataset.section)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      setActiveNav(btn.dataset.section);
    });
  });

  $('jumpUpload').addEventListener('click', () => $('upload').scrollIntoView({ behavior: 'smooth' }));
  $('jumpIntegrations').addEventListener('click', () => $('integrations').scrollIntoView({ behavior: 'smooth' }));
  $('logoutBtn').addEventListener('click', logout);

  $('fileInput').addEventListener('change', (e) => { const [file] = e.target.files; if (file) uploadFile(file); });
  const zone = $('uploadZone');
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const [file] = e.dataTransfer.files;
    if (file) uploadFile(file);
  });
  zone.addEventListener('click', () => $('fileInput').click());

  $('refreshLogsBtn').addEventListener('click', fetchLogs);
  $('searchInput').addEventListener('input', fetchLogs);
  $('levelFilter').addEventListener('change', fetchLogs);
  $('testS3Btn').addEventListener('click', testS3);
  $('testApiBtn').addEventListener('click', testApi);
  $('s3Form').addEventListener('submit', async (e) => { e.preventDefault(); await saveIntegration('s3', 's3Form', 's3Result'); });
  $('apiForm').addEventListener('submit', async (e) => { e.preventDefault(); await saveIntegration('api', 'apiForm', 'apiResult'); });
  $('jobForm').addEventListener('submit', async (e) => { e.preventDefault(); await saveJob(); });
  $('alertForm').addEventListener('submit', async (e) => { e.preventDefault(); await saveAlert(); });
  $('orgForm').addEventListener('submit', async (e) => { e.preventDefault(); await saveOrg(); });

  await fetchBootstrap();
  await fetchLogs();
});
