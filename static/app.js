const state = {
  records: [],
  summary: null,
  integrations: { s3: [], api: [] },
};

const $ = (id) => document.getElementById(id);

function formatNumber(value) {
  return new Intl.NumberFormat().format(value || 0);
}

function setActiveNav(sectionId) {
  document.querySelectorAll('.nav-link').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.section === sectionId);
  });
}

function renderMetrics() {
  const levels = state.summary?.levels || {};
  $('metricTotal').textContent = formatNumber(state.summary?.total || 0);
  $('metricErrors').textContent = formatNumber(levels.error || 0);
  $('metricWarn').textContent = formatNumber(levels.warn || 0);
  $('metricSources').textContent = formatNumber((state.summary?.sources || []).length);
}

function renderSources() {
  const el = $('sourceList');
  const sources = state.summary?.sources || [];
  if (!sources.length) {
    el.className = 'list-box empty-state';
    el.textContent = 'Upload data to populate source analytics.';
    return;
  }
  el.className = 'list-box';
  el.innerHTML = sources.map(([source, count]) => `
    <div class="list-item">
      <span>${escapeHtml(source)}</span>
      <strong>${formatNumber(count)}</strong>
    </div>
  `).join('');
}

function renderTerms() {
  const el = $('termList');
  const terms = state.summary?.top_terms || [];
  if (!terms.length) {
    el.className = 'tag-box empty-state';
    el.textContent = 'Upload data to see repeated operational terms.';
    return;
  }
  el.className = 'tag-box';
  el.innerHTML = terms.map(([term, count]) => `<span class="tag">${escapeHtml(term)} · ${count}</span>`).join('');
}

function badge(level) {
  return `<span class="level-badge level-${level}">${escapeHtml(level)}</span>`;
}

function filterRecords() {
  const q = $('searchInput').value.trim().toLowerCase();
  const level = $('levelFilter').value;
  return state.records.filter((record) => {
    const matchesLevel = level === 'all' || record.level === level;
    const blob = `${record.message} ${record.source} ${record.event_id}`.toLowerCase();
    const matchesQuery = !q || blob.includes(q);
    return matchesLevel && matchesQuery;
  });
}

function renderRecords() {
  const rows = filterRecords();
  const el = $('recordsBody');
  if (!rows.length) {
    el.innerHTML = '<tr><td colspan="5" class="empty-cell">No matching records.</td></tr>';
    return;
  }

  el.innerHTML = rows.slice(0, 200).map(record => `
    <tr>
      <td>${escapeHtml(record.timestamp)}</td>
      <td>${badge(record.level)}</td>
      <td>${escapeHtml(record.source || 'system')}</td>
      <td>${escapeHtml(record.event_id || '—')}</td>
      <td>${escapeHtml(record.message || '')}</td>
    </tr>
  `).join('');
}

function renderIntegrations() {
  const el = $('integrationList');
  const all = [...(state.integrations.s3 || []), ...(state.integrations.api || [])];
  if (!all.length) {
    el.className = 'list-box empty-state';
    el.textContent = 'No integrations saved yet.';
    return;
  }
  el.className = 'list-box';
  el.innerHTML = all.map(item => `
    <div class="list-item">
      <div>
        <strong>${escapeHtml(item.name)}</strong>
        <div class="muted">${escapeHtml(item.kind.toUpperCase())} · created ${escapeHtml(item.created_at)}</div>
      </div>
      <span class="pill">saved</span>
    </div>
  `).join('');
}

async function fetchIntegrations() {
  const res = await fetch('/api/integrations');
  state.integrations = await res.json();
  renderIntegrations();
}

async function uploadFile(file) {
  const formData = new FormData();
  formData.append('file', file);
  $('uploadStatus').textContent = `Parsing ${file.name}...`;

  const response = await fetch('/api/upload', { method: 'POST', body: formData });
  const data = await response.json();
  if (!response.ok) {
    $('uploadStatus').textContent = data.error || 'Upload failed.';
    return;
  }

  state.records = data.records || [];
  state.summary = data.summary || {};
  $('uploadStatus').textContent = `${data.filename} parsed successfully. Showing up to 200 recent records.`;
  renderMetrics();
  renderSources();
  renderTerms();
  renderRecords();
}

async function testS3() {
  const form = new FormData($('s3Form'));
  const payload = Object.fromEntries(form.entries());
  $('s3Result').textContent = 'Testing S3 connection...';
  const response = await fetch('/api/integrations/s3/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  $('s3Result').textContent = data.success
    ? `${data.message}${data.objects?.length ? ` Sample objects: ${data.objects.map(o => o.key).join(', ')}` : ''}`
    : data.message;
}

async function testApi() {
  const form = new FormData($('apiForm'));
  const payload = Object.fromEntries(form.entries());
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
    ? `${data.message} Status: ${data.status_code}. Preview: ${data.preview || 'No response body.'}`
    : data.message;
}

async function saveIntegration(kind, formId) {
  const form = new FormData($(formId));
  const payload = Object.fromEntries(form.entries());
  if (kind === 'api') {
    try {
      payload.headers = payload.headers ? JSON.parse(payload.headers) : {};
    } catch {
      $('apiResult').textContent = 'Headers must be valid JSON before saving.';
      return;
    }
  }
  const response = await fetch('/api/integrations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind, name: payload.name, settings: payload }),
  });
  const data = await response.json();
  if (kind === 's3') $('s3Result').textContent = data.message || 'Integration saved.';
  if (kind === 'api') $('apiResult').textContent = data.message || 'Integration saved.';
  await fetchIntegrations();
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

window.addEventListener('DOMContentLoaded', async () => {
  document.querySelectorAll('.nav-link').forEach(btn => {
    btn.addEventListener('click', () => {
      const section = document.getElementById(btn.dataset.section);
      section?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      setActiveNav(btn.dataset.section);
    });
  });

  $('jumpUpload').addEventListener('click', () => document.getElementById('upload').scrollIntoView({ behavior: 'smooth' }));
  $('jumpIntegrations').addEventListener('click', () => document.getElementById('integrations').scrollIntoView({ behavior: 'smooth' }));

  $('fileInput').addEventListener('change', (e) => {
    const [file] = e.target.files;
    if (file) uploadFile(file);
  });

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

  $('testS3Btn').addEventListener('click', testS3);
  $('testApiBtn').addEventListener('click', testApi);
  $('s3Form').addEventListener('submit', async (e) => { e.preventDefault(); await saveIntegration('s3', 's3Form'); });
  $('apiForm').addEventListener('submit', async (e) => { e.preventDefault(); await saveIntegration('api', 'apiForm'); });
  $('searchInput').addEventListener('input', renderRecords);
  $('levelFilter').addEventListener('change', renderRecords);

  await fetchIntegrations();
  renderMetrics();
});
