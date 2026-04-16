/* =====================================================
   ObserveX Enterprise — app.js v4
   All backend API calls preserved + UI enhancements
   ===================================================== */

'use strict';

// ─── State ────────────────────────────────────────────
const state = {
  bootstrap: null,
  records: [],
  charts: {},
  currentSection: 'overviewSection',
};

// ─── Tiny helpers ─────────────────────────────────────
const $ = (id) => document.getElementById(id);
const fmt = (v) => new Intl.NumberFormat().format(v || 0);

function escape(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function fmtTs(ts) {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'medium' });
  } catch { return ts; }
}

function initials(name) {
  return (name || '?').split(' ').map(p => p[0]).join('').slice(0, 2).toUpperCase();
}

// ─── Result box helper ────────────────────────────────
function setResult(elId, msg, type = '') {
  const el = $(elId);
  if (!el) return;
  el.textContent = msg;
  el.className = `result-box${type ? ' ' + type : ''}`;
}

// ─── Navigation ───────────────────────────────────────
const SECTION_LABELS = {
  overviewSection:      'Overview',
  logsSection:          'Log Explorer',
  integrationsSection:  'Integrations',
  jobsSection:          'Ingestion Jobs',
  alertsSection:        'Alert Rules',
  usersSection:         'Users & RBAC',
  orgSection:           'Organization',
  auditSection:         'Audit Trail',
};

function setActiveNav(sectionId) {
  if (!$(sectionId)) return;
  state.currentSection = sectionId;

  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.section === sectionId);
  });

  document.querySelectorAll('.section').forEach(sec => {
    sec.classList.toggle('active', sec.id === sectionId);
  });

  const label = SECTION_LABELS[sectionId] || sectionId;
  const eyebrow = $('pageSectionLabel');
  if (eyebrow) eyebrow.textContent = label;

  // Lazy load logs when switching to that section
  if (sectionId === 'logsSection' && state.records.length === 0) {
    fetchLogs();
  }
}

// ─── Apply org theme ──────────────────────────────────
function applyOrgTheme() {
  const org = state.bootstrap?.organization;
  if (!org) return;

  // CSS variable for primary accent
  document.documentElement.style.setProperty('--accent', org.theme_color || '#0a84ff');
  document.documentElement.style.setProperty('--accent-glow', hexToRgba(org.theme_color || '#0a84ff', 0.25));
  document.documentElement.style.setProperty('--accent-surface', hexToRgba(org.theme_color || '#0a84ff', 0.1));

  const orgLogo = $('orgLogo');
  if (orgLogo) orgLogo.textContent = org.logo_text || 'OX';

  const orgSlugDisplay = $('orgSlugDisplay');
  if (orgSlugDisplay) orgSlugDisplay.textContent = org.name || 'Enterprise';

  const orgNameDisplay = $('orgNameDisplay');
  if (orgNameDisplay) orgNameDisplay.textContent = `${org.name || 'Workspace'} — Workspace`;

  const adminModeBadge = $('adminModeBadge');
  if (adminModeBadge) {
    adminModeBadge.textContent = `Admin mode: ${org.admin_only ? 'on' : 'off'}`;
    adminModeBadge.className = org.admin_only ? 'pill-badge active-pill' : 'pill-badge';
  }

  const subdomainBadge = $('subdomainBadge');
  if (subdomainBadge) subdomainBadge.textContent = org.subdomain_hint || '';

  // Prefill org form
  if ($('orgName'))       $('orgName').value = org.name || '';
  if ($('orgSlug'))       $('orgSlug').value = org.slug || '';
  if ($('orgLogoText'))   $('orgLogoText').value = org.logo_text || '';
  if ($('orgThemeColor')) $('orgThemeColor').value = org.theme_color || '#0a84ff';
  if ($('orgAdminOnly'))  $('orgAdminOnly').checked = !!org.admin_only;
}

function hexToRgba(hex, alpha) {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r},${g},${b},${alpha})`;
}

// ─── Summary / metrics ────────────────────────────────
function renderSummary() {
  const summary = state.bootstrap?.summary || { totals: {}, levels: {}, source_breakdown: [], error_rate: 0 };
  const totals = summary.totals || {};

  if ($('metricLogs'))       animateCount($('metricLogs'), totals.logs || 0);
  if ($('metricUsers'))      animateCount($('metricUsers'), totals.users || 0);
  if ($('metricIntegrations')) animateCount($('metricIntegrations'), totals.integrations || 0);
  if ($('metricErrorRate'))  $('metricErrorRate').textContent = `${summary.error_rate || 0}%`;

  // Update logs badge in nav
  const logsBadge = $('logsBadge');
  if (logsBadge) logsBadge.textContent = fmt(totals.logs || 0);

  // Signal list
  const signalList = $('sourceSignalList');
  if (signalList) {
    const breakdown = summary.source_breakdown || [];
    const maxCount = Math.max(...breakdown.map(x => x.count), 1);
    if (!breakdown.length) {
      signalList.innerHTML = '<div class="empty-state"><span class="empty-icon">📡</span>Upload logs to populate analytics.</div>';
    } else {
      signalList.innerHTML = breakdown.map(item => `
        <div class="signal-row">
          <span class="signal-name">${escape(item.source)}</span>
          <div class="signal-bar-wrap">
            <div class="signal-bar" style="width: ${Math.round((item.count / maxCount) * 100)}%"></div>
          </div>
          <span class="signal-count">${fmt(item.count)}</span>
        </div>
      `).join('');
    }
  }

  renderCharts(summary);
}

function animateCount(el, target) {
  if (!el) return;
  const start = 0;
  const duration = 800;
  const startTime = performance.now();
  const formatted = fmt(target);
  if (target === 0) { el.textContent = '0'; return; }
  function step(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = fmt(Math.round(start + (target - start) * eased));
    if (progress < 1) requestAnimationFrame(step);
    else el.textContent = formatted;
  }
  requestAnimationFrame(step);
}

// ─── Charts ───────────────────────────────────────────
Chart.defaults.color = 'rgba(245,245,247,0.45)';
Chart.defaults.font.family = 'Inter, sans-serif';
Chart.defaults.font.size = 12;

function renderCharts(summary) {
  const levelData   = summary.levels   || {};
  const sourceData  = summary.source_breakdown || [];

  if (state.charts.levelChart)  state.charts.levelChart.destroy();
  if (state.charts.sourceChart) state.charts.sourceChart.destroy();

  const levelColors = {
    error:   'rgba(255,69,58,0.8)',
    warn:    'rgba(255,159,10,0.8)',
    info:    'rgba(10,132,255,0.8)',
    success: 'rgba(48,209,88,0.8)',
    debug:   'rgba(191,90,242,0.8)',
  };

  const levelCtx  = $('levelChart');
  const sourceCtx = $('sourceChart');

  if (levelCtx && Object.keys(levelData).length) {
    state.charts.levelChart = new Chart(levelCtx, {
      type: 'bar',
      data: {
        labels: Object.keys(levelData).map(l => l.toUpperCase()),
        datasets: [{
          data: Object.values(levelData),
          backgroundColor: Object.keys(levelData).map(l => levelColors[l] || 'rgba(245,245,247,0.4)'),
          borderRadius: 8,
          borderSkipped: false,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: 'rgba(12,12,18,0.95)',
            borderColor: 'rgba(255,255,255,0.1)',
            borderWidth: 1,
            titleColor: '#f5f5f7',
            bodyColor: 'rgba(245,245,247,0.6)',
            padding: 12,
            cornerRadius: 10,
          },
        },
        scales: {
          x: { grid: { color: 'rgba(255,255,255,0.04)' }, border: { display: false } },
          y: { grid: { color: 'rgba(255,255,255,0.04)' }, border: { display: false }, beginAtZero: true },
        },
        animation: { duration: 600, easing: 'easeOutQuart' },
      },
    });
  }

  if (sourceCtx && sourceData.length) {
    const palette = [
      'rgba(10,132,255,0.8)', 'rgba(48,209,88,0.8)', 'rgba(255,159,10,0.8)',
      'rgba(191,90,242,0.8)', 'rgba(255,69,58,0.8)', 'rgba(90,200,250,0.8)',
    ];
    state.charts.sourceChart = new Chart(sourceCtx, {
      type: 'doughnut',
      data: {
        labels: sourceData.map(x => x.source),
        datasets: [{
          data: sourceData.map(x => x.count),
          backgroundColor: palette,
          borderColor: 'rgba(12,12,18,0.9)',
          borderWidth: 3,
          hoverBorderWidth: 0,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '68%',
        plugins: {
          legend: {
            position: 'right',
            labels: { boxWidth: 10, padding: 16, font: { size: 12 } },
          },
          tooltip: {
            backgroundColor: 'rgba(12,12,18,0.95)',
            borderColor: 'rgba(255,255,255,0.1)',
            borderWidth: 1,
            titleColor: '#f5f5f7',
            bodyColor: 'rgba(245,245,247,0.6)',
            padding: 12,
            cornerRadius: 10,
          },
        },
        animation: { duration: 600, easing: 'easeOutQuart' },
      },
    });
  }
}

// ─── Render integrations ──────────────────────────────
function renderIntegrations() {
  const list  = $('integrationList');
  const items = state.bootstrap?.integrations || [];
  if (!list) return;
  if (!items.length) {
    list.innerHTML = '<div class="empty-state"><span class="empty-icon">🔌</span>No integrations saved yet.</div>';
    return;
  }
  list.innerHTML = items.map(item => `
    <div class="list-item">
      <div class="list-item-main">
        <span class="list-item-title">${escape(item.name)}</span>
        <span class="list-item-sub">${escape(item.kind?.toUpperCase())} · ${escape(item.status)}</span>
      </div>
      <div class="list-item-actions">
        <span class="status-tag ${item.status === 'healthy' ? 'tag-green' : 'tag-blue'}">${escape(item.status)}</span>
      </div>
    </div>
  `).join('');
}

// ─── Render jobs ──────────────────────────────────────
function renderJobs() {
  const list  = $('jobsList');
  const items = state.bootstrap?.jobs || [];
  if (!list) return;
  if (!items.length) {
    list.innerHTML = '<div class="empty-state"><span class="empty-icon">⏰</span>No ingestion jobs configured yet.</div>';
    return;
  }
  list.innerHTML = items.map(item => `
    <div class="list-item" style="flex-direction:column;align-items:start;gap:10px;">
      <div style="display:flex;align-items:center;justify-content:space-between;width:100%;gap:10px;">
        <div class="list-item-main">
          <span class="list-item-title">${escape(item.name)}</span>
          <span class="list-item-sub">${escape(item.source_type?.toUpperCase())} · ${escape(item.schedule)}</span>
          <span class="list-item-sub" style="margin-top:2px;">Last run: ${escape(fmtTs(item.last_run_at) || 'Never')} · Next: ${escape(fmtTs(item.next_run_at) || 'Pending')}</span>
        </div>
        <div class="list-item-actions">
          <span class="status-tag ${item.status === 'scheduled' ? 'tag-green' : 'tag-amber'}">${escape(item.status)}</span>
          <button class="btn-secondary run-job-btn" data-job-id="${item.id}" style="font-size:12px;padding:7px 14px;">▶ Run</button>
        </div>
      </div>
    </div>
  `).join('');
}

// ─── Render alerts ────────────────────────────────────
const SEV_TAGS = { sev1: 'tag-red', sev2: 'tag-amber', sev3: 'tag-blue' };

function renderAlerts() {
  const list  = $('alertsList');
  const items = state.bootstrap?.alerts || [];
  if (!list) return;
  if (!items.length) {
    list.innerHTML = '<div class="empty-state"><span class="empty-icon">🔔</span>No alert rules configured yet.</div>';
    return;
  }
  list.innerHTML = items.map(item => `
    <div class="list-item" style="flex-direction:column;align-items:start;gap:8px;">
      <div style="display:flex;align-items:center;justify-content:space-between;width:100%;gap:10px;">
        <span class="list-item-title">${escape(item.name)}</span>
        <div style="display:flex;gap:6px;align-items:center;flex-shrink:0;">
          <span class="status-tag ${SEV_TAGS[item.severity] || 'tag-gray'}">${escape(item.severity?.toUpperCase())}</span>
          <span class="status-tag ${item.status === 'active' ? 'tag-green' : 'tag-gray'}">${escape(item.status)}</span>
        </div>
      </div>
      <span class="list-item-sub">${escape(item.channel)} · <em style="font-style:normal;color:var(--text-tertiary);">${escape(item.condition_text)}</em></span>
    </div>
  `).join('');
}

// ─── Render users ─────────────────────────────────────
const ROLE_TAGS = { admin: 'tag-red', analyst: 'tag-blue', member: 'tag-gray' };

function renderUsers() {
  const list  = $('userList');
  const items = state.bootstrap?.users || [];
  if (!list) return;
  if (!items.length) {
    list.innerHTML = '<div class="empty-state"><span class="empty-icon">👤</span>No users found.</div>';
    return;
  }
  list.innerHTML = items.map(item => `
    <div class="list-item">
      <div style="display:flex;align-items:center;gap:12px;">
        <div style="width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,#5e35e0,#0a84ff);display:flex;align-items:center;justify-content:center;font-weight:600;font-size:13px;color:#fff;flex-shrink:0;">${initials(item.name)}</div>
        <div class="list-item-main">
          <span class="list-item-title">${escape(item.name)}</span>
          <span class="list-item-sub">${escape(item.email)}</span>
        </div>
      </div>
      <span class="status-tag ${ROLE_TAGS[item.role] || 'tag-gray'}">${escape(item.role)}</span>
    </div>
  `).join('');
}

// ─── Render audit ─────────────────────────────────────
function renderAudit() {
  const list  = $('auditList');
  const items = state.bootstrap?.audit || [];
  if (!list) return;
  if (!items.length) {
    list.innerHTML = '<div class="empty-state"><span class="empty-icon">📋</span>No audit events yet.</div>';
    return;
  }
  list.innerHTML = items.map(item => `
    <div class="audit-item">
      <div class="audit-dot"></div>
      <div class="audit-content">
        <span class="audit-action">${escape(item.action)}</span>
        <span class="audit-meta">${escape(item.target_type)} · ${escape(item.target_id || '—')} · ${escape(fmtTs(item.created_at))}</span>
      </div>
    </div>
  `).join('');
}

// ─── Render log records ───────────────────────────────
function levelBadge(level) {
  return `<span class="level-badge level-${escape(level)}">${escape(level)}</span>`;
}

function renderRecords() {
  const body = $('recordsBody');
  if (!body) return;
  if (!state.records.length) {
    body.innerHTML = '<tr class="empty-row"><td colspan="5">No matching records. Upload logs or adjust your filter.</td></tr>';
    return;
  }
  body.innerHTML = state.records.map(r => `
    <tr class="log-row" data-id="${r.id}">
      <td class="ts-cell">${escape(fmtTs(r.timestamp))}</td>
      <td>${levelBadge(r.level)}</td>
      <td class="src-cell">${escape(r.source || 'system')}</td>
      <td class="evid-cell">${escape(r.event_id || '—')}</td>
      <td class="msg-cell"><span class="msg-text">${escape(r.message || '')}</span></td>
    </tr>
  `).join('');
}

// ─── Log detail modal ─────────────────────────────────
async function showLogDetail(id) {
  const res = await fetch(`/api/logs/${id}`);
  if (!res.ok) return;
  const data = await res.json();

  const logMeta = $('logMeta');
  if (logMeta) {
    logMeta.innerHTML = [
      { label: 'Timestamp', value: fmtTs(data.timestamp) },
      { label: 'Level',     value: data.level },
      { label: 'Source',    value: data.source },
      { label: 'Event ID',  value: data.event_id || '—' },
    ].map(cell => `
      <div class="meta-cell">
        <span class="meta-label">${cell.label}</span>
        <span class="meta-value">${escape(cell.value)}</span>
      </div>
    `).join('');
  }

  const logPayload = $('logPayload');
  if (logPayload) logPayload.textContent = JSON.stringify(data.payload, null, 2);

  const modal = $('logModal');
  if (modal) modal.classList.add('open');
}

function closeModal() {
  const modal = $('logModal');
  if (modal) modal.classList.remove('open');
}

// ─── Bootstrap ────────────────────────────────────────
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

  // Populate user display
  const user = state.bootstrap.user;
  if (user) {
    if ($('userNameDisplay')) $('userNameDisplay').textContent = user.name || '';
    if ($('userRoleDisplay')) $('userRoleDisplay').textContent = user.role || '';
    if ($('userAvatarInitials')) $('userAvatarInitials').textContent = initials(user.name);
  }
}

// ─── Fetch logs ───────────────────────────────────────
async function fetchLogs() {
  const q     = ($('searchInput')?.value || '').trim();
  const level = $('levelFilter')?.value || 'all';
  const params = new URLSearchParams({ q, level });

  const body = $('recordsBody');
  if (body) body.innerHTML = '<tr class="empty-row"><td colspan="5">Loading…</td></tr>';

  const res  = await fetch(`/api/logs?${params}`);
  const data = await res.json();
  state.records = data.records || [];
  renderRecords();
}

// ─── Upload ───────────────────────────────────────────
async function uploadFile(file) {
  const formData = new FormData();
  formData.append('file', file);
  setResult('uploadStatus', `Parsing ${file.name}…`, 'info');

  const res  = await fetch('/api/upload', { method: 'POST', body: formData });
  const data = await res.json();

  if (!res.ok) {
    setResult('uploadStatus', data.error || 'Upload failed.', 'err');
    return;
  }
  setResult('uploadStatus', `✓ ${data.filename} — ${fmt(data.summary?.total || 0)} records ingested.`, 'ok');
  await fetchBootstrap();
  await fetchLogs();
  setActiveNav('logsSection');
}

// ─── S3 integration ───────────────────────────────────
async function testS3() {
  setResult('s3Result', 'Testing S3 connection…', 'info');
  const payload = {
    name:       $('s3Name')?.value,
    region:     $('s3Region')?.value,
    bucket:     $('s3Bucket')?.value,
    prefix:     $('s3Prefix')?.value,
    access_key: $('s3AccessKey')?.value,
    secret_key: $('s3SecretKey')?.value,
  };
  const res  = await fetch('/api/integrations/s3/test', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  const data = await res.json();
  setResult('s3Result', data.success
    ? `✓ ${data.message}${data.objects?.length ? ` Sample keys: ${data.objects.slice(0,3).map(o => o.key).join(', ')}` : ''}`
    : `✗ ${data.message}`,
    data.success ? 'ok' : 'err'
  );
}

async function saveS3() {
  const payload = {
    name:       $('s3Name')?.value,
    region:     $('s3Region')?.value,
    bucket:     $('s3Bucket')?.value,
    prefix:     $('s3Prefix')?.value,
    access_key: $('s3AccessKey')?.value,
    secret_key: $('s3SecretKey')?.value,
  };
  const res  = await fetch('/api/integrations', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 's3', name: payload.name, status: 'configured', settings: payload }),
  });
  const data = await res.json();
  setResult('s3Result', data.message || data.error || 'Saved.', res.ok ? 'ok' : 'err');
  if (res.ok) await fetchBootstrap();
}

// ─── API integration ──────────────────────────────────
async function testApi() {
  setResult('apiResult', 'Testing API connection…', 'info');
  let headers = {};
  try {
    const raw = $('apiHeaders')?.value?.trim();
    if (raw) headers = JSON.parse(raw);
  } catch {
    setResult('apiResult', '✗ Headers field must be valid JSON.', 'err'); return;
  }
  const payload = { url: $('apiUrl')?.value, token: $('apiToken')?.value, headers };
  const res  = await fetch('/api/integrations/api/test', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  const data = await res.json();
  setResult('apiResult', data.success
    ? `✓ ${data.message} Status ${data.status_code}. Preview: ${(data.preview || '').slice(0, 200)}`
    : `✗ ${data.message}`,
    data.success ? 'ok' : 'err'
  );
}

async function saveApi() {
  let headers = {};
  try {
    const raw = $('apiHeaders')?.value?.trim();
    if (raw) headers = JSON.parse(raw);
  } catch {
    setResult('apiResult', '✗ Headers must be valid JSON before saving.', 'err'); return;
  }
  const payload = {
    name:    $('apiName')?.value,
    url:     $('apiUrl')?.value,
    token:   $('apiToken')?.value,
    headers,
  };
  const res  = await fetch('/api/integrations', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 'api', name: payload.name, status: 'configured', settings: payload }),
  });
  const data = await res.json();
  setResult('apiResult', data.message || data.error || 'Saved.', res.ok ? 'ok' : 'err');
  if (res.ok) await fetchBootstrap();
}

// ─── Jobs ─────────────────────────────────────────────
async function createJob() {
  let details = {};
  try {
    const raw = $('jobDetails')?.value?.trim();
    if (raw) details = JSON.parse(raw);
  } catch {
    setResult('jobResult', '✗ Job details must be valid JSON.', 'err'); return;
  }
  const payload = {
    name:        $('jobName')?.value,
    source_type: $('jobSourceType')?.value,
    status:      $('jobStatus')?.value,
    schedule:    $('jobSchedule')?.value,
    details,
  };
  const res  = await fetch('/api/jobs', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  const data = await res.json();
  setResult('jobResult', data.message || data.error || 'Job created.', res.ok ? 'ok' : 'err');
  if (res.ok) await fetchBootstrap();
}

async function runJob(id) {
  setResult('jobResult', 'Running job…', 'info');
  const res  = await fetch(`/api/jobs/${id}/run`, { method: 'POST' });
  const data = await res.json();
  setResult('jobResult', data.message || data.error || 'Job run completed.', data.success ? 'ok' : 'err');
  if (data.success) {
    await fetchBootstrap();
    await fetchLogs();
  }
}

// ─── Alerts ───────────────────────────────────────────
async function createAlert() {
  const payload = {
    name:           $('alertName')?.value,
    severity:       $('alertSeverity')?.value,
    channel:        $('alertChannel')?.value,
    status:         $('alertStatus')?.value,
    condition_text: $('alertCondition')?.value,
  };
  const res  = await fetch('/api/alerts', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  const data = await res.json();
  setResult('alertResult', data.message || data.error || 'Alert created.', res.ok ? 'ok' : 'err');
  if (res.ok) await fetchBootstrap();
}

// ─── Users ────────────────────────────────────────────
async function createUser() {
  const payload = {
    name:     $('userName')?.value,
    email:    $('userEmail')?.value,
    password: $('userPassword')?.value,
    role:     $('userRole')?.value,
  };
  if (!payload.name || !payload.email || !payload.password) {
    setResult('userResult', '✗ Name, email, and password are required.', 'err'); return;
  }
  const res  = await fetch('/api/users', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  const data = await res.json();
  setResult('userResult', data.message || data.error || 'User created.', res.ok ? 'ok' : 'err');
  if (res.ok) {
    if ($('userName'))    $('userName').value    = '';
    if ($('userEmail'))   $('userEmail').value   = '';
    if ($('userPassword')) $('userPassword').value = '';
    await fetchBootstrap();
  }
}

// ─── Org settings ─────────────────────────────────────
async function saveOrg() {
  const payload = {
    name:        $('orgName')?.value,
    slug:        $('orgSlug')?.value,
    logo_text:   $('orgLogoText')?.value,
    theme_color: $('orgThemeColor')?.value,
    admin_only:  !!$('orgAdminOnly')?.checked,
  };
  const res  = await fetch('/api/org', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  const data = await res.json();
  setResult('orgResult', data.message || data.error || 'Settings saved.', res.ok ? 'ok' : 'err');
  if (res.ok) await fetchBootstrap();
}

// ─── Logout ───────────────────────────────────────────
async function logout() {
  await fetch('/logout', { method: 'POST' });
  window.location.href = '/';
}

// ─── Drag and drop ────────────────────────────────────
function initDropZone() {
  const zone = $('dropZone');
  if (!zone) return;

  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const file = e.dataTransfer.files?.[0];
    if (file) uploadFile(file);
  });
}

// ─── Event bindings ───────────────────────────────────
function bindEvents() {
  // Navigation
  document.querySelectorAll('.nav-item[data-section]').forEach(btn => {
    btn.addEventListener('click', () => setActiveNav(btn.dataset.section));
  });

  document.querySelectorAll('[data-jump]').forEach(btn => {
    btn.addEventListener('click', () => setActiveNav(btn.dataset.jump));
  });

  // Log out
  $('logoutBtn')?.addEventListener('click', logout);

  // Log search
  $('searchBtn')?.addEventListener('click', fetchLogs);
  $('levelFilter')?.addEventListener('change', fetchLogs);
  $('searchInput')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') fetchLogs(); });

  // File upload
  $('logFileInput')?.addEventListener('change', (e) => {
    const file = e.target.files?.[0];
    if (file) uploadFile(file);
  });

  // S3
  $('testS3Btn')?.addEventListener('click', testS3);
  $('saveS3Btn')?.addEventListener('click', saveS3);

  // API
  $('testApiBtn')?.addEventListener('click', testApi);
  $('saveApiBtn')?.addEventListener('click', saveApi);

  // Jobs
  $('createJobBtn')?.addEventListener('click', createJob);

  // Alerts
  $('createAlertBtn')?.addEventListener('click', createAlert);

  // Users
  $('createUserBtn')?.addEventListener('click', createUser);

  // Org
  $('saveOrgBtn')?.addEventListener('click', saveOrg);

  // Modal
  $('closeModalBtn')?.addEventListener('click', closeModal);
  $('logModal')?.addEventListener('click', (e) => {
    if (e.target === $('logModal')) closeModal();
  });

  // Log row click
  document.addEventListener('click', (e) => {
    const row    = e.target.closest('.log-row');
    const runBtn = e.target.closest('.run-job-btn');
    if (row)    showLogDetail(row.dataset.id);
    if (runBtn) runJob(runBtn.dataset.jobId);
  });

  // Close modal on Escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
  });

  // Live color preview
  $('orgThemeColor')?.addEventListener('input', (e) => {
    document.documentElement.style.setProperty('--accent', e.target.value);
  });
}

// ─── Init ─────────────────────────────────────────────
(async function init() {
  bindEvents();
  initDropZone();

  // Staggered entry animations for metric cards
  document.querySelectorAll('.metric-card').forEach((card, i) => {
    card.style.animationDelay = `${i * 0.08}s`;
    card.style.animation = `fadeSlideUp 0.6s cubic-bezier(0.16,1,0.3,1) ${i * 0.08}s both`;
  });

  await fetchBootstrap();
  // Pre-load logs in background so switching is instant
  fetchLogs();
})();
