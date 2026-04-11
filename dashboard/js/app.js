/**
 * Sentinel Dashboard — Main application logic
 *
 * Security note: All dynamic values are passed through Utils.escapeHtml()
 * before DOM insertion. JSON evidence is rendered via JSON.stringify which
 * produces safe output. No raw user input is ever inserted unescaped.
 */

const App = (() => {
  /* ------------------------------------------------------------------ */
  /*  State                                                              */
  /* ------------------------------------------------------------------ */

  let currentView = 'status';
  let refreshInterval = 5000; // ms
  let refreshTimer = null;
  let alertPage = 1;
  let alertSortDir = {};
  let deviceSortDir = {};
  let logSortDir = {};
  let knownAlertIds = new Set();

  /* ------------------------------------------------------------------ */
  /*  Mock data — shown when the service is not running                  */
  /* ------------------------------------------------------------------ */

  const MOCK = {
    status: {
      service: 'running',
      driver: 'loaded',
      uptime_seconds: 87432,
      version: '1.0.0',
      detection_count: 147,
      active_protections: 4,
      last_scan: Date.now() / 1000 - 120,
    },
    devices: [
      { vendor_id: '0x8086', device_id: '0x1533', name: 'Intel I210 Gigabit NIC', trust: 'trusted', class: 'Network Controller', first_seen: Date.now() / 1000 - 864000, last_seen: Date.now() / 1000 - 30 },
      { vendor_id: '0x10DE', device_id: '0x2684', name: 'NVIDIA GeForce RTX 4090', trust: 'trusted', class: 'Display Controller', first_seen: Date.now() / 1000 - 864000, last_seen: Date.now() / 1000 - 10 },
      { vendor_id: '0x1022', device_id: '0x43F7', name: 'AMD USB 3.2 Host Controller', trust: 'trusted', class: 'USB Controller', first_seen: Date.now() / 1000 - 864000, last_seen: Date.now() / 1000 - 5 },
      { vendor_id: '0x1D6A', device_id: '0x0001', name: 'Unknown FPGA Device', trust: 'suspicious', class: 'Memory Controller', first_seen: Date.now() / 1000 - 300, last_seen: Date.now() / 1000 - 15 },
      { vendor_id: '0xFFFF', device_id: '0x0100', name: 'Unidentified PCIe Bridge', trust: 'blocked', class: 'PCI Bridge', first_seen: Date.now() / 1000 - 60, last_seen: Date.now() / 1000 - 60 },
      { vendor_id: '0x14E4', device_id: '0x43A0', name: 'Broadcom BCM4360 Wireless', trust: 'trusted', class: 'Network Controller', first_seen: Date.now() / 1000 - 864000, last_seen: Date.now() / 1000 - 2 },
    ],
    alerts: {
      page: 1,
      total_pages: 3,
      total: 28,
      items: [
        { id: 'a001', severity: 'critical', source: 'dma_detect', message: 'Unauthorized DMA read detected from unknown FPGA device targeting game memory region 0x7FF60000-0x7FF6FFFF', confidence: 94, timestamp: Date.now() / 1000 - 45, evidence: { device: '0x1D6A:0x0001', target_region: '0x7FF60000-0x7FF6FFFF', access_type: 'read', iommu_bypass: false, timing_anomaly: true } },
        { id: 'a002', severity: 'high', source: 'pcie_enum', message: 'New PCIe device appeared during active session — possible hot-plug DMA hardware', confidence: 78, timestamp: Date.now() / 1000 - 120, evidence: { vendor_id: '0xFFFF', device_id: '0x0100', class: 'PCI Bridge', pnp_event: 'arrival' } },
        { id: 'a003', severity: 'high', source: 'memory_integrity', message: 'Page table modification detected for protected memory region', confidence: 85, timestamp: Date.now() / 1000 - 300, evidence: { region: '0x7FF60000-0x7FF6FFFF', modification: 'PTE write bit changed', source_process: 'unknown' } },
        { id: 'a004', severity: 'medium', source: 'process_monitor', message: 'Suspicious process detected: cheatengine-x86_64.exe with debug privileges', confidence: 92, timestamp: Date.now() / 1000 - 600, evidence: { process: 'cheatengine-x86_64.exe', pid: 4812, privileges: ['SeDebugPrivilege'], parent: 'explorer.exe' } },
        { id: 'a005', severity: 'medium', source: 'signature_scanner', message: 'Known cheat signature match in loaded module injected into game process', confidence: 88, timestamp: Date.now() / 1000 - 900, evidence: { module: 'unk_overlay.dll', pattern: 'SIG_AIMBOT_V3', match_offset: '0x1A40', process: 'game.exe' } },
        { id: 'a006', severity: 'low', source: 'module_integrity', message: 'Minor hash mismatch in non-critical game module — possible update in progress', confidence: 35, timestamp: Date.now() / 1000 - 1800, evidence: { module: 'game_audio.dll', expected_hash: 'a1b2c3d4', actual_hash: 'e5f6a7b8', bytes_changed: 128 } },
        { id: 'a007', severity: 'low', source: 'device_monitor', message: 'USB device connected during session — standard HID device', confidence: 15, timestamp: Date.now() / 1000 - 3600, evidence: { vendor_id: '0x046D', device_id: '0xC52B', class: 'HID', description: 'Logitech Unifying Receiver' } },
      ],
    },
    config: {
      scan_interval_ms: 2000,
      alert_poll_interval_ms: 1000,
      detection_threshold: 70,
      iommu_check_enabled: true,
      pcie_rescan_on_pnp: true,
      whitelist: [
        '0x8086:0x1533',
        '0x10DE:0x2684',
        '0x1022:0x43F7',
        '0x14E4:0x43A0',
      ],
    },
    stats: {
      total_scans: 43780,
      total_alerts: 147,
      alerts_by_severity: { critical: 3, high: 18, medium: 42, low: 84 },
      alerts_by_source: { dma_detect: 12, pcie_enum: 24, memory_integrity: 31, process_monitor: 38, signature_scanner: 27, module_integrity: 9, device_monitor: 6 },
      devices_scanned: 6,
      uptime_seconds: 87432,
    },
    logs: [
      { timestamp: Date.now() / 1000 - 10, level: 'info', source: 'service', message: 'Periodic PCIe device scan completed — 6 devices enumerated' },
      { timestamp: Date.now() / 1000 - 30, level: 'warn', source: 'dma_detect', message: 'Timing anomaly detected on bus device 0x1D6A:0x0001' },
      { timestamp: Date.now() / 1000 - 45, level: 'error', source: 'dma_detect', message: 'Unauthorized DMA read from 0x1D6A:0x0001 targeting 0x7FF60000' },
      { timestamp: Date.now() / 1000 - 60, level: 'warn', source: 'pcie_enum', message: 'Unknown device appeared: 0xFFFF:0x0100 (PCI Bridge)' },
      { timestamp: Date.now() / 1000 - 120, level: 'info', source: 'device_monitor', message: 'PnP arrival event — triggering PCIe rescan' },
      { timestamp: Date.now() / 1000 - 180, level: 'info', source: 'process_monitor', message: 'Process scan: 142 processes enumerated, 1 flagged' },
      { timestamp: Date.now() / 1000 - 300, level: 'error', source: 'memory_integrity', message: 'PTE modification detected on protected region 0x7FF60000-0x7FF6FFFF' },
      { timestamp: Date.now() / 1000 - 600, level: 'warn', source: 'process_monitor', message: 'Suspicious process: cheatengine-x86_64.exe (PID 4812) with SeDebugPrivilege' },
      { timestamp: Date.now() / 1000 - 900, level: 'warn', source: 'signature_scanner', message: 'Signature match: SIG_AIMBOT_V3 in unk_overlay.dll at offset 0x1A40' },
      { timestamp: Date.now() / 1000 - 1200, level: 'info', source: 'driver_comm', message: 'Driver heartbeat OK — ring buffer 12% utilized' },
      { timestamp: Date.now() / 1000 - 1500, level: 'info', source: 'service', message: 'Configuration reloaded — detection threshold set to 70' },
      { timestamp: Date.now() / 1000 - 1800, level: 'info', source: 'module_integrity', message: 'Module scan: 48 modules verified, 1 minor mismatch (game_audio.dll)' },
    ],
  };

  /* ------------------------------------------------------------------ */
  /*  Data fetchers (fall back to mock when service is unreachable)      */
  /* ------------------------------------------------------------------ */

  async function fetchData(apiFn, mockKey) {
    try {
      return await apiFn();
    } catch {
      return typeof mockKey === 'function' ? mockKey() : MOCK[mockKey];
    }
  }

  /* ------------------------------------------------------------------ */
  /*  Safe DOM helpers                                                   */
  /* ------------------------------------------------------------------ */

  /**
   * Set sanitized HTML on an element. All dynamic values in the HTML
   * strings built by this module are escaped via Utils.escapeHtml()
   * before interpolation, so the resulting markup is safe.
   */
  function setContent(el, html) {
    if (typeof el === 'string') el = document.getElementById(el);
    if (el) el.innerHTML = html; // eslint-disable-line no-unsanitized/property
  }

  /* ------------------------------------------------------------------ */
  /*  Toast notifications                                                */
  /* ------------------------------------------------------------------ */

  function showToast(title, body, severity) {
    const container = document.getElementById('toast-container');
    const el = document.createElement('div');
    const cls = severity === 'critical' ? ' toast--critical' : severity === 'high' ? ' toast--high' : '';
    el.className = 'toast' + cls;

    const titleDiv = document.createElement('div');
    titleDiv.className = 'toast__title';
    titleDiv.textContent = title;

    const bodyDiv = document.createElement('div');
    bodyDiv.className = 'toast__body';
    bodyDiv.textContent = body;

    el.appendChild(titleDiv);
    el.appendChild(bodyDiv);
    container.appendChild(el);

    setTimeout(() => {
      el.classList.add('toast--out');
      el.addEventListener('animationend', () => el.remove());
    }, 5000);
  }

  /* ------------------------------------------------------------------ */
  /*  Navigation                                                         */
  /* ------------------------------------------------------------------ */

  function navigate(view) {
    currentView = view;
    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('nav-item--active', el.dataset.view === view);
    });
    document.querySelectorAll('.view').forEach(el => {
      el.classList.toggle('view--active', el.id === 'view-' + view);
    });
    document.getElementById('topbar-title').textContent = view.charAt(0).toUpperCase() + view.slice(1);

    // Close mobile sidebar
    document.querySelector('.sidebar').classList.remove('sidebar--open');

    renderCurrentView();
  }

  /* ------------------------------------------------------------------ */
  /*  View: Status                                                       */
  /* ------------------------------------------------------------------ */

  async function renderStatus() {
    const [status, stats] = await Promise.all([
      fetchData(API.getStatus, 'status'),
      fetchData(API.getStats, 'stats'),
    ]);

    const s = status;
    const sourceCards = Object.entries(stats.alerts_by_source || {}).map(function(entry) {
      return '<div class="card">'
        + '<div class="card__label">' + Utils.escapeHtml(entry[0].replace(/_/g, ' ')) + '</div>'
        + '<div class="card__value">' + Utils.escapeHtml(String(entry[1])) + '</div>'
        + '</div>';
    }).join('');

    const html = ''
      + '<div class="card-grid">'
      +   '<div class="card">'
      +     '<div class="card__label">Service Status</div>'
      +     '<div class="card__value card__value--accent">' + Utils.statusDot(s.service === 'running') + ' ' + Utils.escapeHtml(s.service || 'unknown') + '</div>'
      +   '</div>'
      +   '<div class="card">'
      +     '<div class="card__label">Driver Status</div>'
      +     '<div class="card__value card__value--accent">' + Utils.statusDot(s.driver === 'loaded') + ' ' + Utils.escapeHtml(s.driver || 'unknown') + '</div>'
      +   '</div>'
      +   '<div class="card">'
      +     '<div class="card__label">Uptime</div>'
      +     '<div class="card__value">' + Utils.escapeHtml(Utils.formatUptime(s.uptime_seconds)) + '</div>'
      +   '</div>'
      +   '<div class="card">'
      +     '<div class="card__label">Active Protections</div>'
      +     '<div class="card__value card__value--accent">' + Utils.escapeHtml(String(s.active_protections ?? 0)) + '</div>'
      +   '</div>'
      +   '<div class="card">'
      +     '<div class="card__label">Total Detections</div>'
      +     '<div class="card__value">' + Utils.escapeHtml(String(stats.total_alerts ?? s.detection_count ?? 0)) + '</div>'
      +   '</div>'
      +   '<div class="card">'
      +     '<div class="card__label">Last Scan</div>'
      +     '<div class="card__value" style="font-size:16px">' + Utils.escapeHtml(Utils.formatTimestamp(s.last_scan)) + '</div>'
      +   '</div>'
      + '</div>'
      + '<div class="section-header"><h2>Alerts by Severity</h2></div>'
      + '<div class="card-grid">'
      +   '<div class="card"><div class="card__label">Critical</div><div class="card__value card__value--critical">' + Utils.escapeHtml(String(stats.alerts_by_severity?.critical ?? 0)) + '</div></div>'
      +   '<div class="card"><div class="card__label">High</div><div class="card__value" style="color:var(--high)">' + Utils.escapeHtml(String(stats.alerts_by_severity?.high ?? 0)) + '</div></div>'
      +   '<div class="card"><div class="card__label">Medium</div><div class="card__value" style="color:var(--medium)">' + Utils.escapeHtml(String(stats.alerts_by_severity?.medium ?? 0)) + '</div></div>'
      +   '<div class="card"><div class="card__label">Low</div><div class="card__value" style="color:var(--low)">' + Utils.escapeHtml(String(stats.alerts_by_severity?.low ?? 0)) + '</div></div>'
      + '</div>'
      + '<div class="section-header"><h2>Detection Sources</h2></div>'
      + '<div class="card-grid">' + sourceCards + '</div>';

    setContent('view-status', html);
  }

  /* ------------------------------------------------------------------ */
  /*  View: Devices                                                      */
  /* ------------------------------------------------------------------ */

  async function renderDevices() {
    const devices = await fetchData(API.getDevices, 'devices');
    const el = document.getElementById('view-devices');

    function buildTable(data) {
      if (!data || data.length === 0) {
        return '<div class="empty-state"><div class="empty-state__icon">&#x2693;</div><div class="empty-state__text">No devices detected</div></div>';
      }
      var rows = data.map(function(d) {
        return '<tr>'
          + '<td class="mono">' + Utils.escapeHtml(d.vendor_id) + '</td>'
          + '<td class="mono">' + Utils.escapeHtml(d.device_id) + '</td>'
          + '<td>' + Utils.escapeHtml(d.name || '\u2014') + '</td>'
          + '<td>' + Utils.escapeHtml(d.class || '\u2014') + '</td>'
          + '<td>' + Utils.trustBadge(d.trust) + '</td>'
          + '<td class="mono">' + Utils.escapeHtml(Utils.formatTimestamp(d.first_seen)) + '</td>'
          + '<td class="mono">' + Utils.escapeHtml(Utils.formatTimestamp(d.last_seen)) + '</td>'
          + '</tr>';
      }).join('');

      return '<table>'
        + '<thead><tr>'
        + '<th data-sort="vendor_id">Vendor ID</th>'
        + '<th data-sort="device_id">Device ID</th>'
        + '<th data-sort="name">Name</th>'
        + '<th data-sort="class">Class</th>'
        + '<th data-sort="trust">Trust</th>'
        + '<th data-sort="first_seen">First Seen</th>'
        + '<th data-sort="last_seen">Last Seen</th>'
        + '</tr></thead>'
        + '<tbody>' + rows + '</tbody>'
        + '</table>';
    }

    var content = '<div class="table-wrap">'
      + '<div class="table-toolbar">'
      + '<span class="table-toolbar__title">PCIe Devices (' + Utils.escapeHtml(String(devices.length)) + ')</span>'
      + '<input type="search" id="device-search" placeholder="Filter devices..." />'
      + '</div>'
      + '<div id="device-table-body">' + buildTable(devices) + '</div>'
      + '</div>';

    setContent(el, content);

    // Search filter
    var searchInput = document.getElementById('device-search');
    searchInput.addEventListener('input', function() {
      var filtered = Utils.filterArray(devices, searchInput.value);
      setContent('device-table-body', buildTable(filtered));
    });

    // Column sort
    el.addEventListener('click', function(e) {
      var th = e.target.closest('th[data-sort]');
      if (!th) return;
      var key = th.dataset.sort;
      deviceSortDir[key] = deviceSortDir[key] === 'asc' ? 'desc' : 'asc';
      var sorted = Utils.sortArray(devices, key, deviceSortDir[key]);
      setContent('device-table-body', buildTable(sorted));
    });
  }

  /* ------------------------------------------------------------------ */
  /*  View: Alerts                                                       */
  /* ------------------------------------------------------------------ */

  async function renderAlerts() {
    var data = await fetchData(function() { return API.getAlerts(alertPage); }, 'alerts');
    var items = data.items || [];
    var el = document.getElementById('view-alerts');

    // Track for toast notifications
    items.forEach(function(a) {
      if (!knownAlertIds.has(a.id)) {
        if (knownAlertIds.size > 0) {
          showToast('New Alert', a.message, a.severity);
        }
        knownAlertIds.add(a.id);
      }
    });

    var rows = items.map(function(a) {
      var evidenceStr = JSON.stringify(a.evidence || {}, null, 2);
      return '<tr class="alert-row" data-id="' + Utils.escapeHtml(a.id) + '">'
        + '<td>' + Utils.severityBadge(a.severity) + '</td>'
        + '<td class="mono">' + Utils.escapeHtml(a.source) + '</td>'
        + '<td>' + Utils.escapeHtml(a.message) + '</td>'
        + '<td>' + Utils.confidenceBadge(a.confidence) + '</td>'
        + '<td class="mono">' + Utils.escapeHtml(Utils.formatTimestamp(a.timestamp)) + '</td>'
        + '</tr>'
        + '<tr class="alert-detail" data-detail="' + Utils.escapeHtml(a.id) + '">'
        + '<td colspan="5"><pre>' + Utils.escapeHtml(evidenceStr) + '</pre></td>'
        + '</tr>';
    }).join('');

    var html = '<div class="table-wrap">'
      + '<div class="table-toolbar">'
      + '<span class="table-toolbar__title">Detection Alerts (' + Utils.escapeHtml(String(data.total ?? items.length)) + ')</span>'
      + '</div>'
      + '<table><thead><tr>'
      + '<th>Severity</th><th>Source</th><th>Message</th><th>Confidence</th><th>Time</th>'
      + '</tr></thead><tbody>' + rows + '</tbody></table>'
      + '</div>'
      + '<div class="pagination">'
      + '<button class="btn btn--sm" id="alerts-prev"' + (alertPage <= 1 ? ' disabled' : '') + '>&larr; Prev</button>'
      + '<span class="pagination__info">Page ' + Utils.escapeHtml(String(data.page ?? alertPage)) + ' of ' + Utils.escapeHtml(String(data.total_pages ?? 1)) + '</span>'
      + '<button class="btn btn--sm" id="alerts-next"' + (alertPage >= (data.total_pages ?? 1) ? ' disabled' : '') + '>Next &rarr;</button>'
      + '</div>';

    setContent(el, html);

    // Expandable detail rows
    el.querySelectorAll('.alert-row').forEach(function(row) {
      row.addEventListener('click', function() {
        var id = row.dataset.id;
        var detail = el.querySelector('.alert-detail[data-detail="' + id + '"]');
        if (detail) detail.classList.toggle('alert-detail--open');
      });
    });

    // Pagination
    var prevBtn = document.getElementById('alerts-prev');
    var nextBtn = document.getElementById('alerts-next');
    if (prevBtn) prevBtn.addEventListener('click', function() { alertPage = Math.max(1, alertPage - 1); renderAlerts(); });
    if (nextBtn) nextBtn.addEventListener('click', function() { alertPage++; renderAlerts(); });
  }

  /* ------------------------------------------------------------------ */
  /*  View: Config                                                       */
  /* ------------------------------------------------------------------ */

  async function renderConfig() {
    var config = await fetchData(API.getConfig, 'config');
    var el = document.getElementById('view-config');

    var whitelistHtml = (config.whitelist || []).map(function(w) {
      return '<li class="whitelist-item"><span>' + Utils.escapeHtml(w) + '</span>'
        + '<button data-remove="' + Utils.escapeHtml(w) + '" title="Remove">&times;</button></li>';
    }).join('');

    var html = '<div class="config-form">'
      + '<div class="section-header"><h2>Detection Parameters</h2></div>'
      + '<div class="form-row">'
      +   '<div class="form-group">'
      +     '<label for="cfg-scan-interval">Scan Interval (ms)</label>'
      +     '<input type="number" id="cfg-scan-interval" value="' + Utils.escapeHtml(String(config.scan_interval_ms ?? 2000)) + '" min="500" step="100" />'
      +     '<span class="hint">How often the driver scans for PCIe changes</span>'
      +   '</div>'
      +   '<div class="form-group">'
      +     '<label for="cfg-alert-poll">Alert Poll Interval (ms)</label>'
      +     '<input type="number" id="cfg-alert-poll" value="' + Utils.escapeHtml(String(config.alert_poll_interval_ms ?? 1000)) + '" min="200" step="100" />'
      +     '<span class="hint">How often the service polls driver alerts</span>'
      +   '</div>'
      + '</div>'
      + '<div class="form-group">'
      +   '<label for="cfg-threshold">Detection Threshold (%)</label>'
      +   '<input type="number" id="cfg-threshold" value="' + Utils.escapeHtml(String(config.detection_threshold ?? 70)) + '" min="0" max="100" />'
      +   '<span class="hint">Minimum confidence score to trigger an alert</span>'
      + '</div>'
      + '<div class="form-row">'
      +   '<div class="form-group">'
      +     '<label>IOMMU Check</label>'
      +     '<select id="cfg-iommu">'
      +       '<option value="true"' + (config.iommu_check_enabled !== false ? ' selected' : '') + '>Enabled</option>'
      +       '<option value="false"' + (config.iommu_check_enabled === false ? ' selected' : '') + '>Disabled</option>'
      +     '</select>'
      +   '</div>'
      +   '<div class="form-group">'
      +     '<label>PCIe Rescan on PnP</label>'
      +     '<select id="cfg-pnp-rescan">'
      +       '<option value="true"' + (config.pcie_rescan_on_pnp !== false ? ' selected' : '') + '>Enabled</option>'
      +       '<option value="false"' + (config.pcie_rescan_on_pnp === false ? ' selected' : '') + '>Disabled</option>'
      +     '</select>'
      +   '</div>'
      + '</div>'
      + '<div class="section-header" style="margin-top:12px"><h2>Device Whitelist</h2></div>'
      + '<div class="form-group">'
      +   '<ul class="whitelist-list" id="whitelist-list">' + whitelistHtml + '</ul>'
      +   '<div class="whitelist-add">'
      +     '<input type="text" id="whitelist-input" placeholder="vendor:device (e.g. 0x8086:0x1533)" />'
      +     '<button class="btn btn--sm" id="whitelist-add-btn">Add</button>'
      +   '</div>'
      + '</div>'
      + '<div style="margin-top: 8px;">'
      +   '<button class="btn btn--primary" id="config-save-btn">Save Configuration</button>'
      + '</div>'
      + '</div>';

    setContent(el, html);

    // Whitelist remove
    el.querySelectorAll('[data-remove]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var val = btn.dataset.remove;
        config.whitelist = config.whitelist.filter(function(w) { return w !== val; });
        renderConfig();
      });
    });

    // Whitelist add
    document.getElementById('whitelist-add-btn').addEventListener('click', function() {
      var input = document.getElementById('whitelist-input');
      var val = input.value.trim();
      if (val && !config.whitelist.includes(val)) {
        config.whitelist.push(val);
        renderConfig();
      }
    });

    // Save
    document.getElementById('config-save-btn').addEventListener('click', async function() {
      var newConfig = {
        scan_interval_ms: parseInt(document.getElementById('cfg-scan-interval').value, 10),
        alert_poll_interval_ms: parseInt(document.getElementById('cfg-alert-poll').value, 10),
        detection_threshold: parseInt(document.getElementById('cfg-threshold').value, 10),
        iommu_check_enabled: document.getElementById('cfg-iommu').value === 'true',
        pcie_rescan_on_pnp: document.getElementById('cfg-pnp-rescan').value === 'true',
        whitelist: config.whitelist,
      };
      try {
        await API.updateConfig(newConfig);
        showToast('Configuration Saved', 'Settings updated successfully.', 'low');
      } catch {
        showToast('Save Failed', 'Could not reach the Sentinel service.', 'high');
      }
    });
  }

  /* ------------------------------------------------------------------ */
  /*  View: Logs                                                         */
  /* ------------------------------------------------------------------ */

  async function renderLogs() {
    var logs = MOCK.logs; // Logs come from mock; real endpoint TBD
    var el = document.getElementById('view-logs');

    function buildTable(data) {
      var rows = data.map(function(l) {
        var levelCls = l.level === 'error' ? 'badge--critical' : l.level === 'warn' ? 'badge--high' : 'badge--low';
        return '<tr>'
          + '<td class="mono">' + Utils.escapeHtml(Utils.formatTimestamp(l.timestamp)) + '</td>'
          + '<td><span class="badge ' + levelCls + '">' + Utils.escapeHtml(l.level.toUpperCase()) + '</span></td>'
          + '<td class="mono">' + Utils.escapeHtml(l.source) + '</td>'
          + '<td>' + Utils.escapeHtml(l.message) + '</td>'
          + '</tr>';
      }).join('');

      return '<table>'
        + '<thead><tr>'
        + '<th data-sort="timestamp">Time</th>'
        + '<th data-sort="level">Level</th>'
        + '<th data-sort="source">Source</th>'
        + '<th>Message</th>'
        + '</tr></thead>'
        + '<tbody>' + rows + '</tbody>'
        + '</table>';
    }

    var html = '<div class="table-wrap">'
      + '<div class="table-toolbar">'
      + '<span class="table-toolbar__title">Event Log (' + Utils.escapeHtml(String(logs.length)) + ')</span>'
      + '<div style="display:flex;gap:8px;align-items:center">'
      + '<input type="search" id="log-search" placeholder="Search logs..." />'
      + '<button class="btn btn--sm" id="log-export-btn">Export CSV</button>'
      + '</div></div>'
      + '<div id="log-table-body">' + buildTable(logs) + '</div>'
      + '</div>';

    setContent(el, html);

    // Search
    document.getElementById('log-search').addEventListener('input', function(e) {
      var filtered = Utils.filterArray(logs, e.target.value);
      setContent('log-table-body', buildTable(filtered));
    });

    // Sort
    el.addEventListener('click', function(e) {
      var th = e.target.closest('th[data-sort]');
      if (!th) return;
      var key = th.dataset.sort;
      logSortDir[key] = logSortDir[key] === 'asc' ? 'desc' : 'asc';
      var sorted = Utils.sortArray(logs, key, logSortDir[key]);
      setContent('log-table-body', buildTable(sorted));
    });

    // Export
    document.getElementById('log-export-btn').addEventListener('click', function() {
      var header = 'Timestamp,Level,Source,Message\n';
      var rows = logs.map(function(l) {
        return '"' + Utils.formatTimestamp(l.timestamp) + '","' + l.level + '","' + l.source + '","' + l.message.replace(/"/g, '""') + '"';
      }).join('\n');
      var blob = new Blob([header + rows], { type: 'text/csv' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'sentinel-logs-' + Date.now() + '.csv';
      a.click();
      URL.revokeObjectURL(url);
    });
  }

  /* ------------------------------------------------------------------ */
  /*  View dispatcher                                                    */
  /* ------------------------------------------------------------------ */

  function renderCurrentView() {
    var renderers = {
      status: renderStatus,
      devices: renderDevices,
      alerts: renderAlerts,
      config: renderConfig,
      logs: renderLogs,
    };
    var fn = renderers[currentView];
    if (fn) fn();
  }

  /* ------------------------------------------------------------------ */
  /*  Auto-refresh                                                       */
  /* ------------------------------------------------------------------ */

  function startAutoRefresh() {
    stopAutoRefresh();
    refreshTimer = setInterval(function() {
      if (currentView === 'status' || currentView === 'alerts') {
        renderCurrentView();
      }
      updateConnectionStatus();
    }, refreshInterval);
  }

  function stopAutoRefresh() {
    if (refreshTimer) {
      clearInterval(refreshTimer);
      refreshTimer = null;
    }
  }

  function updateConnectionStatus() {
    var dot = document.getElementById('conn-dot');
    var label = document.getElementById('conn-label');
    if (!dot || !label) return;
    var connected = API.isConnected();
    dot.className = 'status-dot ' + (connected ? 'status-dot--online' : 'status-dot--offline');
    label.textContent = connected ? 'Service connected' : 'Using mock data';
  }

  /* ------------------------------------------------------------------ */
  /*  Init                                                               */
  /* ------------------------------------------------------------------ */

  function init() {
    // Nav clicks
    document.querySelectorAll('.nav-item').forEach(function(el) {
      el.addEventListener('click', function() { navigate(el.dataset.view); });
    });

    // Mobile menu toggle
    var menuBtn = document.getElementById('menu-btn');
    if (menuBtn) {
      menuBtn.addEventListener('click', function() {
        document.querySelector('.sidebar').classList.toggle('sidebar--open');
      });
    }

    // Refresh interval selector
    var refreshSelect = document.getElementById('refresh-select');
    if (refreshSelect) {
      refreshSelect.addEventListener('change', function(e) {
        refreshInterval = parseInt(e.target.value, 10);
        startAutoRefresh();
      });
    }

    // Render initial view
    navigate('status');
    startAutoRefresh();
    updateConnectionStatus();
  }

  return { init: init };
})();

document.addEventListener('DOMContentLoaded', App.init);
