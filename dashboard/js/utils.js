/**
 * Sentinel Dashboard — Utility functions
 */

const Utils = (() => {

  /**
   * Format a Unix timestamp (seconds) or ISO string to a human-readable local string.
   */
  function formatTimestamp(ts) {
    if (!ts) return '\u2014';
    const date = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
    if (isNaN(date.getTime())) return '\u2014';
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  }

  /**
   * Format seconds into a human-readable uptime string (e.g. "3d 4h 12m").
   */
  function formatUptime(seconds) {
    if (seconds == null || seconds < 0) return '\u2014';
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    const parts = [];
    if (d > 0) parts.push(`${d}d`);
    if (h > 0) parts.push(`${h}h`);
    if (m > 0) parts.push(`${m}m`);
    if (parts.length === 0) parts.push(`${s}s`);
    return parts.join(' ');
  }

  /**
   * Return the CSS class suffix for a severity level.
   */
  function severityClass(level) {
    const map = {
      critical: 'critical',
      high: 'high',
      medium: 'medium',
      low: 'low',
    };
    return map[(level || '').toLowerCase()] || 'low';
  }

  /**
   * Render a severity badge as an HTML string.
   */
  function severityBadge(level) {
    const cls = severityClass(level);
    const label = (level || 'unknown').toUpperCase();
    return `<span class="badge badge--${cls}">${label}</span>`;
  }

  /**
   * Render a trust status badge.
   */
  function trustBadge(status) {
    const s = (status || 'unknown').toLowerCase();
    const map = {
      trusted: { cls: 'trusted', label: 'TRUSTED' },
      suspicious: { cls: 'suspicious', label: 'SUSPICIOUS' },
      blocked: { cls: 'blocked', label: 'BLOCKED' },
      unknown: { cls: 'unknown', label: 'UNKNOWN' },
    };
    const info = map[s] || map.unknown;
    return `<span class="badge badge--${info.cls}">${info.label}</span>`;
  }

  /**
   * Render a status indicator dot.
   */
  function statusDot(isOnline) {
    const cls = isOnline ? 'status-dot--online' : 'status-dot--offline';
    return `<span class="status-dot ${cls}"></span>`;
  }

  /**
   * Simple client-side table sort. Returns a new sorted array.
   */
  function sortArray(arr, key, direction) {
    const dir = direction === 'desc' ? -1 : 1;
    return [...arr].sort((a, b) => {
      const va = a[key];
      const vb = b[key];
      if (va == null && vb == null) return 0;
      if (va == null) return 1;
      if (vb == null) return -1;
      if (typeof va === 'string') return dir * va.localeCompare(vb);
      return dir * (va - vb);
    });
  }

  /**
   * Filter an array of objects by a search term across all string values.
   */
  function filterArray(arr, term) {
    if (!term) return arr;
    const lower = term.toLowerCase();
    return arr.filter(item =>
      Object.values(item).some(
        v => typeof v === 'string' && v.toLowerCase().includes(lower)
      )
    );
  }

  /**
   * Escape HTML to prevent injection.
   */
  function escapeHtml(str) {
    const el = document.createElement('div');
    el.textContent = str;
    return el.innerHTML;
  }

  /**
   * Format a confidence score (0-100) with color hint.
   */
  function confidenceBadge(score) {
    if (score == null) return '\u2014';
    let cls = 'confidence--low';
    if (score >= 80) cls = 'confidence--high';
    else if (score >= 50) cls = 'confidence--medium';
    return `<span class="confidence ${cls}">${score}%</span>`;
  }

  return {
    formatTimestamp,
    formatUptime,
    severityClass,
    severityBadge,
    trustBadge,
    statusDot,
    sortArray,
    filterArray,
    escapeHtml,
    confidenceBadge,
  };
})();
