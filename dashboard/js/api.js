/**
 * Sentinel Dashboard — API communication module
 */

const API = (() => {
  const BASE_URL = 'http://localhost:8088';
  const MAX_RETRIES = 2;
  const RETRY_DELAY_MS = 1000;

  let _connected = false;

  function isConnected() {
    return _connected;
  }

  async function _fetch(path, options = {}) {
    const url = `${BASE_URL}${path}`;
    let lastError;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      try {
        const resp = await fetch(url, {
          headers: { 'Content-Type': 'application/json' },
          ...options,
        });
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
        }
        _connected = true;
        return await resp.json();
      } catch (err) {
        lastError = err;
        if (attempt < MAX_RETRIES) {
          await new Promise(r => setTimeout(r, RETRY_DELAY_MS * (attempt + 1)));
        }
      }
    }

    _connected = false;
    throw lastError;
  }

  async function getStatus() {
    return _fetch('/api/status');
  }

  async function getDevices() {
    return _fetch('/api/devices');
  }

  async function getAlerts(page = 1) {
    return _fetch(`/api/alerts?page=${page}`);
  }

  async function getConfig() {
    return _fetch('/api/config');
  }

  async function updateConfig(config) {
    return _fetch('/api/config', {
      method: 'PUT',
      body: JSON.stringify(config),
    });
  }

  async function getStats() {
    return _fetch('/api/stats');
  }

  return {
    isConnected,
    getStatus,
    getDevices,
    getAlerts,
    getConfig,
    updateConfig,
    getStats,
  };
})();
