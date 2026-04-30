/**
 * Sentinel Dashboard — Collector API module.
 *
 * Talks to the collector's read endpoints using a bearer token. Both base URL
 * and token are user-configurable and persisted in localStorage:
 *   sentinel.collector.url, sentinel.collector.key
 */

const Collector = (() => {
  const URL_KEY = 'sentinel.collector.url';
  const TOKEN_KEY = 'sentinel.collector.key';

  function getConfig() {
    return {
      url: localStorage.getItem(URL_KEY) || '',
      key: localStorage.getItem(TOKEN_KEY) || '',
    };
  }

  function setConfig({ url, key }) {
    if (typeof url === 'string') localStorage.setItem(URL_KEY, url.trim());
    if (typeof key === 'string') localStorage.setItem(TOKEN_KEY, key.trim());
  }

  function isConfigured() {
    const { url, key } = getConfig();
    return url !== '' && key !== '';
  }

  async function _fetch(path) {
    const { url, key } = getConfig();
    if (!url || !key) {
      throw new Error('Collector not configured. Open Settings to set URL and API key.');
    }
    const resp = await fetch(`${url}${path}`, {
      headers: {
        'Authorization': `Bearer ${key}`,
        'Accept': 'application/json',
      },
    });
    if (resp.status === 401) {
      throw new Error('Unauthorized — admin API key is invalid.');
    }
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
    }
    return await resp.json();
  }

  async function listEvents(limit = 50) {
    return _fetch(`/v1/events?limit=${encodeURIComponent(limit)}`);
  }

  async function getEvent(id) {
    return _fetch(`/v1/events/${encodeURIComponent(id)}`);
  }

  async function ping() {
    // /v1/healthz is unauthenticated, so use it to test connectivity
    // without burning the configured admin key.
    const { url } = getConfig();
    if (!url) throw new Error('Collector URL not set.');
    const resp = await fetch(`${url}/v1/healthz`);
    if (!resp.ok) throw new Error(`Collector unreachable (HTTP ${resp.status}).`);
    return await resp.json();
  }

  return { getConfig, setConfig, isConfigured, listEvents, getEvent, ping };
})();
