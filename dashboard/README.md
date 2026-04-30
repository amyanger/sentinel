# Sentinel Dashboard

Static HTML/CSS/JS — no build step. Serves on `http://localhost:3000`.

```bash
npm run dev
```

## Views

- **Status, Devices, Alerts, Config, Logs** — talk to the Sentinel service's local REST API at `http://localhost:8088`. Render mock data when the service isn't running.
- **Collector** — talks to a remote (or local) detection collector. URL and admin API key are configured via the in-app settings modal and persisted in `localStorage`.

## Configuring the Collector view

1. Run a collector (see `collector/README.md`).
2. Register an admin key:
   ```bash
   ./collector admin add-admin dashboard-dev --config <path>
   ```
3. Make sure the collector's TOML config has the dashboard origin allowed for CORS:
   ```toml
   [server]
   allowed_origins = ["http://localhost:3000"]
   ```
4. In the dashboard, click **Collector** → **Configure**. Paste the URL and admin key. **Test connection** uses the unauthenticated `/v1/healthz` to verify reachability without burning the admin key.

## Security notes

- The admin key sits in `localStorage`. Acceptable for a developer laptop, not for a shared kiosk. For production, a server-side proxy holding the key is required.
- The collector view is read-only. All collector data is rendered with escaped HTML (`Utils.escapeHtml`) and `textContent` to defend against XSS via malicious `client_id` / `summary` / etc.
