# Detection Collector — End-to-End Smoke Test Runbook

**Purpose:** Verify a full mac↔Windows round trip of a synthetic detection event from the Sentinel service to the Detection Collector.

**When to run:** Before merging `feat/detection-collector` to `main`, and any time the client↔collector wire is touched.

**Prereqs:**
- macOS host with Go ≥ 1.22 and `curl` installed
- Windows VM with MSVC (Visual Studio 2022) and CMake ≥ 3.20
- Shared filesystem or git access between host and VM
- Host IP as seen from the VM (varies by VM tool — see Step 4)

## Step 1 — Start the collector on macOS

```bash
cd ~/Documents/Dev/sentinel/collector
go build ./cmd/collector

cat > /tmp/collector-smoke.toml <<'EOF'
[server]
listen = "0.0.0.0:18443"

[storage]
sqlite_path = "/tmp/collector-smoke.db"

[clients]
EOF

./collector admin add-client smoke-vm-01 --config /tmp/collector-smoke.toml
```

**Copy the printed 64-hex API key.** You'll need it in Step 3.

Then start the server:

```bash
./collector serve --config /tmp/collector-smoke.toml
```

Expected:
- `{"level":"INFO","msg":"keys loaded","count":1}`
- `{"level":"INFO","msg":"collector listening","addr":"0.0.0.0:18443","tls":false}`

**Note on TLS:** this runbook deliberately skips TLS (plaintext HTTP on `0.0.0.0:18443`) because generating a cert valid for the host-VM loopback is too much ceremony for a smoke test. In a real pilot you'd use `[server] tls_cert = ...` and `tls_key = ...`, and the client would reject any cert that doesn't validate.

## Step 2 — Verify the collector is reachable from the Mac

In a second macOS terminal:

```bash
curl -s http://127.0.0.1:18443/v1/healthz
```

Expected: `{"status":"ok","version":"0.1.0"}`

If this fails, the VM won't work either — fix the collector first.

## Step 3 — Store the API key in the VM's credential store

Inside the Windows VM, in an **Administrator** PowerShell:

```powershell
cmdkey /generic:SentinelCollectorApiKey /user:sentinel /pass:<paste-64-hex-key-from-step-1>
```

Verify it's there:

```powershell
cmdkey /list:SentinelCollectorApiKey
```

You should see `Target: SentinelCollectorApiKey` in the output.

**Note:** `cmdkey` writes to the *user*'s credential store, not LOCAL_MACHINE. Our `credential_store_win.cpp` writes with `CRED_PERSIST_LOCAL_MACHINE`, but `CredReadW` reads from both locations — so `cmdkey` works for this test. For production, use the service's own init path to write the credential.

## Step 4 — Find the host IP as seen from the VM

This depends on your VM platform. From inside the VM:

| VM tool | Likely host IP |
|---|---|
| VMware Fusion (NAT) | `192.168.x.1` (where `x` varies; check with `ipconfig` → default gateway) |
| VirtualBox (NAT) | `10.0.2.2` |
| Parallels (Shared) | `10.211.55.2` |
| Hyper-V (Default Switch) | Run `ipconfig` → Default Gateway |
| UTM | Depends on network mode |

Verify connectivity from inside the VM:

```cmd
curl http://<HOST-IP>:18443/v1/healthz
```

Expected: same healthz JSON as Step 2. If this fails, **stop and fix networking** before continuing — the Sentinel service will fail the same way.

## Step 5 — Build and run the service with the inject flag

Inside the Windows VM, checkout the `feat/detection-collector` branch (via shared folder or `git fetch`), then in a Developer Command Prompt for VS 2022:

```cmd
cd C:\path\to\sentinel
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --target sentinel_service
```

If you want the C++ unit tests too:

```cmd
cmake -B build -G "Visual Studio 17 2022" -A x64 -DSENTINEL_SERVICE_TESTS=ON
cmake --build build --config Release --target sentinel_service_tests
ctest --test-dir build --output-on-failure -C Release
```

Expected: clean build, `sentinel_service.exe` in `build\bin\Release\`.

If the build fails, see **Troubleshooting** below. Note any changes you made so they can be committed back.

Then run the service with the inject flag:

```cmd
set SENTINEL_COLLECTOR_URL=http://<HOST-IP>:18443
set SENTINEL_CLIENT_ID=smoke-vm-01
build\bin\Release\sentinel_service.exe --console --inject-test-event
```

Expected output lines (order approximate):
- `Initializing service modules...`
- `collector_client: started, target=http://<HOST-IP>:18443`
- `Collector client started.`
- `All modules initialized.`
- `Injected synthetic DMA_ANOMALY event at startup.`
- A short pause, then possibly `ALERT TRIGGERED: Synthetic DMA_ANOMALY...` (depends on how the detection engine scores a single high-confidence event against its threshold — 0.90 > 0.70 default, so it should fire).

Let it run for ~5 seconds then Ctrl+C.

If the collector is reachable, the service's console should NOT print `collector_client: retry later, ...` — one POST, clean accept. If you see retries, re-check Step 4's networking and the API key in Step 3.

## Step 6 — Verify the event landed on the Mac

Back on macOS, replace `<key>` with the 64-hex API key from Step 1:

```bash
curl -s -H "Authorization: Bearer <key>" \
  http://127.0.0.1:18443/v1/events | python3 -m json.tool
```

Expected: a JSON response with exactly one event:

```json
{
  "events": [
    {
      "schema_version": 1,
      "event_id": "018...",
      "client_id": "smoke-vm-01",
      "sentinel_version": "0.3.1",
      "timestamp": "2026-...",
      "source": "driver",
      "detection_type": "DMA_ANOMALY",
      "severity": "high",
      "confidence": 90,
      "summary": "Synthetic DMA_ANOMALY injected via --inject-test-event",
      "host": {
        "hostname": "<your-vm-hostname>",
        "os_version": "Windows",
        "arch": "x64"
      },
      "context": {
        "process_id": 0
      }
    }
  ]
}
```

**If the event is there → the round trip works end-to-end. 🎉 T22 passes.**

## Step 7 — Optional: verify idempotency

Stop the service (Ctrl+C in the VM) and re-run the same command. Inject fires again with a fresh UUIDv7 (it's regenerated per call in `generate_uuidv7`), so the collector sees a **second distinct event** (not a duplicate).

```bash
curl -s -H "Authorization: Bearer <key>" \
  http://127.0.0.1:18443/v1/events | python3 -c "import sys,json;print(len(json.load(sys.stdin)['events']))"
```

Expected: `2`.

If you see `1`, something is wrong with UUIDv7 generation (not seeding, constant output, etc.) — investigate.

## Cleanup

On macOS:

```bash
# Stop the collector (Ctrl+C in its terminal)
rm -f /tmp/collector-smoke.toml /tmp/collector-smoke.db /tmp/collector-smoke.db-*
rm -f ~/Documents/Dev/sentinel/collector/collector
```

On Windows:

```powershell
cmdkey /delete:SentinelCollectorApiKey
```

## Troubleshooting

### MSVC build errors

The C++ code was edited on macOS and only syntax-checked with clang. MSVC is stricter. Likely issues:

- **`winhttp.h` or `wincred.h` missing symbols.** Already fixed in commit `602c802` for `collector_http_win.cpp` — Windows headers are now at file scope before `namespace sentinel`. If `wincred.h` has similar trouble, apply the same pattern.
- **Unused parameter warnings.** `/W4 /WX` treats these as errors. If a new warning fires, mark the parameter unused: `(void)param;` or `/*param*/`.
- **`(DWORD)-1` cast.** If MSVC complains, use `static_cast<DWORD>(-1)` or `WINHTTP_NO_REQUEST_DATA_LENGTH` constant.
- **`to_wstring` ambiguity.** `sentinel::to_wstring(const std::string&)` should not collide with `std::to_wstring(int)` — they're in different namespaces and have different signatures. If MSVC confuses them, fully qualify the call site.

If you hit something and fix it in the VM, paste the diff into a new commit:

```cmd
cd C:\path\to\sentinel
git add <files>
git commit -m "service: fix MSVC-specific compile errors"
```

### Service fails to start because "credential not found"

Means `CredReadW` on `SentinelCollectorApiKey` returned an error. Check:
- Step 3's `cmdkey` command ran successfully
- You're running the service as the same user that ran `cmdkey`
- The target name matches exactly: `SentinelCollectorApiKey` (case-sensitive)

The service will still run — it just logs `collector: credential not found in store; forwarding disabled` and the collector client stays off. Fix the credential and restart.

### Collector says "invalid API key" (401)

The key stored in credential manager doesn't match the one registered with the collector. Redo Step 1's `admin add-client` to get a fresh key, then redo Step 3 to store it.

### Events never arrive but service logs "Injected synthetic event"

Check the service's stderr for `collector_client: retry later, status=0` — that means TCP/DNS/routing failure, not collector-side rejection. Go back to Step 4 and fix networking.

If you see `status=401`, the API key is wrong (see above).

If you see `status=400`, the wire format has drifted between client and collector — this is a bug that needs code changes, not a config fix.

## Step 8 — Optional: load the dashboard against the smoke collector

Useful to eyeball the same data the curl in Step 6 returns.

On macOS:

```bash
./collector admin add-admin dashboard-dev --config /tmp/collector-smoke.toml
# Note the printed admin key.
```

Edit `/tmp/collector-smoke.toml` and add to the `[server]` table:

```toml
allowed_origins = ["http://localhost:3000"]
```

Restart the collector. Then:

```bash
cd ~/Documents/Dev/sentinel/dashboard
npm run dev
```

Open Safari → `http://localhost:3000` → **Collector** → **Configure** → paste `http://127.0.0.1:18443` and the admin key. The event injected from the VM in Step 5 should appear in the table.
