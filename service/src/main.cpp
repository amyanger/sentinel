/*
 * main.cpp -- Windows service entry point for the Sentinel anticheat service.
 *
 * This file wires together all the service modules and manages the Windows
 * Service Control Manager (SCM) lifecycle. Here's how Windows services work:
 *
 *   1. main() calls StartServiceCtrlDispatcher, which tells the SCM "I'm ready"
 *   2. The SCM calls our ServiceMain callback
 *   3. ServiceMain registers a control handler (for stop/pause signals)
 *   4. ServiceMain initializes all modules and enters the main loop
 *   5. When the SCM sends SERVICE_CONTROL_STOP, our handler sets a flag
 *   6. The main loop sees the flag, tears everything down, and exits
 *
 * For development/testing, we also support running as a console application
 * by passing --console on the command line. This skips the SCM registration
 * and just runs the service logic directly.
 */

#include <sentinel/service.h>
#include <sentinel/driver_comm.h>
#include <sentinel/process_monitor.h>
#include <sentinel/signature_scanner.h>
#include <sentinel/module_integrity.h>
#include <sentinel/detection_engine.h>
#include <sentinel/api_server.h>
#include <sentinel/collector_client.h>
#include <sentinel/credential_store.h>

/* The service name as registered with the SCM. */
static constexpr const char* SERVICE_NAME = "SentinelAnticheat";

/* -------------------------------------------------------------------
 * Global state -- these must be accessible from the SCM callbacks,
 * which are plain C-style function pointers (no captures allowed).
 * ------------------------------------------------------------------- */

#ifdef _WIN32
static SERVICE_STATUS_HANDLE g_status_handle = nullptr;
static SERVICE_STATUS        g_service_status = {};
#endif

static std::atomic<bool> g_running{false};

/* All service modules, owned by ServiceMain's scope. */
static std::unique_ptr<sentinel::DriverComm>       g_driver_comm;
static std::unique_ptr<sentinel::ProcessMonitor>    g_process_monitor;
static std::unique_ptr<sentinel::SignatureScanner>  g_signature_scanner;
static std::unique_ptr<sentinel::ModuleIntegrity>   g_module_integrity;
static std::unique_ptr<sentinel::DetectionEngine>   g_detection_engine;
static std::unique_ptr<sentinel::ApiServer>         g_api_server;
static std::unique_ptr<sentinel::CollectorClient>   g_collector_client;

/* Shared configuration, mutable via the REST API. */
static sentinel::ServiceConfig g_config;
static std::mutex              g_config_mutex;

/* -------------------------------------------------------------------
 * report_status -- Update the SCM with our current state.
 *
 * This is required by the SCM protocol. We must report transitions
 * like START_PENDING -> RUNNING -> STOP_PENDING -> STOPPED.
 * ------------------------------------------------------------------- */
#ifdef _WIN32
static void report_status(DWORD current_state, DWORD exit_code = NO_ERROR,
                           DWORD wait_hint = 0) {
    g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_service_status.dwCurrentState = current_state;
    g_service_status.dwWin32ExitCode = exit_code;
    g_service_status.dwWaitHint = wait_hint;

    /*
     * Accept stop requests only when running. During start/stop
     * transitions, we don't accept any controls.
     */
    if (current_state == SERVICE_START_PENDING) {
        g_service_status.dwControlsAccepted = 0;
    } else {
        g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    }

    /*
     * Checkpoint must increment during pending operations so the SCM
     * knows we're making progress. Reset to 0 when in a stable state.
     */
    static DWORD checkpoint = 0;
    if (current_state == SERVICE_RUNNING || current_state == SERVICE_STOPPED) {
        g_service_status.dwCheckPoint = 0;
    } else {
        g_service_status.dwCheckPoint = ++checkpoint;
    }

    SetServiceStatus(g_status_handle, &g_service_status);
}
#endif

/* -------------------------------------------------------------------
 * service_ctrl_handler -- Called by the SCM when it wants us to stop.
 *
 * This is a plain C callback registered with RegisterServiceCtrlHandler.
 * It must respond quickly -- just set a flag and return.
 * ------------------------------------------------------------------- */
#ifdef _WIN32
static void WINAPI service_ctrl_handler(DWORD control) {
    switch (control) {
        case SERVICE_CONTROL_STOP:
            report_status(SERVICE_STOP_PENDING, NO_ERROR, 5000);
            g_running = false;
            break;

        case SERVICE_CONTROL_INTERROGATE:
            /* The SCM is asking us to re-report our status. */
            break;

        default:
            break;
    }
}
#endif

/* -------------------------------------------------------------------
 * log_to_stderr -- Simple logging helper for startup/shutdown messages.
 * In production, this would go to the Windows Event Log.
 * ------------------------------------------------------------------- */
static void log_to_stderr(const char* message) {
    auto now = std::chrono::system_clock::now();
    std::string ts = sentinel::format_timestamp(now);
    std::fprintf(stderr, "[%s] %s\n", ts.c_str(), message);
}

/* -------------------------------------------------------------------
 * initialize_modules -- Create and start all service modules.
 *
 * Order matters: DriverComm first (it talks to the kernel), then
 * DetectionEngine (aggregator), then the individual detectors, and
 * finally the API server (which queries everything).
 * ------------------------------------------------------------------- */
static bool initialize_modules() {
    log_to_stderr("Initializing service modules...");

    /* 1. Driver communication -- our link to ring 0. */
    g_driver_comm = std::make_unique<sentinel::DriverComm>();

    /* 1.5 Collector client -- forwards detections to a central collector.
     * Disabled unless SENTINEL_COLLECTOR_URL and SENTINEL_CLIENT_ID are set
     * in the environment and a valid API key is present in the Windows
     * credential store under the target "SentinelCollectorApiKey". */
    {
        sentinel::CollectorConfig cc;
        const char* url_env       = std::getenv("SENTINEL_COLLECTOR_URL");
        const char* client_id_env = std::getenv("SENTINEL_CLIENT_ID");
        cc.url       = url_env       ? url_env       : "";
        cc.client_id = client_id_env ? client_id_env : "";
        cc.enabled   = !cc.url.empty() && !cc.client_id.empty();

        if (cc.enabled) {
            if (!sentinel::load_credential(
                    sentinel::COLLECTOR_CREDENTIAL_TARGET, cc.api_key)) {
                log_to_stderr("collector: credential not found in store; "
                              "forwarding disabled");
                cc.enabled = false;
            }
        }

        sentinel::CollectorHostInfo host;
#ifdef _WIN32
        {
            char hostbuf[256] = {};
            DWORD n = sizeof(hostbuf);
            if (GetComputerNameA(hostbuf, &n)) host.hostname = hostbuf;
        }
        host.os_version = "Windows";
        host.arch       = "x64";
#else
        host.hostname   = "sentinel-dev";
        host.os_version = "Windows (stubbed)";
        host.arch       = "x64";
#endif

        g_collector_client = std::make_unique<sentinel::CollectorClient>();
        g_collector_client->start(cc, host, "0.3.1");
        if (cc.enabled) {
            log_to_stderr("Collector client started.");
        }
    }

    /* 2. Detection engine -- receives events from all sources. */
    g_detection_engine = std::make_unique<sentinel::DetectionEngine>();
    g_detection_engine->start(g_config,
        [](const sentinel::DetectionEvent& event, double score) {
            /*
             * This callback fires when cumulative confidence exceeds
             * the threshold. In a real system you'd take action here
             * (e.g., suspend the process, notify the game server).
             */
            std::string msg = "ALERT TRIGGERED: " + event.description +
                              " (score=" + std::to_string(score) + ")";
            log_to_stderr(msg.c_str());
            /* Forward to the central collector (non-blocking, drops silently
             * if the collector client isn't enabled). */
            if (g_collector_client) {
                g_collector_client->enqueue(event);
            }
        });

    /* 3. Start the driver communication with alert forwarding. */
    bool driver_ok = g_driver_comm->start(
        g_config.poll_interval_ms,
        [](const SENTINEL_ALERT& alert) {
            /* Forward driver alerts to the detection engine. */
            if (g_detection_engine) {
                g_detection_engine->submit_driver_alert(alert);
            }
        });

    if (!driver_ok) {
        log_to_stderr("WARNING: Could not connect to kernel driver. "
                      "Driver-based detection is disabled.");
        /*
         * We continue running even without the driver -- user-mode
         * detections still work. This is intentional for development
         * and graceful degradation.
         */
    }

    /* 4. Process monitor -- watches for cheat tools and injection. */
    g_process_monitor = std::make_unique<sentinel::ProcessMonitor>();
    if (g_config.enable_process_monitor) {
        g_process_monitor->start(
            g_config.scan_interval_ms,
            [](const sentinel::DetectionEvent& event) {
                if (g_detection_engine) {
                    g_detection_engine->submit_event(event);
                }
            });
        log_to_stderr("Process monitor started.");
    }

    /* 5. Signature scanner -- byte pattern matching in process memory. */
    g_signature_scanner = std::make_unique<sentinel::SignatureScanner>();
    if (g_config.enable_signature_scan) {
        if (g_signature_scanner->start(
                sentinel::SIGNATURE_DB_PATH,
                [](const sentinel::DetectionEvent& event) {
                    if (g_detection_engine) {
                        g_detection_engine->submit_event(event);
                    }
                })) {
            log_to_stderr("Signature scanner started.");
        } else {
            log_to_stderr("WARNING: Could not load signature database.");
        }
    }

    /* 6. Module integrity checker -- DLL hash verification. */
    g_module_integrity = std::make_unique<sentinel::ModuleIntegrity>();
    if (g_config.enable_module_integrity) {
        if (g_module_integrity->start(
                sentinel::HASH_DB_PATH,
                [](const sentinel::DetectionEvent& event) {
                    if (g_detection_engine) {
                        g_detection_engine->submit_event(event);
                    }
                })) {
            log_to_stderr("Module integrity checker started.");
        } else {
            log_to_stderr("WARNING: Could not load hash database.");
        }
    }

    /* 7. REST API server -- last, because it queries all other modules. */
    g_api_server = std::make_unique<sentinel::ApiServer>(
        *g_driver_comm, *g_detection_engine, g_config, g_config_mutex);
    if (g_api_server->start(sentinel::API_SERVER_PORT)) {
        log_to_stderr("API server listening on localhost:8088.");
    } else {
        log_to_stderr("ERROR: Could not start API server.");
        return false;
    }

    log_to_stderr("All modules initialized.");
    return true;
}

/* -------------------------------------------------------------------
 * shutdown_modules -- Stop all modules in reverse initialization order.
 *
 * Reverse order ensures that consumers stop before producers.
 * ------------------------------------------------------------------- */
static void shutdown_modules() {
    log_to_stderr("Shutting down service modules...");

    if (g_api_server)         g_api_server->stop();
    if (g_module_integrity)   g_module_integrity->stop();
    if (g_signature_scanner)  g_signature_scanner->stop();
    if (g_process_monitor)    g_process_monitor->stop();
    if (g_driver_comm)        g_driver_comm->stop();
    if (g_detection_engine)   g_detection_engine->stop();
    if (g_collector_client)   g_collector_client->stop();

    /* Release all module objects. */
    g_api_server.reset();
    g_module_integrity.reset();
    g_signature_scanner.reset();
    g_process_monitor.reset();
    g_driver_comm.reset();
    g_detection_engine.reset();
    g_collector_client.reset();

    log_to_stderr("All modules stopped.");
}

/* -------------------------------------------------------------------
 * service_main -- The actual service entry point called by the SCM.
 *
 * This is where the real work happens. It:
 *   1. Registers the control handler
 *   2. Reports START_PENDING
 *   3. Initializes all modules
 *   4. Reports RUNNING
 *   5. Sits in the main loop until g_running becomes false
 *   6. Tears everything down
 *   7. Reports STOPPED
 * ------------------------------------------------------------------- */
#ifdef _WIN32
static void WINAPI service_main(DWORD argc, LPSTR* argv) {
    (void)argc;
    (void)argv;

    /* Register our control handler with the SCM. */
    g_status_handle = RegisterServiceCtrlHandlerA(SERVICE_NAME,
                                                   service_ctrl_handler);
    if (!g_status_handle) {
        return;
    }

    report_status(SERVICE_START_PENDING, NO_ERROR, 10000);

    /* Initialize all modules. */
    if (!initialize_modules()) {
        report_status(SERVICE_STOPPED, GetLastError());
        shutdown_modules();
        return;
    }

    g_running = true;
    report_status(SERVICE_RUNNING);
    log_to_stderr("Sentinel Anticheat service is running.");

    /*
     * Main service loop: sleep in short intervals so we can respond
     * to stop requests promptly. The real work is done by the module
     * background threads.
     */
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    /* Clean shutdown. */
    report_status(SERVICE_STOP_PENDING, NO_ERROR, 5000);
    shutdown_modules();
    report_status(SERVICE_STOPPED);
    log_to_stderr("Sentinel Anticheat service stopped.");
}
#endif

/* -------------------------------------------------------------------
 * run_console -- Run the service as a console application for debugging.
 *
 * Ctrl+C sets g_running to false, which triggers clean shutdown.
 * ------------------------------------------------------------------- */
static void run_console() {
    log_to_stderr("Running in console mode (Ctrl+C to stop)...");

#ifdef _WIN32
    /* Set up Ctrl+C handler. */
    SetConsoleCtrlHandler([](DWORD event) -> BOOL {
        if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT) {
            g_running = false;
            return TRUE;
        }
        return FALSE;
    }, TRUE);
#endif

    if (!initialize_modules()) {
        log_to_stderr("Failed to initialize modules.");
        shutdown_modules();
        return;
    }

    g_running = true;
    log_to_stderr("Sentinel Anticheat running. Press Ctrl+C to stop.");

    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    shutdown_modules();
    log_to_stderr("Sentinel Anticheat stopped.");
}

/* -------------------------------------------------------------------
 * main -- Program entry point.
 *
 * If --console is passed, run interactively for debugging.
 * Otherwise, register with the SCM as a Windows service.
 * ------------------------------------------------------------------- */
int main(int argc, char* argv[]) {
    /* Check for console mode flag. */
    bool console_mode = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--console") == 0) {
            console_mode = true;
            break;
        }
    }

    if (console_mode) {
        run_console();
        return 0;
    }

#ifdef _WIN32
    /*
     * Register with the Service Control Manager.
     *
     * SERVICE_TABLE_ENTRY maps a service name to its entry point.
     * The table is null-terminated. StartServiceCtrlDispatcher blocks
     * until the service stops.
     */
    SERVICE_TABLE_ENTRYA service_table[] = {
        { const_cast<char*>(SERVICE_NAME), service_main },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherA(service_table)) {
        DWORD error = GetLastError();
        if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            /*
             * This error means we were started from a console, not the SCM.
             * Fall back to console mode automatically.
             */
            log_to_stderr("Not started by SCM. Falling back to console mode.");
            run_console();
        } else {
            std::fprintf(stderr, "StartServiceCtrlDispatcher failed: %lu\n", error);
            return 1;
        }
    }
#else
    /* On non-Windows (macOS dev), just run in console mode. */
    run_console();
#endif

    return 0;
}
