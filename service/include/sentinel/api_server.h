/*
 * sentinel/api_server.h
 *
 * ApiServer provides a lightweight HTTP REST API for the dashboard
 * to query service status, detection events, device lists, and
 * configuration.
 *
 * Implementation: Uses raw Winsock (ws2_32) for a minimal HTTP server.
 * This avoids any third-party HTTP library dependency. The server
 * only binds to localhost (127.0.0.1) -- no external network exposure.
 *
 * Supported routes:
 *   GET  /api/status   — Service and driver health
 *   GET  /api/devices  — PCIe device list from the driver
 *   GET  /api/alerts   — Detection events (with optional pagination)
 *   GET  /api/config   — Current service configuration
 *   PUT  /api/config   — Update service configuration
 *   GET  /api/stats    — Detection statistics
 *
 * All responses are JSON. Request/response bodies use manual JSON
 * formatting to avoid third-party dependencies.
 */

#ifndef SENTINEL_API_SERVER_H
#define SENTINEL_API_SERVER_H

#include <sentinel/service.h>

namespace sentinel {

/* Forward declarations -- the API server holds references to these. */
class DriverComm;
class DetectionEngine;

class ApiServer {
public:
    /**
     * Construct an API server.
     *
     * @param driver   Reference to the driver communication module.
     * @param engine   Reference to the detection engine.
     * @param config   Shared reference to the mutable service config.
     * @param config_mutex  Mutex protecting the config.
     */
    ApiServer(DriverComm& driver,
              DetectionEngine& engine,
              ServiceConfig& config,
              std::mutex& config_mutex);
    ~ApiServer();

    ApiServer(const ApiServer&) = delete;
    ApiServer& operator=(const ApiServer&) = delete;

    /* -------------------------------------------------------------------
     * Lifecycle
     * ------------------------------------------------------------------- */

    /**
     * Start listening on localhost:port.
     *
     * @param port  TCP port to bind (default: 8088).
     * @return true if the socket was bound and listening.
     */
    bool start(int port = API_SERVER_PORT);

    /** Stop the server and close all connections. */
    void stop();

    /** Returns true if the server is accepting connections. */
    bool is_running() const;

private:
    /* -------------------------------------------------------------------
     * HTTP infrastructure
     * ------------------------------------------------------------------- */

    /** Parsed HTTP request. */
    struct HttpRequest {
        std::string method;   /* GET, PUT, etc.              */
        std::string path;     /* /api/status, /api/config    */
        std::string body;     /* Request body (for PUT)      */
        std::unordered_map<std::string, std::string> query_params;
    };

    /** HTTP response to send back. */
    struct HttpResponse {
        int status_code = 200;
        std::string status_text = "OK";
        std::string content_type = "application/json";
        std::string body;
    };

    /** Accept loop: runs on the server thread, accepts connections. */
    void accept_loop();

    /** Handle a single client connection (read request, route, respond). */
    void handle_client(SOCKET client_socket);

    /** Parse a raw HTTP request string into an HttpRequest struct. */
    static HttpRequest parse_request(const std::string& raw);

    /** Send an HTTP response over the socket. */
    static void send_response(SOCKET client_socket, const HttpResponse& response);

    /* -------------------------------------------------------------------
     * Route handlers -- each returns a JSON response body.
     * ------------------------------------------------------------------- */

    /** GET /api/status -- service and driver health. */
    HttpResponse handle_status();

    /** GET /api/devices -- PCIe device list. */
    HttpResponse handle_devices();

    /** GET /api/alerts -- detection events with optional pagination. */
    HttpResponse handle_alerts(const HttpRequest& request);

    /** GET /api/config -- current configuration. */
    HttpResponse handle_get_config();

    /** PUT /api/config -- update configuration. */
    HttpResponse handle_put_config(const HttpRequest& request);

    /** GET /api/stats -- detection statistics. */
    HttpResponse handle_stats();

    /* -------------------------------------------------------------------
     * JSON utilities
     * ------------------------------------------------------------------- */

    /** Escape a string for JSON output (handles quotes, backslashes). */
    static std::string json_escape(const std::string& str);

    /** Build a simple JSON error response. */
    static HttpResponse make_error(int code, const std::string& message);

    /** Parse a simple JSON object into key-value pairs (flat only). */
    static std::unordered_map<std::string, std::string> parse_json_flat(
        const std::string& json);

    /* --- State --- */
    DriverComm&       driver_;
    DetectionEngine&  engine_;
    ServiceConfig&    config_;
    std::mutex&       config_mutex_;

    SOCKET            listen_socket_;
    std::atomic<bool> running_;
    std::thread       server_thread_;

    /* Uptime tracking for status endpoint. */
    std::chrono::steady_clock::time_point start_time_;
};

} /* namespace sentinel */

#endif /* SENTINEL_API_SERVER_H */
