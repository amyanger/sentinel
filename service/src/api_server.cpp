/*
 * api_server.cpp -- ApiServer implementation.
 *
 * A lightweight HTTP server using raw Winsock (ws2_32.dll) for the
 * Sentinel dashboard REST API. Binds to localhost only -- no external
 * network exposure.
 *
 * Why raw Winsock instead of a library?
 *   This is a learning project, and understanding socket-level HTTP
 *   is valuable. The API is simple enough that a full HTTP framework
 *   would be overkill. We handle:
 *     - TCP accept loop on a background thread
 *     - Basic HTTP/1.1 request parsing (method, path, body)
 *     - Route dispatch to handler functions
 *     - JSON response formatting
 *
 * Limitations (acceptable for localhost-only use):
 *   - No HTTPS (localhost doesn't need it)
 *   - No chunked transfer encoding
 *   - No keep-alive (connection closed after each response)
 *   - Synchronous request handling (one at a time)
 */

#include <sentinel/api_server.h>
#include <sentinel/driver_comm.h>
#include <sentinel/detection_engine.h>

namespace sentinel {

ApiServer::ApiServer(DriverComm& driver,
                     DetectionEngine& engine,
                     ServiceConfig& config,
                     std::mutex& config_mutex)
    : driver_(driver)
    , engine_(engine)
    , config_(config)
    , config_mutex_(config_mutex)
    , listen_socket_(INVALID_SOCKET)
    , running_(false) {
}

ApiServer::~ApiServer() {
    stop();
}

/* -------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------- */

bool ApiServer::start(int port) {
#ifdef _WIN32
    /*
     * Initialize Winsock. This must be called before any socket API.
     * WSAStartup is reference-counted, so multiple calls are safe
     * (each needs a matching WSACleanup).
     */
    WSADATA wsa_data;
    int wsa_result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (wsa_result != 0) {
        std::fprintf(stderr,
            "[ApiServer] WSAStartup failed with error %d\n", wsa_result);
        return false;
    }

    /* Create the listening socket. */
    listen_socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket_ == INVALID_SOCKET) {
        std::fprintf(stderr, "[ApiServer] socket() failed\n");
        WSACleanup();
        return false;
    }

    /* Allow port reuse (helpful during development restarts). */
    int opt = 1;
    setsockopt(listen_socket_, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&opt), sizeof(opt));

    /*
     * Bind to localhost only (127.0.0.1). This is a security requirement
     * from CLAUDE.md: "REST API binds to localhost only -- no external
     * network exposure."
     */
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* 127.0.0.1 */

    if (bind(listen_socket_, reinterpret_cast<sockaddr*>(&addr),
             sizeof(addr)) == SOCKET_ERROR) {
        std::fprintf(stderr,
            "[ApiServer] bind() failed on port %d\n", port);
        closesocket(listen_socket_);
        listen_socket_ = INVALID_SOCKET;
        WSACleanup();
        return false;
    }

    /* Start listening with a small backlog (dashboard is the only client). */
    if (listen(listen_socket_, 5) == SOCKET_ERROR) {
        std::fprintf(stderr, "[ApiServer] listen() failed\n");
        closesocket(listen_socket_);
        listen_socket_ = INVALID_SOCKET;
        WSACleanup();
        return false;
    }

    start_time_ = std::chrono::steady_clock::now();
    running_ = true;
    server_thread_ = std::thread(&ApiServer::accept_loop, this);

    return true;
#else
    (void)port;
    return false;
#endif
}

void ApiServer::stop() {
    running_ = false;

#ifdef _WIN32
    /* Close the listening socket to unblock accept(). */
    if (listen_socket_ != INVALID_SOCKET) {
        closesocket(listen_socket_);
        listen_socket_ = INVALID_SOCKET;
    }
#endif

    if (server_thread_.joinable()) {
        server_thread_.join();
    }

#ifdef _WIN32
    WSACleanup();
#endif
}

bool ApiServer::is_running() const {
    return running_;
}

/* -------------------------------------------------------------------
 * accept_loop -- Background thread that accepts incoming connections.
 *
 * Each accepted connection is handled synchronously (one at a time).
 * For a localhost-only API with a single dashboard client, this is
 * perfectly adequate.
 * ------------------------------------------------------------------- */

void ApiServer::accept_loop() {
#ifdef _WIN32
    while (running_) {
        /*
         * Set a timeout on accept so we can check running_ periodically.
         * Without this, accept() would block forever and prevent shutdown.
         */
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_socket_, &read_fds);

        timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int select_result = select(0, &read_fds, nullptr, nullptr, &timeout);
        if (select_result <= 0) {
            continue; /* Timeout or error -- check running_ and retry. */
        }

        SOCKET client = accept(listen_socket_, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            continue;
        }

        handle_client(client);
        closesocket(client);
    }
#endif
}

/* -------------------------------------------------------------------
 * handle_client -- Read a request, route it, and send a response.
 *
 * We read up to 8KB of request data, which is more than enough for
 * any request the dashboard will send. Large request bodies (like
 * config updates) are well under 1KB.
 * ------------------------------------------------------------------- */

void ApiServer::handle_client(SOCKET client_socket) {
#ifdef _WIN32
    /* Read the raw HTTP request. */
    char buffer[8192];
    int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        return;
    }
    buffer[bytes_received] = '\0';

    /* Parse the HTTP request. */
    HttpRequest request = parse_request(std::string(buffer, bytes_received));

    /* Route to the appropriate handler. */
    HttpResponse response;

    if (request.method == "GET" && request.path == "/api/status") {
        response = handle_status();
    } else if (request.method == "GET" && request.path == "/api/devices") {
        response = handle_devices();
    } else if (request.method == "GET" && request.path == "/api/alerts") {
        response = handle_alerts(request);
    } else if (request.method == "GET" && request.path == "/api/config") {
        response = handle_get_config();
    } else if (request.method == "PUT" && request.path == "/api/config") {
        response = handle_put_config(request);
    } else if (request.method == "GET" && request.path == "/api/stats") {
        response = handle_stats();
    } else {
        response = make_error(404, "Not found");
    }

    send_response(client_socket, response);
#else
    (void)client_socket;
#endif
}

/* -------------------------------------------------------------------
 * parse_request -- Parse a raw HTTP request string.
 *
 * HTTP/1.1 request format:
 *   METHOD /path?query=value HTTP/1.1\r\n
 *   Header-Name: value\r\n
 *   \r\n
 *   body
 *
 * We only need the method, path, query params, and body.
 * ------------------------------------------------------------------- */

ApiServer::HttpRequest ApiServer::parse_request(const std::string& raw) {
    HttpRequest req;

    /* Find the request line (first line). */
    size_t first_newline = raw.find("\r\n");
    if (first_newline == std::string::npos) {
        first_newline = raw.find('\n');
    }
    if (first_newline == std::string::npos) return req;

    std::string request_line = raw.substr(0, first_newline);

    /* Parse: METHOD /path HTTP/1.1 */
    size_t method_end = request_line.find(' ');
    if (method_end == std::string::npos) return req;
    req.method = request_line.substr(0, method_end);

    size_t path_start = method_end + 1;
    size_t path_end = request_line.find(' ', path_start);
    if (path_end == std::string::npos) path_end = request_line.size();
    std::string full_path = request_line.substr(path_start, path_end - path_start);

    /* Split path and query string. */
    size_t query_start = full_path.find('?');
    if (query_start != std::string::npos) {
        req.path = full_path.substr(0, query_start);
        std::string query = full_path.substr(query_start + 1);

        /* Parse query parameters: key1=val1&key2=val2 */
        std::istringstream qs(query);
        std::string param;
        while (std::getline(qs, param, '&')) {
            auto eq = param.find('=');
            if (eq != std::string::npos) {
                req.query_params[param.substr(0, eq)] = param.substr(eq + 1);
            }
        }
    } else {
        req.path = full_path;
    }

    /* Extract the body (everything after the blank line). */
    size_t body_start = raw.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        req.body = raw.substr(body_start + 4);
    }

    return req;
}

/* -------------------------------------------------------------------
 * send_response -- Write an HTTP response to the socket.
 * ------------------------------------------------------------------- */

void ApiServer::send_response(SOCKET client_socket,
                               const HttpResponse& response) {
#ifdef _WIN32
    /*
     * Build the HTTP response manually.
     * CORS headers are included for dashboard development convenience
     * (the dashboard might be served from a different port).
     */
    std::string http_response =
        "HTTP/1.1 " + std::to_string(response.status_code) + " " +
        response.status_text + "\r\n"
        "Content-Type: " + response.content_type + "\r\n"
        "Content-Length: " + std::to_string(response.body.size()) + "\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n"
        "\r\n" +
        response.body;

    send(client_socket, http_response.c_str(),
         static_cast<int>(http_response.size()), 0);
#else
    (void)client_socket;
    (void)response;
#endif
}

/* -------------------------------------------------------------------
 * Route handlers
 * ------------------------------------------------------------------- */

ApiServer::HttpResponse ApiServer::handle_status() {
    auto uptime = std::chrono::steady_clock::now() - start_time_;
    auto uptime_sec = std::chrono::duration_cast<std::chrono::seconds>(uptime).count();

    bool driver_connected = driver_.is_connected();

    HttpResponse resp;
    resp.body = "{"
        "\"service_running\":true,"
        "\"driver_connected\":" + std::string(driver_connected ? "true" : "false") + ","
        "\"uptime_seconds\":" + std::to_string(uptime_sec) + ","
        "\"api_version\":\"1.0\""
        "}";
    return resp;
}

ApiServer::HttpResponse ApiServer::handle_devices() {
    SENTINEL_DEVICE_LIST device_list;
    bool ok = driver_.get_devices(device_list);

    HttpResponse resp;

    if (!ok) {
        resp.body = "{\"error\":\"Driver not connected\",\"devices\":[]}";
        return resp;
    }

    /* Build JSON array of devices. */
    std::string devices_json = "[";
    for (UINT32 i = 0; i < device_list.device_count; ++i) {
        if (i > 0) devices_json += ",";

        const auto& dev = device_list.devices[i];
        char vendor_hex[8], device_hex[8];
        std::snprintf(vendor_hex, sizeof(vendor_hex), "0x%04X", dev.vendor_id);
        std::snprintf(device_hex, sizeof(device_hex), "0x%04X", dev.device_id);

        /* Map trust level to string. */
        const char* trust_str = "unknown";
        switch (dev.trust_level) {
            case SENTINEL_TRUST_WHITELISTED: trust_str = "whitelisted"; break;
            case SENTINEL_TRUST_SUSPICIOUS:  trust_str = "suspicious";  break;
            case SENTINEL_TRUST_BLOCKED:     trust_str = "blocked";     break;
            default: break;
        }

        std::string desc(reinterpret_cast<const char*>(dev.description),
                         strnlen(reinterpret_cast<const char*>(dev.description),
                                 sizeof(dev.description)));

        devices_json += "{"
            "\"vendor_id\":\"" + std::string(vendor_hex) + "\","
            "\"device_id\":\"" + std::string(device_hex) + "\","
            "\"bus\":" + std::to_string(dev.bus) + ","
            "\"device\":" + std::to_string(dev.device) + ","
            "\"function\":" + std::to_string(dev.function) + ","
            "\"trust\":\"" + trust_str + "\","
            "\"description\":\"" + json_escape(desc) + "\""
            "}";
    }
    devices_json += "]";

    resp.body = "{\"device_count\":" + std::to_string(device_list.device_count) +
                ",\"devices\":" + devices_json + "}";
    return resp;
}

ApiServer::HttpResponse ApiServer::handle_alerts(const HttpRequest& request) {
    /* Optional pagination: ?offset=0&limit=50 */
    int offset = 0;
    int limit = 50;

    auto offset_it = request.query_params.find("offset");
    if (offset_it != request.query_params.end()) {
        try { offset = std::stoi(offset_it->second); } catch (...) {}
    }
    auto limit_it = request.query_params.find("limit");
    if (limit_it != request.query_params.end()) {
        try { limit = std::stoi(limit_it->second); } catch (...) {}
    }

    /* Clamp to reasonable bounds. */
    if (offset < 0) offset = 0;
    if (limit < 1) limit = 1;
    if (limit > 200) limit = 200;

    auto all_events = engine_.get_all_events();
    int total = static_cast<int>(all_events.size());

    /* Build JSON array of events within the requested page. */
    std::string events_json = "[";
    int count = 0;
    for (int i = offset; i < total && count < limit; ++i, ++count) {
        if (count > 0) events_json += ",";

        const auto& evt = all_events[i];
        events_json += "{"
            "\"source\":\"" + std::string(alert_source_name(evt.source)) + "\","
            "\"severity\":\"" + std::string(severity_name(evt.severity)) + "\","
            "\"description\":\"" + json_escape(evt.description) + "\","
            "\"pid\":" + std::to_string(evt.process_id) + ","
            "\"confidence\":" + std::to_string(evt.confidence) + ","
            "\"time\":\"" + format_timestamp(evt.timestamp) + "\""
            "}";
    }
    events_json += "]";

    HttpResponse resp;
    resp.body = "{"
        "\"total\":" + std::to_string(total) + ","
        "\"offset\":" + std::to_string(offset) + ","
        "\"limit\":" + std::to_string(limit) + ","
        "\"alerts\":" + events_json +
        "}";
    return resp;
}

ApiServer::HttpResponse ApiServer::handle_get_config() {
    std::lock_guard<std::mutex> lock(config_mutex_);

    HttpResponse resp;
    resp.body = "{"
        "\"poll_interval_ms\":" + std::to_string(config_.poll_interval_ms) + ","
        "\"scan_interval_ms\":" + std::to_string(config_.scan_interval_ms) + ","
        "\"detection_threshold\":" + std::to_string(config_.detection_threshold) + ","
        "\"enable_process_monitor\":" +
            std::string(config_.enable_process_monitor ? "true" : "false") + ","
        "\"enable_signature_scan\":" +
            std::string(config_.enable_signature_scan ? "true" : "false") + ","
        "\"enable_module_integrity\":" +
            std::string(config_.enable_module_integrity ? "true" : "false") +
        "}";
    return resp;
}

ApiServer::HttpResponse ApiServer::handle_put_config(const HttpRequest& request) {
    if (request.body.empty()) {
        return make_error(400, "Empty request body");
    }

    /* Parse the JSON body (flat key-value pairs). */
    auto fields = parse_json_flat(request.body);
    if (fields.empty()) {
        return make_error(400, "Invalid JSON");
    }

    /* Update config fields that were provided. */
    {
        std::lock_guard<std::mutex> lock(config_mutex_);

        auto it = fields.find("poll_interval_ms");
        if (it != fields.end()) {
            try { config_.poll_interval_ms = std::stoi(it->second); } catch (...) {}
        }

        it = fields.find("scan_interval_ms");
        if (it != fields.end()) {
            try { config_.scan_interval_ms = std::stoi(it->second); } catch (...) {}
        }

        it = fields.find("detection_threshold");
        if (it != fields.end()) {
            try {
                double val = std::stod(it->second);
                if (val >= 0.0 && val <= 1.0) {
                    config_.detection_threshold = val;
                    engine_.set_threshold(val);
                }
            } catch (...) {}
        }

        it = fields.find("enable_process_monitor");
        if (it != fields.end()) {
            config_.enable_process_monitor = (it->second == "true");
        }

        it = fields.find("enable_signature_scan");
        if (it != fields.end()) {
            config_.enable_signature_scan = (it->second == "true");
        }

        it = fields.find("enable_module_integrity");
        if (it != fields.end()) {
            config_.enable_module_integrity = (it->second == "true");
        }
    }

    /* Return the updated config as confirmation. */
    return handle_get_config();
}

ApiServer::HttpResponse ApiServer::handle_stats() {
    auto stats = engine_.get_stats();

    HttpResponse resp;
    resp.body = "{"
        "\"total_events\":" + std::to_string(stats.total_events_received) + ","
        "\"alerts_triggered\":" + std::to_string(stats.alerts_triggered) + ","
        "\"events_by_source\":{"
            "\"pcie_enum\":" + std::to_string(stats.events_by_source[0]) + ","
            "\"dma_detect\":" + std::to_string(stats.events_by_source[1]) + ","
            "\"memory\":" + std::to_string(stats.events_by_source[2]) + ","
            "\"device_monitor\":" + std::to_string(stats.events_by_source[3]) + ","
            "\"process_monitor\":" + std::to_string(stats.events_by_source[4]) + ","
            "\"signature_scan\":" + std::to_string(stats.events_by_source[5]) + ","
            "\"module_integrity\":" + std::to_string(stats.events_by_source[6]) +
        "}"
        "}";
    return resp;
}

/* -------------------------------------------------------------------
 * JSON utilities
 * ------------------------------------------------------------------- */

std::string ApiServer::json_escape(const std::string& str) {
    std::string result;
    result.reserve(str.size() + 8);
    for (char c : str) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n";  break;
            case '\r': result += "\\r";  break;
            case '\t': result += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    /* Control character -- escape as \u00XX. */
                    char hex[8];
                    std::snprintf(hex, sizeof(hex), "\\u%04x",
                                  static_cast<unsigned char>(c));
                    result += hex;
                } else {
                    result += c;
                }
                break;
        }
    }
    return result;
}

ApiServer::HttpResponse ApiServer::make_error(int code,
                                               const std::string& message) {
    HttpResponse resp;
    resp.status_code = code;

    switch (code) {
        case 400: resp.status_text = "Bad Request"; break;
        case 404: resp.status_text = "Not Found"; break;
        case 500: resp.status_text = "Internal Server Error"; break;
        default:  resp.status_text = "Error"; break;
    }

    resp.body = "{\"error\":\"" + json_escape(message) + "\"}";
    return resp;
}

/* -------------------------------------------------------------------
 * parse_json_flat -- Minimal flat JSON object parser.
 *
 * Handles: {"key":"value", "key2":123, "key3":true}
 * Does NOT handle nested objects or arrays.
 *
 * This is intentionally simple -- a proper JSON parser would be
 * overkill for the small config payloads the dashboard sends.
 * ------------------------------------------------------------------- */

std::unordered_map<std::string, std::string> ApiServer::parse_json_flat(
    const std::string& json) {
    std::unordered_map<std::string, std::string> result;

    /* Find the opening brace. */
    size_t pos = json.find('{');
    if (pos == std::string::npos) return result;
    ++pos;

    while (pos < json.size()) {
        /* Skip whitespace and commas. */
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
               json[pos] == '\n' || json[pos] == '\r' || json[pos] == ',')) {
            ++pos;
        }

        if (pos >= json.size() || json[pos] == '}') break;

        /* Parse key (must be a quoted string). */
        if (json[pos] != '"') break;
        ++pos;
        size_t key_end = json.find('"', pos);
        if (key_end == std::string::npos) break;
        std::string key = json.substr(pos, key_end - pos);
        pos = key_end + 1;

        /* Skip colon. */
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':')) ++pos;

        /* Parse value. */
        std::string value;
        if (pos < json.size() && json[pos] == '"') {
            /* String value. */
            ++pos;
            size_t val_end = pos;
            while (val_end < json.size() && json[val_end] != '"') {
                if (json[val_end] == '\\') val_end++; /* Skip escaped char */
                val_end++;
            }
            value = json.substr(pos, val_end - pos);
            pos = val_end + 1;
        } else {
            /* Numeric or boolean value. */
            size_t val_start = pos;
            while (pos < json.size() && json[pos] != ',' &&
                   json[pos] != '}' && json[pos] != ' ') {
                ++pos;
            }
            value = json.substr(val_start, pos - val_start);
        }

        if (!key.empty()) {
            result[key] = value;
        }
    }

    return result;
}

} /* namespace sentinel */
