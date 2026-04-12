/*
 * sentinel/collector_http.h
 *
 * Contract between collector_client.cpp and the platform-specific HTTP
 * sender (collector_http_win.cpp on Windows). Defining this in a shared
 * header avoids ODR problems and makes the contract explicit.
 */

#ifndef SENTINEL_COLLECTOR_HTTP_H
#define SENTINEL_COLLECTOR_HTTP_H

#include <string>

namespace sentinel {

/**
 * Result of a single POST attempt, classified so the caller can decide
 * whether to retry, drop, or fail closed.
 */
enum class SendResult {
    Accepted,        /* 2xx — drop the batch from the queue */
    RetryLater,      /* 5xx or transient network error — retain and retry */
    PermanentDrop,   /* 400, 401, 413 — drop without retry */
    CertError        /* TLS cert verification failed — fail closed */
};

/**
 * POST a JSON batch body to <url>/v1/events with the given bearer token.
 * @param http_status Out: HTTP response code (0 if no response was received).
 */
SendResult http_post_events(const std::string& url,
                             const std::string& api_key,
                             const std::string& batch_json,
                             int& http_status);

} /* namespace sentinel */

#endif /* SENTINEL_COLLECTOR_HTTP_H */
