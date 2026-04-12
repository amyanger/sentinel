/*
 * collector_http_win.cpp
 *
 * WinHTTP implementation of the collector POST.
 *
 * Compiles only on Windows (#ifdef _WIN32). On macOS, provides a stub
 * that returns false, so the file parses for static analysis.
 *
 * Strict TLS: WinHTTP is configured with WINHTTP_FLAG_SECURE and we do
 * NOT set WINHTTP_FLAG_IGNORE_* — certificate verification must succeed.
 * Cert-validation failures are reported as a distinct return code so the
 * caller can fail closed instead of retrying.
 */

#include <sentinel/collector_http.h>

/*
 * Windows system headers must be included at file scope (not inside
 * namespace sentinel) and <windows.h> must come before <winhttp.h>.
 * MSVC will refuse to compile this otherwise; macOS clang is silently
 * permissive of the old in-namespace layout, which is why this bug
 * hid during earlier syntax checks.
 */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

namespace sentinel {

#ifdef _WIN32

static std::wstring to_wstring(const std::string& s) {
    if (s.empty()) return std::wstring();
    int wlen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
                                    static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
                        static_cast<int>(s.size()), &w[0], wlen);
    return w;
}

SendResult http_post_events(const std::string& url,
                             const std::string& api_key,
                             const std::string& batch_json,
                             int& http_status) {
    http_status = 0;

    URL_COMPONENTS uc{};
    wchar_t host[256] = {};
    wchar_t path[1024] = {};
    uc.dwStructSize     = sizeof(uc);
    uc.lpszHostName     = host;
    uc.dwHostNameLength = ARRAYSIZE(host);
    uc.lpszUrlPath      = path;
    uc.dwUrlPathLength  = ARRAYSIZE(path);

    std::wstring wurl = to_wstring(url);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc)) {
        return SendResult::PermanentDrop; /* malformed URL — config bug */
    }
    bool secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    INTERNET_PORT port = uc.nPort ? uc.nPort : (secure ? 443 : 80);

    HINTERNET session = WinHttpOpen(L"SentinelCollectorClient/0.1",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return SendResult::RetryLater;

    HINTERNET connect = WinHttpConnect(session, host, port, 0);
    if (!connect) { WinHttpCloseHandle(session); return SendResult::RetryLater; }

    /* Build full path: /v1/events (append to uc.lpszUrlPath root). */
    std::wstring full_path = L"/v1/events";

    DWORD flags = secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"POST",
                                            full_path.c_str(),
                                            nullptr, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            flags);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return SendResult::RetryLater;
    }

    std::wstring headers = L"Content-Type: application/json\r\n"
                           L"Authorization: Bearer " + to_wstring(api_key) + L"\r\n";

    BOOL sent = WinHttpSendRequest(request,
                                    headers.c_str(),
                                    (DWORD)-1, /* headers length auto */
                                    (LPVOID)batch_json.data(),
                                    (DWORD)batch_json.size(),
                                    (DWORD)batch_json.size(),
                                    0);

    SendResult result = SendResult::RetryLater;

    if (!sent) {
        DWORD err = GetLastError();
        /* Cert verification failures: fail closed. */
        if (err == ERROR_WINHTTP_SECURE_FAILURE) {
            result = SendResult::CertError;
        } else {
            result = SendResult::RetryLater;
        }
    } else if (!WinHttpReceiveResponse(request, nullptr)) {
        result = SendResult::RetryLater;
    } else {
        DWORD status = 0;
        DWORD len = sizeof(status);
        WinHttpQueryHeaders(request,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX,
                             &status, &len, WINHTTP_NO_HEADER_INDEX);
        http_status = static_cast<int>(status);

        if (status >= 200 && status < 300)      result = SendResult::Accepted;
        else if (status == 400 || status == 401 || status == 413)
                                                result = SendResult::PermanentDrop;
        else if (status >= 500 && status < 600) result = SendResult::RetryLater;
        else                                    result = SendResult::RetryLater;
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return result;
}

#else /* !_WIN32 — stub for macOS static analysis */

SendResult http_post_events(const std::string& /*url*/,
                             const std::string& /*api_key*/,
                             const std::string& /*batch_json*/,
                             int& http_status) {
    http_status = 0;
    return SendResult::RetryLater;
}

#endif /* _WIN32 */

} /* namespace sentinel */
