/*
 * credential_store_win.cpp
 *
 * Windows CredRead/CredWrite wrapper for the collector API key.
 */

#include <sentinel/credential_store.h>

#ifdef _WIN32
#include <windows.h>
#include <wincred.h>
#pragma comment(lib, "advapi32.lib")
#endif

namespace sentinel {

#ifdef _WIN32

static std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int wlen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
                                    static_cast<int>(s.size()),
                                    nullptr, 0);
    std::wstring w(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
                        static_cast<int>(s.size()), &w[0], wlen);
    return w;
}

bool load_credential(const std::string& target, std::string& out_key) {
    std::wstring wtarget = utf8_to_wide(target);
    PCREDENTIALW cred = nullptr;
    if (!CredReadW(wtarget.c_str(), CRED_TYPE_GENERIC, 0, &cred)) {
        return false;
    }
    out_key.assign(reinterpret_cast<const char*>(cred->CredentialBlob),
                   cred->CredentialBlobSize);
    CredFree(cred);
    return true;
}

bool store_credential(const std::string& target, const std::string& key) {
    std::wstring wtarget = utf8_to_wide(target);
    CREDENTIALW cred{};
    cred.Type              = CRED_TYPE_GENERIC;
    cred.TargetName        = const_cast<LPWSTR>(wtarget.c_str());
    cred.CredentialBlobSize= static_cast<DWORD>(key.size());
    cred.CredentialBlob    = reinterpret_cast<LPBYTE>(const_cast<char*>(key.data()));
    cred.Persist           = CRED_PERSIST_LOCAL_MACHINE;
    return CredWriteW(&cred, 0) != FALSE;
}

#else /* !_WIN32 — stub for macOS static analysis */

bool load_credential(const std::string& /*target*/, std::string& /*out_key*/) {
    return false;
}
bool store_credential(const std::string& /*target*/, const std::string& /*key*/) {
    return false;
}

#endif

} /* namespace sentinel */
