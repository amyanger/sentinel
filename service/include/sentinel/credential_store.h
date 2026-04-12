/*
 * sentinel/credential_store.h
 *
 * Thin wrapper around the Windows Credential Store (wincred.h) for
 * loading the collector API key. Keeps the secret off disk as much as
 * possible — on Windows, CredRead decrypts per-user blobs protected
 * by DPAPI.
 *
 * On non-Windows platforms (macOS editing environment), these functions
 * are stubs that return false. The service does not run outside Windows,
 * so this is only for static analysis.
 */

#ifndef SENTINEL_CREDENTIAL_STORE_H
#define SENTINEL_CREDENTIAL_STORE_H

#include <string>

namespace sentinel {

/**
 * Load an API key from the Windows credential store under the given target.
 *
 * @param target  Credential target name (e.g., "SentinelCollectorApiKey").
 * @param out_key Output: the retrieved key (UTF-8).
 * @return true on success. false if the credential does not exist or
 *         the platform does not support credential storage.
 */
bool load_credential(const std::string& target, std::string& out_key);

/**
 * Store an API key in the Windows credential store. Overwrites any
 * existing credential with the same target name.
 *
 * @return true on success.
 */
bool store_credential(const std::string& target, const std::string& key);

} /* namespace sentinel */

#endif /* SENTINEL_CREDENTIAL_STORE_H */
