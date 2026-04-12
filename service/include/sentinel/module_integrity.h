/*
 * sentinel/module_integrity.h
 *
 * ModuleIntegrity validates that game DLLs haven't been tampered with
 * by comparing in-memory module images against known-good hashes.
 *
 * Attack scenario this detects:
 *   A cheat modifies a game's DLL in memory (patching out anticheat
 *   checks, hooking functions, etc.) but the on-disk file is untouched.
 *   By hashing the in-memory image and comparing to a known-good hash,
 *   we detect the modification.
 *
 * The known-good hash database is loaded from a file so game updates
 * can refresh it without recompiling the service.
 */

#ifndef SENTINEL_MODULE_INTEGRITY_H
#define SENTINEL_MODULE_INTEGRITY_H

#include <sentinel/service.h>

namespace sentinel {

class ModuleIntegrity {
public:
    /* A hash entry: module name -> expected SHA-256 hash. */
    struct HashEntry {
        std::string module_name;    /* DLL filename (lowercase)        */
        std::string expected_hash;  /* SHA-256 hex string (64 chars)   */
    };

    /* Callback for delivering integrity violations. */
    using DetectionCallback = std::function<void(const DetectionEvent&)>;

    ModuleIntegrity();
    ~ModuleIntegrity();

    ModuleIntegrity(const ModuleIntegrity&) = delete;
    ModuleIntegrity& operator=(const ModuleIntegrity&) = delete;

    /* -------------------------------------------------------------------
     * Lifecycle
     * ------------------------------------------------------------------- */

    /**
     * Load the known-good hash database and prepare for verification.
     *
     * @param db_path   Path to the hash database file.
     * @param callback  Function called for each integrity violation.
     * @return true if the database was loaded successfully.
     */
    bool start(const std::string& db_path, DetectionCallback callback);

    /** Release resources. */
    void stop();

    /* -------------------------------------------------------------------
     * Verification
     * ------------------------------------------------------------------- */

    /**
     * Verify all tracked modules loaded in a target process.
     *
     * For each module whose name is in our hash database, we:
     *   1. Read the module's in-memory image
     *   2. Compute its SHA-256 hash
     *   3. Compare against the known-good hash
     *   4. Report mismatches as detection events
     *
     * @param pid  Target process ID.
     * @return All integrity violations found.
     */
    std::vector<DetectionEvent> verify_process(DWORD pid);

    /**
     * Compare a module's on-disk file against its in-memory image.
     * Reports which sections/regions differ.
     *
     * @param pid          Target process ID.
     * @param module_path  Full path to the DLL file on disk.
     * @param base_address In-memory base address of the module.
     * @param module_size  Size of the module in memory.
     * @return Detection event if tampering was found, empty otherwise.
     */
    std::vector<DetectionEvent> compare_disk_vs_memory(
        DWORD pid,
        const std::string& module_path,
        uintptr_t base_address,
        size_t module_size);

    /** Reload the hash database from file. */
    bool reload_database(const std::string& db_path);

    /** Return the number of tracked module hashes. */
    size_t tracked_module_count() const;

private:
    /**
     * Parse the hash database file.
     *
     * File format (line-based):
     *   # Comments start with #
     *   module_name.dll=sha256hexhash
     *
     * @param db_path  Path to the database file.
     * @return Map of lowercase module name -> expected hash.
     */
    std::unordered_map<std::string, std::string> load_database(
        const std::string& db_path);

    /**
     * Compute SHA-256 hash of a memory buffer.
     *
     * Implementation note: We use the Windows CryptoAPI (BCrypt) on
     * Windows. This avoids pulling in a third-party crypto library.
     *
     * @param data  Pointer to the data.
     * @param size  Size in bytes.
     * @return Lowercase hex string of the SHA-256 digest.
     */
    static std::string compute_sha256(const uint8_t* data, size_t size);

    /**
     * Read a module's in-memory image from a remote process.
     *
     * @param pid           Target process ID.
     * @param base_address  Module base address in the target process.
     * @param size          Number of bytes to read.
     * @return The module's memory contents, or empty on failure.
     */
    static std::vector<uint8_t> read_remote_module(
        DWORD pid, uintptr_t base_address, size_t size);

    /**
     * Return hardcoded known-good hashes for critical Windows system DLLs.
     * Returns empty map — system DLL hashes vary per Windows Update, so
     * the file-based database (hashes.db) is the correct deployment mechanism.
     * Disk-vs-memory comparison works without any database.
     */
    static std::unordered_map<std::string, std::string> get_default_hashes();

    /* --- State --- */
    std::unordered_map<std::string, std::string> hash_db_;
    mutable std::mutex db_mutex_;
    DetectionCallback  callback_;
    std::atomic<bool>  active_;
};

} /* namespace sentinel */

#endif /* SENTINEL_MODULE_INTEGRITY_H */
