/*
 * sentinel/signature_scanner.h
 *
 * SignatureScanner performs byte-pattern matching against process memory
 * to detect known cheat signatures. This is the classic antivirus-style
 * detection approach, adapted for in-memory scanning.
 *
 * Pattern format: hex bytes with ?? wildcards.
 * Example: "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ??"
 *   - "48" matches exactly byte 0x48
 *   - "??" matches any byte (wildcard)
 *
 * The signature database is loaded from a file so it can be updated
 * without recompiling the service.
 */

#ifndef SENTINEL_SIGNATURE_SCANNER_H
#define SENTINEL_SIGNATURE_SCANNER_H

#include <sentinel/service.h>

namespace sentinel {

class SignatureScanner {
public:
    /* -------------------------------------------------------------------
     * Signature -- a named byte pattern with metadata.
     * ------------------------------------------------------------------- */
    struct Signature {
        std::string name;          /* Human-readable signature name       */
        std::string description;   /* What this signature detects         */
        std::vector<uint8_t> pattern;   /* The byte pattern to match      */
        std::vector<bool> mask;    /* true = must match, false = wildcard */
        double confidence;         /* How confident we are if this hits   */
    };

    /* Callback for delivering detections. */
    using DetectionCallback = std::function<void(const DetectionEvent&)>;

    SignatureScanner();
    ~SignatureScanner();

    SignatureScanner(const SignatureScanner&) = delete;
    SignatureScanner& operator=(const SignatureScanner&) = delete;

    /* -------------------------------------------------------------------
     * Lifecycle
     * ------------------------------------------------------------------- */

    /**
     * Load signatures from the database file and prepare for scanning.
     *
     * @param db_path   Path to the signature database file.
     * @param callback  Function called for each signature match.
     * @return true if signatures were loaded successfully.
     */
    bool start(const std::string& db_path, DetectionCallback callback);

    /** Stop and release resources. */
    void stop();

    /* -------------------------------------------------------------------
     * Scanning
     * ------------------------------------------------------------------- */

    /**
     * Scan all loaded modules in a target process for known signatures.
     *
     * Opens the target process with PROCESS_VM_READ access and reads
     * each module's memory region, scanning for pattern matches.
     *
     * @param pid  Target process ID to scan.
     * @return All signature matches found.
     */
    std::vector<DetectionEvent> scan_process(DWORD pid);

    /**
     * Scan a raw memory buffer against all loaded signatures.
     * This is the core matching engine, also useful for unit testing.
     *
     * @param data       Pointer to the memory to scan.
     * @param data_size  Size of the memory region in bytes.
     * @param context_pid  Process ID for attribution (0 if N/A).
     * @return All signature matches found.
     */
    std::vector<DetectionEvent> scan_buffer(const uint8_t* data,
                                            size_t data_size,
                                            DWORD context_pid = 0);

    /** Return the number of signatures currently loaded. */
    size_t signature_count() const;

    /**
     * Reload signatures from the database file.
     * Can be called at runtime to pick up database updates.
     */
    bool reload_signatures(const std::string& db_path);

private:
    /**
     * Parse a signature database file into Signature objects.
     *
     * File format (line-based):
     *   [SignatureName]
     *   description=What this detects
     *   confidence=0.85
     *   pattern=48 8B 05 ?? ?? ?? ?? 48 85 C0
     *
     * @param db_path  Path to the database file.
     * @return Parsed signatures.
     */
    std::vector<Signature> load_database(const std::string& db_path);

    /**
     * Parse a hex pattern string into bytes and mask arrays.
     *
     * @param pattern_str  e.g., "48 8B ?? ?? 74 ??"
     * @param out_bytes    Populated with byte values (0 for wildcards).
     * @param out_mask     Populated with true (exact) / false (wildcard).
     * @return true if parsing succeeded.
     */
    static bool parse_pattern(const std::string& pattern_str,
                              std::vector<uint8_t>& out_bytes,
                              std::vector<bool>& out_mask);

    /**
     * Search for a single pattern in a buffer. Returns the offset of the
     * first match, or -1 if not found.
     *
     * This uses a straightforward linear scan. For a production system
     * you'd want something like the Aho-Corasick algorithm for multi-
     * pattern matching, but linear scan is clear and correct.
     */
    static ptrdiff_t find_pattern(const uint8_t* data, size_t data_size,
                                  const Signature& sig);

    /**
     * Return hardcoded default signatures for known DMA cheat patterns.
     * These are always available even if no database file exists.
     */
    static std::vector<Signature> get_default_signatures();

    /**
     * Merge default and file-based signatures.
     * File signatures override defaults by matching name; unmatched
     * defaults are preserved. Logs merged counts to stderr.
     *
     * @param defaults   Hardcoded built-in signatures.
     * @param file_sigs  Signatures loaded from the database file.
     * @return Merged signature list.
     */
    static std::vector<Signature> merge_signatures(
        std::vector<Signature> defaults,
        std::vector<Signature> file_sigs);

    /* --- State --- */
    std::vector<Signature> signatures_;
    mutable std::mutex     signatures_mutex_;
    DetectionCallback      callback_;
    std::atomic<bool>      active_;
};

} /* namespace sentinel */

#endif /* SENTINEL_SIGNATURE_SCANNER_H */
