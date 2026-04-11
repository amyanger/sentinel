/*
 * signature_scanner.cpp -- SignatureScanner implementation.
 *
 * Performs byte-pattern matching against process memory to detect known
 * cheat signatures. This is the classic "signature scan" approach used
 * by antivirus and anticheat software.
 *
 * How pattern matching works:
 *   A signature is a sequence of bytes with optional wildcards.
 *   Example: "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ??"
 *   - "48" must match exactly byte 0x48
 *   - "??" matches any byte (wildcard)
 *
 *   The scanner slides through memory byte-by-byte, checking each
 *   position against every loaded signature. On a match, a detection
 *   event is generated with the signature's confidence score.
 *
 * Performance note: This is O(n * m * k) where n = memory size,
 * m = number of signatures, k = average pattern length. For production
 * use, you'd want Aho-Corasick or similar multi-pattern algorithms.
 * The linear approach here is chosen for clarity.
 */

#include <sentinel/signature_scanner.h>

namespace sentinel {

SignatureScanner::SignatureScanner()
    : active_(false) {
}

SignatureScanner::~SignatureScanner() {
    stop();
}

/* -------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------- */

bool SignatureScanner::start(const std::string& db_path,
                              DetectionCallback callback) {
    callback_ = std::move(callback);
    auto sigs = load_database(db_path);

    if (sigs.empty()) {
        /* No signatures loaded -- not necessarily an error (empty db). */
        std::fprintf(stderr,
            "[SignatureScanner] Warning: No signatures loaded from %s\n",
            db_path.c_str());
    }

    {
        std::lock_guard<std::mutex> lock(signatures_mutex_);
        signatures_ = std::move(sigs);
    }

    active_ = true;
    return true;
}

void SignatureScanner::stop() {
    active_ = false;
}

size_t SignatureScanner::signature_count() const {
    std::lock_guard<std::mutex> lock(signatures_mutex_);
    return signatures_.size();
}

bool SignatureScanner::reload_signatures(const std::string& db_path) {
    auto sigs = load_database(db_path);
    std::lock_guard<std::mutex> lock(signatures_mutex_);
    signatures_ = std::move(sigs);
    return !signatures_.empty();
}

/* -------------------------------------------------------------------
 * scan_process -- Scan all loaded modules in a target process.
 *
 * Strategy:
 *   1. Take a snapshot of the target process's module list
 *   2. For each module, read its memory into a local buffer
 *   3. Run scan_buffer against the local copy
 *   4. Collect and return all matches
 *
 * We read memory into a local buffer rather than scanning in-place
 * because ReadProcessMemory is slow per call -- better to do one
 * large read than many small ones.
 * ------------------------------------------------------------------- */

std::vector<DetectionEvent> SignatureScanner::scan_process(DWORD pid) {
    std::vector<DetectionEvent> all_detections;

    if (!active_) return all_detections;

#ifdef _WIN32
    /* Open the target process for memory reading. */
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                  FALSE, pid);
    if (!process) {
        return all_detections;
    }

    /* Snapshot the module list. */
    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        CloseHandle(process);
        return all_detections;
    }

    MODULEENTRY32 mod_entry;
    mod_entry.dwSize = sizeof(mod_entry);

    if (Module32First(snapshot, &mod_entry)) {
        do {
            /*
             * Read the module's memory region. We cap at 64MB to avoid
             * excessive memory usage on unusually large modules.
             */
            size_t module_size = mod_entry.modBaseSize;
            constexpr size_t MAX_SCAN_SIZE = 64 * 1024 * 1024;
            if (module_size > MAX_SCAN_SIZE) {
                module_size = MAX_SCAN_SIZE;
            }

            std::vector<uint8_t> buffer(module_size);
            SIZE_T bytes_read = 0;

            if (ReadProcessMemory(process, mod_entry.modBaseAddr,
                                   buffer.data(), module_size, &bytes_read)) {
                auto detections = scan_buffer(buffer.data(), bytes_read, pid);

                /* Annotate detections with the module name for context. */
                for (auto& det : detections) {
                    det.description += " [in module: " +
                                       std::string(mod_entry.szModule) + "]";
                }

                all_detections.insert(all_detections.end(),
                                       detections.begin(), detections.end());
            }
        } while (Module32Next(snapshot, &mod_entry));
    }

    CloseHandle(snapshot);
    CloseHandle(process);
#else
    (void)pid;
#endif

    return all_detections;
}

/* -------------------------------------------------------------------
 * scan_buffer -- Scan a raw memory buffer against all signatures.
 *
 * This is the core matching engine. For each loaded signature, we
 * call find_pattern to search the buffer. If a match is found, we
 * create a DetectionEvent with the signature's metadata.
 * ------------------------------------------------------------------- */

std::vector<DetectionEvent> SignatureScanner::scan_buffer(
    const uint8_t* data, size_t data_size, DWORD context_pid) {
    std::vector<DetectionEvent> detections;

    std::lock_guard<std::mutex> lock(signatures_mutex_);

    for (const auto& sig : signatures_) {
        ptrdiff_t offset = find_pattern(data, data_size, sig);
        if (offset >= 0) {
            DetectionEvent event;
            event.source = AlertSource::SIGNATURE_SCAN;
            event.severity = SENTINEL_SEVERITY_HIGH;
            event.description = "Signature match: " + sig.name +
                                " at offset 0x" +
                                ([](ptrdiff_t v) {
                                    char hex[32];
                                    std::snprintf(hex, sizeof(hex), "%lX",
                                                  static_cast<long>(v));
                                    return std::string(hex);
                                })(offset);
            event.process_id = context_pid;
            event.confidence = sig.confidence;
            event.timestamp = std::chrono::system_clock::now();
            detections.push_back(std::move(event));

            /* Deliver immediately through callback if available. */
            if (callback_) {
                callback_(detections.back());
            }
        }
    }

    return detections;
}

/* -------------------------------------------------------------------
 * find_pattern -- Search for a single signature in a buffer.
 *
 * This is a straightforward linear scan:
 *   For each position in the buffer:
 *     For each byte in the pattern:
 *       If the mask says "must match" and the bytes differ: break
 *       If we get through the whole pattern: match found
 *
 * Returns the offset of the first match, or -1 if not found.
 * ------------------------------------------------------------------- */

ptrdiff_t SignatureScanner::find_pattern(const uint8_t* data, size_t data_size,
                                          const Signature& sig) {
    if (sig.pattern.empty() || data_size < sig.pattern.size()) {
        return -1;
    }

    size_t scan_end = data_size - sig.pattern.size();

    for (size_t i = 0; i <= scan_end; ++i) {
        bool matched = true;

        for (size_t j = 0; j < sig.pattern.size(); ++j) {
            /*
             * mask[j] == true means this byte must match exactly.
             * mask[j] == false means it's a wildcard (skip).
             */
            if (sig.mask[j] && data[i + j] != sig.pattern[j]) {
                matched = false;
                break;
            }
        }

        if (matched) {
            return static_cast<ptrdiff_t>(i);
        }
    }

    return -1;
}

/* -------------------------------------------------------------------
 * parse_pattern -- Convert a pattern string to bytes and mask.
 *
 * Input:  "48 8B ?? ?? 74 ??"
 * Output: bytes = {0x48, 0x8B, 0x00, 0x00, 0x74, 0x00}
 *         mask  = {true, true, false, false, true, false}
 * ------------------------------------------------------------------- */

bool SignatureScanner::parse_pattern(const std::string& pattern_str,
                                      std::vector<uint8_t>& out_bytes,
                                      std::vector<bool>& out_mask) {
    out_bytes.clear();
    out_mask.clear();

    std::istringstream stream(pattern_str);
    std::string token;

    while (stream >> token) {
        if (token == "??" || token == "?") {
            /* Wildcard byte. */
            out_bytes.push_back(0x00);
            out_mask.push_back(false);
        } else {
            /* Hex byte -- parse it. */
            unsigned int byte_val = 0;
            try {
                byte_val = std::stoul(token, nullptr, 16);
            } catch (...) {
                /* Invalid hex token -- parsing failed. */
                out_bytes.clear();
                out_mask.clear();
                return false;
            }

            if (byte_val > 0xFF) {
                out_bytes.clear();
                out_mask.clear();
                return false;
            }

            out_bytes.push_back(static_cast<uint8_t>(byte_val));
            out_mask.push_back(true);
        }
    }

    return !out_bytes.empty();
}

/* -------------------------------------------------------------------
 * load_database -- Parse a signature database file.
 *
 * File format (INI-like, one signature per section):
 *
 *   [CheatEngine_Speed_Hack]
 *   description=Detects CheatEngine speed hack module
 *   confidence=0.90
 *   pattern=48 8B 05 ?? ?? ?? ?? FF 50 08 48 85 C0
 *
 *   [AimBot_Pattern_v2]
 *   description=Common aimbot angle calculation
 *   confidence=0.75
 *   pattern=F3 0F 10 ?? ?? F3 0F 5C ?? ?? F3 0F 11
 *
 * Lines starting with # are comments. Empty lines are ignored.
 * ------------------------------------------------------------------- */

std::vector<SignatureScanner::Signature> SignatureScanner::load_database(
    const std::string& db_path) {
    std::vector<Signature> signatures;

    std::ifstream file(db_path);
    if (!file.is_open()) {
        return signatures;
    }

    Signature current;
    bool in_signature = false;
    std::string line;

    while (std::getline(file, line)) {
        /* Trim leading/trailing whitespace. */
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        line = line.substr(start);
        size_t end = line.find_last_not_of(" \t\r\n");
        if (end != std::string::npos) line = line.substr(0, end + 1);

        /* Skip comments. */
        if (line.empty() || line[0] == '#') continue;

        /* New signature section: [SignatureName] */
        if (line.front() == '[' && line.back() == ']') {
            /* Save the previous signature if it's complete. */
            if (in_signature && !current.pattern.empty()) {
                signatures.push_back(std::move(current));
            }

            current = Signature();
            current.name = line.substr(1, line.size() - 2);
            in_signature = true;
            continue;
        }

        if (!in_signature) continue;

        /* Key=value pairs within a signature section. */
        auto eq_pos = line.find('=');
        if (eq_pos == std::string::npos) continue;

        std::string key = line.substr(0, eq_pos);
        std::string value = line.substr(eq_pos + 1);

        if (key == "description") {
            current.description = value;
        } else if (key == "confidence") {
            try {
                current.confidence = std::stod(value);
            } catch (...) {
                current.confidence = 0.5;
            }
        } else if (key == "pattern") {
            parse_pattern(value, current.pattern, current.mask);
        }
    }

    /* Don't forget the last signature. */
    if (in_signature && !current.pattern.empty()) {
        signatures.push_back(std::move(current));
    }

    std::fprintf(stderr, "[SignatureScanner] Loaded %zu signatures from %s\n",
                 signatures.size(), db_path.c_str());

    return signatures;
}

} /* namespace sentinel */
