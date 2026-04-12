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

    auto defaults  = get_default_signatures();
    auto file_sigs = load_database(db_path);
    auto merged    = merge_signatures(std::move(defaults),
                                      std::move(file_sigs));

    {
        std::lock_guard<std::mutex> lock(signatures_mutex_);
        signatures_ = std::move(merged);
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
    auto defaults  = get_default_signatures();
    auto file_sigs = load_database(db_path);
    auto merged    = merge_signatures(std::move(defaults),
                                      std::move(file_sigs));

    std::lock_guard<std::mutex> lock(signatures_mutex_);
    signatures_ = std::move(merged);
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
 * merge_signatures -- Combine defaults with file-loaded signatures.
 *
 * File signatures override defaults by matching name.  Unmatched
 * defaults are kept, and all file signatures are appended.
 * ------------------------------------------------------------------- */

std::vector<SignatureScanner::Signature> SignatureScanner::merge_signatures(
    std::vector<Signature> defaults,
    std::vector<Signature> file_sigs) {

    std::vector<Signature> merged;
    merged.reserve(defaults.size() + file_sigs.size());

    /* Build name lookup for file signatures. */
    std::unordered_set<std::string> file_names;
    file_names.reserve(file_sigs.size());
    for (const auto& s : file_sigs) {
        file_names.insert(s.name);
    }

    /* Keep defaults not overridden by a file signature. */
    for (auto& s : defaults) {
        if (file_names.find(s.name) == file_names.end()) {
            merged.push_back(std::move(s));
        }
    }

    /* Append all file signatures (they take priority for shared names). */
    for (auto& s : file_sigs) {
        merged.push_back(std::move(s));
    }

    std::fprintf(stderr,
        "[SignatureScanner] Merged %zu default + %zu file signatures"
        " = %zu total\n",
        defaults.size(), file_sigs.size(), merged.size());

    return merged;
}

/* -------------------------------------------------------------------
 * get_default_signatures -- Hardcoded signatures for known cheat tools.
 *
 * These ship with the binary so detection works out of the box, even
 * when no signature database file is present on disk.  File-based
 * signatures can override any of these by matching name.
 * ------------------------------------------------------------------- */

std::vector<SignatureScanner::Signature>
SignatureScanner::get_default_signatures() {
    std::vector<Signature> defaults;

    /*
     * Helper lambda: build a Signature from a hex pattern string.
     * Validates parse_pattern return and pushes directly into defaults,
     * skipping any signature whose pattern fails to parse.
     */
    auto add_sig = [&defaults](const char* name,
                               const char* description,
                               double confidence,
                               const char* pattern_str) {
        Signature sig;
        sig.name        = name;
        sig.description = description;
        sig.confidence  = confidence;

        if (!parse_pattern(pattern_str, sig.pattern, sig.mask)) {
            std::fprintf(stderr,
                "[SignatureScanner] BUG: failed to parse built-in "
                "pattern for '%s' -- skipping\n", name);
            return;
        }

        defaults.push_back(std::move(sig));
    };

    /*
     * 1. pcileech firmware ASCII marker.
     *    The string "pcileech" appears verbatim in pcileech firmware images
     *    and in DMA-backed cheat payloads that embed the firmware blob.
     */
    add_sig(
        "pcileech_firmware_marker",
        "pcileech firmware ASCII marker found in process memory",
        0.85,
        "70 63 69 6C 65 65 63 68"   /* "pcileech" */
    );

    /*
     * 2. pcileech DMA_READ command word (0x00000001) followed by a
     *    64-bit address field, as seen in pcileech command descriptors
     *    submitted through bar1/bar2 MMIO regions.
     */
    add_sig(
        "pcileech_dma_read_cmd",
        "pcileech DMA_READ command descriptor pattern",
        0.80,
        "01 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ??"
    );

    /*
     * 3. Xilinx Artix-7 FPGA bitstream sync word (0xAA995566) followed by
     *    the TYPE1 NOP header (0x20000000).  Screamer and similar FPGA DMA
     *    boards begin their bitstreams with this sequence.
     */
    add_sig(
        "screamer_fpga_bitstream_sync",
        "Xilinx Artix-7 FPGA bitstream sync word (Screamer hardware)",
        0.90,
        "AA 99 55 66 20 00 00 00"
    );

    /*
     * 4. DMA scatter-gather list construction pattern.
     *    The byte sequence encodes a 64-bit base address load into a
     *    scatter-gather descriptor, a common pattern in DMA engine setup
     *    code injected by hardware-assisted cheats.
     *    Pattern: MOV [rax], rcx ; MOV [rax+8], rdx ; RET
     *
     *    NOTE: Broad pattern — this sequence appears in legitimate code
     *    (any function that stores two 64-bit values and returns).
     *    Confidence kept low; useful only as a supporting signal.
     */
    add_sig(
        "dma_scatter_gather_construct",
        "DMA scatter-gather list construction in process memory",
        0.40,
        "48 89 08 48 89 50 08 C3"
    );

    /*
     * 5. CheatEngine speed hack QPC hook.
     *    CheatEngine patches QueryPerformanceCounter to return a scaled
     *    value for speed hacking.  The prolog of the hooked function
     *    begins with a PUSH RBP / MOV RBP,RSP prologue immediately
     *    followed by a MOV RAX, <imm64> trampoline jump.
     *    Pattern: PUSH RBP ; MOV RBP,RSP ; MOV RAX,imm64
     */
    add_sig(
        "cheatengine_qpc_hook",
        "CheatEngine QueryPerformanceCounter speed hack hook",
        0.75,
        "55 48 89 E5 48 B8 ?? ?? ?? ?? ?? ?? ?? ??"
    );

    /*
     * 6. IAT hook trampoline.
     *    A classic Import Address Table hook overwrites a function pointer
     *    with a JMP to a trampoline stub.  The stub pattern is:
     *    FF 25 00 00 00 00 (JMP QWORD PTR [RIP+0]) followed by the
     *    absolute target address.
     *
     *    NOTE: Very broad — this is the standard import thunk format
     *    emitted by MSVC and the Windows loader for delay-load imports.
     *    Confidence kept very low; only useful combined with other signals.
     */
    add_sig(
        "iat_hook_trampoline",
        "IAT hook trampoline (FF25 absolute indirect JMP)",
        0.25,
        "FF 25 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ??"
    );

    /*
     * 7. Inline hook JMP + NOP sled.
     *    Many cheats patch the first bytes of a target function with a
     *    relative JMP (E9) followed by NOPs (90) to align the patch.
     *    Requiring 5 NOPs reduces false positives from short alignment
     *    padding while still catching typical inline hook patches.
     *    Pattern: JMP rel32 ; NOP x5
     */
    add_sig(
        "inline_hook_jmp_nop_sled",
        "Inline function hook: JMP followed by NOP sled",
        0.45,
        "E9 ?? ?? ?? ?? 90 90 90 90 90"
    );

    /*
     * 8. rawudp DMA exfiltration marker.
     *    The rawudp DMA tool embeds the ASCII tag "RDMA" in its payload
     *    headers when exfiltrating memory contents over the network.
     */
    add_sig(
        "rawudp_dma_exfil_marker",
        "rawudp DMA exfiltration payload header marker",
        0.80,
        "52 44 4D 41"   /* "RDMA" */
    );

    /*
     * 9. VirtualProtect PAGE_EXECUTE_READWRITE setup.
     *    Cheats that perform manual mapping call VirtualProtect to mark
     *    the injected region executable.  The Win32 constant for
     *    PAGE_EXECUTE_READWRITE is 0x40; this pattern captures the common
     *    MOV EDX, 0x40 ; CALL sequence used before the VirtualProtect call.
     *    Pattern: MOV EDX,0x40 ; XOR R9D,R9D ; CALL rel32
     */
    add_sig(
        "virtualprotect_exec_rw_setup",
        "VirtualProtect PAGE_EXECUTE_READWRITE setup before manual map",
        0.70,
        "BA 40 00 00 00 45 33 C9 E8 ?? ?? ?? ??"
    );

    /*
     * 10. Manual-map PE header parse pattern.
     *     Manual mappers walk the PE optional header to resolve imports.
     *     The sequence loads the DataDirectory RVA (at offset 0x78 in the
     *     optional header) with a chain of MOV/MOVZX instructions that is
     *     characteristic of PE parsing stubs.
     *     Pattern: MOV EAX,[rcx+0x3C] ; MOVZX ECX,WORD PTR [rcx+rax+0x18]
     */
    add_sig(
        "manual_map_pe_header_parse",
        "Manual mapper PE optional-header parsing stub",
        0.65,
        "8B 41 3C 0F B7 4C 01 18"
    );

    return defaults;
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
