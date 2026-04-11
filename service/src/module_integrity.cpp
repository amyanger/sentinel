/*
 * module_integrity.cpp -- ModuleIntegrity implementation.
 *
 * Validates that game DLLs haven't been tampered with by comparing
 * in-memory images against known-good SHA-256 hashes.
 *
 * Attack scenario:
 *   An attacker patches a game DLL in memory (e.g., NOPing out an
 *   anticheat check, hooking a function) without modifying the file
 *   on disk. By hashing what's actually loaded in memory and comparing
 *   to the known-good hash, we catch the modification.
 *
 * SHA-256 implementation:
 *   On Windows, we use the BCrypt API (bcrypt.dll), which is the
 *   modern Microsoft cryptographic API. It's available on Windows
 *   Vista and later, so no compatibility concerns.
 */

#include <sentinel/module_integrity.h>

#ifdef _WIN32
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

namespace sentinel {

ModuleIntegrity::ModuleIntegrity()
    : active_(false) {
}

ModuleIntegrity::~ModuleIntegrity() {
    stop();
}

/* -------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------- */

bool ModuleIntegrity::start(const std::string& db_path,
                             DetectionCallback callback) {
    callback_ = std::move(callback);
    auto db = load_database(db_path);

    {
        std::lock_guard<std::mutex> lock(db_mutex_);
        hash_db_ = std::move(db);
    }

    active_ = true;
    return !hash_db_.empty();
}

void ModuleIntegrity::stop() {
    active_ = false;
}

bool ModuleIntegrity::reload_database(const std::string& db_path) {
    auto db = load_database(db_path);
    std::lock_guard<std::mutex> lock(db_mutex_);
    hash_db_ = std::move(db);
    return !hash_db_.empty();
}

size_t ModuleIntegrity::tracked_module_count() const {
    std::lock_guard<std::mutex> lock(db_mutex_);
    return hash_db_.size();
}

/* -------------------------------------------------------------------
 * verify_process -- Check all tracked modules in a target process.
 *
 * Steps:
 *   1. Enumerate modules loaded in the target process
 *   2. For each module that's in our hash database:
 *      a. Read its in-memory image via ReadProcessMemory
 *      b. Compute SHA-256 of the in-memory bytes
 *      c. Compare to the expected hash
 *      d. Report mismatches as tampering detections
 * ------------------------------------------------------------------- */

std::vector<DetectionEvent> ModuleIntegrity::verify_process(DWORD pid) {
    std::vector<DetectionEvent> detections;

    if (!active_) return detections;

#ifdef _WIN32
    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return detections;
    }

    MODULEENTRY32 mod_entry;
    mod_entry.dwSize = sizeof(mod_entry);

    std::lock_guard<std::mutex> lock(db_mutex_);

    if (Module32First(snapshot, &mod_entry)) {
        do {
            /* Convert module name to lowercase for database lookup. */
            std::string mod_name = mod_entry.szModule;
            std::string mod_lower = mod_name;
            std::transform(mod_lower.begin(), mod_lower.end(),
                           mod_lower.begin(), ::tolower);

            /* Check if this module is in our hash database. */
            auto it = hash_db_.find(mod_lower);
            if (it == hash_db_.end()) {
                continue; /* Not tracked -- skip. */
            }

            const std::string& expected_hash = it->second;

            /* Read the module's in-memory image. */
            auto memory = read_remote_module(
                pid,
                reinterpret_cast<uintptr_t>(mod_entry.modBaseAddr),
                mod_entry.modBaseSize);

            if (memory.empty()) {
                /* Couldn't read -- report as a potential issue. */
                DetectionEvent event;
                event.source = AlertSource::MODULE_INTEGRITY;
                event.severity = SENTINEL_SEVERITY_LOW;
                event.description = "Could not read module " + mod_name +
                                    " in PID " + std::to_string(pid);
                event.process_id = pid;
                event.confidence = 0.2;
                event.timestamp = std::chrono::system_clock::now();
                detections.push_back(std::move(event));
                continue;
            }

            /* Compute SHA-256 of the in-memory image. */
            std::string actual_hash = compute_sha256(
                memory.data(), memory.size());

            /* Compare against known-good. */
            if (actual_hash != expected_hash) {
                DetectionEvent event;
                event.source = AlertSource::MODULE_INTEGRITY;
                event.severity = SENTINEL_SEVERITY_HIGH;
                event.description = "Module tampered: " + mod_name +
                                    " (expected " + expected_hash.substr(0, 16) +
                                    "..., got " + actual_hash.substr(0, 16) + "...)";
                event.process_id = pid;
                event.confidence = 0.8;
                event.timestamp = std::chrono::system_clock::now();
                detections.push_back(std::move(event));

                if (callback_) {
                    callback_(detections.back());
                }
            }
        } while (Module32Next(snapshot, &mod_entry));
    }

    CloseHandle(snapshot);
#else
    (void)pid;
#endif

    return detections;
}

/* -------------------------------------------------------------------
 * compare_disk_vs_memory -- Byte-level comparison between the on-disk
 * DLL and its in-memory image.
 *
 * This is a more detailed analysis than hash comparison -- it can
 * identify exactly which bytes differ, providing evidence of what
 * was patched.
 * ------------------------------------------------------------------- */

std::vector<DetectionEvent> ModuleIntegrity::compare_disk_vs_memory(
    DWORD pid,
    const std::string& module_path,
    uintptr_t base_address,
    size_t module_size) {
    std::vector<DetectionEvent> detections;

    /* Read the on-disk file. */
    std::ifstream file(module_path, std::ios::binary);
    if (!file.is_open()) {
        return detections;
    }

    std::vector<uint8_t> disk_data(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());
    file.close();

    /* Read the in-memory image. */
    auto mem_data = read_remote_module(pid, base_address, module_size);
    if (mem_data.empty()) {
        return detections;
    }

    /*
     * Compare byte-by-byte up to the smaller size.
     *
     * Note: PE modules can differ between disk and memory legitimately
     * due to relocations, import resolution, etc. A production system
     * would need to account for these expected differences by parsing
     * the PE headers and skipping known-mutable sections. For this
     * learning implementation, we flag all differences.
     */
    size_t compare_size = std::min(disk_data.size(), mem_data.size());
    size_t diff_count = 0;
    size_t first_diff_offset = 0;

    for (size_t i = 0; i < compare_size; ++i) {
        if (disk_data[i] != mem_data[i]) {
            if (diff_count == 0) {
                first_diff_offset = i;
            }
            ++diff_count;
        }
    }

    if (diff_count > 0) {
        /*
         * Build a hex string showing the first few differing bytes
         * as evidence in the detection event.
         */
        char offset_hex[32];
        std::snprintf(offset_hex, sizeof(offset_hex), "0x%zX",
                      first_diff_offset);

        DetectionEvent event;
        event.source = AlertSource::MODULE_INTEGRITY;
        event.severity = SENTINEL_SEVERITY_HIGH;
        event.description = "Disk vs memory mismatch: " +
                            std::to_string(diff_count) + " bytes differ, " +
                            "first at offset " + offset_hex;
        event.process_id = pid;
        event.confidence = 0.75;
        event.timestamp = std::chrono::system_clock::now();
        detections.push_back(std::move(event));
    }

    return detections;
}

/* -------------------------------------------------------------------
 * compute_sha256 -- Hash a buffer using Windows BCrypt API.
 *
 * BCrypt (not to be confused with the password hashing algorithm)
 * is the modern Windows cryptographic API. It's part of the OS,
 * so no third-party libraries needed.
 *
 * Flow:
 *   1. Open an algorithm provider for SHA-256
 *   2. Create a hash object
 *   3. Feed in data
 *   4. Finalize and extract the digest
 *   5. Clean up (RAII would be nicer, but we keep it explicit here)
 * ------------------------------------------------------------------- */

std::string ModuleIntegrity::compute_sha256(const uint8_t* data, size_t size) {
#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg_handle = nullptr;
    BCRYPT_HASH_HANDLE hash_handle = nullptr;
    std::string result;

    /* Step 1: Open the SHA-256 algorithm provider. */
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &alg_handle, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status != 0) {
        return result;
    }

    /* Step 2: Determine hash object and digest sizes. */
    DWORD hash_object_size = 0;
    DWORD data_size_out = 0;
    BCryptGetProperty(alg_handle, BCRYPT_OBJECT_LENGTH,
                      reinterpret_cast<PUCHAR>(&hash_object_size),
                      sizeof(hash_object_size), &data_size_out, 0);

    DWORD hash_size = 0;
    BCryptGetProperty(alg_handle, BCRYPT_HASH_LENGTH,
                      reinterpret_cast<PUCHAR>(&hash_size),
                      sizeof(hash_size), &data_size_out, 0);

    /* Step 3: Allocate hash object buffer. */
    std::vector<uint8_t> hash_object(hash_object_size);
    std::vector<uint8_t> hash_digest(hash_size);

    /* Step 4: Create the hash object. */
    status = BCryptCreateHash(alg_handle, &hash_handle,
                               hash_object.data(), hash_object_size,
                               nullptr, 0, 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(alg_handle, 0);
        return result;
    }

    /* Step 5: Feed in the data. */
    status = BCryptHashData(hash_handle,
                             const_cast<PUCHAR>(data),
                             static_cast<ULONG>(size), 0);
    if (status != 0) {
        BCryptDestroyHash(hash_handle);
        BCryptCloseAlgorithmProvider(alg_handle, 0);
        return result;
    }

    /* Step 6: Finalize and extract the digest. */
    status = BCryptFinishHash(hash_handle, hash_digest.data(), hash_size, 0);
    if (status == 0) {
        /* Convert to hex string. */
        result.reserve(hash_size * 2);
        for (DWORD i = 0; i < hash_size; ++i) {
            char hex[3];
            std::snprintf(hex, sizeof(hex), "%02x", hash_digest[i]);
            result += hex;
        }
    }

    /* Step 7: Clean up. */
    BCryptDestroyHash(hash_handle);
    BCryptCloseAlgorithmProvider(alg_handle, 0);

    return result;
#else
    /*
     * Non-Windows stub: returns a placeholder hash.
     * Real hashing only happens on Windows at runtime.
     */
    (void)data;
    (void)size;
    return "0000000000000000000000000000000000000000000000000000000000000000";
#endif
}

/* -------------------------------------------------------------------
 * read_remote_module -- Read memory from a remote process.
 *
 * Opens the target process with PROCESS_VM_READ access and reads
 * the specified memory region. Returns empty vector on failure.
 * ------------------------------------------------------------------- */

std::vector<uint8_t> ModuleIntegrity::read_remote_module(
    DWORD pid, uintptr_t base_address, size_t size) {
    std::vector<uint8_t> buffer;

#ifdef _WIN32
    HANDLE process = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (!process) {
        return buffer;
    }

    buffer.resize(size);
    SIZE_T bytes_read = 0;

    BOOL success = ReadProcessMemory(
        process,
        reinterpret_cast<LPCVOID>(base_address),
        buffer.data(),
        size,
        &bytes_read);

    CloseHandle(process);

    if (!success || bytes_read == 0) {
        buffer.clear();
        return buffer;
    }

    /* Shrink to actual bytes read (might be less than requested). */
    buffer.resize(bytes_read);
#else
    (void)pid;
    (void)base_address;
    (void)size;
#endif

    return buffer;
}

/* -------------------------------------------------------------------
 * load_database -- Parse the known-good hash database file.
 *
 * File format (one entry per line):
 *   # Comments start with #
 *   module_name.dll=sha256hexhash
 *
 * Example:
 *   # Game client DLLs
 *   game_client.dll=a1b2c3d4e5f6...
 *   game_render.dll=f6e5d4c3b2a1...
 * ------------------------------------------------------------------- */

std::unordered_map<std::string, std::string> ModuleIntegrity::load_database(
    const std::string& db_path) {
    std::unordered_map<std::string, std::string> db;

    std::ifstream file(db_path);
    if (!file.is_open()) {
        return db;
    }

    std::string line;
    while (std::getline(file, line)) {
        /* Trim whitespace. */
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        line = line.substr(start);

        /* Skip comments. */
        if (line.empty() || line[0] == '#') continue;

        /* Parse key=value. */
        auto eq_pos = line.find('=');
        if (eq_pos == std::string::npos) continue;

        std::string module_name = line.substr(0, eq_pos);
        std::string hash_value = line.substr(eq_pos + 1);

        /* Normalize module name to lowercase. */
        std::transform(module_name.begin(), module_name.end(),
                       module_name.begin(), ::tolower);

        /* Trim whitespace from hash. */
        size_t hash_end = hash_value.find_last_not_of(" \t\r\n");
        if (hash_end != std::string::npos) {
            hash_value = hash_value.substr(0, hash_end + 1);
        }

        /* Normalize hash to lowercase. */
        std::transform(hash_value.begin(), hash_value.end(),
                       hash_value.begin(), ::tolower);

        if (!module_name.empty() && hash_value.size() == 64) {
            db[module_name] = hash_value;
        }
    }

    std::fprintf(stderr, "[ModuleIntegrity] Loaded %zu hash entries from %s\n",
                 db.size(), db_path.c_str());

    return db;
}

} /* namespace sentinel */
