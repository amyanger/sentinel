/*
 * memory_integrity.c — Memory integrity monitoring
 *
 * Allows the user-mode service to mark memory regions as "protected" and
 * then periodically checks those regions for unauthorized modifications.
 * This detects DMA-based memory writes from external hardware, as well as
 * software-based tampering with game data.
 *
 * How it works:
 *   1. The service sends SENTINEL_IOCTL_PROTECT_REGION with a base address
 *      and size for each region it wants to monitor.
 *   2. The driver computes a hash of the region's initial contents (baseline).
 *   3. Periodically, the driver re-hashes each protected region and compares
 *      against the baseline.
 *   4. If a mismatch is found, an alert is generated with the region details.
 *
 * Hashing:
 *   We use a simple FNV-1a hash for speed. This is NOT cryptographically
 *   secure, but for integrity checking it's fast and has good distribution.
 *   A production driver might use SHA-256 via the BCrypt kernel API.
 *
 * Memory access safety:
 *   Since these are user-mode virtual addresses, we must be careful about
 *   accessing them from kernel mode. We use MmIsAddressValid() and
 *   structured exception handling (__try/__except) to avoid BSoD on
 *   invalid or paged-out memory.
 */

#include <sentinel/driver.h>
#include <ntstrsafe.h>

/* -------------------------------------------------------------------------
 * sentinel_memory_fnv1a_hash - FNV-1a hash over a byte buffer.
 *
 * FNV-1a is a fast, non-cryptographic hash with good avalanche properties.
 * We use the 64-bit variant for a 8-byte digest that fits in our 32-byte
 * hash field (with zero padding).
 *
 * This runs at PASSIVE_LEVEL since we may be accessing pageable memory.
 * ------------------------------------------------------------------------- */
static UINT64 sentinel_memory_fnv1a_hash(const UINT8 *data, UINT64 length)
{
    const UINT64 FNV_OFFSET_BASIS = 14695981039346656037ULL;
    const UINT64 FNV_PRIME        = 1099511628211ULL;
    UINT64 hash = FNV_OFFSET_BASIS;

    for (UINT64 i = 0; i < length; i++) {
        hash ^= (UINT64)data[i];
        hash *= FNV_PRIME;
    }

    return hash;
}

/* -------------------------------------------------------------------------
 * sentinel_memory_compute_region_hash - Hash a memory region safely.
 *
 * Reads the memory at the given virtual address and computes its hash.
 * Uses structured exception handling to catch access violations from
 * unmapped or paged-out memory.
 *
 * Returns STATUS_SUCCESS and fills hash_out on success.
 * Returns STATUS_ACCESS_VIOLATION if the memory can't be read.
 * ------------------------------------------------------------------------- */
static NTSTATUS sentinel_memory_compute_region_hash(
    UINT64  base_address,
    UINT64  size_bytes,
    UINT8  *hash_out)
{
    UINT64 hash_value;

    /*
     * Zero the output hash buffer first. We store the 8-byte FNV hash
     * in the first 8 bytes and leave the rest zeroed.
     */
    RtlZeroMemory(hash_out, SENTINEL_HASH_SIZE);

    /*
     * Validate the address range. MmIsAddressValid() checks if the
     * given virtual address is currently mapped and accessible.
     *
     * IMPORTANT: MmIsAddressValid() is a point-in-time check -- the page
     * could become invalid immediately after. That's why we also wrap
     * the actual access in __try/__except.
     */
    if (!MmIsAddressValid((PVOID)(ULONG_PTR)base_address)) {
        return STATUS_ACCESS_VIOLATION;
    }

    /*
     * Read and hash the region under structured exception handling.
     * If the memory is paged out or the address becomes invalid during
     * our read, we catch the exception instead of crashing the system.
     */
    __try {
        hash_value = sentinel_memory_fnv1a_hash(
            (const UINT8 *)(ULONG_PTR)base_address,
            size_bytes);

        /* Store the hash value in the output buffer (little-endian). */
        RtlCopyMemory(hash_out, &hash_value, sizeof(hash_value));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[Sentinel] Memory hash: exception accessing region "
                 "at 0x%llX (size=%llu)\n", base_address, size_bytes);
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------
 * sentinel_memory_init - Initialize the memory integrity monitor.
 *
 * Zeroes the region table and initializes the spinlock. No regions are
 * protected until the service explicitly registers them via IOCTL.
 * ------------------------------------------------------------------------- */
NTSTATUS sentinel_memory_init(PSENTINEL_DEVICE_EXTENSION ext)
{
    if (ext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("[Sentinel] Memory integrity monitor initializing...\n");

    RtlZeroMemory(&ext->region_table, sizeof(ext->region_table));
    KeInitializeSpinLock(&ext->region_table.lock);

    DbgPrint("[Sentinel] Memory integrity monitor initialized. "
             "Max regions: %d\n", SENTINEL_MAX_PROTECTED_REGIONS);

    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------
 * sentinel_memory_protect_region - Register or unregister a protected region.
 *
 * Called from the IOCTL handler for SENTINEL_IOCTL_PROTECT_REGION.
 *
 * Add (SENTINEL_PROTECT_FLAG_ADD):
 *   - Finds a free slot in the region table
 *   - Computes and stores the baseline hash
 *   - Marks the slot as active
 *
 * Remove (SENTINEL_PROTECT_FLAG_REMOVE):
 *   - Finds the region by base address
 *   - Marks the slot as inactive
 * ------------------------------------------------------------------------- */
NTSTATUS sentinel_memory_protect_region(
    PSENTINEL_DEVICE_EXTENSION ext,
    const SENTINEL_PROTECT_REQUEST *request)
{
    KIRQL old_irql;
    NTSTATUS status = STATUS_SUCCESS;

    if (ext == NULL || request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->flags & SENTINEL_PROTECT_FLAG_ADD) {
        /* --- Add a new protected region --- */

        UINT8 baseline_hash[SENTINEL_HASH_SIZE];

        /*
         * Compute the baseline hash BEFORE acquiring the spinlock.
         * Hashing may take a while and we don't want to hold the lock
         * at elevated IRQL for that long. The hash function accesses
         * potentially pageable memory, which must be done at PASSIVE_LEVEL.
         */
        status = sentinel_memory_compute_region_hash(
            request->base_address,
            request->size_bytes,
            baseline_hash);

        if (!NT_SUCCESS(status)) {
            DbgPrint("[Sentinel] Memory protect: failed to hash region "
                     "at 0x%llX (status=0x%08X)\n",
                     request->base_address, status);
            return status;
        }

        /* Now acquire the lock and insert into the table. */
        KeAcquireSpinLock(&ext->region_table.lock, &old_irql);

        /* Check if we already have this region registered. */
        for (UINT32 i = 0; i < SENTINEL_MAX_PROTECTED_REGIONS; i++) {
            if (ext->region_table.regions[i].is_active &&
                ext->region_table.regions[i].base_address == request->base_address) {
                /* Already protected -- update the size and re-hash. */
                ext->region_table.regions[i].size_bytes = request->size_bytes;
                RtlCopyMemory(
                    ext->region_table.regions[i].baseline_hash,
                    baseline_hash,
                    SENTINEL_HASH_SIZE);
                ext->region_table.regions[i].violation_count = 0;

                KeReleaseSpinLock(&ext->region_table.lock, old_irql);

                DbgPrint("[Sentinel] Memory protect: updated region "
                         "at 0x%llX (size=%llu)\n",
                         request->base_address, request->size_bytes);
                return STATUS_SUCCESS;
            }
        }

        /* Find a free slot. */
        for (UINT32 i = 0; i < SENTINEL_MAX_PROTECTED_REGIONS; i++) {
            if (!ext->region_table.regions[i].is_active) {
                ext->region_table.regions[i].base_address = request->base_address;
                ext->region_table.regions[i].size_bytes   = request->size_bytes;
                ext->region_table.regions[i].is_active    = TRUE;
                ext->region_table.regions[i].violation_count = 0;

                RtlCopyMemory(
                    ext->region_table.regions[i].baseline_hash,
                    baseline_hash,
                    SENTINEL_HASH_SIZE);

                ext->region_table.region_count++;

                KeReleaseSpinLock(&ext->region_table.lock, old_irql);

                DbgPrint("[Sentinel] Memory protect: added region "
                         "at 0x%llX (size=%llu, slot=%lu)\n",
                         request->base_address, request->size_bytes, i);
                return STATUS_SUCCESS;
            }
        }

        KeReleaseSpinLock(&ext->region_table.lock, old_irql);

        DbgPrint("[Sentinel] Memory protect: no free slots (max=%d)\n",
                 SENTINEL_MAX_PROTECTED_REGIONS);
        return STATUS_INSUFFICIENT_RESOURCES;

    } else {
        /* --- Remove a protected region --- */

        KeAcquireSpinLock(&ext->region_table.lock, &old_irql);

        for (UINT32 i = 0; i < SENTINEL_MAX_PROTECTED_REGIONS; i++) {
            if (ext->region_table.regions[i].is_active &&
                ext->region_table.regions[i].base_address == request->base_address) {

                RtlZeroMemory(&ext->region_table.regions[i],
                              sizeof(SENTINEL_PROTECTED_REGION));
                ext->region_table.region_count--;

                KeReleaseSpinLock(&ext->region_table.lock, old_irql);

                DbgPrint("[Sentinel] Memory protect: removed region "
                         "at 0x%llX\n", request->base_address);
                return STATUS_SUCCESS;
            }
        }

        KeReleaseSpinLock(&ext->region_table.lock, old_irql);

        DbgPrint("[Sentinel] Memory protect: region at 0x%llX not found\n",
                 request->base_address);
        return STATUS_NOT_FOUND;
    }
}

/* -------------------------------------------------------------------------
 * sentinel_memory_check_integrity - Check all protected regions.
 *
 * Iterates through all active protected regions, re-computes their hash,
 * and compares against the stored baseline. Generates alerts for any
 * regions whose contents have changed.
 *
 * MUST be called at PASSIVE_LEVEL (below DISPATCH_LEVEL) because we
 * access potentially pageable user-mode memory.
 * ------------------------------------------------------------------------- */
NTSTATUS sentinel_memory_check_integrity(PSENTINEL_DEVICE_EXTENSION ext)
{
    KIRQL old_irql;
    UINT8 current_hash[SENTINEL_HASH_SIZE];
    NTSTATUS hash_status;

    if (ext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Skip if memory integrity checking is disabled. */
    if (!(ext->config.flags & SENTINEL_CONFIG_FLAG_MEMORY_ENABLED)) {
        return STATUS_SUCCESS;
    }

    for (UINT32 i = 0; i < SENTINEL_MAX_PROTECTED_REGIONS; i++) {
        BOOLEAN is_active;
        UINT64 base_address;
        UINT64 size_bytes;
        UINT8 stored_hash[SENTINEL_HASH_SIZE];

        /* Read region info under lock. */
        KeAcquireSpinLock(&ext->region_table.lock, &old_irql);

        is_active = ext->region_table.regions[i].is_active;
        if (is_active) {
            base_address = ext->region_table.regions[i].base_address;
            size_bytes   = ext->region_table.regions[i].size_bytes;
            RtlCopyMemory(stored_hash,
                          ext->region_table.regions[i].baseline_hash,
                          SENTINEL_HASH_SIZE);
        }

        KeReleaseSpinLock(&ext->region_table.lock, old_irql);

        if (!is_active) {
            continue;
        }

        /* Compute current hash (outside the spinlock -- may access paged memory). */
        hash_status = sentinel_memory_compute_region_hash(
            base_address, size_bytes, current_hash);

        if (!NT_SUCCESS(hash_status)) {
            /* Region became inaccessible -- that's also notable. */
            char alert_msg[96];
            RtlStringCbPrintfA(alert_msg, sizeof(alert_msg),
                "Protected region at 0x%llX (size=%llu) is no longer accessible",
                base_address, size_bytes);

            sentinel_alert_push(
                &ext->alert_ring,
                SENTINEL_SEVERITY_MEDIUM,
                SENTINEL_SOURCE_MEMORY,
                base_address,
                alert_msg);
            continue;
        }

        /* Compare current hash against baseline. */
        if (RtlCompareMemory(current_hash, stored_hash, SENTINEL_HASH_SIZE)
            != SENTINEL_HASH_SIZE) {
            /*
             * Mismatch! The region contents have changed since the
             * baseline was recorded. This could indicate:
             *   - A DMA device writing to the region
             *   - Software-based memory patching
             *   - Legitimate game state changes (if the service registered
             *     a region that naturally changes -- that's a service bug)
             */
            char alert_msg[96];
            RtlStringCbPrintfA(alert_msg, sizeof(alert_msg),
                "Memory integrity violation at 0x%llX (size=%llu)",
                base_address, size_bytes);

            sentinel_alert_push(
                &ext->alert_ring,
                SENTINEL_SEVERITY_HIGH,
                SENTINEL_SOURCE_MEMORY,
                base_address,
                alert_msg);

            /* Increment violation counter. */
            KeAcquireSpinLock(&ext->region_table.lock, &old_irql);
            if (ext->region_table.regions[i].is_active) {
                ext->region_table.regions[i].violation_count++;
            }
            KeReleaseSpinLock(&ext->region_table.lock, old_irql);
        }
    }

    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------
 * sentinel_memory_cleanup - Release memory monitor resources.
 *
 * Clears all protected regions. Currently no dynamic allocations to free.
 * ------------------------------------------------------------------------- */
void sentinel_memory_cleanup(PSENTINEL_DEVICE_EXTENSION ext)
{
    if (ext == NULL) {
        return;
    }

    KIRQL old_irql;
    KeAcquireSpinLock(&ext->region_table.lock, &old_irql);
    RtlZeroMemory(ext->region_table.regions,
                   sizeof(ext->region_table.regions));
    ext->region_table.region_count = 0;
    KeReleaseSpinLock(&ext->region_table.lock, old_irql);

    DbgPrint("[Sentinel] Memory integrity monitor cleaned up.\n");
}
