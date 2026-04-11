/*
 * pcie_enum.c — PCIe device enumeration and fingerprinting
 *
 * Scans the PCI bus to enumerate all connected devices, fingerprints them
 * by vendor/device ID and class code, and checks against a whitelist of
 * known-good devices. Suspicious devices (FPGA boards, repurposed capture
 * cards) are flagged with elevated trust levels and generate alerts.
 *
 * PCIe Scanning on Windows:
 *   We use the PCI bus interface to read config space rather than direct
 *   port I/O. On modern Windows, HalGetBusDataByOffset() reads PCI config
 *   space in a safe, HAL-abstracted way. For device enumeration we walk
 *   all possible bus/device/function combinations (brute-force scan) since
 *   the driver needs a complete view independent of the PnP manager.
 *
 * Suspicious Vendor IDs:
 *   Known FPGA vendors commonly used in DMA cheat hardware:
 *   - 0x10EE: Xilinx (most common DMA card FPGA)
 *   - 0x1172: Intel/Altera (Stratix, Cyclone FPGAs)
 *   - 0x1D87: Rockchip (some DMA bridges)
 *   - 0x1B4B: Marvell (DMA-capable bridge chips)
 */

#include <sentinel/driver.h>
#include <ntstrsafe.h>

/* -------------------------------------------------------------------------
 * Suspicious vendor ID table
 *
 * These vendor IDs are associated with FPGA or DMA-capable hardware
 * commonly used in external cheat devices. A match does not mean the
 * device is malicious -- it means it warrants closer inspection.
 * ------------------------------------------------------------------------- */

typedef struct _SUSPICIOUS_VENDOR {
    UINT16      vendor_id;
    const char *description;
} SUSPICIOUS_VENDOR;

static const SUSPICIOUS_VENDOR g_suspicious_vendors[] = {
    { 0x10EE, "Xilinx FPGA"         },
    { 0x1172, "Intel/Altera FPGA"    },
    { 0x1D87, "Rockchip bridge"      },
    { 0x1B4B, "Marvell DMA bridge"   },
    { 0x12D8, "Pericom PCIe bridge"  },
    { 0x1217, "O2Micro (DMA bridge)" },
};

#define SUSPICIOUS_VENDOR_COUNT \
    (sizeof(g_suspicious_vendors) / sizeof(g_suspicious_vendors[0]))

/* -------------------------------------------------------------------------
 * sentinel_pcie_is_suspicious - Check if a vendor ID is suspicious.
 *
 * Returns a pointer to the matching entry's description, or NULL if the
 * vendor is not in the suspicious list.
 * ------------------------------------------------------------------------- */
static const char *sentinel_pcie_is_suspicious(UINT16 vendor_id)
{
    for (UINT32 i = 0; i < SUSPICIOUS_VENDOR_COUNT; i++) {
        if (g_suspicious_vendors[i].vendor_id == vendor_id) {
            return g_suspicious_vendors[i].description;
        }
    }
    return NULL;
}

/* -------------------------------------------------------------------------
 * sentinel_pcie_classify_device - Assign a trust level to a device.
 *
 * Currently uses a simple vendor ID check. A production implementation
 * would cross-reference a whitelist database and check class codes,
 * subsystem IDs, and other fingerprinting data.
 * ------------------------------------------------------------------------- */
static SENTINEL_DEVICE_TRUST sentinel_pcie_classify_device(
    UINT16 vendor_id,
    UINT16 device_id,
    UINT8  class_code)
{
    UNREFERENCED_PARAMETER(device_id);

    /* Check against suspicious vendor list first. */
    if (sentinel_pcie_is_suspicious(vendor_id) != NULL) {
        return SENTINEL_TRUST_SUSPICIOUS;
    }

    /*
     * Common, well-known vendor IDs are whitelisted.
     * In production this would be a proper database lookup.
     */
    switch (vendor_id) {
    case 0x8086:  /* Intel */
    case 0x1022:  /* AMD */
    case 0x10DE:  /* NVIDIA */
    case 0x1002:  /* AMD/ATI */
    case 0x14E4:  /* Broadcom */
    case 0x168C:  /* Qualcomm Atheros */
    case 0x8087:  /* Intel (wireless) */
        return SENTINEL_TRUST_WHITELISTED;

    default:
        break;
    }

    /*
     * Classify by PCI class code for remaining devices.
     * Host bridges (class 0x06) and standard peripherals are lower risk.
     */
    if (class_code == 0x06) {  /* Bridge device */
        return SENTINEL_TRUST_WHITELISTED;
    }

    return SENTINEL_TRUST_UNKNOWN;
}

/* -------------------------------------------------------------------------
 * sentinel_pcie_read_config - Read PCI config space for a device.
 *
 * Uses HalGetBusDataByOffset() to read the 256-byte PCI config space
 * header. This is the HAL-abstracted way to access PCI config on Windows.
 *
 * Returns the number of bytes actually read, or 0 on failure.
 * A return of 2 means the bus/device/function does not exist (PCI spec:
 * reading vendor ID of nonexistent device returns 0xFFFF).
 * ------------------------------------------------------------------------- */
static ULONG sentinel_pcie_read_config(
    UINT8   bus,
    UINT8   device,
    UINT8   function,
    PVOID   buffer,
    ULONG   length)
{
    /*
     * PCI_SLOT_NUMBER encodes the device and function numbers into
     * the format expected by the HAL bus data functions.
     */
    PCI_SLOT_NUMBER slot;
    slot.u.AsULONG = 0;
    slot.u.bits.DeviceNumber   = device;
    slot.u.bits.FunctionNumber = function;

    /*
     * HalGetBusDataByOffset reads PCI config space.
     * Parameters:
     *   PCIConfiguration - we're reading PCI config space
     *   bus              - PCI bus number
     *   slot.u.AsULONG   - encoded device/function
     *   buffer           - destination for config data
     *   0                - offset to start reading from
     *   length           - number of bytes to read
     *
     * Returns: number of bytes actually read.
     * Returns 0 if the bus doesn't exist.
     * Returns 2 if the device doesn't exist (vendor ID = 0xFFFF).
     */
    return HalGetBusDataByOffset(
        PCIConfiguration,
        (ULONG)bus,
        slot.u.AsULONG,
        buffer,
        0,
        length);
}

/* -------------------------------------------------------------------------
 * sentinel_pcie_scan - Enumerate all PCIe devices on the system.
 *
 * Walks all possible bus/device/function combinations (256 buses x
 * 32 devices x 8 functions = 65536 slots). For each valid device found,
 * we fingerprint it, classify its trust level, and store it in the
 * device table.
 *
 * New or suspicious devices generate alerts.
 *
 * Note: This brute-force scan is intentional -- we want a complete view
 * of the PCI topology that's independent of the Windows PnP manager,
 * since DMA cheat hardware may not properly enumerate via PnP.
 * ------------------------------------------------------------------------- */
NTSTATUS sentinel_pcie_scan(PSENTINEL_DEVICE_EXTENSION ext)
{
    KIRQL old_irql;
    UINT32 device_count = 0;
    UINT8  config_header[64]; /* First 64 bytes of PCI config space */
    ULONG  bytes_read;

    if (ext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("[Sentinel] Starting PCIe bus scan...\n");

    KeAcquireSpinLock(&ext->device_table.lock, &old_irql);

    /* Mark all existing devices as not-present before the scan. */
    for (UINT32 i = 0; i < ext->device_table.device_count; i++) {
        ext->device_table.devices[i].was_present = ext->device_table.devices[i].is_present;
        ext->device_table.devices[i].is_present  = FALSE;
    }

    KeReleaseSpinLock(&ext->device_table.lock, old_irql);

    /*
     * Walk all PCI bus/device/function combinations.
     * We limit to 8 buses for now -- most desktop systems use fewer.
     * A production driver would detect the actual bus count.
     */
    for (UINT16 bus = 0; bus < 8; bus++) {
        for (UINT8 dev = 0; dev < 32; dev++) {
            for (UINT8 func = 0; func < 8; func++) {

                bytes_read = sentinel_pcie_read_config(
                    (UINT8)bus, dev, func, config_header, sizeof(config_header));

                /*
                 * If we get back 0 or 2 bytes, the device doesn't exist.
                 * A valid PCI device returns at least 64 bytes of config data.
                 */
                if (bytes_read < sizeof(config_header)) {
                    continue;
                }

                /* Extract key fields from the PCI config header. */
                UINT16 vendor_id  = *(UINT16 *)&config_header[0];
                UINT16 device_id  = *(UINT16 *)&config_header[2];
                UINT8  revision   = config_header[8];
                UINT8  class_code = config_header[11];
                UINT8  subclass   = config_header[10];

                /* Vendor ID 0xFFFF means empty slot. */
                if (vendor_id == 0xFFFF) {
                    continue;
                }

                /* Classify the device. */
                SENTINEL_DEVICE_TRUST trust = sentinel_pcie_classify_device(
                    vendor_id, device_id, class_code);

                /* Record the device in our tracking table. */
                KeAcquireSpinLock(&ext->device_table.lock, &old_irql);

                if (device_count < SENTINEL_MAX_TRACKED_DEVICES) {
                    SENTINEL_TRACKED_DEVICE *tracked =
                        &ext->device_table.devices[device_count];

                    tracked->info.vendor_id  = vendor_id;
                    tracked->info.device_id  = device_id;
                    tracked->info.bus        = (UINT8)bus;
                    tracked->info.device     = dev;
                    tracked->info.function   = func;
                    tracked->info.class_code = class_code;
                    tracked->info.subclass   = subclass;
                    tracked->info.revision   = revision;
                    tracked->info.trust_level = (UINT32)trust;

                    LARGE_INTEGER now = KeQueryPerformanceCounter(NULL);
                    if (tracked->info.first_seen_ticks == 0) {
                        tracked->info.first_seen_ticks = (UINT64)now.QuadPart;
                    }
                    tracked->info.last_seen_ticks = (UINT64)now.QuadPart;

                    /* Copy a short description. */
                    const char *desc = sentinel_pcie_is_suspicious(vendor_id);
                    if (desc != NULL) {
                        RtlStringCbCopyA(
                            (char *)tracked->info.description,
                            sizeof(tracked->info.description),
                            desc);
                    } else {
                        RtlStringCbCopyA(
                            (char *)tracked->info.description,
                            sizeof(tracked->info.description),
                            "PCI device");
                    }

                    tracked->is_present = TRUE;
                    tracked->scan_miss_count = 0;

                    /* Copy raw config space for deeper analysis. */
                    RtlZeroMemory(tracked->config_space, sizeof(tracked->config_space));
                    RtlCopyMemory(tracked->config_space, config_header, sizeof(config_header));

                    device_count++;
                }

                KeReleaseSpinLock(&ext->device_table.lock, old_irql);

                /* Generate alert for suspicious devices. */
                if (trust == SENTINEL_TRUST_SUSPICIOUS) {
                    char alert_msg[96];
                    RtlStringCbPrintfA(alert_msg, sizeof(alert_msg),
                        "Suspicious PCIe device: vendor=0x%04X device=0x%04X "
                        "at %u:%u.%u",
                        vendor_id, device_id, (UINT32)bus, (UINT32)dev, (UINT32)func);

                    sentinel_alert_push(
                        &ext->alert_ring,
                        SENTINEL_SEVERITY_HIGH,
                        SENTINEL_SOURCE_PCIE_ENUM,
                        ((UINT64)vendor_id << 16) | device_id,
                        alert_msg);
                }
            }
        }
    }

    KeAcquireSpinLock(&ext->device_table.lock, &old_irql);
    ext->device_table.device_count = device_count;
    KeReleaseSpinLock(&ext->device_table.lock, old_irql);

    DbgPrint("[Sentinel] PCIe scan complete: %lu devices found.\n", device_count);
    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------
 * sentinel_pcie_init - Initialize the PCIe enumerator and run first scan.
 * ------------------------------------------------------------------------- */
NTSTATUS sentinel_pcie_init(PSENTINEL_DEVICE_EXTENSION ext)
{
    if (ext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&ext->device_table, sizeof(ext->device_table));
    KeInitializeSpinLock(&ext->device_table.lock);

    DbgPrint("[Sentinel] PCIe enumerator initializing...\n");

    /* Perform the initial scan at driver load time. */
    return sentinel_pcie_scan(ext);
}

/* -------------------------------------------------------------------------
 * sentinel_pcie_get_device_list - Copy device list to IOCTL output buffer.
 *
 * Called by the IOCTL handler. Copies the public SENTINEL_DEVICE_INFO
 * records from our internal tracking table into the user-facing
 * SENTINEL_DEVICE_LIST structure.
 * ------------------------------------------------------------------------- */
NTSTATUS sentinel_pcie_get_device_list(
    PSENTINEL_DEVICE_EXTENSION ext,
    SENTINEL_DEVICE_LIST *output,
    ULONG output_length,
    PULONG bytes_returned)
{
    KIRQL old_irql;
    UINT32 count;

    UNREFERENCED_PARAMETER(output_length);

    if (ext == NULL || output == NULL || bytes_returned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&ext->device_table.lock, &old_irql);

    count = ext->device_table.device_count;
    if (count > SENTINEL_MAX_DEVICES) {
        count = SENTINEL_MAX_DEVICES;
    }

    output->device_count = count;
    output->reserved = 0;

    for (UINT32 i = 0; i < count; i++) {
        RtlCopyMemory(
            &output->devices[i],
            &ext->device_table.devices[i].info,
            sizeof(SENTINEL_DEVICE_INFO));
    }

    KeReleaseSpinLock(&ext->device_table.lock, old_irql);

    *bytes_returned = sizeof(SENTINEL_DEVICE_LIST);
    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------
 * sentinel_pcie_cleanup - Release PCIe enumerator resources.
 *
 * Currently a no-op since we don't allocate dynamic memory for the
 * device table (it lives in the device extension). Provided as a hook
 * for future resource cleanup.
 * ------------------------------------------------------------------------- */
void sentinel_pcie_cleanup(PSENTINEL_DEVICE_EXTENSION ext)
{
    if (ext == NULL) {
        return;
    }

    DbgPrint("[Sentinel] PCIe enumerator cleaned up.\n");
}
