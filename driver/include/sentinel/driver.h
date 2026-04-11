/*
 * sentinel/driver.h — Internal driver header
 *
 * Central header for the Sentinel kernel driver. Defines the device
 * extension structure (our per-device state), declares all module
 * functions, and sets internal constants.
 *
 * Every source file in the driver includes this header.
 */

#ifndef SENTINEL_DRIVER_H
#define SENTINEL_DRIVER_H

#include <ntddk.h>
#include <wdm.h>

#include <sentinel/types.h>
#include <sentinel/ioctl_codes.h>
#include <sentinel/shared_types.h>

/* -------------------------------------------------------------------------
 * Constants
 * ------------------------------------------------------------------------- */

/* NT device and symbolic link names for the driver. User-mode opens
 * \\.\Sentinel to communicate via DeviceIoControl(). */
#define SENTINEL_DEVICE_NAME    L"\\Device\\Sentinel"
#define SENTINEL_SYMLINK_NAME   L"\\DosDevices\\Sentinel"

/* Default configuration values applied at driver load. */
#define SENTINEL_DEFAULT_PCIE_SCAN_INTERVAL_MS    5000
#define SENTINEL_DEFAULT_MEMORY_CHECK_INTERVAL_MS 2000
#define SENTINEL_DEFAULT_DMA_THRESHOLD_NS         500
#define SENTINEL_DEFAULT_ALERT_POLL_INTERVAL_MS   1000

/* Driver pool tag for memory allocations (appears in !poolused output). */
#define SENTINEL_POOL_TAG 'lntS'  /* 'Sntl' reversed for little-endian */

/* -------------------------------------------------------------------------
 * Device Extension
 *
 * This is the driver's per-device state structure, stored in the
 * DEVICE_OBJECT->DeviceExtension field. It holds all subsystem state
 * so the driver is fully self-contained with no global variables.
 *
 * WDM pattern: The I/O Manager allocates DeviceExtension when we call
 * IoCreateDevice(). We cast DeviceObject->DeviceExtension to this type.
 * ------------------------------------------------------------------------- */

typedef struct _SENTINEL_DEVICE_EXTENSION {
    PDEVICE_OBJECT  self;           /* Back-pointer to our device object */

    /* Alert ring buffer -- all subsystems enqueue alerts here */
    SENTINEL_RING_BUFFER alert_ring;

    /* PCIe device tracking table */
    SENTINEL_DEVICE_TABLE device_table;

    /* Protected memory region table */
    SENTINEL_REGION_TABLE region_table;

    /* Active configuration */
    SENTINEL_CONFIG config;

    /* PnP notification handle -- must be unregistered on unload */
    PVOID pnp_notification_handle;

    /* Flag indicating subsystems are initialized (for clean teardown) */
    BOOLEAN subsystems_initialized;

} SENTINEL_DEVICE_EXTENSION, *PSENTINEL_DEVICE_EXTENSION;

/* -------------------------------------------------------------------------
 * Module Function Declarations
 *
 * Each source file implements one detection module. Functions are prefixed
 * with sentinel_ per the project coding conventions.
 * ------------------------------------------------------------------------- */

/* --- main.c: IRP dispatch routines --- */

/**
 * sentinel_dispatch_create - Handle IRP_MJ_CREATE requests.
 *
 * Called when user-mode opens a handle to \Device\Sentinel via CreateFile().
 * We simply complete the IRP with STATUS_SUCCESS -- no per-handle state needed.
 */
NTSTATUS sentinel_dispatch_create(PDEVICE_OBJECT device_object, PIRP irp);

/**
 * sentinel_dispatch_close - Handle IRP_MJ_CLOSE requests.
 *
 * Called when the last handle to our device is closed. Clean completion.
 */
NTSTATUS sentinel_dispatch_close(PDEVICE_OBJECT device_object, PIRP irp);

/**
 * sentinel_dispatch_device_control - Handle IRP_MJ_DEVICE_CONTROL requests.
 *
 * Routes incoming IOCTLs to the appropriate handler in ioctl.c.
 */
NTSTATUS sentinel_dispatch_device_control(PDEVICE_OBJECT device_object, PIRP irp);

/* --- ioctl.c: IOCTL dispatch --- */

/**
 * sentinel_handle_ioctl - Process a single IOCTL request.
 *
 * Validates buffer sizes, extracts the control code, and dispatches to
 * the appropriate module function. Returns NTSTATUS for IRP completion.
 *
 * @ext:              Device extension containing driver state.
 * @ioctl_code:       The IOCTL control code from the IRP stack location.
 * @input_buffer:     Pointer to the input buffer (may be NULL).
 * @input_length:     Size of the input buffer in bytes.
 * @output_buffer:    Pointer to the output buffer (may be NULL).
 * @output_length:    Size of the output buffer in bytes.
 * @bytes_returned:   [out] Number of bytes written to the output buffer.
 */
NTSTATUS sentinel_handle_ioctl(
    PSENTINEL_DEVICE_EXTENSION ext,
    ULONG ioctl_code,
    PVOID input_buffer,
    ULONG input_length,
    PVOID output_buffer,
    ULONG output_length,
    PULONG bytes_returned
);

/* --- pcie_enum.c: PCIe device enumeration --- */

/**
 * sentinel_pcie_init - Initialize the PCIe enumerator.
 *
 * Sets up the device table and performs the initial PCIe bus scan.
 */
NTSTATUS sentinel_pcie_init(PSENTINEL_DEVICE_EXTENSION ext);

/**
 * sentinel_pcie_scan - Perform a full PCIe bus scan.
 *
 * Enumerates all PCIe devices, fingerprints them, checks against the
 * whitelist, and generates alerts for new or suspicious devices.
 */
NTSTATUS sentinel_pcie_scan(PSENTINEL_DEVICE_EXTENSION ext);

/**
 * sentinel_pcie_get_device_list - Copy current device list to output buffer.
 *
 * Called by the IOCTL handler to serve SENTINEL_IOCTL_GET_DEVICES.
 */
NTSTATUS sentinel_pcie_get_device_list(
    PSENTINEL_DEVICE_EXTENSION ext,
    SENTINEL_DEVICE_LIST *output,
    ULONG output_length,
    PULONG bytes_returned
);

/**
 * sentinel_pcie_cleanup - Release PCIe enumerator resources.
 */
void sentinel_pcie_cleanup(PSENTINEL_DEVICE_EXTENSION ext);

/* --- dma_detect.c: DMA anomaly detection --- */

/**
 * sentinel_dma_init - Initialize the DMA anomaly detector.
 *
 * Checks for IOMMU/VT-d presence and records baseline state.
 */
NTSTATUS sentinel_dma_init(PSENTINEL_DEVICE_EXTENSION ext);

/**
 * sentinel_dma_check - Run a DMA anomaly detection pass.
 *
 * Checks IOMMU state, verifies DMA remapping, and performs timing analysis.
 * Generates alerts for any detected anomalies.
 */
NTSTATUS sentinel_dma_check(PSENTINEL_DEVICE_EXTENSION ext);

/**
 * sentinel_dma_cleanup - Release DMA detector resources.
 */
void sentinel_dma_cleanup(PSENTINEL_DEVICE_EXTENSION ext);

/* --- memory_integrity.c: Memory integrity monitoring --- */

/**
 * sentinel_memory_init - Initialize the memory integrity monitor.
 */
NTSTATUS sentinel_memory_init(PSENTINEL_DEVICE_EXTENSION ext);

/**
 * sentinel_memory_protect_region - Register or unregister a protected region.
 *
 * @ext:     Device extension.
 * @request: Protection request from user-mode (address, size, add/remove).
 */
NTSTATUS sentinel_memory_protect_region(
    PSENTINEL_DEVICE_EXTENSION ext,
    const SENTINEL_PROTECT_REQUEST *request
);

/**
 * sentinel_memory_check_integrity - Check all protected regions for changes.
 *
 * Computes current hashes of protected regions and compares against baselines.
 * Generates alerts for any regions whose contents have changed.
 */
NTSTATUS sentinel_memory_check_integrity(PSENTINEL_DEVICE_EXTENSION ext);

/**
 * sentinel_memory_cleanup - Release memory monitor resources.
 */
void sentinel_memory_cleanup(PSENTINEL_DEVICE_EXTENSION ext);

/* --- device_monitor.c: PnP device monitoring --- */

/**
 * sentinel_devmon_init - Register PnP notification callbacks.
 *
 * Registers with the I/O Manager to receive notifications when new
 * devices arrive or existing devices are removed.
 */
NTSTATUS sentinel_devmon_init(
    PSENTINEL_DEVICE_EXTENSION ext,
    PDRIVER_OBJECT driver_object
);

/**
 * sentinel_devmon_cleanup - Unregister PnP notification callbacks.
 */
void sentinel_devmon_cleanup(PSENTINEL_DEVICE_EXTENSION ext);

/* --- Alert ring buffer helpers (used by all modules) --- */

/**
 * sentinel_alert_init - Initialize the alert ring buffer.
 */
void sentinel_alert_init(SENTINEL_RING_BUFFER *ring);

/**
 * sentinel_alert_push - Enqueue a new alert into the ring buffer.
 *
 * Thread-safe via spinlock. If the buffer is full, the oldest alert
 * is overwritten and the drop counter is incremented.
 *
 * @ring:     Ring buffer to push into.
 * @severity: Alert severity level.
 * @source:   Which subsystem generated this alert.
 * @context:  Source-specific context value.
 * @message:  Human-readable alert message (will be truncated to fit).
 */
void sentinel_alert_push(
    SENTINEL_RING_BUFFER *ring,
    SENTINEL_ALERT_SEVERITY severity,
    SENTINEL_ALERT_SOURCE source,
    UINT64 context,
    const char *message
);

/**
 * sentinel_alert_drain - Copy pending alerts into an output batch.
 *
 * Moves alerts from the ring buffer into the SENTINEL_ALERT_BATCH
 * structure for delivery to user-mode via IOCTL.
 *
 * @ring:           Ring buffer to drain.
 * @batch:          Output batch structure.
 * @bytes_returned: [out] Bytes written to the batch.
 */
NTSTATUS sentinel_alert_drain(
    SENTINEL_RING_BUFFER *ring,
    SENTINEL_ALERT_BATCH *batch,
    PULONG bytes_returned
);

#endif /* SENTINEL_DRIVER_H */
