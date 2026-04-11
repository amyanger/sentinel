/*
 * ioctl.c — IOCTL dispatch handler
 *
 * Routes incoming IOCTL requests to the appropriate detection module.
 * All IOCTLs use METHOD_BUFFERED, meaning the I/O Manager copies data
 * between user and kernel space for us -- we work with SystemBuffer.
 *
 * Security: Every IOCTL handler validates input/output buffer sizes before
 * touching the data. Never trust user-mode-supplied lengths or content.
 */

#include <sentinel/driver.h>

/* -------------------------------------------------------------------------
 * sentinel_handle_get_devices - SENTINEL_IOCTL_GET_DEVICES handler.
 *
 * Copies the current PCIe device list into the user-mode output buffer.
 * Output buffer must be at least sizeof(SENTINEL_DEVICE_LIST).
 * ------------------------------------------------------------------------- */
static NTSTATUS sentinel_handle_get_devices(
    PSENTINEL_DEVICE_EXTENSION ext,
    PVOID output_buffer,
    ULONG output_length,
    PULONG bytes_returned)
{
    if (output_buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (output_length < sizeof(SENTINEL_DEVICE_LIST)) {
        DbgPrint("[Sentinel] GET_DEVICES: output buffer too small "
                 "(got %lu, need %lu)\n",
                 output_length,
                 (ULONG)sizeof(SENTINEL_DEVICE_LIST));
        return STATUS_BUFFER_TOO_SMALL;
    }

    return sentinel_pcie_get_device_list(
        ext,
        (SENTINEL_DEVICE_LIST *)output_buffer,
        output_length,
        bytes_returned);
}

/* -------------------------------------------------------------------------
 * sentinel_handle_get_alerts - SENTINEL_IOCTL_GET_ALERTS handler.
 *
 * Drains pending alerts from the ring buffer into the output batch.
 * Output buffer must be at least sizeof(SENTINEL_ALERT_BATCH).
 * ------------------------------------------------------------------------- */
static NTSTATUS sentinel_handle_get_alerts(
    PSENTINEL_DEVICE_EXTENSION ext,
    PVOID output_buffer,
    ULONG output_length,
    PULONG bytes_returned)
{
    if (output_buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (output_length < sizeof(SENTINEL_ALERT_BATCH)) {
        DbgPrint("[Sentinel] GET_ALERTS: output buffer too small "
                 "(got %lu, need %lu)\n",
                 output_length,
                 (ULONG)sizeof(SENTINEL_ALERT_BATCH));
        return STATUS_BUFFER_TOO_SMALL;
    }

    return sentinel_alert_drain(
        &ext->alert_ring,
        (SENTINEL_ALERT_BATCH *)output_buffer,
        bytes_returned);
}

/* -------------------------------------------------------------------------
 * sentinel_handle_set_config - SENTINEL_IOCTL_SET_CONFIG handler.
 *
 * Applies a new configuration from user-mode. Validates all fields before
 * committing the change.
 *
 * Input buffer must be exactly sizeof(SENTINEL_CONFIG).
 * ------------------------------------------------------------------------- */
static NTSTATUS sentinel_handle_set_config(
    PSENTINEL_DEVICE_EXTENSION ext,
    PVOID input_buffer,
    ULONG input_length)
{
    const SENTINEL_CONFIG *new_config;

    if (input_buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (input_length < sizeof(SENTINEL_CONFIG)) {
        DbgPrint("[Sentinel] SET_CONFIG: input buffer too small "
                 "(got %lu, need %lu)\n",
                 input_length,
                 (ULONG)sizeof(SENTINEL_CONFIG));
        return STATUS_BUFFER_TOO_SMALL;
    }

    new_config = (const SENTINEL_CONFIG *)input_buffer;

    /*
     * Validate configuration values. Reject clearly unreasonable values
     * that could cause driver instability (e.g., scanning every 0ms).
     */
    if (new_config->pcie_scan_interval_ms < 100) {
        DbgPrint("[Sentinel] SET_CONFIG: pcie_scan_interval_ms too low (%lu)\n",
                 new_config->pcie_scan_interval_ms);
        return STATUS_INVALID_PARAMETER;
    }

    if (new_config->memory_check_interval_ms < 100) {
        DbgPrint("[Sentinel] SET_CONFIG: memory_check_interval_ms too low (%lu)\n",
                 new_config->memory_check_interval_ms);
        return STATUS_INVALID_PARAMETER;
    }

    if (new_config->dma_timing_threshold_ns == 0) {
        DbgPrint("[Sentinel] SET_CONFIG: dma_timing_threshold_ns cannot be zero\n");
        return STATUS_INVALID_PARAMETER;
    }

    /* Commit the new configuration. */
    RtlCopyMemory(&ext->config, new_config, sizeof(SENTINEL_CONFIG));

    DbgPrint("[Sentinel] Configuration updated: pcie_scan=%lums, "
             "mem_check=%lums, dma_threshold=%luns, flags=0x%08X\n",
             ext->config.pcie_scan_interval_ms,
             ext->config.memory_check_interval_ms,
             ext->config.dma_timing_threshold_ns,
             ext->config.flags);

    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------
 * sentinel_handle_protect_region - SENTINEL_IOCTL_PROTECT_REGION handler.
 *
 * Registers or unregisters a memory region for integrity monitoring.
 * Input buffer must be exactly sizeof(SENTINEL_PROTECT_REQUEST).
 * ------------------------------------------------------------------------- */
static NTSTATUS sentinel_handle_protect_region(
    PSENTINEL_DEVICE_EXTENSION ext,
    PVOID input_buffer,
    ULONG input_length)
{
    const SENTINEL_PROTECT_REQUEST *request;

    if (input_buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (input_length < sizeof(SENTINEL_PROTECT_REQUEST)) {
        DbgPrint("[Sentinel] PROTECT_REGION: input buffer too small "
                 "(got %lu, need %lu)\n",
                 input_length,
                 (ULONG)sizeof(SENTINEL_PROTECT_REQUEST));
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (const SENTINEL_PROTECT_REQUEST *)input_buffer;

    /* Validate the request. */
    if (request->base_address == 0 || request->size_bytes == 0) {
        DbgPrint("[Sentinel] PROTECT_REGION: invalid region "
                 "(base=0x%llX, size=%llu)\n",
                 request->base_address, request->size_bytes);
        return STATUS_INVALID_PARAMETER;
    }

    /* Check for overflow in (base + size). */
    if (request->base_address + request->size_bytes < request->base_address) {
        DbgPrint("[Sentinel] PROTECT_REGION: address range overflow\n");
        return STATUS_INVALID_PARAMETER;
    }

    return sentinel_memory_protect_region(ext, request);
}

/* -------------------------------------------------------------------------
 * sentinel_handle_ioctl - Main IOCTL dispatcher.
 *
 * Called from sentinel_dispatch_device_control() in main.c. Routes each
 * IOCTL code to its handler function.
 *
 * WDM pattern: The IOCTL code encodes the function number, transfer method,
 * and access rights. We already know the method is METHOD_BUFFERED because
 * that's how we defined our codes in ioctl_codes.h.
 * ------------------------------------------------------------------------- */
NTSTATUS sentinel_handle_ioctl(
    PSENTINEL_DEVICE_EXTENSION ext,
    ULONG ioctl_code,
    PVOID input_buffer,
    ULONG input_length,
    PVOID output_buffer,
    ULONG output_length,
    PULONG bytes_returned)
{
    NTSTATUS status;

    if (ext == NULL || bytes_returned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *bytes_returned = 0;

    switch (ioctl_code) {
    case SENTINEL_IOCTL_GET_DEVICES:
        status = sentinel_handle_get_devices(
            ext, output_buffer, output_length, bytes_returned);
        break;

    case SENTINEL_IOCTL_GET_ALERTS:
        status = sentinel_handle_get_alerts(
            ext, output_buffer, output_length, bytes_returned);
        break;

    case SENTINEL_IOCTL_SET_CONFIG:
        status = sentinel_handle_set_config(
            ext, input_buffer, input_length);
        break;

    case SENTINEL_IOCTL_PROTECT_REGION:
        status = sentinel_handle_protect_region(
            ext, input_buffer, input_length);
        break;

    default:
        DbgPrint("[Sentinel] Unknown IOCTL code: 0x%08X\n", ioctl_code);
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    return status;
}
