/*
 * main.c — Sentinel kernel driver entry point
 *
 * Implements DriverEntry (driver load) and DriverUnload (driver teardown),
 * plus the basic IRP dispatch routines for Create, Close, and DeviceControl.
 *
 * WDM Driver Lifecycle:
 *   1. Windows loads the .sys and calls DriverEntry()
 *   2. DriverEntry creates a device object and symbolic link
 *   3. User-mode opens \\.\Sentinel and sends IOCTLs
 *   4. When the driver is stopped, DriverUnload() tears everything down
 *
 * The device object's DeviceExtension holds all driver state -- we avoid
 * global variables so the driver is clean and testable.
 */

#include <sentinel/driver.h>
#include <ntstrsafe.h>

/* Forward declaration for DriverEntry (SAL annotations for WDK). */
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     sentinel_driver_unload;

/* -------------------------------------------------------------------------
 * sentinel_alert_init - Initialize the alert ring buffer.
 *
 * Zeroes all slots and initializes the spinlock that protects concurrent
 * writes from different subsystems.
 * ------------------------------------------------------------------------- */
void sentinel_alert_init(SENTINEL_RING_BUFFER *ring)
{
    RtlZeroMemory(ring, sizeof(*ring));
    KeInitializeSpinLock(&ring->lock);
}

/* -------------------------------------------------------------------------
 * sentinel_alert_push - Enqueue a new alert.
 *
 * All subsystems call this to report detections. The spinlock ensures
 * safe concurrent access from different threads/IRQLs.
 *
 * If the ring buffer is full, the oldest alert is silently overwritten
 * and the drop counter increments -- the service will see this in the
 * alerts_dropped field when it polls.
 * ------------------------------------------------------------------------- */
void sentinel_alert_push(
    SENTINEL_RING_BUFFER *ring,
    SENTINEL_ALERT_SEVERITY severity,
    SENTINEL_ALERT_SOURCE source,
    UINT64 context,
    const char *message)
{
    KIRQL old_irql;
    SENTINEL_ALERT *slot;

    KeAcquireSpinLock(&ring->lock, &old_irql);

    /* Pick the next write slot. */
    slot = &ring->entries[ring->head % SENTINEL_RING_BUFFER_SIZE];

    /* If the buffer is full, we're overwriting the tail (oldest alert). */
    if (ring->count >= SENTINEL_RING_BUFFER_SIZE) {
        ring->tail = (ring->tail + 1) % SENTINEL_RING_BUFFER_SIZE;
        ring->total_dropped++;
    } else {
        ring->count++;
    }

    /* Fill the alert slot. */
    slot->alert_id = ring->total_produced++;
    slot->severity = (UINT32)severity;
    slot->source   = (UINT32)source;
    slot->reserved = 0;

    LARGE_INTEGER perf_counter;
    perf_counter = KeQueryPerformanceCounter(NULL);
    slot->timestamp_ticks = (UINT64)perf_counter.QuadPart;
    slot->context_value   = context;

    /* Copy message, ensuring null termination. */
    RtlZeroMemory(slot->message, sizeof(slot->message));
    if (message != NULL) {
        RtlStringCbCopyA((char *)slot->message, sizeof(slot->message), message);
    }

    /* Advance the write head. */
    ring->head = (ring->head + 1) % SENTINEL_RING_BUFFER_SIZE;

    KeReleaseSpinLock(&ring->lock, old_irql);
}

/* -------------------------------------------------------------------------
 * sentinel_alert_drain - Copy pending alerts to a user-mode batch.
 *
 * Called from the IOCTL handler to serve SENTINEL_IOCTL_GET_ALERTS.
 * Copies up to SENTINEL_MAX_ALERTS_PER_PULL alerts from the ring buffer
 * into the output batch structure.
 * ------------------------------------------------------------------------- */
NTSTATUS sentinel_alert_drain(
    SENTINEL_RING_BUFFER *ring,
    SENTINEL_ALERT_BATCH *batch,
    PULONG bytes_returned)
{
    KIRQL old_irql;
    UINT32 copied = 0;

    if (batch == NULL || bytes_returned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&ring->lock, &old_irql);

    /* Copy alerts from tail toward head, up to the batch limit. */
    while (ring->count > 0 && copied < SENTINEL_MAX_ALERTS_PER_PULL) {
        RtlCopyMemory(
            &batch->alerts[copied],
            &ring->entries[ring->tail],
            sizeof(SENTINEL_ALERT));

        ring->tail = (ring->tail + 1) % SENTINEL_RING_BUFFER_SIZE;
        ring->count--;
        copied++;
    }

    batch->alert_count   = copied;
    batch->alerts_dropped = ring->total_dropped;

    KeReleaseSpinLock(&ring->lock, old_irql);

    *bytes_returned = sizeof(SENTINEL_ALERT_BATCH);
    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------
 * sentinel_init_default_config - Apply default configuration values.
 * ------------------------------------------------------------------------- */
static void sentinel_init_default_config(SENTINEL_CONFIG *config)
{
    RtlZeroMemory(config, sizeof(*config));
    config->pcie_scan_interval_ms    = SENTINEL_DEFAULT_PCIE_SCAN_INTERVAL_MS;
    config->memory_check_interval_ms = SENTINEL_DEFAULT_MEMORY_CHECK_INTERVAL_MS;
    config->dma_timing_threshold_ns  = SENTINEL_DEFAULT_DMA_THRESHOLD_NS;
    config->alert_poll_interval_ms   = SENTINEL_DEFAULT_ALERT_POLL_INTERVAL_MS;
    config->flags = SENTINEL_CONFIG_FLAG_DMA_ENABLED
                  | SENTINEL_CONFIG_FLAG_MEMORY_ENABLED
                  | SENTINEL_CONFIG_FLAG_PNP_ENABLED;
}

/* -------------------------------------------------------------------------
 * sentinel_dispatch_create - IRP_MJ_CREATE handler.
 *
 * Called when user-mode calls CreateFile("\\.\Sentinel", ...).
 * We have no per-handle state, so just complete the request successfully.
 *
 * WDM pattern: Every IRP must be completed. We set IoStatus.Status and
 * IoStatus.Information, then call IoCompleteRequest().
 * ------------------------------------------------------------------------- */
NTSTATUS sentinel_dispatch_create(PDEVICE_OBJECT device_object, PIRP irp)
{
    UNREFERENCED_PARAMETER(device_object);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------
 * sentinel_dispatch_close - IRP_MJ_CLOSE handler.
 *
 * Called when the last handle to our device is closed. Nothing to clean up.
 * ------------------------------------------------------------------------- */
NTSTATUS sentinel_dispatch_close(PDEVICE_OBJECT device_object, PIRP irp)
{
    UNREFERENCED_PARAMETER(device_object);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------
 * sentinel_dispatch_device_control - IRP_MJ_DEVICE_CONTROL handler.
 *
 * This is the main entry point for IOCTL communication. The I/O Manager
 * calls this when user-mode invokes DeviceIoControl().
 *
 * WDM pattern for METHOD_BUFFERED IOCTLs:
 *   - Input buffer:  irp->AssociatedIrp.SystemBuffer (copied from user)
 *   - Output buffer: irp->AssociatedIrp.SystemBuffer (same pointer)
 *   - Input size:    stack->Parameters.DeviceIoControl.InputBufferLength
 *   - Output size:   stack->Parameters.DeviceIoControl.OutputBufferLength
 *
 * The I/O Manager handles the user<->kernel buffer copy for us.
 * ------------------------------------------------------------------------- */
NTSTATUS sentinel_dispatch_device_control(PDEVICE_OBJECT device_object, PIRP irp)
{
    NTSTATUS status;
    PIO_STACK_LOCATION stack;
    PSENTINEL_DEVICE_EXTENSION ext;
    ULONG ioctl_code;
    PVOID buffer;
    ULONG input_length;
    ULONG output_length;
    ULONG bytes_returned = 0;

    ext   = (PSENTINEL_DEVICE_EXTENSION)device_object->DeviceExtension;
    stack = IoGetCurrentIrpStackLocation(irp);

    ioctl_code    = stack->Parameters.DeviceIoControl.IoControlCode;
    buffer        = irp->AssociatedIrp.SystemBuffer;
    input_length  = stack->Parameters.DeviceIoControl.InputBufferLength;
    output_length = stack->Parameters.DeviceIoControl.OutputBufferLength;

    /* Delegate to the IOCTL handler module. */
    status = sentinel_handle_ioctl(
        ext, ioctl_code,
        buffer, input_length,
        buffer, output_length,
        &bytes_returned);

    irp->IoStatus.Status      = status;
    irp->IoStatus.Information = bytes_returned;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

/* -------------------------------------------------------------------------
 * sentinel_driver_unload - Driver teardown.
 *
 * Called when the driver is stopped (sc stop sentinel, or system shutdown).
 * Must release all resources in reverse order of creation.
 *
 * WDM pattern: DriverUnload is optional but required for development drivers
 * that need to be loaded/unloaded without rebooting.
 * ------------------------------------------------------------------------- */
void sentinel_driver_unload(PDRIVER_OBJECT driver_object)
{
    PDEVICE_OBJECT device_object;
    PSENTINEL_DEVICE_EXTENSION ext;
    UNICODE_STRING symlink_name;

    DbgPrint("[Sentinel] Driver unloading...\n");

    device_object = driver_object->DeviceObject;
    if (device_object == NULL) {
        return;
    }

    ext = (PSENTINEL_DEVICE_EXTENSION)device_object->DeviceExtension;

    /* Tear down subsystems in reverse initialization order. */
    if (ext->subsystems_initialized) {
        sentinel_devmon_cleanup(ext);
        sentinel_memory_cleanup(ext);
        sentinel_dma_cleanup(ext);
        sentinel_pcie_cleanup(ext);
        ext->subsystems_initialized = FALSE;
    }

    /* Delete the symbolic link so user-mode can no longer open \\.\Sentinel. */
    RtlInitUnicodeString(&symlink_name, SENTINEL_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink_name);

    /* Delete the device object and free its DeviceExtension memory. */
    IoDeleteDevice(device_object);

    DbgPrint("[Sentinel] Driver unloaded successfully.\n");
}

/* -------------------------------------------------------------------------
 * DriverEntry - Driver initialization (called by Windows at load time).
 *
 * This is the kernel equivalent of main(). We:
 *   1. Create a device object (\Device\Sentinel)
 *   2. Create a symbolic link (\DosDevices\Sentinel) so user-mode can find us
 *   3. Set up IRP dispatch routines
 *   4. Initialize all detection subsystems
 *
 * If any step fails, we clean up everything already created and return
 * an error NTSTATUS, which tells Windows the driver failed to load.
 *
 * WDM pattern: DriverEntry receives the DRIVER_OBJECT (our identity in
 * the kernel) and a RegistryPath (our service key in the registry).
 * ------------------------------------------------------------------------- */
NTSTATUS DriverEntry(
    PDRIVER_OBJECT  driver_object,
    PUNICODE_STRING registry_path)
{
    NTSTATUS status;
    PDEVICE_OBJECT device_object = NULL;
    PSENTINEL_DEVICE_EXTENSION ext;
    UNICODE_STRING device_name;
    UNICODE_STRING symlink_name;
    BOOLEAN symlink_created = FALSE;

    UNREFERENCED_PARAMETER(registry_path);

    DbgPrint("[Sentinel] Driver loading (build: " __DATE__ " " __TIME__ ")\n");

    /* --- Step 1: Create the device object --- */

    /*
     * IoCreateDevice allocates a DEVICE_OBJECT plus our DeviceExtension
     * in one contiguous block of nonpaged pool. The extension size tells
     * the I/O Manager how much extra space to allocate.
     *
     * FILE_DEVICE_UNKNOWN is the standard type for custom devices.
     * FILE_DEVICE_SECURE_OPEN enforces security checks on opens.
     */
    RtlInitUnicodeString(&device_name, SENTINEL_DEVICE_NAME);

    status = IoCreateDevice(
        driver_object,
        sizeof(SENTINEL_DEVICE_EXTENSION),
        &device_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,                     /* Not exclusive -- multiple handles allowed */
        &device_object);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[Sentinel] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    /* --- Step 2: Initialize the device extension --- */

    ext = (PSENTINEL_DEVICE_EXTENSION)device_object->DeviceExtension;
    RtlZeroMemory(ext, sizeof(SENTINEL_DEVICE_EXTENSION));
    ext->self = device_object;
    ext->subsystems_initialized = FALSE;

    /* Initialize alert ring buffer. */
    sentinel_alert_init(&ext->alert_ring);

    /* Apply default configuration. */
    sentinel_init_default_config(&ext->config);

    /* --- Step 3: Create symbolic link --- */

    /*
     * A symbolic link in the \DosDevices namespace lets user-mode code
     * open the device with CreateFile("\\.\Sentinel", ...).
     * Without this, only kernel-mode code could access our device.
     */
    RtlInitUnicodeString(&symlink_name, SENTINEL_SYMLINK_NAME);

    status = IoCreateSymbolicLink(&symlink_name, &device_name);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Sentinel] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(device_object);
        return status;
    }
    symlink_created = TRUE;

    /* --- Step 4: Set up IRP dispatch table --- */

    /*
     * The dispatch table tells the I/O Manager which function to call
     * for each type of IRP (I/O Request Packet). We handle:
     *   - IRP_MJ_CREATE:         User-mode opens a handle
     *   - IRP_MJ_CLOSE:          User-mode closes a handle
     *   - IRP_MJ_DEVICE_CONTROL: User-mode sends an IOCTL
     */
    driver_object->MajorFunction[IRP_MJ_CREATE]         = sentinel_dispatch_create;
    driver_object->MajorFunction[IRP_MJ_CLOSE]          = sentinel_dispatch_close;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = sentinel_dispatch_device_control;
    driver_object->DriverUnload = sentinel_driver_unload;

    /* --- Step 5: Initialize detection subsystems --- */

    status = sentinel_pcie_init(ext);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Sentinel] PCIe enumerator init failed: 0x%08X\n", status);
        goto cleanup;
    }

    status = sentinel_dma_init(ext);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Sentinel] DMA detector init failed: 0x%08X\n", status);
        sentinel_pcie_cleanup(ext);
        goto cleanup;
    }

    status = sentinel_memory_init(ext);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Sentinel] Memory monitor init failed: 0x%08X\n", status);
        sentinel_dma_cleanup(ext);
        sentinel_pcie_cleanup(ext);
        goto cleanup;
    }

    status = sentinel_devmon_init(ext, driver_object);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Sentinel] Device monitor init failed: 0x%08X\n", status);
        sentinel_memory_cleanup(ext);
        sentinel_dma_cleanup(ext);
        sentinel_pcie_cleanup(ext);
        goto cleanup;
    }

    ext->subsystems_initialized = TRUE;
    DbgPrint("[Sentinel] Driver loaded successfully. All subsystems initialized.\n");
    return STATUS_SUCCESS;

cleanup:
    if (symlink_created) {
        IoDeleteSymbolicLink(&symlink_name);
    }
    IoDeleteDevice(device_object);
    return status;
}
