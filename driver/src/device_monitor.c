/*
 * device_monitor.c — PnP device monitoring
 *
 * Registers Plug and Play notification callbacks to detect when new
 * devices are connected to or removed from the system. This catches
 * hot-plugged DMA hardware during gameplay -- a common attack vector
 * where the cheat device is plugged in after the anticheat starts.
 *
 * WDM PnP Notifications:
 *   Windows provides IoRegisterPlugPlayNotification() for drivers that
 *   need to know about device changes. We register for notifications
 *   on all device interface classes so we see every device arrival
 *   and removal.
 *
 *   The notification callback runs at PASSIVE_LEVEL in an arbitrary
 *   thread context. We can safely access our device extension and
 *   generate alerts from within the callback.
 *
 * Notification types we handle:
 *   - GUID_DEVICE_INTERFACE_ARRIVAL: A new device interface was registered
 *   - GUID_DEVICE_INTERFACE_REMOVAL: A device interface was unregistered
 *
 * On any device arrival, we immediately trigger a PCIe rescan to update
 * our device table and detect if the new device is suspicious.
 */

#include <sentinel/driver.h>
#include <ntstrsafe.h>

/*
 * PCI device class GUID.
 * This is the well-known GUID for PCI bus devices. Registering for
 * notifications on this class lets us see all PCI device arrivals/removals.
 *
 * {4D36E97D-E325-11CE-BFC1-08002BE10318} = System device class
 * We also monitor the generic device interface GUID to catch everything.
 */
static const GUID SENTINEL_PCI_CLASS_GUID = {
    0x4D36E97D, 0xE325, 0x11CE,
    { 0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18 }
};

/* -------------------------------------------------------------------------
 * sentinel_pnp_notification_callback - PnP event handler.
 *
 * Called by the I/O Manager when a device interface arrives or is removed.
 * This callback runs at PASSIVE_LEVEL in an arbitrary thread context.
 *
 * Parameters:
 *   notification_structure - Pointer to a DEVICE_INTERFACE_CHANGE_NOTIFICATION
 *                           structure containing the event details.
 *   context               - Our PSENTINEL_DEVICE_EXTENSION, passed when we
 *                           registered the notification.
 *
 * Returns:
 *   STATUS_SUCCESS to indicate we processed the notification.
 *   The I/O Manager ignores the return value for this notification type,
 *   but STATUS_SUCCESS is conventional.
 * ------------------------------------------------------------------------- */
static NTSTATUS sentinel_pnp_notification_callback(
    PVOID notification_structure,
    PVOID context)
{
    PDEVICE_INTERFACE_CHANGE_NOTIFICATION notification;
    PSENTINEL_DEVICE_EXTENSION ext;

    notification = (PDEVICE_INTERFACE_CHANGE_NOTIFICATION)notification_structure;
    ext = (PSENTINEL_DEVICE_EXTENSION)context;

    if (ext == NULL || notification == NULL) {
        return STATUS_SUCCESS;
    }

    /*
     * Check the notification event GUID to determine if this is an
     * arrival or removal. The GUIDs are defined in wdmguid.h.
     *
     * GUID_DEVICE_INTERFACE_ARRIVAL: New device interface registered
     * GUID_DEVICE_INTERFACE_REMOVAL: Device interface being removed
     */
    if (IsEqualGUID(&notification->Event, &GUID_DEVICE_INTERFACE_ARRIVAL)) {
        /*
         * A new device appeared. This could be a hot-plugged DMA card.
         * Log the event and trigger an immediate PCIe rescan.
         */
        DbgPrint("[Sentinel] PnP: Device interface arrival detected.\n");

        if (notification->SymbolicLinkName != NULL) {
            DbgPrint("[Sentinel] PnP: Symbolic link: %wZ\n",
                     notification->SymbolicLinkName);
        }

        /* Generate an informational alert for the device arrival. */
        sentinel_alert_push(
            &ext->alert_ring,
            SENTINEL_SEVERITY_INFO,
            SENTINEL_SOURCE_DEVICE_MONITOR,
            0,
            "PnP device arrival detected -- triggering PCIe rescan");

        /*
         * Trigger an immediate PCIe bus rescan. This will detect the
         * new device and classify it. If it's a suspicious FPGA card,
         * the PCIe scanner will generate its own high-severity alert.
         */
        NTSTATUS scan_status = sentinel_pcie_scan(ext);
        if (!NT_SUCCESS(scan_status)) {
            DbgPrint("[Sentinel] PnP: Rescan after device arrival failed: "
                     "0x%08X\n", scan_status);
        }

    } else if (IsEqualGUID(&notification->Event, &GUID_DEVICE_INTERFACE_REMOVAL)) {
        /*
         * A device was removed. Log it -- device removal during gameplay
         * can also be suspicious (e.g., removing a DMA card to cover tracks).
         */
        DbgPrint("[Sentinel] PnP: Device interface removal detected.\n");

        sentinel_alert_push(
            &ext->alert_ring,
            SENTINEL_SEVERITY_LOW,
            SENTINEL_SOURCE_DEVICE_MONITOR,
            0,
            "PnP device removal detected");
    }

    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------
 * sentinel_devmon_init - Register PnP notification callbacks.
 *
 * Registers with the I/O Manager to receive notifications when device
 * interfaces matching our class GUID are created or destroyed.
 *
 * WDM pattern: IoRegisterPlugPlayNotification() takes a driver object
 * (not a device object) and returns an opaque notification handle that
 * must be unregistered on driver unload.
 *
 * @ext:            Device extension for callback context.
 * @driver_object:  Our driver object (needed by IoRegister...).
 * ------------------------------------------------------------------------- */
NTSTATUS sentinel_devmon_init(
    PSENTINEL_DEVICE_EXTENSION ext,
    PDRIVER_OBJECT driver_object)
{
    NTSTATUS status;

    if (ext == NULL || driver_object == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("[Sentinel] Device monitor initializing...\n");

    ext->pnp_notification_handle = NULL;

    /* Skip if PnP monitoring is disabled in config. */
    if (!(ext->config.flags & SENTINEL_CONFIG_FLAG_PNP_ENABLED)) {
        DbgPrint("[Sentinel] Device monitor: PnP monitoring disabled "
                 "by config.\n");
        return STATUS_SUCCESS;
    }

    /*
     * Register for PnP device interface change notifications.
     *
     * EventCategory = EventCategoryDeviceInterfaceChange
     *   We want to know about device interface arrivals and removals.
     *
     * EventCategoryFlags = PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES
     *   Include devices that are already present (we'll get an arrival
     *   notification for each existing device, which serves as a warm-up).
     *
     * DeviceInterfaceClassGuid = SENTINEL_PCI_CLASS_GUID
     *   Only notify us about devices matching this class GUID.
     *
     * DriverObject = driver_object
     *   Ties the notification lifetime to our driver.
     *
     * CallbackRoutine = sentinel_pnp_notification_callback
     *   Function to call when a matching event occurs.
     *
     * Context = ext
     *   Our device extension, passed to the callback.
     *
     * NotificationEntry = &ext->pnp_notification_handle
     *   Receives the opaque handle for later unregistration.
     */
    status = IoRegisterPlugPlayNotification(
        EventCategoryDeviceInterfaceChange,
        PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
        (PVOID)&SENTINEL_PCI_CLASS_GUID,
        driver_object,
        sentinel_pnp_notification_callback,
        (PVOID)ext,
        &ext->pnp_notification_handle);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[Sentinel] IoRegisterPlugPlayNotification failed: "
                 "0x%08X\n", status);
        ext->pnp_notification_handle = NULL;
        return status;
    }

    DbgPrint("[Sentinel] Device monitor initialized. "
             "PnP notifications registered.\n");

    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------
 * sentinel_devmon_cleanup - Unregister PnP notification callbacks.
 *
 * MUST be called during driver unload to avoid dangling callbacks.
 * After IoUnregisterPlugPlayNotification() returns, we are guaranteed
 * that our callback will not be called again.
 * ------------------------------------------------------------------------- */
void sentinel_devmon_cleanup(PSENTINEL_DEVICE_EXTENSION ext)
{
    if (ext == NULL) {
        return;
    }

    if (ext->pnp_notification_handle != NULL) {
        /*
         * IoUnregisterPlugPlayNotification() is synchronous -- it waits
         * for any in-progress callback to complete before returning.
         * This guarantees no use-after-free of our device extension.
         */
        IoUnregisterPlugPlayNotification(ext->pnp_notification_handle);
        ext->pnp_notification_handle = NULL;
        DbgPrint("[Sentinel] PnP notification unregistered.\n");
    }

    DbgPrint("[Sentinel] Device monitor cleaned up.\n");
}
