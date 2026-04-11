/*
 * sentinel/driver_comm.h
 *
 * DriverComm manages the IOCTL connection to the Sentinel kernel driver.
 * It is the sole gateway between user-mode and kernel-mode -- no other
 * module should open handles to the driver device.
 *
 * Key responsibilities:
 *   - Open/close the driver device handle with RAII semantics
 *   - Provide typed wrappers for each of the 4 IOCTL control codes
 *   - Run a background polling loop for driver alerts
 *   - Monitor connection health and attempt reconnection
 *
 * Thread safety: All public methods are safe to call from any thread.
 * The driver handle is protected by a mutex, and the polling loop
 * runs on its own dedicated thread.
 */

#ifndef SENTINEL_DRIVER_COMM_H
#define SENTINEL_DRIVER_COMM_H

#include <sentinel/service.h>

namespace sentinel {

class DriverComm {
public:
    /* Callback type for delivering driver alerts to the DetectionEngine. */
    using AlertCallback = std::function<void(const SENTINEL_ALERT& alert)>;

    DriverComm();
    ~DriverComm();

    /* Non-copyable, non-movable (owns a kernel handle and a thread). */
    DriverComm(const DriverComm&) = delete;
    DriverComm& operator=(const DriverComm&) = delete;

    /* -------------------------------------------------------------------
     * Lifecycle
     * ------------------------------------------------------------------- */

    /**
     * Open a handle to the Sentinel driver device and start the alert
     * polling loop. Returns true if the driver was reachable.
     *
     * @param poll_interval_ms  How often to poll for alerts (milliseconds).
     * @param callback          Function called for each alert received.
     */
    bool start(int poll_interval_ms, AlertCallback callback);

    /**
     * Stop the polling loop and close the driver handle.
     * Safe to call even if start() was never called or failed.
     */
    void stop();

    /** Returns true if the driver handle is currently open and healthy. */
    bool is_connected() const;

    /* -------------------------------------------------------------------
     * IOCTL wrappers -- one per control code from ioctl_codes.h.
     *
     * These are the typed, safe wrappers around raw DeviceIoControl calls.
     * Each returns true on success. On failure, the last error is available
     * via GetLastError() on Windows.
     * ------------------------------------------------------------------- */

    /**
     * Retrieve the list of all detected PCIe devices from the driver.
     *
     * @param out_list  Populated with device info on success.
     * @return true if the IOCTL succeeded.
     */
    bool get_devices(SENTINEL_DEVICE_LIST& out_list);

    /**
     * Pull pending alerts from the driver's ring buffer.
     *
     * @param out_batch  Populated with alert data on success.
     * @return true if the IOCTL succeeded.
     */
    bool get_alerts(SENTINEL_ALERT_BATCH& out_batch);

    /**
     * Send updated configuration to the driver.
     *
     * @param config  The new configuration to apply.
     * @return true if the IOCTL succeeded.
     */
    bool set_config(const SENTINEL_CONFIG& config);

    /**
     * Request the driver to protect (or unprotect) a memory region.
     *
     * @param request  The protection parameters.
     * @return true if the IOCTL succeeded.
     */
    bool protect_region(const SENTINEL_PROTECT_REQUEST& request);

private:
    /** Open the driver device handle. Called by start(). */
    bool open_device();

    /** Close the driver device handle. Called by stop(). */
    void close_device();

    /**
     * Send a raw IOCTL to the driver.
     * This is the single bottleneck through which all IOCTLs flow.
     *
     * @param ioctl_code     The CTL_CODE value.
     * @param in_buffer      Input data (nullptr if none).
     * @param in_size        Input buffer size in bytes.
     * @param out_buffer     Output data (nullptr if none).
     * @param out_size       Output buffer size in bytes.
     * @param bytes_returned Actual bytes written to output buffer.
     * @return true if DeviceIoControl succeeded.
     */
    bool send_ioctl(DWORD ioctl_code,
                    void* in_buffer, DWORD in_size,
                    void* out_buffer, DWORD out_size,
                    DWORD& bytes_returned);

    /** Background thread entry point: polls for alerts in a loop. */
    void poll_loop();

    /* --- State --- */
    HANDLE                device_handle_;   /* Handle to \\.\Sentinel device */
    mutable std::mutex    handle_mutex_;    /* Protects device_handle_       */
    std::atomic<bool>     running_;         /* Controls the poll loop        */
    std::atomic<bool>     connected_;       /* Is the driver reachable?      */
    std::thread           poll_thread_;     /* Background polling thread     */
    int                   poll_interval_ms_;
    AlertCallback         alert_callback_;

    /* Connection health tracking */
    int                   consecutive_failures_;
    static constexpr int  MAX_FAILURES_BEFORE_RECONNECT = 5;
};

} /* namespace sentinel */

#endif /* SENTINEL_DRIVER_COMM_H */
