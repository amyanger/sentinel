/*
 * driver_comm.cpp -- DriverComm implementation.
 *
 * This module manages the IOCTL connection to the Sentinel kernel driver.
 * It is the only code in the service that talks directly to ring 0.
 *
 * Key design decisions:
 *   - RAII handle management via open_device/close_device
 *   - All IOCTLs go through a single send_ioctl bottleneck for consistency
 *   - No exceptions (per CLAUDE.md: "No exceptions in the driver comm layer")
 *   - Background polling thread for driver alerts
 *   - Auto-reconnection after consecutive failures
 */

#include <sentinel/driver_comm.h>

namespace sentinel {

DriverComm::DriverComm()
    : device_handle_(INVALID_HANDLE_VALUE)
    , running_(false)
    , connected_(false)
    , poll_interval_ms_(DEFAULT_POLL_INTERVAL_MS)
    , consecutive_failures_(0) {
}

DriverComm::~DriverComm() {
    stop();
}

/* -------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------- */

bool DriverComm::start(int poll_interval_ms, AlertCallback callback) {
    poll_interval_ms_ = poll_interval_ms;
    alert_callback_ = std::move(callback);

    if (!open_device()) {
        return false;
    }

    /*
     * Start the background polling thread. This thread continuously
     * pulls alerts from the driver's ring buffer and delivers them
     * through the callback.
     */
    running_ = true;
    poll_thread_ = std::thread(&DriverComm::poll_loop, this);

    return true;
}

void DriverComm::stop() {
    running_ = false;

    /* Wait for the polling thread to finish. */
    if (poll_thread_.joinable()) {
        poll_thread_.join();
    }

    close_device();
}

bool DriverComm::is_connected() const {
    return connected_;
}

/* -------------------------------------------------------------------
 * IOCTL wrappers
 *
 * Each wrapper prepares the appropriate input/output buffers and
 * calls send_ioctl. The pattern is always:
 *   1. Zero-initialize the output buffer
 *   2. Call send_ioctl with the correct IOCTL code
 *   3. Return success/failure
 * ------------------------------------------------------------------- */

bool DriverComm::get_devices(SENTINEL_DEVICE_LIST& out_list) {
    std::memset(&out_list, 0, sizeof(out_list));
    DWORD bytes_returned = 0;

    return send_ioctl(
        SENTINEL_IOCTL_GET_DEVICES,
        nullptr, 0,                              /* No input buffer */
        &out_list, sizeof(out_list),
        bytes_returned);
}

bool DriverComm::get_alerts(SENTINEL_ALERT_BATCH& out_batch) {
    std::memset(&out_batch, 0, sizeof(out_batch));
    DWORD bytes_returned = 0;

    return send_ioctl(
        SENTINEL_IOCTL_GET_ALERTS,
        nullptr, 0,                              /* No input buffer */
        &out_batch, sizeof(out_batch),
        bytes_returned);
}

bool DriverComm::set_config(const SENTINEL_CONFIG& config) {
    DWORD bytes_returned = 0;

    /*
     * const_cast is safe here -- DeviceIoControl declares the input
     * buffer as LPVOID (not const), but SET_CONFIG only reads from it.
     */
    return send_ioctl(
        SENTINEL_IOCTL_SET_CONFIG,
        const_cast<SENTINEL_CONFIG*>(&config), sizeof(config),
        nullptr, 0,                              /* No output buffer */
        bytes_returned);
}

bool DriverComm::protect_region(const SENTINEL_PROTECT_REQUEST& request) {
    DWORD bytes_returned = 0;

    return send_ioctl(
        SENTINEL_IOCTL_PROTECT_REGION,
        const_cast<SENTINEL_PROTECT_REQUEST*>(&request), sizeof(request),
        nullptr, 0,
        bytes_returned);
}

/* -------------------------------------------------------------------
 * Device handle management (RAII)
 *
 * open_device/close_device are the only places where CreateFile and
 * CloseHandle are called. This ensures the handle is always properly
 * cleaned up, even on error paths.
 * ------------------------------------------------------------------- */

bool DriverComm::open_device() {
    std::lock_guard<std::mutex> lock(handle_mutex_);

    if (device_handle_ != INVALID_HANDLE_VALUE) {
        /* Already open. */
        connected_ = true;
        return true;
    }

#ifdef _WIN32
    /*
     * Open a handle to the Sentinel driver device.
     *
     * The driver creates a device named \\Device\\Sentinel with a
     * symbolic link \\DosDevices\\Sentinel, which user-mode sees as
     * \\.\Sentinel.
     *
     * GENERIC_READ | GENERIC_WRITE gives us both directions for IOCTLs.
     * FILE_ATTRIBUTE_NORMAL is standard for device handles.
     */
    device_handle_ = CreateFileA(
        DRIVER_DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0,                                /* No sharing */
        nullptr,                          /* Default security */
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr                           /* No template */
    );

    if (device_handle_ == INVALID_HANDLE_VALUE) {
        connected_ = false;
        return false;
    }
#else
    /* Non-Windows stub for development. */
    connected_ = false;
    return false;
#endif

    connected_ = true;
    consecutive_failures_ = 0;
    return true;
}

void DriverComm::close_device() {
    std::lock_guard<std::mutex> lock(handle_mutex_);

#ifdef _WIN32
    if (device_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(device_handle_);
        device_handle_ = INVALID_HANDLE_VALUE;
    }
#endif

    connected_ = false;
}

/* -------------------------------------------------------------------
 * send_ioctl -- The single bottleneck for all driver communication.
 *
 * Every IOCTL goes through here, which gives us one place to:
 *   - Hold the handle lock
 *   - Track failure counts for reconnection
 *   - Log errors consistently
 * ------------------------------------------------------------------- */

bool DriverComm::send_ioctl(DWORD ioctl_code,
                             void* in_buffer, DWORD in_size,
                             void* out_buffer, DWORD out_size,
                             DWORD& bytes_returned) {
    std::lock_guard<std::mutex> lock(handle_mutex_);

    if (device_handle_ == INVALID_HANDLE_VALUE) {
        return false;
    }

#ifdef _WIN32
    BOOL success = DeviceIoControl(
        device_handle_,
        ioctl_code,
        in_buffer, in_size,
        out_buffer, out_size,
        &bytes_returned,
        nullptr                           /* No overlapped I/O */
    );

    if (!success) {
        ++consecutive_failures_;

        /*
         * After too many consecutive failures, the driver may have
         * crashed or been unloaded. Close the handle so the next
         * attempt triggers a reconnection.
         */
        if (consecutive_failures_ >= MAX_FAILURES_BEFORE_RECONNECT) {
            CloseHandle(device_handle_);
            device_handle_ = INVALID_HANDLE_VALUE;
            connected_ = false;
        }

        return false;
    }

    /* Success -- reset the failure counter. */
    consecutive_failures_ = 0;
    return true;
#else
    (void)ioctl_code;
    (void)in_buffer;
    (void)in_size;
    (void)out_buffer;
    (void)out_size;
    (void)bytes_returned;
    return false;
#endif
}

/* -------------------------------------------------------------------
 * poll_loop -- Background thread that continuously pulls alerts.
 *
 * This loop runs for the lifetime of the DriverComm object (from
 * start() to stop()). It:
 *   1. Calls get_alerts() to pull from the driver's ring buffer
 *   2. Delivers each alert through the callback
 *   3. Sleeps for the configured interval
 *   4. Attempts reconnection if the connection was lost
 * ------------------------------------------------------------------- */

void DriverComm::poll_loop() {
    while (running_) {
        if (!connected_) {
            /*
             * Try to reconnect. If the driver was reloaded or we
             * recovered from a transient failure, this will succeed.
             */
            if (!open_device()) {
                /* Still can't connect -- wait and try again. */
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(poll_interval_ms_ * 2));
                continue;
            }
        }

        /* Pull alerts from the driver. */
        SENTINEL_ALERT_BATCH batch;
        if (get_alerts(batch)) {
            /*
             * Deliver each alert through the callback. The callback
             * is typically DetectionEngine::submit_driver_alert, which
             * handles thread safety on its end.
             */
            for (UINT32 i = 0; i < batch.alert_count; ++i) {
                if (alert_callback_) {
                    alert_callback_(batch.alerts[i]);
                }
            }

            /*
             * Log if alerts were dropped due to ring buffer overflow.
             * This means the service isn't polling fast enough.
             */
            if (batch.alerts_dropped > 0) {
                std::fprintf(stderr,
                    "[DriverComm] WARNING: %u alerts dropped by driver\n",
                    batch.alerts_dropped);
            }
        }

        /* Sleep between polls. Use short intervals for responsive shutdown. */
        auto sleep_end = std::chrono::steady_clock::now() +
                         std::chrono::milliseconds(poll_interval_ms_);
        while (running_ && std::chrono::steady_clock::now() < sleep_end) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
}

} /* namespace sentinel */
