/*
 * sentinel/ioctl_codes.h
 *
 * IOCTL control codes shared between the Sentinel kernel driver and
 * user-mode service. This header is the communication contract --
 * changes here must be synchronized across both components.
 */

#ifndef SENTINEL_IOCTL_CODES_H
#define SENTINEL_IOCTL_CODES_H

#ifdef _WIN32
#include <winioctl.h>
#else
/*
 * Stub definitions for non-Windows builds (e.g., static analysis on macOS).
 * The actual driver and service always build on Windows with the real macros.
 */
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#define FILE_DEVICE_UNKNOWN     0x00000022
#define METHOD_BUFFERED         0
#define FILE_ANY_ACCESS         0
#define FILE_READ_ACCESS        0x0001
#define FILE_WRITE_ACCESS       0x0002
#endif

/*
 * Custom function codes start at 0x800 per Microsoft convention.
 * Range 0x000-0x7FF is reserved for Microsoft-defined codes.
 */
#define SENTINEL_IOCTL_FUNCTION_BASE    0x800

/* List all detected PCIe devices with trust status (Driver -> Service) */
#define SENTINEL_IOCTL_GET_DEVICES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, \
             SENTINEL_IOCTL_FUNCTION_BASE + 0, \
             METHOD_BUFFERED, \
             FILE_READ_ACCESS)

/* Pull pending detection alerts from the alert queue (Driver -> Service) */
#define SENTINEL_IOCTL_GET_ALERTS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, \
             SENTINEL_IOCTL_FUNCTION_BASE + 1, \
             METHOD_BUFFERED, \
             FILE_READ_ACCESS)

/* Update detection parameters -- scan intervals, thresholds (Service -> Driver) */
#define SENTINEL_IOCTL_SET_CONFIG \
    CTL_CODE(FILE_DEVICE_UNKNOWN, \
             SENTINEL_IOCTL_FUNCTION_BASE + 2, \
             METHOD_BUFFERED, \
             FILE_WRITE_ACCESS)

/* Mark a memory region for integrity monitoring (Service -> Driver) */
#define SENTINEL_IOCTL_PROTECT_REGION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, \
             SENTINEL_IOCTL_FUNCTION_BASE + 3, \
             METHOD_BUFFERED, \
             FILE_WRITE_ACCESS)

#endif /* SENTINEL_IOCTL_CODES_H */
