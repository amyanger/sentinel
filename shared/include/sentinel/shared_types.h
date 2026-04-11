/*
 * sentinel/shared_types.h
 *
 * Data structures passed between the Sentinel kernel driver and user-mode
 * service via IOCTLs. These are the wire types -- they must be layout-
 * compatible between kernel (C) and user-mode (C++) builds.
 *
 * Rules:
 *   - No pointers (kernel addresses are meaningless in user-mode)
 *   - No variable-length members
 *   - All structs are packed to a known alignment
 *   - Fixed-size arrays only
 */

#ifndef SENTINEL_SHARED_TYPES_H
#define SENTINEL_SHARED_TYPES_H

#ifdef _WIN32
#include <windows.h>
#else
/* Stub types for static analysis on non-Windows platforms. */
#include <stdint.h>
typedef uint8_t  UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef int32_t  INT32;
typedef int      BOOLEAN;
#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif
#endif

/* -------------------------------------------------------------------------
 * PCIe Device Information
 * Returned by SENTINEL_IOCTL_GET_DEVICES
 * ------------------------------------------------------------------------- */

/* Trust classification for a detected PCIe device. */
typedef enum _SENTINEL_DEVICE_TRUST {
    SENTINEL_TRUST_UNKNOWN     = 0, /* Not yet classified */
    SENTINEL_TRUST_WHITELISTED = 1, /* Known-good device */
    SENTINEL_TRUST_SUSPICIOUS  = 2, /* Matches FPGA/DMA card signatures */
    SENTINEL_TRUST_BLOCKED     = 3  /* Actively blocked */
} SENTINEL_DEVICE_TRUST;

/* Single PCIe device descriptor. 64 bytes, naturally aligned. */
typedef struct _SENTINEL_DEVICE_INFO {
    UINT16 vendor_id;           /* PCI vendor ID (e.g., 0x10EE = Xilinx) */
    UINT16 device_id;           /* PCI device ID */
    UINT8  bus;                 /* PCI bus number */
    UINT8  device;              /* PCI device number on the bus */
    UINT8  function;            /* PCI function number */
    UINT8  class_code;          /* PCI class code (e.g., 0x02 = network) */
    UINT8  subclass;            /* PCI subclass */
    UINT8  revision;            /* PCI revision ID */
    UINT8  reserved[2];         /* Padding for alignment */
    UINT32 trust_level;         /* SENTINEL_DEVICE_TRUST enum value */
    UINT64 first_seen_ticks;    /* KeQueryPerformanceCounter at first detection */
    UINT64 last_seen_ticks;     /* KeQueryPerformanceCounter at last scan */
    UINT8  description[24];     /* Short description, null-terminated */
} SENTINEL_DEVICE_INFO;

/* Response buffer for SENTINEL_IOCTL_GET_DEVICES. */
#define SENTINEL_MAX_DEVICES 64

typedef struct _SENTINEL_DEVICE_LIST {
    UINT32               device_count;
    UINT32               reserved;
    SENTINEL_DEVICE_INFO devices[SENTINEL_MAX_DEVICES];
} SENTINEL_DEVICE_LIST;

/* -------------------------------------------------------------------------
 * Detection Alerts
 * Returned by SENTINEL_IOCTL_GET_ALERTS
 * ------------------------------------------------------------------------- */

/* Alert severity levels. */
typedef enum _SENTINEL_ALERT_SEVERITY {
    SENTINEL_SEVERITY_INFO     = 0,
    SENTINEL_SEVERITY_LOW      = 1,
    SENTINEL_SEVERITY_MEDIUM   = 2,
    SENTINEL_SEVERITY_HIGH     = 3,
    SENTINEL_SEVERITY_CRITICAL = 4
} SENTINEL_ALERT_SEVERITY;

/* Alert source identifiers -- which subsystem raised the alert. */
typedef enum _SENTINEL_ALERT_SOURCE {
    SENTINEL_SOURCE_PCIE_ENUM      = 0, /* PCIe device enumerator */
    SENTINEL_SOURCE_DMA_DETECT     = 1, /* DMA anomaly detector */
    SENTINEL_SOURCE_MEMORY         = 2, /* Memory integrity monitor */
    SENTINEL_SOURCE_DEVICE_MONITOR = 3  /* PnP device monitor */
} SENTINEL_ALERT_SOURCE;

/* Single detection alert. 128 bytes fixed. */
typedef struct _SENTINEL_ALERT {
    UINT32 alert_id;            /* Monotonically increasing alert counter */
    UINT32 severity;            /* SENTINEL_ALERT_SEVERITY enum value */
    UINT32 source;              /* SENTINEL_ALERT_SOURCE enum value */
    UINT32 reserved;
    UINT64 timestamp_ticks;     /* KeQueryPerformanceCounter when raised */
    UINT64 context_value;       /* Source-specific context (address, device, etc.) */
    UINT8  message[96];         /* Human-readable description, null-terminated */
} SENTINEL_ALERT;

/* Response buffer for SENTINEL_IOCTL_GET_ALERTS. */
#define SENTINEL_MAX_ALERTS_PER_PULL 32

typedef struct _SENTINEL_ALERT_BATCH {
    UINT32         alert_count;     /* Number of alerts in this batch */
    UINT32         alerts_dropped;  /* Alerts lost due to ring buffer overflow */
    SENTINEL_ALERT alerts[SENTINEL_MAX_ALERTS_PER_PULL];
} SENTINEL_ALERT_BATCH;

/* -------------------------------------------------------------------------
 * Driver Configuration
 * Sent via SENTINEL_IOCTL_SET_CONFIG
 * ------------------------------------------------------------------------- */

typedef struct _SENTINEL_CONFIG {
    UINT32 pcie_scan_interval_ms;       /* How often to rescan PCIe bus (ms) */
    UINT32 memory_check_interval_ms;    /* How often to check memory integrity (ms) */
    UINT32 dma_timing_threshold_ns;     /* Latency threshold for DMA anomaly (ns) */
    UINT32 alert_poll_interval_ms;      /* Suggested service poll interval (ms) */
    UINT32 flags;                       /* Bitmask: bit 0 = enable DMA checks, etc. */
    UINT32 reserved[3];                 /* Future use */
} SENTINEL_CONFIG;

/* Config flag bits */
#define SENTINEL_CONFIG_FLAG_DMA_ENABLED     (1U << 0)
#define SENTINEL_CONFIG_FLAG_MEMORY_ENABLED  (1U << 1)
#define SENTINEL_CONFIG_FLAG_PNP_ENABLED     (1U << 2)

/* -------------------------------------------------------------------------
 * Memory Region Protection
 * Sent via SENTINEL_IOCTL_PROTECT_REGION
 * ------------------------------------------------------------------------- */

typedef struct _SENTINEL_PROTECT_REQUEST {
    UINT64 base_address;        /* Virtual address of the region to protect */
    UINT64 size_bytes;          /* Length of the region in bytes */
    UINT32 flags;               /* Bit 0: 1 = protect, 0 = unprotect */
    UINT32 reserved;
} SENTINEL_PROTECT_REQUEST;

#define SENTINEL_PROTECT_FLAG_ADD    (1U << 0)
#define SENTINEL_PROTECT_FLAG_REMOVE 0

#endif /* SENTINEL_SHARED_TYPES_H */
