/*
 * sentinel/types.h — Driver-internal types
 *
 * Structures used only within the kernel driver for managing state.
 * These never cross the IOCTL boundary -- the shared_types.h structs
 * are used for that. These types manage the ring buffer, device tracking
 * lists, and protected memory region lists that live in kernel memory.
 */

#ifndef SENTINEL_DRIVER_TYPES_H
#define SENTINEL_DRIVER_TYPES_H

#include <ntddk.h>
#include <sentinel/shared_types.h>

/* -------------------------------------------------------------------------
 * Alert Ring Buffer
 *
 * Lock-free single-producer design: the driver writes alerts into the
 * ring buffer from any subsystem (always under a spinlock), and the
 * IOCTL handler reads them out when the service polls.
 *
 * When the buffer is full, new alerts overwrite the oldest (head advances).
 * The driver tracks how many alerts were dropped so the service knows.
 * ------------------------------------------------------------------------- */

#define SENTINEL_RING_BUFFER_SIZE 256  /* Must be a power of 2 */

typedef struct _SENTINEL_RING_BUFFER {
    SENTINEL_ALERT entries[SENTINEL_RING_BUFFER_SIZE];
    volatile LONG  head;            /* Next slot to write (producer) */
    volatile LONG  tail;            /* Next slot to read  (consumer) */
    volatile LONG  count;           /* Current number of pending alerts */
    UINT32         total_produced;  /* Lifetime alert counter */
    UINT32         total_dropped;   /* Alerts lost due to full buffer */
    KSPIN_LOCK     lock;            /* Protects concurrent writes */
} SENTINEL_RING_BUFFER;

/* -------------------------------------------------------------------------
 * Internal PCIe Device Tracking
 *
 * The driver maintains its own list of detected PCIe devices with richer
 * metadata than what is exposed through the IOCTL interface. This includes
 * the raw PCI config space data and internal classification state.
 * ------------------------------------------------------------------------- */

#define SENTINEL_MAX_TRACKED_DEVICES 128

typedef struct _SENTINEL_TRACKED_DEVICE {
    SENTINEL_DEVICE_INFO info;      /* Public device info (shared with user-mode) */
    UINT32 config_space[64];        /* Raw 256-byte PCI config space as DWORDs */
    BOOLEAN is_present;             /* TRUE if seen on the last scan */
    BOOLEAN was_present;            /* TRUE if seen on the previous scan */
    UINT8   scan_miss_count;        /* Number of consecutive scans where device was absent */
    UINT8   reserved;
} SENTINEL_TRACKED_DEVICE;

typedef struct _SENTINEL_DEVICE_TABLE {
    SENTINEL_TRACKED_DEVICE devices[SENTINEL_MAX_TRACKED_DEVICES];
    UINT32    device_count;         /* Number of valid entries */
    KSPIN_LOCK lock;                /* Protects concurrent access to the table */
} SENTINEL_DEVICE_TABLE;

/* -------------------------------------------------------------------------
 * Protected Memory Region List
 *
 * Regions registered by the service for integrity monitoring. Each region
 * stores a hash of its initial contents so the driver can detect tampering.
 * ------------------------------------------------------------------------- */

#define SENTINEL_MAX_PROTECTED_REGIONS 64
#define SENTINEL_HASH_SIZE             32  /* SHA-256 digest length */

typedef struct _SENTINEL_PROTECTED_REGION {
    UINT64  base_address;           /* Virtual address of the protected region */
    UINT64  size_bytes;             /* Size of the region */
    UINT8   baseline_hash[SENTINEL_HASH_SIZE]; /* Hash at registration time */
    BOOLEAN is_active;              /* TRUE if this slot is in use */
    UINT8   reserved[3];
    UINT32  violation_count;        /* Number of integrity violations detected */
} SENTINEL_PROTECTED_REGION;

typedef struct _SENTINEL_REGION_TABLE {
    SENTINEL_PROTECTED_REGION regions[SENTINEL_MAX_PROTECTED_REGIONS];
    UINT32     region_count;        /* Number of active regions */
    KSPIN_LOCK lock;                /* Protects concurrent access */
} SENTINEL_REGION_TABLE;

#endif /* SENTINEL_DRIVER_TYPES_H */
