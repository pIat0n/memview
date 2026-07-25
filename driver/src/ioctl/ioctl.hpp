#pragma once

// Device is \Device\MemView, reachable from user mode as \\.\MemView via this symlink.
#define MEMVIEW_DEVICE_NAME   L"\\Device\\MemView"
#define MEMVIEW_SYMLINK_NAME  L"\\DosDevices\\MemView"
#define MEMVIEW_WIN32_NAME    L"\\\\.\\MemView"

// Service name the user-mode installer registers with the SCM.
#define MEMVIEW_SERVICE_NAME  L"MemViewDrv"

// METHOD_BUFFERED: read and write share one system buffer, no user-pointer probing needed.
#define MEMVIEW_IOCTL_READ \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MEMVIEW_IOCTL_WRITE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MEMVIEW_IOCTL_QUERY_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MEMVIEW_IOCTL_LIST_MODULES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MEMVIEW_IOCTL_QUERY_REGION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MEMVIEW_IOCTL_PROTECT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Generous fixed upper bound so the client can allocate one output buffer up front.
#define MEMVIEW_MAX_MODULES 256

// READ:  in = MEMVIEW_REQUEST, out = `size` bytes read from the target.
// WRITE: in = MEMVIEW_REQUEST followed by `size` payload bytes, no output.
// 64-bit fields throughout so a 32-bit client and 64-bit driver agree on the layout.
#pragma pack(push, 1)
typedef struct _MEMVIEW_REQUEST {
    unsigned long long pid;
    unsigned long long address;
    unsigned long long size;
} MEMVIEW_REQUEST;

// QUERY_PROCESS and LIST_MODULES only need the pid.
typedef struct _MEMVIEW_PID_REQUEST {
    unsigned long long pid;
} MEMVIEW_PID_REQUEST;

// QUERY_PROCESS out: bitness only.
typedef struct _MEMVIEW_PROCESS_INFO {
    unsigned char isWow64;
} MEMVIEW_PROCESS_INFO;

// LIST_MODULES out: an array of these, up to MEMVIEW_MAX_MODULES.
typedef struct _MEMVIEW_MODULE_INFO {
    unsigned long long base;
    unsigned long long size;
    wchar_t            path[260]; // full path on disk
} MEMVIEW_MODULE_INFO;

// QUERY_REGION: same one-region-at-a-time semantics as VirtualQueryEx.
typedef struct _MEMVIEW_QUERY_REGION_REQUEST {
    unsigned long long pid;
    unsigned long long address;
} MEMVIEW_QUERY_REGION_REQUEST;

typedef struct _MEMVIEW_REGION_INFO {
    unsigned long long base;
    unsigned long long size;
    unsigned long       protect; // PAGE_* flags
    unsigned long       type;    // MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE
    unsigned long       state;   // MEM_COMMIT / MEM_FREE / MEM_RESERVE
} MEMVIEW_REGION_INFO;

// PROTECT: same in/out shape as VirtualProtectEx.
typedef struct _MEMVIEW_PROTECT_REQUEST {
    unsigned long long pid;
    unsigned long long address;
    unsigned long long size;
    unsigned long       newProtect;
} MEMVIEW_PROTECT_REQUEST;

typedef struct _MEMVIEW_PROTECT_RESPONSE {
    unsigned long oldProtect;
} MEMVIEW_PROTECT_RESPONSE;
#pragma pack(pop)
