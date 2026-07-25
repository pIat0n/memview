#pragma once

#include "../nt/functions.hpp"
#include "../ioctl/ioctl.hpp"

namespace memview {

NTSTATUS ReadProcessMemory(HANDLE pid, PVOID address, PVOID out, SIZE_T size, PSIZE_T copied);

NTSTATUS WriteProcessMemory(HANDLE pid, PVOID address, PVOID in, SIZE_T size, PSIZE_T copied);

NTSTATUS QueryProcess(HANDLE pid, MEMVIEW_PROCESS_INFO& out);

ULONG ListModules(HANDLE pid, MEMVIEW_MODULE_INFO* out, ULONG maxCount);

NTSTATUS QueryRegion(HANDLE pid, PVOID address, MEMVIEW_REGION_INFO& out);

NTSTATUS ProtectMemory(HANDLE pid, PVOID address, SIZE_T size,
    ULONG newProtect, ULONG& oldProtect);

} // namespace memview
