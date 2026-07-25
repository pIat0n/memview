#pragma once

#include "../nt/functions.hpp"
#include "../ioctl/ioctl.hpp"

namespace memview {

NTSTATUS ReadPhysicalMemory(PVOID physAddr, PVOID out, SIZE_T size, PSIZE_T copied);

// Refuses unless [physAddr, physAddr+size) is entirely inside a range from
// GetPhysicalRanges - MmMapIoSpaceEx won't check that itself, and a write to
// MMIO/reserved space can bugcheck.
NTSTATUS WritePhysicalMemory(PVOID physAddr, PVOID in, SIZE_T size, PSIZE_T copied);

ULONG GetPhysicalRanges(MEMVIEW_PHYSICAL_RANGE* out, ULONG maxCount);

// *outPa is 0 (not an error) if the page isn't resident.
NTSTATUS VirtualToPhysical(HANDLE pid, PVOID va, PULONGLONG outPa);

} // namespace memview
