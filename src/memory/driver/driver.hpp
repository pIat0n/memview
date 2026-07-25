#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace mem { struct ModuleEntry; struct Region; }

namespace mem::driver {

bool start(std::string& status);

void stop(bool removeService = false);

bool active();

size_t read(uint32_t pid, uintptr_t addr, void* buf, size_t n);
size_t write(uint32_t pid, uintptr_t addr, const void* buf, size_t n);
bool isWow64(uint32_t pid);
std::vector<mem::ModuleEntry> listModules(uint32_t pid);
bool queryRegion(uint32_t pid, uintptr_t addr, mem::Region& out);
bool protect(uint32_t pid, uintptr_t addr, size_t n, unsigned long newProtect, unsigned long& oldProtect);

namespace phys {

struct Range {
    uint64_t base;
    uint64_t size;
};

size_t read(uint64_t addr, void* buf, size_t n);

// False if the range isn't entirely inside installed RAM.
bool write(uint64_t addr, const void* buf, size_t n);

// The installed-RAM map, skipping MMIO/reserved holes.
std::vector<Range> ranges();

// 0 if the page isn't resident (not committed, or paged out).
uint64_t translate(uint32_t pid, uint64_t va);

} // namespace phys

} // namespace mem::driver
