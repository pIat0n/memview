#pragma once
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#include <optional>
#include <span>
#include <atomic>
#include <algorithm>
#include <cmath>
#include <cctype>

#include "memory/driver/driver.hpp"

namespace mem {

// ============================================================================
// Process
// ============================================================================

// WinApi uses a real process handle; Kernel routes everything through the
// driver's IOCTL client instead and never opens a handle to the target.
// Physical isn't a process at all - see open_physical below.
enum class Backend { WinApi, Kernel, Physical };

struct ProcessEntry {
    DWORD       pid;
    std::string name;
    std::string path; // full path to the executable, empty if it couldn't be resolved
};

struct Process {
    DWORD   pid    = 0;
    HANDLE  handle = nullptr;      // null in Backend::Kernel/Physical - no handle is held
    char    name[MAX_PATH] = {};
    Backend backend = Backend::WinApi;

    bool is_open() const
    {
        if (backend == Backend::Physical) return true;
        return backend == Backend::Kernel ? pid != 0 : (handle && handle != INVALID_HANDLE_VALUE);
    }
};

// A loaded module (exe or dll) in the target process's address space.
struct ModuleEntry {
    uintptr_t   base;
    size_t      size;
    std::string name; // short file name, e.g. "ntdll.dll"
    std::string path; // full path on disk, for the .pdb sitting next to it
};

struct Region {
    uintptr_t base;
    size_t    size;
    DWORD     protect; // PAGE_READWRITE etc.
    DWORD     type;    // MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE
    DWORD     state;   // MEM_COMMIT / MEM_FREE / MEM_RESERVE
};

namespace detail {

// Undocumented but stable (same technique Process Hacker etc. use) - only
// NtQuerySystemInformation itself is declared in <winternl.h>, not this class.
constexpr SYSTEM_INFORMATION_CLASS kSystemProcessIdInformation =
    static_cast<SYSTEM_INFORMATION_CLASS>(88);

struct SystemProcessIdInformation {
    HANDLE         ProcessId;  // set before the call
    UNICODE_STRING ImageName;  // caller supplies Buffer/MaximumLength; fills Length
};

// Maps an NT device path (\Device\HarddiskVolume3\...) back to a drive letter.
// Rebuilt each call (26 cheap QueryDosDeviceW lookups) since letters can change.
inline std::wstring nt_path_to_dos_path(const std::wstring& ntPath)
{
    for (wchar_t drive = L'A'; drive <= L'Z'; ++drive)
    {
        const wchar_t driveStr[3] = { drive, L':', 0 };
        wchar_t       target[MAX_PATH];
        if (QueryDosDeviceW(driveStr, target, MAX_PATH) == 0)
            continue;

        const size_t len = wcslen(target);
        if (ntPath.size() > len && _wcsnicmp(ntPath.c_str(), target, len) == 0 && ntPath[len] == L'\\')
            return std::wstring(driveStr, 2) + ntPath.substr(len);
    }
    return {};
}

inline bool process_exists(DWORD pid)
{
    SystemProcessIdInformation info{};
    info.ProcessId = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
    return NtQuerySystemInformation(kSystemProcessIdInformation, &info, sizeof(info), nullptr)
        != static_cast<NTSTATUS>(0xC000000B); // STATUS_INVALID_CID
}

} // namespace detail

inline std::vector<ProcessEntry> list_processes()
{
    std::vector<ProcessEntry> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe))
    {
        do {
            ProcessEntry e;
            e.pid = pe.th32ProcessID;
            char buf[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, buf, MAX_PATH, nullptr, nullptr);
            e.name = buf;

            // Full path for the icon lookup, without opening a handle to the process -
            // matters for ones that deny even PROCESS_QUERY_LIMITED_INFORMATION.
            detail::SystemProcessIdInformation info{};
            info.ProcessId = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(e.pid));
            wchar_t nameBuf[1024];
            info.ImageName.Buffer        = nameBuf;
            info.ImageName.MaximumLength = sizeof(nameBuf);

            if (NtQuerySystemInformation(detail::kSystemProcessIdInformation, &info, sizeof(info), nullptr) >= 0
                && info.ImageName.Length > 0)
            {
                const std::wstring ntPath(info.ImageName.Buffer, info.ImageName.Length / sizeof(wchar_t));
                const std::wstring dosPath = detail::nt_path_to_dos_path(ntPath);
                if (!dosPath.empty())
                {
                    char pbuf[MAX_PATH];
                    WideCharToMultiByte(CP_UTF8, 0, dosPath.c_str(), -1, pbuf, MAX_PATH, nullptr, nullptr);
                    e.path = pbuf;
                }
            }

            out.push_back(std::move(e));
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

// Backend::Kernel: confirm the pid exists instead of opening a handle.
inline bool open(Process& proc, DWORD pid, Backend backend = Backend::WinApi,
    DWORD access = PROCESS_VM_READ | PROCESS_VM_WRITE |
                   PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION)
{
    if (backend == Backend::Kernel)
    {
        if (!detail::process_exists(pid))
            return false;
        proc.handle  = nullptr;
        proc.pid     = pid;
        proc.backend = Backend::Kernel;
    }
    else
    {
        proc.handle = OpenProcess(access, FALSE, pid);
        if (!proc.is_open()) return false;
        proc.pid     = pid;
        proc.backend = Backend::WinApi;
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe))
        {
            do {
                if (pe.th32ProcessID == pid)
                {
                    WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1,
                        proc.name, MAX_PATH, nullptr, nullptr);
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    return true;
}

inline bool open_by_name(Process& proc, const char* exe_name, Backend backend = Backend::WinApi,
    DWORD access = PROCESS_VM_READ | PROCESS_VM_WRITE |
                   PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION)
{
    for (auto& e : list_processes())
        if (_stricmp(e.name.c_str(), exe_name) == 0)
            return open(proc, e.pid, backend, access);
    return false;
}

// No real process backs this - reads/writes go straight through driver::phys
// by physical address. False if the driver isn't loaded (no WinApi fallback).
inline bool open_physical(Process& proc)
{
    if (!driver::active())
        return false;

    proc.handle  = nullptr;
    proc.pid     = 0;
    proc.backend = Backend::Physical;
    snprintf(proc.name, sizeof(proc.name), "Physical Memory");
    return true;
}

// Enable SeDebugPrivilege so an elevated process can OpenProcess targets owned
// by other users/sessions (e.g. SYSTEM services). Returns false if not elevated
// or the privilege can't be granted.
inline bool enable_debug_privilege()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    LUID luid;
    bool ok = false;
    if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid))
    {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount           = 1;
        tp.Privileges[0].Luid       = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr)
            && GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(token);
    return ok;
}

// False once the target has exited (is_open() alone can't tell - the handle/pid
// stays valid until close()).
inline bool is_alive(const Process& proc)
{
    if (proc.backend == Backend::Physical)
        return proc.is_open() && driver::active();
    return proc.is_open() && detail::process_exists(proc.pid);
}

inline void close(Process& proc)
{
    if (proc.handle && proc.handle != INVALID_HANDLE_VALUE)
        CloseHandle(proc.handle);
    proc.handle  = nullptr;
    proc.pid     = 0;
    proc.name[0] = '\0';
    proc.backend = Backend::WinApi;
}

// Loaded modules, main .exe first (Toolhelp order on WinApi; the driver's own
// PEB walk is main-module-first too). Used to label addresses as "module+offset".
inline std::vector<ModuleEntry> list_modules(const Process& proc)
{
    if (proc.backend == Backend::Kernel)
        return driver::listModules(proc.pid);
    if (proc.backend == Backend::Physical)
        return {}; // no modules in raw physical address space

    std::vector<ModuleEntry> out;
    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, proc.pid);
    if (snap == INVALID_HANDLE_VALUE) return out;

    MODULEENTRY32W me = {}; me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me))
    {
        do {
            char buf[MAX_PATH], pathBuf[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, buf, sizeof(buf), nullptr, nullptr);
            WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, pathBuf, sizeof(pathBuf), nullptr, nullptr);
            out.push_back({
                reinterpret_cast<uintptr_t>(me.modBaseAddr),
                (size_t)me.modBaseSize,
                buf,
                pathBuf
            });
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return out;
}

// Base of the process's main module (the .exe), or 0 if unavailable.
inline uintptr_t main_module_base(const Process& proc)
{
    const std::vector<ModuleEntry> mods = list_modules(proc);
    return mods.empty() ? 0 : mods[0].base;
}

// True if the target is WOW64 (32-bit on 64-bit Windows), so disassemble as x86.
inline bool is_wow64(const Process& proc)
{
    if (proc.backend == Backend::Kernel)
        return driver::isWow64(proc.pid);
    if (proc.backend == Backend::Physical)
        return false; // no bitness to inherit - disassemble as x64
    BOOL wow = FALSE;
    return IsWow64Process(proc.handle, &wow) && wow;
}

// Single choke point for reads: the kernel driver when loaded and selected, else
// ReadProcessMemory. Every read path below funnels through here.
inline size_t read_bytes(const Process& proc, uintptr_t addr, void* buf, size_t n)
{
    if (proc.backend == Backend::Physical)
        return driver::phys::read(addr, buf, n);
    if (proc.backend == Backend::Kernel)
        return driver::read(proc.pid, addr, buf, n);

    SIZE_T rd = 0;
    ReadProcessMemory(proc.handle, reinterpret_cast<LPCVOID>(addr), buf, n, &rd);
    return rd;
}

// Write counterpart of read_bytes; protection handling stays in write_raw.
inline size_t write_bytes(const Process& proc, uintptr_t addr, const void* buf, size_t n)
{
    if (proc.backend == Backend::Physical)
        return driver::phys::write(addr, buf, n) ? n : 0;
    if (proc.backend == Backend::Kernel)
        return driver::write(proc.pid, addr, buf, n);

    SIZE_T wr = 0;
    WriteProcessMemory(proc.handle, reinterpret_cast<LPVOID>(addr), buf, n, &wr);
    return wr;
}

// Read as many bytes as possible from `addr`, stopping at the first unreadable
// page. Returns the count of contiguous readable bytes (0 if `addr` is unreadable).
inline size_t read_tolerant(const Process& proc, uintptr_t addr,
    uint8_t* buf, size_t n)
{
    constexpr size_t kPage = 0x1000;
    size_t done = 0;
    while (done < n)
    {
        // Clamp to the next page boundary so one bad page doesn't abort the rest.
        const size_t toBoundary = kPage - ((addr + done) & (kPage - 1));
        const size_t chunk = std::min<size_t>(toBoundary, n - done);
        const size_t rd = read_bytes(proc, addr + done, buf + done, chunk);
        done += rd;
        if (rd != chunk) break; // hit an unreadable page
    }
    return done;
}

// ============================================================================
// Raw read / write
// ============================================================================

inline bool read_raw(const Process& proc, uintptr_t addr, void* buf, size_t n)
{
    return read_bytes(proc, addr, buf, n) == n;
}

inline bool write_raw(const Process& proc, uintptr_t addr, const void* buf, size_t n)
{
    if (write_bytes(proc, addr, buf, n) == n)
        return true;

    // No page protection to lift and retry - the driver already validated the range.
    if (proc.backend == Backend::Physical)
        return false;

    // Lift page protection and retry.
    if (proc.backend == Backend::Kernel)
    {
        DWORD oldProtect = 0;
        if (!driver::protect(proc.pid, addr, n, PAGE_EXECUTE_READWRITE, oldProtect))
            return false;

        const bool ok = write_bytes(proc, addr, buf, n) == n;

        DWORD tmp = 0;
        driver::protect(proc.pid, addr, n, oldProtect, tmp);
        return ok;
    }

    LPVOID target = reinterpret_cast<LPVOID>(addr);
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(proc.handle, target, n, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    const bool ok = write_bytes(proc, addr, buf, n) == n;

    DWORD tmp = 0;
    VirtualProtectEx(proc.handle, target, n, oldProtect, &tmp);
    return ok;
}

// Typed convenience wrappers

template<typename T>
bool read(const Process& proc, uintptr_t addr, T& out)
{
    return read_raw(proc, addr, &out, sizeof(T));
}

template<typename T>
std::optional<T> read(const Process& proc, uintptr_t addr)
{
    T val{};
    if (!read_raw(proc, addr, &val, sizeof(T))) return std::nullopt;
    return val;
}

template<typename T>
bool write(const Process& proc, uintptr_t addr, const T& value)
{
    return write_raw(proc, addr, &value, sizeof(T));
}

// ============================================================================
// Memory regions
// ============================================================================

inline std::vector<Region> query_regions(const Process& proc, bool committed_only = true)
{
    std::vector<Region> out;
    uintptr_t addr = 0;

    if (proc.backend == Backend::Physical)
    {
        // No real page protection here; PAGE_READWRITE/MEM_PRIVATE/MEM_COMMIT
        // are a stand-in so scrollbars/Regions/scanning work unchanged.
        for (const driver::phys::Range& r : driver::phys::ranges())
            out.push_back({ (uintptr_t)r.base, (size_t)r.size,
                             PAGE_READWRITE, MEM_PRIVATE, MEM_COMMIT });
        return out;
    }

    if (proc.backend == Backend::Kernel)
    {
        Region r{};
        while (driver::queryRegion(proc.pid, addr, r))
        {
            if (!committed_only || r.state == MEM_COMMIT)
                out.push_back(r);
            const uintptr_t next = r.base + r.size;
            if (next <= addr) break; // no progress, or wrapped
            addr = next;
        }
        return out;
    }

    MEMORY_BASIC_INFORMATION mbi;
    while (VirtualQueryEx(proc.handle, reinterpret_cast<LPCVOID>(addr),
        &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        if (!committed_only || mbi.State == MEM_COMMIT)
        {
            out.push_back({
                reinterpret_cast<uintptr_t>(mbi.BaseAddress),
                mbi.RegionSize,
                mbi.Protect,
                mbi.Type,
                mbi.State
            });
        }
        addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (addr == 0) break; // wrapped
    }
    return out;
}

// ============================================================================
// Scanning
// ============================================================================

enum class ScanType : int {
    Exact = 0,
    NotEqual,
    GreaterThan,
    LessThan,
    GreaterOrEqual,
    LessOrEqual,
    Between,       // needle packs [lo, hi] (two value_size-wide bounds): lo <= current <= hi
    Changed,
    Unchanged,
    Increased,
    Decreased,
    IncreasedBy,   // current - prev == needle
    DecreasedBy,   // prev - current == needle
    UnknownInitial,
};

// Tri-state page-protection filter (CE's Writable/Executable checkboxes).
// First scan only; later scans revisit addresses already found.
enum class TriState : int {
    DontCare = 0, // scan regardless of this attribute (indeterminate checkbox)
    Only     = 1, // only scan pages that have it       (checked)
    Exclude  = 2, // do not scan pages that have it     (unchecked)
};

enum class ValueType : int {
    Int8   = 0,
    Int16,
    Int32,
    Int64,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Float,
    Double,
    String,       // variable length; scan width comes from the needle, not value_size
    ArrayOfBytes, // variable length hex signature with optional wildcards (see mask)
};

// Fixed byte width of a value type; 0 for the variable-length String/ArrayOfBytes
// (use the needle length instead).
inline size_t value_size(ValueType vt)
{
    switch (vt)
    {
    case ValueType::Int8:   case ValueType::UInt8:   return 1;
    case ValueType::Int16:  case ValueType::UInt16:  return 2;
    case ValueType::Int32:  case ValueType::UInt32:
    case ValueType::Float:                           return 4;
    case ValueType::Int64:  case ValueType::UInt64:
    case ValueType::Double:                          return 8;
    case ValueType::String:
    case ValueType::ArrayOfBytes:                    return 0;
    }
    return 4;
}

// True for value types that scan byte-by-byte at needle length (String/AOB).
inline bool is_bytewise(ValueType vt)
{
    return vt == ValueType::String || vt == ValueType::ArrayOfBytes;
}

struct ScanResult {
    uintptr_t address;
    uint8_t   snapshot[8]; // value at time of last scan
};

// Case-insensitive byte-string equality (ASCII folding).
inline bool str_eq_ascii_ci(const uint8_t* a, const uint8_t* b, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        if (std::tolower(a[i]) != std::tolower(b[i])) return false;
    return true;
}

// Case-insensitive UTF-16LE equality (`n` = byte length). Folds via CharUpperW
// so non-ASCII text (e.g. Cyrillic) matches too; its single-char form packs the
// code unit into the pointer. Surrogate halves fold to themselves.
inline bool str_eq_utf16_ci(const uint8_t* a, const uint8_t* b, size_t n)
{
    auto upper = [](uint16_t c) -> uint16_t {
        return (uint16_t)(uintptr_t)CharUpperW(
            reinterpret_cast<LPWSTR>((uintptr_t)c));
    };
    for (size_t i = 0; i + 1 < n; i += 2)
    {
        uint16_t ca, cb;
        memcpy(&ca, a + i, 2);
        memcpy(&cb, b + i, 2);
        if (upper(ca) != upper(cb)) return false;
    }
    return true;
}

// Compare raw value buffers by scan/value type. `needle` = target, `current` =
// memory now, `prev` = last scan's snapshot (for Changed/Increased/...). `sz` is
// the width (value_size, or needle length for String/AOB). String: `ci` folds
// case, `wide` selects UTF-16. AOB: `mask` selects which bits must match per byte.
inline bool compare(ScanType st, ValueType vt,
    const void* current, const void* prev, const void* needle, size_t sz,
    bool ci = false, bool wide = false, const void* mask = nullptr)
{
    // Byte signature: match each position through its mask. Equality only; prev
    // is unused (snapshots hold at most 8 bytes).
    if (vt == ValueType::ArrayOfBytes)
    {
        const auto* c = static_cast<const uint8_t*>(current);
        const auto* n = static_cast<const uint8_t*>(needle);
        const auto* m = static_cast<const uint8_t*>(mask);
        bool eq = true;
        for (size_t i = 0; i < sz; ++i)
            if (((c[i] ^ n[i]) & m[i]) != 0) { eq = false; break; }
        if (st == ScanType::Exact)    return eq;
        if (st == ScanType::NotEqual) return !eq;
        return false;
    }

    // Text: equality only (ordering/deltas undefined). prev is unused; snapshots
    // hold at most 8 bytes, which need not cover a longer needle.
    if (vt == ValueType::String)
    {
        const auto* c = static_cast<const uint8_t*>(current);
        const auto* n = static_cast<const uint8_t*>(needle);
        const bool eq = !ci ? (memcmp(current, needle, sz) == 0)
                      : wide ? str_eq_utf16_ci(c, n, sz)
                             : str_eq_ascii_ci(c, n, sz);
        if (st == ScanType::Exact)    return eq;
        if (st == ScanType::NotEqual) return !eq;
        return false;
    }

    // Numeric compares go through double.
    auto asF64 = [&](const void* p) -> double {
        switch (vt)
        {
        case ValueType::Int8:   { int8_t   v; memcpy(&v, p, 1); return v; }
        case ValueType::Int16:  { int16_t  v; memcpy(&v, p, 2); return v; }
        case ValueType::Int32:  { int32_t  v; memcpy(&v, p, 4); return v; }
        case ValueType::Int64:  { int64_t  v; memcpy(&v, p, 8); return (double)v; }
        case ValueType::UInt8:  { uint8_t  v; memcpy(&v, p, 1); return v; }
        case ValueType::UInt16: { uint16_t v; memcpy(&v, p, 2); return v; }
        case ValueType::UInt32: { uint32_t v; memcpy(&v, p, 4); return v; }
        case ValueType::UInt64: { uint64_t v; memcpy(&v, p, 8); return (double)v; }
        case ValueType::Float:  { float    v; memcpy(&v, p, 4); return v; }
        case ValueType::Double: { double   v; memcpy(&v, p, 8); return v; }
        case ValueType::String:
        case ValueType::ArrayOfBytes: return 0; // handled above
        }
        return 0;
    };

    switch (st)
    {
    case ScanType::Exact:
        // Floats rarely match bit-for-bit, so compare within a relative tolerance.
        // Integers use an exact byte compare.
        if (vt == ValueType::Float)
        {
            float a, b; memcpy(&a, current, 4); memcpy(&b, needle, 4);
            return std::fabs(a - b) <= 0.001f * std::fmax(1.0f, std::fabs(b));
        }
        if (vt == ValueType::Double)
        {
            double a, b; memcpy(&a, current, 8); memcpy(&b, needle, 8);
            return std::fabs(a - b) <= 0.001 * std::fmax(1.0, std::fabs(b));
        }
        return memcmp(current, needle, sz) == 0;
    case ScanType::NotEqual:     return memcmp(current, needle, sz) != 0;
    case ScanType::GreaterThan:  return asF64(current) >  asF64(needle);
    case ScanType::LessThan:     return asF64(current) <  asF64(needle);
    case ScanType::GreaterOrEqual: return asF64(current) >= asF64(needle);
    case ScanType::LessOrEqual:    return asF64(current) <= asF64(needle);
    case ScanType::Between:
    {
        // needle holds two `sz`-wide bounds back to back. Inclusive, order-independent.
        const double v  = asF64(current);
        const double lo = asF64(needle);
        const double hi = asF64(static_cast<const uint8_t*>(needle) + sz);
        return lo <= hi ? (v >= lo && v <= hi) : (v >= hi && v <= lo);
    }
    case ScanType::Changed:      return memcmp(current, prev, sz) != 0;
    case ScanType::Unchanged:    return memcmp(current, prev, sz) == 0;
    case ScanType::Increased:    return asF64(current) >  asF64(prev);
    case ScanType::Decreased:    return asF64(current) <  asF64(prev);
    // "by N": the delta from the previous scan must equal the typed value.
    // Floats use a relative tolerance; integers compare exactly.
    case ScanType::IncreasedBy:
    case ScanType::DecreasedBy:
    {
        const double d = st == ScanType::IncreasedBy
                       ? asF64(current) - asF64(prev)
                       : asF64(prev)    - asF64(current);
        const double n = asF64(needle);
        if (vt == ValueType::Float || vt == ValueType::Double)
            return std::fabs(d - n) <= 0.001 * std::fmax(1.0, std::fabs(n));
        return d == n;
    }
    case ScanType::UnknownInitial: return true;
    }
    return false;
}

// True if the page protection grants write access.
inline bool is_writable(DWORD protect)
{
    const DWORD w = PAGE_READWRITE | PAGE_WRITECOPY |
                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (protect & w) != 0;
}

// True if the page protection grants execute access.
inline bool is_executable(DWORD protect)
{
    const DWORD x = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (protect & x) != 0;
}

// Readable, committed regions, constrained by the writable/executable filters.
inline bool is_scannable(const Region& r,
    TriState writable   = TriState::DontCare,
    TriState executable = TriState::DontCare)
{
    if (r.state != MEM_COMMIT) return false;
    const DWORD bad = PAGE_NOACCESS | PAGE_GUARD | PAGE_NOCACHE;
    if (r.protect & bad)       return false;
    // PAGE_EXECUTE (execute-only) is excluded: reading it faults.
    const DWORD rw  = PAGE_READWRITE | PAGE_WRITECOPY |
                      PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY |
                      PAGE_READONLY | PAGE_EXECUTE_READ;
    if ((r.protect & rw) == 0) return false;

    const bool w = is_writable(r.protect);
    if (writable == TriState::Only    && !w) return false;
    if (writable == TriState::Exclude &&  w) return false;

    const bool x = is_executable(r.protect);
    if (executable == TriState::Only    && !x) return false;
    if (executable == TriState::Exclude &&  x) return false;
    return true;
}

inline std::vector<ScanResult> scan_first(
    const Process& proc,
    ScanType       type,
    ValueType      vtype,
    const void*    needle,
    size_t         needle_len,
    TriState       wfilter = TriState::DontCare,
    TriState       xfilter = TriState::DontCare,
    bool           caseSensitive = true,
    bool           utf16         = false,
    const void*    mask          = nullptr,
    const std::atomic<bool>* cancel = nullptr)
{
    // Numeric types scan aligned to their fixed width; strings/AOB scan
    // byte-by-byte at needle length.
    const bool   bw    = is_bytewise(vtype);
    const size_t width = bw ? needle_len : value_size(vtype);
    const size_t step  = bw ? 1          : width;
    const bool   ci    = (vtype == ValueType::String) && !caseSensitive;
    std::vector<ScanResult> results;
    std::vector<uint8_t>    chunk;

    if (width == 0) return results; // empty needle / nothing to match

    auto cancelled = [&] { return cancel && cancel->load(std::memory_order_relaxed); };

    // Scan an already-read buffer, appending matches to `results`.
    auto scanBuffer = [&](uintptr_t base, const uint8_t* data, size_t len)
    {
        const uint8_t zero[8]{};
        const size_t  limit = len >= width ? len - width + 1 : 0;
        const size_t  snap  = width < sizeof(ScanResult::snapshot)
                            ? width : sizeof(ScanResult::snapshot);
        size_t ticks = 0;
        for (size_t off = 0; off < limit; off += step)
        {
            // Poll for cancellation periodically so a huge region can still abort.
            if ((++ticks & 0xFFFF) == 0 && cancelled()) return;
            const uint8_t* cur = data + off;
            if (compare(type, vtype, cur, zero, needle, width, ci, utf16, mask))
            {
                ScanResult r{};
                r.address = base + off;
                memcpy(r.snapshot, cur, snap);
                results.push_back(r);
            }
        }
    };

    // Read/scan in bounded windows, not the whole region at once - a physical
    // RAM range can be many gigabytes in one block.
    constexpr size_t kMaxWindow = 64 * 1024 * 1024;
    constexpr size_t kPage      = 0x1000;
    for (auto& region : query_regions(proc))
    {
        if (cancelled()) return results;
        if (!is_scannable(region, wfilter, xfilter)) continue;

        for (size_t off = 0; off < region.size; off += kMaxWindow)
        {
            if (cancelled()) return results;
            const size_t    want = std::min<size_t>(kMaxWindow, region.size - off);
            const uintptr_t base = region.base + off;

            chunk.resize(want);
            if (read_bytes(proc, base, chunk.data(), want) == want)
            {
                scanBuffer(base, chunk.data(), want);
                continue;
            }

            // This window's read failed (a guard/decommitted page inside): fall
            // back to page-by-page so the rest survives.
            for (size_t p = 0; p < want; p += kPage)
            {
                if (cancelled()) return results;
                const size_t pageLen = std::min<size_t>(kPage, want - p);
                const size_t pgot = read_bytes(proc, base + p, chunk.data(), pageLen);
                if (pgot) scanBuffer(base + p, chunk.data(), pgot);
            }
        }
    }
    return results;
}

inline std::vector<ScanResult> scan_next(
    const Process&                 proc,
    const std::vector<ScanResult>& prev,
    ScanType                       type,
    ValueType                      vtype,
    const void*                    needle,
    size_t                         needle_len,
    bool                           caseSensitive = true,
    bool                           utf16         = false,
    const void*                    mask          = nullptr,
    const std::atomic<bool>*       cancel        = nullptr)
{
    const bool   bw    = is_bytewise(vtype);
    const size_t width = bw ? needle_len : value_size(vtype);
    const size_t snap  = width < sizeof(ScanResult::snapshot)
                       ? width : sizeof(ScanResult::snapshot);
    const bool   ci    = (vtype == ValueType::String) && !caseSensitive;
    std::vector<ScanResult> results;
    if (width == 0) return results;
    results.reserve(prev.size());

    // `prev` is address-sorted, so consecutive entries mostly fall in one read.
    // Cache a sliding window instead of a ReadProcessMemory per address (millions
    // of syscalls on an unknown-initial follow-up scan).
    constexpr size_t     kWindow = 64 * 1024;
    std::vector<uint8_t> win(kWindow);
    uintptr_t            winBase = 0;
    size_t               winLen  = 0; // valid bytes starting at winBase

    auto keep = [&](const ScanResult& r, const uint8_t* cur)
    {
        if (compare(type, vtype, cur, r.snapshot, needle, width, ci, utf16, mask))
        {
            ScanResult nr = r;
            memcpy(nr.snapshot, cur, snap);
            results.push_back(nr);
        }
    };

    size_t ticks = 0;
    for (auto& r : prev)
    {
        // Poll for cancellation so an abort doesn't wait for the whole prev list.
        if ((++ticks & 0xFFF) == 0 && cancel &&
            cancel->load(std::memory_order_relaxed))
            return results;

        // Fast path: value fully inside the cached window.
        if (winLen && r.address >= winBase && r.address + width <= winBase + winLen)
        {
            keep(r, win.data() + (r.address - winBase));
            continue;
        }

        // Refill the window starting at this address.
        const size_t got = read_bytes(proc, r.address, win.data(), kWindow);
        if (got >= width)
        {
            winBase = r.address;
            winLen  = got;
            keep(r, win.data());
        }
        else
        {
            // Isolated unreadable spot: single-value read, sized to the needle.
            winLen = 0;
            std::vector<uint8_t> one(width);
            if (read_raw(proc, r.address, one.data(), width)) keep(r, one.data());
        }
    }
    return results;
}

// Read the current value of a scan result back as a double (for display)
inline double read_as_f64(const Process& proc, uintptr_t addr, ValueType vt)
{
    uint8_t buf[8]{};
    read_raw(proc, addr, buf, value_size(vt));
    switch (vt)
    {
    case ValueType::Int8:   { int8_t   v; memcpy(&v,buf,1); return v; }
    case ValueType::Int16:  { int16_t  v; memcpy(&v,buf,2); return v; }
    case ValueType::Int32:  { int32_t  v; memcpy(&v,buf,4); return v; }
    case ValueType::Int64:  { int64_t  v; memcpy(&v,buf,8); return (double)v; }
    case ValueType::UInt8:  { uint8_t  v; memcpy(&v,buf,1); return v; }
    case ValueType::UInt16: { uint16_t v; memcpy(&v,buf,2); return v; }
    case ValueType::UInt32: { uint32_t v; memcpy(&v,buf,4); return v; }
    case ValueType::UInt64: { uint64_t v; memcpy(&v,buf,8); return (double)v; }
    case ValueType::Float:  { float    v; memcpy(&v,buf,4); return v; }
    case ValueType::Double: { double   v; memcpy(&v,buf,8); return v; }
    case ValueType::String:
    case ValueType::ArrayOfBytes: return 0;
    }
    return 0;
}

} // namespace mem
