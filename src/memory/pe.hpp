#pragma once
#include "memory.hpp"
#include <cstddef>

// Reads a module's PE tables out of the target's memory.
namespace mem {

struct ExportSym {
    std::string name;
    uintptr_t   addr;    // absolute, not an RVA
    uint16_t    ordinal;
};

// A mapped section (".text", ".rdata", ...) as an absolute VA range.
struct Section {
    uintptr_t base;
    size_t    size;    // VirtualSize, rounded up to a page
    char      name[9]; // 8-char section name + NUL
};

// The .pdb a module was built with - (name, guid, age) is unique per build.
struct PdbRef {
    std::string name;     // "ntdll.pdb"
    std::string origPath; // recorded at build time, often not on this machine
    uint8_t     guid[16] = {};
    uint32_t    age      = 0;
};

namespace detail {

// Same offsets in PE32 and PE32+; only the optional header's interior differs.
constexpr size_t kNtFileHdr = offsetof(IMAGE_NT_HEADERS64, FileHeader);
constexpr size_t kNtOptHdr  = offsetof(IMAGE_NT_HEADERS64, OptionalHeader);

// CodeView "RSDS" record
#pragma pack(push, 1)
struct CvInfoPdb70 {
    uint32_t signature;
    uint8_t  guid[16];
    uint32_t age;
    char     pdbName[260]; // NUL-terminated
};
#pragma pack(pop)

constexpr uint32_t kRsdsSignature = 0x53445352; // "RSDS"
constexpr size_t   kCvFixedSize   = offsetof(CvInfoPdb70, pdbName);
static_assert(kCvFixedSize == 24, "CvInfoPdb70 must stay packed");

inline std::string read_cstr(const Process& proc, uintptr_t addr, size_t cap = 512)
{
    char buf[512];
    if (cap > sizeof(buf)) cap = sizeof(buf);
    size_t got = read_tolerant(proc, addr, reinterpret_cast<uint8_t*>(buf), cap);
    if (got == 0) return {};
    size_t len = 0;
    while (len < got && buf[len] != '\0') ++len;
    return std::string(buf, len);
}

inline Section parse_section_header(const uint8_t* hdr, uintptr_t modBase)
{
    IMAGE_SECTION_HEADER sh;
    memcpy(&sh, hdr, sizeof(sh)); // `hdr` isn't aligned for a cast

    Section s{};
    memcpy(s.name, sh.Name, IMAGE_SIZEOF_SHORT_NAME); // Name isn't NUL-terminated
    s.name[IMAGE_SIZEOF_SHORT_NAME] = '\0';
    const uint32_t vsize = sh.Misc.VirtualSize;
    s.base = modBase + sh.VirtualAddress;
    // Page-align so a region split by protection still lands inside its section.
    s.size = (vsize + 0xFFF) & ~(size_t)0xFFF;
    return s;
}

struct PeHeaders {
    uint8_t  page[0x1000];
    size_t   got     = 0;   // bytes read; the header page is one committed region
    size_t   nt      = 0;   // offset of "PE\0\0" within page
    bool     valid   = false;
    bool     is64    = false;
    uint16_t numSecs = 0;
    uint16_t optSize = 0;

    uint16_t u16(size_t off) const
    { uint16_t v = 0; if (off + 2 <= got) memcpy(&v, page + off, 2); return v; }
    uint32_t u32(size_t off) const
    { uint32_t v = 0; if (off + 4 <= got) memcpy(&v, page + off, 4); return v; }

    // {0, 0} if the header is too short to reach entry `i`.
    void data_dir(int i, uint32_t& rva, uint32_t& size) const
    {
        const size_t ddOff = is64 ? offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory)
                                  : offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
        const size_t slot  = nt + kNtOptHdr + ddOff +
                             (size_t)i * sizeof(IMAGE_DATA_DIRECTORY);
        rva  = u32(slot + offsetof(IMAGE_DATA_DIRECTORY, VirtualAddress));
        size = u32(slot + offsetof(IMAGE_DATA_DIRECTORY, Size));
    }
};

inline PeHeaders read_pe_headers(const Process& proc, uintptr_t modBase)
{
    PeHeaders h;
    h.got = read_tolerant(proc, modBase, h.page, sizeof(h.page));
    if (h.got < sizeof(IMAGE_DOS_HEADER) ||
        h.u16(offsetof(IMAGE_DOS_HEADER, e_magic)) != IMAGE_DOS_SIGNATURE) // "MZ"
        return h;

    const int32_t lfanew = (int32_t)h.u32(offsetof(IMAGE_DOS_HEADER, e_lfanew));
    // u16/u32 bound-check themselves, so this only has to cover the file header.
    if (lfanew <= 0 || (size_t)lfanew + kNtOptHdr > h.got) return h;
    h.nt = (size_t)lfanew;
    if (h.u32(h.nt + offsetof(IMAGE_NT_HEADERS64, Signature)) != IMAGE_NT_SIGNATURE)
        return h;                                           // "PE\0\0"

    h.numSecs = h.u16(h.nt + kNtFileHdr + offsetof(IMAGE_FILE_HEADER, NumberOfSections));
    h.optSize = h.u16(h.nt + kNtFileHdr + offsetof(IMAGE_FILE_HEADER, SizeOfOptionalHeader));
    h.is64    = h.u16(h.nt + kNtOptHdr + offsetof(IMAGE_OPTIONAL_HEADER64, Magic))
                == IMAGE_NT_OPTIONAL_HDR64_MAGIC; // PE32+ vs PE32
    h.valid   = true;
    return h;
}

// Empty if the table spills past the header page - read_sections handles that.
inline void parse_sections(const PeHeaders& h, uintptr_t modBase,
    std::vector<Section>& out)
{
    out.clear();
    if (!h.valid || h.numSecs == 0 || h.numSecs > 96) return; // PE caps sections at 96

    const size_t secTable = h.nt + kNtOptHdr + h.optSize;
    if (secTable + (size_t)h.numSecs * sizeof(IMAGE_SECTION_HEADER) > h.got) return;

    out.reserve(h.numSecs);
    for (uint16_t i = 0; i < h.numSecs; ++i)
        out.push_back(parse_section_header(
            h.page + secTable + (size_t)i * sizeof(IMAGE_SECTION_HEADER), modBase));
}

// A missing entry still returns true, with zero rva/size.
inline bool find_data_dir(const Process& proc, uintptr_t modBase, int dirIndex,
    uint32_t& dirRva, uint32_t& dirSize, bool& is64)
{
    const PeHeaders h = read_pe_headers(proc, modBase);
    if (!h.valid) return false;
    is64 = h.is64;
    h.data_dir(dirIndex, dirRva, dirSize);
    return true;
}

} // namespace detail

// In header order (.text, .rdata, ...).
inline std::vector<Section> read_sections(const Process& proc, const ModuleEntry& mod)
{
    const detail::PeHeaders h = detail::read_pe_headers(proc, mod.base);
    std::vector<Section> out;
    detail::parse_sections(h, mod.base, out);
    if (!out.empty() || !h.valid || h.numSecs == 0 || h.numSecs > 96)
        return out;

    // Table spilled past the header page (~90+ sections); read those directly.
    const size_t secTable = h.nt + detail::kNtOptHdr + h.optSize;
    out.reserve(h.numSecs);
    for (uint16_t i = 0; i < h.numSecs; ++i)
    {
        uint8_t hdr[sizeof(IMAGE_SECTION_HEADER)];
        if (!read_raw(proc, mod.base + secTable + (uintptr_t)i * sizeof(hdr),
                      hdr, sizeof(hdr)))
            break;
        out.push_back(detail::parse_section_header(hdr, mod.base));
    }
    return out;
}

namespace detail {

inline bool read_pdb_ref_from_dir(const Process& proc, const ModuleEntry& mod,
    uint32_t dirRva, uint32_t dirSize, PdbRef& out)
{
    constexpr size_t kEntry    = sizeof(IMAGE_DEBUG_DIRECTORY);
    constexpr uint32_t kMaxDbg = 64; // no real module carries more

    if (dirRva == 0 || dirSize < kEntry) return false;

    uint32_t n = (uint32_t)(dirSize / kEntry);
    if (n > kMaxDbg) n = kMaxDbg;
    uint8_t dir[kEntry * kMaxDbg];
    const size_t got = read_tolerant(proc, mod.base + dirRva, dir, (size_t)n * kEntry);
    n = (uint32_t)(got / kEntry);

    for (uint32_t i = 0; i < n; ++i)
    {
        IMAGE_DEBUG_DIRECTORY e;
        memcpy(&e, dir + (size_t)i * kEntry, kEntry);
        if (e.Type != IMAGE_DEBUG_TYPE_CODEVIEW) continue;

        // AddressOfRawData is an RVA once the image is mapped.
        CvInfoPdb70 cv;
        const size_t rgot = read_tolerant(proc, mod.base + e.AddressOfRawData,
            reinterpret_cast<uint8_t*>(&cv), sizeof(cv));
        if (rgot < kCvFixedSize) continue;
        if (cv.signature != kRsdsSignature) continue;
        memcpy(out.guid, cv.guid, sizeof(out.guid));
        out.age = cv.age;

        const size_t avail = rgot - kCvFixedSize;
        size_t len = 0;
        while (len < avail && cv.pdbName[len] != '\0') ++len;
        if (len == 0) continue;
        out.origPath.assign(cv.pdbName, len);

        const size_t slash = out.origPath.find_last_of("\\/");
        out.name = slash == std::string::npos ? out.origPath
                                              : out.origPath.substr(slash + 1);

        // Goes into a cache path and a server URL - strip what a hostile module
        // could smuggle in.
        for (char& c : out.name)
        {
            const unsigned char u = (unsigned char)c;
            if (u < 0x20 || c == '\\' || c == '/' || c == ':' || c == '*' ||
                c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
                c = '_';
        }
        return !out.name.empty();
    }
    return false;
}

} // namespace detail

// False on a stripped binary.
inline bool read_pdb_ref(const Process& proc, const ModuleEntry& mod, PdbRef& out)
{
    uint32_t dirRva = 0, dirSize = 0;
    bool is64 = false;
    if (!detail::find_data_dir(proc, mod.base, IMAGE_DIRECTORY_ENTRY_DEBUG,
            dirRva, dirSize, is64) || dirRva == 0)
        return false;
    return detail::read_pdb_ref_from_dir(proc, mod, dirRva, dirSize, out);
}

// Both in one page read - a bulk "load all" would cost ~25 tiny reads per module.
inline bool read_symbol_inputs(const Process& proc, const ModuleEntry& mod,
    std::vector<Section>& sections, PdbRef& outRef, bool& hasRef)
{
    hasRef = false;
    sections.clear();

    const detail::PeHeaders h = detail::read_pe_headers(proc, mod.base);
    if (!h.valid) return false;

    detail::parse_sections(h, mod.base, sections);
    // Only ~90+ section modules spill past the header page.
    if (sections.empty() && h.numSecs != 0 && h.numSecs <= 96)
        sections = read_sections(proc, mod);

    // The slot is in the header page; the records it points at aren't.
    uint32_t dbgRva = 0, dbgSize = 0;
    h.data_dir(IMAGE_DIRECTORY_ENTRY_DEBUG, dbgRva, dbgSize);
    hasRef = detail::read_pdb_ref_from_dir(proc, mod, dbgRva, dbgSize, outRef);
    return true;
}

// Absolute addresses; forwarders are skipped.
inline std::vector<ExportSym> read_exports(const Process& proc, const ModuleEntry& mod)
{
    std::vector<ExportSym> out;

    uint32_t dirRva = 0, dirSize = 0;
    bool is64 = false;
    if (!detail::find_data_dir(proc, mod.base, IMAGE_DIRECTORY_ENTRY_EXPORT,
            dirRva, dirSize, is64) || dirRva == 0)
        return out;

    // Only the fields from Base onward are used. Reading just those keeps this
    // working when the page holding the directory's first bytes won't read.
    constexpr size_t kUsed = offsetof(IMAGE_EXPORT_DIRECTORY, Base);
    IMAGE_EXPORT_DIRECTORY ed{};
    if (!read_raw(proc, mod.base + dirRva + kUsed,
            (uint8_t*)&ed + kUsed, sizeof(ed) - kUsed))
        return out;

    // A corrupt header shouldn't drive a giant allocation.
    constexpr uint32_t kMaxExports = 1'000'000;
    const uint32_t numNames = ed.NumberOfNames;
    const uint32_t numFuncs = ed.NumberOfFunctions;
    if (numNames == 0 || numNames > kMaxExports || numFuncs > kMaxExports) return out;

    std::vector<uint32_t> nameRvas(numNames);
    std::vector<uint16_t> ordIdx(numNames);
    std::vector<uint32_t> funcRvas(numFuncs);
    if (!read_raw(proc, mod.base + ed.AddressOfNames,
            nameRvas.data(), numNames * sizeof(uint32_t)) ||
        !read_raw(proc, mod.base + ed.AddressOfNameOrdinals,
            ordIdx.data(), numNames * sizeof(uint16_t)) ||
        !read_raw(proc, mod.base + ed.AddressOfFunctions,
            funcRvas.data(), numFuncs * sizeof(uint32_t)))
        return out;

    out.reserve(numNames);
    for (uint32_t i = 0; i < numNames; ++i)
    {
        const uint16_t fi = ordIdx[i];
        if (fi >= numFuncs) continue;
        const uint32_t frva = funcRvas[fi];
        if (frva == 0) continue;
        // A forwarder's "address" lands inside the export directory itself.
        if (frva >= dirRva && frva < dirRva + dirSize) continue;

        std::string name = detail::read_cstr(proc, mod.base + nameRvas[i], 256);
        if (name.empty()) continue;
        out.push_back({std::move(name), mod.base + frva, (uint16_t)(fi + ed.Base)});
    }
    return out;
}

} // namespace mem
