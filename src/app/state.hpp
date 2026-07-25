#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include "memory/memory.hpp"
#include "memory/pe.hpp"
#include "memory/scan_session.hpp"
#include "memory/dissect/def.hpp"
#include "memory/symbols/store.hpp"

namespace app {

// A user-tracked address (a row in the addy list).
struct AddyEntry {
    char      desc[64];
    uintptr_t address;
    int       typeIdx;        // index into kValueTypeNames
    int       stringEncoding = 0; // 0 = UTF-8, 1 = UTF-16 (used only for String)
    int       length = 8;     // read/display width in bytes, for String & Pattern
    std::string value;        // current/edited value; grows for long strings
    bool      frozen;

    // Module anchor: survives ASLR across a re-attach. When moduleName is set,
    // `address` is derived (module base + rva) and re-resolved on every module
    // refresh; empty means a plain absolute address (heap/stack/private).
    std::string moduleName;         // e.g. "game.exe"; empty = absolute
    uintptr_t   rva = 0;            // offset from the module base, when anchored
    bool        anchorUnresolved = false; // anchored, but the module isn't loaded now

    // Feedback for the last manual write attempt (0=none, 1=ok, 2=failed).
    int       writeStatus = 0;
};

// Shared application state, passed by reference to the UI draw functions.
struct AppState {
    mem::Process proc;
    char         processLabel[256] = "No process selected";
    std::string  procIconPath;      // exe path of the attached process, for the toolbar icon

    // Target exited: the handle is closed, but the addy list and scan results
    // are kept - those addresses are still worth something on a re-attach.
    bool         procExited         = false;
    double       procAliveNextCheck = 0.0; // ImGui::GetTime() of the next liveness check

    // Scan inputs (bound to the controls on the right panel).
    char scanValue[4096] = "";  // large enough for long AOB signatures
    char scanValue2[64]  = "";  // upper bound, used only by the "Value between" scan type
    int  scanType      = 0;   // index into kScanTypeNames
    int  valueType     = 2;   // index into kValueTypeNames (default: 4 Bytes)

    // Tri-state page-protection filters (mem::TriState as int):
    // 0 = don't care, 1 = only, 2 = exclude.
    int  writableFilter   = 1;  // default: writable only
    int  executableFilter = 0;

    // String-scan options (used only when valueType == String).
    bool stringCaseSensitive = true;
    int  stringEncoding      = 0;   // 0 = UTF-8/ASCII, 1 = UTF-16 (LE)

    ScanSession scan;

    // Selection over the current scan results (parallel to scan.results()).
    std::vector<char> resultSel;      // 1 = selected
    int               selAnchor = -1; // last clicked row, for Shift-range

    std::vector<AddyEntry> addyList;

    // Process picker modal.
    bool                           showProcPicker  = false;
    std::vector<mem::ProcessEntry> procList;
    char                           procFilter[128] = "";
    int                            procSelected    = -1;
    double                         procNextRefresh = 0.0; // ImGui::GetTime() of next auto-refresh
    char                           attachError[160] = ""; // set by attachToProcess on failure; shown in the picker
    bool                           wasProcPickerOpen = false; // tracks open->closed edge, to clear attachError on (re)open

    // Add-address modal. Input is a hex address or "module.exe+offset".
    bool showAddAddr        = false;
    char addAddrInput[128]  = "";
    char addAddrDesc[64]    = "No description";
    int  addAddrType        = 2;   // default: 4 Bytes
    int  addAddrStringEncoding = 0; // 0 = UTF-8, 1 = UTF-16 (used only for String)
    int  addAddrLength      = 8;   // read/display width, for String & Pattern

    // "Clear all addresses" confirmation modal.
    bool showClearAddy      = false;

    // Settings window.
    bool showSettings = false;
    bool darkTheme    = false;  // false = light theme (default), true = dark

    // Routes raw reads/writes through the driver's IOCTL client instead of
    // Read/WriteProcessMemory when on; driverStatus explains the current state.
    bool        useKernelDriver = false;
    std::string driverStatus;

    // Memory View window. Both panes navigate independently; the Go bar seeds both.
    bool      showMemView  = false;
    uintptr_t disasmAddr   = 0;      // first visible disasm line
    uintptr_t hexAddr      = 0;      // first visible hex row
    // Selected disasm row, keyed by address so the highlight tracks scrolling
    // (0 = none). Ctrl+C copies it.
    uintptr_t disasmSelAddr = 0;
    // Hex byte selection: inclusive address range (0/0 = none). Anchor is the
    // fixed end of a drag; keyed by address so it tracks scrolling.
    uintptr_t hexSelStart  = 0;
    uintptr_t hexSelEnd    = 0;
    uintptr_t hexSelAnchor = 0;
    bool      hexSelecting = false;
    // Disassembly scrollbar range. Recomputed while idle (module > region >
    // 64 KB fallback); frozen while dragging so the mapping can't shift.
    uintptr_t disasmSbBase = 0;
    size_t    disasmSbSize = 0;
    bool      disasmSbDrag = false;
    // Same, for the Hex View scrollbar.
    uintptr_t hexSbBase = 0;
    size_t    hexSbSize = 0;
    bool      hexSbDrag = false;

    // IDA-style pane sync toggles: each pane follows the other's address; both
    // on = two-way lock. prev* are last frame's addresses, to detect which moved.
    bool      syncDisasmToHex = false; // Disassembly follows Hex View
    bool      syncHexToDisasm = false; // Hex View follows Disassembly
    uintptr_t prevDisasmAddr  = 0;
    uintptr_t prevHexAddr     = 0;
    int       memViewArch  = 0;      // 0 = x64, 1 = x86 (auto-detected)
    // Hex address or "module.exe+offset" expression.
    char      memGotoInput[128] = "";

    // Memory Regions panel: committed regions, refreshed periodically.
    std::vector<mem::Region> memRegions;
    double                   regionsNextRefresh = 0.0;
    // The panel follows the Disassembly address by itself; "Follow in Regions"
    // just asks it to come forward and scroll there.
    bool                     regionsFollow      = false;
    uintptr_t                regionsShownBase   = 0; // region it last scrolled to

    // Loaded modules, used to label addresses as "module+offset".
    std::vector<mem::ModuleEntry> modules;
    double                        modulesNextRefresh = 0.0;
    char                          moduleFilter[128]  = ""; // name filter in the Modules pane

    // Lazily-parsed PE exports per module, for "module.Symbol" syntax like
    // kernel32.CreateFileW. Keyed by lower-cased module name; cleared on refresh.
    struct ModuleExports {
        std::unordered_map<std::string, uintptr_t> byName; // lower(export) -> addr
        std::vector<std::string> names;                    // original case, sorted, for autocomplete
        // Reverse index for labeling: exports sorted by address, so an address
        // can be named by the nearest export at or before it.
        struct ExportAddr { uintptr_t addr; std::string name; };
        std::vector<ExportAddr> byAddr;
    };
    // mutable: filled on demand by the (const) address-expression parser.
    mutable std::unordered_map<std::string, ModuleExports> exportCache;

    // Lazily-parsed PE sections per module, to label regions by section. Keyed
    // by module base; cleared on refresh.
    mutable std::unordered_map<uintptr_t, std::vector<mem::Section>> sectionCache;

    // PDB symbols per module, parsed on a worker thread. mutable for the same
    // reason as exportCache: the const label/expression paths ask for a module's
    // symbols the first time an address inside it comes up. Survives the periodic
    // module refresh (it's keyed by base) and is dropped when the target exits.
    mutable mem::SymbolStore symbols;

    // Module bases waiting to be scanned for "Load all symbols". Filled by the
    // button, drained a few per frame by pumpSymbolScan so the PE reads don't
    // stall one frame. Order doesn't matter.
    mutable std::vector<uintptr_t> symScanQueue;

    // "Load PDB..." accepts a file whose build GUID doesn't match the module.
    bool symbolIgnoreMismatch = false;

    // Assemble modal (right-click a Disassembly row -> Assemble).
    bool      showAssemble    = false;
    uintptr_t asmAddress      = 0;
    char      asmInput[256]   = "";

    // Shared by Assemble, Change Opcode and NOP-fill - see setWriteError (app.cpp).
    char   writeError[128] = "";
    double writeErrorUntil = 0.0;

    // NOP-pad confirmation: shown when the assembled code is shorter than the
    // instruction(s) it overwrites (Yes = pad tail, No = write as-is, Cancel).
    // The assembled bytes wait here meanwhile.
    bool      showAsmNopConfirm = false;
    size_t    asmNopNewLen      = 0;   // length of the assembled code
    size_t    asmNopCoverLen    = 0;   // length of the overwritten instruction(s)
    size_t    asmNopByteCount   = 0;
    uint8_t   asmNopBytes[32]   = {};

    // Change-opcode modal: type raw instruction bytes as hex, written directly.
    // opcodeOrigLen is the original instruction length, to pad short edits.
    bool      showChangeOpcode  = false;
    uintptr_t opcodeAddress     = 0;
    size_t    opcodeOrigLen     = 0;
    char      opcodeInput[256]  = "";

    // Create-Signature modal. sigStyle 0 = IDA, 1 = Code.
    bool      showSignature   = false;
    uintptr_t sigAddress      = 0;
    int       sigStyle        = 0;
    bool      sigUnique       = false;
    char      sigOutput[512]  = "";

    // Find-Signature modal: scan the whole address space for a pasted pattern,
    // list the hits and jump Disassembly to the one the user takes. On its own
    // session so the results panel is left untouched.
    bool        showFindSig       = false;
    bool        findSigPending    = false; // waiting on a find scan (dropped if abandoned)
    char        findSigInput[512] = "";
    char        findSigError[128] = "";
    ScanSession findSigScan;
    std::vector<uintptr_t> findSigHits;       // what the last scan found
    size_t                 findSigTotal = 0;  // matches found, before the display cap
    size_t                 findSigLen   = 0;  // bytes in the pattern that found them
    int                    findSigSel   = -1; // selected row in that list

    // "Edit Value" modal for the Hex View: a type-aware write at one byte.
    bool      showHexEditValue       = false;
    uintptr_t hexEditValueAddr       = 0;
    uintptr_t hexCtxAddr             = 0;   // byte captured on right-click, for the menu
    int       hexEditValueType       = 0;   // index into kValueTypeNames (Byte)
    bool      hexEditValueHex        = false; // show/enter the value as hex (int types)
    int       hexEditValueEncoding   = 0;   // 0 = UTF-8, 1 = UTF-16 (String only)
    int       hexEditValueLength     = 8;   // read/write width for String & Pattern
    char      hexEditValueInput[256] = "";
    char      hexEditValueError[128] = "";

    // Module-name autocomplete shared by every address input. Only one field is
    // focused at a time, so a single owner id + highlighted row is enough.
    unsigned int addrAcOwner     = 0; // ImGui id of the input owning the dropdown
    int          addrAcHighlight = 0; // selected suggestion row

    // "Go to Address" modals, one per pane so a jump in one doesn't move the other.
    bool showGotoDisasm         = false;
    char gotoDisasmInput[128]   = "";
    bool showGotoHex            = false;
    char gotoHexInput[128]      = "";

    // Back-button history. Each pane keeps its own stack, pushed right before
    // that pane's address changes.
    std::vector<uintptr_t> disasmHistory;
    std::vector<uintptr_t> hexHistory;

    // Structure Dissector: classes on the left, the selected one on the right,
    // read at a single address.
    bool                showStructDissect = false;
    mem::StructRegistry structDefs;
    int                 structCur        = -1;  // selected class, -1 = none
    int                 dissectGuessSize = 512; // bytes the guesser reads
    // The address input, kept in step with the selected class's addressExpr;
    // dissectAddrClass is the class it currently holds.
    char                dissectAddr[128] = "";
    int                 dissectAddrClass = -1;
    // Class being renamed in the list, or -1.
    int                 structRenaming     = -1;
    char                structNameEdit[64] = "";
    // The value cell being edited, keyed by address so it survives the nesting
    // without having to track a path through it.
    uintptr_t           dissectEditAddr    = 0;
    char                dissectEditBuf[256] = "";
    // "Generate C++" window.
    bool                showStructCodegen = false;
    std::string         structCodeText;
};

} // namespace app
