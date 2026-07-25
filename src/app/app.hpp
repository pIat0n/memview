#pragma once
#include <string_view>

#include "app/state.hpp"

struct ImGuiViewport;

namespace app {

// Owns the shared state and draws one UI frame.
class App {
public:
    // Apply the light theme + style tweaks (once, after context init).
    void setupStyle();

    // Build the UI for the current frame.
    void drawFrame();

    AppState& state() { return state_; }

private:
    AppState state_;
};

// --- Actions shared between UI panels (implemented in app.cpp) --------------

// Switch between the light/dark color scheme, reapplying setupStyle()'s tweaks.
void applyTheme(AppState& s, bool dark);

// Applies s.useKernelDriver to s.proc.backend, falling back to WinAPI (with the
// reason in s.driverStatus) if the driver won't load. Safe with no process attached.
void applyBackend(AppState& s);

// Disassembly syntax colors (packed IM_COL32). Kept small; punctuation stays
// in the theme text color so the listing doesn't turn into a christmas tree.
struct DisasmPalette {
    uint32_t mnemonic; // regular mnemonics + prefixes (rep, lock, ...)
    uint32_t reg;      // registers
    uint32_t num;      // immediates, displacements and raw addresses
    uint32_t sym;      // resolved "module+offset" symbols (label color)
    uint32_t call;     // call/ret mnemonics
    uint32_t jump;     // jmp/jcc mnemonics
};

// Palette for the active theme: x64dbg Dark on dark, the same hues darkened on
// light (derived from s.darkTheme).
const DisasmPalette& disasmPalette(const AppState& s);

// Parse the scan inputs and kick off a first/next scan.
void startFirstScan(AppState& s);
void startNextScan(AppState& s);

// Attach to a process: open a handle, update the label, reset the scan. Returns
// false on failure, with s.attachError set for the picker to show.
bool attachToProcess(AppState& s, const mem::ProcessEntry& entry);

// Attach to raw physical RAM instead of a process. Returns false (with
// s.attachError set) if the driver isn't loaded.
bool attachToPhysicalMemory(AppState& s);

// Call once per frame: notices the target exiting and tears the session down.
// Rate-limited, so it costs a wait syscall a few times a second.
void pollProcessAlive(AppState& s);

// Stop the scans, close the handle, drop everything read from the dead address
// space. The addy list and scan results are left alone.
void onProcessExited(AppState& s);

// Copy a scan result (by display index) into the addy list.
void addAddyFromResult(AppState& s, int displayIndex);

// Copy every selected scan result into the addy list.
void addSelectedResultsToAddy(AppState& s);

// Open Memory View at the target's main module, picking x86/x64 from bitness.
void openMemoryView(AppState& s);

// Open Memory View and jump both panes to `address`.
void openMemoryViewAt(AppState& s, uintptr_t address);

// Open the Structure Dissector, its own window like Memory View.
void openStructDissect(AppState& s);

// Add an addy-list entry for a raw address (used by the disasm context menu).
// `typeIdx` indexes kValueTypeNames; `length` is the read width String and
// Pattern need, clamped to what the list can read.
void addAddyAddress(AppState& s, uintptr_t address, int typeIdx = 2,
                    int length = 8);

// The module `addr` falls inside, or nullptr (heap, stack, private mappings).
const mem::ModuleEntry* findModule(const AppState& s, uintptr_t addr);

// Set an addy entry's address and (re)capture its module anchor: if `addr` falls
// inside a loaded module the entry anchors to (module, rva) so it survives ASLR
// on a re-attach; otherwise the anchor is cleared and the address stays absolute.
void anchorAddyEntry(const AppState& s, AddyEntry& e, uintptr_t addr);

// Re-resolve every anchored addy entry against the current module list: address
// becomes base + rva. Entries whose module isn't loaded are flagged unresolved
// (address zeroed so live-sync skips them until the module appears).
void rebaseAddyList(AppState& s);

// Reload the module list and drop the caches keyed off module bases, then rebase
// the addy list. The single place module bases get refreshed; call sites keep
// owning their own refresh timer.
void refreshModules(AppState& s);

// Name of the section of `mod` containing `addr` (".text", ".rdata", ...), or
// nullptr for addresses before the first section (the PE header region). Parses
// and caches the module's section headers on first use.
const char* findSectionName(const AppState& s, const mem::ModuleEntry& mod, uintptr_t addr);

// Queue a PDB load for `m`. Reads the module's CodeView record and section table
// here, on the thread that owns the process handle, then hands plain data to the
// worker. `forcedPath` skips the usual search order (the "Load PDB..." action);
// `verify` off accepts a PDB whose build GUID doesn't match.
void requestModuleSymbols(const AppState& s, const mem::ModuleEntry& m,
    bool force = false, const char* forcedPath = nullptr, bool verify = true);

// Queue every loaded module that hasn't been tried yet. Cheap: it only records
// the module bases; pumpSymbolScan does the per-module PE reads a few per frame.
void requestAllModuleSymbols(const AppState& s);

// Drain a bounded slice of the "load all" scan queue, reading each module's PE
// headers and queueing its PDB load. Call once per frame.
void pumpSymbolScan(const AppState& s);

// Widest label formatAddrLabel will emit. An undecorated C++ name runs to
// hundreds of characters, and the address column is sized to its longest row.
constexpr int kAddrLabelMax = 44;

// A resolved symbol. `name` views into the module's symbol table: a PDB symbol
// lives until the target exits; an export name lives until the next module
// refresh drops the export cache. Either way it's valid for the current frame,
// which is all formatAddrLabel needs. (A view, so a PDB pmr::string and an export
// std::string resolve through one field.)
struct SymHit {
    std::string_view        name;
    const mem::ModuleEntry* module; // the module it was found in
    uintptr_t               base;   // where the symbol starts
    uintptr_t               disp;   // addr - base
};

// Nearest PDB symbol at or before `addr`, inside the module holding it. Queues
// that module's symbols the first time it's asked, so simply rendering an
// address is enough to pull them in.
bool findSymbolAt(const AppState& s, uintptr_t addr, SymHit& out);

// Label `addr` as "module.Symbol+offset" when symbols are loaded, else
// "module+offset" inside a loaded module, else raw hex. Long C++ names lose
// their parameter list and are clipped to kAddrLabelMax.
void formatAddrLabel(const AppState& s, uintptr_t addr, char* out, size_t n);

// Parse a "Go to"/"Add Address" expression: plain hex, a module name (its base),
// or "module+offset" with a hex offset, e.g. "notepad.exe+1a2b". Module names
// match case-insensitively. Returns false if nothing resolves.
bool parseAddrExpr(const AppState& s, const char* text, uintptr_t& out);

// Like ImGui::InputText, plus a module-name autocomplete dropdown (case-insensitive
// prefix; Tab/click to accept, Up/Down to choose). `flags` are ImGuiInputTextFlags.
// Optional outs: `deactivatedAfterEdit` mirrors IsItemDeactivatedAfterEdit() for the
// field; `accepted` is set the frame a suggestion is inserted into `buf`.
bool addrInput(AppState& s, const char* id, char* buf, size_t bufSize,
    int flags, bool* deactivatedAfterEdit = nullptr, bool* accepted = nullptr,
    const char* hint = nullptr);

// Assemble s.asmInput at s.asmAddress and write it into the target. Closes the
// modal on success; leaves it open with s.writeError on failure.
bool assembleAndWrite(AppState& s);

// Resolve the NOP-pad prompt: write the bytes stashed by assembleAndWrite. If
// padWithNops, pad the tail up to s.asmNopCoverLen. Closes the modals.
bool commitAsmBytes(AppState& s, bool padWithNops);

// Parse the hex bytes in s.opcodeInput and write them at s.opcodeAddress
// (whitespace-tolerant). Short edits pad the tail with NOPs up to s.opcodeOrigLen.
// Closes the modal on success; leaves it open with s.writeError on failure.
bool changeOpcodeAndWrite(AppState& s);

// Overwrite `length` bytes at `address` with single-byte 0x90 NOPs. False
// (with s.writeError set) if the write failed.
bool nopFill(AppState& s, uintptr_t address, size_t length);

// (Re)generate the signature for s.sigAddress in style s.sigStyle, filling
// s.sigOutput/s.sigUnique. Called when the modal opens or its style changes.
void generateSignature(AppState& s);

// A modal that blocks only its own viewport, used like BeginPopupModal/EndPopup.
// The real thing freezes every window in every OS viewport, so a dialog in the
// main window also locks up a torn-out Memory View. `vp` is the viewport to
// block and center on; width/height <= 0 auto-size that axis.
bool beginBlockingModal(const char* title, bool* p_open,
                        const ImGuiViewport* vp, float width, float height);

} // namespace app
