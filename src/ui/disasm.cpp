#include "ui/memory_view.hpp"
#include "app/app.hpp"
#include "memory/memory.hpp"
#include "memory/value_format.hpp" // parseAob (Find Signature modal)
#include <imgui.h>
#include <imgui_internal.h> // FindWindowByName to anchor the modal's viewport
#include <Zydis/Zydis.h>
#include <Zycore/Format.h> // ZyanStringAppendFormat (symbol hook)
#include <vector>
#include <cstdio>
#include <cstring>
#include <algorithm>

namespace ui {

namespace {

// ZydisDecoderDecodeFull writes up to ZYDIS_MAX_OPERAND_COUNT operands, so the
// array must be that size or it overruns the stack.
using OperandArray = ZydisDecodedOperand[ZYDIS_MAX_OPERAND_COUNT];

// arch: 0 = x64, 1 = x86.
void initDecoder(ZydisDecoder& dec, int arch)
{
    if (arch == 1)
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
            ZYDIS_STACK_WIDTH_32);
    else
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64,
            ZYDIS_STACK_WIDTH_64);
}

// Decode the length of the single instruction at `code`. Returns 0 on failure.
uint8_t instrLen(const ZydisDecoder& dec, const uint8_t* code, size_t avail)
{
    ZydisDecodedInstruction ins;
    OperandArray ops;
    if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code, avail, &ins, ops)))
        return ins.length;
    return 0;
}

// Start of the instruction ending exactly at `addr`. x86 is variable length, so
// try candidate lengths 1..15 and keep the one that decodes cleanly up to
// `addr` (the usual scroll-up heuristic). Falls back to addr-1.
uintptr_t prevInstr(const mem::Process& proc, const ZydisDecoder& dec,
    uintptr_t addr)
{
    if (addr <= kAddrFloor) return addr;
    uint8_t buf[16];
    for (int len = 15; len >= 1; --len)
    {
        const uintptr_t cand = addr - (uintptr_t)len;
        if (mem::read_tolerant(proc, cand, buf, (size_t)len) != (size_t)len)
            continue;
        const uint8_t got = instrLen(dec, buf, (size_t)len);
        if (got == len) return cand;
    }
    return addr - 1;
}

// Advance `addr` by one instruction (for scrolling down).
uintptr_t nextInstr(const mem::Process& proc, const ZydisDecoder& dec,
    uintptr_t addr)
{
    uint8_t buf[16];
    const size_t got = mem::read_tolerant(proc, addr, buf, sizeof(buf));
    const uint8_t len = got ? instrLen(dec, buf, got) : 0;
    return addr + (len ? len : 1);
}

// --- Syntax highlighting ------------------------------------------------

// Instruction flavor for the mnemonic accent: control flow gets color, nop/int3
// filler fades.
enum RowKind : uint8_t { kKindNormal, kKindCall, kKindJump, kKindRet, kKindNop };

uint8_t rowKind(const ZydisDecodedInstruction& ins)
{
    switch (ins.meta.category)
    {
    case ZYDIS_CATEGORY_CALL:      return kKindCall;
    case ZYDIS_CATEGORY_COND_BR:
    case ZYDIS_CATEGORY_UNCOND_BR: return kKindJump;
    case ZYDIS_CATEGORY_RET:       return kKindRet;
    case ZYDIS_CATEGORY_NOP:       return kKindNop;
    case ZYDIS_CATEGORY_INTERRUPT:
        return ins.mnemonic == ZYDIS_MNEMONIC_INT3 ? kKindNop : kKindNormal;
    default:                       return kKindNormal;
    }
}

// Branch destination for a call/jmp/jcc, for double-click follow. Returns 0 when
// there's no static target (register-indirect, or an unreadable pointer slot).
uintptr_t followTarget(const mem::Process& proc, int arch,
    const ZydisDecodedInstruction& ins, const ZydisDecodedOperand* ops,
    uintptr_t rip)
{
    for (int o = 0; o < ins.operand_count_visible; ++o)
    {
        const ZydisDecodedOperand& op = ops[o];
        ZyanU64 abs = 0;
        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &op, rip, &abs)))
                return (uintptr_t)abs;
        }
        // RIP-relative memory operand (e.g. IAT thunk `jmp [rip+disp]`): the
        // effective address is the pointer slot; dereference it for the target.
        else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                 op.mem.base == ZYDIS_REGISTER_RIP &&
                 ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &op, rip, &abs)))
        {
            uintptr_t ptr = 0;
            const size_t psz = arch == 1 ? 4 : 8;
            if (mem::read_raw(proc, (uintptr_t)abs, &ptr, psz))
                return ptr;
            return 0;
        }
    }
    return 0;
}

// Default PRINT_ADDRESS_ABS handler, captured when the hook is installed.
// File-scope is fine: the UI is single-threaded.
ZydisFormatterFunc defaultPrintAddrAbs = nullptr;

// Formatter hook: absolute addresses inside a loaded module print as a symbol
// ("ntdll.NtCreateFile+11") or "module+offset" via a SYMBOL token, so they pick
// up the symbol color. Covers call/jmp targets and RIP-relative operands, e.g.
// "[user32.dll+1A2B]". Addresses outside every module fall through to the
// default handler, which prints them as a plain value.
ZyanStatus printAddrAbs(const ZydisFormatter* formatter,
    ZydisFormatterBuffer* buffer, ZydisFormatterContext* context)
{
    const auto* s = static_cast<const app::AppState*>(context->user_data);
    ZyanU64 address = 0;
    if (s && ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(context->instruction,
            context->operand, context->runtime_address, &address)) &&
        app::findModule(*s, (uintptr_t)address))
    {
        // Same label the address column shows, so an operand and the line it
        // points at read identically.
        char label[app::kAddrLabelMax + 24];
        app::formatAddrLabel(*s, (uintptr_t)address, label, sizeof(label));

        ZYAN_CHECK(ZydisFormatterBufferAppend(buffer, ZYDIS_TOKEN_SYMBOL));
        ZyanString* str;
        ZYAN_CHECK(ZydisFormatterBufferGetString(buffer, &str));
        return ZyanStringAppendFormat(str, "%s", label);
    }
    return defaultPrintAddrAbs(formatter, buffer, context);
}

// Token type -> color. Unlisted tokens (punctuation, "ptr", whitespace) keep
// the theme text color by design.
ImU32 spanColor(const app::DisasmPalette& pal, uint8_t kind, uint8_t type,
    ImU32 def, ImU32 dim)
{
    if (kind == kKindNop) return dim; // inter-function filler fades
    switch (type)
    {
    case ZYDIS_TOKEN_PREFIX:
    case ZYDIS_TOKEN_MNEMONIC:
        if (kind == kKindCall || kind == kKindRet) return pal.call;
        if (kind == kKindJump)                     return pal.jump;
        return pal.mnemonic;
    case ZYDIS_TOKEN_REGISTER:     return pal.reg;
    // Raw addresses use the value color; only resolved symbols get the label
    // color (the Value/Address vs Label split x64dbg makes).
    case ZYDIS_TOKEN_IMMEDIATE:
    case ZYDIS_TOKEN_DISPLACEMENT:
    case ZYDIS_TOKEN_ADDRESS_ABS:
    case ZYDIS_TOKEN_ADDRESS_REL:  return pal.num;
    case ZYDIS_TOKEN_SYMBOL:       return pal.sym;
    default:                       return def;
    }
}

// Plain text (no symbol substitution) of the instruction at `addr`, for the
// Assemble prefill: the assembler understands "call 0x...", not "call user32.dll+...".
void formatPlainInstr(const app::AppState& s, const ZydisDecoder& dec,
    uintptr_t addr, char* out, size_t n)
{
    out[0] = '\0';
    uint8_t buf[16];
    const size_t got = mem::read_tolerant(s.proc, addr, buf, sizeof(buf));
    if (!got) return;
    ZydisDecodedInstruction ins;
    OperandArray ops;
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, buf, got, &ins, ops)))
        return;
    ZydisFormatter fmt;
    ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterFormatInstruction(&fmt, &ins, ops,
        ins.operand_count_visible, out, n, addr, ZYAN_NULL);
}

} // namespace

void drawDisasm(app::AppState& s)
{
    ZydisDecoder dec;
    initDecoder(dec, s.memViewArch);

    const float lineH = ImGui::GetTextLineHeightWithSpacing();
    int rows = (int)(ImGui::GetContentRegionAvail().y / lineH);
    if (rows < 1) rows = 1;

    // Pane geometry, leaving a strip on the right for the region scrollbar.
    const ImVec2 paneOrigin = ImGui::GetCursorScreenPos();
    const ImVec2 paneAvail  = ImGui::GetContentRegionAvail();
    const float  sbW  = ImGui::GetStyle().ScrollbarSize;
    // Selectable widens its highlight by ItemSpacing.x; back that out so it
    // doesn't bleed under the scrollbar strip.
    const float  rowW = paneAvail.x > sbW
        ? paneAvail.x - sbW - ImGui::GetStyle().ItemSpacing.x
        : paneAvail.x;

    // Wheel paging (the pane has NoScrollWithMouse).
    if (ImGui::IsWindowHovered())
    {
        const float wheel = ImGui::GetIO().MouseWheel;
        if (wheel != 0.f)
        {
            const int steps = (int)(std::abs(wheel) * kLinesPerNotch + 0.5f);
            for (int i = 0; i < steps; ++i)
                s.disasmAddr = (wheel > 0.f)
                    ? prevInstr(s.proc, dec, s.disasmAddr)
                    : nextInstr(s.proc, dec, s.disasmAddr);
        }

        // Mouse "back" button.
        if (ImGui::IsMouseClicked(kMouseButtonBack))
            goBack(s.disasmHistory, s.disasmAddr);

        // Ctrl+G opens the Go to Address popup.
        if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_G))
        {
            s.gotoDisasmInput[0] = '\0';
            s.showGotoDisasm     = true;
        }

        // Ctrl+C copies the selected row's address.
        if (s.disasmSelAddr &&
            ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_C))
        {
            char addr[24];
            snprintf(addr, sizeof(addr), "%llX",
                (unsigned long long)s.disasmSelAddr);
            ImGui::SetClipboardText(addr);
        }
    }

    // Read enough for `rows` instructions (max 15 bytes each).
    std::vector<uint8_t> buf((size_t)rows * 16 + 16);
    const size_t got = mem::read_tolerant(s.proc, s.disasmAddr,
        buf.data(), buf.size());

    ZydisFormatter fmt;
    ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);

    // Install the module+offset symbol hook; SetHook hands back the default
    // for the fall-through path.
    ZydisFormatterFunc hook = &printAddrAbs;
    ZydisFormatterSetHook(&fmt, ZYDIS_FORMATTER_FUNC_PRINT_ADDRESS_ABS,
        (const void**)&hook);
    defaultPrintAddrAbs = hook;

    // Decode the whole screenful first, then render: the address column is sized
    // to the longest visible label so the columns stay flush for any mix.
    struct Span { uint8_t off, len, type; }; // colored slice of `text` (ZydisTokenType)
    struct Row {
        uintptr_t addr;
        uintptr_t target;     // branch destination for double-click follow; 0 = none
        uint8_t   len;        // instruction length; 0 = undecodable byte
        uint8_t   kind;       // RowKind, drives the mnemonic accent
        char      label[app::kAddrLabelMax + 24]; // symbol + "+offset"
        char      bytes[32];
        char      text[192];
        Span      spans[24];
        uint8_t   nspans;
    };
    std::vector<Row> view((size_t)rows);
    int labelW = kAddrLabelWidth;

    uintptr_t rip = s.disasmAddr;
    size_t    off = 0;
    for (int i = 0; i < rows; ++i)
    {
        Row& d = view[(size_t)i];
        d.addr = rip;
        app::formatAddrLabel(s, rip, d.label, sizeof(d.label));
        const int labLen = (int)strlen(d.label);
        if (labLen > labelW) labelW = labLen;

        ZydisDecodedInstruction ins;
        OperandArray ops;
        if (off < got && ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &dec, buf.data() + off, got - off, &ins, ops)))
        {
            d.kind    = rowKind(ins);
            d.target  = (d.kind == kKindCall || d.kind == kKindJump)
                ? followTarget(s.proc, s.memViewArch, ins, ops, rip) : 0;
            d.nspans  = 0;
            d.text[0] = '\0';

            // Tokenize rather than plain-format so each token's type becomes a
            // color span. Token values point into `tokBuf`, so copy them out.
            char tokBuf[256];
            ZydisFormatterTokenConst* tok = nullptr;
            if (ZYAN_SUCCESS(ZydisFormatterTokenizeInstruction(&fmt, &ins,
                    ops, ins.operand_count_visible, tokBuf, sizeof(tokBuf),
                    rip, &tok, &s)))
            {
                int tp = 0;
                while (tok)
                {
                    ZydisTokenType       type;
                    ZyanConstCharPointer val;
                    ZydisFormatterTokenGetValue(tok, &type, &val);
                    const int vlen = (int)strlen(val);
                    if (tp + vlen >= (int)sizeof(d.text)) break;
                    memcpy(d.text + tp, val, (size_t)vlen);
                    if (d.nspans < (uint8_t)IM_ARRAYSIZE(d.spans))
                        d.spans[d.nspans++] =
                            { (uint8_t)tp, (uint8_t)vlen, (uint8_t)type };
                    tp += vlen;
                    if (!ZYAN_SUCCESS(ZydisFormatterTokenNext(&tok)))
                        tok = nullptr;
                }
                d.text[tp] = '\0';
            }
            else
            {
                // Tokenizer failure: plain text in the default color.
                ZydisFormatterFormatInstruction(&fmt, &ins, ops,
                    ins.operand_count_visible, d.text, sizeof(d.text), rip,
                    ZYAN_NULL);
                d.spans[0] = { 0, (uint8_t)strlen(d.text),
                    (uint8_t)ZYDIS_TOKEN_INVALID };
                d.nspans   = 1;
            }

            // Raw bytes column (up to 8, ".." if longer).
            int bp = 0;
            const int shown = ins.length < 8 ? ins.length : 8;
            for (int b = 0; b < shown; ++b)
                bp += snprintf(d.bytes + bp, sizeof(d.bytes) - bp, "%02X ",
                    buf[off + b]);
            if (ins.length > 8)
                snprintf(d.bytes + bp, sizeof(d.bytes) - bp, "..");

            d.len = ins.length;
            off += ins.length;
            rip += ins.length;
        }
        else
        {
            // Unreadable or undecodable byte: show it and step one.
            d.len      = 0;
            d.target   = 0;
            d.kind     = kKindNormal;
            d.nspans   = 0;
            d.bytes[0] = '\0';
            d.text[0]  = '\0';
            off += 1;
            rip += 1;
        }
    }

    // Column x-offsets in pixels (font is monospace, so char-count math holds).
    const app::DisasmPalette& pal = app::disasmPalette(s);
    const ImU32 colText = ImGui::GetColorU32(ImGuiCol_Text);
    const ImU32 colDim  = ImGui::GetColorU32(ImGuiCol_TextDisabled);
    const float charW   = ImGui::CalcTextSize("0").x;
    const float bytesX  = (float)(labelW + 2) * charW;
    const float textX   = bytesX + 27.f * charW;

    char line[288];
    for (int i = 0; i < rows; ++i)
    {
        const Row& d = view[(size_t)i];

        ImGui::PushID(i);

        if (d.len)
        {
            // Invisible Selectable handles hit-testing, selection and the
            // context menu; the colored text is drawn over it span by span.
            const ImVec2 rowPos = ImGui::GetCursorScreenPos();
            if (ImGui::Selectable("##row", d.addr == s.disasmSelAddr, 0,
                    ImVec2(rowW, 0.f)))
                s.disasmSelAddr = d.addr;

            // Double-click a branch to follow its target.
            if (d.target && ImGui::IsItemHovered() &&
                ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
            {
                pushHistory(s.disasmHistory, s.disasmAddr);
                s.disasmAddr    = d.target;
                s.disasmSelAddr = d.target;
            }

            ImDrawList* dl = ImGui::GetWindowDrawList();
            dl->AddText(rowPos, colText, d.label);
            dl->AddText(ImVec2(rowPos.x + bytesX, rowPos.y), colDim, d.bytes);

            float x = rowPos.x + textX;
            for (int t = 0; t < (int)d.nspans; ++t)
            {
                const Span& sp = d.spans[t];
                const char* b  = d.text + sp.off;
                const char* e  = b + sp.len;
                dl->AddText(ImVec2(x, rowPos.y),
                    spanColor(pal, d.kind, sp.type, colText, colDim), b, e);
                x += ImGui::CalcTextSize(b, e).x;
            }
        }
        else
        {
            snprintf(line, sizeof(line), "%-*s  ??", labelW, d.label);
            ImGui::PushStyleColor(ImGuiCol_Text,
                ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
            if (ImGui::Selectable(line, d.addr == s.disasmSelAddr, 0,
                    ImVec2(rowW, 0.f)))
                s.disasmSelAddr = d.addr;
            ImGui::PopStyleColor();
        }

        // One menu for both row kinds - it binds to whichever Selectable the
        // row drew. What a ?? row can't do is greyed out, not missing.
        if (ImGui::BeginPopupContextItem("##disasmctx"))
        {
            // Select the row the menu opened on, so the highlight matches
            // what it (and Ctrl+C) acts on. Done here rather than on the
            // right-click, since an already-open popup blocks item hover.
            s.disasmSelAddr = d.addr;

            if (ImGui::MenuItem("Follow", "Dbl-click", false, d.target != 0))
            {
                pushHistory(s.disasmHistory, s.disasmAddr);
                s.disasmAddr    = d.target;
                s.disasmSelAddr = d.target;
            }
            if (ImGui::MenuItem("Follow in Regions"))
                s.regionsFollow = true;
            // Symbols for the module this line lives in, without going hunting
            // for its row in the Modules pane.
            if (const mem::ModuleEntry* m = app::findModule(s, d.addr))
                if (ImGui::BeginMenu("Symbols"))
                {
                    symbolsContextMenu(s, *m);
                    ImGui::EndMenu();
                }
            if (ImGui::MenuItem("Go to Address", "Ctrl+G"))
            {
                s.gotoDisasmInput[0] = '\0';
                s.showGotoDisasm     = true;
            }
            if (ImGui::MenuItem("Back", "Mouse 4", false, !s.disasmHistory.empty()))
                goBack(s.disasmHistory, s.disasmAddr);

            if (ImGui::MenuItem("Copy Address", "Ctrl+C"))
            {
                char addr[24];
                snprintf(addr, sizeof(addr), "%llX", (unsigned long long)d.addr);
                ImGui::SetClipboardText(addr);
            }

            // Offset from the module base; disabled outside any module.
            const mem::ModuleEntry* rvaMod = app::findModule(s, d.addr);
            if (ImGui::MenuItem("Copy RVA", nullptr, false, rvaMod != nullptr))
            {
                char rva[24];
                snprintf(rva, sizeof(rva), "%llX",
                    (unsigned long long)(d.addr - rvaMod->base));
                ImGui::SetClipboardText(rva);
            }

            if (ImGui::MenuItem("Add to List"))
                app::addAddyAddress(s, d.addr);

            ImGui::Separator();

            if (ImGui::MenuItem("Find Signature"))
            {
                // Keep the last pattern; just clear the stale error.
                s.findSigError[0] = '\0';
                s.showFindSig     = true;
            }
            if (ImGui::MenuItem("Create Signature"))
            {
                s.sigAddress   = d.addr;
                s.showSignature = true;
                app::generateSignature(s);
            }

            ImGui::Separator();
            // Patching actions sit below the separator, harder to hit by accident.
            if (ImGui::MenuItem("Assemble", nullptr, false, d.len != 0))
            {
                s.asmAddress = d.addr;
                // Re-format without the symbol hook; the assembler can't
                // parse the "module+offset" symbols in `d.text`.
                formatPlainInstr(s, dec, d.addr, s.asmInput,
                    sizeof(s.asmInput));
                s.writeError[0] = '\0';
                s.showAssemble  = true;
            }
            if (ImGui::MenuItem("Change opcode", nullptr, false, d.len != 0))
            {
                s.opcodeAddress = d.addr;
                s.opcodeOrigLen = d.len;
                // Prefill with the current raw bytes, read fresh (d.bytes is
                // truncated at 8 for display).
                uint8_t raw[16];
                const size_t n = d.len <= sizeof(raw) ? d.len : sizeof(raw);
                int op = 0;
                if (s.proc.is_open() &&
                    mem::read_raw(s.proc, d.addr, raw, n))
                    for (size_t b = 0; b < n; ++b)
                        op += snprintf(s.opcodeInput + op,
                            sizeof(s.opcodeInput) - op,
                            b ? " %02X" : "%02X", raw[b]);
                else
                    s.opcodeInput[0] = '\0';
                s.writeError[0]    = '\0';
                s.showChangeOpcode = true;
            }
            if (ImGui::MenuItem("Replace with NOP(s)", nullptr, false, d.len != 0))
                app::nopFill(s, d.addr, d.len);

            ImGui::Separator();
            // IDA-style sync: follow Hex View's address. The snap on
            // toggle-on doesn't push history; Back is for explicit jumps only.
            if (ImGui::MenuItem("Sync with Hex View", nullptr,
                    s.syncDisasmToHex))
            {
                s.syncDisasmToHex = !s.syncDisasmToHex;
                if (s.syncDisasmToHex)
                    s.disasmAddr = s.hexAddr;
            }
            ImGui::EndPopup();
        }

        ImGui::PopID();
    }

    // --- Region scrollbar ----------------------------------------------------
    // The thumb tracks the view within the current module (falling back to the
    // region, then a 64 KB window), and dragging jumps anywhere in that range.
    // The range is frozen while dragging; dragging doesn't push Back history.
    if (!s.disasmSbDrag)
    {
        s.disasmSbBase = 0;
        s.disasmSbSize = 0;
        if (const mem::ModuleEntry* mod = app::findModule(s, s.disasmAddr))
        {
            s.disasmSbBase = mod->base;
            s.disasmSbSize = mod->size;
        }
        else
            for (const mem::Region& rg : s.memRegions)
                if (s.disasmAddr >= rg.base && s.disasmAddr < rg.base + rg.size)
                {
                    s.disasmSbBase = rg.base;
                    s.disasmSbSize = rg.size;
                    break;
                }
        if (!s.disasmSbSize)
        {
            constexpr uintptr_t half = 0x8000;
            s.disasmSbBase = s.disasmAddr > kAddrFloor + half
                ? s.disasmAddr - half : kAddrFloor;
            s.disasmSbSize = 2 * half;
        }
    }

    {
        // Track spans the rows area.
        const float  trackH = (float)rows * lineH;
        const ImVec2 tl(paneOrigin.x + paneAvail.x - sbW, paneOrigin.y);

        ImGui::SetCursorScreenPos(tl);
        ImGui::InvisibleButton("##disasmsb",
            ImVec2(sbW, trackH > 1.f ? trackH : 1.f));
        s.disasmSbDrag = ImGui::IsItemActive();

        if (s.disasmSbDrag)
        {
            float frac = (ImGui::GetMousePos().y - tl.y) / trackH;
            frac = frac < 0.f ? 0.f : (frac > 1.f ? 1.f : frac);
            s.disasmAddr = s.disasmSbBase
                + (uintptr_t)((double)frac * (double)s.disasmSbSize);
        }

        ImDrawList* dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(tl, ImVec2(tl.x + sbW, tl.y + trackH),
            ImGui::GetColorU32(ImGuiCol_ScrollbarBg));

        // Thumb sized to the visible fraction, with a floor so it stays grabbable.
        float thumbH = trackH
            * (float)((double)rows * 16.0 / (double)s.disasmSbSize);
        if (thumbH < 24.f)    thumbH = 24.f;
        if (thumbH > trackH)  thumbH = trackH;

        double tf = (double)(s.disasmAddr - s.disasmSbBase)
            / (double)s.disasmSbSize;
        tf = tf < 0.0 ? 0.0 : (tf > 1.0 ? 1.0 : tf);
        const float ty = tl.y + (float)tf * (trackH - thumbH);

        const ImU32 col = ImGui::GetColorU32(
            ImGui::IsItemActive()  ? ImGuiCol_ScrollbarGrabActive :
            ImGui::IsItemHovered() ? ImGuiCol_ScrollbarGrabHovered
                                   : ImGuiCol_ScrollbarGrab);
        dl->AddRectFilled(ImVec2(tl.x + 2.f, ty),
            ImVec2(tl.x + sbW - 2.f, ty + thumbH), col,
            ImGui::GetStyle().ScrollbarRounding);
    }
}

// --- Assemble modal ----------------------------------------------------------

void drawAssembleModal(app::AppState& s)
{
    if (!s.showAssemble) return;

    // Anchor on whichever OS window Disassembly is in; it may have been torn out,
    // so the main viewport would place the modal somewhere unrelated.
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    if (ImGuiWindow* disasmWin = ImGui::FindWindowByName("Disassembly"))
        vp = disasmWin->Viewport;

    if (!app::beginBlockingModal("Assemble", &s.showAssemble, vp, 420, 0))
        return;

    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        ImGui::IsKeyPressed(ImGuiKey_Escape, false))
        s.showAssemble = false;

    ImGui::Text("Address: %016llX", (unsigned long long)s.asmAddress);

    ImGui::Spacing();
    ImGui::TextUnformatted("Instruction (Intel syntax)");
    ImGui::SetNextItemWidth(-1);
    const bool submit = ImGui::InputText("##asminput", s.asmInput, sizeof(s.asmInput),
        ImGuiInputTextFlags_EnterReturnsTrue);

    if (s.writeError[0])
    {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.85f, 0.1f, 0.1f, 1.f), "%s", s.writeError);
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    const bool valid = s.asmInput[0] != '\0';

    ImGui::BeginDisabled(!valid);
    if (ImGui::Button("Assemble", ImVec2(120, 0)) || (submit && valid))
        app::assembleAndWrite(s);
    ImGui::EndDisabled();

    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(120, 0)))
        s.showAssemble = false;

    ImGui::End();
}

// --- Assemble NOP-pad confirmation -------------------------------------------

void drawAsmNopConfirm(app::AppState& s)
{
    if (!s.showAsmNopConfirm) return;

    // Anchor on Disassembly's OS window (see drawAssembleModal).
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    if (ImGuiWindow* disasmWin = ImGui::FindWindowByName("Disassembly"))
        vp = disasmWin->Viewport;

    // The X cancels: it aborts the write and doesn't reopen the Assemble box.
    bool open = true;
    const bool visible = app::beginBlockingModal("Confirmation##asmnop", &open,
        vp, 440, 0);
    if (!open)
        s.showAsmNopConfirm = false;
    if (!visible)
        return;

    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        ImGui::IsKeyPressed(ImGuiKey_Escape, false))
        s.showAsmNopConfirm = false;

    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + 420.f);
    ImGui::Text(
        "The generated code is %llu byte(s) long, but the selected opcode is "
        "%llu byte(s) long! Do you want to replace the incomplete opcode(s) "
        "with NOP's?",
        (unsigned long long)s.asmNopNewLen,
        (unsigned long long)s.asmNopCoverLen);
    ImGui::PopTextWrapPos();

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (ImGui::Button("Yes", ImVec2(110, 0)))
        app::commitAsmBytes(s, true);
    ImGui::SameLine();
    if (ImGui::Button("No", ImVec2(110, 0)))
        app::commitAsmBytes(s, false);

    ImGui::End();
}

// --- Change-opcode modal -----------------------------------------------------

void drawChangeOpcodeModal(app::AppState& s)
{
    if (!s.showChangeOpcode) return;

    // Anchor on Disassembly's OS window (see drawAssembleModal).
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    if (ImGuiWindow* disasmWin = ImGui::FindWindowByName("Disassembly"))
        vp = disasmWin->Viewport;

    if (!app::beginBlockingModal("Change opcode", &s.showChangeOpcode, vp, 420, 0))
        return;

    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        ImGui::IsKeyPressed(ImGuiKey_Escape, false))
        s.showChangeOpcode = false;

    ImGui::Text("Address: %016llX", (unsigned long long)s.opcodeAddress);

    ImGui::Spacing();
    ImGui::TextUnformatted("Bytes (hex)");
    ImGui::SetNextItemWidth(-1);
    const bool submit = ImGui::InputText("##opcodeinput", s.opcodeInput,
        sizeof(s.opcodeInput), ImGuiInputTextFlags_EnterReturnsTrue);

    if (s.writeError[0])
    {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.85f, 0.1f, 0.1f, 1.f), "%s", s.writeError);
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    const bool valid = s.opcodeInput[0] != '\0';

    ImGui::BeginDisabled(!valid);
    if (ImGui::Button("Write", ImVec2(120, 0)) || (submit && valid))
        app::changeOpcodeAndWrite(s);
    ImGui::EndDisabled();

    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(120, 0)))
        s.showChangeOpcode = false;

    ImGui::End();
}

// --- Create Signature modal --------------------------------------------------

void drawSignatureModal(app::AppState& s)
{
    if (!s.showSignature) return;

    // Anchor on Disassembly's OS window (see drawAssembleModal).
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    if (ImGuiWindow* disasmWin = ImGui::FindWindowByName("Disassembly"))
        vp = disasmWin->Viewport;

    if (!app::beginBlockingModal("Create Signature", &s.showSignature, vp, 480, 0))
        return;

    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        ImGui::IsKeyPressed(ImGuiKey_Escape, false))
        s.showSignature = false;

    ImGui::Text("Address: %016llX", (unsigned long long)s.sigAddress);

    ImGui::Spacing();
    ImGui::TextUnformatted("Style");
    if (ImGui::RadioButton("IDA", s.sigStyle == 0)) { s.sigStyle = 0; app::generateSignature(s); }
    ImGui::SameLine();
    if (ImGui::RadioButton("Code", s.sigStyle == 1)) { s.sigStyle = 1; app::generateSignature(s); }

    ImGui::Spacing();
    ImGui::TextUnformatted("Signature");
    ImGui::SetNextItemWidth(-1);
    // Read-only so the pattern can still be selected/copied.
    ImGui::InputText("##sigout", s.sigOutput, sizeof(s.sigOutput),
        ImGuiInputTextFlags_ReadOnly);

    if (!s.sigUnique)
        ImGui::TextColored(ImVec4(0.85f, 0.55f, 0.1f, 1.f),
            "Not unique within module (hit length cap).");

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (ImGui::Button("Copy", ImVec2(120, 0)))
        ImGui::SetClipboardText(s.sigOutput);
    ImGui::SameLine();
    if (ImGui::Button("Close", ImVec2(120, 0)))
        s.showSignature = false;

    ImGui::End();
}

// --- Find Signature modal ----------------------------------------------------

void drawFindSignatureModal(app::AppState& s)
{
    // Collect a finished scan even if the modal was closed meanwhile, so its
    // hits can't surface on reopen. Runs before the visibility check.
    if (s.findSigPending && !s.findSigScan.running())
    {
        s.findSigScan.poll(s.proc);
        s.findSigPending = false;
        if (s.showFindSig)
        {
            const auto& hits = s.findSigScan.results();
            if (hits.empty())
                snprintf(s.findSigError, sizeof(s.findSigError),
                    "Pattern not found");
            else
            {
                // Even a lone hit is listed instead of jumped to: a match can
                // land in the wrong module, and the list is still there on
                // reopen, saving a second scan of the whole address space.
                // Regions are walked in address order, so the hits come sorted.
                s.findSigTotal = s.findSigScan.totalFound();
                s.findSigHits.clear();
                s.findSigHits.reserve(hits.size());
                for (const auto& h : hits)
                    s.findSigHits.push_back(h.address);
                s.findSigSel = 0;
            }
        }
        s.findSigScan.reset(); // one-shot session
    }

    if (!s.showFindSig) return;

    // Anchor on Disassembly's OS window (see drawAssembleModal).
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    if (ImGuiWindow* disasmWin = ImGui::FindWindowByName("Disassembly"))
        vp = disasmWin->Viewport;

    if (!app::beginBlockingModal("Find Signature", &s.showFindSig, vp, 480, 0))
        return;

    // Reopened with a hit list: bring the last pick back into view.
    const bool appearing = ImGui::IsWindowAppearing();

    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        ImGui::IsKeyPressed(ImGuiKey_Escape, false))
        s.showFindSig = false;

    ImGui::TextUnformatted("Signature");
    ImGui::SetNextItemWidth(-1);
    bool doFind = ImGui::InputText("##findsigin", s.findSigInput,
        sizeof(s.findSigInput), ImGuiInputTextFlags_EnterReturnsTrue);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Byte pattern, e.g.\nE8 ? ? ? ? 48 83 3D 0C B0 20 00 00\n"
                          "? or ?? = wildcard byte, A? / ?B = nibble wildcard");

    if (s.findSigPending)
        ImGui::TextUnformatted("Searching...");
    else if (s.findSigError[0])
        ImGui::TextColored(ImVec4(1.f, 0.35f, 0.35f, 1.f), "%s", s.findSigError);

    // The jump leaves the hit list alone, so reopening the modal offers the
    // other matches.
    const auto goToHit = [&s](uintptr_t hit) {
        pushHistory(s.disasmHistory, s.disasmAddr);
        s.disasmAddr    = hit;
        s.disasmSelAddr = hit;
        s.showFindSig   = false;
    };

    if (!s.findSigHits.empty())
    {
        ImGui::Spacing();
        if (s.findSigTotal > s.findSigHits.size())
            ImGui::Text("%zu matches (showing the first %zu)",
                s.findSigTotal, s.findSigHits.size());
        else
            ImGui::Text("%zu match%s", s.findSigTotal,
                s.findSigTotal == 1 ? "" : "es");

        const ImGuiTableFlags flags =
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit;

        if (ImGui::BeginTable("##findsighits", 2, flags, ImVec2(0, 200)))
        {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Address",  ImGuiTableColumnFlags_WidthFixed, 150);
            ImGui::TableSetupColumn("Location", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin((int)s.findSigHits.size());
            // SetScrollHereY only works on a submitted row, so keep that one.
            if (appearing)
                clipper.IncludeItemByIndex(s.findSigSel);
            while (clipper.Step())
            {
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i)
                {
                    const uintptr_t hit = s.findSigHits[i];
                    char label[64];
                    app::formatAddrLabel(s, hit, label, sizeof(label));

                    ImGui::TableNextRow();
                    if (appearing && i == s.findSigSel)
                        ImGui::SetScrollHereY(0.5f);

                    ImGui::TableSetColumnIndex(0);
                    char row[40];
                    snprintf(row, sizeof(row), "%llX##hit%d",
                        (unsigned long long)hit, i);
                    if (ImGui::Selectable(row, s.findSigSel == i,
                            ImGuiSelectableFlags_SpanAllColumns))
                        s.findSigSel = i;
                    if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0))
                        goToHit(hit);

                    // No str_id: the popup hangs off the row's Selectable id.
                    if (ImGui::BeginPopupContextItem())
                    {
                        if (ImGui::MenuItem("Copy Address"))
                        {
                            char copyBuf[24];
                            snprintf(copyBuf, sizeof(copyBuf), "%llX",
                                (unsigned long long)hit);
                            ImGui::SetClipboardText(copyBuf);
                        }
                        // Outside a module the label is the address again.
                        if (ImGui::MenuItem("Copy Location", nullptr, false,
                                app::findModule(s, hit) != nullptr))
                            ImGui::SetClipboardText(label);
                        // Type 7 is Pattern: the entry then shows the matched
                        // bytes, not an int32 read off code.
                        if (ImGui::MenuItem("Add to List"))
                            app::addAddyAddress(s, hit, 7, (int)s.findSigLen);
                        ImGui::EndPopup();
                    }

                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(label);
                }
            }
            ImGui::EndTable();
        }
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::BeginDisabled(s.findSigPending || s.findSigScan.running());
    doFind |= ImGui::Button("Find", ImVec2(120, 0));
    ImGui::EndDisabled();
    if (!s.findSigHits.empty())
    {
        ImGui::SameLine();
        if (ImGui::Button("Go", ImVec2(120, 0)))
            goToHit(s.findSigHits[s.findSigSel]);
    }
    ImGui::SameLine();
    if (ImGui::Button("Close", ImVec2(120, 0)))
        s.showFindSig = false;

    // firstScan() quietly does nothing while a worker is still up, which would
    // leave the modal searching forever.
    if (doFind && !s.findSigPending && !s.findSigScan.running())
    {
        s.findSigError[0] = '\0';

        uint8_t needle[2048];
        uint8_t mask[2048];
        const size_t n = app::parseAob(s.findSigInput, needle, mask,
            sizeof(needle));
        if (n == 0)
            snprintf(s.findSigError, sizeof(s.findSigError), "Invalid pattern");
        else if (s.proc.is_open())
        {
            // Whole-address-space search on its own session. Both filters are
            // DontCare so the writable-only default doesn't skip code pages.
            s.findSigHits.clear();
            s.findSigTotal = 0;
            s.findSigSel   = -1;
            s.findSigLen   = n; // the width an "Add to List" entry reads
            s.findSigScan.firstScan(s.proc, mem::ScanType::Exact,
                mem::ValueType::ArrayOfBytes, needle, n,
                mem::TriState::DontCare, mem::TriState::DontCare,
                true, false, mask);
            s.findSigPending = true;
        }
    }

    // Every way out of the modal lands here. Closed mid-scan, nobody wants the
    // result, so stop the worker rather than let it walk the rest of the
    // address space; the next firstScan() drops whatever it staged.
    if (!s.showFindSig && s.findSigPending)
    {
        s.findSigScan.cancel();
        s.findSigPending = false;
    }

    ImGui::End();
}

} // namespace ui
