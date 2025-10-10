#define _CRT_SECURE_NO_WARNINGS
#include "SCP.h"

#include <psapi.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <cstdarg>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "psapi.lib")

namespace {

#if SCP_ENABLE_LOGS
void DbgPrint(const char* level, const char* fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);

    std::fprintf(stderr, "[%s] %s\n", level, buf);

    std::string line = "["; line += level; line += "] "; line += buf; line += "\n";
    ::OutputDebugStringA(line.c_str());
}
#define LOGI(...) DbgPrint("INFO", __VA_ARGS__)
#define LOGW(...) DbgPrint("WARN", __VA_ARGS__)
#define LOGE(...) DbgPrint("ERR",  __VA_ARGS__)
#else
#define LOGI(...) do{}while(0)
#define LOGW(...) do{}while(0)
#define LOGE(...) do{}while(0)
#endif

bool IsExecProtect(DWORD prot) {
    const DWORD m = prot & 0xFF;
    return m == PAGE_EXECUTE
        || m == PAGE_EXECUTE_READ
        || m == PAGE_EXECUTE_READWRITE
        || m == PAGE_EXECUTE_WRITECOPY;
}

const char* ProtStr(DWORD p) {
    switch (p & 0xFF) {
        case PAGE_NOACCESS: return "NOACCESS";
        case PAGE_READONLY: return "R";
        case PAGE_READWRITE: return "RW";
        case PAGE_WRITECOPY: return "RW-COPY";
        case PAGE_EXECUTE: return "X";
        case PAGE_EXECUTE_READ: return "XR";
        case PAGE_EXECUTE_READWRITE: return "XRW";
        case PAGE_EXECUTE_WRITECOPY: return "XRW-COPY";
        default: return "UNKNOWN";
    }
}

const char* StateStr(DWORD s) {
    if (s == MEM_COMMIT) return "COMMIT";
    if (s == MEM_RESERVE) return "RESERVE";
    if (s == MEM_FREE) return "FREE";
    return "UNKNOWN";
}

const char* TypeStr(DWORD t) {
    if (t == MEM_IMAGE) return "IMAGE";
    if (t == MEM_MAPPED) return "MAPPED";
    if (t == MEM_PRIVATE) return "PRIVATE";
    return "UNKNOWN";
}

void HexDump(const void* p, size_t n) {
#if SCP_ENABLE_LOGS
    auto* b = static_cast<const unsigned char*>(p);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < n; ++i) {
        if (i % 16 == 0) oss << "    ";
        oss << std::setw(2) << unsigned(b[i]) << ((i + 1) % 16 ? ' ' : '\n');
    }
    if (n % 16) oss << "\n";
    std::string out = oss.str();
    ::OutputDebugStringA(out.c_str());
    std::fwrite(out.data(), 1, out.size(), stderr);
#else
    (void)p; (void)n;
#endif
}

} // namespace

BYTE* ScpcfgFindDispatchNoES(HMODULE hNtdll) {
    if (!hNtdll) return nullptr;

    MODULEINFO mi{};
    if (!::GetModuleInformation(::GetCurrentProcess(), hNtdll, &mi, sizeof(mi)))
        return nullptr;

    auto* base = static_cast<BYTE*>(mi.lpBaseOfDll);
    const SIZE_T size = mi.SizeOfImage;
    LOGI("ntdll base=%p size=0x%Ix", base, size);

    // Observed layout: SCPCFG lives just past the image. dispatch_no_es at +0x40.
    BYTE* cand = base + size + 0x40;
    LOGI("SCPCFG candidate dispatch_no_es=%p", cand);

    MEMORY_BASIC_INFORMATION mbi{};
    if (!::VirtualQuery(cand, &mbi, sizeof(mbi))) {
        LOGE("VirtualQuery(%p) failed, GLE=%lu", cand, ::GetLastError());
        return nullptr;
    }

    LOGI("Region: AllocationBase=%p Base=%p Size=0x%Ix State=%s Protect=%s Type=%s",
         mbi.AllocationBase, mbi.BaseAddress, (SIZE_T)mbi.RegionSize,
         StateStr(mbi.State), ProtStr(mbi.Protect), TypeStr(mbi.Type));

    if (static_cast<BYTE*>(mbi.AllocationBase) != base) {
        LOGW("AllocationBase mismatch. Not in ntdll allocation.");
        return nullptr;
    }
    if (!IsExecProtect(mbi.Protect)) {
        LOGW("Protect is not executable.");
        return nullptr;
    }

    // first bytes are JMP RAX = 48 FF E0
    __try {
        LOGI("First 32 bytes at candidate:");
        HexDump(cand, 32);
        if (cand[0] == 0x48 && cand[1] == 0xFF && cand[2] == 0xE0) {
            LOGI("Signature OK: starts with JMP RAX (48 FF E0)");
            return cand;
        } else {
            LOGW("Signature mismatch. Expected 48 FF E0.");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LOGE("SEH: access fault when reading candidate bytes.");
        return nullptr;
    }
    return nullptr;
}

void* ScpcfgBuildThunkStrict(HMODULE hNtdll, void* target) {
    if (!hNtdll || !target) {
        LOGE("Invalid args: hNtdll=%p target=%p", hNtdll, target);
        return nullptr;
    }

    BYTE* dispatch_no_es = ScpcfgFindDispatchNoES(hNtdll);
    if (!dispatch_no_es) {
        LOGE("SCPCFG dispatch_no_es not found or invalid.");
        return nullptr;
    }

    BYTE* page = static_cast<BYTE*>(
        ::VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!page) {
        LOGE("VirtualAlloc failed, GLE=%lu", ::GetLastError());
        return nullptr;
    }
    LOGI("Allocated RW page=%p", page);

    BYTE* sc = page;
    // mov rax, imm64
    sc[0] = 0x48; sc[1] = 0xB8;
    std::memcpy(&sc[2], &target, sizeof(target));

    // jmp [rip+0]
    sc[10] = 0xFF; sc[11] = 0x25;
    *reinterpret_cast<INT32*>(&sc[12]) = 0; // rel32 to next qword

    // dq dispatch_no_es
    std::memcpy(&sc[16], &dispatch_no_es, sizeof(dispatch_no_es));

    const SIZE_T sz = 24;
    LOGI("Thunk bytes (24):");
    HexDump(sc, sz);

    ::FlushInstructionCache(::GetCurrentProcess(), sc, sz);

    DWORD oldProt{};
    if (!::VirtualProtect(page, 0x1000, PAGE_EXECUTE_READ, &oldProt)) {
        LOGE("VirtualProtect -> RX failed, GLE=%lu", ::GetLastError());
        ::VirtualFree(page, 0, MEM_RELEASE);
        return nullptr;
    }
    LOGI("Page set to RX. OldProtect=%s", ProtStr(oldProt));

    return page;
}

void ScpcfgFreeThunk(void* thunk) {
    if (thunk) {
        LOGI("Free thunk=%p", thunk);
        ::VirtualFree(thunk, 0, MEM_RELEASE);
    }
}