// example.cpp
#include "SCP.h"

#include <iostream>
#include <memory>
#include <iomanip>
#include <string>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

using NtGetCurrentProcessorNumber_t = ULONG (NTAPI*)(void);

struct ThunkDeleter {
    void operator()(void* p) const noexcept { ScpcfgFreeThunk(p); }
};

static void PrintMbi(const MEMORY_BASIC_INFORMATION& mbi) {
    auto protStr = [](DWORD p)->const char* {
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
    };
    auto stateStr = [](DWORD s)->const char* {
        if (s == MEM_COMMIT) return "COMMIT";
        if (s == MEM_RESERVE) return "RESERVE";
        if (s == MEM_FREE) return "FREE";
        return "UNKNOWN";
    };
    auto typeStr = [](DWORD t)->const char* {
        if (t == MEM_IMAGE) return "IMAGE";
        if (t == MEM_MAPPED) return "MAPPED";
        if (t == MEM_PRIVATE) return "PRIVATE";
        return "UNKNOWN";
    };

    std::cerr << "    AllocationBase: " << mbi.AllocationBase
              << "  BaseAddress: " << mbi.BaseAddress
              << "  RegionSize: 0x" << std::hex << (size_t)mbi.RegionSize << std::dec << "\n"
              << "    State=" << stateStr(mbi.State)
              << "  Protect=" << protStr(mbi.Protect)
              << "  Type=" << typeStr(mbi.Type) << "\n";
}

static void HexDump(const void* p, size_t n) {
    auto* b = static_cast<const unsigned char*>(p);
    std::cerr << std::hex << std::setfill('0');
    for (size_t i = 0; i < n; ++i) {
        if (i % 16 == 0) std::cerr << "    ";
        std::cerr << std::setw(2) << unsigned(b[i]) << ((i + 1) % 16 ? ' ' : '\n');
    }
    if (n % 16) std::cerr << "\n";
    std::cerr << std::dec;
}

int main() {
    static_assert(sizeof(void*) == 8, "x64 only");

    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        std::cerr << "[-] GetModuleHandleW(ntdll) failed\n";
        return 1;
    }

    MODULEINFO mi{};
    ::GetModuleInformation(::GetCurrentProcess(), ntdll, &mi, sizeof(mi));
    std::cerr << "[*] ntdll base=" << mi.lpBaseOfDll
              << " size=0x" << std::hex << mi.SizeOfImage << std::dec << "\n";

    BYTE* dispatch = ScpcfgFindDispatchNoES(ntdll);
    std::cerr << "[*] dispatch_no_es=" << static_cast<void*>(dispatch) << "\n";
    if (dispatch) {
        MEMORY_BASIC_INFORMATION mbi{};
        ::VirtualQuery(dispatch, &mbi, sizeof(mbi));
        PrintMbi(mbi);
        std::cerr << "[*] First 32 bytes of dispatch_no_es:\n";
        HexDump(dispatch, 32);
    }

    auto target = reinterpret_cast<void*>(
        ::GetProcAddress(ntdll, "NtGetCurrentProcessorNumber"));
    if (!target) {
        std::cerr << "[-] Resolve NtGetCurrentProcessorNumber failed\n";
        return 1;
    }
    std::cerr << "[*] target stub=" << target << "\n";

    std::unique_ptr<void, ThunkDeleter> thunk{ ScpcfgBuildThunkStrict(ntdll, target) };
    if (!thunk) {
        std::cerr << "[-] SCPCFG dispatch not available or validation failed\n";
        return 1;
    }
    std::cerr << "[+] Thunk=" << thunk.get() << " (RX)\n";

    auto fn = reinterpret_cast<NtGetCurrentProcessorNumber_t>(thunk.get());
    ULONG cpu = fn();
    std::cout << "[+] CPU: " << cpu << " (via SCPCFG)\n";

    return 0;
}