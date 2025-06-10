#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <iostream>

class RemoteCall {
    HANDLE hProcess = NULL;
    DWORD pid = 0;
    bool is64bit = false;

    bool DetectProcessArch() {
        BOOL wow64 = FALSE;
        if (!IsWow64Process(hProcess, &wow64)) return false;
        // If current process is 64bit but target is WOW64 -> target is x86
        // If wow64 == FALSE and OS is 64bit, target is x64
        SYSTEM_INFO si = {};
        GetNativeSystemInfo(&si);
        if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
            is64bit = !wow64;
        }
        else {
            is64bit = false; // OS is 32bit, so target must be x86
        }
        return true;
    }

    static bool ParseSignature(const std::string& pattern, std::vector<BYTE>& bytes, std::string& mask) {
        bytes.clear();
        mask.clear();

        size_t len = pattern.length();
        for (size_t i = 0; i < len;) {
            if (pattern[i] == ' ') {
                ++i;
                continue;
            }
            if (pattern[i] == '?') {
                bytes.push_back(0);
                mask += '?';
                if (i + 1 < len && pattern[i + 1] == '?') i += 2; else i++;
            }
            else {
                if (i + 1 >= len) return false;
                std::string byteStr = pattern.substr(i, 2);
                BYTE b = (BYTE)strtol(byteStr.c_str(), nullptr, 16);
                bytes.push_back(b);
                mask += 'x';
                i += 2;
            }
        }
        return true;
    }

    static uint8_t* FindPattern(uint8_t* data, size_t dataSize, const std::vector<BYTE>& pattern, const std::string& mask) {
        size_t patLen = pattern.size();
        for (size_t i = 0; i <= dataSize - patLen; i++) {
            bool found = true;
            for (size_t j = 0; j < patLen; j++) {
                if (mask[j] == 'x' && data[i + j] != pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return data + i;
        }
        return nullptr;
    }

public:
    RemoteCall() = default;
    bool ReadMemory(uint64_t address, void* buffer, size_t size) const;
    bool WriteMemory(uint64_t address, const void* buffer, size_t size) const;
    bool Is64Bit() const { return is64bit; }
    explicit RemoteCall(const std::string& windowTitle) {
        HWND hwnd = FindWindowA(NULL, windowTitle.c_str());
        if (!hwnd) return;
        GetWindowThreadProcessId(hwnd, &pid);
        if (!pid) return;
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (hProcess) DetectProcessArch();
    }

    explicit RemoteCall(DWORD processId) : pid(processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (hProcess) DetectProcessArch();
    }

    ~RemoteCall() {
        if (hProcess) CloseHandle(hProcess);
    }

    bool IsValid() const { return hProcess != NULL; }
    HANDLE GetProcessHandle() const { return hProcess; }

    uint64_t AllocString(const char* str) {
        size_t len = strlen(str) + 1;
        uint64_t remoteMem = (uint64_t)VirtualAllocEx(GetProcessHandle(), nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteMem) return 0;
        if (!WriteProcessMemory(GetProcessHandle(), (LPVOID)remoteMem, str, len, nullptr)) {
            VirtualFreeEx(GetProcessHandle(), (LPVOID)remoteMem, 0, MEM_RELEASE);
            return 0;
        }
        return remoteMem;
    }


    uint64_t GetModuleBase(const wchar_t* moduleName) const {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot == INVALID_HANDLE_VALUE) return 0;

        MODULEENTRY32W modEntry{};
        modEntry.dwSize = sizeof(modEntry);
        uint64_t base = 0;

        if (Module32FirstW(snapshot, &modEntry)) {
            do {
                if (_wcsicmp(modEntry.szModule, moduleName) == 0) {
                    base = (uint64_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32NextW(snapshot, &modEntry));
        }
        CloseHandle(snapshot);
        return base;
    }

    uint64_t GetExportAddress(const wchar_t* moduleName, const char* exportName) const {
        if (!IsValid()) {
            printf("[!] Process handle invalid\n");
            return 0;
        }

        uint64_t base = GetModuleBase(moduleName);
        if (!base) {
            printf("[!] Module base for %ls not found\n", moduleName);
            return 0;
        }
        printf("[+] Module %ls base found at 0x%llx\n", moduleName, base);

        IMAGE_DOS_HEADER dosHeader{};
        if (!ReadMemory(base, &dosHeader, sizeof(dosHeader))) {
            printf("[!] Failed to read DOS header at 0x%llx\n", base);
            return 0;
        }
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            printf("[!] DOS header signature invalid: 0x%x\n", dosHeader.e_magic);
            return 0;
        }

        if (is64bit) {
            IMAGE_NT_HEADERS64 ntHeaders64{};
            uint64_t ntHeaderAddr = base + dosHeader.e_lfanew;
            if (!ReadMemory(ntHeaderAddr, &ntHeaders64, sizeof(ntHeaders64))) {
                printf("[!] Failed to read NT headers (64) at 0x%llx\n", ntHeaderAddr);
                return 0;
            }
            if (ntHeaders64.Signature != IMAGE_NT_SIGNATURE) {
                printf("[!] NT headers signature invalid: 0x%x\n", ntHeaders64.Signature);
                return 0;
            }
            auto& exportData = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (!exportData.VirtualAddress || !exportData.Size) {
                printf("[!] No export directory found (VirtualAddress=0x%x, Size=0x%x)\n",
                    exportData.VirtualAddress, exportData.Size);
                return 0;
            }

            uint64_t exportDirAddr = base + exportData.VirtualAddress;
            IMAGE_EXPORT_DIRECTORY exportDir{};
            if (!ReadMemory(exportDirAddr, &exportDir, sizeof(exportDir))) {
                printf("[!] Failed to read export directory at 0x%llx\n", exportDirAddr);
                return 0;
            }

            std::vector<DWORD> nameRVAs(exportDir.NumberOfNames);
            if (!ReadMemory(base + exportDir.AddressOfNames, nameRVAs.data(), nameRVAs.size() * sizeof(DWORD))) {
                printf("[!] Failed to read AddressOfNames at 0x%llx\n", base + exportDir.AddressOfNames);
                return 0;
            }

            std::vector<WORD> ordinals(exportDir.NumberOfNames);
            if (!ReadMemory(base + exportDir.AddressOfNameOrdinals, ordinals.data(), ordinals.size() * sizeof(WORD))) {
                printf("[!] Failed to read AddressOfNameOrdinals at 0x%llx\n", base + exportDir.AddressOfNameOrdinals);
                return 0;
            }

            for (size_t i = 0; i < nameRVAs.size(); i++) {
                char nameBuffer[64] = {};
                uint64_t nameAddr = base + nameRVAs[i];
                if (!ReadMemory(nameAddr, nameBuffer, sizeof(nameBuffer))) {
                    printf("[!] Failed to read function name at 0x%llx\n", nameAddr);
                    continue;
                }

                if (_stricmp(nameBuffer, exportName) == 0) {
                    WORD ordinal = ordinals[i];
                    uint64_t funcAddrRVAAddr = base + exportDir.AddressOfFunctions + ordinal * sizeof(DWORD);
                    DWORD funcRVA = 0;
                    if (!ReadMemory(funcAddrRVAAddr, &funcRVA, sizeof(funcRVA))) {
                        printf("[!] Failed to read function RVA at 0x%llx\n", funcAddrRVAAddr);
                        return 0;
                    }

                    uint64_t funcAddr = base + funcRVA;
                    printf("[+] Found export '%s' at 0x%llx\n", exportName, funcAddr);
                    return funcAddr;
                }
            }
        }
        else { // x86 32bit process
            IMAGE_NT_HEADERS32 ntHeaders32{};
            uint64_t ntHeaderAddr = base + dosHeader.e_lfanew;
            if (!ReadMemory(ntHeaderAddr, &ntHeaders32, sizeof(ntHeaders32))) {
                printf("[!] Failed to read NT headers (32) at 0x%llx\n", ntHeaderAddr);
                return 0;
            }
            if (ntHeaders32.Signature != IMAGE_NT_SIGNATURE) {
                printf("[!] NT headers signature invalid: 0x%x\n", ntHeaders32.Signature);
                return 0;
            }
            auto& exportData = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (!exportData.VirtualAddress || !exportData.Size) {
                printf("[!] No export directory found (VirtualAddress=0x%x, Size=0x%x)\n",
                    exportData.VirtualAddress, exportData.Size);
                return 0;
            }

            uint64_t exportDirAddr = base + exportData.VirtualAddress;
            IMAGE_EXPORT_DIRECTORY exportDir{};
            if (!ReadMemory(exportDirAddr, &exportDir, sizeof(exportDir))) {
                printf("[!] Failed to read export directory at 0x%llx\n", exportDirAddr);
                return 0;
            }

            std::vector<DWORD> nameRVAs(exportDir.NumberOfNames);
            if (!ReadMemory(base + exportDir.AddressOfNames, nameRVAs.data(), nameRVAs.size() * sizeof(DWORD))) {
                printf("[!] Failed to read AddressOfNames at 0x%llx\n", base + exportDir.AddressOfNames);
                return 0;
            }

            std::vector<WORD> ordinals(exportDir.NumberOfNames);
            if (!ReadMemory(base + exportDir.AddressOfNameOrdinals, ordinals.data(), ordinals.size() * sizeof(WORD))) {
                printf("[!] Failed to read AddressOfNameOrdinals at 0x%llx\n", base + exportDir.AddressOfNameOrdinals);
                return 0;
            }

            for (size_t i = 0; i < nameRVAs.size(); i++) {
                char nameBuffer[64] = {};
                uint64_t nameAddr = base + nameRVAs[i];
                if (!ReadMemory(nameAddr, nameBuffer, sizeof(nameBuffer))) {
                    printf("[!] Failed to read function name at 0x%llx\n", nameAddr);
                    continue;
                }

                if (_stricmp(nameBuffer, exportName) == 0) {
                    WORD ordinal = ordinals[i];
                    uint64_t funcAddrRVAAddr = base + exportDir.AddressOfFunctions + ordinal * sizeof(DWORD);
                    DWORD funcRVA = 0;
                    if (!ReadMemory(funcAddrRVAAddr, &funcRVA, sizeof(funcRVA))) {
                        printf("[!] Failed to read function RVA at 0x%llx\n", funcAddrRVAAddr);
                        return 0;
                    }

                    uint64_t funcAddr = base + funcRVA;
                    printf("[+] Found export '%s' at 0x%llx\n", exportName, funcAddr);
                    return funcAddr;
                }
            }
        }

        printf("[!] Export '%s' not found in module %ls\n", exportName, moduleName);
        return 0;
    }

    std::vector<BYTE> BuildShellcode(
        uint64_t funcAddr,
        const std::vector<uint64_t>& intArgs,
        const std::vector<double>& floatArgs,
        uint64_t retAddr)
    {
        std::vector<BYTE> shell;

        // Calculate how many args to push on stack (args after the 4th)
        size_t stackArgCount = intArgs.size() > 4 ? intArgs.size() - 4 : 0;

        // Shadow space (32 bytes) + space for pushed stack args + possible alignment padding
        size_t stackSpace = 32 + (stackArgCount * 8);

        // Align stackSpace to 16 bytes
        if (stackSpace % 16 != 0) stackSpace += 8;

        // sub rsp, stackSpace
        shell.insert(shell.end(), { 0x48, 0x81, 0xEC });
        shell.insert(shell.end(), (BYTE*)&stackSpace, (BYTE*)&stackSpace + 4);

        // Push stack args in reverse order (right to left)
        for (size_t i = 0; i < stackArgCount; i++) {
            uint64_t val = intArgs[intArgs.size() - 1 - i];
            // mov rax, val
            shell.push_back(0x48);
            shell.push_back(0xB8);
            shell.insert(shell.end(), (BYTE*)&val, (BYTE*)&val + 8);
            // mov [rsp + offset], rax
            // offset = 32 + i*8 (shadow space + i-th arg)
            uint32_t offset = 32 + static_cast<uint32_t>(i * 8);
            shell.insert(shell.end(), { 0x48, 0x89, 0x84, 0x24 });
            shell.insert(shell.end(), (BYTE*)&offset, (BYTE*)&offset + 4);
        }

        // Move first 4 int args into RCX, RDX, R8, R9 or zero if missing
        static const BYTE mov_rcx[] = { 0x48, 0xB9 };
        static const BYTE mov_rdx[] = { 0x48, 0xBA };
        static const BYTE mov_r8[] = { 0x49, 0xB8 };
        static const BYTE mov_r9[] = { 0x49, 0xB9 };
        uint64_t zero64 = 0;

        auto addIntArg = [&](int idx, const BYTE* movInst) {
            shell.insert(shell.end(), movInst, movInst + 2);
            if ((size_t)idx < intArgs.size())
                shell.insert(shell.end(), (BYTE*)&intArgs[idx], (BYTE*)&intArgs[idx] + 8);
            else
                shell.insert(shell.end(), (BYTE*)&zero64, (BYTE*)&zero64 + 8);
            };

        addIntArg(0, mov_rcx);
        addIntArg(1, mov_rdx);
        addIntArg(2, mov_r8);
        addIntArg(3, mov_r9);

        // Move floating-point args into XMM0, XMM1, XMM2, XMM3 (max 4)
        for (size_t i = 0; i < 4; i++) {
            if (i < floatArgs.size()) {
                double val = floatArgs[i];
                uint64_t valBits = *(uint64_t*)&val;

                // mov rax, imm64
                shell.push_back(0x48);
                shell.push_back(0xB8);
                shell.insert(shell.end(), (BYTE*)&valBits, (BYTE*)&valBits + 8);

                // movq xmmN, rax
                shell.push_back(0x66);
                shell.push_back(0x48);
                shell.push_back(0x0F);
                shell.push_back(0x6E);
                shell.push_back((BYTE)(0xC0 + i));
            }
        }

        // mov rax, funcAddr
        shell.insert(shell.end(), { 0x48, 0xB8 });
        shell.insert(shell.end(), (BYTE*)&funcAddr, (BYTE*)&funcAddr + 8);

        // call rax
        shell.insert(shell.end(), { 0xFF, 0xD0 });

        // mov [retAddr], rax            ; store HRESULT return
        shell.insert(shell.end(), { 0x48, 0xA3 });
        shell.insert(shell.end(), (BYTE*)&retAddr, (BYTE*)&retAddr + 8);

        // mov rax, [rcx]               ; load *ppDevice
        shell.insert(shell.end(), { 0x48, 0x8B, 0x01 });

        // mov [retAddr+8], rax         ; store device pointer
        uint64_t retAddrPlus8 = retAddr + 8;
        shell.insert(shell.end(), { 0x48, 0xA3 });
        shell.insert(shell.end(), (BYTE*)&retAddrPlus8, (BYTE*)&retAddrPlus8 + 8);

        // mov rax, [rdx]               ; load *ppImmediateContext
        shell.insert(shell.end(), { 0x48, 0x8B, 0x12 });

        // mov [retAddr+16], rax        ; store context pointer
        uint64_t retAddrPlus16 = retAddr + 16;
        shell.insert(shell.end(), { 0x48, 0xA3 });
        shell.insert(shell.end(), (BYTE*)&retAddrPlus16, (BYTE*)&retAddrPlus16 + 8);

        // movsd [retAddr+24], xmm0     ; store float/double return
        uint64_t retAddrPlus24 = retAddr + 24;
        shell.insert(shell.end(), { 0x48, 0xB8 });
        shell.insert(shell.end(), (BYTE*)&retAddrPlus24, (BYTE*)&retAddrPlus24 + 8);
        shell.insert(shell.end(), { 0xF2, 0x0F, 0x11, 0x00 });

        // add rsp, stackSpace          ; restore stack
        shell.insert(shell.end(), { 0x48, 0x81, 0xC4 });
        shell.insert(shell.end(), (BYTE*)&stackSpace, (BYTE*)&stackSpace + 4);

        // ret
        shell.push_back(0xC3);

        return shell;
    }

    std::vector<BYTE> BuildD3D11InitShellcode(uint64_t coInitAddr, uint64_t createDeviceAddr, const std::vector<uint64_t>& intArgs, uint64_t retAddr) {
        std::vector<BYTE> shell;

        size_t stackSpace = 0x40; // generous alignment for our sins

        // sub rsp, stackSpace
        shell.insert(shell.end(), { 0x48, 0x81, 0xEC });
        shell.insert(shell.end(), (BYTE*)&stackSpace, (BYTE*)&stackSpace + 4);

        // === Call CoInitialize(NULL) ===
        // xor rcx, rcx
        shell.insert(shell.end(), { 0x48, 0x31, 0xC9 });

        // mov rax, coInitAddr
        shell.insert(shell.end(), { 0x48, 0xB8 });
        shell.insert(shell.end(), (BYTE*)&coInitAddr, (BYTE*)&coInitAddr + 8);

        // call rax
        shell.insert(shell.end(), { 0xFF, 0xD0 });

        // === Setup RCX, RDX, R8, R9 ===
        static const BYTE regs[][2] = {
            {0x48, 0xB9}, // rcx
            {0x48, 0xBA}, // rdx
            {0x49, 0xB8}, // r8
            {0x49, 0xB9}  // r9
        };
        for (size_t i = 0; i < 4; i++) {
            shell.insert(shell.end(), regs[i], regs[i] + 2);
            uint64_t val = i < intArgs.size() ? intArgs[i] : 0;
            shell.insert(shell.end(), (BYTE*)&val, (BYTE*)&val + 8);
        }

        // Push stack args (5+)
        for (size_t i = intArgs.size(); i-- > 4;) {
            uint64_t val = intArgs[i];
            // mov rax, val
            shell.insert(shell.end(), { 0x48, 0xB8 });
            shell.insert(shell.end(), (BYTE*)&val, (BYTE*)&val + 8);
            // push rax
            shell.push_back(0x50);
        }

        // mov rax, createDeviceAddr
        shell.insert(shell.end(), { 0x48, 0xB8 });
        shell.insert(shell.end(), (BYTE*)&createDeviceAddr, (BYTE*)&createDeviceAddr + 8);

        // call rax
        shell.insert(shell.end(), { 0xFF, 0xD0 });

        // Store HRESULT
        shell.insert(shell.end(), { 0x48, 0xA3 });
        shell.insert(shell.end(), (BYTE*)&retAddr, (BYTE*)&retAddr + 8);

        // mov rax, [rcx] ; device
        shell.insert(shell.end(), { 0x48, 0x8B, 0x01 });
        uint64_t devOut = retAddr + 8;
        shell.insert(shell.end(), { 0x48, 0xA3 });
        shell.insert(shell.end(), (BYTE*)&devOut, (BYTE*)&devOut + 8);

        // mov rax, [rdx] ; context
        shell.insert(shell.end(), { 0x48, 0x8B, 0x12 });
        uint64_t ctxOut = retAddr + 16;
        shell.insert(shell.end(), { 0x48, 0xA3 });
        shell.insert(shell.end(), (BYTE*)&ctxOut, (BYTE*)&ctxOut + 8);

        // add rsp, stackSpace
        shell.insert(shell.end(), { 0x48, 0x81, 0xC4 });
        shell.insert(shell.end(), (BYTE*)&stackSpace, (BYTE*)&stackSpace + 4);

        // ret
        shell.push_back(0xC3);

        return shell;
    }

    std::vector<BYTE> BuildGetDeviceShellcode(uint64_t swapPtr, uint64_t vfuncAddr, uint64_t iidPtr, uint64_t outPtr) {
        std::vector<BYTE> shell;

        // sub rsp, 0x28 (shadow space)
        shell.insert(shell.end(), { 0x48, 0x83, 0xEC, 0x28 });

        // mov rcx, swapPtr
        shell.push_back(0x48); shell.push_back(0xB9);
        shell.insert(shell.end(), (BYTE*)&swapPtr, (BYTE*)&swapPtr + 8);

        // mov rdx, iidPtr
        shell.push_back(0x48); shell.push_back(0xBA);
        shell.insert(shell.end(), (BYTE*)&iidPtr, (BYTE*)&iidPtr + 8);

        // mov r8, outPtr
        shell.push_back(0x49); shell.push_back(0xB8);
        shell.insert(shell.end(), (BYTE*)&outPtr, (BYTE*)&outPtr + 8);

        // mov rax, [rcx]         ; load vtable
        shell.insert(shell.end(), { 0x48, 0x8B, 0x01 });

        // mov rax, [rax + 0x40]  ; load GetDevice fn ptr
        shell.insert(shell.end(), { 0x48, 0x8B, 0x40, 0x40 });

        // call rax
        shell.insert(shell.end(), { 0xFF, 0xD0 });

        // add rsp, 0x28
        shell.insert(shell.end(), { 0x48, 0x83, 0xC4, 0x28 });

        // ret
        shell.push_back(0xC3);

        return shell;
    }


    template<typename... Args>
    uint64_t Call(uint64_t funcAddr, Args... args) {
        if (!IsValid()) return 0;

        std::vector<uint64_t> intArgs;
        std::vector<double> floatArgs;
        std::vector<void*> remoteStrings;

        auto processArg = [&](auto arg) {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, const char*>) {
                size_t len = strlen(arg) + 1;
                void* remoteStr = VirtualAllocEx(hProcess, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!remoteStr) return false;
                if (!WriteMemory((uint64_t)remoteStr, arg, len)) {
                    VirtualFreeEx(hProcess, remoteStr, 0, MEM_RELEASE);
                    return false;
                }
                intArgs.push_back((uint64_t)remoteStr);
                remoteStrings.push_back(remoteStr);
                return true;
            }
            else if constexpr (std::is_integral_v<T>) {
                intArgs.push_back((uint64_t)arg);
                return true;
            }
            else if constexpr (std::is_same_v<T, float>) {
                floatArgs.push_back(static_cast<double>(arg));
                return true;
            }
            else if constexpr (std::is_same_v<T, double>) {
                floatArgs.push_back(arg);
                return true;
            }
            else {
                return false;
            }
            };

        bool ok = (processArg(args) && ...);
        if (!ok) {
            for (auto ptr : remoteStrings)
                VirtualFreeEx(hProcess, ptr, 0, MEM_RELEASE);
            return 0;
        }

        // Allocate return buffer: 16 bytes (8 bytes for rax + 8 bytes for xmm0)
        void* remoteRetVal = VirtualAllocEx(hProcess, NULL, 16, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteRetVal) {
            for (auto ptr : remoteStrings)
                VirtualFreeEx(hProcess, ptr, 0, MEM_RELEASE);
            return 0;
        }

        auto shellcode = BuildShellcode(funcAddr, intArgs, floatArgs, (uint64_t)remoteRetVal);

        // Allocate shellcode memory remotely
        void* remoteShell = VirtualAllocEx(hProcess, NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteShell) {
            VirtualFreeEx(hProcess, remoteRetVal, 0, MEM_RELEASE);
            for (auto ptr : remoteStrings)
                VirtualFreeEx(hProcess, ptr, 0, MEM_RELEASE);
            return 0;
        }

        if (!WriteMemory((uint64_t)remoteShell, shellcode.data(), shellcode.size())) {
            VirtualFreeEx(hProcess, remoteShell, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, remoteRetVal, 0, MEM_RELEASE);
            for (auto ptr : remoteStrings)
                VirtualFreeEx(hProcess, ptr, 0, MEM_RELEASE);
            return 0;
        }

        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteShell, NULL, 0, NULL);
        if (!hThread) {
            VirtualFreeEx(hProcess, remoteShell, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, remoteRetVal, 0, MEM_RELEASE);
            for (auto ptr : remoteStrings)
                VirtualFreeEx(hProcess, ptr, 0, MEM_RELEASE);
            return 0;
        }

        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);

        // Read 16 bytes return buffer
        struct ReturnValue {
            uint64_t rax;    // integer return
            double xmm0;     // float/double return
        } retVal{};

        ReadMemory((uint64_t)remoteRetVal, &retVal, sizeof(retVal));

        VirtualFreeEx(hProcess, remoteShell, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteRetVal, 0, MEM_RELEASE);
        for (auto ptr : remoteStrings)
            VirtualFreeEx(hProcess, ptr, 0, MEM_RELEASE);

        // By default, return the integer return value (rax).
        // If you want to get float/double return, interpret retVal.xmm0 instead.
        return retVal.rax;
    }

    uint64_t AllocMemory(size_t size) {
        void* addr = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        return (uint64_t)addr;
    }


    uint64_t SignatureScan(const wchar_t* moduleName, const std::string& pattern) {
        uint64_t base = GetModuleBase(moduleName);
        if (!base) return 0;

        IMAGE_DOS_HEADER dosHeader{};
        if (!ReadMemory(base, &dosHeader, sizeof(dosHeader)) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
            return 0;

        IMAGE_NT_HEADERS64 ntHeaders{};
        if (!ReadMemory(base + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders)) || ntHeaders.Signature != IMAGE_NT_SIGNATURE)
            return 0;

        size_t imageSize = ntHeaders.OptionalHeader.SizeOfImage;
        std::vector<BYTE> buffer(imageSize);

        if (!ReadMemory(base, buffer.data(), imageSize))
            return 0;

        std::vector<BYTE> patternBytes;
        std::string mask;
        if (!ParseSignature(pattern, patternBytes, mask)) return 0;

        BYTE* data = buffer.data();
        size_t patternLength = patternBytes.size();

        for (size_t i = 0; i <= imageSize - patternLength; i++) {
            bool match = true;
            for (size_t j = 0; j < patternLength; j++) {
                if (mask[j] == 'x' && data[i + j] != patternBytes[j]) {
                    match = false;
                    break;
                }
            }
            if (match)
                return base + i;
        }

        return 0;
    }

    bool valid() const {
        return hProcess != nullptr;
    }

    uint64_t alloc(size_t size) {
        return (uint64_t)VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    bool read(uint64_t addr, void* out, size_t len) {
        SIZE_T readSize;
        return ReadProcessMemory(hProcess, (LPCVOID)addr, out, len, &readSize);
    }

    bool write(uint64_t addr, const void* in, size_t len) {
        SIZE_T written;
        return WriteProcessMemory(hProcess, (LPVOID)addr, in, len, &written);
    }

    uint64_t call_vfunc(uint64_t obj, int index) {
        uint64_t vtable = 0;
        if (!read(obj, &vtable, sizeof(vtable))) return 0;

        uint64_t fn = 0;
        if (!read(vtable + index * 8, &fn, sizeof(fn))) return 0;

        return Call(fn, obj);
    }

    std::vector<uint8_t> BuildD3D11InitShellcodeWithCoInitialize(
        uint64_t coInitializeAddr,
        uint64_t d3dCreateAddr,
        const std::vector<uint64_t>& args,
        uint64_t retBuf)
    {
        std::vector<uint8_t> code;

        // prolog: push rbp; mov rbp, rsp
        code.insert(code.end(), { 0x55, 0x48, 0x89, 0xE5 });

        // sub rsp, 0x28 (40) to reserve shadow space + align stack
        code.insert(code.end(), { 0x48, 0x83, 0xEC, 0x28 });

        // -- Call CoInitialize(NULL) --
        // xor rcx, rcx
        code.insert(code.end(), { 0x48, 0x31, 0xC9 });
        // mov rax, coInitializeAddr
        code.push_back(0x48); code.push_back(0xB8);
        for (int i = 0; i < 8; i++) code.push_back((coInitializeAddr >> (8 * i)) & 0xFF);
        // call rax
        code.insert(code.end(), { 0xFF, 0xD0 });
        // test eax, eax
        code.insert(code.end(), { 0x85, 0xC0 });
        // jns continue_call (jump if no failure)
        code.insert(code.end(), { 0x79, 0x10 }); // jump +16 bytes

        // failure path: store HRESULT to [retBuf], cleanup and return
        // mov rax, retBuf
        code.push_back(0x48); code.push_back(0xB8);
        for (int i = 0; i < 8; i++) code.push_back((retBuf >> (8 * i)) & 0xFF);
        // mov [rax], eax
        code.insert(code.end(), { 0x89, 0x00 });
        // add rsp, 0x28
        code.insert(code.end(), { 0x48, 0x83, 0xC4, 0x28 });
        // leave; ret
        code.insert(code.end(), { 0xC9, 0xC3 });

        // continue_call:
        // mov rcx, args[0]
        code.push_back(0x48); code.push_back(0xB9);
        for (int i = 0; i < 8; i++) code.push_back((args[0] >> (8 * i)) & 0xFF);
        // mov rdx, args[1]
        code.push_back(0x48); code.push_back(0xBA);
        for (int i = 0; i < 8; i++) code.push_back((args[1] >> (8 * i)) & 0xFF);
        // mov r8, args[2]
        code.push_back(0x49); code.push_back(0xB8);
        for (int i = 0; i < 8; i++) code.push_back((args[2] >> (8 * i)) & 0xFF);
        // mov r9, args[3]
        code.push_back(0x49); code.push_back(0xB9);
        for (int i = 0; i < 8; i++) code.push_back((args[3] >> (8 * i)) & 0xFF);

        // push rest of args on stack (right to left)
        for (int i = (int)args.size() - 1; i >= 4; i--) {
            // mov rax, args[i]
            code.push_back(0x48); code.push_back(0xB8);
            for (int b = 0; b < 8; b++) code.push_back((args[i] >> (8 * b)) & 0xFF);
            // push rax
            code.insert(code.end(), { 0x50 });
        }

        // mov rax, d3dCreateAddr
        code.push_back(0x48); code.push_back(0xB8);
        for (int i = 0; i < 8; i++) code.push_back((d3dCreateAddr >> (8 * i)) & 0xFF);

        // call rax
        code.insert(code.end(), { 0xFF, 0xD0 });

        // mov rdi, retBuf
        code.push_back(0x48); code.push_back(0xBF);
        for (int i = 0; i < 8; i++) code.push_back((retBuf >> (8 * i)) & 0xFF);

        // mov [rdi], eax (store HRESULT)
        code.insert(code.end(), { 0x89, 0x07 });

        // add rsp, 0x28 (clean shadow space + args)
        code.insert(code.end(), { 0x48, 0x83, 0xC4, 0x28 });

        // leave; ret
        code.insert(code.end(), { 0xC9, 0xC3 });

        return code;
    }

    uint64_t FindSwapChainInstance(uint64_t vtableAddr) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);

        MEMORY_BASIC_INFORMATION mbi{};
        uint64_t addr = (uint64_t)si.lpMinimumApplicationAddress;
        uint64_t maxAddr = (uint64_t)si.lpMaximumApplicationAddress;

        while (addr < maxAddr) {
            if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) {
                if ((mbi.State == MEM_COMMIT) &&
                    (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) &&
                    (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE))) {

                    std::vector<BYTE> buffer(mbi.RegionSize);
                    SIZE_T bytesRead;
                    if (ReadProcessMemory(hProcess, (LPCVOID)addr, buffer.data(), mbi.RegionSize, &bytesRead)) {
                        for (size_t i = 0; i < bytesRead - sizeof(uint64_t); i += sizeof(uint64_t)) {
                            uint64_t possiblePtr = *(uint64_t*)(buffer.data() + i);
                            if (possiblePtr == vtableAddr) {
                                uint64_t foundAddr = addr + i - 0; // subtract offset to start of object if needed
                                printf("[+] Found SwapChain instance candidate at 0x%llx\n", foundAddr);
                                return foundAddr;
                            }
                        }
                    }
                }
                addr += mbi.RegionSize;
            }
            else {
                addr += 0x1000; // page size fallback
            }
        }

        printf("[-] SwapChain instance not found\n");
        return 0;
    }

    bool FreeMemory(uint64_t addr) {
        return VirtualFreeEx(hProcess, (LPVOID)addr, 0, MEM_RELEASE);
    }


   


};

bool RemoteCall::ReadMemory(uint64_t address, void* buffer, size_t size) const {
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(hProcess, (LPCVOID)address, buffer, size, &bytesRead) && bytesRead == size;
}

bool RemoteCall::WriteMemory(uint64_t address, const void* buffer, size_t size) const {
    SIZE_T bytesWritten = 0;
    return WriteProcessMemory(hProcess, (LPVOID)address, buffer, size, &bytesWritten) && bytesWritten == size;
}
