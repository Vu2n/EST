#include "remotecall.h"
#include <iostream>
#include <thread>
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>
#include <initguid.h>
#include <d3d11.h>
#include <deque>
#include <chrono>
#include <cstdlib> 
#include <ctime>   

// RC can be altered to call game/engine functions if your smart enough, testing on assualtcube proved this as i was able to call Reload etc

uint64_t RemoteCallVFunc(RemoteCall& rc, uint64_t instance, int index,
    uint64_t arg1 = 0, uint64_t arg2 = 0,
    uint64_t arg3 = 0, uint64_t arg4 = 0,
    const std::vector<uint8_t>& stackData = {})
{
    uint64_t vtablePtr = 0;
    if (!rc.ReadMemory(instance, &vtablePtr, sizeof(vtablePtr))) {
        std::cout << "[!] Failed to read vtable pointer\n";
        return 0;
    }

    uint64_t funcPtr = 0;
    if (!rc.ReadMemory(vtablePtr + index * sizeof(uint64_t), &funcPtr, sizeof(funcPtr))) {
        std::cout << "[!] Failed to read function pointer from vtable\n";
        return 0;
    }

    return rc.Call(funcPtr, instance, arg1, arg2, arg3, arg4);
}

uint64_t RemoteCallVFunc3(RemoteCall& rc, uint64_t instance, int index,
    uint64_t arg1, uint64_t arg2, uint64_t arg3) {
    return RemoteCallVFunc(rc, instance, index, arg1, arg2, arg3);
}

uint64_t RemoteGetDevice(RemoteCall& rc, uint64_t swapChainInstance) {
    static const GUID IID_ID3D11Device = __uuidof(ID3D11Device);

    uint64_t remoteIID = rc.AllocMemory(sizeof(GUID));
    if (!remoteIID) {
        std::cerr << "[!] Failed to allocate memory for IID\n";
        return 0;
    }
    if (!rc.WriteMemory(remoteIID, &IID_ID3D11Device, sizeof(GUID))) {
        std::cerr << "[!] Failed to write IID memory\n";
        return 0;
    }

    uint64_t remoteDevicePtr = rc.AllocMemory(sizeof(uint64_t));
    if (!remoteDevicePtr) {
        std::cerr << "[!] Failed to allocate memory for device pointer\n";
        return 0;
    }
    uint64_t zero = 0;
    rc.WriteMemory(remoteDevicePtr, &zero, sizeof(zero));

    uint64_t hr = RemoteCallVFunc(rc, swapChainInstance, 7, remoteIID, remoteDevicePtr);
    if (hr != 0) {
        std::cerr << "[!] GetDevice failed with HRESULT: 0x" << std::hex << hr << "\n";
        return 0;
    }

    uint64_t devicePtr = 0;
    if (!rc.ReadMemory(remoteDevicePtr, &devicePtr, sizeof(devicePtr)) || devicePtr == 0) {
        std::cerr << "[!] Failed to read device pointer\n";
        return 0;
    }

    return devicePtr;
}

void DumpDeviceVtable(RemoteCall& rc, uint64_t devicePtr) {
    uint64_t deviceVtable = 0;
    if (!rc.ReadMemory(devicePtr, &deviceVtable, sizeof(deviceVtable))) {
        std::cerr << "Failed to read device vtable ptr\n";
        return;
    }

    std::cout << "Device vtable at: 0x" << std::hex << deviceVtable << "\n";

    constexpr int vtableEntriesCount = 20;
    std::vector<uint64_t> funcs(vtableEntriesCount);
    if (!rc.ReadMemory(deviceVtable, funcs.data(), sizeof(uint64_t) * vtableEntriesCount)) {
        std::cerr << "Failed to read device vtable entries\n";
        return;
    }

    for (int i = 0; i < vtableEntriesCount; i++) {
        std::cout << "  [" << i << "] = 0x" << std::hex << funcs[i] << "\n";
    }
}

void DumpVtable(RemoteCall& rc, uint64_t instance, size_t count = 10) {
    uint64_t vtablePtr = 0;
    if (!rc.ReadMemory(instance, &vtablePtr, sizeof(vtablePtr)) || vtablePtr == 0) {
        std::cerr << "[!] Failed to read vtable pointer\n";
        return;
    }
    std::cout << "[+] Vtable at: 0x" << std::hex << vtablePtr << "\n";

    std::vector<uint64_t> entries(count);
    if (!rc.ReadMemory(vtablePtr, entries.data(), count * sizeof(uint64_t))) {
        std::cerr << "[!] Failed to read vtable entries\n";
        return;
    }

    for (size_t i = 0; i < entries.size(); i++) {
        std::cout << "  [" << i << "]: 0x" << std::hex << entries[i] << "\n";
    }
}

uint64_t GetImmediateContext_SkipAddRef(RemoteCall& rc, uint64_t devicePtr) {
    std::cout << "[*] Attempting to get immediate context pointer (skipping AddRef)...\n";

    uint64_t innerPtr = 0;
    if (!rc.ReadMemory(devicePtr + 0x3E0, &innerPtr, sizeof(innerPtr)) || innerPtr == 0) {
        std::cerr << "[!] Failed to read inner pointer at devicePtr + 0x3E0\n";
        return 0;
    }
    std::cout << "[+] innerPtr: 0x" << std::hex << innerPtr << "\n";

    uint64_t contextPtr = 0;
    if (!rc.ReadMemory(innerPtr + 0x60, &contextPtr, sizeof(contextPtr)) || contextPtr == 0) {
        std::cerr << "[!] Failed to read immediate context pointer at innerPtr + 0x60\n";
        return 0;
    }
    std::cout << "[+] Immediate context pointer: 0x" << std::hex << contextPtr << "\n";

    DumpVtable(rc, contextPtr, 10);

    return contextPtr;
}

uint64_t RemoteGetBackBuffer(RemoteCall& rc, uint64_t swapChainInstance) {
    static uint64_t remoteBackBufferPtr = 0;
    if (!remoteBackBufferPtr) {
        remoteBackBufferPtr = rc.AllocMemory(sizeof(uint64_t));
        if (!remoteBackBufferPtr) {
            std::cerr << "[!] Failed to allocate memory for backbuffer output pointer\n";
            return 0;
        }
    }
    uint64_t zero = 0;
    rc.WriteMemory(remoteBackBufferPtr, &zero, sizeof(zero));

    static uint64_t remoteIID = 0;
    if (!remoteIID) {
        remoteIID = rc.AllocMemory(sizeof(GUID));
        if (!remoteIID) {
            std::cerr << "[!] Failed to allocate memory for IID\n";
            return 0;
        }
        static const GUID IID_ID3D11Texture2D = __uuidof(ID3D11Texture2D);
        rc.WriteMemory(remoteIID, &IID_ID3D11Texture2D, sizeof(GUID));
    }

    uint64_t hr = RemoteCallVFunc(rc, swapChainInstance, 9, 0, remoteIID, remoteBackBufferPtr);
    std::cout << "[*] GetBuffer returned HRESULT: 0x" << std::hex << hr << "\n";
    if (hr != 0) {
        std::cerr << "[!] GetBuffer failed\n";
        return 0;
    }

    uint64_t backBufferPtr = 0;
    for (int i = 0; i < 5; i++) {
        if (rc.ReadMemory(remoteBackBufferPtr, &backBufferPtr, sizeof(backBufferPtr)) && backBufferPtr != 0) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (backBufferPtr == 0) {
        std::cerr << "[!] Failed to read backbuffer pointer after retries\n";
        return 0;
    }

    std::cout << "[+] Got backbuffer pointer: 0x" << std::hex << backBufferPtr << "\n";
    return backBufferPtr;
}

uint64_t RemoteCreateRTV(RemoteCall& rc, uint64_t devicePtr, uint64_t backBufferPtr) {
    static uint64_t remoteRTVPtr = 0;
    if (!remoteRTVPtr) {
        remoteRTVPtr = rc.AllocMemory(sizeof(uint64_t));
        if (!remoteRTVPtr) {
            std::cerr << "[!] Failed to allocate memory for RTV output pointer\n";
            return 0;
        }
    }
    uint64_t zero = 0;
    rc.WriteMemory(remoteRTVPtr, &zero, sizeof(zero));

    // CreateRenderTargetView signature:
    // HRESULT CreateRenderTargetView(ID3D11Resource *pResource, const D3D11_RENDER_TARGET_VIEW_DESC *pDesc, ID3D11RenderTargetView **ppRTView);

    // We pass NULL for pDesc (second param = 0)

    uint64_t hr = RemoteCallVFunc(rc, devicePtr, 9, backBufferPtr, 0, remoteRTVPtr);
    std::cout << "[*] CreateRenderTargetView returned HRESULT: 0x" << std::hex << hr << "\n";

    if (hr != 0) {
        std::cerr << "[!] CreateRenderTargetView failed\n";
        return 0;
    }

    uint64_t rtvPtr = 0;
    for (int i = 0; i < 5; i++) {
        if (rc.ReadMemory(remoteRTVPtr, &rtvPtr, sizeof(rtvPtr)) && rtvPtr != 0) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (rtvPtr == 0) {
        std::cerr << "[!] Failed to read RTV pointer after retries\n";
        return 0;
    }

    std::cout << "[+] Got RTV pointer: 0x" << std::hex << rtvPtr << "\n";
    return rtvPtr;
}

uint64_t SearchForRTV(RemoteCall& rc, uint64_t contextPtr) {
    std::cout << "[*] Starting RTV pointer search...\n";

    constexpr uint64_t SEARCH_START = 0x0000000010000000; 
    constexpr uint64_t SEARCH_END = 0x0000000100000000;
    constexpr size_t STEP = 0x10;
    constexpr int maxTries = 100;

    float testColor[4] = { 1.0f, 0.0f, 0.0f, 1.0f }; 

    uint64_t remoteColor = rc.AllocMemory(sizeof(float) * 4);
    rc.WriteMemory(remoteColor, testColor, sizeof(float) * 4);

    uint64_t vtable = 0;
    rc.ReadMemory(contextPtr, &vtable, sizeof(vtable));

    uint64_t fnClear = 0;
    rc.ReadMemory(vtable + 50 * sizeof(uint64_t), &fnClear, sizeof(fnClear));

    for (uint64_t addr = SEARCH_START; addr < SEARCH_END && addr < SEARCH_START + maxTries * STEP; addr += STEP) {
        uint64_t dummy = 0;
        if (!rc.ReadMemory(addr, &dummy, sizeof(dummy))) continue;
        if (dummy == 0 || dummy == 0xCCCCCCCCCCCCCCCC) continue;

        uint64_t result = rc.Call(fnClear, contextPtr, addr, remoteColor);
        if (result == 0) {
            std::cout << "[+] Found viable RTV pointer: 0x" << std::hex << addr << "\n";
            rc.FreeMemory(remoteColor);
            return addr;
        }
    }

    rc.FreeMemory(remoteColor);
    std::cerr << "[!] Failed to find RTV pointer via brute force\n";
    return 0;
}


bool RemoteClearRTV(RemoteCall& rc, uint64_t contextPtr, uint64_t rtvPtr, const float color[4]) {
    uint64_t remoteColor = rc.AllocMemory(sizeof(float) * 4);
    if (!remoteColor) return false;
    rc.WriteMemory(remoteColor, color, sizeof(float) * 4);

    uint64_t vtablePtr = 0;
    if (!rc.ReadMemory(contextPtr, &vtablePtr, sizeof(vtablePtr))) return false;

    uint64_t fn = 0;
    if (!rc.ReadMemory(vtablePtr + 50 * sizeof(uint64_t), &fn, sizeof(fn))) return false;

    rc.Call(fn, contextPtr, rtvPtr, remoteColor);

    rc.FreeMemory(remoteColor);
    return true;
}

bool RemoteBindRTV(RemoteCall& rc, uint64_t contextPtr, uint64_t rtvPtr) {
    uint64_t remoteArray = rc.AllocMemory(sizeof(uint64_t));
    if (!remoteArray) {
        std::cerr << "[!] Failed to allocate memory for RTV array\n";
        return false;
    }
    if (!rc.WriteMemory(remoteArray, &rtvPtr, sizeof(rtvPtr))) {
        std::cerr << "[!] Failed to write RTV pointer to remote array\n";
        return false;
    }

    uint64_t vtablePtr = 0;
    if (!rc.ReadMemory(contextPtr, &vtablePtr, sizeof(vtablePtr))) {
        std::cerr << "[!] Failed to read context vtable\n";
        return false;
    }

    uint64_t omSetRTsFunc = 0;
    if (!rc.ReadMemory(vtablePtr + 8 * sizeof(uint64_t), &omSetRTsFunc, sizeof(omSetRTsFunc))) {
        std::cerr << "[!] Failed to read OMSetRenderTargets function pointer\n";
        return false;
    }

    if (!rc.Call(omSetRTsFunc, contextPtr, 1, remoteArray, 0)) {
        std::cerr << "[!] OMSetRenderTargets call failed\n";
        return false;
    }

    rc.FreeMemory(remoteArray);
    return true;
}

int main() {
    srand(static_cast<unsigned int>(time(nullptr)));
    const wchar_t* targetProcessName = L"AVF2-Win64-Shipping.exe";

    DWORD pid = 0;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            std::cerr << "[!] Failed to create process snapshot\n";
            return 1;
        }
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, targetProcessName) == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    if (!pid) {
        std::cerr << "[!] Target process not found\n";
        return 1;
    }

    RemoteCall rc(pid);
    if (!rc.IsValid()) {
        std::cerr << "[!] Failed to open target process\n";
        return 1;
    }
    std::cout << "[+] Opened process PID " << pid << "\n";

    uint64_t dxgiBase = rc.GetModuleBase(L"dxgi.dll");
    if (!dxgiBase) {
        std::cerr << "[!] Failed to find dxgi.dll module base\n";
        return 1;
    }
    std::cout << "[+] dxgi.dll base: 0x" << std::hex << dxgiBase << "\n";

    uint64_t idaDxgiBase = 0x180000000;
    uint64_t idaVtableAddr = 0x18009A000;
    uint64_t idaPresentAddr = 0x1800018C0;

    uint64_t realVtableAddr = dxgiBase + (idaVtableAddr - idaDxgiBase);
    uint64_t realPresentAddr = dxgiBase + (idaPresentAddr - idaDxgiBase);

    std::cout << "[+] Rebased vtable address: 0x" << std::hex << realVtableAddr << "\n";
    std::cout << "[+] Original Present addr: 0x" << std::hex << realPresentAddr << "\n";

    uint64_t swapChainInstance = rc.FindSwapChainInstance(realVtableAddr);
    if (!swapChainInstance) {
        std::cerr << "[!] Failed to find swapchain instance\n";
        return 1;
    }
    std::cout << "[+] Found swapchain instance at 0x" << std::hex << swapChainInstance << "\n";

    uint64_t vtablePtr = 0;
    if (!rc.ReadMemory(swapChainInstance, &vtablePtr, sizeof(vtablePtr))) {
        std::cerr << "[!] Failed to read swapchain vtable pointer\n";
        return 1;
    }
    std::cout << "[+] SwapChain vtable at: 0x" << std::hex << vtablePtr << "\n";

    constexpr size_t vtableSize = 18 * sizeof(uint64_t);
    std::vector<uint64_t> vtableEntries(18);
    if (!rc.ReadMemory(vtablePtr, vtableEntries.data(), vtableSize)) {
        std::cerr << "[!] Failed to read swapchain vtable entries\n";
        return 1;
    }

    uint64_t counterAddr = rc.AllocMemory(sizeof(uint64_t));
    if (!counterAddr) {
        std::cerr << "[!] Failed to allocate remote memory for Present call counter\n";
        return 1;
    }
    uint64_t zero64 = 0;
    if (!rc.WriteMemory(counterAddr, &zero64, sizeof(zero64))) {
        std::cerr << "[!] Failed to write zero to Present counter memory\n";
        return 1;
    }

    auto BuildPresentTrampoline = [&](uint64_t originalPresentAddr, uint64_t counterAddr) -> std::vector<uint8_t> {
        std::vector<uint8_t> shell;

        shell.insert(shell.end(), { 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51 });

        shell.push_back(0x48); shell.push_back(0xB8);
        for (int i = 0; i < 8; i++)
            shell.push_back((counterAddr >> (8 * i)) & 0xFF);

        shell.insert(shell.end(), { 0x48, 0x8B, 0x08 });

        shell.insert(shell.end(), { 0x48, 0x83, 0xC1, 0x01 });

        shell.insert(shell.end(), { 0x48, 0x89, 0x08 });

        shell.insert(shell.end(), { 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58 });

        shell.push_back(0x48);
        shell.push_back(0xB8);
        for (int i = 0; i < 8; i++)
            shell.push_back((originalPresentAddr >> (8 * i)) & 0xFF);

        shell.insert(shell.end(), { 0xFF, 0xE0 });

        return shell;
        };

    auto presentShellcode = BuildPresentTrampoline(vtableEntries[8], counterAddr);
    size_t presentShellSize = presentShellcode.size();
    uint64_t remotePresentShell = rc.AllocMemory(presentShellSize);
    if (!remotePresentShell) {
        std::cerr << "[!] Failed to allocate remote memory for Present hook\n";
        return 1;
    }
    if (!rc.WriteMemory(remotePresentShell, presentShellcode.data(), presentShellSize)) {
        std::cerr << "[!] Failed to write Present hook shellcode\n";
        return 1;
    }
    DWORD oldProtect;
    if (!VirtualProtectEx(rc.GetProcessHandle(), (LPVOID)remotePresentShell, presentShellSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "[!] Failed to set Present hook memory protection\n";
        return 1;
    }
    FlushInstructionCache(rc.GetProcessHandle(), (LPCVOID)remotePresentShell, presentShellSize);

    std::vector<uint64_t> newVtable = vtableEntries;
    newVtable[8] = remotePresentShell;

    uint64_t remoteVtable = rc.AllocMemory(vtableSize);
    if (!remoteVtable) {
        std::cerr << "[!] Failed to allocate remote memory for new vtable\n";
        return 1;
    }
    if (!rc.WriteMemory(remoteVtable, newVtable.data(), vtableSize)) {
        std::cerr << "[!] Failed to write new vtable memory\n";
        return 1;
    }
    if (!rc.WriteMemory(swapChainInstance, &remoteVtable, sizeof(remoteVtable))) {
        std::cerr << "[!] Failed to patch swapchain vtable pointer\n";
        return 1;
    }

    std::cout << "[+] Present hooked with counter increment trampoline\n";

    uint64_t devicePtr = RemoteGetDevice(rc, swapChainInstance);
    if (!devicePtr) {
        std::cerr << "[!] Failed to get device pointer\n";
        return 1;
    }
    std::cout << "[+] Device pointer: 0x" << std::hex << devicePtr << "\n";

    DumpDeviceVtable(rc, devicePtr);

    uint64_t contextPtr = GetImmediateContext_SkipAddRef(rc, devicePtr);
    if (!contextPtr) {
        std::cerr << "[!] Failed to get immediate context pointer\n";
        return 1;
    }
    std::cout << "[+] Immediate context pointer acquired.\n";


    std::thread([&]() {
        uint64_t lastCount = 0;
        auto lastTime = std::chrono::steady_clock::now();
        std::deque<std::pair<std::chrono::steady_clock::time_point, uint64_t>> history;

        static uint64_t cachedBackBuffer = 0;
        static uint64_t cachedRTV = 0;
        static bool initialized = false;

        while (true) {
            uint64_t count = 0;
            if (rc.ReadMemory(counterAddr, &count, sizeof(count))) {
                auto now = std::chrono::steady_clock::now();
                uint64_t frameDelta = count - lastCount;
                lastCount = count;

                history.emplace_back(now, frameDelta);
                while (!history.empty() &&
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        now - history.front().first).count() > 1000) {
                    history.pop_front();
                }

                uint64_t framesInLastSecond = 0;
                for (const auto& pair : history)
                    framesInLastSecond += pair.second;

                std::cout << std::dec << "[FPS] ~" << framesInLastSecond << "\n";

                if (!initialized) {
                    cachedBackBuffer = RemoteGetBackBuffer(rc, swapChainInstance);
                    if (!cachedBackBuffer) continue;

                    cachedRTV = SearchForRTV(rc, contextPtr);
                    if (!cachedRTV) continue;

                    if (!RemoteBindRTV(rc, contextPtr, cachedRTV)) {
                        std::cerr << "[!] Failed to bind RTV\n";
                        continue;
                    }

                    initialized = true;

                }


                float color[4] = {
                    static_cast<float>((rand() % 100) / 100.0f),
                    static_cast<float>((rand() % 100) / 100.0f),
                    static_cast<float>((rand() % 100) / 100.0f),
                    1.0f
                };

                RemoteClearRTV(rc, contextPtr, cachedRTV, color);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        }).detach();



    std::cout << "[*] Hook installed. Keep this program running...\n";

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
