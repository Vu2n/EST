# EST (External Shellcode Toolkit)

This project is an experiment in **external Direct3D 11 manipulation** using manual shellcode injection — no DLLs, no internal hooks. 
The goal was to understand how to interact with D3D11 components remotely by resolving interfaces, calling vtable functions, 
and performing basic rendering-related operations from an external process.

> This isn't meant to be production-ready or undetectable. It's a learning tool and research base.

---

## Features

- External `IDXGISwapChain::Present` hook via shellcode trampoline
- Remote COM function calls via generated shellcode
- Support for RCX/RDX/R8/R9, shadow space, and XMM registers
- Resolves D3D11 device/context externally
- Can call device/context functions via vtables
- FPS tracking via Present count

---

## RemoteCall (RC) Wrapper

The `RemoteCall` class acts as a low-level wrapper that enables calling **in-game or engine functions remotely** from an external process. It builds shellcode dynamically to:

* Push arguments (integers, floats, strings) into the appropriate registers and stack slots
* Call arbitrary function addresses in the target process
* Return results (both from `RAX` and `XMM0`)

### Example Use Case

Once you've resolved an in-game function pointer (e.g., via vtable or signature scan), you can call it like this:

```cpp
uint64_t result = rc.Call(funcAddress, arg1, arg2, ...);
```

This allows you to:

* Call virtual functions (via resolved vtables)
* Execute engine methods without injecting code
* Initialize D3D objects or issue rendering commands externally

It's a flexible way to interact with the target application's codebase entirely from the outside, as long as you have the right function address and calling convention.
---

## Limitations

- Backbuffer and RTV retrieval is **currently unreliable**
- Works only on **x64** targets
- Only tested with games using D3D11 and `dxgi.dll`
- No GUI or overlay (yet)
- Requires manual rebase of `dxgi.dll` vtable address (based on IDA offsets)

---

## Requirements

- Windows 10/11
- Target must be a D3D11 x64 application
- Built with Visual Studio 2019+ (C++17 or later)

---

## Usage

1. Launch your D3D11 target application (e.g., a game).
2. Edit the process name in `Main.cpp`:

```cpp
const wchar_t* targetProcessName = L"AVF2-Win64-Shipping.exe";
```

3. Build and run `Rust.exe` as administrator.
4. The tool will:

   * Find the process
   * Hook `Present`
   * Log FPS
   * Attempt to find device/context/backbuffer/RTV

---

## Future Plans

* Reliable RTV and backbuffer detection
* External ImGui-style overlay (via separate transparent window)
* Remote texture manipulation
* Shared memory IPC for runtime control

---

## License

This project is released under the MIT License.

---

## Disclaimer

This code is for educational and research purposes only. Using it in online games or anti-cheat-protected environments may result in bans or violations of terms of service. Use responsibly.
