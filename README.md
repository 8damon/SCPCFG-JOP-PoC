# SCPCFG JOP Dispatcher Proof of Concept (PoC)

This PoC locates ntdll’s SCPCFG page, validates `dispatch_no_es`, builds a 24-byte trampoline that loads your target into RAX, then jumps into the dispatcher so execution flows into the real stub. In this case, NtGetCurrentProcessorNumber.

## What SCPCFG is

* Windows 11 24H2 added four new RX sections in `ntdll`: **SCPCFG, SCPCFGFP, SCPCFGNP, SCPCFGES**. Each has a header with fixed offsets like `0x40` (dispatch_no_es), `0xC0` (dispatch_es), `0x140` (validate_no_es), and `0x1C0` (validate_es), followed by unwind data and a runtime function table
* At runtime the kernel builds a per-module SCPCFG page and maps it at the end of the image. The effective addresses are computed as `ntdllBase + ntdllImageSizeInMemory + offset`, which is why `base + SizeOfImage + 0x40` lands on `dispatch_no_es` on 24H2 builds
* The SCPCFG dispatchers are tiny. The "nop" flavor is literally `jmp rax`. The regular SCPCFG dispatcher validates the target against the CFG bitmap, then jumps to RAX. Either way, setting `RAX = <target>` then jumping to the dispatcher fwds control into the target stub, which is exactly what this PoC does

## How it works

1. Resolve `ntdll.dll`, read `SizeOfImage`, compute `base + SizeOfImage + 0x40` and validate it is executable and begins with `48 FF E0` for a `jmp rax` style dispatcher. The offsets are fixed in the section header on 24H2
2. Build a 24-byte trampoline: `mov rax, <target>` then `jmp [rip+0]` with an inline pointer to `dispatch_no_es`.
3. Flip the page to RX, call through it, and print the result.
4. You are doing JOP, not ROP, since control transfer is jump based and you do not pivot the stack.

## Refs

* ynwarcs, “CFG in Windows 11 24H2” (deep dive into SCPCFG sections, offsets, mapping logic, dispatcher bodies)
* NtDoc: `RTL_SCPCFG_NTDLL_EXPORTS` (structure exported by ntdll for SCPCFG addresses)
* x64dbg issue on build 26100 showing SCPCFG, SCPCFGFP, SCPCFGNP, SCPCFGES visible in memory maps
