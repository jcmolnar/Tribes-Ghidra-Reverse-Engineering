# Bov's AI crash fix (ServerSidePlugin.dll) — analysis + 1.40 porting

## The DLL
`Kingdom of Kronos V0.8.1 Development\Plugins\ServerSidePlugin.dll` (Bov). NOT packed (plain MSVC, readable
strings: "Patching an AI crash bug. ...Bov Bov Bov", "Patching a hook into the AI", `ShowAICrash`). Patches
**T1Vista** at runtime via `VirtualProtect(0x40)+memcpy` (`FUN_10004202(target,src,len)`). Patch table:
- **0x43ffee** — 15 bytes → `E8 73 48 BC 0F`(CALL→plugin 0x10004866)+10×NOP  ← **the AI crash fix**
- 0x43bff4 — 6 bytes → CALL→plugin 0x1000883A ("AIJetPatch": AI death/jet — stop next AI spawning airborne)
- 0x40be84(1B), 0x40cd4e(2B), 0x550cc8(1B), 0x550ccd(1B) — small byte patches (related AI/flag tweaks)

## The bug (T1Vista FUN_0043ffbc — an AI line-of-sight / containment check)
```c
if (FUN_0058a87c(query, this+0x1a0, 0)) return 1;             // self box vs query
if (this->flags(+0x4c) & 2)
    return FUN_0058a87c(query, *(this+0x1c0) + 0x23c, 0);     // <<< *(this+0x1c0) (mount/target obj ptr) NULL -> crash
return 0;
```
Crash instr `MOV EDX,[ECX+0x23c]` with `ECX=*(this+0x1c0)`. When the AI's mount/target object (ptr at +0x1c0)
is NULL (destroyed), the `+0x23c` (its world box) deref crashes the **server** (AI runs server-side).

## Bov's fix (plugin handler @0x10004866) = a NULL guard
```asm
CMP ECX,0 ; JZ safe_exit ; MOV EDX,[ECX+0x23c] ; XOR ECX,ECX ; MOV EAX,ESI ; CALL FUN_0058a87c
```
i.e. `if (*(this+0x1c0)) { ...original... }` — identical in spirit to our catalog wire-data NULL guards.

## Porting to 1.40 — status + challenge
- This is a **server-side** fix (AI simulation). It belongs on a **1.40-based Kronos SERVER**; the existing
  T1Vista Kronos server already has it (via this very plugin). The 1.40 CLIENT only hits it if it runs AI.
- **No byte-pattern match in 1.40**: searched `Tribes 1.40.655\Tribes.exe` for `MOV [reg+0x1c0]`→`MOV
  [ECX+0x23c]` — 18 `+0x23c` derefs exist but NONE preceded by `+0x1c0`. T1Vista's struct offsets are
  Kronos-MODDED (0x1c0/0x23c are mod-shifted); stock 1.40 has the same FIELDS at different offsets. So porting
  needs SEMANTIC matching: find 1.40's analog of FUN_0043ffbc (a function that calls a containment-check sub
  twice — once on `this+<selfBox>`, once on `*(this+<obj>)+<objBox>`, gated by a flag bit), then guard the 2nd
  deref. Deeper than byte-patching.

## Coherent set
Bov's AI guard + our catalog wire-data guards (re/crashvec_140.md: DataBlock/RemoteCreate/Player/Lightning) are
the SAME class (NULL-deref guards on engine pointers). Catalog = CLIENT wire crashes; Bov's AI = SERVER AI
crash. The crashFix deliverable should target the right binary per deployment.
