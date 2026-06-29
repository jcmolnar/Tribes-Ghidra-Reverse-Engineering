# DLL Reverse-Engineering & Build Manual (Tribes / Kronos)

The standing reference for how we reverse-engineer the Tribes binaries and build
native DLL plugins/patches for them. Read this first when picking up DLL/RE work
in a fresh chat. Companion deep-dives are the other `re/*.md` files; per-binary
ground truth lives in the auto-memory (`MEMORY.md` index).

---

## 1. Targets

| Binary | What | Base | ASLR | Compiler | Notes |
|---|---|---|---|---|---|
| `T1Vista.exe` | Kronos 0.8.5 "Last Hope" 1.3 client **and** dedicated server (same exe) | 0x400000 | none | **Borland C++ 5.x (1998)** | sha1 3b6fa9b664ba, 2632192 B. Our main DLL target. |
| `Tribes.exe` 1.40.655 | Stock Tribes 1.40 | 0x400000 | none | MSVC 2005 (+RTTI) | future "port Kronos to 1.40" track. Patched in-place (exe edits), not DLLs yet. |
| `mem.dll` | The Kronos **plugin loader** (+ MS_Malloc/Free/Realloc/Calloc) | 0x10000000 | n/a | MSVC | 5KB, NOT packed. RE'd: re/memdll.txt. |

No-ASLR + fixed base means **every VA is a stable constant** — we hardcode engine
addresses directly in our DLLs.

---

## 2. RE stack — Ghidra headless

Ghidra lives at `tools/ghidra_*/` in the Tribes Browser Based project. Binaries are
pre-imported into the project `re/proj` (project name `tribes`).

**Run a script against an already-imported program:**
```bash
GH=$(ls -d tools/ghidra_*/support/analyzeHeadless.bat | head -1)
"$GH" re/proj tribes -process T1Vista.exe -noanalysis \
      -scriptPath re/ghidra_scripts -postScript MyScript.java
```
- `-process <name>` runs against an imported program **by name** (no path) — use this.
- `-import <file>` adds a NEW program, but **chokes on spaced paths**. Copy the file
  to a no-space path first (e.g. `C:\Temp\x\foo.dll`) then `-import "C:/Temp/x/foo.dll"`.
  Import auto-analyzes (drop `-noanalysis` for the first import).
- One headless run at a time. Each takes ~1–3 min.

**Script pattern** (write to `re/ghidra_scripts/Name.java`, results to `re/name.txt`):
```java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*; import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*; import java.io.*;
public class Name extends GhidraScript { public void run() throws Exception {
  AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
  DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
  PrintWriter pw=new PrintWriter(new FileWriter("C:\\...\\re\\name.txt"));
  Function f=currentProgram.getFunctionManager().getFunctionContaining(sp.getAddress(0x5f4138L));
  pw.println(di.decompileFunction(f,60,monitor).getDecompiledFunction().getC());
  pw.close(); println("wrote name.txt"); } }
```
GOTCHAS: write the `.java` with the Write tool (NOT a bash heredoc — it mangles the
class and you get "class could not be found"). Match `public class Name` to the
filename. Reusable scripts already in `re/ghidra_scripts/`: DecompOne, CallerOf,
FindRegCall, ConsoleMethods, HandlerABI, DecompAll, GuardScan, etc.

**Reading the decompiler with Borland fastcall in mind** (see §4): Ghidra often shows
`func(param_1, param_2, param_3, ...)` where `param_1=EAX, param_2=EDX, param_3=ECX`,
then stack. When args look "dropped", pull the raw disasm (a script that prints
`ins.getBytes()` + `ins.toString()`) — register args flow through that the decompiler hides.

---

## 3. The Kronos plugin model  (see memory: kronos-plugin-loader)

`mem.dll` is the loader. It `FindFirstFile("Plugins\\*.dll")`, and for each DLL gated
on the console var `$PluginLoader::<dllname-no-.dll> = true`:
`LoadLibrary -> GetProcAddress("getPlugin") -> desc = getPlugin()` then
- VERSION CHECK `*(double*)(desc+8) == 4.0`  (ship dword[+8]=0, dword[+0xc]=0x40100000)
- SIDE CHECK   server uses `*(byte*)(desc+0x1c) & 2`, client `& 1`  (use 3 = both)
- if OK: calls `desc->vtable[0]()` (desc in EAX) = **your init, AFTER the console is
  ready** — register commands / install hooks here, return nonzero to stay loaded.

**Descriptor (40 bytes)** returned by getPlugin: `[+0]`=vtable, `[+4]`=0xbaadf00d,
`[+8..+0xf]`=version double 4.0, `[+0x10]`=name str, `[+0x14]`=desc str, `[+0x18]`=0,
`[+0x1c]`=flags, `[+0x20]`=`[+0x24]`=0xbaadf00d. vtable[0]=your init; vtable[1..7]=engine
console methods (0x5f40d8,0x5f450c,0x5f3ff8,0x5f3f10,0x5f4138,0x5f41a8,0x5f3ddc) — copy them.

**Register a StringCallback console command** (the engine getNumClients template,
call from your init):
```
PUSH handler ; PUSH 0 ; MOV ECX, name_ptr ; XOR EDX,EDX ; CALL 0x005f4138
```
(EAX ignored; registers on global console *0x007afde4; param 0 => no arg-count check,
the handler checks argc itself; RET 8 self-cleans the 2 pushes.)

**Handler ABI**: `ECX = argc`, `[ESP+4] = argv` (char**, argv[0]=name), return `char*`
in EAX, **RET 4**. The naked-shim macro (see playermanager.cpp):
```c
#define HANDLER(NAME,IMPL) __declspec(naked) void NAME(){ \
  __asm mov eax,[esp+4] __asm push eax __asm push ecx \
  __asm call IMPL __asm add esp,8 __asm ret 4 }
```

---

## 4. Build stack

**Toolchain**: VS2022 BuildTools, **x86** (32-bit REQUIRED — the targets are 32-bit).
```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86
cl /nologo /LD /EHsc /O2 myplugin.cpp /Fe:myplugin.dll
```
Run the .bat by FULL PATH from PowerShell (`cmd /c "<fullpath>.bat"`) — a bare name
loses the working dir. vcvarsall prints spaced-path warnings; harmless, cl still builds.

**Borland __fastcall** (the engine's convention): args in **EAX, EDX, ECX**, then stack
(left→right). NOT the MS `ECX,EDX` order. Console handlers use the hybrid ABI in §3.
`#pragma pack` on on-disk/wire structs: Borland honored it; clang/MSVC need the pragma
guarded with `defined(_MSC_VER) || defined(__clang__)` (a recurring WASM-port bug class).

**Self-pin** so the loader can't drop the DLL (belt-and-suspenders with getPlugin):
```c
HMODULE self=NULL;
GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
                   (LPCWSTR)(void*)&someFnInThisDll, &self);
```

---

## 5. Hook / detour idiom

In-place detour (used for every crash guard + the addClient-skip enforcement):
```c
// at site: verify original bytes, then E9 JMP rel32 to our trampoline, NOP the tail
unsigned char* p=(unsigned char*)site;
if(memcmp(p,expected,len)!=0) { /* ABORT: binary changed */ }
int rel=(int)((unsigned)handler-(site+5));
DWORD old; VirtualProtect(p,len,PAGE_EXECUTE_READWRITE,&old);
p[0]=0xE9; *(int*)(p+1)=rel; for(int i=5;i<len;++i)p[i]=0x90;
VirtualProtect(p,len,old,&old); FlushInstructionCache(GetCurrentProcess(),p,len);
```
The trampoline (`__declspec(naked)`) does its guard, then **re-executes the relocated
original prologue** and `PUSH <back_addr>; RET` to continue. For Borland back/skip jumps
use `PUSH imm32; RET` (doesn't clobber a live register, unlike `MOV reg,addr; JMP reg`).
NEVER macro a socket/method name that collides (e.g. winsock `#define accept` broke
`VC::accept`). Always byte-verify the site before patching — abort + log on mismatch.

---

## 6. DLL types & where they deploy

| Kind | Loads on | Deploy folder | Our DLLs |
|---|---|---|---|
| **Client** (player) | the game client | `C:\Dynamix\Tribes\Plugins\` | `kronosfix.dll` |
| **Server** (dedicated host) | the dedicated server | `Kingdom of Kronos V0.8.1 Development\Plugins\` | `kronosfix_server.dll`, `kronos_playermanager.dll` |

Convention: ship each `X.dll` with an `X.txt` ALONGSIDE it (what it does / how to
install / functions / how it works) — every stock plugin does this. Enable via
`$PluginLoader::X = true;` in `Plugins\Scripts\PluginLoader.cs` (client or `$dedicated` block).

---

## 7. Standard workflow (the recipe)

1. **Find the seam** in Ghidra (the wire-decode site / the function to expose). Decompile
   it + its callees; pull raw disasm for exact ABI.
2. **Confirm the fix shape**: NULL/bounds guard for crashes; for a feature, find the
   engine function to call + its exact ABI (decompile a known caller as the template).
3. **Write the DLL**: handlers/impls in C; trampolines + registration in `__declspec(naked)`
   inline asm; descriptor + getPlugin for command plugins (§3); detours in DllMain (§5).
4. **Build** x86 (§4). **Verify statically**: getPlugin export present; every hook site's
   bytes byte-match the live binary (parse the PE / read the .exe bytes — see the
   PowerShell snippets used for kronos_playermanager).
5. **Deploy** to the right Plugins folder + write the `.txt` (§6) + enable in PluginLoader.cs.
6. **Verify live**: the DLL's log file shows install OK + (for command plugins)
   "registered N commands"; test commands in the server/client console.
7. **Document**: update the matching `re/*.md` + the auto-memory.

---

## 8. Verification checklist
- [ ] `getPlugin` exported (parse PE export table or `dumpbin /exports`).
- [ ] Every hook site's expected prologue == the live binary's bytes (install ABORTs + logs on mismatch).
- [ ] Descriptor version 4.0 + side flag set (else loader silently rejects).
- [ ] Live log: load/pin line, each `install OK`, `registered N commands`.
- [ ] Console smoke test of each command / the crash scenario.

---

## 9. Where things live
- RE scripts + outputs: `re/ghidra_scripts/*.java`, `re/*.txt`.
- DLL sources: `re/<name>_plugin/<name>.cpp` + `build_<name>.bat`.
- Deep technical notes per feature: `re/playermanager.md`, `re/server_freeze_rundown.md`,
  `re/freeze_fix_13.md`, `re/t1vista_crashes.md`, `re/crashvec_140.md`, `re/bov_patches_analysis.md`.
- Project map / continuity across chats: the auto-memory `MEMORY.md` index (loaded every session).
- Related repos: native MSVC rebuild = `C:\Users\Joe\Desktop\Tribes Native Build`;
  Kronos server/mod = `C:\Users\Joe\Desktop\Kingdom of Kronos V0.8.1 Development`.
