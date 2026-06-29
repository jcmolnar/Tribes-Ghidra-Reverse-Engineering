# Scope: port Hudbot (ScriptGL + text input) to T1Vista.exe (1.3, Borland)

Goal: run the Hudbot ScriptGL interface — the `gl*` draw commands, the
`ScriptGL::playGui::onPreDraw/onPostDraw` render hook, the `onMouse*` callbacks,
and the new `glTextInput` keyboard seam — on the **stock T1Vista.exe (1.3,
Borland)** client, so the Kronos Presto GUI (`config\Presto\*.cs`, incl. the
KronosChat composer) works there exactly as on 1.40. The script layer
(KronosInput.cs + all Kronos GUI) is engine-agnostic and needs ZERO changes.

## The big enabler: T1Vista has a NATIVE plugin loader
Unlike 1.40 (no loader → injected by xtloader), T1Vista loads `Plugins\*.dll`
via **mem.dll** through a `getPlugin()` descriptor (gated by the
`$PluginLoader::<dllname>` console var). So Hudbot-on-T1Vista is a normal Kronos
plugin DLL, and the console seam is already fully RE'd. See
**re/DLL_RE_MANUAL.md** + memory [[kronos-plugin-loader]].

## Per-exe seam table (what differs)

| seam | Tribes.exe 1.40 (MSVC) — DONE | T1Vista.exe 1.3 (Borland) |
|---|---|---|
| load mechanism | xtloader → DllMain | **mem.dll → getPlugin descriptor** (Plugins\, `$PluginLoader::hudbot 1`) |
| register a command | `addCommand` 0x403600 (`__thiscall(console,id,name,cb,priv)`) | **StringCallback template, `CALL 0x5f4138`** (`PUSH handler;PUSH 0;MOV ECX,name;XOR EDX,EDX`) |
| command handler ABI | `const char*(void* con,int id,int argc,const char** argv)` | **ECX=argc, [ESP+4]=argv, ret char* in EAX, `RET 4`** |
| call a script fn | `executef` 0x403680 (cdecl variadic) | **`evaluate` 0x5f41a8**(console,cmd,1,0,0) — build the cmd string |
| Console global | `*0x006E284C` | `*0x006583c4` (and registrar console `*0x007afde4`) |
| keyboard→bind dispatch | 0x00526560 (event=[ESP+4], `ret 4`, 5-byte patch→0x526565) | **0x0050d62c (event=EDX, this=EAX, plain `ret`, 7-byte patch→0x50d633)** |
| render seam (present) | IAT-hook gdi32!SwapBuffers / opengl32!wglSwapBuffers | **SAME — verified: T1Vista imports both + glBegin/glViewport/wglMakeCurrent/wglGetCurrentDC** |
| raw gl* draw | opengl32 imported | **SAME — opengl32 imported** |
| canvas cursor offsets (pumpMouse) | CURSOR_ON 0x1ac, BUTTONS 0x1b0, X 0x1f8, Y 0x1fc; mgr `*0x6D4FBC`; findObject vtbl+0x68 | **NEEDS RE** (Borland SimCanvas layout differs) — Phase 2 |

Everything in the table is known/verified EXCEPT the last row (cursor offsets),
which only the mouse path needs.

## Work plan

### Phase 1 — ScriptGL render + keyboard text input (no mouse)
Gets the Kronos HUD rendering AND the chat composer typing on T1Vista. The
composer is reached by a key bound to `KronosChat::beginSay()` (the key seam is
global; click-to-focus needs the mouse path = Phase 2).

1. **getPlugin descriptor** (T1Vista build only): 40-byte descriptor (version
   double 4.0, flags `&1` client, name/desc strings, the 0xbaadf00d sentinels),
   vtable[0]=our init (registers commands + installs hooks; must return nonzero),
   vtable[1..7]=the engine console methods per [[kronos-plugin-loader]]. 1.40
   keeps its DllMain/xtloader path.
2. **Per-exe address table + exe detection**: a `struct EngineAbi { … }` chosen
   at load by module filename (or a signature byte at a known VA). Replaces the
   current hardcoded 1.40 constants.
3. **Command registration shim**: each `gl*`/`glTextInput` handler gets a tiny
   naked thunk for the Borland StringCallback ABI (read ECX=argc, [ESP+4]=argv,
   `call` the shared C handler `(NULL,0,argc,argv)`, move return to EAX, `ret 4`),
   registered via `CALL 0x5f4138`. ~20 thunks or one macro/generic adapter.
4. **`callScript(fn,arg)` abstraction**: `executef` on 1.40; on T1Vista build
   `fn @ "(\"arg\");"` and `evaluate(*0x6583c4, cmd, 1,0,0)`. Used by onChar/onKey
   (and the onMouse* callbacks in Phase 2).
5. **Render hook**: the existing `iatHook(... "SwapBuffers"/"wglSwapBuffers" ...)`
   is import-table-generic → works unchanged (verified the imports exist).
6. **keydispatch detour (T1Vista)**: naked hook at 0x0050d62c — event is in **EDX**
   (not [ESP+4]), `this` in EAX; same field offsets (+0x04/0x20/0x28/0x29/0x2a/
   0x2b/0x2c, identical to 1.40); on a swallowed key set EAX=1 and **plain `ret`**
   (register args, nothing to pop); trampoline runs the 4 prologue instrs
   (PUSH EBX;PUSH ESI;MOV ESI,EAX;MOV EAX,[EDX+4]) then `jmp 0x50d633`. Recipe in
   re/keydispatch_findings.md.

### Phase 2 — mouse / GUI interaction (drag, click, composer click-to-focus)
7. **RE the T1Vista SimCanvas cursor offsets** (CURSOR_ON/BUTTONS/CURSOR_X/Y) +
   the manager global + findObject vtable slot — the Borland layout differs from
   1.40's 0x1ac/0x1b0/0x1f8/0x1fc. Use the runtime-diff-probe approach already
   used for 1.40 (re/hudbot_cursor.txt, re/ghidra_scripts/HudbotCursor.java).
8. **Port `pumpMouse`** to those offsets → `onMouseActive/onMouseMove/onMouseLMB`
   fire → drag/click works (TAB menu, shop, composer click-to-focus).

## Borland gotchas
- Command handler ABI (ECX=argc/[ESP+4]=argv/ret char*/ret 4) — the naked thunks.
- keydispatch ABI (event=EDX, plain ret) — different naked hook than 1.40.
- The register call is itself inline asm (specific reg setup + `CALL 0x5f4138`).
- Confirm mem.dll loads our plugin AFTER the console is up (it does — vtable[0]
  is called post-console-ready) so registration/hook install timing is safe.

## Effort & risk
- **Phase 1: focused plumbing, low RE risk** — every address is known (loader,
  register, evaluate, console global, keydispatch) and the render/GL imports are
  verified. The work is the descriptor + ABI-adapter thunks + the second
  keydispatch detour + exe-detection refactor. Highest-value: ScriptGL HUD +
  chat typing on the real T1Vista client.
- **Phase 2: one real RE task** (the SimCanvas cursor offsets) + a mechanical
  pumpMouse port. Medium.
- Risks: Borland struct offsets (Phase 2 canvas) must be probed, not assumed;
  the gl* thunks must marshal argv exactly; verify `$PluginLoader::hudbot` is set
  so mem.dll actually loads the DLL.

## Deploy (T1Vista)
Build x86 (`cl /LD /EHsc /O2`), drop `hudbot.dll` in the Kronos client `Plugins\`,
set `$PluginLoader::hudbot 1`, ship the Presto scripts + Hudbot\Fonts + ScriptGL
assets as today. (No xtloader.)
