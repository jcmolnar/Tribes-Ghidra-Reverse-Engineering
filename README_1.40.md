# Tribes 1.40 — Reverse Engineering (`1.40` branch)

Reverse-engineering notes, Ghidra scripts, and DLL **source** for **Starsiege Tribes 1.40.655**
(MSVC 2005 build, image base 0x400000, no ASLR). Companion to the `main` branch's Ghidra script
collection. Goal: understand the 1.40 binary well enough to fix long-standing crashes/hangs and
port Kronos-era features onto the stock 1.40 client/server (via the TribesXT framework).

> No game binaries or game assets are included — only our own RE analysis, scripts, and source.
> Reverse-engineering for interoperability/modding; nothing copyrighted is redistributed.

## Layout
- `ghidra_scripts/` — Ghidra headless RE scripts (shared with `main`).
- `docs/` — RE findings & write-ups (index below).
- `findings/` — raw Ghidra output / address dumps backing the docs.
- `plugins/` — our DLL source (build-from-source; **no compiled binaries**):
  - `freezefix/` — the ~3-day dedicated-server freeze fix (float sim-clock rebase).
  - `hudbot/` — ScriptGL reimplementation for the stock-1.40 client HUD (Hudbot/Presto port).

## What's covered (`docs/`)
- **In-place exe patches** — mouse fix, AI crash fix, DataBlock/RemoteCreate wire-crash guards,
  packet-rate cap. (`crashvec_140.md`, `diff_140.md`, `ai_fix_140.md`, `ai_crash_fix.md`)
- **3-day server freeze** — root cause (32-bit float `SimTime` hits a precision wall at ~2^18 s,
  ULP exceeds the 10 ms schedule interval -> scheduler infinite-loops) + the rebase fix.
  (`freeze_fix_13.md`, `server_freeze.md`, `server_freeze_rundown.md`)
- **Bov ServerSidePlugin patches** — analysis: which are real crash fixes vs behavior/tuning.
  (`bov_patches_analysis.md`)
- **HUD / ScriptGL** — the client HUD render interface. (`hudbot_140.md`, `hudbot_t1vista_port.md`)
- **Porting Kronos to 1.40** — plan/constraints (1.40 has no native plugin loader; script/asset
  mods work, native plugins need the TribesXT framework). (`kronos_on_140.md`, `tribes140_ref.md`)
- **DLL RE & build workflow** — the Ghidra-headless + x86-build + hook/detour stack end to end.
  (`DLL_RE_MANUAL.md`)

## Build
DLL source builds with VS2022 BuildTools (**x86** — the target is 32-bit):
`cl /nologo /LD /EHsc /O2 <file>.cpp` (see each plugin's `build_*.bat`).
Ghidra scripts run headless:
`analyzeHeadless <project-dir> <project-name> -process Tribes.exe -scriptPath ghidra_scripts -postScript <Script>.java`.
