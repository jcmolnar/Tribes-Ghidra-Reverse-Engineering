# Tribes Ghidra Reverse-Engineering Scripts

Custom [Ghidra](https://ghidra-sre.org/) scripts used to reverse-engineer **Starsiege Tribes** (Dynamix *Darkstar* engine, 1998) — recovering wire/packet formats, the persistent-class registry, ghost/event decode, crash vectors, and the native plugin/DLL ABI across the T1Vista (1.3), 1.40, and Kronos `mem.dll` binaries.

These are the *tools*, not Ghidra and not the analyzed binaries or project databases.

## Ghidra version

Built and run against **Ghidra 12.1.2 PUBLIC**. Ghidra is **not** included here — download it from <https://ghidra-sre.org/> (the APIs these scripts use are stable across recent 11.x/12.x, but 12.1.2 PUBLIC is what they were written and tested on).

## Usage

1. Open Ghidra and load the target program.
2. **Window → Script Manager → Manage Script Directories** (the bundles icon) → add the `ghidra_scripts/` folder from this repo.
3. The scripts appear in the Script Manager (by filename); run against the open program.

> ⚠️ Many scripts reference **specific function addresses** (`FUN_00xxxxxx`) and offsets for **specific binaries** — T1Vista.exe (Borland C++ 5.x, v1.3), the 1.40.655 client (MSVC), and the Kronos `mem.dll` plugin loader. Those hardcoded addresses will **not** match other builds; treat such scripts as templates / documentation of where things live, and re-anchor to your binary.

## What's in here (by theme)

- **Wire / packet / persistence:** `PersistWalker`, `Registrars`, `NameBitStream`, `FullCatalog`, `GhostCatalog`, `PlayerPSCRead`, `FindClassTag`, `EventMap`, `RealTags`, `CompareTag`, `DumpPack`, `DumpTagTable` — enumerate persistent classes and recover their exact bitstream formats.
- **Crash-vector hunting:** `CrashVec`, `Guard`, `GuardScan`, `T1Hunt`, `DelVerify`, `FinalVerify` — locate the unguarded wire-data deref sites (createDataBlock / RemoteCreate / ghost-slot / lightning) the WASM port and native rebuild had to guard.
- **Decompile / dump helpers:** `Decomp*`, `DumpAsm`, `DumpReg`, `DumpHelpers`, `DumpCreate`, `DisasmFns`, `WrapDisasm`, `CallerOf`, `ProgInfo`.
- **Plugin / DLL ABI (Kronos `mem.dll`, ScriptGL):** `GetPluginRE`, `HandlerABI`, `RegWrappers`, `PluginPM`, `PluginReg`, `PM*` (PlayerManager DLL), `Mem*` (mem.dll loader), `FindLoader`, `FindConsoleAbi`, `ConsoleMethods`, `SimConsole`.
- **1.40 client:** `AICaller140`, `AIFix140`, `FindGates140`, `FindMatcher140`, `Probe140`, `Cat140`, `GhostCat140`.
- **AI / gameplay subsystems:** `AI*`, `FindGhostMgr`, `FindObjective`, `FindCoop`, `FindFreeList`, `FindInput`, `FindMouse`, `FindResLoad`/`ResLoadDump`, `BitmapRE`, `TexCacheLimit`/`TexCallers`.
- **Hudbot / ScriptGL input:** `HudbotCursor*`, `HudbotSeam`, `DumpKeyDispatch`, `FindKeyDispatch`.
- **Version diff / catalog:** `V1V7`, `V7b`–`V7h`, `VtableDump`/`VtScan`, `FindVtable`, `VerifyMap`.

## License / notes

Starsiege Tribes has been freeware since 2015. These scripts are original reverse-engineering tooling for interoperability/preservation research; they contain no game source. Provided as-is.
