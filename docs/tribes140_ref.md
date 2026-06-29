# Tribes 1.40.655 — RE reference & recompile feasibility

Source assets (all on Desktop):
- `Tribes 1.40.655\Tribes.exe` — the client binary (the live-server-required version).
- `Tribes 1.40.655\TribesXT\` — community RE of 1.40 (git repo, MSVC v143, C++latest).
- `Tribes 1.40.655\Tribes Source Leak Console\console.cpp` — single leaked file (1999), not engine source.
- `Kingdom of Kronos V0.8.1 Development\T1Vista.exe` — the OLD Borland RE target (Kronos 0.8.5).

## Binary identity (Tribes.exe, 1.40.655)

| Property | Value |
|---|---|
| Compiler | **MSVC 2005 (VC2k5)**, linker 8.0 |
| Build | Release Win32, PDB path `d:\Tribes\Tribes\buildFiles\Link\VC2k5.Release.Win32\Tribes-release.pdb` (author's machine — we don't have the PDB) |
| Timestamp | 2009-08-27 |
| Sections | `.text/.rdata/.data/.rsrc` (modern MSVC) |
| RTTI | **849 MSVC type descriptors, full readable class names** |
| Lineage | playtribes.com **Darkstar 1.4** (`Tribes.torsion`: SearchProduct=Darkstar, SearchVersion=1.4) + **Torque/GGConnect** NAT/matchmaking layer (`Torque::InternalPublishing`, GGConnect API 0.7.0.0) |
| Version gate | embedded string: "You must upgrade your executable to play on this server (requires version **1.40** or higher)." |

**Why this supersedes T1Vista as an RE target:** T1Vista is Borland (no RTTI → we hand-rolled `PersistWalker`). 1.40 has full MSVC RTTI, so Ghidra auto-recovered class names + vtables (`Windows x86 PE RTTI Analyzer` ran 15 s during import). It's also the *correct* protocol version — live servers gate on 1.40, not the 1.30/0.8.5 T1Vista speaks. Imported into the Ghidra project `re/proj/tribes` as `Tribes.exe` (alongside `T1Vista.exe`).

## TribesXT — what it is (and isn't)

A **hook DLL** loaded into the running `Tribes.exe` via its `plugins/` folder (`main.cpp` `DllMain` → `SimGame::get()->registerPlugin(...)`). It is **binary-interop, pinned to build 655**:
- `util/hooks.h` — `CodePatch` / `JmpHook` (`__fastcall`→`__thiscall` trampolines).
- `FIELD(0xNNN, T, name)` macros = members at hardcoded offsets; method calls jump to hardcoded addresses (e.g. `PacketStream::getAverageRTT` = `0x519CC0`, `Net::setLastError` = `0x517EF0`, `serverNetcodeVersion` = `*0x6D0FF8`).

So it is **not** recompilable Tribes source — it needs the original exe. But its `src/darkstar/` + `src/tribes/` headers are **layout-accurate, human-verified RE of 1.40's classes & wire formats** — exactly the spec our WASM port reconstructs by hand. The git log shows deep netcode work (lag comp, ghost extrapolation, clock sync, weapon-swap prediction).

### Confirmed against our port
- `Core/bitstream.h` `BitStream` layout = `{dataPtr, bitNum, bufSize, error, maxReadBitNum, maxWriteBitNum}` — matches the offsets the port already RE'd (`+0x0c buf, +0x10 cursor, +0x1c max`).
- `readNormalVector`/`readSignedInt`/`readSignedFloat`/`readFloat` match the mirror stubs in `test/enginepstream.cpp` bit-for-bit.
- `Sim/Net/ghostManager.h` — full `GhostInfo` + `PacketObjectRef` layout, `GhostInfo::Flags` bits, `MaxGhostCount=1024`. Directly relevant to the stalled Phase B-2 ghost work.
- `tribes/fearDcl.h` — projectile **datablock** persist tags: Bullet=600, Grenade=601, RocketDumb=602 (distinct from the event-tag table 1024-1151 in `program/inc/FearDcl.h`).

### Netcode version map (important)
`plugins/netXT/version.h` + `tribes/version.h`:
- `Netcode::Old = (1,0)`, **`Netcode::New = (1,1)` = vanilla 1.40**.
- `Netcode::XT::v100 = (1,2)` = TribesXT's *added* netcode (subtick input, lag compensation, clock sync, client projectiles, tracer inheritance, etc.) — only active vs XT-enabled servers.

→ For joining stock live 1.40 servers, target **netcode (1,1)**. XT (1,2) is opt-in and only matters against XT servers.

## Recompile verdict (honest)

- ❌ **Rebuild `Tribes.exe` 1.40 byte-perfect from source** — not possible. No full engine source exists (TribesXT = RE headers + hook DLL; only `console.cpp` leaked). Decompiling 3 MB of optimized MSVC C++ to recompilable source is not a real path.
- ✅ **Recompile a 1.40-protocol-compatible client** — feasible by porting the 1.40 deltas onto the buildable tree we already have (`Tribes Native Build` makes a working exe), now well-specified by TribesXT + Ghidra-RTTI as the spec. Same mirror-the-binary method that already produced full datablock/event/ghost decode.

## Plan (ref first, per user)

1. **[done]** Import 1.40 into Ghidra w/ RTTI (`re/proj/tribes` → `Tribes.exe`).
2. Dump a **1.40 Persistent class + tag + vtable + `unpack()` catalog** from Ghidra RTTI → `re/full_catalog_140.txt` (analog of `re/full_catalog.txt` for T1Vista, but RTTI-driven so far cheaper).
3. **Three-way diff**: TribesXT headers ↔ our `engine/program` tree ↔ Ghidra catalog → `re/diff_140.md`. Focus: netcode (1,1) wire deltas, class-tag tables, new classes (publishing layer).
4. Map **GGConnect / Torque::InternalPublishing** (NAT discovery, master query) — shim vs port decision for the WASM relay path.
5. Fold confirmed deltas into the buildable tree → 1.40-protocol client.
