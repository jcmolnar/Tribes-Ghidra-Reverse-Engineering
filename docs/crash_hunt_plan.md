# Crash-vector hunt plan (1.40 client + dedicated server)

All the crashes we've found share ONE shape: **an unchecked deref of a lookup/factory result that can be NULL
on untrusted or stale input.** Bov's AI fix and our wire-catalog are the same bug class. This plan finds the rest
systematically. Base 0x400000, no ASLR → addresses stable; fix = detour NULL-guard (see re/ai_fix_140.md / the
applied patches) or a from-source guard.

## Pattern A — "factory result deref'd without NULL check" (highest yield)
Enumerate every call to a function that returns NULL on bad input, then check each call site for a NULL test
before the next deref. Known NULL-returning factories/lookups in 1.40:
- `createDataBlock` `FUN_00434890` (group → datablock; NULL if no case)  ✔ guarded (DataBlockEvent)
- `Persistent::create` `FUN_004131e0` (tag → obj; NULL if unregistered)  — guard RemoteCreateEvent + ALL callers
- `resolveGhost(idx)` (ghost index → SimNetObject; NULL if not yet ghosted) — Player/Lightning unpackUpdate + others
- `findObject`/`findClient`/`findBaseRep` (id/name → obj; NULL if absent)
- the AI name-link `*(this+0x1cc)` deref pattern (Bov's) — find OTHER `*(this+ptr)+field` derefs of mount/control/
  target object pointers that can be NULL (mount destroyed) — these are the "related to the AI one" siblings.
METHOD (Ghidra): `getReferencesTo(factory)` → for each caller, decompile and check if the return flows into a
deref with no intervening `TEST/CMP ...,0; JZ`. Script: extend re/ghidra_scripts/FindGates pattern. Output a
table of guarded-vs-unguarded call sites.

## Pattern B — port the AssertFatal-on-wire-data audit to 1.40
`re/crash_vectors.md` (our reconstructed-source audit) lists 5 fixed + ~27 reviewed AssertFatal sites on the
wire path. For each, locate the 1.40 analog (same method via RTTI vtable / structure, as done for the AI fix) and
confirm guarded vs not. The reconstructed source NAMES them — use it to drive 1.40 location.

## Pattern C — reverse the rest of Bov's ServerSidePlugin patches
ServerSidePlugin patched T1Vista at 0x43ffee (done), **0x43bff4 (AIJet)**, **0x40be84**, **0x40cd4e**,
**0x550cc8/0x550ccd** — these are more AI/related fixes (re/aipatch.txt has the installers; decompile T1Vista at
each + the plugin handlers, like the main one). Port the genuinely-crash ones to 1.40 (same semantic-match
method). Also triage CommLink/DoSFix/PatchesPlugin for any real guards (most are features — quick check).

## Pattern D — array-index / bounds (the other untrusted-input crash class)
Wire fields used as array indices without bounds checks: `readInt(N)` results indexing fixed arrays (team/client
id, ghost idx, datablock group, anim index). Grep decompiles for `[base + reg*scale]` where reg is a recent
`readInt`. (TeamId, ClientId, ghost idx are the usual suspects.)

## Pattern E — dynamic fuzz (catches what static misses)
Extend `run-replay-tests.ps1` / the enginepstream decode harness ([[wire-format-regression-tests]]) to FUZZ
captured packets — mutate wire fields to out-of-range values (groups>NumDataTypes, unregistered tags, ghost idx
beyond scope, oversized counts) and run them through the REAL PacketStream/EventManager/Ghost decode; any
AV/abort = a vector. CI-able, reproducible, no live server needed.

## Order of attack
1. Pattern A on `Persistent::create` + `resolveGhost` callers → finish RemoteCreate/Player/Lightning + find new ones.
2. Pattern C (Bov's other AI patches — directly "related to that").
3. Pattern B (the catalog → 1.40 sweep).
4. Pattern D/E for breadth.
Each fix = a detour NULL-guard / bounds-clamp to Tribes.exe (with the Tribes.exe.orig backup), verified live.

## Immediate next batch (already located, need detours)
- RemoteCreateEvent::unpack `0x517d00` — Persistent::create NULL; whole if-body uses the ptr → guard = NULL→set
  `Net::setLastError("Invalid packet.")`@0x517EF0 + return (not just skip one deref).
- Player::unpackUpdate `0x4bc8c0` + Lightning::unpackUpdate `0x4c68b0` — resolveGhost NULL in flag-gated branches
  (pin the exact deref instr via Ghidra, then detour-skip the apply block).
