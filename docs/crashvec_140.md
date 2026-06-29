# 1.40 crash-vector locations (for the crashFix plugin)

Our catalog wire-data crash vectors (from `re/crash_vectors.md`), located in `Tribes 1.40.655\Tribes.exe`
(MSVC2005, base 0x400000, no ASLR → addresses are stable). Each is an unchecked deref of a function result
that can be NULL on hostile/desynced wire data. Decompiles + disasm: `re/crashvec.txt`.

| Vector | Fn @ | NULL source | **Crash instr** | Safe skip target | Reg |
|---|---|---|---|---|---|
| DataBlockEvent::unpack | 0x434fa0 | `createDataBlock(group)` = `FUN_00434890` (NULL if group has no case) | **0x435037** `MOV EDX,[EAX]` | 0x435041 (epilogue: pops + `[ESI+0x14]=0x2d1` + ret 0xc) | EAX |
| Net::RemoteCreateEvent::unpack | 0x517d00 | `Persistent::create(tag)` = `FUN_004131e0` (NULL if tag unregistered) | deref right after `CALL 0x4131e0` @0x517d23 (`(*piVar3+0x68)`) | function epilogue / ret | EAX |
| Player::unpackUpdate | 0x4bc8c0 | `resolveGhost(idx)` NULL on MountMask branch | in the mount/ghost branch (pin during build) | skip the mount-apply block | TBD |
| Lightning::unpackUpdate | 0x4c68b0 | `resolveGhost(idx)` NULL ×2 (readInitialPacket + TargetChangedMask) | in the flag-gated branches (pin during build) | skip the apply block | TBD |

Plus the already-handled **ServerListCtrl::onAdd** NULL bitmap deref @0x46d867 (fixed via converted assets, but
the general guard belongs here too).

## Hook mechanism (decided)
TribesXT `x86Hook` (`src/nofix/x86Hook.{h,cpp}`) — gives a handler `CpuState{reg,eflag}` + an alternate-return
`ret` + `NOINSTRUCTION`/`BEFORE` opts. For a **conditional** NULL-skip, the clean form is a small **detour**: at
the crash instr, JMP to a cave doing `TEST reg,reg; JZ <skip>; <relocated original>; JMP <back>` — the
conditionality lives in the cave, not the handler. (x86Hook's handler-modifies-flags style suits the
ServerList/console fixes; the create/resolveGhost NULL-skips want the detour form.) Properly, the NULL branch
should also `Net::setLastError("Invalid packet.")` (0x517EF0) so the stream disconnects cleanly instead of
desyncing — same as the reconstructed-source fix.

## Plan
1. (agent, running) reverse `mem.dll` → full Kronos patch list + the patch/detour style → `re/memdll_patches.md`.
2. Pin Player/Lightning resolveGhost crash instrs (need resolveGhost's addr — the agent may surface it).
3. Build ONE crashFix plugin: detour guards for catalog vectors + the applicable mem.dll patches, injected via
   `xtloader` (proven). Then iterative gameplay testing (each guard verified live).

## *** STATUS — wire-crash hunt COMPLETE (Patterns A + B done) ***
All FIVE source-catalog (re/crash_vectors.md) wire-crash vectors are addressed in stock 1.40:
- **DataBlockEvent::unpack** — ✅ PATCHED (detour @0x435037 → cave, createDataBlock-NULL skip).
- **RemoteCreateEvent::unpack** — ✅ PATCHED (detour @0x517d34 → cave, Persistent::create-NULL skip+ret).
- **Player::unpackUpdate mount** — ✅ already GUARDED in 1.40 (FUN_004bc8c0 @0x4bca38): getGhost result stored as
  the NEW mount without deref; deleteNotify (0x51d890) runs on the OLD mount which IS guarded (TEST/CMP+JZ). The
  catalog's "deleteNotify(newMount) crash" doesn't exist in the shipping binary's structure.
- **Lightning readInitialPacket + unpackUpdate** — ✅ already GUARDED (FUN_004c68b0 @0x4c6a3e: getGhost→cast
  (0x5ac26b)→CMP/TEST+JZ).
GuardScan (re/guardscan.txt) proved getGhost(0x517eb0)/Persistent::create(0x4131e0)/createDataBlock(0x434890)
have NO other unguarded wire derefs. EventManager::readPacket (FUN_00517490) audited (re/decompone.txt): create
GUARDED ("Invalid packet."), getGhost NULL-checked, the do/while(true) event loop is STREAM-BOUNDED (each iter
consumes ≥1 bit of a finite buffer → no wire-driven infinite loop), ghost idx bounded by bit-width = array size
(no OOB). The catalog "safe by design" list (readString cap 255, GhostManager idSize≤10, DeltaScore findTeam
null-check, setTeamObjective bounds) all hold in 1.40. CONCLUSION: 1.40's shipping wire decode is hardened; the
only 2 genuine gaps (DataBlock, RemoteCreate) are now patched. Residual NON-wire item: GFXBitmapArray::getBitmap
OOB (FearGuiShellBorder, render-side, needs a malformed GUI/skin asset not a packet) — only thing left in the
catalog, lower priority. Hang surface = the float-clock freeze (fixed, re/freeze_fix_13.md + freezefix.dll); no
other wire-driven infinite loop found (packet loops are all finite-buffer-bounded).
