# Tribes 1.40.655 ↔ our reconstructed tree — three-way diff (sizing the delta)

Sources: Ghidra-RTTI catalog `re/full_catalog_140.txt` (834 classes, 44 SimEvent wire formats) ·
TribesXT RE'd headers · our `engine/`+`program/` tree · T1Vista catalog `re/full_catalog.txt`.

## Verdict (the answer to "how big is the delta / is a recompile worth it")

**Small and well-bounded.** The entire *networked* object model — events, datablocks, ghost objects,
the DNet/Net stack, PlayerManager/PlayerPSC/FearCSDelegate — is the **same set of classes** in 1.40 as
in our tree, with the same hierarchy. What actually changed:
1. **Version-gated wire field widths** inside those classes (the netcode `(1,1)` bump). Concrete, finite.
2. **Added non-wire subsystems** (matchmaking/NAT, XML, Ogg) that are irrelevant to a relay-based connect.

So updating our buildable tree to speak 1.40 is a **targeted field-width pass**, not a rewrite.

## Class inventory: three buckets (834 RTTI classes in 1.40)

**A. Shared core (present in both — the whole protocol surface):**
- Net stack: `Net::CSDelegate`, `Net::EventManager`, `Net::GhostManager`, `Net::PacketStream`,
  `Net::RemoteCreateEvent`, `DNet::{Session,Transport,UDPTransport,UDPVC,VC,LOOP*}`.
- All 44 SimEvents (see catalog) incl. every gameplay event: `TeamAddEvent`, `PlayerAddEvent`,
  `PlayerRemoveEvent`, `DeltaScoreEvent`, `PlayerTeamChangeEvent`, `PlayerSayEvent`, `TargetNameEvent`,
  `PlayerSkinEvent`, `PlayerSelectCmdrEvent`, `PlayerCommandEvent`, `DataBlockEvent`, `MissionResetEvent`,
  `LocSoundEvent`, `VoiceEvent`, `SoundEvent`, `PingPLEvent`, `TeamObjectiveEvent`.
- Full datablock + ghost hierarchy: `GameBase(Data)`, `ShapeBase(Data)`, `StaticBase(Data)`, `Player(Data)`,
  `Item(Data)`, `ItemImageData`, `Vehicle(Data)`, `Flier/Tank≈Moveable(Data)`, `Projectile(Data)`,
  `Bullet/Grenade/RocketDumb/SeekingMissile/Laser/TargetLaser/Lightning/Mine/Marker/Debris/Explosion/Trigger/
  Turret/Sensor/StaticShape/RepairEffect` + their `*Data`, `SoundData/SoundProfileData/DamageSkinData`.
- `PlayerManager`, `PlayerPSC`, `FearCSDelegate`, `DataBlockManager`, the SimGui + FearGui control trees,
  Ts3 (`TS::Shape/ShapeInstance/...`), Interior, Terrain, the **AST console** (`ASTNode`/`*ExprNode` — our
  `engine/console/ast.h`+`gram.y` already match this; NOT a delta).

**B. 1.40-only (added; confirmed 0 occurrences in our `engine/`):**
- **Matchmaking/NAT publishing**: `GGConnectInterface::*`, `_GGConnect*`, `GGCEvent*`,
  `InternalPublishing::Torque::*`, `Publishing::{NatTunnelImpl,nat_discovery_client_harness,
  turn_connection_client_harness}`, `IAGame/IARuntime/Tribes2IA`. (GGConnect API 0.7.0.0.)
- **TinyXML**: `TiXml{Document,Element,Node,Attribute,...}` (server list / config).
- **Ogg audio**: `OggVorbis::ResourceTypeOggFile`.
- Modern GL: `OpenGL::{FBO,RenderTextureFBOManager,RenderTextureGenericManager}` (our port targets WebGL
  separately, so N/A).
- Misc newer: `Processor_SSE`, AI bots (`AI::*`), mission-lighting/editor tools (`ITR*`, `ME*`, `Inspect*`).
→ **None are on the join/play wire path.** A relay-based client never invokes GGConnect/NAT (that's master
  discovery + NAT punch; we use the WS relay). They only matter if we want in-client server browsing/voice.

**C. Our-tree / port-only:** the WASM shims, the relay seam (`UDPNet.cpp`), the deferred Win32/Glide/movPlay
stubs — orthogonal to 1.40.

## The real deltas: version-gated wire formats (netcode `(1,1)`)

1.40 gates several reads on `serverNetcodeVersion` (the global at **`0x6D0FF8`**, byte-swapped to a uint16
and compared to `0x101` = version `(1,1)`). This is exactly TribesXT's `Netcode::New = (1,1) // 1.40`.

**Confirmed delta — `DataBlockEvent::unpack` (`0x434fa0`):**
```c
group = readInt(6);
if (serverNetcodeVersion < 0x101) {        // OLD servers (incl. the live Kronos the port decodes today)
    id = readInt(8);  block = readInt(8);   // 8-bit, sentinel 255
} else {                                     // 1.40 servers
    id = readInt(32); block = readInt(32);   // 32-bit, no 255 sentinel
}
```
→ Explains why the port's 8-bit datablock decode synced live (those servers are pre-1.1). A real 1.40
  server needs the 32-bit branch. **Action:** make the port's datablock-header decode version-aware.

**COMPLETE netcode-gate inventory (binary-wide):** `FindGates140.java` found **every** function that reads
`serverNetcodeVersion (0x6D0FF8)` / `ourNetcodeVersion (0x6D0FFC)` — exactly **10** (decompiles in
`re/version_gates_140.txt`). The datablock/ghost `unpackUpdate` sweep (`re/ghostcat_140.txt`, 27 datablocks +
20 ghosts) found **zero** gates — those payloads are single-format and match the port's mirror stubs
(`GameBaseData::unpack` = `readSignedInt(8)` mapFilter + 2 strings; `ShapeBaseData::unpack` = Parent + 3×
`readInt(8)-1` blockIds + `readInt(32)` + 16-iter sequence loop). So the 10 gates are the whole story:

| Fn | What | Wire? |
|---|---|---|
| `0x434fa0` | **DataBlockEvent::unpack** — id/block `readInt(8)`(+255 sentinel) vs `readInt(32)` | ★ READ — port must branch |
| `0x443360` | **client Accept handler** — 2nd id high-bit flags version, then `readInt(8)`+`readInt(8)`=major/minor → sets serverNetcodeVersion (else old) | ★ READ — how client learns server is 1.40 |
| `0x519d00` | **PacketStream connect framing** — serializes version byte (write mode2 / read mode3) | ★ framing for the above |
| `0x443c80` | **server onConnectionRequest** ("requires version 1.40") — writes `ourNetcodeVersion(8)+(8)` into accept, reads client ver | server-side (port reads its output) |
| `0x482e30` | **PlayerPSC::writePacket** — extra gated field when sending moves | only once spawned/playing |
| `0x45be50,0x4e7d30,0x4acdd0,0x4e7b90,0x4aca90` | observer-cam / damage-flash / movement-smoothing | ✗ client behavior, NOT on wire |

**Net:** to connect a client to a stock 1.40 server, the wire deltas are just (1) read the server netcode
version from the accept packet's high-bit-flagged 2nd id, and (2) switch DataBlockEvent id/block to 32-bit
when that version ≥ (1,1). PlayerPSC adds one field only when actively sending moves. Everything else is
client-side behavior. The subtick/lag-comp/clock-sync in TribesXT's `netXT/version.h` are its OWN `(1,2)`
additions (in `playerPSCXT.cpp`), NOT vanilla 1.40 — feature names: subtick input, lag
compensation, clock sync, client projectiles, tracer inheritance, `GameBaseDataSendClassName`,
`ProjectileDataSend*`, `ItemImageDataSendAccuFire`, `SendCurrentPlayerState` — but note most of those are
TribesXT's **own** `(1,2)` additions, not vanilla `(1,1)`; for stock 1.40 only the `(1,1)` gates apply.

## Event catalog status

44 SimEvent `unpack`/`pack` decompiled in `re/full_catalog_140.txt`. Slot map (verified): SimEvent vtable
**slot 6 = pack, slot 7 = unpack**; `readInt=FUN_0040fd10(bits)`, `writeInt=FUN_0040fd50(v,bits)`,
StreamIO vtbl `+0x1c read(n,&dst)` / `+0x28 readString` / `+0x2c writeString`. Spot-checked
PlayerSay/TeamObjective/DeltaScore/TeamAdd vs the port's mirror stubs → match (modulo decompiler thiscall
arg-loss on the stream-vtable indirect calls; for byte-exact widths on a noisy one, read the disassembly).

## What this means / next actions

- **Ref goal — essentially met.** 1.40 is now a far better reference than T1Vista (RTTI names + correct
  protocol version), catalogued and diffed. Immediate port win: add the netcode-version gate to the
  datablock decode (and sweep for other `0x6D0FF8` gates).
- **Recompile goal — feasible, and the delta is small.** Path = take the buildable `Tribes Native Build`
  tree (already an exe), confirm-or-patch the networked unpacks against this catalog, and decide whether to
  stub or port the GGConnect/NAT layer (stub is fine for relay-based connect). No engine rewrite needed.
- **Open:** decode the per-field widths of the remaining events where the decompiler lost args (disasm a
  handful), and locate the datablock/ghost `unpackUpdate` slots (next Ghidra pass, same method as the
  SimEvent slot ID).
