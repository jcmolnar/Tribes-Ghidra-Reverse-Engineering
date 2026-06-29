# Getting Kronos running on the Tribes 1.40 base

## What Kronos actually is (3 layers)

From `C:\Users\Joe\Desktop\Kingdom of Kronos V0.8.1 Development\`:
1. **Server-side scripts + assets** — the bulk of the RPG (NPCs, quests, economy, the v0.8.5 Las Vegas
   gambling district) is TorqueScript `.cs` (`LasVegas.cs`, `comchat.cs`, …) + `.vol`/`.dts`/skins in `base/`.
2. **Native server-side plugin DLLs** — `Plugins/`: `PlayerManagerPlugin.dll`, `MathPlugin.dll`,
   `StringPlugin.dll`, `ServerSidePlugin.dll`, `CommLinkPlugin.dll`, `BovExpansionPlugin.dll`, `DoSFix.dll`,
   etc. They add console commands (`Player::setJet/getPitch/setGravity`, `AStar::find_path`, `String::Create`,
   `Math::*`) and engine-level fixes. Compiled against the **OLD Borland binary's exact addresses**
   (`sg.playerManager 0x006A842C`, `Console 0x6E284C`, `addCommand 0x403600`). Source in `TribesSource/`.
3. **Custom-compiled client** — `TribesSource/` (Borland `Tribes.vcxproj`) builds the Kronos `Tribes.exe`
   (= T1Vista, "requires version 1.30").

Model (per `Plugins/ServerSidePlugin.txt`): **server-side** — "The client can have a standard 1.11 and still
join!" So most of Kronos is server logic; clients are near-stock + the RPG HUD scripts (KHudOn).

## Why it doesn't "just run" on 1.40 — the blockers

- **No native-DLL plugin loader in stock 1.40.** The install is just `Tribes.exe`/`Editor.exe`/
  `MissionLighting.exe` — no `plugins/` dir, no loader/injector, no `.dll` refs in scripts. Stock 1.40 loads
  only scripts + `.zip`/`.vol` volumes. → layer-2 plugins can't load at all.
- **Old plugins are binary-pinned.** Even injected, they hardcode old-Borland addresses; the 1.40 MSVC binary
  has a totally different layout. → must be rebound to 1.40 addresses.
- **Asset format drift.** 1.40 reads `.vol` AND `.zip`, but **dropped Phoenix bitmap support** ("Phoenix
  bitmaps are not supported!"). → old skins/textures (PBMP/Phoenix) need reconversion (the
  "RPG Skins Upscaler to PBMP" + `batch_convert.py` work already in the Kronos folder).
- **Version gate.** 1.40 server rejects <1.40 ("requires version 1.40"); old Kronos server rejects ≠1.30.
  Mutual. Mooted if the Kronos *server* runs on the 1.40 engine. (Cross-version client↔server is the separate
  netcode-bridge in `re/diff_140.md`.)

## The fix path (decomposed by effort)

| Layer | Effort | How |
|---|---|---|
| Assets (`.vol`/`.dts`/skins) | LOW | 1.40 reads `.vol` directly. Reconvert Phoenix/PBMP bitmaps (tooling already in the Kronos folder). |
| Server scripts (`.cs` RPG logic) | MED, mechanical | Copy into a 1.40 mod (`<mod>/<mod>.zip` + `<mod>.cs`, `-mod`). Fix 1.30→1.40 console-API deltas (function name/sig changes). Both versions use the AST script VM, so semantics carry. |
| Native plugins (`PlayerManager`/`Math`/`String`/`ServerSide`/…) | HIGH | **Port onto the TribesXT framework** — rewrite each as a TribesXT plugin, rebinding the hardcoded addresses to 1.40's actual layout. This is already underway (`PlayerManagerXT`). Many plugins only *register console commands*; those can be consolidated into ONE TribesXT plugin, or (where logic is simple) converted to **script addons** (as `getFreeId`→`support_getFreeId.cs` already was — version-independent). |
| Client | LOW | Server-side model = stock-ish 1.40 client joins. RPG HUD = client scripts/assets, portable. |

## The leverage you already have

- **TribesXT** = the 1.40 plugin loader/framework + RE'd 1.40 class layouts (`src/darkstar`, `src/tribes`) +
  hook utilities (`util/hooks.h`). This is the binding layer the ported plugins need.
- **Kronos plugin SOURCE** (`TribesSource/PlayerManagerPlugin.cpp`, `GetFreeIdPlugin.cpp`, …) = the logic.
- **Our Ghidra work** (`re/full_catalog_140.txt`, `re/ghostcat_140.txt`, `re/version_gates_140.txt`,
  `re/diff_140.md`) = 1.40 ground-truth addresses/layouts/wire formats the plugins bind against.

## How plugins load on 1.40 (the loader question — answered)

**Neither 1.40 nor T1Vista has a built-in native-plugin loader.** Byte-scan of both binaries: no `_open`/
`_close` export ABI, no `Plugins\%s.dll` path string, no `PluginLoader`. The `_open`/`_close` exports in
`GetFreeIdPlugin.cpp` and Kronos's `PluginLoader.cs`/`$PluginLoader::X` flags target a loader that is **not in
the engine** — so native plugins are loaded by an **external injector/launcher** shipped with the plugin
distribution (a launcher that `LoadLibrary`-injects, or a proxy/hijack DLL), NOT by the game. Confirms
`support_getFreeId.cs`: "native DLL injection is **blocked by the specific T1Vista executable**" — i.e. their
current build resists injection, so they fall back to scripts. (1.40's only 2 `LoadLibrary` sites are for
GL + `mscoree`/.NET=GGConnect, not plugins.)

TribesXT (github.com/AltimorTASDK/TribesXT) is plugin **source only** — its DllMain runs `SimGame::
registerPlugin` once injected, but the **injector ships separately**. So step 0 for ANY native plugin on 1.40
is a working injector for the 1.40.655 build. (TribesXT's own loader, or a generic LoadLibrary injector /
proxy DLL targeting Tribes.exe.)

## OLD → 1.40 plugin binding map (template: getFreeId / PlayerManager)

TribesXT has already RE'd most 1.40 addresses the Kronos plugins need — porting is mostly re-pointing:

| Symbol | Kronos/old note | 1.40 (TribesXT-confirmed) | Status |
|---|---|---|---|
| `Console*` global | 0x6E284C | `*(CMDConsole**)0x6E284C` (console.h:137) | ✓ identical |
| `CMDConsole::addCommand` | 0x403600 | 0x403600 (console.h:87) | ✓ identical |
| `printf` / `printf(color)` | — | 0x4039B0 / 0x403A10 | ✓ have |
| `addVariable` | — | 0x403500 / 0x403560 | ✓ have |
| `findPlayerObject(name)` | — | 0x489200 (console.h asm) | ✓ have |
| `sg` server globals | — | `*(WorldGlobals*)0x6D5020` (worldGlobals.h) | ✓ have |
| PlayerManager pointer | `*0x006A842C` | verify in Ghidra (refs to 0x6A842C) or get via `sg.manager`→find by id | ⚠ resolve |
| `clientFreeList` offset | 0x24E2C (MaxTeams=9) | recompute via `offset_calc.cpp` with 1.40's MaxTeams + ClientRep/TeamRep layout | ⚠ resolve |

Recipe per plugin command: `addCommandXT<"Player::setGravity", &handler>(Console)` (TribesXT
`util/tribes/console.h` already provides the templated registrar with arg marshalling) → inside the handler,
read/write engine objects via TribesXT's `FIELD(off,...)` layouts (player.h/playerPSC.h) or `JmpHook` an engine
function. Most Kronos plugin commands (`Player::setJet/getPitch/setGravity`, `String::*`, `Math::*`) are exactly
this shape. (Note: pure-data commands like `getFreeId` don't even need a plugin — already done in
`support_getFreeId.cs` via `Client::getName`/`getOwnedObject`.)

## Recommended first step

Pick **one** native plugin and port it to TribesXT as the template — `ServerSidePlugin` (self-contained:
registers `Player::setJet/getPitch/setGravity`, `CollisionCallback::Mask`, `AStar::find_path`) is a good
first target because it's pure console-command registration + Player field access, and TribesXT already RE'd
`Player`/`PlayerPSC`. Steps: read `TribesSource/<plugin>.cpp` → map each old hardcoded address/offset to its
1.40 equivalent via the Ghidra catalog → re-express as TribesXT `JmpHook`/`FIELD`/`addCommand` → build the
DLL → load via the TribesXT loader → verify the console commands appear. That proves the pipeline; the rest
follow the same recipe. (First, confirm how the TribesXT *loader/injector* gets the DLL into the 1.40 process
— the repo here is plugin source only; the loader is part of the TribesXT distribution.)
