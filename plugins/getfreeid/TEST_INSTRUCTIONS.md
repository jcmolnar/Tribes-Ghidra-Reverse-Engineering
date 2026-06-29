# Live test — getFreeIdNative plugin on Tribes 1.40.655

This is the end-to-end proof: an injected DLL that adds a console command bound to the **1.40.655**
addresses we reverse-engineered. Two 32-bit artifacts (match the 32-bit `Tribes.exe`):
- `xtloader.exe`        — launches `Tribes.exe`, waits until the engine boots, injects the DLL
- `getFreeIdNative.dll` — registers console command `PlayerManager::getFreeIdNative`

Both have also been copied into `C:\Users\Joe\Desktop\Tribes 1.40.655\` so you can run from there directly.

## Run it

1. Open a terminal in `C:\Users\Joe\Desktop\Tribes 1.40.655\`.
2. Launch + inject:
   ```
   xtloader.exe Tribes.exe getFreeIdNative.dll
   ```
   `xtloader` starts Tribes, polls the engine `Console` global (`*0x6E284C`) until non-NULL = engine up,
   then `CreateRemoteThread(LoadLibraryA)` to load the DLL. Its `DllMain` registers the command.
   - You should see in xtloader's console: `LoadLibraryA returned <non-zero>` (success). A NULL return
     means the DLL wasn't found / wrong arch / DllMain failed.

3. In the game, open the console and verify the command exists and runs:
   ```
   echo(PlayerManager::getFreeIdNative());
   ```
   - **Hosting a server** (Create Server / LAN, or dedicated): returns the next free client id (e.g. `2049`).
     That is the live proof — it read the real server `PlayerManager` at `*0x6D5054` + `clientFreeList @ +0x344F8`.
   - **Not hosting** (plain client at menu): returns `-1` (no server PlayerManager) — that still proves the
     command registered and ran; host to get a real id.

## What "success" looks like
- The command is recognized (no "Unknown command"), and returns `-1` as a client or a real id (≥2049) when hosting.

## Notes / caveats
- Registration runs from the injected thread in `DllMain` (same pattern TribesXT uses). Fine for this idle
  one-shot; a production plugin would defer engine calls to the main thread.
- To remove: delete `xtloader.exe` + `getFreeIdNative.dll` from the Tribes folder. Nothing else is touched.
- If injection is blocked (AV flags `CreateRemoteThread`), allow-list `xtloader.exe`, or use the
  `opengl32.dll` proxy alternative in `re/injector/`.
- Rebuild the DLL anytime: `re/plugin_proof/build_plugin.bat` (x86 MSVC). Injector: `re/injector/build.bat`.
