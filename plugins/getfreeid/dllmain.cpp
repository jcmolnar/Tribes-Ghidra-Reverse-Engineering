//============================================================================
// dllmain.cpp — minimal plugin entry for the getFreeIdNative proof.
//
// xtloader.exe injects this DLL only AFTER the engine's Console (*0x6E284C) is
// non-NULL (it polls for exactly that), so the console is ready at attach time.
// We register the command directly in DllMain — the same pattern TribesXT's own
// main.cpp uses (SimGame::registerPlugin / Console->printf at DLL_PROCESS_ATTACH).
//
// NOTE (caveat): registration runs on the injected LoadLibrary thread, not the
// game's main thread. For a one-shot console-command insert on an idle (menu)
// game this is fine and matches TribesXT; a production plugin doing heavier work
// should defer to the main thread (hook a per-frame tick) instead.
//============================================================================
#include <windows.h>

// Defined in getFreeIdNative.cpp (standalone "raw" path, built without /DTRIBESXT):
void registerGetFreeIdNative_raw();

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID /*reserved*/)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinst);
        registerGetFreeIdNative_raw();   // adds "PlayerManager::getFreeIdNative" to the console
    }
    return TRUE;
}
