//============================================================================
// getFreeIdNative.cpp  —  PROOF: GetFreeIdPlugin.cpp rebound to Tribes 1.40.655
//
// Registers the console command  PlayerManager::getFreeIdNative  which returns
// the next free client id from the server PlayerManager, i.e. the engine's own
//   PlayerManager::getFreeId()  ==  return clientFreeList[0].id;
//
// All addresses/offsets are the 1.40.655 values resolved in
//   re/playermanager_offsets.md  (read out of Tribes.exe via Ghidra, ground truth):
//     server PlayerManager singleton  = *(PlayerManager**)0x6D5054
//     clientFreeList member offset     = +0x344F8   (holds a ClientRep*)
//     ClientRep.id (BaseRep::id)        = +0x00
//   (OLD Borland 0x6A842C / 0x24E2C are gone in 1.40 — do NOT use them.)
//
// Drop this into a TribesXT-style plugin (the framework provides Console,
// addCommandXT, CMDConsole) and call registerGetFreeIdNative(Console) from your
// plugin's init().  A raw-addCommand fallback (no TribesXT headers) is at the
// bottom so this also compiles as a standalone injected DLL.
//============================================================================

#include <cstdio>

//----------------------------------------------------------------------------
// 1.40.655 engine layout — the only three constants the command needs.
//----------------------------------------------------------------------------
static constexpr unsigned long PM_SERVER_GLOBAL = 0x6D5054;  // *(PlayerManager**)
static constexpr unsigned long OFF_clientFreeList = 0x344F8;  // PlayerManager::clientFreeList (ClientRep*)
static constexpr unsigned long OFF_BaseRep_id     = 0x000;    // ClientRep.id (first member)

// Robust fallback path (version-independent): reach the manager via sg, find the
// PlayerManager by its well-known id, and sanity-check its vtable.
static constexpr unsigned long SG_MANAGER       = 0x6D5034;   // *(SimManager**)  == sg.manager
static constexpr unsigned long PlayerManagerId  = 0x2c9;      // 713
static constexpr unsigned long PM_VTABLE        = 0x65d3fc;   // PlayerManager::vftable
static constexpr unsigned long SimManager_findObject_vtslot = 0x68; // (**(mgr+0x68))(id)

//----------------------------------------------------------------------------
// Resolve the server PlayerManager*. Primary = hard global; if null, fall back
// to sg.manager->findObject(PlayerManagerId) and verify the vtable.
//----------------------------------------------------------------------------
static void *resolvePlayerManager()
{
    void *pm = *reinterpret_cast<void **>(PM_SERVER_GLOBAL);
    if (pm != nullptr)
        return pm;

    // Fallback: sg.manager->findObject(0x2c9)
    void *mgr = *reinterpret_cast<void **>(SG_MANAGER);
    if (mgr == nullptr)
        return nullptr;

    using FindObject = void *(__thiscall *)(void *self, int id);
    void **mgrVtbl  = *reinterpret_cast<void ***>(mgr);
    FindObject findObject =
        reinterpret_cast<FindObject>(mgrVtbl[SimManager_findObject_vtslot / sizeof(void *)]);

    void *obj = findObject(mgr, static_cast<int>(PlayerManagerId));
    if (obj == nullptr)
        return nullptr;

    // Verify it really is a PlayerManager (cheaper than a full RTTI dynamic_cast).
    if (*reinterpret_cast<unsigned long *>(obj) != PM_VTABLE)
        return nullptr;

    return obj;
}

//----------------------------------------------------------------------------
// The actual logic: PlayerManager::getFreeId()  ==  clientFreeList[0].id
//----------------------------------------------------------------------------
static int getFreeId()
{
    void *pm = resolvePlayerManager();
    if (pm == nullptr)
        return -1;                                  // no server PlayerManager (not hosting?)

    // clientFreeList is a ClientRep* stored at pm + 0x344F8.
    void *freeRep =
        *reinterpret_cast<void **>(reinterpret_cast<char *>(pm) + OFF_clientFreeList);
    if (freeRep == nullptr)
        return -1;                                  // free list exhausted

    // ClientRep.id == BaseRep::id == first member (offset 0).
    return *reinterpret_cast<int *>(reinterpret_cast<char *>(freeRep) + OFF_BaseRep_id);
}

//============================================================================
// (A) Idiomatic TribesXT registration.
//     addCommandXT marshals args/return automatically; getFreeId() takes no
//     args and returns int, so the script command "PlayerManager::getFreeIdNative"
//     returns the id as a string.  Call this from your plugin's init().
//
//     #include "util/tribes/console.h"     // addCommandXT, CMDConsole, Console
//============================================================================
#if defined(TRIBESXT)   // define when building inside the TribesXT tree
#include "util/tribes/console.h"

void registerGetFreeIdNative(CMDConsole *console)
{
    addCommandXT<"PlayerManager::getFreeIdNative", &getFreeId>(console);
}
#endif

//============================================================================
// (B) Standalone fallback — raw Console->addCommand, no TribesXT headers.
//     Mirrors the original GetFreeIdPlugin.cpp callback ABI, rebound to 1.40:
//        Console global               = *(void**)0x6E284C
//        CMDConsole::addCommand        = 0x403600  (__thiscall)
//        Callback = const char*(__cdecl*)(void* console,int id,int argc,const char** argv)
//============================================================================
#if !defined(TRIBESXT)

typedef const char *(__cdecl *ConsoleCallback)(void *console, int id, int argc, const char **argv);
typedef void(__thiscall *AddCommandFunc)(void *console, int id, const char *name,
                                         ConsoleCallback cb, int privilegeLevel);

static constexpr unsigned long ADDR_ConsoleGlobal = 0x6E284C;   // *(void**)
static constexpr unsigned long ADDR_addCommand    = 0x403600;

static const char *__cdecl c_getFreeIdNative(void *console, int id, int argc, const char **argv)
{
    (void)console; (void)id; (void)argc; (void)argv;
    static char buf[16];
    std::sprintf(buf, "%d", getFreeId());
    return buf;
}

// Call once after the engine is up (e.g. from your injector's _open / DllMain
// post-init), with the live Console.
void registerGetFreeIdNative_raw()
{
    void *console = *reinterpret_cast<void **>(ADDR_ConsoleGlobal);
    if (console == nullptr)
        return;
    AddCommandFunc addCommand = reinterpret_cast<AddCommandFunc>(ADDR_addCommand);
    addCommand(console, 0, "PlayerManager::getFreeIdNative", &c_getFreeIdNative, 0);
}

#endif
