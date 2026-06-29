//============================================================================
// freezefix.cpp — 1.40 dedicated-server "3-day freeze" fix, as an injected plugin.
//
// ROOT CAUSE (see re/freeze_fix_13.md): the sim/event clock is a 32-bit float in
// seconds (SimTime). The server loop feeds advanceToTime((currentTime-timeBase)*0.001),
// a value that grows with uptime. At ~2^18 s (3.03 days) the float's ULP (~0.0156 s)
// exceeds the smallest reschedule interval (Kronos uses 10 ms schedules), so a
// self-rescheduling event's new time == current time in float -> pop returns it every
// iteration -> infinite loop inside advanceToTime holding the sim lock -> total freeze.
//
// FIX: bound the float clock. We hook the server loop's advanceToTime call site
// (0x4e8feb, the ONE `CALL 0x0051e710` in FUN_004e8ee0). Each call, if the float time
// exceeds THRESHOLD (~1h), we shift the sim clock + EVERY queued event back by the same
// delta (preserving all relative timings -> nothing fires early), bump sg.timeBase to
// match, and rewrite the incoming time arg, then tail-call the real advanceToTime. The
// float clock thus stays in ~[1s, 3600s] forever -> ULP << tick -> can never freeze.
//
// Pinned 1.40 layout (Ghidra, re/disasm_freeze.txt):
//   advanceToTime = 0x0051e710 (__thiscall: ECX=SimManager, [ESP+4]=float time)
//   SimManager:   targetTime @ +0x78 (float),  eventQueue @ +0x7c
//   eventQueue:   size @ +0x00 (int),  array @ +0x10 (SimEvent**),
//                 currentTime @ +0x14 (float),  csQueue @ +0x1c (CRITICAL_SECTION)
//   SimEvent:     time @ +0x0c (float)
//   server loop call site = 0x4e8feb (E8 + rel32 -> 0x0051e710), return = 0x4e8ff0
//   globals: sg.currentTime = *0x6D5024,  sg.timeBase = *0x6D5028
//============================================================================
#include <windows.h>
#include <cstdio>

// --- tunable: rebase once the float clock passes this many seconds. 3600 (1h) keeps the
//     float ULP ~0.0004s, far below the 10ms tick. Lower it (e.g. 30.0f) to verify a
//     rebase fires within seconds on a live test server. ---
#ifndef FREEZE_THRESHOLD
#define FREEZE_THRESHOLD 3600.0f
#endif

static const unsigned CALL_SITE   = 0x004e8feb;  // the E8 of `CALL advanceToTime`
static const unsigned RET_ADDR    = 0x004e8ff0;  // instruction after the call
static const unsigned REAL_ADVANCE= 0x0051e710;  // SimManager::advanceToTime
static const unsigned SG_CURTIME  = 0x006d5024;
static const unsigned SG_TIMEBASE = 0x006d5028;

static void flog(const char* fmt, ...)
{
    FILE* f = fopen("freezefix.log", "a");
    if (!f) return;
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fputc('\n', f); fclose(f);
}

// The actual rebase. Runs on the server loop thread, just before advanceToTime.
extern "C" void __cdecl freeze_rebase(unsigned mgr, float* argp)
{
    float t = *argp;
    if (t <= FREEZE_THRESHOLD) return;            // common case: do nothing

    float  shift = t - 1.0f;                      // keep a 1s margin
    unsigned eq  = mgr + 0x7c;
    CRITICAL_SECTION* cs = (CRITICAL_SECTION*)(eq + 0x1c);

    EnterCriticalSection(cs);                     // same lock pop()/insert() use
    int      size = *(int*)(eq + 0x00);
    char**   arr  = *(char***)(eq + 0x10);        // SimEvent**
    for (int i = 0; i < size; ++i)
        *(float*)(arr[i] + 0x0c) -= shift;        // event->time
    *(float*)(eq + 0x14) -= shift;                // eventQueue.currentTime
    LeaveCriticalSection(cs);

    *(float*)(mgr + 0x78) -= shift;               // SimManager::targetTime (main-thread)
    *(unsigned*)SG_TIMEBASE = *(unsigned*)SG_CURTIME - 1000;  // keep 1s of ms
    *argp = t - shift;                            // = 1.0  (corrected time for this call)

    flog("rebase: t=%.3f shift=%.3f events=%d -> newClock=%.3f newTimeBase=%u",
         t, shift, size, *argp, *(unsigned*)SG_TIMEBASE);
}

// __thiscall trampoline: entered via the patched CALL. ECX=SimManager(this),
// [ESP]=return addr (0x4e8ff0), [ESP+4]=float time arg. We rebase if needed, then
// tail-jmp into the real advanceToTime (which RET 4's straight back to 0x4e8ff0).
__declspec(naked) void freeze_hook()
{
    __asm {
        pushad                       // save EAX..EDI (0x20). ESP -= 0x20
        lea  eax, [esp+0x24]         // &floatArg = orig[ESP+4] = (esp+0x20)+4
        push eax                     // arg2: argp
        push ecx                     // arg1: mgr (SimManager, still in ECX)
        call freeze_rebase
        add  esp, 8
        popad                        // restore regs (ECX = SimManager again)
        mov  eax, REAL_ADVANCE
        jmp  eax                     // tail-call advanceToTime; stack/ECX intact
    }
}

static bool install_hook()
{
    unsigned char* p = (unsigned char*)CALL_SITE;
    // verify it's the expected `CALL 0x0051e710` before touching it
    int origRel = *(int*)(CALL_SITE + 1);
    if (p[0] != 0xE8 || (unsigned)(CALL_SITE + 5 + origRel) != REAL_ADVANCE) {
        flog("install ABORT: unexpected bytes at 0x%08x (op=%02x rel->0x%08x)",
             CALL_SITE, p[0], CALL_SITE + 5 + origRel);
        return false;
    }
    int newRel = (int)((unsigned)&freeze_hook - RET_ADDR);  // rel32 from the call
    DWORD old;
    VirtualProtect(p + 1, 4, PAGE_EXECUTE_READWRITE, &old);
    *(int*)(p + 1) = newRel;
    VirtualProtect(p + 1, 4, old, &old);
    FlushInstructionCache(GetCurrentProcess(), p, 5);
    flog("install OK: 0x%08x CALL -> freeze_hook @0x%08x (threshold=%.0fs)",
         CALL_SITE, (unsigned)&freeze_hook, (double)FREEZE_THRESHOLD);
    return true;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        install_hook();   // .text is mapped by injection time; the hook is dormant until
                          // the server loop runs, so installing on attach is safe.
    }
    return TRUE;
}
