# 3-day server freeze — DOES it exist in 1.3 (T1Vista / Kronos 0.8.5), and the fix

## Verdict: YES — identical bug, same engine code. (This is *why* "every" Tribes server freezes at ~3 days.)
The freeze is an **engine-level** flaw in the float simulation clock, present in ALL Darkstar builds (1.0 → 1.40).
Verified directly in **`TribesSource`** — the exact source T1Vista/Kronos 0.8.5 is built from:

- `darkstar/Sim/inc/simBase.h:28` — **`typedef float SimTime;`** (the sim/event clock is a 32-bit float, seconds).
- `darkstar/Sim/code/simBase.cpp:1439` — `int SimManager::advanceToTime(SimTime time)` (takes **float**), with
  `if (time == targetTime) return 0;` (float-equality early-out) then `pop(targetTime)` draining events whose
  `time <= targetTime`.
- `program/code/main.cpp:445-446` (server loop, 32 ms chunks) —
  `curTime = (sg.currentTime - sg.timeBase) * 0.001; sManager->advanceToTime(curTime);`
  `curTime` is a `double`, but **truncates to float** at the `advanceToTime(SimTime)` boundary, and `SimEvent::time`
  is float — so precision is lost there regardless of the double upper layers.

### Mechanism (a HANG, not a crash)
A 32-bit float's ULP at **2^18 s = 262,144 s = 3.03 days** is ≈ **0.0156 s**. The server's smallest repeating
timer sets the threshold: a self-rescheduling event posts at `now + dt`; once `dt < ULP`, `now + dt == now` in
float, so `pop(targetTime)` returns that same event **every iteration → infinite loop inside `advanceToTime`,
holding the sim critical section → 100% CPU, total freeze.** (With no self-rescheduler, `targetTime` simply stops
advancing → frozen sim.) Threshold scales with the smallest interval: 10 ms → 3.04 d, 16 ms → 6 d, 32 ms → 12 d.
The Kronos RPG scripts use `schedule(..., 0.01)` (10 ms) → lands on ~3 days, matching the symptom exactly.

### Why `resetTime()` can't just be called periodically
`SimManager::resetTime()` → `SimEventQueue::subtractTime(0)` (simBase.cpp:119,1433). But `subtractTime` **ignores
its parameter** (`t;` no-op) and rebases to the *earliest queued event's* time (sets it to 0, currentTime to 0).
Mid-session that makes the next-scheduled event fire immediately (loses `frontTime - now`), so it's only safe at
mission load, not as a periodic fix. We need a *correct* rebase that subtracts the current clock from everything.

## The fix (source-level — primary, because the 1.3 server is built from TribesSource)
Bound the float clock by rebasing it (and all event times) by the same delta periodically — exact, fires nothing
early, no typedef/struct/wire changes.

**1) New engine method** (`darkstar/Sim/code/simBase.cpp`, decl in `simBase.h` near `resetTime`):
```cpp
// Shift the whole sim clock back by `delta` seconds: subtract it from targetTime, the queue's
// currentTime, and EVERY queued event. Preserves all relative timings (nothing fires early).
void SimManager::rebaseTime(SimTime delta)
{
   eventQueue.lock();
   for (SimEventQueue::iterator it = eventQueue.begin(); it != eventQueue.end(); ++it)
      (*it)->time -= delta;
   eventQueue.setCurrentTime(eventQueue.getCurrentTime() - delta);  // or: currentTime -= delta (friend/member)
   targetTime -= delta;
   eventQueue.unlock();
}
```
(`SimEventQueue` already exposes `iterator/begin()/end()/lock()/unlock()/setCurrentTime()` — see subtractTime.)

**2) Call it from the server loop** (`program/code/main.cpp`, replace the two lines at 445-446):
```cpp
curTime = (sg.currentTime - sg.timeBase) * 0.001;
if (curTime > 3600.0) {                          // once the float clock passes ~1 h, rebase
   SimTime shift = (SimTime)(curTime - 1.0);     // keep a 1 s margin
   sManager->rebaseTime(shift);                  // clock + all events shift back by `shift`
   sg.timeBase = sg.currentTime - 1000;          // shift the ms base to match (1 s)
   curTime = (sg.currentTime - sg.timeBase) * 0.001;   // now ≈ 1.0
}
sManager->advanceToTime(curTime);
```
Result: `curTime` is permanently bounded to ~[1 s, 3600 s] → float ULP ≤ ~0.0004 s ≪ the 0.01 s (10 ms) tick →
the early-out/infinite-loop degeneracy can never trigger. The server runs indefinitely. (Do the same for the
CLIENT feed at main.cpp:374 `cg`/`cg.timeBase` if a client is ever left running for days — not the reported issue.)
Blast radius: 1 new method + ~5 lines; no change to `SimTime`, `SimEvent`, or any wire format.

### Alternative A — widen the clock to double (cleaner in theory, bigger blast radius)
`typedef double SimTime;` removes the precision loss for ~100+ years. BUT `SimEvent::time` size changes (struct
layout / any persistence), and it touches every `SimTime` site — only worth it in a full source refresh, not a
targeted fix. The rebase above is preferred.

### Alternative B — no-source (stock T1Vista.exe / can't rebuild)
If the production server runs the **stock Borland T1Vista.exe** and rebuilding from TribesSource isn't viable
(version-matched-server.md notes the PDB /FS + SAFESEH + MaxTeams build hurdles), deliver the same logic as a
runtime hook in the Bov `ServerSidePlugin.dll` style (VirtualProtect + detour on the server-loop `advanceToTime`
call), or a small standalone plugin. Needs T1Vista's addresses for the server loop, the `SimEventQueue`
(begin/end/currentTime), `targetTime`, and `sg.timeBase` — pinnable in Ghidra (re/proj has T1Vista.exe; the
serverProcess analog is the Borland twin of 1.40 `FUN_004e8ee0`, advanceToTime = twin of `FUN_0051e710`). Ask
and I'll pin them and build the plugin.

### Stopgap (zero work)
Restart the dedicated server every ~2 days (before the ~3-day threshold). Buys time until the real fix ships.

## Same fix for the 1.40 path
1.40 is the stock MSVC binary (no source), so 1.40 gets the **binary/plugin** form (hook `FUN_004e8ee0`'s
`advanceToTime` call / the float feed) — the same rebase logic, applied to `FUN_0051e710` (advanceToTime,
targetTime = `param_1[0x1e]`) + the server loop's `sg.timeBase` (`*0x6D5028`) + the event queue. The 1.3 source
fix above is the reference algorithm for it.
