# Tribes dedicated-server ~3-day freeze — root cause

**Verdict: CONFIRMED — the float-seconds simulation clock is the root cause.** The hypothesis
was right about the *mechanism* (32-bit float sim clock, ULP stall) and right about *3 days =
2^18 s*, but the precise trigger is sharper than "the clock stops": it is an **infinite loop
inside `SimManager::advanceToTime`'s event-pop loop**, triggered when a periodic
console-`schedule()` re-arms itself with a delta of ~8–16 ms once server **uptime crosses
2^18 s = 262 144 s = 3.03 days**. The server hangs (busy-spins in a critical section), it does
not crash — exactly the reported symptom.

Confidence: **high** on the engine mechanism (verified in source AND in the shipped 1.40
binary via Ghidra). **Medium-high** on the exact triggering script loop (the engine guarantees
the failure window; *which* RPG `schedule` loop trips first is server-config-dependent, but a
10 ms (`0.01`) reschedule — the most common sub-tick interval in the Kronos RPG scripts — maps
to *exactly* 3.037 days).

---

## The clock is a 32-bit float in seconds — verified two ways

**Source (`engine/`, the reconstructed Darkstar tree):**
- `engine/Sim/inc/simBase.h:28` — `typedef float SimTime;`
- `SimEvent::time` (`simBase.h:209`) = `SimTime` (float). The **entire event queue keys on this float.**
- `SimEventQueue::currentTime` and `SimManager::targetTime` (`simBase.h:51,447`) = `SimTime` (float).
- `int SimManager::advanceToTime(SimTime time)` (`simBase.h:481`, body `simBase.cpp:1439`) — param is **float**.

**Server feed (`program/code/main.cpp:432-446`, `FearGame::serverProcess`):**
```c
double curTime  = getTime();                       // double, QPC seconds since start
DWORD  finalTime = DWORD(curTime*1000) & ~0x1F;     // uint32 ms, clean
while (sg.currentTime < finalTime) {               // uint32 ms compare — NOT the bug
   sg.currentTime += 32;                           // 32 ms tick
   curTime = (sg.currentTime - sg.timeBase) * 0.001;   // -> seconds
   sManager->advanceToTime(curTime);               // <-- TRUNCATED TO float HERE
}
```
`sg.currentTime/timeBase` are `DWORD` ms (`program/inc/fearGlobals.h:38-39`) and wrap at 49.7
days — *not* the culprit. The culprit is the **float truncation at the `advanceToTime(float)`
call boundary**: the master sim/event clock is `(uptime_ms)*0.001f`, a float that grows with
**server uptime in seconds**.

**Shipped binary (`Tribes.exe` 1.40.655, Ghidra, base 0x400000):** decompiles confirm it byte-for-byte.
- `FearMain::onIdle` = `FUN_004e9120`: `startFrame(); serverProcess(); Sleep(cg.manager==0); clientProcess(); endFrame();`
- `serverProcess` = `FUN_004e8ee0`: the `while (sg.currentTime < (finalTime & ~0x1F))` loop, and inside it
  `fVar2 = (float)(int)(sg.currentTime - sg.timeBase); advanceToTime(fVar2 * 0.001f);` — **the cast to `float` is explicit in the binary.**
- `SimManager::advanceToTime` = `FUN_0051e710`: signature `int __thiscall(int*, **float** param_2)`; `targetTime` at `+0x1e` compared as `(float)`; loop `while ((ev = pop(targetTime)) != 0) process(ev);`
- `SimEventQueue::pop` = `FUN_0051dfd0`: signature `(int*, **float** param_2)`; event time read at `+0xc` as `*(float*)`; returns the head event while `event->time <= targetTime`.

The shipped binary also adds a defensive guard the source lacks: in `advanceToTime`,
`if (param_2 < (float)targetTime) param_2 += <small const>;` — evidence the developers already
hit *time-regression* problems with this float clock and patched around the symptom rather than
the cause.

---

## Why it freezes at ~3 days (2^18 s), and why it's a HANG not a crash

A float32 has a 23-bit mantissa, so its ULP (smallest representable step) at value `t` is
`2^(floor(log2 t) - 23)`:

| uptime t | days | ULP (s) |
|---|---|---|
| 131072 (2^17) | 1.52 | 0.0078 |
| **262144 (2^18)** | **3.03** | **0.0156** |
| 524288 (2^19) | 6.07 | 0.0313 |
| 1048576 (2^20) | 12.14 | 0.0625 |

A periodic event reschedules as `event->time = getCurrentTime() + dt` (console `schedule`:
`simGame.cpp:262`, both operands float). Once `dt < ULP(t)`, **`getCurrentTime() + dt == getCurrentTime()` in float** — the reschedule lands on a time `<= targetTime`. In
`advanceToTime`'s loop, `pop` then returns that same event *again immediately*, every iteration,
forever. **Infinite loop, inside `EnterCriticalSection` → the server thread spins at 100% holding
the sim lock → total hang (no crash, no exit).**

The freeze uptime is set by the smallest self-rescheduling interval `dt` present:

| reschedule dt | freezes at |
|---|---|
| 1 ms | 0.38 d |
| 4–5 ms | 1.52 d (2^17) |
| **8–15 ms** | **3.04 d (2^18)** |
| 16–20 ms | 6.07 d (2^19) |
| 32 ms | 12.14 d (2^20) |
| 64 ms | 24.3 d (2^21) |

The **~3-day** report ⇒ the first loop to trip uses a **~8–15 ms** delta. The Kronos RPG
scripts contain **`schedule(..., 0.01)` (10 ms) in 12 places** and confirmed self-rescheduling
loops (`WalkSlowInvisLoop`, `Moveable::moveToWaypoint`, `UpdateClientTimes`). A 10 ms self-reschedule
freezes at **exactly 2^18 s = 3.037 days** — a clean match. (Even pure-tick math degrades here:
at 2^19/6 days the 32 ms tick itself starts losing sub-steps; at 2^21/24 days *every* tick is
lost. So a vanilla server with no fine schedules would freeze nearer ~6–24 days; the RPG mod's
sub-tick schedules pull it in to 3.)

---

## Secondary contributors — ruled OUT

- **Resource leak / OOM:** would give gradual slowdown then a crash/alloc-failure, not a clean
  hang at a power-of-two time. The exact 2^18 s match is arithmetic, not exhaustion. Not the cause.
- **uint32 ms / GetTickCount wrap:** `sg.currentTime`, `Net::PacketStream::currentTime`, and
  `netCSDelegate` times are all uint32 ms → wrap at **49.7 days**, not 3. The `while` loop and
  `finalTime` are computed in `double`/uint32 and are clean. Not the cause.
- **Packet sequence / ghost-id / notify-counter wrap:** these are masked counters that wrap
  harmlessly far from a 3-day count. Not implicated.
- **`clockTime` (the mission display clock):** float at `WorldGlobals+0x0C` in the 1.40 binary
  (TribesXT `tribes/worldGlobals.h`), but it's a *client HUD* value (`clockhud.cpp`), not the
  server sim driver. Not the cause.

---

## Recommended fix

**Root fix (from-source build — preferred):** make the master/event clock monotonic-bounded so
ULP never approaches the tick. Two equivalent options:

1. **Rebase the sim clock periodically.** The engine already has the machinery:
   `SimManager::resetTime()` → `SimEventQueue::subtractTime(0)` (`simBase.cpp:119,1433`) rebases
   all queued event times and `currentTime`/`targetTime` to 0. Drive it from `serverProcess`:
   subtract the elapsed base every N hours (e.g. when `sg.currentTime - sg.timeBase` exceeds ~1 h
   of ms), and bump `sg.timeBase` by the same amount so the float fed to `advanceToTime` stays
   small (uptime-seconds-mod-3600 ⇒ ULP ≤ 2^-13 s, forever safe). This is the minimal,
   behavior-preserving change.

2. **Widen the clock to `double`.** Change `typedef float SimTime;` → `typedef double SimTime;`
   (`simBase.h:28`) and the `advanceToTime`/`pop` signatures. A double's ULP at 3 days is ~6e-11 s
   — the stall is pushed past 10^8 years. Larger blast radius (every `SimEvent`/`pack` that
   assumes 4-byte time, plus the `+0xc`/`+0x1e` binary offsets if any plugin pins them), so
   option 1 is safer for an existing tree.

**Binary patch (no source — for the shipped 1.40 server):** a from-binary clock-widen is
impractical (float assumed everywhere). The realistic in-binary mitigation is a **periodic
auto-restart / rebase**:
   - Simplest operational fix: **schedule a server restart every ~2 days** (well under 3). Zero risk.
   - In-process: a plugin (TribesXT-style hook) that calls the engine's `SimManager::resetTime`
     path on a timer, or that bumps `sg.timeBase` (`*0x6D5028`) toward `sg.currentTime` every hour
     so the float handed to `advanceToTime` (`0x4e8ee0`) stays small. This reproduces fix #1
     without recompiling.

**Defense-in-depth (either build):** in `advanceToTime`'s pop loop, guard against the
zero/negative-progress reschedule — if `pop` returns the same event time as the previous
iteration more than the queue size, break (prevents the infinite spin even if a sub-ULP delta
slips through). Cheap insurance.

---

### What was verified vs inferred
- **Verified (source + 1.40 binary):** `SimTime`=float; `advanceToTime`/`pop`/event-`time` all
  float; the server feeds `(uptime_ms)*0.001f`; the pop loop re-delivers events with `time <= targetTime`; ULP/2^18-s arithmetic; the binary's hidden time-regression guard.
- **Verified (Kronos scripts):** presence of 10 ms (`0.01`) schedules and self-rescheduling loops.
- **Inferred:** that one of those specific loops is the first to trip at 3 days (engine guarantees
  *a* freeze in the 3–6 day band given sub-16 ms schedules; pinning the exact loop would need a
  live capture of the server's scheduled-event queue near t≈3 d, or instrumenting `schedule`).
