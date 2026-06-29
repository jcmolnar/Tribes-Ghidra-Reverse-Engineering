# The Tribes "~3-day server freeze" — root cause and fix

## Symptom
A Tribes/Kronos **dedicated server freezes after ~3 days of continuous uptime** — the sim stops
advancing (and on Kronos, pins a CPU core at 100%). A restart fixes it for another ~3 days. This has
affected Tribes servers since 1998; it's uptime-dependent, not load-dependent.

## Root cause: the simulation clock is a 32-bit `float` in seconds
The engine's sim/event clock is `typedef float SimTime` — a **32-bit float**, in **seconds**. Every
frame the dedicated-server loop feeds the scheduler:

    advanceToTime( (currentTime - timeBase) * 0.001 )      // currentTime/timeBase are ms

`timeBase` is fixed at server start, so the float value **grows with uptime**. Scheduled events store
their fire time as a float too.

The problem is IEEE-754 precision. A 32-bit float has a 24-bit mantissa, so near a value of magnitude
2^E the smallest representable gap (the ULP) is `2^(E-23)`. As the clock grows, that gap grows:

| clock value | ≈ uptime | ULP (smallest step it can represent) |
|---|---|---|
| 2^16 s | 0.76 days | 0.0078 s |
| 2^17 s | 1.5 days  | 0.0156 s |
| **2^18 s** | **3.03 days** | **0.03125 s** |
| 2^19 s | 6.1 days  | 0.0625 s |

## Why exactly ~3 days
Kronos schedules self-repeating events as little as **10 ms** apart (`schedule(..., 0.01)`). Such an
event reschedules itself with `nextTime = now + 0.01`.

A float rounds `now + dt` back to `now` when `dt` is smaller than **half** the ULP. At **2^18 s ≈ 3.03
days**, ULP = 0.03125 s, so half-ULP = 0.0156 s, and `0.01 < 0.0156`. Therefore:

    now + 0.01  ==  now      (the 10 ms reschedule produces the SAME time)

The event is now scheduled for the *exact current time*, so the scheduler pops it, runs it, it
reschedules to the same time again, pop, run, reschedule… **an infinite loop inside `advanceToTime`,
holding the sim lock → 100% CPU, total freeze.** The threshold scales with the smallest repeating
timer: 10 ms → 3 days, 16 ms → 6 days, 32 ms → 12 days. Kronos's 10 ms timers land it on ~3 days.

(If a server had no sub-tick repeating events, the same precision loss instead makes the clock simply
stop advancing — the sim halts rather than spins. Same root cause, slightly different face.)

## Reproduce it yourself in 5 lines (no Tribes needed)
This is the whole bug, isolated. It proves the float math is the cause:

```c
#include <stdio.h>
int main(void) {
    float now = 262144.0f;        // 2^18 seconds ≈ 3.03 days of uptime
    float next = now + 0.01f;     // a 10 ms (schedule 0.01) reschedule
    printf("now =%.5f\nnext=%.5f\n", now, next);
    printf(next == now ? "FROZEN: reschedule == now -> scheduler loops forever\n"
                       : "ok\n");
    return 0;
}
```

Output: `next == now` → **FROZEN**. Run it with `now = 131072.0f` (2^17, 1.5 days) and it still
advances — the failure switches on exactly where the math says it will.

## Evidence in the actual binary (for anyone checking T1Vista.exe, base 0x400000)
- Dedicated-server loop: `FUN_004eba40` — advances `sg.currentTime (*0x6a841c)` in 32 ms chunks.
- `advanceToTime` (`FUN_004ffb40`) is called at **`0x4ebb2f`** with `(currentTime - timeBase) * 0.001`
  as a **float** (`sg.timeBase = *0x6a8420`).
- The clock/targetTime/events are all floats: `SimManager.targetTime @+0x6c`, eventQueue `@+0x70`
  (events hold `time @+0xc`). Same shape exists in 1.40 (`FUN_0051e710`) and in the Darkstar source
  (`typedef float SimTime`, simBase.h).

## The fix: keep the float clock small
You can't make a float more precise, so instead **never let the clock get large**. Periodically (well
before 3 days — we rebase once the float exceeds 1 hour) shift the whole clock back toward zero:

1. pick `shift = currentFloatClock - 1.0` (keep a 1-second margin),
2. subtract `shift` from **every queued event's time**, from the event-queue's currentTime, and from
   the SimManager's targetTime — i.e. move *everything* by the same amount,
3. bump `timeBase` by the matching milliseconds.

Because every time value moves by the *same* delta, **all relative timings are preserved** — an event
5 seconds out is still 5 seconds out; nothing fires early or late. The float clock then lives forever
in roughly **[1 s, 3600 s]**, where the ULP is < 0.001 s — far below any 10 ms timer — so the rounding
failure can never happen.

(Note: the engine's own `subtractTime`/`resetTime` does a *different*, buggy rebase that snaps to the
earliest queued event, which would fire that event early mid-session — that's why we don't reuse it and
do a correct uniform shift instead.)

We ship it as an injected DLL (`kronosfix_server.dll`) that hooks the `advanceToTime` call and does the
rebase, then tail-calls the original. No engine rebuild, no script changes.

## Proof it works (live, on the production server)
Built with a 30-second test threshold and loaded on a real dedicated server:

```
install OK: 0x004ebb2f CALL advanceToTime -> freeze_hook (threshold=30s)
rebase: t=30.015 shift=29.015 events=26 -> clock=1.000 timeBase=29016
rebase: t=30.023 shift=29.023 events=26 -> clock=1.000 timeBase=58040
```

The clock climbs to ~30 s, gets rebased to exactly 1.000 (all 26 queued events shifted with it),
climbs again, rebases again — bounded forever. With the production 1-hour threshold it rebases ~hourly
and the clock never approaches the 3-day precision wall, so the server can run indefinitely.

## How others can verify
1. **The math** — run the 5-line program above; flip `now` between 2^17 and 2^18 and watch the failure
   switch on at exactly 3 days' worth of seconds.
2. **The mechanism** — confirm the server's smallest repeating `schedule()` interval; 10 ms predicts
   ~3 days, and the freeze timing should track that interval per the table.
3. **The fix** — load the 30-second test build, leave a dedicated server up ~1 minute, and check
   `kronosfix_server.log` for `rebase:` lines plus normal gameplay (respawns/AI/timers on time) across
   a rebase. Then confirm a server with the 1-hour build survives past 3 days without freezing.
```
