# Bov's ServerSidePlugin — full patch classification + 1.40 port status

Decoded from the installers (FUN_100048ce + FUN_10004248, re/aipatch.txt) + the T1Vista patch-site
decompiles (re/bov_t1vista.txt). **Key finding: only ONE of the six is a true crash fix; the rest are
behavior/tuning.** The "massive crash fix" the user recalled = the AI fix (#1), which is ported.

| # | T1Vista site | What it changes | Class | 1.40 status |
|---|---|---|---|---|
| 1 | 0x43ffee (15B → CALL handler) | NULL-guard the AI name-scope filter's `*(this+0x1c0)+0x250` deref | **CRASH** | ✅ **PORTED** (FUN_004298c0 @0x4298f1, re/ai_fix_140.md) |
| 2 | 0x550cc8 + 0x550ccd (2×1B) | raise `$pref::PacketRate` clamp 30→127 | tuning | ✅ **PORTED** (FUN_00519bb0: 0x519c0a + 0x519c10, `1e→7f`) |
| 3 | 0x40be84 + 0x40cd4e (retarget CALL) | redirect 2 sites from `getClientById` (FUN_0040de38) to `FUN_0040de80` | behavior | ⏸ **not ported** (see below) |
| 4 | 0x43bff4 (6B → CALL handler "AIJetPatch") | wrap the AI-jet state fn's mount-vtable call; "stop next AI spawning airborne" | behavior (crash-adjacent) | ⏸ **not ported** (see below) |

## #3 — getClientById redirect (behavior, not a crash)
`FUN_0040de38` = `getClientById` (id−0x800, bound [0,0x7f], **returns NULL if the slot's `+0x250ec` flag byte
is set**). `FUN_0040de80` = same lookup **without** that flag check. Bov redirects the **skin-set**
(FUN_0040be10) and **AI-distance** (FUN_0040cd34) call sites to include *transitional/flagged* clients.
- Not a crash: both lookups return NULL safely on bad input and the callers null-check the result.
- In **1.40 `getClientById` is INLINED** across the player manager (`ADD reg,0xfffff800; CMP 0x7f; IMUL
  0x1e8; [+0x25104]==0xdeadbeef(empty); [+0x250f4] flag` — re/analogs.txt §2), so there's no function to
  re-point. Porting would mean NOP-ing the `[+0x250f4]` flag-check branch at the specific 1.40 analogs of
  FUN_0040be10/FUN_0040cd34 — a Kronos-behavior change, not a stability fix.
- **Recommendation: skip** unless you specifically want a 1.40 server to replicate Kronos's
  include-transitional-clients-in-skin/AI behavior. It changes gameplay, not stability.

## #4 — AIJetPatch (behavior; crash-adjacent)
T1Vista FUN_0043bf3c (AI jet/movement state: copies a transform to `+0xe0`, switches on the AI state
`+0x100`, then `CALL [*(this+0x1c0)→vtable+0x150]`). Bov replaces that final mount-object vtable call
with a handler; the strings say "stop next AI spawning airborne" → the handler alters spawn state, not
just a NULL check.
- The handler's exact logic is **unpinnable statically** (the hardcoded CALL rel32 resolves into the
  DLL's CRT region → ServerSidePlugin relocates; the real handler address isn't recoverable from the
  install bytes).
- The crash-subset (NULL `+0x1c0` mount → bad vtable call) IS real, but the **1.40 analog wasn't found**
  by pattern (mount `+0x1cc` + vtable `+0x150`, re/aijet.txt = 0 hits) — that function's object type uses
  different offsets than the main AI fix, so it needs its own semantic match.
- **Recommendation:** if wanted, port only the **defensive NULL-guard** (find the 1.40 analog of
  FUN_0043bf3c by its shape — transform-copy to `+0xe0`, state switch, mount-vtable call — and guard the
  mount ptr before the call). That stops the crash variant; the airborne-spawn behavior can't be
  faithfully reproduced without the handler. Lower priority than the hunt for genuine wire crashes.

## Net
Crash fixes from Bov's plugin that matter for 1.40 stability: **#1 (AI), ported.** #2 ported as a tuning
courtesy. #3/#4 are Kronos behavior tweaks, documented for a deliberate decision rather than mis-ported.
