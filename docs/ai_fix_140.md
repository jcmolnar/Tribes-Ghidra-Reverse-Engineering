# 1.40 AI crash fix — analog of T1Vista `FUN_0043ffbc` (NULL-deref of AI mount/target object)

## Result (high confidence)
The 1.40 (`Tribes 1.40.655\Tribes.exe`, base 0x400000) analog of T1Vista `FUN_0043ffbc` is:

### `FUN_004298c0` @ **0x004298c0**  — an AI-object scope/name-match predicate (`__thiscall`)

```c
undefined4 __thiscall FUN_004298c0(int this /*ECX*/, char *queryPattern /*[ESP+0xc]*/)
{
  // 1) match query pattern against THIS object's own name string  (this+0x1ac)
  if (matchWildcard(queryPattern, this + 0x1ac, 0)) return 1;
  // 2) if flag bit (this+0x54)&2 set, ALSO match against the LINKED (mount/control) object's name:
  //    [*(this+0x1cc) + 0x250]  — *(this+0x1cc) can be NULL  ->  CRASH
  if ((*(byte*)(this + 0x54) & 2) != 0)
      return matchWildcard(queryPattern, *(char**)(*(int*)(this + 0x1cc) + 0x250), 0);
  return 0;
}
```

This is a **byte-for-byte structural isomorph** of T1Vista `FUN_0043ffbc`: a small bool fn, two calls to the
same sub (`FUN_00411bb0`, the 1.40 wildcard matcher), the 2nd on `*(this+OBJ)+BOX` gated by `[this+FLAGS]&2`.

### Important reframing of "the inner primitive"
T1Vista `FUN_0058a87c` (and its 1.40 twin `FUN_00411bb0` @0x411bb0) is **NOT a box/containment test** — it is
the engine's recursive **DOS-style wildcard string matcher** (`'*'`=0x2a, `'?'`=0x3f, case-insensitive via
`_toupper`; cf. reconstructed source `engine\console\code\tagDictionary.cpp` `TagDictionary::match`). So
`FUN_0043ffbc`/`FUN_004298c0` is a **name/scope-match query**, not a geometry/LOS check. The `+0x1a0/+0x23c`
operands are **char\* name fields**, not world boxes. (The deliverable brief's "line-of-sight/containment /
world box" framing was a mis-read of the disasm; the crash *shape* and fix are identical regardless.)

### Identity confirmed by the caller
Sole caller `FUN_0042f980` @0x42f980 is the **AI-manager console-command dispatcher** (strings
`"...can't install AI manager..."`, `"...register AI manager..."`, `"MissionCleanup"`). It walks the AI
manager's object list (`*(mgr+0x6c)`, count `*(mgr+0x5c)`) and calls `FUN_004298c0(obj, namePattern)` per
object to select which AI objects a command targets by name — i.e. an `AI::Object`-name scope filter. The
crash fires server-side when an AI object whose `(+0x54)&2` flag is set has a NULL linked object at `+0x1cc`
(controlled/mount object destroyed) while a name-scoped AI console command runs.

## Crash instruction + register + guard target (1.40)
Disassembly of the 2nd-match branch (verified — no existing NULL check; the obj-ptr load flows straight into
the deref):
```
0x004298e5  TEST byte ptr [ESI+0x54], 0x2        ; flag gate (ESI = this)
0x004298e9  JZ   0x00429908                       ; -> return false
0x004298eb  MOV  ECX, dword ptr [ESI+0x1cc]       ; ECX = *(this+0x1cc)  (mount/target obj ptr; may be NULL)
0x004298f1  MOV  EAX, dword ptr [ECX+0x250]       ; <<< CRASH: deref name field; ECX NULL -> AV
0x004298f7  PUSH 0x0
0x004298f9  PUSH EAX
0x004298fa  PUSH EDI                               ; queryPattern
0x004298fb  CALL 0x00411bb0                        ; matchWildcard
0x00429900  ADD  ESP, 0xc
0x00429903  POP  EDI
0x00429904  POP  ESI
0x00429905  RET  0x4
0x00429908  POP  EDI                               ; <-- SAFE skip target (no-match path)
0x00429909  XOR  AL, AL                            ;     returns 0 (false)
0x0042990b  POP  ESI
0x0042990c  RET  0x4
```
- **Crash instruction address:** `0x004298f1` (`MOV EAX,[ECX+0x250]`).
- **Maybe-NULL register at crash:** `ECX` (`= *(this+0x1cc)`, loaded at `0x004298eb`).
- **Safe guard / skip target:** `0x00429908` (the `POP EDI; XOR AL,AL; POP ESI; RET 4` false-return path) —
  exactly mirrors Bov's plugin handler (`CMP ECX,0; JZ <false-exit>` before the `MOV reg,[ECX+0x250]` deref).

## Resolved struct offsets (T1Vista → 1.40)
| meaning | T1Vista | 1.40 |
|---|---|---|
| FLAGS byte (`&2` gate) | `+0x4c` | **`+0x54`** |
| self name char\* field | `+0x1a0` | **`+0x1ac`** |
| linked (mount/target) OBJ ptr | `+0x1c0` | **`+0x1cc`** |
| linked obj's name char\* field (the `+BOX`) | `+0x23c` | **`+0x250`** |

(Offsets shifted because T1Vista's struct layout is Kronos-modded — which is why the raw byte-pattern search
failed; the function MATCHES by structure/identity, not offsets, as predicted.)

## Bug status in stock 1.40
**Genuinely present and unguarded.** At `0x4298eb`→`0x4298f1` the obj-ptr load feeds the `+0x250` deref with no
intervening NULL test. The fix = insert a NULL guard on `ECX` after `0x4298eb`: `if (ECX==0) goto 0x429908`
(return false), then proceed to the original deref+match. Server-side fix (AI runs on the server), so it
belongs on a 1.40-based dedicated server, identical in spirit to Bov's `ServerSidePlugin.dll` patch at T1Vista
`0x43ffee`.

### Suggested patch (VirtualProtect + memcpy, same style as Bov)
The clean in-place patch: at `0x004298eb` (the `MOV ECX,[ESI+0x1cc]`, 6 bytes) keep the load, then before the
deref insert `TEST ECX,ECX` / `JZ 0x00429908`. There isn't room in-line for the 4 extra bytes, so the
plugin-trampoline approach Bov used is the right port: redirect `0x004298f1` (the `MOV EAX,[ECX+0x250]`, here a
6-byte instruction) to a handler that does `CMP ECX,0 / JZ ->0x429908 / MOV EAX,[ECX+0x250] / push args / CALL
0x411bb0 / ...`, mirroring the plugin handler at DLL `0x10004866`.

## Confidence: HIGH
Structural isomorphism is exact (same instruction sequence, same two matcher calls, same flag-gate, same
two `RET 4` exits), the matcher twin (`FUN_00411bb0`) is confirmed as the wildcard matcher, the single caller
is confirmed as the AI-manager command dispatcher by its error strings, and the four offsets map 1:1. The
only departure from the brief is semantic (name-scope match, not LOS/box) — it does not change the crash site
or the fix.
