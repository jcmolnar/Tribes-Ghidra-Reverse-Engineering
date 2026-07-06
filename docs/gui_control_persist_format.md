# SimGui / FearGui control persist (`.gui`) on-disk format — T1Vista 1.3

Reverse-engineered from **T1Vista.exe** (Kronos 0.8.5 "Last Hope" 1.3 client, Borland C++ 5.x)
with the Ghidra Borland compiler spec (`x86borland.cspec`, `__fastcall` args in EAX/EDX/ECX).
Everything below is transcribed from decompiled functions and cross-checked against the **actual
bytes** of the shipped `RMRPG/gui/Options.gui`. Two independent proofs back the load-bearing facts:
(1) the persist dispatcher's raw disassembly (which vtable slot is called), and (2) the class-rep
registration records (which name the read/write function per FOURCC tag).

Recovering scripts (in `ghidra_scripts/`): `GuiPersistDump`, `GuiPersist0`, `PersistSlot`,
`PersistDispatch`, `SliderDeep`, `TagMap`, `TagRead`, `FindTagStores`, `CtrlRead`. Outputs land in
`re/*.txt`. Method: (a) disassemble `Persistent::readObject`/`writeObject` to find the read/write
vtable offsets; (b) recover every FOURCC tag's class-rep by scanning `.text` for the
`MOV dword[rep+0x90], <tag>` store the `IMPLEMENT_PERSISTENT` macro emits; (c) follow the class-rep
descriptor to the per-class read/write and decompile it.

---

## 1. Object framing & dispatch — `Persistent::readObject` (`FUN_0058b2e0`)

Persistent objects are streamed through a **length-framed sub-stream**. The stream object is virtual;
its method table (distinct from the control vtable) uses these offsets:

| stream vtbl offset | operation |
|---|---|
| `+0x00` | `getStatus()` (0 == ok) |
| `+0x08` | `getPosition()` |
| `+0x0c` | `setPosition(n)` |
| `+0x18` | `write(nBytes, src)` |
| `+0x1c` | `read(nBytes, dst)` → copies exactly `nBytes` bytes, returns success bool |
| `+0x28` | `readSTString(dst)` (Huffman/ST string) |
| `+0x2c` | `writeSTString(src, maxLen)` |

Each persisted object read does, in order:

1. Open a sub-stream over the next block (the block is self-delimiting; a control that reads the
   wrong number of bytes does **not** desync its siblings — the outer loop reseeks by block length).
2. Read a **4-byte class id** (`iStack_a0`). Three cases:
   - `0x54434944` `'DICT'` → read a 4-byte **dictionary index**; the object is a back-reference to an
     already-deserialized shared object (looked up in the reference table `DAT_00641b20`). No new read.
   - `0x53524550` `'PERS'` → read a **2-byte length** (must be ≤ 0x80) then that many bytes of a
     class **name**; create by name via `FUN_0058afa4`.
   - otherwise the id **is a FOURCC class tag** → create via `Persistent::create(tag)` (`FUN_0058afe4`).
3. Register the new object pointer in the reference table (so later `'DICT'` entries can point back).
4. **Dispatch the read** (raw disasm of `FUN_0058b2e0`, verified):
   ```
   version = (**(obj + 0x0c))(obj, stream, &err);   // vtable SLOT 3 = getPersistVersion
   err     = (**(obj + 0x00))(obj, stream, version, dictIdx);  // vtable SLOT 0 = READ
   ```
   **→ persist READ = object vtable slot 0.** It receives `(stream, version, user)`.

`Persistent::writeObject` (`FUN_0058b540`) mirrors this:
```
tag = (**(obj + 0x08))();                      // vtable SLOT 2 = getPersistTag
err = (**(obj + 0x04))(obj, stream, tag, mode); // vtable SLOT 1 = WRITE
```
**→ persist WRITE = object vtable slot 1.**

> ⚠️ **Vtable-slot caveat that caused a multi-session detour.** A Control is multiple-inheritance
> (`SimGroup` + `Responder`) and therefore has *two* vtables. In the object's **primary** vtable,
> read/write are slots **0/1**. But a *secondary/thunk* vtable (which some tooling — and this repo's
> earlier `full_catalog.txt` — reports as "the vtbl") lays them out at slots **10/11**, with slot 0 =
> destructor. Do **not** identify persist read/write by "slot 10 of the catalog vtbl": for most
> classes slot 10 coincidentally equals the real read, but for classes that override the
> console/inspector methods (e.g. FGSlider's slot 10 = an `atoi`-based `processArguments` at
> `0x539d50`) it is **wrong**. The authoritative source is the **class-rep descriptor** (§3), or the
> primary-vtable slot 0.

---

## 2. Class-rep registry — recovering tag → read/write

`IMPLEMENT_PERSISTENT(Class, tag)` builds a static **class-rep** and emits, in the registrar:
```
MOV dword ptr [rep+0x00], <descriptorVtable>   ; C7 05 <rep>   <descVt>
MOV dword ptr [rep+0x90], <FOURCC tag>          ; C7 05 <rep+90> <tag>
```
`FindTagStores.java` scans `.text` for the second store and back-scans ≤ 80 bytes for the first,
giving **tag → rep → descriptorVtable** for every persistent class (≈130 in this exe). The **FearGui**
descriptor layout is: **slot 0 = create** (operator new + ctor, sets the object vtable), **slot 6 =
persist read**, **slot 7 = persist write**, slots 8-10 = getTag/getVersion/writeTag. (The **SimGui**
`SG**` descriptor orders differently — slot 6 there is *create*; use the object primary vtable slot 0
for SG reads, which is what §5 lists.)

Full FOURCC tag list (all persistent classes, from `re/tag_stores.txt`) — GUI-relevant subset:

```
FGsk FGSlider     FGsl (slider2)   FGst standardCombo  FGcf checkbox/frame  FGkt (ctrl)
FGub buySell      FGmi missionList FGte textEdit       FGcl comboList       FGsb scrollBar
FGsx ...          FGms masterList  FGmz ...            FGft filterText      FGtl textList
FGpa playerCombo  FGpl playerList  FGmn menu           FGcb comboBox        FGhi hudInv
SGct Control      SGsC ScrollContent SGsc scrollCtrl   SGsl Slider          SGtb testButton
SGtc testCheck    SGtk textEdit    SGtl textList       SGtr testRadial      SGtf textFormat
SGts TSControl    SGtw textWrap    SGpc progressCtrl   SGmc matrixCtrl      SGbb (button)
MMsb MMShellBorder  ME** mission-editor controls
```
(These class-name guesses come from the read shape + catalog names; the **tag→read fn** mapping is
exact. See `re/tag_stores.txt` for the complete rep/descVt/read/write per tag.)

---

## 3. Base read chain (exact field offsets)

### `SimGui::Control::read` — `FUN_00539098`
`Control` = `SimGroup` + `Responder`. Reads, in order (all stream reads are `+0x1c`):

```
read(1)  version                                   -> local (call it V)
if V==0 : read(4);read(4);read(1);read(1);  mbOpaque@0x74 = mbBoarder@0x75 = 0
if V==1 : read(4); read(1)->mbOpaque@0x74; read(1)->@0x76; read(1)->mbBoarder@0x75; read(1)->@0x79
if V>=2 : read(4) unused;
          read(1)->mbOpaque@0x74;
          read(1)->fillColor@0x76;         // *** each color/flag is ONE BYTE (palette index) ***
          read(1)->selectFillColor@0x77;
          read(1)->ghostFillColor@0x78;
          read(1)->mbBoarder@0x75;
          read(1)->boarderColor@0x79;
          read(1)->selectBoarderColor@0x7a;
          read(1)->ghostBoarderColor@0x7b;
read(1) len; if(len){ read(len)->consoleCommand@0xe1;  consoleCommand[len]=0 }
if V>2 : read(1) len; if(len){ read(len)->altConsoleCommand@0x132; altConsoleCommand[len]=0 }
read(4)->position.x@0x19c; if ok read(4)->position.y@0x1a0     // Point2I
read(4)->extent.x@0x1a4;  if ok read(4)->extent.y@0x1a8        // Point2I
read(4)->flags/mask@0x190
read(4)->tag@0x84
read(4)->horizSizing@0x88
read(4)->vertSizing@0x8c
if V>3 : read(4)->helpTag@0x188
read(0x51)->consoleVariable@0x90              // fixed 81 bytes = MAX_STRING_LEN(80)+1
Parent::read -> SimGroup::read (children)
```
Notes: v>=2 header colors are **1 byte each**; `altConsoleCommand` only when `V>2`; `helpTag` only
when `V>3`; `consoleVariable` is always a fixed 81-byte field. The shipped Options.gui controls are a
mix of `V==0` (e.g. the sliders) and `V==4`.

### `SimGui::ActiveCtrl::read` — `FUN_0053c900`
```
read(1)->active@0x1b4 (bool)
read(4)->message@0x1b8
Control::read
```

### `SimGroup::read` (children) — `FUN_004ff044` + `Persistent::readObject`
```
read(4) childCount@0x4c
repeat childCount times: child = Persistent::readObject(stream); addObject(child)   // §1
```
`SimGroup::write` (`FUN_004fefdc`) writes `childCount` then `writeObject` per child.

---

## 4. `FearGui::FGSlider` ('FGsk') — DEFINITIVE

**Persist read = the FGsk class-rep descriptor slot 6 = `FUN_004cb0e8`** (authoritative; also the
FGsk object vtable `0x629824` slot 0). Chain:

```
FGSlider::read (FUN_004cb0e8):
    read(4)  unused/version          (discarded)
    read(4)  numDiscreteValues -> 0x1e8      (if < 2: minVal=0.0, maxVal=1.0f in-memory)
    -> SimGui::Slider::read (FUN_0054d38c):
         read(4)  minVal (float)     -> 0x1bc
         read(4)  maxVal (float)     -> 0x1c0
         read(4)  increment (float)  -> 0x1c4
    -> ActiveCtrl::read (FUN_0053c900):
         read(1)  active             -> 0x1b4
         read(4)  message            -> 0x1b8
    -> Control::read (FUN_00539098)
```

So on disk an FGSlider block is a **5-dword (20-byte) numeric prefix**
`[unused][numDiscreteValues][minVal][maxVal][increment]`, then the ActiveCtrl `active`(1)+`message`(4),
then the standard Control body. **This confirms the original live-verified format** (the six
Graphics-Detail sliders in Options.gui load and place correctly with exactly this reader).

**Byte-level proof** — first `FGsk` block in `RMRPG/gui/Options.gui` (payload after `[tag:4][len:4]`):
```
00000000 00000000 00000000 00000000 0000803f 00000000 01...04...
 unused   numDisc   minVal   maxVal   incr=1.0  active=0,msg  Control V=0 ...
```
`increment = 0x3f800000 = 1.0f`; then `active`, then Control version byte, matching `FUN_004cb0e8`
exactly.

**Write** = descriptor slot 7 = `FUN_004cb090`: `write(4) 0; write(4) numDiscreteValues@0x1e8;`
then `SimGui::Slider::write` (`FUN_0054d318`: min/max/incr) → `ActiveCtrl::write` → `Control::write`.

> History note: an earlier pass mislabeled FGSlider by reading slot 10/11 of a secondary vtable
> (`0x539d50`/`0x53c7f8`), which are the console-args/inspector methods (`atoi`-based, `FUN_006070c8`),
> **not** persist. The class-rep descriptor (this section) is the correct source and agrees with the
> shipped bytes.

**`FGsl` is NOT a slider — it is `FearGuiScrollCtrl`** (a scroll/matrix control; 3× in Options.gui).
Resolved via its create `FUN_004c3b60` → object vtable `0x62600c`, whose **slot 0 = read = `0x4cb...`
→ `FUN_004c3a90`** (identical to the FearGuiScrollCtrl row in §5): `read(4) discard; read(4)@0x1b4 →
MatrixCtrl::read (FUN_0054b4a0) → MatrixCtrl-parent (FUN_0054aeb4) → Control`. Its ~28-byte on-disk
prefix (seen in Options.gui) matches that chain. FGsl's vtable also shows **slot 0 = the persist read
(`0x4c3a90`)** and **slot 10 = the `atoi` console method (`0x539d50`)** — the same split as FGSlider,
independently confirming "persist read = primary-vtable slot 0, not slot 10."

---

## 5. Per-control added fields (before the base chain)

All offsets are into the control object; every `read(n)` is stream `+0x1c`. Each row lists only the
**class-specific** reads; they then chain to the named base. (From `re/gui_persist_dump.txt` /
`re/tag_stores.txt`, cross-checked.)

| control (read fn) | class-specific reads → base |
|---|---|
| **ActiveCtrl** `0x53c900` | `active`(1)@0x1b4, `message`(4)@0x1b8 → Control |
| **Control** `0x539098` | (§3) → SimGroup |
| **TextFormat** `0x538a14` | (none) → ActiveCtrl |
| **TextFmt subclass** `0x4ce4bc` (FGTextFormat, FGIRCActiveTextFormat) | read(4) discard → TextFormat |
| **Button/label base** `0x5406bc` (MEButton, MEPopup, MEPopupButton, TestButton, FGIRCTopicCtrl) | read(4)×2 discard; (4)@0x1c4; (4)@0x1bc; (4)@0x1c0; (4)@0x1c8; read(0x51) text@0x1d8; (4)@0x2dc; (4)@0x2d8 → ActiveCtrl |
| **CFGButton** `0x49ec7c` | read(4) discard; readSTString@0x2fd; (4)@0x350; (4)@0x354; (4)@0x358; (4)@0x35c; (4)@0x360 → Button base |
| **Combo** `0x4b76d0` (FGComboBox, FGControls/Mission/Player/ServerFilter) | read(4) discard; read(1) len; if len read(len) str@0x2f8 (nul-term) → Button base |
| **StandardCombo/BuddyCombo** `0x4bbc3c` | delegates to Combo `0x4b76d0` |
| **Check / TestCheck** `0x54de00` | read(1) bool@0x2e0 → Button base |
| **Radio / TestRadial** `0x53df7c` | read(1) bool@0x2e0 → Button base |
| **TextEdit** `0x53f6ac` (TestEdit, METextEdit) | read(4)→bool@0x320; read(4)×2 discard; (4)@0x2e0 → Button base |
| **TabMenu** `0x4ccd1c` | read(4)@0x1c4 → ActiveCtrl |
| **ScrollCtrl** `0x4c3a90` (FearGuiScrollCtrl) | read(4) discard; (4)@0x1b4 → MatrixCtrl |
| **MatrixCtrl** `0x54b4a0` | read(4)@0x284 (if ok read(4)@0x288) → MatrixCtrl-parent `0x54aeb4` |
| **MatrixCtrl-parent** `0x54aeb4` | (4)@0x27c; (1)bool@0x281; (4)@0x274; (4)@0x278; (1)bool@0x280 → Control |
| **ProgressCtrl** `0x544b60` | (4)@0x1c0; (4)@0x1bc; (4)@0x1c8 → ActiveCtrl |
| **TSControl** `0x547864` | read(1) bool@0x228 → Control |
| **TimerCtrl** `0x547fac` | (4)@0x1ac; (4)@0x1b0; (4)@0x1b4 → Control |
| **SimGui::Slider** `0x54d38c` | (4)min@0x1bc; (4)max@0x1c0; (4)incr@0x1c4 → ActiveCtrl |
| **TextList / METextList** `0x54baa8` | (4)@0x1ec; (4)@0x1f0; (4)@0x1f4; (1)bool@0x208; (1)bool@0x209 → ActiveCtrl; then post-load `setup(0x1ec), setup(0x1f0)` |
| **TextWrap** `0x54cb7c` | (4)→bool@0x1fd; (4)@0x1c0; (4)@0x208; (4)@0x1bc; (4)@0x1c4; (4)@0x1d8 → ActiveCtrl |
| **FearGuiDialog** `0x4aef68` | (4)@0x1ac (if ok (4)@0x1b0) → Control |
| **MMShellBorder** `0x49c8d4` | read(1) sentinel; if ==0xFF readSTString@0x1b4 else 0x1b4=0 & rewind 1 → Control |
| **ShapeView** `0x4993a8` | readSTString@0x1f4 → ActiveCtrl |
| **FGSlider (FGsk)** `0x4cb0e8` | (§4) unused, numDiscrete@0x1e8 → SimGui::Slider → ActiveCtrl → Control |

Writes are the exact byte-for-byte inverse of each read (same offsets, `+0x18` stream writes);
see `re/gui_persist_dump.txt` "DISTINCT WRITE FUNCTIONS" — they confirm every field width above.

---

## 6. Reference / shared-object table (`DICT`)

`DAT_00641b20` is a growable array of already-deserialized object pointers. Every `readObject`
appends the new object; a `'DICT'` id in the stream reads a 4-byte index into this array and returns
the existing pointer (no re-read). This is how the format shares palettes/skins/fonts referenced by
multiple controls without duplicating them. Writing mirrors it: `writeObject` first scans the table;
a hit emits `'DICT'` + index instead of the full object.

---

## 7. Slider render (`FGSlider::onRender` `FUN_004c9c70`) — bitmap fields & draw order

The slider draws **two** bitmaps per frame through the surface's `drawBitmap` (`surface vtbl +0x24`,
args `(surface, GFXBitmap*, &Point2I, palette@0x1d8)`; each field holds a `GFXBitmap*` whose `+0x14`
is the bits). State flags: `active`@0x1b4, expanded-thumb`@0x2e0` (set true when the control is small,
`extent < 0x200×0x180`), and a hover/highlight flag (true when the bound console var resolves).

```
DRAW 1 (thumb, at [x, y+1]):     field = expanded? 0x2f4 : 0x2e4
DRAW 2 (track, at [x+1, y]):
    if !highlight:
        expanded? (active? 0x2ec : 0x2e8) : (active? 0x1d0 : 0x1cc)
    else (highlight):
        expanded? 0x2f0 : 0x1d4
```
So the eight bitmap-pointer fields are: **0x1cc/0x1d0/0x1d4** (normal-size track: idle/pressed/hover)
and **0x2e4/0x2e8/0x2ec/0x2f0/0x2f4** (thumb + expanded-size variants). These are populated during
resource load in the FGSlider onAdd path (`FUN_004ca08c`, descriptor slot 3) from the slider's `.pba`
bitmap array; a plain-rect fallback render (as used in the WASM/native port) is a valid substitute.

## 8. `.pba` frame order — RE'd

The FGSlider `.pba` frame→state→field mapping is now fully reverse-engineered from the REAL FGsk
onRender `FUN_004ca7b8` (the earlier `FUN_004c9c70`/`FUN_004ca08c` belonged to a different slider
variant). Full 15-frame table and draw order in
[`gui_internals_complete.md`](gui_internals_complete.md) §6. Key correction: the per-element state
order is **disabled, pressed, normal** (0/1/2 = left arrow disabled/pressed/normal, etc.), not the
normal-first order ports had guessed. Everything in the T1Vista GUI is now RE'd; the only items
outside the engine binary are the game-side `.cs` shell delegates.
