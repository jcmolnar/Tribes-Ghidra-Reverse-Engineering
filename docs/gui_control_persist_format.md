# SimGui / FearGui control persist (`.gui`) on-disk format — T1Vista 1.3

Reverse-engineered from **T1Vista.exe** (Kronos 0.8.5 "Last Hope" 1.3 client, Borland C++ 5.x)
with the Ghidra Borland compiler spec. Everything below is transcribed from decompiled functions
and **verified live** — the six Graphics-Detail sliders in `RMRPG/gui/Options.gui` load, place at
their authored positions, run their `onAction` commands, and reflect their `$pref` variables when a
reimplementation reads exactly these fields. This is **not** inferred from byte patterns alone.

Recovering scripts (in `ghidra_scripts/`): `SliderRawFind`, `SliderVt2`, `CtrlRead`, `SliderNear`
(1.3); `FGSlider140` (1.40 cross-check). Method: find the class ctor via a byte-pattern search for
a known string address, read the two vtables it stores, decompile the persist `read`/`write` slots,
then dump the raw block substream at read-entry to pin exact offsets.

## Block framing

Each persisted control block is read through its **own** length-framed sub-stream: the persist
loader consumes the 4-byte length, then calls `obj->read(stream)` with the stream positioned at the
payload (`getPosition() == 4` at every `read` entry). A control's read consuming the wrong number of
bytes therefore does **not** desync sibling blocks.

Stream I/O is virtual on the stream object: **`stream_vtbl + 0x1c` = `read(this, nBytes, &dst)`**,
`+0x18` = `write`. A read of `nBytes` copies exactly `nBytes` bytes.

## `SimGui::Control::read` — `FUN_00539098`

`Control` is a `SimGroup` (multiple-inheritance: `SimGroup` + `Responder`). Field offsets are into
the object. Read order, exactly:

```
read(1)  version                      -> local
if (version == 0)   { read(4); read(4); read(1); read(1);  mbBoarder=mbOpaque=0 }
if (version == 1)   { read(4); read(1)->mbOpaque@0x74; read(1)->@0x76; read(1)->mbBoarder@0x75; read(1)->@0x79 }
if (version >= 2)   { read(4);                                  // unused DWORD
                      read(1)->mbOpaque@0x74;
                      read(1)->fillColor@0x76;                  // *** colors are ONE BYTE each (palette index) ***
                      read(1)->selectFillColor@0x77;
                      read(1)->ghostFillColor@0x78;
                      read(1)->mbBoarder@0x75;
                      read(1)->boarderColor@0x79;
                      read(1)->selectBoarderColor@0x7a;
                      read(1)->ghostBoarderColor@0x7b; }
read(1) len;  if(len) { read(len)->consoleCommand@0xe1;  consoleCommand[len]=0 }
if (version > 2) { read(1) len; if(len) { read(len)->altConsoleCommand@0x132; altConsoleCommand[len]=0 } }   // v>=3 ONLY
read(4)->position.x@0x19c;  read(4)->position.y@0x1a0        // Point2I (x read; y read only if x-read succeeded)
read(4)->extent.x@0x1a4;    read(4)->extent.y@0x1a8          // Point2I
read(4)->flags/mask@0x190
read(4)->tag@0x84
read(4)->horizSizing@0x88
read(4)->vertSizing@0x8c
if (version > 3) read(4)->helpTag@0x188                       // v>=4 ONLY
read(0x51)->consoleVariable@0x90                             // 81 bytes = Inspect::MAX_STRING_LEN(80) + 1
Parent::read  -> SimGroup::read  (int childCount, then that many child objects)
```

Notes that bite reconstructions:
- **Colors/flags in the v>=2 header are 1 byte each**, not 4. Getting this wrong shifts everything after by 21 bytes.
- **`altConsoleCommand` is present only when `version > 2`**, `helpTag` only when `version > 3`.
- `consoleVariable` is a **fixed 81-byte** field regardless of content.
- The shipped Options.gui controls are `version == 4`.

## `SimGui::ActiveCtrl::read` — `FUN_0053c900`

```
read(1)->active@0x1b4 (as bool)
read(4)->message@0x1b8
Control::read
```

## `FearGui::FGSlider` ('FGsk' tag)

- Vtables: **0x629538** (final; the ctor `FUN_004c95cc` stores 0x61f2dc first, then 0x629538).
- The persist `read`/`write` are vtable slots 0/1 = `FUN_0053c900`/`FUN_0053c8a4` (inherited
  `ActiveCtrl` versions) — **FGSlider does not override the persist read at the vtable**, but its
  block on disk carries a **20-byte / 5-field slider prefix before the ActiveCtrl fields**:

```
read(4)  slider version
read(4)  numDiscreteValues     -> 0x1e8
read(4)  minVal (float)        -> 0x1bc
read(4)  maxVal (float)        -> 0x1c0    (1.0 for the shipped detail sliders)
read(4)  increment (float)                (e.g. 0.05 for the gamma slider)
   -> then ActiveCtrl(active@0x1b4 + message@0x1b8) -> Control::read
```

(Confirmed by dumping the raw substream: `active`=`0x01` at raw[20], the Control `version`=`0x04`
at raw[25], `consoleCommand` length byte at raw[38].)

- Other FGSlider members / methods (1.3): minThumbX@0x1dc, thumbWidth@0x1d0, maxThumbX@0x1e0,
  curThumbX@0x1e4, dragOffset@0x1ec, bma(bitmap array)@0x1f4.
  onAdd `0x4c97b0`; onMouseDown `FUN_004ca3a0`; getRegion `FUN_004ca338`;
  onRender `FUN_004c9c70` (draws from **per-state stored bitmap-pointer fields**
  0x1cc/0x1d0/0x1d4/0x2e4/0x2e8/0x2ec/0x2f0/0x2f4 — **not** `getBitmap(index)`).

## 1.40 cross-check

In the 1.40.655 client (MSVC, clean RTTI), `FGSlider::read` (`FUN_004745d0`, vtable slot 20 of
RTTI vtable 0x0065532c) persists only **2** fields — `version` + `numDiscreteValues` — a genuine
cross-version format difference. Do **not** use the 1.40 slider layout to parse 1.3 `.gui` files.

## Not yet reverse-engineered

- The **`.pba` frame order** (which ShellSliderCtrl.pba sub-image is which part). `onRender`
  (`FUN_004c9c70`) reads pre-resolved bitmap pointers from object fields set in `onAdd`; the
  `onAdd` frame→field mapping was not decompiled. Anything claiming a specific frame order is a
  guess, not RE.
