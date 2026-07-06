# T1Vista 1.3 GUI — complete internals (SimGui / FearGui)

Reverse-engineered from **T1Vista.exe** (Kronos "Last Hope" 1.3 client, Borland C++ 5.x) with the
Ghidra Borland compiler spec. This is the exhaustive companion to
[`gui_control_persist_format.md`](gui_control_persist_format.md) (the on-disk `.gui` format): it
covers the **runtime** side — the object/vtable model, rendering, input, layout, lifecycle, and the
per-class method map for every GUI control.

Raw decompiles this is built from (in `re/`): `gui_full_map.txt` (every class → object vtable, all
slots), `gui_distinct_fns.txt` + `gui_all_fns.txt` (730 distinct GUI functions decompiled),
`control_slots.txt` (Control primary vtable, 44 slots), `control_responder.txt` +
`gui_secondary.txt` (Responder/input vtables), `gui_pipeline.txt` (ActiveCtrl interaction handlers).
Scripts: `GuiFullMap`, `DecompVtable`, `GuiDecompAll`, `DecompList`, `PersistDispatch`, `TagRead`,
`FindTagStores`.

---

## 1. Object & vtable model

Every GUI control is `SimGui::Control` or a subclass. **`Control : SimGroup, Responder`** — multiple
inheritance, so each object has **TWO vtables**:

| vtable | stored at | contains |
|---|---|---|
| **primary** | `*obj` (offset 0) | Persistent + SimObject/SimSet/SimGroup + Control: read/write, lifecycle, **render**, **layout**, script-value, inspector |
| **Responder (secondary)** | `obj[0x1b]` (offset **0x6c**) | **input**: onMouse*/onKey*/onMessage/first-responder |

The ctor sets the primary at `[obj+0]` and the secondary at `[obj+0x6c]`. Persist dispatch
(`Persistent::readObject FUN_0058b2e0`) calls **primary slot 0 = read**, **slot 1 = write**. Input
dispatch calls through the **Responder** vtable; each Responder method is an adjustor thunk that does
`this -= 0x6c; call realHandler(this)`.

### Object field offsets (Control, into `this`)
```
0x38  dynamic-field list head        0x44  manager (SimManager*)
0x4c  child count (SimGroup)         0x58  child array
0x6c  Responder vtable ptr           0x74  mbOpaque   0x75 mbBoarder
0x76  fillColor 0x77 selFill 0x78 ghostFill   0x79 boarderColor 0x7a selBorder 0x7b ghostBorder
0x80  root (Canvas*)                 0x84  tag        0x88 horizSizing  0x8c vertSizing
0x90  consoleVariable[81]            0xe1 consoleCommand[81]   0x132 altConsoleCommand[81]
0x184 x  0x188 helpTag  0x18c y      0x190 flags (bit0=Visible bit1=DeleteOnLoseContent)
0x19c position.x 0x1a0 position.y    0x1a4 extent.x 0x1a8 extent.y
```
ActiveCtrl adds: `0x1ac` stateDepressed, `0x1ad` mouseOver, `0x1b4` active(bool), `0x1b8` message.

---

## 2. Primary vtable — full slot map (Control, objVt `0x63c180`)

Every control shares this layout; subclasses override individual slots. Offset = slot×4.

| slot | off | method | addr (Control) | behavior |
|--|--|--|--|--|
| 0 | 0x00 | **read** | 0539098 | persist read (see persist doc) |
| 1 | 0x04 | **write** | 0538dfc | persist write |
| 2 | 0x08 | getPersistTag | 058b7a0 | returns class tag (0 base) |
| 3 | 0x0c | readVersion | 058b7a4 | read persist-object version dword |
| 4 | 0x10 | writeVersion | 058b7d0 | write it |
| 5 | 0x14 | getClassRep | 0542b70 | returns `&classRep` |
| 6 | 0x18 | setDataField | 04fe53c | SimObject dynamic string field add/get (list @0x38) |
| 7 | 0x1c | **~destructor** | 0538d58 | re-vtable, free children |
| 8 | 0x20 | registerObject | 04fef4c | SimObject::registerObject + recurse children |
| 9 | 0x24 | getId? | 04fe848 | returns 0 |
| 10 | 0x28 | **processArguments** | 0539d50 | console `newObject` args → atoi → position/extent (NOT persist!) |
| 11 | 0x2c | **inspectRead** | 0539884 | editor inspector read (TypedIO FUN_00510724) |
| 12 | 0x30 | **inspectWrite** | 0539460 | editor inspector write |
| 13 | 0x34 | **onAdd** | 0539cec | register; add to Named/Tagged sets; `variableChanged(var)` if consoleVariable |
| 14 | 0x38 | **onRemove** | 0538da4 | remove from canvas + SimGroup::onRemove |
| 15 | 0x3c | onWake | 04fe718 | (base empty) |
| 16 | 0x40 | onSleep | 04fe71c | (base empty) |
| 17 | 0x44 | onGroupRemove | 0539cd8 | remove from set if manager |
| 18 | 0x48 | deleteNotify | 04fed4c | (*this+0x60) then base |
| 19 | 0x4c | processDeleteNotify | 04feea4 | recurse children (+0x4c) |
| 20 | 0x50 | begin (iterator) | 04025ac | SimSet iterator begin |
| 21 | 0x54 | end (iterator) | 04025d0 | SimSet iterator end |
| 22 | 0x58 | onEditAction | 04fe934 | (base empty) |
| 23 | 0x5c | **setCanvas/onWake** | 0539ec4 | attach to canvas: `canvas+0x7c=this`, wire Responder |
| 24 | 0x60 | clearCanvas/onSleep | 0539f18 | detach from canvas |
| 25 | 0x64 | assignName | 04ff24c | SimObject::assignName (Named set) |
| 26 | 0x68 | findObjectById | 04ff29c | manager lookup |
| 27 | 0x6c | **findObject(path)** | 04ff2a8 | resolve `a/b/c` name path to child |
| 28 | 0x70 | onNameChange | 0539dcc | (base empty) |
| 29 | 0x74 | **getMinExtent** | 053a674 | returns Point2I(4,4) |
| 30 | 0x78 | **onRender** | 053a59c | opaque fill(0x76) + border(0x79) + `renderChildControls` |
| 31 | 0x7c | **onPreRender** | 053945c | (base empty; sliders/lists override) |
| 32 | 0x80 | **resize** | 053a350 | set position/extent, notify children (+0x88) & parent (+0x84) |
| 33 | 0x84 | onChildResized | 053a3f0 | (base empty) |
| 34 | 0x88 | **parentResized** | 053a2a0 | apply horiz/vertSizing (0x22/0x23) → new pos/extent → resize |
| 35 | 0x8c | **pointInControl** | 0539f6c | hit-test point vs extent |
| 36 | 0x90 | **findHitControl** | 0539f9c | walk children back→front, return hit child (or self) |
| 37 | 0x94 | **getScriptValue** | 053a13c | returns NULL (base) |
| 38 | 0x98 | **setScriptValue** | 053a140 | empty (base) |
| 39 | 0x9c | **setVisible** | 0538dc4 | flags bit0 = visible; setUpdate |
| 40 | 0xa0 | getX | 0488d70 | `this+0x184` |
| 41 | 0xa4 | getHelpTag | 0488d78 | `this+0x188` |
| 42 | 0xa8 | getY | 0488d88 | `this+0x18c` |
| 43 | 0xac | **variableChanged** | 053a7cc | empty (base; controls override to sync from consoleVariable) |

**ActiveCtrl extends** the primary vtable past slot 43:
`+0xd4` = **pointInThumb/hitRegion**, `+0xd8` = **onAction** (fires consoleCommand / message).
onAction chain: `if consoleCommand → Console->evaluate; if named → "<name>::onAction"; if message → onMessage(this,msg)`.

### onRender (slot 30, `FUN_053a59c`)
```
if (mbOpaque@0x74)  surface->fillRect(rect, fillColor@0x76, 1.0f);   // vtbl +0x10
if (mbBoarder@0x75) surface->drawRect(rect, boarderColor@0x79);      // vtbl +0x0c
renderChildControls(surface, ...)                                     // FUN_053a3f4
```
Colors are palette indices. `renderChildControls` clips to the update region and calls each visible
child's onRender (slot 30). This is the base; buttons/sliders/text override slot 30 for custom art.

### Layout (resize / parentResized / sizing)
`horizSizing`@0x88 and `vertSizing`@0x89 codes (SimGui::Control enum): `0`=fixed(absolute pos+size),
`1`=relative-to-right/bottom, `2`=center, `3`=proportional/percent, plus `resizeRelative`. On a parent
resize, each child's **parentResized** (slot 34) recomputes its pos/extent from these codes, then calls
**resize** (slot 32), which recurses. This is how a `.gui` authored at 640×480 reflows to any canvas
size.

---

## 3. Responder (input) vtable — slot map

Secondary vtable at `obj[0x6c]`. Slot order = native `SimGui::Responder` declaration
(`engine/SimGui/inc/simGuiBase.h`). Control's Responder **forwards** every event to `this+4` (the
next responder / delegate); interactive controls override with real handlers.

| slot | method | Control (0x63c25c) | ActiveCtrl (0x63c834) |
|--|--|--|--|
| 0 | **onMouseDown** | forward | `053c5e0` |
| 1 | onMouseRepeat | forward | forward |
| 2 | **onMouseUp** | forward | `053c62c` |
| 3 | onMouseMove | forward | `053c4c4` |
| 4 | onMouseEnter | forward | forward |
| 5 | onMouseLeave | forward | `053c5c0` |
| 6 | **onMouseDragged** | forward | `053c708` |
| 7-10 | onRightMouse{Down,Repeat,Up,Dragged} | forward | forward |
| 11 | onKeyUp | forward | (thunk) |
| 12 | onKeyRepeat | forward | forward |
| 13 | **onKeyDown** | forward | (thunk `053db60`) |
| 14 | onMessage | forward | forward |
| 15 | loseFirstResponder | (thunk) | (thunk `053db58`) |
| 16 | becomeFirstResponder | (thunk) | (thunk `053db50`) |

### The interaction model (ActiveCtrl, from `gui_pipeline.txt`)
```
onMouseDown (053c5e0):
   if (!active@0x1b4) forward to next responder; return
   if (mouseOver@0x1ad):
       root->mouseLock(this)          (FUN_00534234)
       root->setFirstResponder(this)  (FUN_00533f14)
       stateDepressed@0x1ac = 1
   setUpdate()

onMouseDragged (053c708):
   if (this == root->lockedControl@0x260):
       hit = pointInThumb(localMouse)     ((*this+0xd4))
       stateDepressed = hit; if changed setUpdate()

onMouseUp (053c62c):
   if (this == root->lockedControl) root->mouseUnlock()   (FUN_0053423c)
   setUpdate()
   if (stateDepressed) { stateDepressed = 0; onAction() }   ((*this+0xd8))

onMouseMove (053c4c4):
   mouseOver@0x1ad = pointInThumb(localMouse); if changed setUpdate()
   set the active cursor tag (0x61)
```
So a click that presses AND releases over the control fires **onAction** (→ its `consoleCommand`).
This is the mechanism every button/checkbox/slider uses; no `consoleVariable` auto-write (see persist
doc §4 — value output is script-driven via `consoleCommand`).

---

## 4. Per-control catalogue

Every GUI persistent class, its object vtable, and the slots it overrides vs Control. Full slot lists
in `re/gui_full_map.txt`; each function decompiled in `re/gui_all_fns.txt`. Persist read/write per
class in the persist doc §5. Selected key classes (tag → objVt → overrides beyond persist):

- **SGct `SimGui::Control`** (0x63c180) — the base; renders opaque fill+border+children.
- **ActiveCtrl** (SG Test* / all FearGui interactive) — adds active/message, onMouse*, onAction,
  get/setScriptValue.
- **SGtb `TestButton`** (0x63c71c) — overrides onRender (drawBorder), getScriptValue/setScriptValue.
- **SGtc `TestCheck`** (0x63d96c) — onAction toggles `set`; onRender draws box+check; variableChanged.
- **SGtr `TestRadial`**, **SGsl `Slider`** (0x63e788), **SGpc `ProgressCtrl`** (0x63dbcc),
  **SGtk `TextEdit`** (0x6303e0), **SGtl/SGts/SGtw/SGtf** text controls, **SGmc MatrixCtrl**.
- **FGsk `FearGui::FGSlider`** (0x629824) — persist read `FUN_004cb0e8`; onAdd `FUN_004b36e4`
  (loads `.pba` art + fonts into fields 0x1e4..0x200); onRender `FUN_004c9c70` (per-state bitmap
  fields 0x1cc/0x1d0/0x1d4/0x2e4..0x2f4); onMouseDown/Up/Dragged `0x4cb384/0x4cb374/…` (thumb drag,
  discrete rounding, fires consoleCommand on release).
- **FGsl `FearGui::FearGuiScrollCtrl`** (0x62600c) — MatrixCtrl-family; NOT a slider.
- **FGst StandardCombo, FGcf, FGcm, FGub BuySell, FGmi MissionList, FGms MasterList, MMsb
  MMShellBorder, ME* editor controls** — see `gui_full_map.txt` for each objVt + overrides.

Full tag→objVt table (42 GUI classes) is the head of `re/gui_full_map.txt`.

---

## 5. Rendering & input pipelines (top level)

**Render**: `SimGui::Canvas::render` walks the content-control stack; for each it resizes the root to
the surface, seeds the update regions (`resetUpdateRegions` = full surface on first frame / on
content resize), then calls the root's **onRender** (slot 30), which recurses through
`renderChildControls` within the accumulated dirty regions. The in-game console overlay renders on top
(`getConsole()->render`). Controls mark themselves dirty via `setUpdate()` (`FUN_0053a890`), which
adds their rect to the update region so the next frame redraws them.

**Input**: the platform layer feeds mouse/key events to the Canvas, which hit-tests via **findHitControl**
(slot 36 → pointInControl slot 35) to route to the deepest control under the cursor, then dispatches
through that control's **Responder** vtable. Unhandled events forward up the responder chain
(`this+4`). Keyboard goes to the **first responder** (set by becomeFirstResponder on click). Mouse
capture (drag) is held by `root->lockedControl` (Canvas +0x260).

---

## 6. Still open / not RE'd

- **`.pba` frame INDEX → field mapping** (which sub-image is arrow/thumb/track for each skinned
  control) — the render *logic* is decompiled (which field draws when), but not the onAdd frame-
  extraction indices (Ghidra-obfuscated). Ports render plain rects as a stable workaround.
- **Delegate system** (game-side `.cs` `*CSDelegate` classes bound to `.gui` roots) — these are in
  the game/shell module, not the engine, and drive tab-switching / apply-buttons via script.
- Font (`.pft`) glyph rendering and palette expansion are engine-internal (GFXFont/GFXPalette) and
  render correctly on the port already; not re-detailed here.
