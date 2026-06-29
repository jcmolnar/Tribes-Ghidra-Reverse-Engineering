# Porting Hudbot + Presto to Tribes 1.40

Goal: make the team5150 **Hudbot** ScriptGL drawing interface and the **Presto/Kronos**
client GUI scripts (`C:\Dynamix\Tribes\config\Presto`) run on the stock **Tribes 1.40.655**
client (`C:\Users\Joe\Desktop\Tribes 1.40.655\Tribes.exe`).

## What the two things actually are
- **Hudbot** (`C:\Dynamix\Tribes\Hudbot`) — a native client patch for the *old* (1.11-era,
  Borland) Tribes client. Its load-bearing feature is **ScriptGL**: a set of `gl*` console
  commands plus a render hook (`ScriptGL::playGui::onPreDraw` / `onPostDraw`) that lets
  TorqueScript draw arbitrary OpenGL (rects, TrueType text, textures) over the playGui each
  frame. It also ships texture/skin replacements, CRC texture overrides, and TTF fonts.
  ScriptGL is NOT in TribesSource — it was a binary patch, so it doesn't exist on 1.40.
- **Presto** (`config/Presto/*.cs`) — the Kronos client GUI built ON TOP of ScriptGL:
  KronosHUD (vhud HP/MP/XP bars), KronosMenu (TAB menu + scale/drag framework), KronosShop,
  KronosChat (custom chat overlay), KronosNPC. Plus the stock Hudbot `config/scriptgl2.cs`
  vhud framework and `config/vhud.halflife2.cs`. See `config/Presto/KronosGUI_README.md`.

## API surface Presto needs (measured from the .cs)
`glColor4ub`(97), `glRectangle`(66), `glDrawString`(38), `glSetFont`(32),
`glGetStringDimensions`(14), `glDisable`(14), `glBlendFunc`(14), plus from scriptgl2.cs:
`glTexEnvi`, `glDrawTexture` (1 use). The render hook is `ScriptGL::playGui::onPreDraw(%dim)`
and `onPostDraw(%dim)`, `%dim` = "width height". Drawing is in **screen pixels, top-left
origin, y-down**.

## How it loads on 1.40 (settled)
1.40 has **no native plugin loader**. We inject a DLL with **`re/injector/xtloader.exe`**
(launches Tribes suspended, waits for `Console` to come up, `CreateRemoteThread(LoadLibrary)`).
The binary is base `0x400000`, no ASLR, relocs stripped → every engine VA is a constant.

## 1.40 engine seams (confirmed in Ghidra — `re/hudbot_seam.txt`)
| Symbol | Address | ABI |
|---|---|---|
| `Console` global | `*(CMDConsole**)0x006E284C` | NULL until engine init |
| `CMDConsole::addCommand(id,name,cb,priv)` | `0x00403600` | `__thiscall` (this=ECX) |
| `CMDConsole::executef(console,argc,...)` | `0x00403680` | `__cdecl` variadic; argv[0]=fn name |
| `CMDConsole::printf` | `0x004039B0` | for logging to the in-game console |
| Callback ABI | — | `const char*(*)(CMDConsole*,int id,int argc,const char** argv)` |

NOTE: TribesXT's `console.h` lists `evaluate@0x403640`, but Ghidra shows 0x403640 is a
*second* `addCommand` variant (calls 0x405c60), not evaluate — a copy-paste bug in that
header. We don't need evaluate: constants come from a `.cs`, the render hook uses `executef`.

## Architecture (v1 — `re/hudbot_plugin/hudbot.cpp`)
Standalone DLL (matches `kronosfix`/`freezefix` conventions), injected by xtloader.
- **Constants** live in `hudbot_gl.cs` (shipped, exec'd by Presto). `$GL_*` are set to the
  *real* OpenGL enum values, so the native `gl*` handlers pass the script int straight to GL.
  `$GLEX_*` (DRAW/CENTERED/SCALED/ROTATED, PIXEL/SMOOTH) are Hudbot-specific (0..3).
- **Commands** registered on `*Console` via `addCommand(0,name,cb,0)`.
- **Render hook = `wglSwapBuffers` overlay.** We IAT-hook the present call; on each present
  the GL context is current and the frame is drawn, so we save GL state, set a top-left/y-down
  ortho from the GL viewport, `executef("ScriptGL::playGui::onPreDraw","w h")` then
  `onPostDraw`, restore state, then call the real present. (The original Hudbot split
  pre/post around the playGui's own render; an overlay-both is correct for onPostDraw and
  visually fine for onPreDraw in v1. Splitting at the true playGui render seam is a later
  refinement — see TODO.)
- **Fonts**: `glSetFont` builds a per-(name,height) `wglUseFontBitmaps` display-list set from
  a GDI `HFONT` (real TrueType glyphs at a pixel height), cached. `glDrawString` parses
  `\n` + inline `<RRGGBBAA>`, sets `glColor`, `glRasterPos2i(x, y+ascent)`, `glCallLists`.
  `glGetStringDimensions` uses `GetTextExtentPoint32A` per line. Custom `.ttf` in `Hudbot\Fonts`
  are `AddFontResourceEx(FR_PRIVATE)`'d at load.
- **Primitives**: `glColor4ub`/`glRectangle` raw GL; `glBegin/glEnd/glVertex2i/glTexCoord2f/`
  `glBlendFunc/glTexEnvi/glDisable` thin pass-throughs to real GL (valid inside the ortho).

## Status — ScriptGL FULLY BUILT OUT (pre-live-test)
- [x] Discovery: Hudbot/Presto contents, API surface, 1.40 seams confirmed in Ghidra.
- [x] Plan + skeleton (`re/hudbot_plugin/`): `hudbot.cpp`, `hudbot_img.cpp/.h`, `hudbot_gl.cs`, build, README.
- [x] All 18 gl* commands implemented (not stubs).
- [x] **Texture pipeline**: TGA (RLE+raw, 8/24/32bpp) from Hudbot\ScriptGL loose files OR .zip,
      with a built-in DEFLATE inflate (RFC1951 "puff"). VERIFIED offline (`imgtest.exe`) against
      the real HUD zips — correct uncompressed sizes, dimensions, pixels. glBindTexture/glDrawTexture
      (DRAW/CENTERED/SCALED/ROTATED) / glGetTextureDimensions / glRescanTextureDirectory all live.
- [x] **AA + glow fonts**: GDI antialiased glyphs -> per-glyph GL textures (lazy + cached);
      $GLEX_PIXEL/$GLEX_SMOOTH, glow radius 0..16 (box-blurred halo); private Hudbot\Fonts\*.ttf
      AddFontResource'd. GDI coverage path VERIFIED offline (`glyphtest.exe`): correct shapes,
      metrics, AA gradients, DIB orientation, private-TTF load.
- [x] Builds x86 clean (159KB, exports getPlugin); render seam (gdi32!SwapBuffers) import confirmed.
- [x] **One-click launcher**: `C:\Users\Joe\Desktop\Tribes 1.40.655\Play RPG.bat` now does the
      WHOLE deploy+inject (idempotent): copies hudbot.dll + xtloader.exe next to Tribes.exe;
      mirrors Hudbot\Fonts + Hudbot\ScriptGL; copies the ScriptGL constants + 5 Kronos GUI
      scripts (+scriptgl2/vhud) into config\hudbot\; generates config\scriptpack\hudbot_loader.cs
      (the RPG client autoloads scriptpack\*.cs and it execs the GUI in order); then launches
      `xtloader Tribes.exe hudbot.dll -mod RPG`. Deploy steps validated (loader .cs well-formed,
      all files land). Uninstall = delete config\scriptpack\hudbot_loader.cs.
- [ ] **NEXT: live test** — double-click Play RPG.bat; check hudbot.log + in-game
      "registered (18 gl* commands)"; confirm the Kronos HUD renders (watch for load-order /
      RPG-HUD conflicts with the existing scriptpack rpg_*.cs).

## Deferred (documented, not blocking Presto)
- True `onPreDraw`-under-HUD seam (we overlay both pre/post at present; fine for Kronos).
- `$ScriptGL::Latency` throttle / display-list carbon-copy — omitted (every-frame is fine on
  modern HW; recording lazy texture/glyph creation into a list is unsafe).
- NPOT textures (Hudbot's are pow2; would need padding for GL 1.1).
- Hudbot texture/skin REPLACEMENTS + CRC overrides (a separate subsystem, not ScriptGL).
- 1.40 dropped Phoenix bitmaps — skin/texture reconversion (separate asset track, see kronos_on_140.md).

## Test tools (re/hudbot_plugin/)
- `imgtest.cpp` -> imgtest.exe: inflate+zip+TGA against C:\Dynamix\Tribes\Hudbot zips.
- `glyphtest.cpp` -> glyphtest.exe: GDI glyph coverage/metrics (ASCII preview) w/o a GL context.
