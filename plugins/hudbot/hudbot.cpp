//============================================================================
// hudbot.cpp — ScriptGL for Tribes 1.40.655 (injected client DLL).
//
// Reimplements the team5150 "Hudbot" ScriptGL drawing interface on the STOCK
// 1.40 client so the Presto / Kronos client GUI (config\Presto\*.cs, the vhud
// HUD, TAB menu, shop, chat, NPC windows) renders. ScriptGL was a Borland-era
// binary patch and does not exist in 1.40; this adds the gl* console commands
// and the ScriptGL::playGui::onPreDraw / onPostDraw render hook.
//
// Loaded into a live Tribes.exe by re\injector\xtloader.exe (1.40 has no native
// plugin loader). Binary is base 0x400000, no ASLR — engine VAs are constants
// (confirmed in re\hudbot_seam.txt):
//   Console  = *(CMDConsole**)0x006E284C        addCommand = 0x00403600 (__thiscall)
//   executef = 0x00403680 (__cdecl variadic)    con::printf = 0x004039B0
//
// Render seam (v1): IAT-hook the present call (SwapBuffers / wglSwapBuffers). On
// each present the GL context is current and the frame is drawn, so we set a
// top-left/y-down ortho from the GL viewport and call the script draw hooks as
// an overlay, then present. See re\hudbot_140.md for the design + TODO layers.
//============================================================================
#include <windows.h>
#include <gl/GL.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <cmath>
#include "hudbot_img.h"

#ifndef GL_TEXTURE_ENV
#define GL_TEXTURE_ENV       0x2300
#define GL_TEXTURE_ENV_MODE  0x2200
#endif
#ifndef GL_CLAMP_TO_EDGE
#define GL_CLAMP_TO_EDGE     0x812F
#endif

#pragma comment(lib, "opengl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

//---------------------------------------------------------------- logging -----
static void flog(const char* fmt, ...)
{
    FILE* f = fopen("hudbot.log", "a"); if (!f) return;
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fputc('\n', f); fclose(f);
}

//---------------------------------------------------- engine ABI (1.40.655) ---
typedef const char* (*Callback)(void* console, int id, int argc, const char** argv);
typedef void (__thiscall* AddCmd_t)(void* self, int id, const char* name, Callback cb, int priv);
typedef void (__cdecl*    Exec_t)(void* console, int argc, ...);
typedef void (__cdecl*    Printf_t)(void* console, const char* fmt, ...);

static void**    const g_ppConsole  = (void**)0x006E284C;   // *(CMDConsole**)
static AddCmd_t  const pAddCommand   = (AddCmd_t)0x00403600;
static Exec_t    const pExecutef     = (Exec_t)0x00403680;
static Printf_t  const pConPrintf    = (Printf_t)0x004039B0;

static void* con() { return *g_ppConsole; }
static void  addCmd(const char* name, Callback cb) { if (con()) pAddCommand(con(), 0, name, cb, 0); }

//------------------------------------------------------ ScriptGL draw state ---
static bool sInDraw  = false;                 // true only inside the present hook
static int  sScreenW = 0, sScreenH = 0;
static int  sR = 255, sG = 255, sB = 255, sA = 255;

// In-game gate: set via the native `hudbotInGame` command from hudbot_gl.cs's
// eventGuiOpen/Close hooks (no getBoolVariable dependency). Only draw when true.
static volatile bool sGate = false;
// Crash tracing: the SEH handler logs these so we know exactly where a fault hit.
static volatile int  sPhase = 0;              // 1=onPreDraw 2=onPostDraw 3=done
static const char*   sLastCmd = "";           // last gl* handler entered

//---------------------------------------------------- font cache (TTF + glow) --
// Real TrueType glyphs rendered with GDI antialiasing into 32-bit DIBs, optional
// glow (box-blurred coverage halo), uploaded as per-glyph GL textures (lazy, like
// Hudbot). glDrawString draws a textured quad per char in the current color.
struct Glyph {
    GLuint tex; int cellW, cellH, texW, texH, advance; bool ready;
};
struct GLFont {
    char     key[112];
    HFONT    hfont;
    int      height;     // tmHeight (line advance)
    int      ascent;
    int      glow;       // glow radius (0 = none)
    bool     aa;
    unsigned stamp;
    Glyph    g[256];
};
static const int   MAX_FONTS = 32;
static GLFont      sFonts[MAX_FONTS];
static int         sFontCount = 0;
static GLFont*     sCur = NULL;
static unsigned    sFrame = 0;

static void fontFreeGlyphs(GLFont* f)
{
    for (int i = 0; i < 256; ++i) if (f->g[i].ready && f->g[i].tex) glDeleteTextures(1, &f->g[i].tex);
}

static GLFont* fontGetOrCreate(const char* name, int pixH, bool aa, int glow)
{
    if (glow < 0) glow = 0; if (glow > 16) glow = 16;
    char key[112];
    _snprintf(key, sizeof(key), "%s#%d#%d#%d", name, pixH, aa ? 1 : 0, glow); key[111] = 0;

    for (int i = 0; i < sFontCount; ++i)
        if (strcmp(sFonts[i].key, key) == 0) { sFonts[i].stamp = sFrame; return &sFonts[i]; }

    GLFont* slot;
    if (sFontCount < MAX_FONTS) slot = &sFonts[sFontCount++];
    else {                                    // evict LRU
        slot = &sFonts[0];
        for (int i = 1; i < sFontCount; ++i) if (sFonts[i].stamp < slot->stamp) slot = &sFonts[i];
        fontFreeGlyphs(slot);
        if (slot->hfont) DeleteObject(slot->hfont);
        memset(slot, 0, sizeof(*slot));
    }

    HFONT hf = CreateFontA(-pixH, 0, 0, 0, FW_NORMAL, 0, 0, 0, ANSI_CHARSET,
                           OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS,
                           aa ? ANTIALIASED_QUALITY : NONANTIALIASED_QUALITY,
                           DEFAULT_PITCH | FF_DONTCARE, name);
    if (!hf) { if (sFontCount > 0 && slot == &sFonts[sFontCount-1]) --sFontCount; return NULL; }

    HDC mdc = CreateCompatibleDC(NULL);
    HGDIOBJ old = SelectObject(mdc, hf);
    TEXTMETRICA tm; GetTextMetricsA(mdc, &tm);
    SelectObject(mdc, old); DeleteDC(mdc);

    memset(slot, 0, sizeof(*slot));
    _snprintf(slot->key, sizeof(slot->key), "%s", key); slot->key[111] = 0;
    slot->hfont = hf; slot->height = tm.tmHeight; slot->ascent = tm.tmAscent;
    slot->glow = glow; slot->aa = aa; slot->stamp = sFrame;
    return slot;
}

// separable box blur of an 8-bit coverage map (radius r), in place via scratch
static void boxBlur(unsigned char* a, int w, int h, int r)
{
    if (r <= 0) return;
    unsigned char* t = (unsigned char*)malloc((size_t)w * h);
    if (!t) return;
    int div = 2 * r + 1;
    for (int y = 0; y < h; ++y) {                   // horizontal
        for (int x = 0; x < w; ++x) {
            int s = 0;
            for (int k = -r; k <= r; ++k) { int xx = x + k; if (xx < 0) xx = 0; if (xx >= w) xx = w - 1; s += a[y*w + xx]; }
            t[y*w + x] = (unsigned char)(s / div);
        }
    }
    for (int y = 0; y < h; ++y)                      // vertical
        for (int x = 0; x < w; ++x) {
            int s = 0;
            for (int k = -r; k <= r; ++k) { int yy = y + k; if (yy < 0) yy = 0; if (yy >= h) yy = h - 1; s += t[yy*w + x]; }
            a[y*w + x] = (unsigned char)(s / div);
        }
    free(t);
}

// Render one glyph of font f into a GL texture (white RGB, coverage in alpha).
static void renderGlyph(GLFont* f, unsigned char c)
{
    Glyph& gl = f->g[c];
    gl.ready = true; gl.tex = 0;

    HDC dc = CreateCompatibleDC(NULL);
    HGDIOBJ oldf = SelectObject(dc, f->hfont);
    int cw = 0; { ABC abc; if (GetCharABCWidthsA(dc, c, c, &abc)) cw = abc.abcA + (int)abc.abcB + abc.abcC; }
    if (cw <= 0) { INT w0 = 0; GetCharWidth32A(dc, c, c, &w0); cw = w0; }
    gl.advance = cw;

    int glow = f->glow;
    int cellW = cw + 2 * glow + 2; if (cellW < 1) cellW = 1;
    int cellH = f->height + 2 * glow + 2; if (cellH < 1) cellH = 1;
    int texW = 1; while (texW < cellW) texW <<= 1;
    int texH = 1; while (texH < cellH) texH <<= 1;

    BITMAPINFO bi; memset(&bi, 0, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = texW; bi.bmiHeader.biHeight = -texH;   // top-down
    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32; bi.bmiHeader.biCompression = BI_RGB;
    void* bits = NULL;
    HBITMAP dib = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
    if (!dib) { SelectObject(dc, oldf); DeleteDC(dc); return; }
    HGDIOBJ oldb = SelectObject(dc, dib);
    memset(bits, 0, (size_t)texW * texH * 4);

    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(255, 255, 255));
    SetTextAlign(dc, TA_TOP | TA_LEFT);
    char ch = (char)c; TextOutA(dc, glow, glow, &ch, 1);
    GdiFlush();

    // coverage = blue channel (white-on-black render). glow = blurred halo, alpha = max(core,halo)
    int n = texW * texH;
    unsigned char* cov = (unsigned char*)malloc(n);
    unsigned char* src = (unsigned char*)bits;
    for (int i = 0; i < n; ++i) cov[i] = src[i * 4];
    unsigned char* rgba = (unsigned char*)malloc((size_t)n * 4);
    if (glow > 0) {
        unsigned char* halo = (unsigned char*)malloc(n);
        memcpy(halo, cov, n);
        boxBlur(halo, texW, texH, glow);
        for (int i = 0; i < n; ++i) {
            int a = cov[i]; int hh = (int)(halo[i] * 1.6f); if (hh > 255) hh = 255;
            int v = a > hh ? a : hh;
            rgba[i*4] = 255; rgba[i*4+1] = 255; rgba[i*4+2] = 255; rgba[i*4+3] = (unsigned char)v;
        }
        free(halo);
    } else {
        for (int i = 0; i < n; ++i) { rgba[i*4] = 255; rgba[i*4+1] = 255; rgba[i*4+2] = 255; rgba[i*4+3] = cov[i]; }
    }

    GLuint id = 0; glGenTextures(1, &id); glBindTexture(GL_TEXTURE_2D, id);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, texW, texH, 0, GL_RGBA, GL_UNSIGNED_BYTE, rgba);

    free(cov); free(rgba);
    SelectObject(dc, oldb); DeleteObject(dib);
    SelectObject(dc, oldf); DeleteDC(dc);

    gl.tex = id; gl.cellW = cellW; gl.cellH = cellH; gl.texW = texW; gl.texH = texH;
}

// hex pair "ab" -> 0..255
static int hex2(const char* p)
{
    auto h = [](char c)->int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    int hi = h(p[0]), lo = h(p[1]);
    return (hi < 0 || lo < 0) ? -1 : (hi * 16 + lo);
}
static bool isColorTag(const char* p)   // "<RRGGBBAA>"
{
    if (p[0] != '<') return false;
    for (int i = 1; i <= 8; ++i) {
        char c = p[i];
        if (!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'))) return false;
    }
    return p[9] == '>';
}

//---------------------------------------------------- texture index + cache ---
// Index: texture basename -> source (loose file path, or "zip\0entry"). Built by
// scanning Hudbot\ScriptGL (loose .tga take precedence over zipped, per Hudbot docs).
struct TexSrc { char name[64]; char path[MAX_PATH]; bool inZip; };
static const int  MAX_TEXSRC = 1024;
static TexSrc     sTexSrc[MAX_TEXSRC];
static int        sTexSrcCount = 0;

struct GLTex { char name[64]; GLuint id; int w, h; unsigned stamp; };
static const int  MAX_TEX = 256;
static GLTex      sTex[MAX_TEX];
static int        sTexCount = 0;

static const char* TEX_ROOT = "Hudbot\\ScriptGL";

static bool texHasName(const char* name)
{
    for (int i = 0; i < sTexSrcCount; ++i) if (_stricmp(sTexSrc[i].name, name) == 0) return true;
    return false;
}
static void texAddLoose(const char* name, const char* path)
{
    if (sTexSrcCount >= MAX_TEXSRC || texHasName(name)) return;
    TexSrc& t = sTexSrc[sTexSrcCount++];
    _snprintf(t.name, sizeof(t.name), "%s", name); t.name[63] = 0;
    _snprintf(t.path, sizeof(t.path), "%s", path); t.path[MAX_PATH-1] = 0;
    t.inZip = false;
}
static const char* sScanZip = NULL;
static void texZipEntryCb(const char* basename, void*)
{
    const char* dot = strrchr(basename, '.');
    if (!dot || _stricmp(dot, ".tga") != 0) return;
    if (sTexSrcCount >= MAX_TEXSRC || texHasName(basename)) return;   // loose precedence
    TexSrc& t = sTexSrc[sTexSrcCount++];
    _snprintf(t.name, sizeof(t.name), "%s", basename); t.name[63] = 0;
    _snprintf(t.path, sizeof(t.path), "%s", sScanZip); t.path[MAX_PATH-1] = 0;
    t.inZip = true;
}

static void texScanDir(const char* dir)   // recursive: loose .tga first, then .zip
{
    char pat[MAX_PATH]; _snprintf(pat, sizeof(pat), "%s\\*", dir); pat[MAX_PATH-1] = 0;
    WIN32_FIND_DATAA fd; HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    // pass 1: loose files + recurse
    do {
        if (fd.cFileName[0] == '.') continue;
        char full[MAX_PATH]; _snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName); full[MAX_PATH-1] = 0;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { texScanDir(full); continue; }
        const char* dot = strrchr(fd.cFileName, '.');
        if (dot && _stricmp(dot, ".tga") == 0) texAddLoose(fd.cFileName, full);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    // pass 2: zips (after loose, so loose wins)
    h = FindFirstFileA(pat, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            const char* dot = strrchr(fd.cFileName, '.');
            if (dot && _stricmp(dot, ".zip") == 0) {
                static char zp[MAX_PATH];
                _snprintf(zp, sizeof(zp), "%s\\%s", dir, fd.cFileName); zp[MAX_PATH-1] = 0;
                sScanZip = zp; hb_zip_list(zp, texZipEntryCb, NULL); sScanZip = NULL;
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
}

static void texBuildIndex()
{
    sTexSrcCount = 0;
    texScanDir(TEX_ROOT);
    flog("texture index: %d entries under %s", sTexSrcCount, TEX_ROOT);
}

// Load loose file into a malloc'd buffer.
static unsigned char* slurpFile(const char* path, unsigned long* len)
{
    FILE* f = fopen(path, "rb"); if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    if (n <= 0) { fclose(f); return NULL; }
    unsigned char* b = (unsigned char*)malloc(n);
    if (b && (long)fread(b, 1, n, f) != n) { free(b); b = NULL; }
    fclose(f); if (b) *len = (unsigned long)n; return b;
}

// Get (or lazily create) a GL texture by basename. Returns NULL if not found.
static GLTex* texGet(const char* name)
{
    for (int i = 0; i < sTexCount; ++i)
        if (_stricmp(sTex[i].name, name) == 0) { sTex[i].stamp = sFrame; return &sTex[i]; }

    TexSrc* src = NULL;
    for (int i = 0; i < sTexSrcCount; ++i) if (_stricmp(sTexSrc[i].name, name) == 0) { src = &sTexSrc[i]; break; }
    if (!src) return NULL;

    unsigned char* file = NULL; unsigned long flen = 0;
    if (src->inZip) hb_zip_read(src->path, src->name, &file, &flen);
    else            file = slurpFile(src->path, &flen);
    if (!file) return NULL;

    unsigned char* rgba = NULL; int w = 0, h = 0;
    bool ok = hb_decode_tga(file, flen, &rgba, &w, &h);
    free(file);
    if (!ok) return NULL;

    GLuint id = 0; glGenTextures(1, &id); glBindTexture(GL_TEXTURE_2D, id);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, rgba);
    free(rgba);

    GLTex* slot;
    if (sTexCount < MAX_TEX) slot = &sTex[sTexCount++];
    else {                                              // evict LRU
        slot = &sTex[0];
        for (int i = 1; i < sTexCount; ++i) if (sTex[i].stamp < slot->stamp) slot = &sTex[i];
        if (slot->id) glDeleteTextures(1, &slot->id);
    }
    _snprintf(slot->name, sizeof(slot->name), "%s", name); slot->name[63] = 0;
    slot->id = id; slot->w = w; slot->h = h; slot->stamp = sFrame;
    return slot;
}

static void texFreeAll()
{
    for (int i = 0; i < sTexCount; ++i) if (sTex[i].id) glDeleteTextures(1, &sTex[i].id);
    sTexCount = 0;
}

//============================================================================
//  gl* console commands  (all run inside the present hook: ctx current, ortho set)
//============================================================================
static const char* c_glColor4ub(void*, int, int argc, const char** argv)
{
    sLastCmd = "glColor4ub";
    if (argc >= 4) {
        sR = atoi(argv[1]); sG = atoi(argv[2]); sB = atoi(argv[3]);
        sA = (argc > 4) ? atoi(argv[4]) : 255;
        if (sInDraw) glColor4ub((GLubyte)sR,(GLubyte)sG,(GLubyte)sB,(GLubyte)sA);
    }
    return "";
}

static const char* c_glRectangle(void*, int, int argc, const char** argv)
{
    sLastCmd = "glRectangle";
    if (argc >= 5 && sInDraw) {
        int x = atoi(argv[1]), y = atoi(argv[2]), w = atoi(argv[3]), h = atoi(argv[4]);
        glDisable(GL_TEXTURE_2D);
        glColor4ub((GLubyte)sR,(GLubyte)sG,(GLubyte)sB,(GLubyte)sA);
        glBegin(GL_QUADS);
            glVertex2i(x,   y);
            glVertex2i(x+w, y);
            glVertex2i(x+w, y+h);
            glVertex2i(x,   y+h);
        glEnd();
    }
    return "";
}

static const char* c_glSetFont(void*, int, int argc, const char** argv)
{
    // glSetFont(name, pixelHeight, [renderMode=$GLEX_SMOOTH], [glowRadius])
    sLastCmd = "glSetFont";
    if (argc >= 3 && sInDraw) {
        bool aa  = (argc > 3) ? (atoi(argv[3]) != 0) : true;   // $GLEX_PIXEL(0)/$GLEX_SMOOTH(1)
        int  glow = (argc > 4) ? atoi(argv[4]) : 0;
        sCur = fontGetOrCreate(argv[1], atoi(argv[2]), aa, glow);
    }
    return "";
}

static const char* c_glDrawString(void*, int, int argc, const char** argv)
{
    sLastCmd = "glDrawString";
    if (argc < 4 || !sInDraw || !sCur) return "";
    glEnable(GL_TEXTURE_2D);
    glEnable(GL_BLEND); glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);

    const char* s = argv[3];
    const int baseX = atoi(argv[1]), baseY = atoi(argv[2]);
    int  penX = baseX, line = 0;
    int  r = sR, g = sG, b = sB, a = sA;
    const int glow = sCur->glow;

    for (const char* p = s; *p; ) {
        if (*p == '\n') { ++line; penX = baseX; ++p; continue; }
        if (isColorTag(p)) { r = hex2(p+1); g = hex2(p+3); b = hex2(p+5); a = hex2(p+7); p += 10; continue; }
        unsigned char c = (unsigned char)*p; ++p;
        Glyph* gp = &sCur->g[c];
        if (!gp->ready) renderGlyph(sCur, c);
        if (gp->tex) {
            float x0 = (float)(penX - glow), y0 = (float)(baseY + line * sCur->height - glow);
            float u = (float)gp->cellW / gp->texW, v = (float)gp->cellH / gp->texH;
            glColor4ub((GLubyte)r,(GLubyte)g,(GLubyte)b,(GLubyte)a);
            glBindTexture(GL_TEXTURE_2D, gp->tex);
            glBegin(GL_QUADS);
                glTexCoord2f(0,0); glVertex2f(x0,             y0);
                glTexCoord2f(u,0); glVertex2f(x0 + gp->cellW, y0);
                glTexCoord2f(u,v); glVertex2f(x0 + gp->cellW, y0 + gp->cellH);
                glTexCoord2f(0,v); glVertex2f(x0,             y0 + gp->cellH);
            glEnd();
        }
        penX += gp->advance;
    }
    return "";
}

static const char* c_glGetStringDimensions(void*, int, int argc, const char** argv)
{
    sLastCmd = "glGetStringDimensions";
    static char buf[32];
    int w = 0, h = 8;
    if (sCur && argc >= 2) {
        h = sCur->height;
        HDC dc = CreateCompatibleDC(NULL);
        HGDIOBJ old = SelectObject(dc, sCur->hfont);
        int lines = 1, lineW = 0;
        char run[512]; int rl = 0;
        auto measure = [&]() {
            if (rl) { run[rl] = 0; SIZE sz; GetTextExtentPoint32A(dc, run, rl, &sz); lineW += sz.cx; rl = 0; }
        };
        for (const char* p = argv[1]; *p; ) {
            if (*p == '\n')        { measure(); if (lineW > w) w = lineW; lineW = 0; ++lines; ++p; }
            else if (isColorTag(p)){ measure(); p += 10; }
            else                   { if (rl < (int)sizeof(run)-1) run[rl++] = *p; ++p; }
        }
        measure(); if (lineW > w) w = lineW;
        h = lines * sCur->height;
        SelectObject(dc, old); DeleteDC(dc);
    }
    _snprintf(buf, sizeof(buf), "%d %d", w, h); buf[31] = 0;
    return buf;
}

// thin pass-throughs (script passes the real GL enum, set in hudbot_gl.cs)
static const char* c_glBegin(void*, int, int argc, const char** argv) { sLastCmd="glBegin"; if (sInDraw && argc>=2) glBegin((GLenum)atoi(argv[1])); return ""; }
static const char* c_glEnd  (void*, int, int, const char**)           { sLastCmd="glEnd"; if (sInDraw) glEnd(); return ""; }
static const char* c_glVertex2i(void*, int, int argc, const char** argv){ sLastCmd="glVertex2i"; if (sInDraw && argc>=3) glVertex2i(atoi(argv[1]),atoi(argv[2])); return ""; }
static const char* c_glTexCoord2f(void*, int, int argc, const char** argv){ sLastCmd="glTexCoord2f"; if (sInDraw && argc>=3) glTexCoord2f((GLfloat)atof(argv[1]),(GLfloat)atof(argv[2])); return ""; }
static const char* c_glBlendFunc(void*, int, int argc, const char** argv){ sLastCmd="glBlendFunc"; if (sInDraw && argc>=3) glBlendFunc((GLenum)atoi(argv[1]),(GLenum)atoi(argv[2])); return ""; }
static const char* c_glTexEnvi(void*, int, int argc, const char** argv) { sLastCmd="glTexEnvi"; if (sInDraw && argc>=2) glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, atoi(argv[1])); return ""; }
static const char* c_glDisable(void*, int, int argc, const char** argv) { sLastCmd="glDisable"; if (sInDraw && argc>=2) glDisable((GLenum)atoi(argv[1])); return ""; }
static const char* c_glEnable (void*, int, int argc, const char** argv) { sLastCmd="glEnable"; if (sInDraw && argc>=2) glEnable((GLenum)atoi(argv[1])); return ""; }

// glBindTexture(name): enable + bind so the script can issue manual tex/vertex coords.
static GLTex* sBound = NULL;
static const char* c_glBindTexture(void*, int, int argc, const char** argv)
{
    sLastCmd = "glBindTexture";
    if (!sInDraw || argc < 2) return "";
    sBound = texGet(argv[1]);
    if (sBound) { glEnable(GL_TEXTURE_2D); glBindTexture(GL_TEXTURE_2D, sBound->id); }
    return "";
}

// glDrawTexture(name, mode, x, y, [scaleX], [scaleY], [radians])
static const char* c_glDrawTexture(void*, int, int argc, const char** argv)
{
    sLastCmd = "glDrawTexture";
    if (!sInDraw || argc < 5) return "";
    GLTex* t = texGet(argv[1]); if (!t) return "";
    int mode = atoi(argv[2]);
    float x = (float)atof(argv[3]), y = (float)atof(argv[4]);
    float sx = (argc > 5) ? (float)atof(argv[5]) : 1.f;
    float sy = (argc > 6) ? (float)atof(argv[6]) : 1.f;
    float rad = (argc > 7) ? (float)atof(argv[7]) : 0.f;
    float w = (float)t->w, h = (float)t->h;

    glEnable(GL_TEXTURE_2D);
    glBindTexture(GL_TEXTURE_2D, t->id);
    glColor4ub((GLubyte)sR,(GLubyte)sG,(GLubyte)sB,(GLubyte)sA);
    glPushMatrix();

    float x0, y0, x1, y1;
    if (mode == 1) {                       // $GLEX_CENTERED
        x0 = x - w/2; y0 = y - h/2; x1 = x + w/2; y1 = y + h/2;
    } else if (mode == 2) {                // $GLEX_SCALED (top-left)
        x0 = x; y0 = y; x1 = x + w*sx; y1 = y + h*sy;
    } else if (mode == 3) {                // $GLEX_ROTATED (center)
        glTranslatef(x, y, 0); glRotatef(rad * 57.2957795f, 0, 0, 1);
        x0 = -w*sx/2; y0 = -h*sy/2; x1 = w*sx/2; y1 = h*sy/2;
    } else {                               // $GLEX_DRAW (top-left, native)
        x0 = x; y0 = y; x1 = x + w; y1 = y + h;
    }
    glBegin(GL_QUADS);
        glTexCoord2f(0,0); glVertex2f(x0, y0);
        glTexCoord2f(1,0); glVertex2f(x1, y0);
        glTexCoord2f(1,1); glVertex2f(x1, y1);
        glTexCoord2f(0,1); glVertex2f(x0, y1);
    glEnd();
    glPopMatrix();
    return "";
}

static const char* c_glGetTextureDimensions(void*, int, int argc, const char** argv)
{
    sLastCmd = "glGetTextureDimensions";
    static char buf[32];
    int w = 0, h = 0;
    if (argc >= 2 && sInDraw) { GLTex* t = texGet(argv[1]); if (t) { w = t->w; h = t->h; } }
    _snprintf(buf, sizeof(buf), "%d %d", w, h); buf[31] = 0;
    return buf;
}

static const char* c_glRescanTextureDirectory(void*, int, int, const char**)
{
    if (sInDraw) texFreeAll();            // GL deletes need the context
    texBuildIndex();
    return "";
}

// hudbotInGame(0/1): the in-game gate. Called from hudbot_gl.cs's eventGuiOpen/
// Close("playGui") hooks so the HUD draws ONLY while the playGui is active.
static void releaseInGameCursor();   // defined with the mouse pump below
static const char* c_hudbotInGame(void*, int, int argc, const char** argv)
{
    sGate = (argc >= 2 && atoi(argv[1]) != 0);
    if (!sGate) releaseInGameCursor();   // leaving the game: unclip + show OS cursor
    return "";
}

//============================================================================
//  ScriptGL text input  (keyboard -> ScriptGL::onChar / onKey)
//============================================================================
// KronosInput.cs turns this ON via glTextInput(1) while a ScriptGL text field is
// focused. We then detour the engine's keyboard->bind dispatch (see the
// installKeyDispatchHook section + re/keydispatch_findings.md): each keyboard
// MAKE is forwarded to script and SWALLOWED so no action-map bind fires while
// typing. glTextInput(0) makes the detour inert again.
static volatile bool sScriptGLTextInput = false;

// Forward one key to script. Printable -> ScriptGL::onChar("<char>") (TorqueScript
// can't convert an ascii code back to a char, so pass the literal character,
// escaping \ and "); anything else -> ScriptGL::onKey(<DIK scancode>).
static void scriptglForwardKey(int ascii, int dik)
{
    if (!con()) return;
    flog("scriptglForwardKey ascii=%d dik=%d", ascii, dik);   // DIAG: hook reached the forward path
    if (ascii >= 32 && ascii < 127) {
        char buf[8]; int n = 0;
        if (ascii == '\\' || ascii == '"') buf[n++] = '\\';
        buf[n++] = (char)ascii; buf[n] = 0;
        pExecutef(con(), 2, "ScriptGL::onChar", buf);
    } else {
        char num[12]; _snprintf(num, sizeof(num), "%d", dik); num[11] = 0;
        pExecutef(con(), 2, "ScriptGL::onKey", num);
    }
}

static const char* c_glTextInput(void*, int, int argc, const char** argv)
{
    sScriptGLTextInput = (argc >= 2 && atoi(argv[1]) != 0);
    flog("glTextInput(%s) -> sScriptGLTextInput=%d", argc >= 2 ? argv[1] : "?", (int)sScriptGLTextInput);  // DIAG
    return sScriptGLTextInput ? "1" : "0";
}

static void registerCommands()
{
    addCmd("glColor4ub",            c_glColor4ub);
    addCmd("glColor",               c_glColor4ub);
    addCmd("glRectangle",           c_glRectangle);
    addCmd("glSetFont",             c_glSetFont);
    addCmd("glDrawString",          c_glDrawString);
    addCmd("glGetStringDimensions", c_glGetStringDimensions);
    addCmd("glBegin",               c_glBegin);
    addCmd("glEnd",                 c_glEnd);
    addCmd("glVertex2i",            c_glVertex2i);
    addCmd("glTexCoord2f",          c_glTexCoord2f);
    addCmd("glBlendFunc",           c_glBlendFunc);
    addCmd("glTexEnvi",             c_glTexEnvi);
    addCmd("glDisable",             c_glDisable);
    addCmd("glEnable",              c_glEnable);
    addCmd("glBindTexture",         c_glBindTexture);
    addCmd("glDrawTexture",         c_glDrawTexture);
    addCmd("glGetTextureDimensions",c_glGetTextureDimensions);
    addCmd("glRescanTextureDirectory", c_glRescanTextureDirectory);
    addCmd("hudbotInGame",          c_hudbotInGame);
    addCmd("glTextInput",           c_glTextInput);   // keyboard capture -> ScriptGL::onChar/onKey
    if (con()) pConPrintf(con(), "Hudbot ScriptGL: registered (gl* commands + text input)");
    flog("registered gl* commands (console=%p)", con());
}

//============================================================================
//  render hook — IAT-detoured present
//============================================================================
typedef BOOL (WINAPI* Present_t)(HDC);
static Present_t sRealPresent = NULL;

// --- mouse input: Hudbot onMouse* callbacks (drives the Kronos GUI drag/click) ---
// While the GUI cursor is up (TAB menu / shop), report cursor position + buttons to
// script so the GUI can be dragged/clicked. The engine shows the OS cursor in GUI
// mode and hides it during mouse-look, so CURSOR_SHOWING is the active signal.
static HWND sHwnd = NULL;
static bool sMouseActive = false, sLmb = false, sRmb = false;
static int  sLastMX = -99999, sLastMY = -99999;

// Reach the "MainWindow" SimCanvas via the engine's manager global + findObject
// (vtable+0x68), the same path the cursor console commands use.
static void* findCanvas()
{
    void* mgr = *(void**)0x006D4FBCu;
    if (!mgr) return NULL;
    void* vt = *(void**)mgr;
    if (!vt) return NULL;
    typedef void* (__thiscall* FindObj_t)(void*, const char*);
    FindObj_t fo = *(FindObj_t*)((char*)vt + 0x68);
    if (!fo) return NULL;
    return fo(mgr, "MainWindow");
}

// Engine GUI cursor (MainWindow SimCanvas), offsets found by runtime diff probe:
#define CANVAS_CURSOR_ON  0x1ac   // byte: GUI cursor up (TAB/shop) when nonzero
#define CANVAS_BUTTONS    0x1b0   // int: mouse button mask (bit0=LMB, bit1=RMB)
#define CANVAS_CURSOR_X   0x1f8   // int: cursor X in canvas/viewport space
#define CANVAS_CURSOR_Y   0x1fc   // int: cursor Y

static bool sForceOn = false;
static bool sClipped = false;
static bool sOsHidden = false;

// Hide/show the Windows cursor with a single counter adjustment we own, so we never
// fight the engine's own ShowCursor level (we move it by exactly one and put it back).
static void hideOs(bool hide)
{
    if (hide && !sOsHidden)      { ShowCursor(FALSE); sOsHidden = true;  }
    else if (!hide && sOsHidden) { ShowCursor(TRUE);  sOsHidden = false; }
}

// Called from the gate-off path (c_hudbotInGame(0)) when the playGui closes: we stop
// pumping then, so release the clip + restore the OS cursor here instead of pumpMouse.
static void releaseInGameCursor()
{
    ClipCursor(NULL); sClipped = false;
    hideOs(false);
}

static void pumpMouse()
{
    char* cv = (char*)findCanvas();
    if (!cv) return;
    if (!sHwnd) sHwnd = WindowFromDC(wglGetCurrentDC());

    // Button from GetAsyncKeyState: the engine mouse is NONEXCLUSIVE (the EXCLUSIVE
    // "mousefix" was reverted), so the OS sees the real hardware button - immune to
    // the engine clearing its own +0x1b0 state / closing the cursor on a GUI click,
    // which is what made polling +0x1b0 miss panel/menu clicks.
    bool lmb = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
    bool active = (cv[CANVAS_CURSOR_ON] != 0);

    // Latch the GUI cursor ON while LMB is held so the engine can't drop it mid-
    // click/drag before onMouseLMB/onMouseMove reach the Kronos scripts.
    if (lmb && !sLmb && (active || sMouseActive)) sForceOn = true;
    if (!lmb) sForceOn = false;
    if (sForceOn) { cv[CANVAS_CURSOR_ON] = 1; active = true; }

    // Confine the OS cursor to the window the WHOLE time we're in-game (pumpMouse
    // only runs while in-game). NONEXCLUSIVE doesn't auto-confine like EXCLUSIVE did,
    // so without this the cursor escapes during BOTH gameplay (mouse-look won't lock)
    // and the GUI (clicks could land on another app). Released in releaseInGameCursor.
    int clientW = 0, clientH = 0;
    if (sHwnd) {
        RECT rc; if (GetClientRect(sHwnd, &rc)) {
            clientW = rc.right - rc.left; clientH = rc.bottom - rc.top;
            POINT tl = {rc.left, rc.top}, br = {rc.right, rc.bottom};
            ClientToScreen(sHwnd, &tl); ClientToScreen(sHwnd, &br);
            RECT clip = {tl.x, tl.y, br.x, br.y}; ClipCursor(&clip); sClipped = true;
        }
    }

    if (active != sMouseActive) {
        sMouseActive = active;
        // Opening the GUI: drop the OS cursor at screen center so it doesn't appear
        // stuck at a clip edge left over from mouse-look, then sync from there.
        if (active && sHwnd && clientW > 0) {
            POINT c = {clientW / 2, clientH / 2}; ClientToScreen(sHwnd, &c);
            SetCursorPos(c.x, c.y);
        }
        pExecutef(con(), 2, "onMouseActive", active ? "1" : "0");
    }

    // Hide the OS cursor while in-game: during the GUI we draw our own arrow at the
    // synced position; during mouse-look it must be hidden anyway. One visible cursor.
    hideOs(true);

    if (!active) { sLmb = lmb; sLastMX = -99999; return; }

    // *** SINGLE SOURCE OF TRUTH ***  In NONEXCLUSIVE relative mode the engine builds
    // its OWN software cursor (+0x1f8/+0x1fc) by accumulating mouse deltas with its
    // own sensitivity/accel, so it DRIFTS away from the OS cursor -> what you see and
    // where the click lands diverge. Fix: overwrite the engine cursor from the actual
    // OS cursor every frame. Now engine cursor == OS cursor == our drawn arrow == the
    // GUI hit-test, all identical, zero drift. (Scale window-client px -> engine
    // viewport px, the coordinate space of +0x1f8/+0x1fc, captured in sScreenW/H.)
    int mx, my;
    POINT op;
    if (GetCursorPos(&op) && sHwnd && ScreenToClient(sHwnd, &op) && clientW > 0 && clientH > 0) {
        int cx = op.x, cy = op.y;
        if (cx < 0) cx = 0; else if (cx > clientW) cx = clientW;
        if (cy < 0) cy = 0; else if (cy > clientH) cy = clientH;
        mx = (sScreenW > 0) ? (int)((__int64)cx * sScreenW / clientW) : cx;
        my = (sScreenH > 0) ? (int)((__int64)cy * sScreenH / clientH) : cy;
        *(int*)(cv + CANVAS_CURSOR_X) = mx;   // pin the engine cursor to the OS cursor
        *(int*)(cv + CANVAS_CURSOR_Y) = my;
    } else {
        mx = *(int*)(cv + CANVAS_CURSOR_X);
        my = *(int*)(cv + CANVAS_CURSOR_Y);
    }

    if (mx != sLastMX || my != sLastMY) {
        sLastMX = mx; sLastMY = my;
        char xs[16], ys[16]; _snprintf(xs, sizeof(xs), "%d", mx); _snprintf(ys, sizeof(ys), "%d", my);
        pExecutef(con(), 3, "onMouseMove", xs, ys);
    }
    if (lmb != sLmb) { sLmb = lmb; pExecutef(con(), 2, "onMouseLMB", lmb ? "1" : "0"); }
}

// Draw a simple arrow cursor at (sLastMX,sLastMY) ON TOP of the GUI (the engine's
// own cursor is drawn under our overlay, so it's hidden behind the panels).
static void drawCursor()
{
    if (!sMouseActive) return;
    float x = (float)sLastMX, y = (float)sLastMY;
    glDisable(GL_TEXTURE_2D);
    glColor4ub(0, 0, 0, 255);                          // dark outline
    glBegin(GL_TRIANGLES);
        glVertex2f(x - 1, y - 1); glVertex2f(x - 1, y + 18); glVertex2f(x + 13, y + 13);
    glEnd();
    glColor4ub(255, 255, 255, 255);                    // white arrow
    glBegin(GL_TRIANGLES);
        glVertex2f(x + 1, y + 1); glVertex2f(x + 1, y + 15); glVertex2f(x + 11, y + 11);
    glEnd();
}

static void drawOverlay()
{
    if (sInDraw) return;
    if (!wglGetCurrentContext()) return;
    if (!con()) return;
    // Only draw in-game. sGate is set by the native `hudbotInGame` command, called
    // from hudbot_gl.cs's eventGuiOpen/Close("playGui") hooks (mirrors Hud.cs).
    // Keeps the HUD off the main-menu / connecting / loading screens.
    if (!sGate) return;

    GLint vp[4]; glGetIntegerv(GL_VIEWPORT, vp);
    int w = vp[2], h = vp[3];
    if (w <= 0 || h <= 0) return;

    sFrame++;
    sScreenW = w; sScreenH = h;
    sCur = NULL;                       // Hudbot requires glSetFont each frame

    pumpMouse();                       // report cursor/buttons to the GUI scripts

    glPushAttrib(GL_ENABLE_BIT | GL_CURRENT_BIT | GL_COLOR_BUFFER_BIT |
                 GL_TEXTURE_BIT | GL_DEPTH_BUFFER_BIT | GL_TRANSFORM_BIT |
                 GL_LINE_BIT | GL_POLYGON_BIT | GL_LIGHTING_BIT);
    glMatrixMode(GL_PROJECTION); glPushMatrix(); glLoadIdentity();
    glOrtho(0, w, h, 0, -1, 1);                       // top-left origin, y-down
    glMatrixMode(GL_MODELVIEW);  glPushMatrix(); glLoadIdentity();

    glDisable(GL_DEPTH_TEST); glDisable(GL_CULL_FACE); glDisable(GL_LIGHTING);
    glDisable(GL_TEXTURE_2D);  glDisable(GL_ALPHA_TEST);
    glEnable(GL_BLEND); glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

    sInDraw = true;
    char dim[32]; _snprintf(dim, sizeof(dim), "%d %d", w, h); dim[31] = 0;
    sPhase = 1; sLastCmd = "";
    pExecutef(con(), 2, "ScriptGL::playGui::onPreDraw",  dim);
    sPhase = 2; sLastCmd = "";
    pExecutef(con(), 2, "ScriptGL::playGui::onPostDraw", dim);
    sPhase = 3;
    drawCursor();                      // our cursor, on top of the panels
    sInDraw = false;

    glMatrixMode(GL_PROJECTION); glPopMatrix();
    glMatrixMode(GL_MODELVIEW);  glPopMatrix();
    glPopAttrib();
}

static volatile bool sDisabled = false;
static BOOL WINAPI hookPresent(HDC hdc)
{
    // Never let a fault in our draw path take the game down: contain it with SEH
    // and disable hudbot drawing if it ever throws (the engine keeps presenting).
    if (!sDisabled) {
        __try {
            drawOverlay();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            sDisabled = true;
            sInDraw = false;
            flog("EXCEPTION 0x%08x in drawOverlay (phase=%d hook=%s lastCmd=%s) -- drawing DISABLED",
                 GetExceptionCode(), sPhase, sPhase==1?"onPreDraw":sPhase==2?"onPostDraw":"setup", sLastCmd);
        }
    }
    return sRealPresent ? sRealPresent(hdc) : TRUE;
}

// IAT hook: in `mod`'s import table, point `dll!fn` at `hook`; return the original.
static void* iatHook(HMODULE mod, const char* dll, const char* fn, void* hook)
{
    BYTE* base = (BYTE*)mod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY d = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!d.VirtualAddress) return NULL;

    for (IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + d.VirtualAddress);
         imp->Name; ++imp)
    {
        if (_stricmp((const char*)(base + imp->Name), dll) != 0) continue;
        DWORD oftRva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
        IMAGE_THUNK_DATA* oft = (IMAGE_THUNK_DATA*)(base + oftRva);
        IMAGE_THUNK_DATA* ft  = (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
        for (; oft->u1.AddressOfData; ++oft, ++ft) {
            if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(base + oft->u1.AddressOfData);
            if (strcmp((const char*)ibn->Name, fn) != 0) continue;
            void* old = (void*)ft->u1.Function;
            DWORD prot;
            VirtualProtect(&ft->u1.Function, sizeof(void*), PAGE_READWRITE, &prot);
            ft->u1.Function = (ULONG_PTR)hook;
            VirtualProtect(&ft->u1.Function, sizeof(void*), prot, &prot);
            return old;
        }
    }
    return NULL;
}

static void installPresentHook()
{
    HMODULE exe = GetModuleHandleA(NULL);
    // Darkstar's GL surface flips via GDI SwapBuffers; some paths use wglSwapBuffers.
    void* orig = iatHook(exe, "gdi32.dll", "SwapBuffers", (void*)hookPresent);
    if (orig) { sRealPresent = (Present_t)orig; flog("hooked gdi32!SwapBuffers (orig=%p)", orig); return; }
    orig = iatHook(exe, "opengl32.dll", "wglSwapBuffers", (void*)hookPresent);
    if (orig) { sRealPresent = (Present_t)orig; flog("hooked opengl32!wglSwapBuffers (orig=%p)", orig); return; }
    flog("ERROR: no present import found to hook (SwapBuffers / wglSwapBuffers)");
}

//---------------------------------------------- private TrueType font load ----
static void loadFontDir()
{
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA("Hudbot\\Fonts\\*.ttf", &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    int n = 0;
    do {
        char path[MAX_PATH];
        _snprintf(path, sizeof(path), "Hudbot\\Fonts\\%s", fd.cFileName); path[MAX_PATH-1] = 0;
        if (AddFontResourceExA(path, FR_PRIVATE, 0)) ++n;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    flog("AddFontResource: %d private .ttf from Hudbot\\Fonts", n);
}

//------------------------------------------- keyboard->bind dispatch detour ----
// Inline-hook SimGame::processEvent (1.40.655 @0x00526560; __thiscall: this=ECX,
// event=[ESP+4]; returns `ret 4`). When ScriptGL text input is active we forward
// the key to script and return "handled" (EAX=1) so it doesn't fire a bind;
// otherwise we fall through to the original via a trampoline. Event field offsets
// + the full ABI/RE are in re/keydispatch_findings.md. (T1Vista.exe 1.3 uses a
// DIFFERENT VA/ABI - @0x0050d62c, event=EDX, plain ret - not wired here because
// Hudbot's address table is 1.40-only; drop-in once Hudbot is ported to 1.3.)
static const unsigned char* const KD_140 = (const unsigned char*)0x00526560;
static void* sKDTramp = NULL;

__declspec(naked) static void keyDispatchHook_140()
{
    __asm {
        mov     eax, [esp+4]                  // eax = event (thiscall stack arg)
        cmp     byte ptr sScriptGLTextInput, 0
        je      pass
        cmp     dword ptr [eax+0x04], 0x416   // type == SimInputEventType
        jne     pass
        cmp     byte ptr [eax+0x28], 3        // deviceType == SI_KEYBOARD
        jne     pass
        cmp     dword ptr [eax+0x20], 0       // deviceInst == 0
        jne     pass
        cmp     byte ptr [eax+0x29], 0x0A     // objType == SI_KEY
        jne     pass
        // a keyboard key event while typing -> swallow it (no bind); forward makes
        cmp     byte ptr [eax+0x2b], 1        // action == SI_MAKE ?
        jne     swallow
        movzx   ecx, byte ptr [eax+0x2c]      // ascii
        movzx   edx, byte ptr [eax+0x2a]      // DIK scancode
        push    edx
        push    ecx
        call    scriptglForwardKey            // __cdecl(int ascii, int dik)
        add     esp, 8
    swallow:
        mov     eax, 1                        // handled -> caller skips the bind
        ret     4                             // thiscall: pop the event arg
    pass:
        jmp     dword ptr [sKDTramp]          // original prologue + continue at 0x526565
    }
}

static void installKeyDispatchHook()
{
    // verify the prologue matches what we RE'd, or bail (text input just stays off)
    static const unsigned char expect[5] = { 0x56, 0x8B, 0x74, 0x24, 0x08 };  // PUSH ESI; MOV ESI,[ESP+8]
    if (memcmp((void*)KD_140, expect, 5) != 0) {
        flog("keyDispatch: prologue mismatch @0x526560 (%02X %02X %02X %02X %02X) - NOT hooking",
             KD_140[0], KD_140[1], KD_140[2], KD_140[3], KD_140[4]);
        return;
    }
    // trampoline = original 5 bytes (PUSH ESI; MOV ESI,[ESP+8]) + jmp 0x526565
    unsigned char* t = (unsigned char*)VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!t) { flog("keyDispatch: VirtualAlloc failed"); return; }
    memcpy(t, (void*)KD_140, 5);
    t[5] = 0xE9;
    *(int*)(t + 6) = (int)(0x00526565 - (int)(t + 10));
    sKDTramp = t;
    // patch the entry: jmp keyDispatchHook_140 (rel32 over the 5-byte prologue)
    DWORD prot;
    VirtualProtect((void*)KD_140, 5, PAGE_EXECUTE_READWRITE, &prot);
    unsigned char patch[5];
    patch[0] = 0xE9;
    *(int*)(patch + 1) = (int)((int)&keyDispatchHook_140 - ((int)KD_140 + 5));
    memcpy((void*)KD_140, patch, 5);
    VirtualProtect((void*)KD_140, 5, prot, &prot);
    FlushInstructionCache(GetCurrentProcess(), (void*)KD_140, 5);
    flog("keyDispatch: hooked SimGame::processEvent @0x526560 (tramp=%p)", sKDTramp);
}

//----------------------------------------------------------------- DllMain ----
extern "C" __declspec(dllexport) void* getPlugin() { return 0; }   // harmless loader probe

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        HMODULE self = NULL;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                           (LPCWSTR)(void*)&hookPresent, &self);
        flog("--- hudbot ScriptGL loaded (pinned=%p, console=%p) ---", (void*)self, con());
        loadFontDir();
        texBuildIndex();
        installPresentHook();
        registerCommands();
        installKeyDispatchHook();   // keyboard text input (glTextInput / ScriptGL::onChar/onKey)
    }
    return TRUE;
}
