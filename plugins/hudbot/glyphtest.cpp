// glyphtest.cpp — verify the GDI glyph-coverage path (renderGlyph's GDI half)
// without a GL context: render a char to a top-down 32-bit DIB exactly as
// renderGlyph does, extract coverage, print a stats + ASCII preview.
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static void test(const char* font, int pixH, char ch, bool aa)
{
    HDC dc = CreateCompatibleDC(NULL);
    HFONT hf = CreateFontA(-pixH,0,0,0,FW_NORMAL,0,0,0,ANSI_CHARSET,OUT_TT_PRECIS,
                           CLIP_DEFAULT_PRECIS, aa?ANTIALIASED_QUALITY:NONANTIALIASED_QUALITY,
                           DEFAULT_PITCH|FF_DONTCARE, font);
    HGDIOBJ oldf = SelectObject(dc, hf);
    TEXTMETRICA tm; GetTextMetricsA(dc,&tm);
    int cw=0; ABC abc; if (GetCharABCWidthsA(dc,ch,ch,&abc)) cw=abc.abcA+(int)abc.abcB+abc.abcC;
    if (cw<=0){ INT w0=0; GetCharWidth32A(dc,ch,ch,&w0); cw=w0; }

    int glow=0, cellW=cw+2*glow+2, cellH=tm.tmHeight+2*glow+2;
    int texW=1; while(texW<cellW) texW<<=1;
    int texH=1; while(texH<cellH) texH<<=1;

    BITMAPINFO bi; memset(&bi,0,sizeof(bi));
    bi.bmiHeader.biSize=sizeof(BITMAPINFOHEADER); bi.bmiHeader.biWidth=texW;
    bi.bmiHeader.biHeight=-texH; bi.bmiHeader.biPlanes=1; bi.bmiHeader.biBitCount=32; bi.bmiHeader.biCompression=BI_RGB;
    void* bits=NULL; HBITMAP dib=CreateDIBSection(dc,&bi,DIB_RGB_COLORS,&bits,NULL,0);
    HGDIOBJ oldb=SelectObject(dc,dib);
    memset(bits,0,(size_t)texW*texH*4);
    SetBkMode(dc,TRANSPARENT); SetTextColor(dc,RGB(255,255,255)); SetTextAlign(dc,TA_TOP|TA_LEFT);
    TextOutA(dc, glow, glow, &ch, 1); GdiFlush();

    unsigned char* src=(unsigned char*)bits;
    int n=texW*texH, ink=0, maxv=0; long sum=0;
    for(int i=0;i<n;++i){ int v=src[i*4]; if(v>0)ink++; if(v>maxv)maxv=v; sum+=v; }

    printf("== %s '%c' %dpx aa=%d ==\n", font, ch, pixH, aa?1:0);
    printf("  tmHeight=%d ascent=%d advance=%d  cell=%dx%d tex=%dx%d\n",
           tm.tmHeight, tm.tmAscent, cw, cellW, cellH, texW, texH);
    printf("  coverage: ink=%d/%d maxv=%d avg=%ld\n", ink, n, maxv, n?sum/n:0);
    // ASCII preview of the cell
    for(int y=0;y<cellH && y<24;++y){ printf("  ");
        for(int x=0;x<cellW && x<40;++x){ int v=src[(y*texW+x)*4];
            putchar(v>200?'#':v>96?'+':v>16?'.':' '); }
        putchar('\n'); }
    printf("\n");
    SelectObject(dc,oldb); DeleteObject(dib);
    SelectObject(dc,oldf); DeleteObject(hf); DeleteDC(dc);
}

int main()
{
    AddFontResourceExA("C:\\Dynamix\\Tribes\\Hudbot\\Fonts\\halflife2.ttf", FR_PRIVATE, 0);
    test("Arial", 24, 'A', true);
    test("Arial", 24, 'A', false);
    test("HalfLife2", 28, 'K', true);   // typeface name inside halflife2.ttf may differ
    test("Tahoma", 16, 'g', true);
    return 0;
}
