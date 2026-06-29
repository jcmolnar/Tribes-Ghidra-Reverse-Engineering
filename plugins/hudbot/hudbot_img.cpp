//============================================================================
// hudbot_img.cpp — inflate + zip + TGA (see hudbot_img.h).
//============================================================================
#include "hudbot_img.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

//=================================== INFLATE ================================
// RFC1951 DEFLATE decompressor — Mark Adler's "puff" reference (public domain),
// reproduced compactly. Decodes one raw deflate stream into a pre-sized buffer.
namespace {

struct State {
    unsigned char* out; unsigned long outlen, outcnt;
    const unsigned char* in; unsigned long inlen, incnt;
    int bitbuf, bitcnt;
};

int bits(State* s, int need)
{
    long val = s->bitbuf;
    while (s->bitcnt < need) {
        if (s->incnt == s->inlen) return -1;
        val |= (long)(s->in[s->incnt++]) << s->bitcnt;
        s->bitcnt += 8;
    }
    s->bitbuf = (int)(val >> need);
    s->bitcnt -= need;
    return (int)(val & ((1L << need) - 1));
}

int stored(State* s)
{
    s->bitbuf = 0; s->bitcnt = 0;                         // discard to byte boundary
    if (s->incnt + 4 > s->inlen) return 2;
    unsigned len = s->in[s->incnt++]; len |= s->in[s->incnt++] << 8;
    unsigned nlen = s->in[s->incnt++]; nlen |= s->in[s->incnt++] << 8;
    if (len != (~nlen & 0xffff)) return -2;
    if (s->incnt + len > s->inlen) return 2;
    if (s->outcnt + len > s->outlen) return 1;
    while (len--) s->out[s->outcnt++] = s->in[s->incnt++];
    return 0;
}

struct Huffman { short* count; short* symbol; };

int decode(State* s, const Huffman* h)
{
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= 15; len++) {
        int b = bits(s, 1); if (b < 0) return b;
        code |= b;
        int count = h->count[len];
        if (code - count < first) return h->symbol[index + (code - first)];
        index += count; first += count; first <<= 1; code <<= 1;
    }
    return -10;
}

int construct(Huffman* h, const short* length, int n)
{
    int len;
    for (len = 0; len <= 15; len++) h->count[len] = 0;
    for (int sym = 0; sym < n; sym++) h->count[length[sym]]++;
    if (h->count[0] == n) return 0;
    int left = 1;
    for (len = 1; len <= 15; len++) { left <<= 1; left -= h->count[len]; if (left < 0) return left; }
    short offs[16]; offs[1] = 0;
    for (len = 1; len < 15; len++) offs[len + 1] = offs[len] + h->count[len];
    for (int sym = 0; sym < n; sym++) if (length[sym] != 0) h->symbol[offs[length[sym]]++] = (short)sym;
    return left;
}

int codes(State* s, const Huffman* lencode, const Huffman* distcode)
{
    static const short lens[29] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
    static const short lext[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
    static const short dists[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
    static const short dext[30] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
    int sym;
    do {
        sym = decode(s, lencode);
        if (sym < 0) return sym;
        if (sym < 256) {
            if (s->outcnt == s->outlen) return 1;
            s->out[s->outcnt++] = (unsigned char)sym;
        } else if (sym > 256) {
            sym -= 257;
            if (sym >= 29) return -9;
            int e = bits(s, lext[sym]); if (e < 0) return e;
            int len = lens[sym] + e;
            sym = decode(s, distcode); if (sym < 0) return sym;
            e = bits(s, dext[sym]); if (e < 0) return e;
            unsigned dist = dists[sym] + e;
            if (dist > s->outcnt) return -11;
            if (s->outcnt + len > s->outlen) return 1;
            while (len--) { s->out[s->outcnt] = s->out[s->outcnt - dist]; s->outcnt++; }
        }
    } while (sym != 256);
    return 0;
}

int fixed(State* s)
{
    static short lencnt[16], lensym[288], distcnt[16], distsym[30];
    static int built = 0;
    static Huffman lencode = {lencnt, lensym}, distcode = {distcnt, distsym};
    if (!built) {
        short lengths[288]; int i;
        for (i = 0; i < 144; i++) lengths[i] = 8;
        for (; i < 256; i++) lengths[i] = 9;
        for (; i < 280; i++) lengths[i] = 7;
        for (; i < 288; i++) lengths[i] = 8;
        construct(&lencode, lengths, 288);
        for (i = 0; i < 30; i++) lengths[i] = 5;
        construct(&distcode, lengths, 30);
        built = 1;
    }
    return codes(s, &lencode, &distcode);
}

int dynamic(State* s)
{
    static const short order[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
    short lengths[288 + 30];
    short lencnt[16], lensym[288], distcnt[16], distsym[30];
    Huffman lencode = {lencnt, lensym}, distcode = {distcnt, distsym};

    int nlen = bits(s, 5) + 257;
    int ndist = bits(s, 5) + 1;
    int ncode = bits(s, 4) + 4;
    if (nlen > 286 || ndist > 30) return -3;
    int index;
    for (index = 0; index < ncode; index++) lengths[order[index]] = (short)bits(s, 3);
    for (; index < 19; index++) lengths[order[index]] = 0;
    int err = construct(&lencode, lengths, 19);
    if (err != 0) return -4;
    index = 0;
    while (index < nlen + ndist) {
        int sym = decode(s, &lencode); if (sym < 0) return sym;
        if (sym < 16) lengths[index++] = (short)sym;
        else {
            int len = 0;
            if (sym == 16) { if (index == 0) return -5; len = lengths[index - 1]; sym = 3 + bits(s, 2); }
            else if (sym == 17) sym = 3 + bits(s, 3);
            else sym = 11 + bits(s, 7);
            if (index + sym > nlen + ndist) return -6;
            while (sym--) lengths[index++] = (short)len;
        }
    }
    if (construct(&lencode, lengths, nlen) && (nlen != lencnt[0] + lencnt[1])) return -7;
    if (construct(&distcode, lengths + nlen, ndist) && (ndist != distcnt[0] + distcnt[1])) return -8;
    return codes(s, &lencode, &distcode);
}

} // namespace

int hb_inflate(unsigned char* out, unsigned long outlen,
               const unsigned char* in, unsigned long inlen)
{
    State s;
    s.out = out; s.outlen = outlen; s.outcnt = 0;
    s.in = in; s.inlen = inlen; s.incnt = 0;
    s.bitbuf = 0; s.bitcnt = 0;
    int err;
    do {
        int last = bits(&s, 1);
        int type = bits(&s, 2);
        if (type == 0) err = stored(&s);
        else if (type == 1) err = fixed(&s);
        else if (type == 2) err = dynamic(&s);
        else return -1;
        if (err != 0) return err;
        if (last) break;
    } while (1);
    return 0;
}

//==================================== ZIP ==================================
namespace {
inline unsigned rd16(const unsigned char* p) { return p[0] | (p[1] << 8); }
inline unsigned rd32(const unsigned char* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((unsigned)p[3] << 24); }

const char* base_name(const char* path)
{
    const char* b = path;
    for (const char* p = path; *p; ++p) if (*p == '/' || *p == '\\') b = p + 1;
    return b;
}

// Load whole file. Caller free()s. Returns NULL on failure.
unsigned char* slurp(const char* path, unsigned long* outLen)
{
    FILE* f = fopen(path, "rb"); if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    if (n <= 0) { fclose(f); return NULL; }
    unsigned char* buf = (unsigned char*)malloc(n);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, n, f); fclose(f);
    if ((long)got != n) { free(buf); return NULL; }
    *outLen = (unsigned long)n;
    return buf;
}

// Find End Of Central Directory; return offset of central dir + entry count.
bool find_eocd(const unsigned char* z, unsigned long n, unsigned* cdOff, unsigned* cdCount)
{
    if (n < 22) return false;
    long max = (n > 0xFFFF + 22) ? 0xFFFF + 22 : (long)n;
    for (long i = (long)n - 22; i >= (long)n - max; --i) {
        if (i < 0) break;
        if (rd32(z + i) == 0x06054b50) {
            *cdCount = rd16(z + i + 10);
            *cdOff   = rd32(z + i + 16);
            return true;
        }
    }
    return false;
}

// Decompress a central-directory entry at z+cdEntry into a malloc'd buffer.
unsigned char* extract_entry(const unsigned char* z, unsigned long zlen,
                             unsigned cdEntry, unsigned long* outLen)
{
    const unsigned char* c = z + cdEntry;
    if (rd32(c) != 0x02014b50) return NULL;
    unsigned method  = rd16(c + 10);
    unsigned csize   = rd32(c + 20);
    unsigned usize   = rd32(c + 24);
    unsigned nameLen = rd16(c + 28);
    unsigned extraC  = rd16(c + 30);
    unsigned commLen = rd16(c + 32);
    unsigned lho     = rd32(c + 42);
    (void)extraC; (void)commLen; (void)nameLen;

    if (lho + 30 > zlen) return NULL;
    const unsigned char* l = z + lho;
    if (rd32(l) != 0x04034b50) return NULL;
    unsigned lNameLen = rd16(l + 26);
    unsigned lExtra   = rd16(l + 28);
    const unsigned char* data = l + 30 + lNameLen + lExtra;
    if (data + csize > z + zlen) return NULL;

    unsigned char* out = (unsigned char*)malloc(usize ? usize : 1);
    if (!out) return NULL;
    if (method == 0) {
        if (csize != usize) { free(out); return NULL; }
        memcpy(out, data, usize);
    } else if (method == 8) {
        if (hb_inflate(out, usize, data, csize) != 0) { free(out); return NULL; }
    } else { free(out); return NULL; }
    *outLen = usize;
    return out;
}

// Iterate central directory; cb returns the cd-entry offset to extract, or pass through.
template<class F> void iter_cd(const unsigned char* z, unsigned long n, F f)
{
    unsigned cdOff, cdCount;
    if (!find_eocd(z, n, &cdOff, &cdCount)) return;
    unsigned p = cdOff;
    for (unsigned i = 0; i < cdCount; ++i) {
        if (p + 46 > n) break;
        const unsigned char* c = z + p;
        if (rd32(c) != 0x02014b50) break;
        unsigned nameLen = rd16(c + 28);
        unsigned extraC  = rd16(c + 30);
        unsigned commLen = rd16(c + 32);
        char name[260];
        unsigned cn = nameLen < sizeof(name) - 1 ? nameLen : sizeof(name) - 1;
        memcpy(name, c + 46, cn); name[cn] = 0;
        f(p, name);
        p += 46 + nameLen + extraC + commLen;
    }
}
} // namespace

bool hb_zip_read(const char* zipPath, const char* wanted,
                 unsigned char** outData, unsigned long* outLen)
{
    unsigned long zlen = 0;
    unsigned char* z = slurp(zipPath, &zlen);
    if (!z) return false;
    unsigned found = 0; bool hit = false;
    iter_cd(z, zlen, [&](unsigned off, const char* name) {
        if (!hit && _stricmp(base_name(name), wanted) == 0) { found = off; hit = true; }
    });
    bool ok = false;
    if (hit) {
        unsigned char* d = extract_entry(z, zlen, found, outLen);
        if (d) { *outData = d; ok = true; }
    }
    free(z);
    return ok;
}

int hb_zip_list(const char* zipPath, void (*cb)(const char*, void*), void* user)
{
    unsigned long zlen = 0;
    unsigned char* z = slurp(zipPath, &zlen);
    if (!z) return -1;
    int count = 0;
    iter_cd(z, zlen, [&](unsigned, const char* name) { cb(base_name(name), user); ++count; });
    free(z);
    return count;
}

//==================================== TGA ==================================
// Truecolor (2) / grayscale (3), uncompressed or RLE (10/11). 8/24/32 bpp. -> RGBA.
bool hb_decode_tga(const unsigned char* d, unsigned long len,
                   unsigned char** outRGBA, int* outW, int* outH)
{
    if (len < 18) return false;
    unsigned idLen   = d[0];
    unsigned cmType  = d[1];
    unsigned imgType = d[2];
    int w = d[12] | (d[13] << 8);
    int h = d[14] | (d[15] << 8);
    unsigned bpp = d[16];
    unsigned desc = d[17];
    if (cmType != 0) return false;                         // no color-mapped support
    if (w <= 0 || h <= 0 || w > 8192 || h > 8192) return false;
    bool rle = (imgType == 10 || imgType == 11);
    unsigned base = imgType & 0x07;
    if (base != 2 && base != 3) return false;              // truecolor or grayscale only
    if (bpp != 8 && bpp != 24 && bpp != 32) return false;

    const unsigned char* p = d + 18 + idLen;
    const unsigned char* end = d + len;
    unsigned bytespp = bpp / 8;
    unsigned char* rgba = (unsigned char*)malloc((size_t)w * h * 4);
    if (!rgba) return false;

    // decode into a linear pixel array (source order), RGBA
    unsigned npix = (unsigned)w * h;
    unsigned char* px = rgba;
    auto emit = [&](const unsigned char* s) {
        unsigned char r, g, b, a = 255;
        if (bytespp == 1) { r = g = b = s[0]; }
        else { b = s[0]; g = s[1]; r = s[2]; if (bytespp == 4) a = s[3]; }
        px[0] = r; px[1] = g; px[2] = b; px[3] = a; px += 4;
    };

    if (!rle) {
        if (p + (size_t)npix * bytespp > end) { free(rgba); return false; }
        for (unsigned i = 0; i < npix; ++i) emit(p + (size_t)i * bytespp);
    } else {
        unsigned done = 0;
        while (done < npix) {
            if (p >= end) { free(rgba); return false; }
            unsigned hdr = *p++;
            unsigned count = (hdr & 0x7f) + 1;
            if (done + count > npix) { free(rgba); return false; }
            if (hdr & 0x80) {                              // RLE packet: one pixel repeated
                if (p + bytespp > end) { free(rgba); return false; }
                for (unsigned i = 0; i < count; ++i) emit(p);
                p += bytespp;
            } else {                                       // raw packet
                if (p + (size_t)count * bytespp > end) { free(rgba); return false; }
                for (unsigned i = 0; i < count; ++i) emit(p + (size_t)i * bytespp);
                p += (size_t)count * bytespp;
            }
            done += count;
        }
    }

    // TGA origin: bit5 of desc set => top-left already; clear => bottom-left, flip rows.
    if (!(desc & 0x20)) {
        unsigned stride = (unsigned)w * 4;
        unsigned char* tmp = (unsigned char*)malloc(stride);
        if (tmp) {
            for (int y = 0; y < h / 2; ++y) {
                unsigned char* a = rgba + (size_t)y * stride;
                unsigned char* b = rgba + (size_t)(h - 1 - y) * stride;
                memcpy(tmp, a, stride); memcpy(a, b, stride); memcpy(b, tmp, stride);
            }
            free(tmp);
        }
    }

    *outRGBA = rgba; *outW = w; *outH = h;
    return true;
}
