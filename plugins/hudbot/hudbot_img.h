//============================================================================
// hudbot_img.h — texture loading for the Hudbot ScriptGL port.
//   * raw DEFLATE inflate (RFC1951, Mark Adler "puff" algorithm, public domain)
//   * minimal .zip central-directory reader (store + deflate)
//   * TGA decoder (truecolor/grayscale, uncompressed + RLE, 8/24/32 bpp) -> RGBA
//============================================================================
#pragma once
#include <cstddef>

// Inflate `inlen` bytes at `in` into `out` (caller sizes `out` to the known
// uncompressed length). Returns 0 on success, nonzero on error.
int hb_inflate(unsigned char* out, unsigned long outlen,
               const unsigned char* in, unsigned long inlen);

// Decode a TGA image in memory to a freshly malloc'd RGBA8 buffer (top-left
// origin, tightly packed w*h*4). Caller free()s *outRGBA. Returns true on success.
bool hb_decode_tga(const unsigned char* data, unsigned long len,
                   unsigned char** outRGBA, int* outW, int* outH);

// Read one entry (by basename, path/case-insensitive) from a .zip file on disk
// into a freshly malloc'd buffer. Caller free()s *outData. Returns true on success.
bool hb_zip_read(const char* zipPath, const char* basename,
                 unsigned char** outData, unsigned long* outLen);

// Enumerate entry basenames in a .zip (callback per entry). Returns count, or -1.
int hb_zip_list(const char* zipPath, void (*cb)(const char* basename, void* user), void* user);
