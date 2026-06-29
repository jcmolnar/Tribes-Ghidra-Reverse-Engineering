// imgtest.cpp — verify hudbot_img against the real Hudbot zips.
#include "hudbot_img.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

static void listcb(const char* name, void*) { printf("    entry: %s\n", name); }

static void test(const char* zip, const char* entry)
{
    printf("== %s :: %s ==\n", zip, entry);
    int n = hb_zip_list(zip, listcb, 0);
    printf("  list -> %d entries\n", n);
    unsigned char* data = 0; unsigned long len = 0;
    if (!hb_zip_read(zip, entry, &data, &len)) { printf("  ZIP READ FAILED\n\n"); return; }
    printf("  inflated %lu bytes (TGA hdr type=%u bpp=%u w=%d h=%d)\n",
           len, data[2], data[16], data[12] | (data[13] << 8), data[14] | (data[15] << 8));
    unsigned char* rgba = 0; int w = 0, h = 0;
    if (!hb_decode_tga(data, len, &rgba, &w, &h)) { printf("  TGA DECODE FAILED\n\n"); free(data); return; }
    // sample a few pixels
    printf("  decoded RGBA %dx%d; px[0]=%02x%02x%02x%02x  center=%02x%02x%02x%02x\n",
           w, h, rgba[0], rgba[1], rgba[2], rgba[3],
           rgba[(h/2*w + w/2)*4], rgba[(h/2*w + w/2)*4+1], rgba[(h/2*w + w/2)*4+2], rgba[(h/2*w + w/2)*4+3]);
    printf("  OK\n\n");
    free(rgba); free(data);
}

int main()
{
    const char* root = "C:\\Dynamix\\Tribes\\Hudbot\\";
    char zip[512];
    snprintf(zip, sizeof(zip), "%sHUDs\\HealthHUD.zip", root);   test(zip, "Health.Bar.tga");
    snprintf(zip, sizeof(zip), "%sHUDs\\HealthHUD.zip", root);   test(zip, "Health.Frame.tga");
    snprintf(zip, sizeof(zip), "%sScriptGL\\hl2packs.zip", root); test(zip, "hl2.energy.tga");
    snprintf(zip, sizeof(zip), "%sHUDs\\WeaponHUD.zip", root);   test(zip, "WeaponHUD.disc.tga");
    return 0;
}
