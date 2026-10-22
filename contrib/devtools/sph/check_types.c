/* Copyright (c) 2026 The Neurai developers. MIT license, see COPYING. */
/* Exercise byte order, all alignments, exact writes and untouched canaries.
 * Build twice with SPH_TYPES_HEADER selecting algo/ and crypto/ copies. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef SPH_TYPES_HEADER
#define SPH_TYPES_HEADER "algo/sph_types.h"
#endif
#include SPH_TYPES_HEADER

int main(void)
{
    unsigned char storage[64];
    unsigned checks=0;
    const uint64_t cases[]={0,1,UINT64_C(0x0123456789abcdef),UINT64_C(0x8000000000000000),UINT64_MAX};
    size_t n,offset,byte;
    for(n=0;n<sizeof cases/sizeof *cases;n++) for(offset=0;offset<16;offset++) {
        for(unsigned format=0;format<4;format++) {
            const unsigned width=format<2 ? 4 : 8;
            const unsigned big=format%2;
            const uint64_t value=width==4 ? (uint32_t)cases[n] : cases[n];
            memset(storage,0xa5,sizeof storage);
            unsigned char* p=storage+16+offset;
            if(width==4) { if(big)sph_enc32be(p,(sph_u32)value);else sph_enc32le(p,(sph_u32)value); }
            else { if(big)sph_enc64be(p,(sph_u64)value);else sph_enc64le(p,(sph_u64)value); }
            for(byte=0;byte<sizeof storage;byte++) {
                const size_t start=16+offset;
                const unsigned char expected=byte>=start && byte<start+width ?
                    (unsigned char)(value>>(8*(big ? width-1-(byte-start) : byte-start))) : 0xa5;
                if(storage[byte]!=expected) { fprintf(stderr,"byte mismatch format=%u offset=%zu byte=%zu\n",format,offset,byte);return 1; }
                checks++;
            }
            const uint64_t decoded=width==4 ? (big ? sph_dec32be(p) : sph_dec32le(p)) :
                (big ? sph_dec64be(p) : sph_dec64le(p));
            if(decoded!=value)return 2;
            checks++;
        }
    }
    printf("SPH type checks passed: %u\n",checks);
    return 0;
}
