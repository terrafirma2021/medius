/* Medius v3.4.7 host: runtime/memory_copy.c. */
#include "../include/types.h"

/* Native entry: 0x42030f54. */
/* Original function-byte SHA-256:
 * bdfd8600b135b075868306177cda8e818c0f6908d29e6b4f6021b239e56150e1. */
/* Copy forward with native alignment-dependent BYTE/WORD accesses; return no
 * pointer. Equal alignment first copies BYTES to align both addresses, then
 * sixteen-byte blocks, WORDs and BYTES. Each aligned block has four interleaved
 * WORD loads/stores. Unequal alignment first aligns source only; block WORDs are
 * written as BYTES in order 1,2,3,0 for the first three WORDs and 0,1,2,3 for the
 * fourth. Remaining WORDs use BYTE order0,1,2,3. Overlap is not memmove-safe;
 * these exact forward load/store widths and ordering determine corruption.
 *
 * Large lengths retain the native counter truncation. Equal-alignment block
 * count is (((remaining-16)>>4)&65535)+1; high bits are discarded and cursors
 * follow only the blocks actually copied. Unequal-alignment block count starts
 * as (remaining>>4)&65535; zero becomes 0x10000000 blocks through unsigned
 * subtract/shift/add, requesting 4 GiB of accesses before the tail. After that
 * block loop, unequal-alignment cursors are recomputed from the PRE-LOOP bases
 * plus remaining rounded down to 16, even when fewer blocks were copied.
 * Addresses wrap 32 bits. Zero length reads/writes nothing. No NULL, capacity,
 * overlap, overflow, MMIO suitability, fault recovery or large-span repair. */
void medius_copy_bytes(void *destination,void *source,unsigned int length)
{
    unsigned int write_address=(unsigned int)destination;
    unsigned int read_address=(unsigned int)source;
    if (((write_address^read_address)&3U)==0) {
        while (write_address&3U) {
            if (length==0)
                return;
            unsigned char value=*(const volatile unsigned char *)read_address;
            ++read_address;
            *(volatile unsigned char *)write_address=value;
            ++write_address;
            --length;
        }
        if (length>=16) {
            unsigned int blocks=(((length-16U)>>4)&65535U)+1U;
            do {
                unsigned int word=*(const volatile unsigned int *)read_address;
                *(volatile unsigned int *)write_address=word;
                word=*(const volatile unsigned int *)(read_address+4U);
                *(volatile unsigned int *)(write_address+4U)=word;
                word=*(const volatile unsigned int *)(read_address+8U);
                *(volatile unsigned int *)(write_address+8U)=word;
                word=*(const volatile unsigned int *)(read_address+12U);
                read_address+=16;
                *(volatile unsigned int *)(write_address+12U)=word;
                write_address+=16;
            } while (--blocks);
            length&=15U;
        }
        while (length>=4) {
            unsigned int word=*(const volatile unsigned int *)read_address;
            read_address+=4;
            *(volatile unsigned int *)write_address=word;
            write_address+=4;
            length-=4;
        }
    } else {
        if (length==0)
            return;
        while (read_address&3U) {
            unsigned char value=*(const volatile unsigned char *)read_address;
            ++read_address;
            *(volatile unsigned char *)write_address=value;
            ++write_address;
            if (--length==0)
                return;
        }
        if (length>=16) {
            unsigned int original_read=read_address;
            unsigned int original_write=write_address;
            unsigned int blocks=(((length>>4)&65535U)*16U-16U)/16U+1U;
            do {
                unsigned int word=*(const volatile unsigned int *)read_address;
                *(volatile unsigned char *)(write_address+1U)=(unsigned char)(word>>8);
                *(volatile unsigned char *)(write_address+2U)=(unsigned char)(word>>16);
                *(volatile unsigned char *)(write_address+3U)=(unsigned char)(word>>24);
                *(volatile unsigned char *)write_address=(unsigned char)word;
                word=*(const volatile unsigned int *)(read_address+4U);
                *(volatile unsigned char *)(write_address+5U)=(unsigned char)(word>>8);
                *(volatile unsigned char *)(write_address+6U)=(unsigned char)(word>>16);
                *(volatile unsigned char *)(write_address+7U)=(unsigned char)(word>>24);
                *(volatile unsigned char *)(write_address+4U)=(unsigned char)word;
                word=*(const volatile unsigned int *)(read_address+8U);
                *(volatile unsigned char *)(write_address+9U)=(unsigned char)(word>>8);
                *(volatile unsigned char *)(write_address+10U)=(unsigned char)(word>>16);
                *(volatile unsigned char *)(write_address+11U)=(unsigned char)(word>>24);
                *(volatile unsigned char *)(write_address+8U)=(unsigned char)word;
                word=*(const volatile unsigned int *)(read_address+12U);
                read_address+=16;
                *(volatile unsigned char *)(write_address+12U)=(unsigned char)word;
                *(volatile unsigned char *)(write_address+13U)=(unsigned char)(word>>8);
                *(volatile unsigned char *)(write_address+14U)=(unsigned char)(word>>16);
                *(volatile unsigned char *)(write_address+15U)=(unsigned char)(word>>24);
                write_address+=16;
            } while (--blocks);
            unsigned int span=length&~15U;
            read_address=original_read+span;
            write_address=original_write+span;
            length&=15U;
        }
        while (length>=4) {
            unsigned int word=*(const volatile unsigned int *)read_address;
            read_address+=4;
            *(volatile unsigned char *)write_address=(unsigned char)word;
            *(volatile unsigned char *)(write_address+1U)=(unsigned char)(word>>8);
            *(volatile unsigned char *)(write_address+2U)=(unsigned char)(word>>16);
            *(volatile unsigned char *)(write_address+3U)=(unsigned char)(word>>24);
            write_address+=4;
            length-=4;
        }
    }
    while (length!=0) {
        unsigned char value=*(const volatile unsigned char *)read_address;
        ++read_address;
        *(volatile unsigned char *)write_address=value;
        ++write_address;
        --length;
    }
}
