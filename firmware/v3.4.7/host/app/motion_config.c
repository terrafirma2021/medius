/* Medius v3.4.7 host — app/motion_config.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries. */
static unsigned int motion_config_u32(const unsigned char *bytes)
{
    const volatile unsigned char *p=bytes;
    unsigned int second=p[1],first=p[0],third=p[2],fourth=p[3];
    return first|(second<<8)|(third<<16)|(fourth<<24);
}

/* Native entry: 0x4200d1d8. */
/*
 * Medius v3.4.7 — host application; 0x4200d1d8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 4aab807c482d224f07d0da150bf400e352fca5b9f56483926a6508884898af6f.
 */

/*
 * Load the fixed44,484-byte motion configuration. NULL output/image returns-1
 * without clearing output. Otherwise clear152 bytes first; wrong length then
 * returns-2. Decode the first0x9a58 bytes into output->decoded and forward any
 * nonzero decoder status without rollback. Validate the remaining0x136c bytes
 * using CRC32=0x6aa9101c, eight-byte OHV1R16-NUL signature, then little-endian
 * words1,145,16,80 in that order. Each word reads bytes1,0,2,3; the input can
 * be unaligned. A failed tail check returns-2, retaining decoded/cleared output.
 * On success publish the nine tail/table pointers first, then image and length,
 * and return0. All tables borrow the original image; no copy/allocation, lock,
 * MEMW, ownership transfer or overlap protection is added. A nonNULL image
 * must remain readable for length bytes throughout validation and later use.
 */
int medius_motion_config_load(MediusMotionConfiguration *configuration,
    const unsigned char *image,unsigned int length)
{
    if(!configuration||!image)return -1;
    memset(configuration,0,152);
    if(length!=44484)return -2;
    int status=medius_motion_decode_base(&configuration->decoded,image,0x9a58);
    if(status)return status;
    const unsigned char *tail=image+0x9a58;
    if(medius_motion_config_crc32(tail,0x136c)!=0x6aa9101cU)return -2;
    if(memcmp(tail,"OHV1R16",8)!=0)return -2;
    if(motion_config_u32(image+0x9a60)!=1)return -2;
    if(motion_config_u32(image+0x9a64)!=145)return -2;
    if(motion_config_u32(image+0x9a68)!=16)return -2;
    if(motion_config_u32(image+0x9a6c)!=80)return -2;
    volatile MediusMotionConfiguration *out=configuration;
    out->tail_header=tail;
    out->table_145_a=image+0x9a70;
    out->table_145_b=image+0x9b92;
    out->table_16_a=image+0x9cb4;
    out->table_16_b=image+0x9cf4;
    out->matrix_145x16=image+0x9d34;
    out->table_80_a=image+0xa644;
    out->table_80_b=image+0xa784;
    out->matrix_80x16=image+0xa8c4;
    out->image=image;
    out->length=44484;
    return 0;
}

/* Native entry: 0x4200d4d0. */
/*
 * Medius v3.4.7 — host application; 0x4200d4d0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 630daa3c7351ced906a157b26b97f75dd4297fe91e4ee403752ec9dabe4048b3.
 */

/*
 * Compute reflected CRC32 over length bytes: initial/final XOR0xffffffff,
 * polynomial0xedb88320, eight low-bit shifts per byte. length is unsigned32;
 * zero returns0 without reading data, so NULL is accepted only in that case.
 * Nonzero length requires that many readable bytes; no cap, allocation, lock,
 * table lookup, authentication decision or pointer validation is performed.
 */
unsigned int medius_motion_config_crc32(const unsigned char *data,unsigned int length)
{
    if(!length)return 0;
    const volatile unsigned char *bytes=data;
    unsigned int crc=0xffffffffU;
    do{
        crc^=*bytes++;
        for(unsigned int bit=0;bit<8;++bit)
            crc=(crc>>1)^((0U-(crc&1U))&0xedb88320U);
    }while(--length);
    return crc^0xffffffffU;
}

/* Native entry: 0x4200d484. */
/*
 * Medius v3.4.7 — host application; 0x4200d484.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 4965ba75b9131e4f4ff4e2f6bd5642bed5f46d4feecf586e0610460911d53c7c.
 */

/*
 * Gate processing seeding on nonNULL outer state/configuration and the outer
 * collected_samples16 field being exactly256. Return-1 for a missing pointer,
 * -5 for a different count, otherwise return core_seed's status unchanged.
 * All four native arguments are retained. unused is not read or forwarded as
 * meaningful state; seed_a/seed_b are full32 values passed through to the core
 * at outer+8. The core independently validates its own phase/sample count.
 * No lock, MEMW, normalization, cleanup or additional writes occur here.
 */
int medius_motion_seed_processing(MediusMotionProcessingState *state,
    unsigned int unused,unsigned int seed_a,unsigned int seed_b)
{
    (void)unused;
    if(!state)return -1;
    volatile MediusMotionProcessingState *current=state;
    const MediusMotionConfiguration *configuration=current->configuration;
    if(!configuration)return -1;
    unsigned short samples=current->collected_samples;
    if(samples!=256)return -5;
    return medius_motion_core_seed(&state->core,0,seed_a,seed_b);
}

/* Native entry: 0x4200d4b4. */
/*
 * Medius v3.4.7 — host application; 0x4200d4b4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 48a2d881c80c43da52ca6479c245920b98cb1ba835158cfa6c2fe1705e410599.
 */

/*
 * Forward full-width signed X/Y limits to the embedded core at state+8 and
 * return its status unchanged. A NULL outer state returns-1. No outer config,
 * phase or sample-count check, narrowing, lock, MEMW or local update occurs.
 */
int medius_motion_processing_set_limits(MediusMotionProcessingState *state,
    int x_limit,int y_limit)
{
    if(!state)return -1;
    return medius_motion_core_set_limits(&state->core,x_limit,y_limit);
}

/* Native entry: 0x4200e250. */
/*
 * Medius v3.4.7 — host application; 0x4200e250.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * b034c9f4fee0680a161a6fcf1885f7f21f4190e82ef38403690acc160e400094.
 */

/*
 * Initialize an embedded core. NULL core/configuration or a NULL configuration
 * image pointer returns-1 with no writes. Otherwise clear exactly2048 bytes,
 * then publish configuration, phase1 and the native halfword default32767 at
 * core+0x51a, in that order; return0. Configuration validity is sampled before
 * clearing, so overlapping storage is not rejected. No further fields in the
 * configuration are validated. No allocation, lock, MEMW or rollback occurs.
 */
int medius_motion_core_initialize(MediusMotionCoreState *core,
    const MediusMotionDecodedConfiguration *configuration)
{
    if(!core||!configuration)return -1;
    const volatile MediusMotionDecodedConfiguration *source=configuration;
    const unsigned char *image=source->image;
    if(!image)return -1;
    memset(core,0,2048);
    volatile MediusMotionCoreState *out=core;
    out->configuration=configuration;
    out->phase=1;
    out->initial_halfword=32767;
    return 0;
}

/* Native entry: 0x4200e28c. */
/*
 * Medius v3.4.7 — host application; 0x4200e28c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 8c36ffcd6b1336b82da6e649f9e7cba2adcb4d95545a56ffaf7aa1fdb8c773c0.
 */

/*
 * Transition an embedded core from phase1 to phase2. NULL core/configuration
 * returns-1; phase!=1 or core.samples16!=256 returns-5. unused is ignored.
 * Clear the two residual words (8 bytes), then reload configuration and sample
 * only its low16 maximum_step field. Duplicate that raw halfword into one32-bit
 * X/Y-limit store. Clear both seed auxiliaries, store seed_a then seed_b, and
 * publish phase2 last. Return0. The configuration reload occurs after memset;
 * aliasing or callee mutations can change what is read. No range repair,
 * reseeding guard beyond phase, lock, MEMW or reset of other state is added.
 */
int medius_motion_core_seed(MediusMotionCoreState *core,unsigned int unused,
    unsigned int seed_a,unsigned int seed_b)
{
    (void)unused;
    if(!core)return -1;
    volatile MediusMotionCoreState *state=core;
    const MediusMotionDecodedConfiguration *configuration=state->configuration;
    if(!configuration)return -1;
    if(state->phase!=1)return -5;
    if(state->samples!=256)return -5;
    memset((void *)state->residual,0,8);
    configuration=state->configuration;
    const volatile MediusMotionDecodedConfiguration *fresh=configuration;
    unsigned int limit=fresh->maximum_step_low;
    state->limits_word=limit|(limit<<16);
    state->seed_auxiliary[0]=0;state->seed_auxiliary[1]=0;
    state->seed_a=seed_a;state->seed_b=seed_b;
    state->phase=2;
    return 0;
}

/* Native entry: 0x4201e878. */
/*
 * Medius v3.4.7 — host application; 0x4201e878.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * a3dfc5b129cd140ebb49e62e75146a1c6b136bf609154fb732ec7f325a7cb3c9.
 */

/*
 * Set embedded-core limits only in phase2. NULL core/configuration returns-1;
 * any other phase returns-5 without updates. Read maximum_step as a full32-bit
 * value once before either limit store. A signed nonpositive request becomes1.
 * A positive request uses the configured maximum if that maximum is signed
 * negative or is smaller as unsigned; otherwise it uses the request. Store the
 * selected low16 bits to X, then Y, and return0. This intentionally permits0,
 * values above32767 and truncation for malformed/large configurations: it is
 * not the separate public [1,32767] clamp. Y uses the cached maximum even if X
 * aliases it. No lock, MEMW, allocation or other core-state update occurs.
 */
int medius_motion_core_set_limits(MediusMotionCoreState *core,int x_limit,int y_limit)
{
    if(!core)return -1;
    volatile MediusMotionCoreState *state=core;
    const MediusMotionDecodedConfiguration *configuration=state->configuration;
    if(!configuration)return -1;
    if(state->phase!=2)return -5;
    const volatile MediusMotionDecodedConfiguration *source=configuration;
    unsigned int maximum=source->maximum_step;
    unsigned short x=1;
    if(x_limit>0)x=(unsigned short)(((int)maximum<0||(unsigned int)x_limit>maximum)?maximum:(unsigned int)x_limit);
    state->x_limit=x;
    unsigned short y=1;
    if(y_limit>0)y=(unsigned short)(((int)maximum<0||(unsigned int)y_limit>maximum)?maximum:(unsigned int)y_limit);
    state->y_limit=y;
    return 0;
}
