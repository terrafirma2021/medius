/* Medius v3.4.7 host — runtime/stdio_io.c.
 */

#include "../include/types.h"

/* Native entry: 0x420165c0. */
/*
 * Medius v3.4.7 — host application; 0x420165c0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * ab3c62b804ece2e09f8063de65674ae2a3dc1669c30741895ddf9620bf8504b1.
 */

/*
 * Newlib read callback: cookie points to a FILE. Sample its signed 16-bit descriptor
 * and pass reent, descriptor, buffer and all 32 length bits to VFS read. A
 * nonnegative result, including zero, adds to the freshly read cached offset
 * modulo 2^32; it does not set the offset-valid flag. Any negative result clears
 * only flag 0x1000 in the freshly read flags, leaving the cached offset intact.
 * Return the VFS result unchanged. Backend changes to FILE fields are observed
 * after the call. No NULL/buffer/negative-length check, errno reset, allocation,
 * lock or explicit MEMW occurs here; cookie must name accessible FILE storage.
 */
int medius_newlib_stream_read(NewlibReent *reent,void *cookie,
    char *buffer,int length)
{
    volatile NewlibFile *stream = cookie;
    int descriptor = stream->file_descriptor;
    int result = medius_vfs_read(reent,descriptor,buffer,(unsigned int)length);
    if (result < 0) {
        unsigned short flags = stream->flags;
        stream->flags = flags & 0xefffU;
    } else {
        unsigned long offset = stream->cached_offset_bits;
        stream->cached_offset_bits = offset + (unsigned int)result;
    }
    return result;
}

/* Native entry: 0x420165f4. */
/*
 * Medius v3.4.7 — host application; 0x420165f4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 111e1820a48b5d37fe73200f6d8bd331f91d43229f1710c44e4887f0f157e075.
 */

/*
 * Newlib write callback. If the initial FILE flags contain append bit 0x100,
 * seek its then-current signed 16-bit descriptor to offset 0 / origin 2. Discard that
 * seek result and continue even after -1. Next reread flags, sample the fresh
 * descriptor, then clear only offset-valid bit 0x1000 in the sampled flags.
 * Finally call VFS write with the original buffer and all 32 length bits, and
 * return that result unchanged. No cached-offset update or post-write flag
 * repair occurs. Seek/backend FILE mutations and errno changes are retained;
 * no NULL/negative-length check, allocation, locking or MEMW is added here.
 */
int medius_newlib_stream_write(NewlibReent *reent,void *cookie,
    const char *buffer,int length)
{
    volatile NewlibFile *stream = cookie;
    unsigned short initial_flags = stream->flags;
    if (initial_flags & 0x0100U) {
        int descriptor = stream->file_descriptor;
        (void)medius_vfs_seek(reent,descriptor,0,2);
    }
    unsigned short flags = stream->flags;
    int descriptor = stream->file_descriptor;
    stream->flags = flags & 0xefffU;
    return medius_vfs_write(reent,descriptor,buffer,(unsigned int)length);
}

/* Native entry: 0x42016630. */
/*
 * Medius v3.4.7 — host application; 0x42016630.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * cdd8d4078870a46e9bfedd548557d147ba940adc0e4508256fc9914cb24bd97d.
 */

/*
 * Newlib seek callback. Forward reent, the FILE's sampled signed 16-bit descriptor,
 * offset and origin to VFS seek, without narrowing any 32-bit argument bits.
 * Read flags after the callback. Exactly -1 clears bit 0x1000 and leaves the
 * cached offset as the backend left it. Every other result, including other
 * negative values, first sets bit 0x1000, then stores that result at FILE+0x54.
 * Return the result unchanged. No range/origin check, rollback, errno reset,
 * allocation, stream lock or explicit MEMW occurs in this callback.
 */
long medius_newlib_stream_seek(NewlibReent *reent,void *cookie,
    long offset,int origin)
{
    volatile NewlibFile *stream = cookie;
    int descriptor = stream->file_descriptor;
    int result = medius_vfs_seek(reent,descriptor,(int)offset,origin);
    unsigned short flags = stream->flags;
    if (result == -1) stream->flags = flags & 0xefffU;
    else {
        stream->flags = flags | 0x1000U;
        stream->cached_offset = result;
    }
    return result;
}
