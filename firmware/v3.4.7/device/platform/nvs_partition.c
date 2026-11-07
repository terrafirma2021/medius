/* Medius v3.4.7 device: ESP partition backend and NVS partition lookup. */
#include "../include/types.h"

/* Native entry: 0x420145c8. */
/* Original function-byte SHA-256:
 * ab923705a124cb781229ab5ffeeab7b3c94ee0798c74ebebeed0df64209c13a0. */
/* Load the descriptor pointer at object+12, forward full offset/output/size
 * to esp_partition_read_raw and return its status. No local validation,
 * size/offset alignment check, encryption handling or copy is added. */
int nvs_esp_partition_read_raw(NvsPartitionObject *object,
    size_t offset,void *output,size_t size)
{
    const volatile NvsEspPartition *partition = (NvsEspPartition *)object;
    return esp_partition_read_raw(partition->descriptor,offset,output,size);
}

/* Native entry: 0x420145e0. */
/* Original function-byte SHA-256:
 * 8a3267835b8ec486f68cef933bb3b1924e350ea75ea98032f22348814311ce67. */
/* Forward the stored descriptor/full offset/data/size to raw partition write.
 * Return its exact status without local alignment or read-only checks. */
int nvs_esp_partition_write_raw(NvsPartitionObject *object,
    size_t offset,const void *data,size_t size)
{
    const volatile NvsEspPartition *partition = (NvsEspPartition *)object;
    return esp_partition_write_raw(partition->descriptor,offset,data,size);
}

/* Native entry: 0x420145f8. */
/* Original function-byte SHA-256:
 * c6d799b258215da4e0b1b776ab4307a664b45f411fad1a32de1f5c211314795d. */
/* Forward descriptor, offset and size to partition erase_range. Return the
 * callback status; sector bounds/alignment/read-only handling belongs there. */
int nvs_esp_partition_erase_range(NvsPartitionObject *object,
    size_t offset,size_t size)
{
    const volatile NvsEspPartition *partition = (NvsEspPartition *)object;
    return esp_partition_erase_range(partition->descriptor,offset,size);
}

/* Native entry: 0x42014608. */
/* Original function-byte SHA-256:
 * 43a206badf6a96e1c7c303ff8dcbb07aa8114f36250e6ca90f8e8d7e782e6e4f. */
/* Reject sizes not divisible by16 with0x102 before reading the object.
 * Otherwise load its descriptor and perform a normal partition write with
 * full offset/data/size. Zero size is forwarded. No local offset/pointer
 * alignment, descriptor, encryption or read-only validation is supplied. */
int nvs_esp_partition_write(NvsPartitionObject *object,
    size_t offset,const void *data,size_t size)
{
    if ((size & (ESP_ENCRYPT_BLOCK_SIZE - 1U)) != 0)
        return 0x102;
    const volatile NvsEspPartition *partition = (NvsEspPartition *)object;
    return esp_partition_write(partition->descriptor,offset,data,size);
}

/* Native entry: 0x42014628. */
/* Original function-byte SHA-256:
 * c185c04124e25ddde2823407749ed4db6cb35886d5436ba510c4f58ee4978a62. */
/* Reject sizes not divisible by16 with0x102 before reading the object.
 * Otherwise forward descriptor/full offset/output/size to normal partition
 * read. Zero size is allowed here. No local offset or buffer-alignment check. */
int nvs_esp_partition_read(NvsPartitionObject *object,
    size_t offset,void *output,size_t size)
{
    if ((size & (ESP_ENCRYPT_BLOCK_SIZE - 1U)) != 0)
        return 0x102;
    const volatile NvsEspPartition *partition = (NvsEspPartition *)object;
    return esp_partition_read(partition->descriptor,offset,output,size);
}

/* Native entry: 0x42014648. */
/* Original function-byte SHA-256:
 * 5cd4bea55a7c4e6da1de0a35ff22e96c086270fb430e129c51ca2ccdec2aec56. */
/* Construct the16-byte ESP backend: zero previous/next links, store the
 * borrowed descriptor, then publish vtable0x3c047254. If the descriptor is
 * NULL, abort AFTER those stores. Do not copy, allocate or free a descriptor. */
void nvs_esp_partition_construct(NvsEspPartition *partition,
    const EspPartition *descriptor)
{
    volatile NvsEspPartition *state = partition;
    state->base.previous = NULL;
    state->base.next = NULL;
    state->descriptor = descriptor;
    state->base.vtable = NVS_ESP_PARTITION_VTABLE;
    if (descriptor == NULL)
        abort();
}

/* Native entry: 0x42014664. */
/* Original function-byte SHA-256:
 * 94796de3c20adc471758bc296a28594dce0f0b412183e734e45b849f9c5e85d6. */
/* ExceptionlessAllocatable delete: call free(memory), including NULL. No
 * destructor, object inspection, array-cookie processing or pointer reset. */
void nvs_exceptionless_delete(void *memory)
{
    free(memory);
}

/* Native entry: 0x4201625c. */
/* Original function-byte SHA-256:
 * 7a748dcf6f1fe699e6a10bb58d6c91880cec0162e891f90b70deac3346cc6843. */
/* Find the first DATA1/NVS2 partition matching name. Missing returns0x105;
 * an encrypted descriptor byte returns WRONG_ENCRYPTION (0x1119), regardless
 * of the read-only flag. Allocate16 bytes or return0x101, construct the ESP
 * backend, publish its base pointer and return0. Errors leave output intact.
 * Name/output are not locally validated; NULL name is forwarded to find.
 * No list insertion, lock, descriptor copy or cleanup of previous output. */
int nvs_lookup_partition(const char *name,
    NvsPartitionObject *volatile *output)
{
    const EspPartition *descriptor = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA,ESP_PARTITION_SUBTYPE_DATA_NVS,name);
    if (descriptor == NULL)
        return 0x105;
    if (((const volatile EspPartition *)descriptor)->encrypted != 0)
        return 0x1119;
    NvsEspPartition *partition = malloc(sizeof(NvsEspPartition));
    if (partition == NULL)
        return 0x101;
    nvs_esp_partition_construct(partition,descriptor);
    *output = &partition->base;
    return 0;
}

/* Native entry: 0x420211b0. */
/* Original function-byte SHA-256:
 * a50f595a12cc6e7e90d28fa2424790fbfac53a684610d6fe5637b2112f16f23d. */
/*
 * nvs::NVSPartition complete/base destructor, vtable 0x3c047254 slot 0.
 * Return without reading or changing object, links, vtable or borrowed ESP
 * descriptor. Does not unlink, release flash, deinitialize NVS or free memory.
 * The separate deleting destructor owns the allocation release. D1/D2 alias
 * behavior is identical here; object is accepted unchanged, including NULL.
 */
void nvs_esp_partition_destroy(NvsPartitionObject *object)
{
    (void)object;
}

/* Native entry: 0x420129fc. */
/* Original function-byte SHA-256:
 * 100ceca99f18753665a9aa9886ae8dd0dc1d40beefac72ea2e1af2454e38fc3a. */
/*
 * nvs::NVSPartition deleting destructor, vtable 0x3c047254 slot 4.
 * Its complete/base destructor has no effects and is eliminated; call free
 * with the original object pointer, including NULL. No object inspection,
 * list unlink, borrowed descriptor release or global-pointer clearing.
 */
void nvs_esp_partition_delete(NvsPartitionObject *object)
{
    free(object);
}

/* Native entry: 0x420211cc. */
/* Original function-byte SHA-256:
 * 990bf22922c582e79aa813b5031bcb4e3afcddbe7d578a4ecdb4ceaeff83174c. */
/*
 * nvs::NVSPartition::get_partition_name, vtable slot 8. Load the borrowed ESP
 * descriptor at object+12, then return its inline label address at +24.
 * No string reads, copy, allocation, lock or NULL validation. The returned
 * pointer is borrowed and remains subject to the descriptor's lifetime.
 */
const char *nvs_esp_partition_get_name(NvsPartitionObject *object)
{
    const volatile NvsEspPartition *partition=(NvsEspPartition *)object;
    const EspPartition *descriptor=partition->descriptor;
    return (const char *)((uintptr_t)descriptor+offsetof(EspPartition,label));
}

/* Native entry: 0x420211d8. */
/* Original function-byte SHA-256:
 * a08bf5e48a48c5345c1789c28ca04b0bcc07dd81f440049bb60a47473ac86f74. */
/*
 * nvs::NVSPartition::get_address, vtable slot 32. Load object->descriptor,
 * then return its address WORD at +12 unchanged. No translation, range or
 * NULL validation, lock, allocation or modification of either object.
 */
unsigned int nvs_esp_partition_get_address(NvsPartitionObject *object)
{
    const volatile NvsEspPartition *partition=(NvsEspPartition *)object;
    const volatile EspPartition *descriptor=partition->descriptor;
    return descriptor->address;
}

/* Native entry: 0x420211e4. */
/* Original function-byte SHA-256:
 * 2b7945eb297c291b72d2ed390bbf6f6ba7266a410c36fdbdecaa24d18df4dd9e. */
/*
 * nvs::NVSPartition::get_size, vtable slot 36. Load object->descriptor,
 * then return its size WORD at +16 unchanged. No unit conversion, range or
 * NULL validation, lock, allocation or modification of either object.
 */
unsigned int nvs_esp_partition_get_size(NvsPartitionObject *object)
{
    const volatile NvsEspPartition *partition=(NvsEspPartition *)object;
    const volatile EspPartition *descriptor=partition->descriptor;
    return descriptor->size;
}

/* Native entry: 0x420211f0. */
/* Original function-byte SHA-256:
 * bcd946f4555f27cc969ebababc77e2d631e834755221cf977014bdb9b88ee668. */
/*
 * nvs::NVSPartition::get_readonly, vtable slot 40. Load object->descriptor,
 * then zero-extend its readonly BYTE at +42 into the return register. Preserve
 * noncanonical BYTE values rather than introducing a bool normalization.
 * No encrypted-flag test, NULL validation, lock or hardware access.
 */
unsigned int nvs_esp_partition_get_readonly(NvsPartitionObject *object)
{
    const volatile NvsEspPartition *partition=(NvsEspPartition *)object;
    const volatile EspPartition *descriptor=partition->descriptor;
    return descriptor->readonly;
}
