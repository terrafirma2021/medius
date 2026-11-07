/* Medius v3.4.7 host — retained RTC crash records and watchdog text. */
#include "../include/types.h"

/* Inline reconstruction utilities for native inlined retained BYTE stores.
 * Raw32-bit address addition preserves the original unchecked cursor behavior. */
static __inline__ __attribute__((always_inline))
void panic_text_store(unsigned int offset,unsigned char value)
{
    memw();
    *(volatile unsigned char *)(0x50000048U+offset)=value;
}

/* Native entry: 0x42008f34. */
/* Original function-byte SHA-256:
 * 0148ba6bef8aa91d8f34292ece1b967517e354b0e2d8cdcffcaabce07d687c25. */
/*
 * Compute the native additive checksum modulo2^32. MEMW/read, in order:
 * image_id, core, kind, PC, A0, fault address, return count, cause, then all six
 * return slots. Weights are1,5,3,1,7,1,13,11 and17..22 for the slots. Magic,
 * stored checksum and all watchdog tags/text are excluded. No validation,
 * authentication, locking or atomic snapshot; unused return slots still count.
 */
unsigned int panic_record_checksum(void)
{
    volatile RetainedPanicRecord *record=RETAINED_PANIC_RECORD;
    memw(); unsigned int image=record->image_id;
    memw(); unsigned int core=record->core;
    memw(); unsigned int kind=record->kind;
    memw(); unsigned int pc=record->pc;
    memw(); unsigned int a0=record->a0;
    memw(); unsigned int address=record->exception_address;
    memw(); unsigned int count=record->return_count;
    memw(); unsigned int cause=record->exception_cause;
    unsigned int sum=image+5U*core+3U*kind+pc+7U*a0+address+13U*count+11U*cause;
    for (unsigned int index=0;index<6U;++index) {
        memw();
        sum+=(index+17U)*record->return_pc[index];
    }
    return sum;
}

/* Native entry: 0x42008fa0. */
/* Original function-byte SHA-256:
 * 17ea496c74a925459a8b3daccf4cea3f236b97d3e90fa616ddbaeec2da280ce6. */
/*
 * Watchdog text-fragment callback. packed_cursor holds text length in low16
 * and callback ordinal in high16. Snapshot it once; every third call starting
 * at ordinal2 receives a task/user name from the reviewed watchdog reporter.
 * Prepend " unfed=" for ordinal2, otherwise comma, then append the fragment.
 * Each retained BYTE store has MEMW, always leaving a NUL at the current end.
 * A source byte is fetched before checking remaining space. NULL fragments
 * append only their separator. Other ordinals only advance the packed count.
 * Increment high16 modulo65536; retain the resulting low16 offset. No cursor
 * NULL/range check or lock: a caller-supplied offset>95 can make even the NUL
 * store leave the96-byte text array. Does not set either watchdog marker.
 */
void panic_append_unfed_task(void *opaque,const char *fragment)
{
    volatile unsigned int *packed_cursor=opaque;
    unsigned int packed=*packed_cursor;
    unsigned int ordinal=packed>>16;
    unsigned int end=packed&0xffffU;
    if (ordinal>=2U && (ordinal-2U)%3U==0) {
        const char *separator=ordinal==2U?" unfed=":",";
        unsigned int start=end;
        unsigned char character=ordinal==2U?' ':',';
        do {
            if (end+1U>95U) break;
            panic_text_store(end,character);
            ++end;
            character=(unsigned char)separator[end-start];
        } while (character!=0);
        panic_text_store(end,0);
        start=end;
        if (fragment!=NULL) {
            for (;;) {
                character=*(const volatile unsigned char *)(fragment+(end-start));
                if (character==0 || end+1U>95U) break;
                panic_text_store(end,character);
                ++end;
            }
        }
        panic_text_store(end,0);
    }
    *packed_cursor=((ordinal+1U)<<16)|end;
}

/* Native entry: 0x42009038. */
/* Original function-byte SHA-256:
 * fa328cee0d6cd32e84a0803a3c2dd84f3d214bb5f70073b3cdb7c10b8a833fee. */
/*
 * Clear all96 retained text BYTEs, publish pending tag0x54574454, then ask the
 * watchdog reporter for unfed subscriptions via the packed-fragment callback.
 * Ignore reporter status and take only the cursor's low HALFWORD as the end.
 * For core0 then1, get its current TCB and call pcTaskGetName with that return
 * value. Skip names beginning with the four-byte prefix "IDLE", even "IDLEX".
 * Otherwise append a bounded " runN=" prefix and its name, retaining native
 * intermediate NUL stores/truncation behavior. A NULL name still gets a prefix;
 * pcTaskGetName(NULL)'s own current-task fallback is not changed here.
 * No stack capture, allocation, callback-lifetime lock, checksum or final tag.
 */
void panic_capture_watchdog_tasks(void)
{
    for (unsigned int index=0;index<96U;++index) panic_text_store(index,0);
    memw(); RETAINED_PANIC_RECORD->watchdog_pending=0x54574454U;
    PanicTextCursor cursor;
    cursor.packed=0;
    (void)esp_task_wdt_print_triggered_tasks(panic_append_unfed_task,&cursor,NULL);
    unsigned int end=*(volatile unsigned short *)&cursor.length;
    for (unsigned int core=0;core<2U;++core) {
        RtosTask *task=xTaskGetCurrentTaskHandleForCore((int)core);
        const volatile unsigned char *name=(const volatile unsigned char *)pcTaskGetName(task);
        if (name!=NULL && name[0]=='I' && name[1]=='D' && name[2]=='L' && name[3]=='E')
            continue;
        const char *prefix=" run";
        unsigned int start=end;
        unsigned char character=' ';
        for (;;) {
            if (end+1U>95U) {
                panic_text_store(end,0);
                goto append_name;
            }
            panic_text_store(end,character);
            ++end;
            character=(unsigned char)prefix[end-start];
            if (character==0) break;
        }
        panic_text_store(end,0);
        if (end==95U) goto append_name;
        panic_text_store(end,(unsigned char)(core+'0'));
        panic_text_store(end+1U,0);
        if (end+2U==96U) end=95U;
        else {
            panic_text_store(end+1U,'=');
            end+=2U;
        }
append_name:
        panic_text_store(end,0);
        start=end;
        if (name!=NULL) {
            for (;;) {
                character=name[end-start];
                if (character==0 || end+1U>95U) break;
                panic_text_store(end,character);
                ++end;
            }
        }
        panic_text_store(end,0);
    }
}

/* Native entry: 0x42009154. */
/* Original function-byte SHA-256:
 * 5e83b07aa20392d50c39a357c875e93b405fab342f5813cac3b91a366765c8bc. */
/*
 * Save a crash record before calling the reviewed system panic handler.
 * Snapshot current image ID before MEMW/clearing magic; copy it and store
 * kind=exception+1/core, or kind0/core255 for NULL info. Clear exception words
 * and all six return slots in native order. A non-NULL saved frame always
 * supplies PC. Only retained kind1(debug),4(abort),5(fault) also supply saved
 * A0, fault address/cause and a bounded spilled-window trace.
 *
 * Trace follows at most six frames whose incoming SP lies in
 * [0x3fc88010,0x3fcfffff] and is16-byte aligned. Read saved A0 at SP-16, normalize
 * to (A0&0x3fffffff)|0x40000000, then fetch next SP at SP-12 BEFORE rejecting
 * an out-of-region or repeated PC. Admit normalized PC0x40000000..0x400fffff
 * or0x42000000..0x42ffffff. Compare only the immediately preceding PC; no CALL
 * size subtraction, executable predicate, PSRAM/RTC stack admission or cycle set.
 * Each accepted PC store precedes its count store, both with MEMW.
 *
 * Pending watchdog tag0x54574454 preserves text and becomes validated tag
 *0x54574456; otherwise clear96 BYTEs and validated tag. Clear pending tag first,
 * checksum the record, store checksum, then publish magic0xc0debeef last, with
 * MEMW per retained store. No atomic transaction, durability or cross-core lock.
 * Always forward info, including NULL, to esp_panic_handler; that handler does
 * not validate NULL and can fault. Return only if its debugger path returns.
 */
void panic_record_and_handle(PanicInfo *result)
{
    volatile RetainedPanicRecord *record=RETAINED_PANIC_RECORD;
    const volatile PanicInfo *info=result;
    unsigned int image=PANIC_IMAGE_ID;
    memw(); record->magic=0;
    memw(); record->image_id=image;
    unsigned int kind=0,core=255;
    if (info!=NULL) {
        kind=(unsigned int)info->exception+1U;
        core=(unsigned int)info->core;
    }
    memw(); record->kind=kind;
    memw(); record->core=core;
    memw(); record->exception_cause=0;
    memw(); record->exception_address=0;
    memw(); record->a0=0;
    memw(); record->pc=0;
    memw(); record->return_count=0;
    for (unsigned int index=0;index<4U;++index) {
        memw(); record->return_pc[index]=0;
    }
    const volatile XtensaExceptionFrame *frame=NULL;
    if (info!=NULL) frame=info->frame;
    memw(); record->return_pc[4]=0;
    memw(); record->return_pc[5]=0;
    if (frame!=NULL) {
        unsigned int previous_pc=(unsigned int)frame->pc;
        memw(); record->pc=previous_pc;
        memw(); kind=record->kind;
        if (kind-4U<=1U || kind==1U) {
            unsigned int a0=frame->a[0];
            unsigned int fault_address=frame->exception_address;
            memw(); record->a0=a0;
            unsigned int cause=frame->exception_cause;
            memw(); record->exception_address=fault_address;
            memw(); record->exception_cause=cause;
            unsigned int sp=frame->a[1];
            memw(); record->return_count=0;
            unsigned int count=0;
            while (sp-0x3fc88010U<=0x77fefU) {
                if ((sp&15U)!=0) break;
                unsigned int pc=*(const volatile unsigned int *)(sp-16U);
                pc=(pc&0x3fffffffU)|0x40000000U;
                sp=*(const volatile unsigned int *)(sp-12U);
                bool executable_region=pc-0x40000000U<=0xfffffU || pc-0x42000000U<=0xffffffU;
                if (!executable_region || pc==previous_pc) break;
                memw(); record->return_pc[count]=pc;
                ++count;
                memw(); record->return_count=count;
                if (count==6U) break;
                previous_pc=pc;
            }
        }
    }
    memw(); unsigned int pending=record->watchdog_pending;
    unsigned int validated=0;
    if (pending==0x54574454U) validated=0x54574456U;
    else for (unsigned int index=0;index<96U;++index) panic_text_store(index,0);
    memw(); record->watchdog_pending=0;
    memw(); record->watchdog_validated=validated;
    unsigned int checksum=panic_record_checksum();
    memw(); record->checksum=checksum;
    memw(); record->magic=0xc0debeefU;
    esp_panic_handler(result);
}

/* Native entry: 0x42009318. */
/* Original function-byte SHA-256:
 * ac166207a62304833e23c7df4d8d582ae467a77cf618f1828c173214a1ce21f9. */
/*
 * Refresh current image ID from the first four ELF-SHA bytes of the mapped
 * application description, even when buffer/capacity are invalid. Then require
 * non-NULL buffer, nonzero capacity, record magic and matching additive checksum.
 * Failure returns0 without clearing record/text or initializing the buffer.
 * Acceptance consumes magic BEFORE formatting and snapshots kind/current image.
 * Image mismatch is annotated only if the retained ID is nonzero; the long and
 * short suffix tests independently reload that retained ID.
 *
 * Kind2 formats interrupt-WDT state and optionally watchdog text; otherwise a
 * validated watchdog tag selects task-WDT text. Remaining kinds1/4/5 with cause
 *<64 use detailed exception fields; all others use a short category/PC format.
 * Append recorded PCs while the signed formatter total is positive and below
 * capacity, rereading return_count after each call. There is NO six-slot bound
 * on this consumer: a checksum-consistent excessive count can read later RTC
 * words. snprintf return values accumulate modulo32; truncation/error still
 * consumes the record. Formatters may observe changing retained text/fields.
 * Always clear96 text BYTEs and validated tag on acceptance, then return1.
 * No lock, UART output, checksum authentication or original-image address mapping.
 */
int boot_read_previous_panic(char *buffer,unsigned int capacity)
{
    const EspAppDescription *description=get_app_description();
    if (description!=NULL)
        memcpy((void *)&PANIC_IMAGE_ID,description->app_elf_sha256,4U);
    if (buffer==NULL || capacity==0) return 0;
    volatile RetainedPanicRecord *record=RETAINED_PANIC_RECORD;
    memw(); if (record->magic!=0xc0debeefU) return 0;
    memw(); unsigned int expected=record->checksum;
    if (expected!=panic_record_checksum()) return 0;
    memw(); record->magic=0;
    memw(); unsigned int kind=record->kind;
    unsigned int current_image=PANIC_IMAGE_ID;
    const char *long_suffix="";
    memw(); unsigned int saved_image=record->image_id;
    if (saved_image!=current_image) {
        memw(); if (record->image_id!=0)
            long_suffix=" (PREVIOUS IMAGE: addresses are not this one's)";
    }
    memw(); unsigned int watchdog=record->watchdog_validated;
    const char *short_suffix="";
    memw(); saved_image=record->image_id;
    if (saved_image!=current_image) {
        memw(); if (record->image_id!=0) short_suffix=" (prev image)";
    }

    unsigned int used;
    if (kind==2U) {
        memw(); unsigned int core=record->core;
        memw(); unsigned int pc=record->pc;
        used=(unsigned int)newlib_snprintf(buffer,capacity,
            "PANIC was: int watchdog, core=%u pc=0x%08x%s",core,pc,short_suffix);
        if ((int)used>0 && watchdog==0x54574456U && used<capacity)
            (void)newlib_snprintf(buffer+used,capacity-used,",%.*s",96,
                                     (const char *)0x50000048U);
    } else if (watchdog==0x54574456U) {
        memw(); unsigned int core=record->core;
        (void)newlib_snprintf(buffer,capacity,
            "PANIC was: task watchdog, core=%u%s,%.*s",core,short_suffix,96,
            (const char *)0x50000048U);
    } else {
        bool detailed=false;
        if (kind-4U<=1U || kind==1U) {
            memw(); detailed=record->exception_cause<=63U;
        }
        const char *category=kind==4U?"abort":kind==5U?"fault":kind==1U?"debug":
                             kind==3U?"task-wdt":"?";
        if (detailed) {
            memw(); unsigned int core=record->core;
            memw(); unsigned int pc=record->pc;
            memw(); unsigned int a0=record->a0;
            memw(); unsigned int address=record->exception_address;
            memw(); unsigned int cause=record->exception_cause;
            used=(unsigned int)newlib_snprintf(buffer,capacity,
                "PANIC was: %s core=%u pc=0x%08x a0=0x%08x vaddr=0x%08x cause=%u%s",
                category,core,pc,a0,address,cause,long_suffix);
        } else {
            memw(); unsigned int core=record->core;
            memw(); unsigned int pc=record->pc;
            memw(); unsigned int cause=record->exception_cause;
            const char *no_frame=cause>63U?" (no exception frame: watchdog or abort)":"";
            used=(unsigned int)newlib_snprintf(buffer,capacity,
                "PANIC was: %s core=%u pc=0x%08x%s%s",category,core,pc,no_frame,long_suffix);
        }
        memw(); unsigned int count=record->return_count;
        unsigned int index=0;
        while (index<count) {
            if ((int)used<=0 || used>=capacity) break;
            memw();
            unsigned int pc=*(const volatile unsigned int *)(0x50000024U+4U*index);
            ++index;
            unsigned int added=(unsigned int)newlib_snprintf(
                buffer+used,capacity-used," <-0x%08x",pc);
            memw(); count=record->return_count;
            used+=added;
        }
    }
    for (unsigned int index=0;index<96U;++index) panic_text_store(index,0);
    memw(); record->watchdog_validated=0;
    return 1;
}
