/* Medius v3.4.7 device — retained RTC crash records and watchdog text. */
#include "../include/types.h"

/* Inline reconstruction utilities for native inlined retained BYTE stores.
 * Raw 32-bit address addition preserves the original unchecked cursor behavior. */
static __inline__ __attribute__((always_inline))
void panic_text_store(unsigned int offset,unsigned char value)
{
    memw();
    *(volatile unsigned char *)(0x50000048U+offset)=value;
}

/* Native entry: 0x420083f0. */
/* Original function-byte SHA-256:
 * 844efabeba074f206e1569cc6a1b9696da6bb8b0dbd19ca0f4c8eecbf35d236d. */
/*
 * Compute the native additive checksum modulo 2^32. MEMW/read, in order:
 * image_id, core, kind, PC, A0, fault address, return count, cause, then all six
 * return slots. Weights are 1, 5, 3, 1, 7, 1, 13, 11 and 17..22 for the slots. Magic,
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

/* Native entry: 0x4200845c. */
/* Original function-byte SHA-256:
 * 27fa1e55efb659cdf1a3a50ad6a8e521d43ef3e6ecbade0d3ef9a7737494587b. */
/*
 * Watchdog text-fragment callback. packed_cursor holds text length in low 16 bits
 * and callback ordinal in high 16 bits. Snapshot it once; every third call starting
 * at ordinal 2 receives a task/user name from the reviewed watchdog reporter.
 * Prepend " unfed=" for ordinal 2, otherwise comma, then append the fragment.
 * Each retained BYTE store has MEMW, always leaving a NUL at the current end.
 * A source byte is fetched before checking remaining space. NULL fragments
 * append only their separator. Other ordinals only advance the packed count.
 * Increment high 16 bits modulo 65536; retain the resulting low 16 bits offset. No cursor
 * NULL/range check or lock: a caller-supplied offset > 95 can make even the NUL
 * store leave the 96-byte text array. Does not set either watchdog marker.
 */
void panic_append_unfed_task(void *cursor_context,const char *fragment)
{
    volatile unsigned int *packed_cursor=cursor_context;
    unsigned int packed=*packed_cursor;
    unsigned int callback_ordinal=packed>>16;
    unsigned int text_length=packed&0xffffU;
    if (callback_ordinal>=2U && (callback_ordinal-2U)%3U==0) {
        const char *separator=callback_ordinal==2U?" unfed=":",";
        unsigned int fragment_start=text_length;
        unsigned char character=callback_ordinal==2U?' ':',';
        do {
            if (text_length+1U>95U) break;
            panic_text_store(text_length,character);
            ++text_length;
            character=(unsigned char)separator[text_length-fragment_start];
        } while (character!=0);
        panic_text_store(text_length,0);
        fragment_start=text_length;
        if (fragment!=NULL) {
            for (;;) {
                character=*(const volatile unsigned char *)(fragment+(text_length-fragment_start));
                if (character==0 || text_length+1U>95U) break;
                panic_text_store(text_length,character);
                ++text_length;
            }
        }
        panic_text_store(text_length,0);
    }
    *packed_cursor=((callback_ordinal+1U)<<16)|text_length;
}

/* Native entry: 0x420084f4. */
/* Original function-byte SHA-256:
 * 726261c036b99b795c207e23f2ed4a4ced3567c55ac93cf358540cadcd9da180. */
/*
 * Clear all 96 retained text BYTEs, publish pending tag 0x54574454, then ask the
 * watchdog reporter for unfed subscriptions via the packed-fragment callback.
 * Ignore reporter status and take only the cursor's low HALFWORD as the end.
 * For core 0 then 1, get its current TCB and call pcTaskGetName with that return
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
    unsigned int text_length=*(volatile unsigned short *)&cursor.length;
    for (unsigned int core=0;core<2U;++core) {
        RtosTask *task=xTaskGetCurrentTaskHandleForCore((int)core);
        const volatile unsigned char *name=(const volatile unsigned char *)pcTaskGetName(task);
        if (name!=NULL && name[0]=='I' && name[1]=='D' && name[2]=='L' && name[3]=='E')
            continue;
        const char *prefix=" run";
        unsigned int fragment_start=text_length;
        unsigned char character=' ';
        for (;;) {
            if (text_length+1U>95U) {
                panic_text_store(text_length,0);
                goto append_name;
            }
            panic_text_store(text_length,character);
            ++text_length;
            character=(unsigned char)prefix[text_length-fragment_start];
            if (character==0) break;
        }
        panic_text_store(text_length,0);
        if (text_length==95U) goto append_name;
        panic_text_store(text_length,(unsigned char)(core+'0'));
        panic_text_store(text_length+1U,0);
        if (text_length+2U==96U) text_length=95U;
        else {
            panic_text_store(text_length+1U,'=');
            text_length+=2U;
        }
append_name:
        panic_text_store(text_length,0);
        fragment_start=text_length;
        if (name!=NULL) {
            for (;;) {
                character=name[text_length-fragment_start];
                if (character==0 || text_length+1U>95U) break;
                panic_text_store(text_length,character);
                ++text_length;
            }
        }
        panic_text_store(text_length,0);
    }
}

/* Native entry: 0x42008610. */
/* Original function-byte SHA-256:
 * 58218276ddfbf661d87fbf1e474e0692f3f9fe3c9a8f32ea7d6511d397dc9d71. */
/*
 * Save a crash record before calling the reviewed system panic handler.
 * Snapshot current image ID before MEMW/clearing magic; copy it and store
 * kind=exception+1/core, or kind 0/core 255 for NULL info. Clear exception words
 * and all six return slots in native order. A non-NULL saved frame always
 * supplies PC. Only retained kind 1 (debug), 4 (abort), 5 (fault) also supply saved
 * A0, fault address/cause and a bounded spilled-window trace.
 *
 * Trace follows at most six frames whose incoming SP lies in
 * [0x3fc88010,0x3fcfffff] and is 16-byte aligned. Read saved A0 at SP-16, normalize
 * to (A0&0x3fffffff)|0x40000000, then fetch next SP at SP-12 BEFORE rejecting
 * an out-of-region or repeated PC. Admit normalized PC 0x40000000..0x400fffff
 * or 0x42000000..0x42ffffff. Compare only the immediately preceding PC; no CALL
 * size subtraction, executable predicate, PSRAM/RTC stack admission or cycle set.
 * Each accepted PC store precedes its count store, both with MEMW.
 *
 * Pending watchdog tag 0x54574454 preserves text and becomes validated tag
 *0x54574456; otherwise clear 96 BYTEs and validated tag. Clear pending tag first,
 * checksum the record, store checksum, then publish magic 0xc0debeef last, with
 * MEMW per retained store. No atomic transaction, durability or cross-core lock.
 * Always forward info, including NULL, to esp_panic_handler; that handler does
 * not validate NULL and can fault. Return only if its debugger path returns.
 */
void panic_record_and_handle(PanicInfo *panic_info)
{
    volatile RetainedPanicRecord *record=RETAINED_PANIC_RECORD;
    const volatile PanicInfo *info=panic_info;
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
            unsigned int stack_pointer=frame->a[1];
            memw(); record->return_count=0;
            unsigned int count=0;
            while (stack_pointer-0x3fc88010U<=0x77fefU) {
                if ((stack_pointer&15U)!=0) break;
                unsigned int pc=*(const volatile unsigned int *)(stack_pointer-16U);
                pc=(pc&0x3fffffffU)|0x40000000U;
                stack_pointer=*(const volatile unsigned int *)(stack_pointer-12U);
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
    esp_panic_handler(panic_info);
}

/* Native entry: 0x420087d4. */
/* Original function-byte SHA-256:
 * 78ed2a16f60723275b1b152d25655952ae59f29323de044442a6589e481cbcca. */
/*
 * Refresh current image ID from the first four ELF-SHA bytes of the mapped
 * application description, even when buffer/capacity are invalid. Then require
 * non-NULL buffer, nonzero capacity, record magic and matching additive checksum.
 * Failure returns 0 without clearing record/text or initializing the buffer.
 * Acceptance consumes magic BEFORE formatting and snapshots kind/current image.
 * Image mismatch is annotated only if the retained ID is nonzero; the long and
 * short suffix tests independently reload that retained ID.
 *
 * Kind 2 formats interrupt-WDT state and optionally watchdog text; otherwise a
 * validated watchdog tag selects task-WDT text. Remaining kinds 1/4/5 with cause
 *<64 use detailed exception fields; all others use a short category/PC format.
 * Append recorded PCs while the signed formatter total is positive and below
 * capacity, rereading return_count after each call. There is NO six-slot bound
 * on this consumer: a checksum-consistent excessive count can read later RTC
 * words. snprintf return values accumulate modulo 2^32; truncation/error still
 * consumes the record. Formatters may observe changing retained text/fields.
 * Always clear 96 text BYTEs and validated tag on acceptance, then return 1.
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
    memw(); unsigned int expected_checksum=record->checksum;
    if (expected_checksum!=panic_record_checksum()) return 0;
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

    unsigned int formatted_length;
    if (kind==2U) {
        memw(); unsigned int core=record->core;
        memw(); unsigned int pc=record->pc;
        formatted_length=(unsigned int)newlib_snprintf(buffer,capacity,
            "PANIC was: int watchdog, core=%u pc=0x%08x%s",core,pc,short_suffix);
        if ((int)formatted_length>0 && watchdog==0x54574456U && formatted_length<capacity)
            (void)newlib_snprintf(buffer+formatted_length,capacity-formatted_length,",%.*s",96,
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
            formatted_length=(unsigned int)newlib_snprintf(buffer,capacity,
                "PANIC was: %s core=%u pc=0x%08x a0=0x%08x vaddr=0x%08x cause=%u%s",
                category,core,pc,a0,address,cause,long_suffix);
        } else {
            memw(); unsigned int core=record->core;
            memw(); unsigned int pc=record->pc;
            memw(); unsigned int cause=record->exception_cause;
            const char *no_frame=cause>63U?" (no exception frame: watchdog or abort)":"";
            formatted_length=(unsigned int)newlib_snprintf(buffer,capacity,
                "PANIC was: %s core=%u pc=0x%08x%s%s",category,core,pc,no_frame,long_suffix);
        }
        memw(); unsigned int count=record->return_count;
        unsigned int index=0;
        while (index<count) {
            if ((int)formatted_length<=0 || formatted_length>=capacity) break;
            memw();
            unsigned int pc=*(const volatile unsigned int *)(0x50000024U+4U*index);
            ++index;
            unsigned int added=(unsigned int)newlib_snprintf(
                buffer+formatted_length,capacity-formatted_length," <-0x%08x",pc);
            memw(); count=record->return_count;
            formatted_length+=added;
        }
    }
    for (unsigned int index=0;index<96U;++index) panic_text_store(index,0);
    memw(); record->watchdog_validated=0;
    return 1;
}
