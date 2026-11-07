/* Medius v3.4.7 device: recovered 32-bit Xtensa type declarations.
 * Unknown fields remain explicit; these declarations do not make the decompilation buildable.
 * Application SHA-256: a8b414ed474578662305d8109e6c82b3f88a82db94ed8895541ad8bb4b0dad61
 */

#pragma once

#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/times.h>
#include <dirent.h>
#include <utime.h>

/* Explicit native register reads used where Ghidra rendered a bare register.
 * These inline accessors are reconstruction support, not extra firmware entries.
 */
static __inline__ __attribute__((always_inline)) unsigned int xtensa_read_prid(void)
{
    unsigned int value;
    __asm__ volatile ("rsr.prid %0" : "=a"(value));
    return value;
}

static __inline__ __attribute__((always_inline)) unsigned int xtensa_read_intenable(void)
{
    unsigned int value;
    __asm__ volatile ("rsr.intenable %0" : "=a"(value) : : "memory");
    return value;
}

/* ESP32-S3 task-entry frame: 192 bytes, including non-coprocessor state
 * and window spill storage. Offsets match xtensa_context.h and ESP32-S3 tie.h.
 * The separately allocated coprocessor block contains FPU and vector/AI state.
 */
typedef void (*TaskEntry)(void *argument);

/* Contiguous reserved EP0 task slots at 0x3fcd01fc; a storage view, not an
 * allocated SDK object. Availability is a separate byte at 0x3fcab515.
 */
typedef struct MediusUsbEp0TaskResources {
    struct RtosTask * volatile task;  /* 0: retained task handle */
    unsigned int * volatile stack;         /* 4: reserved 6144-byte stack */
    struct RtosTask * volatile tcb;   /* 8: caller-supplied static TCB */
} MediusUsbEp0TaskResources;


/* Solicited yield context, identified by exit_marker==0 at the same offset
 * as an interrupt frame's exit_dispatch pointer. It occupies 32 bytes;
 * register-window state is spilled into the surrounding ABI stack regions.
 */
typedef struct XtensaSolicitedFrame {
    unsigned int exit_marker;            /* 0x00: zero */
    unsigned int return_pc;              /* 0x04: encoded windowed A0 */
    unsigned int ps;                     /* 0x08 */
    unsigned int thread_pointer;         /* 0x0c */
    unsigned int base_save_area[4];      /* 0x10..0x1f: A0-A3 spill region */
} XtensaSolicitedFrame;

/* Non-coprocessor register payload saved at exception frame+0x70.
 * FPU/vector registers use the separate coprocessor payload instead.
 */
typedef struct XtensaExtraState {
    unsigned int thread_pointer;         /* 0x00 */
    unsigned int accumulator_low;        /* 0x04 */
    unsigned int accumulator_high;       /* 0x08 */
    unsigned int boolean_register;       /* 0x0c: BR */
    unsigned int compare_register;       /* 0x10: SCOMPARE1 */
    unsigned int mac[4];                 /* 0x14..0x23: M0-M3 */
} XtensaExtraState;                /* 36 bytes */
typedef struct XtensaExceptionFrame {
    unsigned int exit_dispatch;           /* 0x00: raw code address or solicited marker */
    unsigned int pc;                      /* 0x04: saved instruction address */
    unsigned int ps;                      /* 0x08 */
    unsigned int a[16];                   /* 0x0c: A0..A15 */
    unsigned int sar;                     /* 0x4c */
    unsigned int exception_cause;         /* 0x50 */
    unsigned int exception_address;       /* 0x54 */
    unsigned int loop_begin;              /* 0x58 */
    unsigned int loop_end;                /* 0x5c */
    unsigned int loop_count;              /* 0x60 */
    unsigned int spill_temporary[3];      /* 0x64 */
    unsigned int thread_pointer;         /* 0x70: GCC TLS base */
    unsigned int accumulator_low;        /* 0x74 */
    unsigned int accumulator_high;       /* 0x78 */
    unsigned int boolean_register;       /* 0x7c */
    unsigned int compare_register;       /* 0x80 */
    unsigned int mac[4];                  /* 0x84: M0..M3 */
    unsigned int padding_94[3];           /* 0x94 */
    unsigned int window_spill_area[8];    /* 0xa0..0xbf */
} XtensaExceptionFrame;

typedef struct XtensaCoprocessorHeader {
    union {
        struct { unsigned short enabled; unsigned short stored; }; /* +0/+2 */
        unsigned int enabled_stored;     /* Native combined initialization WORD. */
    };
    union {
        struct { unsigned short callee_saved; unsigned short reserved; }; /* +4/+6 */
        unsigned int saved_reserved;     /* Native combined initialization WORD. */
    };
    void *aligned_save_area;              /* 0x08 */
} XtensaCoprocessorHeader;
void _xt_user_exit(void);
void _xt_coproc_init(void);
void xthal_window_spill(void);
void vPortSetupTimer(void);
int xPortInterruptedFromISRContext(void);
int xPortStartScheduler(void) __attribute__((noreturn));
/* Xtensa StackType_t is uint8_t; offsets in the native frame remain WORD-based. */
unsigned char *pxPortInitialiseStack(unsigned char *top,TaskEntry entry,void *argument);
unsigned char xPortCheckValidTCBMem(void *pointer);
unsigned char xPortcheckValidStackMem(void *pointer);

/* Tick hooks execute in the kernel tick ISR, up to eight callbacks per CPU.
 * Coprocessor owners are per CPU/CP slot; neither table is a timer buffer.
 */
typedef void (*MediusTickHook)(void);
typedef MediusTickHook MediusTickHookTable[2][8];
typedef XtensaCoprocessorHeader *XtensaCoprocessorOwners[2][4];
/* Flat native initialization view of the same two rows of four slots. */
#define XTENSA_COPROCESSOR_OWNER_SLOTS ((XtensaCoprocessorHeader * volatile *)0x3fcab9a0U)
typedef unsigned int MediusSchedulerRunning[2];

/* Lazy ESP32-S3 coprocessor payloads, recovered from both exception handlers.
 * aligned_save_area in XtensaCoprocessorHeader points to the full 288-byte
 * payload below. CP0 starts at 0; CP3 starts at 80, aligned to 16 bytes.
 * These are context-save buffers, not UART/USB transfer buffers.
 */
typedef struct XtensaFpuState {
    unsigned int f[16];                  /* 0..60: raw F0..F15 bits */
    unsigned int fcr;                    /* 64: floating-point control */
    unsigned int fsr;                    /* 68: floating-point status */
} XtensaFpuState;                  /* 72 bytes */

typedef struct XtensaVectorState {
    unsigned int accx[2];                /* 0..4 */
    unsigned int qacc_high[5];           /* 8..24 */
    unsigned int qacc_low[5];            /* 28..44 */
    unsigned int sar_byte;               /* 48 */
    unsigned int fft_bit_width;          /* 52 */
    unsigned int ua_state[4];            /* 56..68 */
    unsigned int padding_72[2];          /* 72..79: not saved or loaded */
    unsigned int q[8][4];                /* 80..207: eight 128-bit Q registers */
} __attribute__((aligned(16))) XtensaVectorState;               /* 208 bytes, 16-byte alignment */

typedef struct XtensaCoprocessorPayload {
    XtensaFpuState fpu;            /* 0..71: CP0 */
    unsigned int padding_72[2];          /* 72..79: CP3 alignment */
    XtensaVectorState vector;      /* 80..287: CP3 */
} __attribute__((aligned(16))) XtensaCoprocessorPayload;             /* 288 bytes */

typedef void (*PthreadDestructor)(void *value);
typedef struct PthreadKeyEntry {
    unsigned int key;
    PthreadDestructor destructor;
    struct PthreadKeyEntry *next;
} PthreadKeyEntry;
typedef struct PthreadValueEntry {
    unsigned int key;
    void *value;
    struct PthreadValueEntry *next;
} PthreadValueEntry;
typedef struct PthreadValueList {
    PthreadValueEntry *first;
} PthreadValueList;
typedef PthreadKeyEntry *PthreadKeyHead;
#define PTHREAD_KEY_REGISTRY_LOCK ((PortMuxWords *)0x3fcaa6ccU)
#define PTHREAD_REGISTERED_KEYS (*(PthreadKeyEntry * volatile *)0x3fcbde30U)
void pthread_cleanup_value_list(PthreadValueList *list);
void pthread_cleanup_thread_specific_data_callback(int index,void *storage);
int pthread_key_create(unsigned int *key,PthreadDestructor destructor);
int pthread_setspecific(unsigned int key,const void *value);

/* Newlib 4.3.0 small/reentrant ABI with ESP backward-compatible fields.
 * Layouts match installed ESP32-S3 reference DWARF and original context initialization.
 * FILE, locale, random-state and auxiliary objects remain opaque behind their pointers.
 */
/* Binary64 representation view for the little-endian ESP32-S3 ABI.
 * word[0] is the low 32 bits, word[1] the high 32 bits; no numeric cast is implied.
 */
typedef union MediusBinary64 {
    double value;
    unsigned int word[2];
} MediusBinary64;

/* Read-only decimal scaling tables, identified by their complete native bytes. */
extern const double __mprec_tens[25]; /* 0x3c047aa0 */
extern const double __mprec_bigtens[5]; /* 0x3c047a78 */

typedef struct MediusBigInt {
    struct MediusBigInt *next;             /* 0x00: freelist/cache chain */
    int bucket;                           /* 0x04: capacity is 2^bucket words */
    int capacity_words;                   /* 0x08 */
    int sign;                             /* 0x0c */
    int used_words;                       /* 0x10 */
    unsigned int words[1];                /* 0x14: variable allocation tail, low word first */
} MediusBigInt;

typedef struct MediusMprec {
    MediusBigInt *result;
    int result_bucket;
    MediusBigInt *powers_of_five;
    MediusBigInt **freelist;
} MediusMprec;

typedef struct NewlibReent NewlibReent;
typedef struct NewlibFile NewlibFile;
typedef void (*NewlibCleanup)(NewlibReent *reent);
typedef void (*ExitFunction)(void);
typedef void (*SignalFunction)(int signal);

typedef struct NewlibAtexit {
    struct NewlibAtexit *next;
    int index;
    ExitFunction functions[32];
    void *on_exit_arguments;
} NewlibAtexit;

typedef struct NewlibGlue {
    struct NewlibGlue *next;
    int stream_count;
    NewlibFile *streams;
} NewlibGlue;

struct NewlibReent {
    int error_number;                     /* 0x00: task-local errno */
    void *standard_input;                 /* 0x04 */
    void *standard_output;                /* 0x08 */
    void *standard_error;                 /* 0x0c */
    int temporary_name_counter;           /* 0x10 */
    char *emergency_buffer;               /* 0x14 */
    int stdio_initialized;                /* 0x18: SDK _REENT_SDIDINIT / reserved_0 */
    int reserved_1;                       /* 0x1c: backward-compatible reserved field */
    void *locale;                         /* 0x20 */
    MediusMprec *mprec;                    /* 0x24: floating-point conversion state */
    NewlibCleanup cleanup;          /* 0x28 */
    int gamma_sign;                       /* 0x2c */
    int conversion_capacity;              /* 0x30 */
    char *conversion_buffer;              /* 0x34 */
    void *random_state;                   /* 0x38 */
    void *local_time_buffer;              /* 0x3c */
    char *ascii_time_buffer;              /* 0x40 */
    SignalFunction *signal_functions; /* 0x44 */
    NewlibAtexit *atexit_head;             /* 0x48: backward-compatible reserved_6 */
    NewlibAtexit atexit_initial;           /* 0x4c..0xd7: reserved_7 */
    NewlibGlue stream_glue;          /* 0xd8: reserved_8 */
    void *stream_files;                   /* 0xe4 */
    void *misc;                           /* 0xe8 */
    char *signal_buffer;                  /* 0xec; total size 0xf0 */
};

/* Fixed startup object and runtime-selected global-context pointer are distinct.
 * Volatile views retain the observed native loads; they do not provide a lock.
 */
#define NEWLIB_STARTUP_CONTEXT ((volatile NewlibReent *)0x3fcabb5cU)
#define NEWLIB_GLOBAL_CONTEXT_POINTER (*(NewlibReent *volatile *)0x3fcabb58U)

/* Newlib magnitude arithmetic; see runtime/number_conversion.c.
 * These are ordinary windowed-C calls. The __d2b binary64 argument consumes an
 * aligned register pair; the compiler supplies the alignment slot.
 */
MediusBigInt *_Balloc(NewlibReent *reent, int bucket);
void _Bfree(NewlibReent *reent, MediusBigInt *value);
MediusBigInt *__multadd(NewlibReent *reent, MediusBigInt *value, int multiplier,
                       int addend);
MediusBigInt *__i2b(NewlibReent *reent, int value);
MediusBigInt *__multiply(NewlibReent *reent, MediusBigInt *left, MediusBigInt *right);
MediusBigInt *__pow5mult(NewlibReent *reent, MediusBigInt *value, int exponent);
MediusBigInt *__lshift(NewlibReent *reent, MediusBigInt *value, int shift_bits);
MediusBigInt *__mdiff(NewlibReent *reent, MediusBigInt *left, MediusBigInt *right);
MediusBigInt *__d2b(NewlibReent *reent, double value, int *exponent,
                   int *significant_bits);
int __hi0bits(unsigned int value);
int __lo0bits(unsigned int *value);
int __mcmp(MediusBigInt *left, MediusBigInt *right);

typedef void (*TlsDeleteCallback)(int index,void *value);

/* ESP-IDF capability region and TLSF multi-heap owner layouts; 32-bit pointers. */
/* In-region multi_heap descriptor: 20 bytes, followed by TLSF control/tables/pool.
 * The region byte count passed to multi_heap_register includes this descriptor.
 */
typedef struct MultiHeap {
    void *lock;                         /* 0x00: optional portMUX spinlock, not an RTOS mutex */
    unsigned int free_bytes;            /* 0x04: allocator accounting counter */
    unsigned int minimum_free_bytes;    /* 0x08: lifetime minimum of that counter */
    unsigned int pool_size;             /* 0x0c: entire TLSF region, INCLUDING its metadata */
    void *heap_data;                    /* 0x10: TLSF control at descriptor+20 */
} MultiHeap;
typedef struct HeapRegion {
    unsigned int caps[3];           /* +0x00: capabilities in priority order */
    int start;                      /* +0x0c: first region address */
    int end;                        /* +0x10: exclusive end address */
    unsigned int lock_owner;        /* +0x14: embedded portMUX owner word */
    unsigned int lock_count;        /* +0x18: embedded portMUX recursion count */
    MultiHeap *heap;          /* +0x1c: NULL until registration succeeds */
    struct HeapRegion *next;  /* +0x20: registered-region list link */
} HeapRegion;
typedef HeapRegion *RegisteredHeapPointer;
typedef void (*HeapAllocationFailureCallback)(unsigned int size,
    unsigned int capabilities,const char *function_name);
#define HEAP_ALLOCATION_FAILURE_CALLBACK (*(HeapAllocationFailureCallback volatile *)0x3fcbda04U)
#define HEAP_INTERNAL_ALLOCATION_THRESHOLD (*(const volatile unsigned int *)0x3fcaa554U)

typedef void (*IpcCallback)(void *argument);

/* Contiguous IPC global-storage view, not an SDK-allocated object.
 * Device base0x3fcbd828; host base0x3fca71d8. Two slots per array.
 * Volatile publication words match the SDK declarations; native MEMWs remain
 * explicit in the recovered callers.
 */
typedef struct IpcDispatchState {
    void * volatile nonblocking_arguments[2];       /* 0x00 */
    volatile unsigned char nonblocking_ready[2];    /* 0x08 */
    unsigned char padding0a[2];
    volatile IpcCallback nonblocking_callbacks[2]; /* 0x0c */
    volatile unsigned int wait_mode[2];             /* 0x14 */
    void * volatile arguments[2];                   /* 0x1c */
    volatile IpcCallback callbacks[2];         /* 0x24 */
    struct RtosQueue *volatile acknowledgements[2]; /* 0x2c */
    struct RtosQueue *volatile submission_mutexes[2]; /* 0x34 */
    struct RtosTask *volatile tasks[2];        /* 0x3c */
} IpcDispatchState;


typedef void (*EspTimerCallback)(void *argument);

/* ESP-IDF software timer object, profiling disabled: 32 bytes.
 * period_and_flags stores a 56-bit microsecond period and an 8-bit flag field.
 * Bit 56 selects ISR dispatch; bit 57 skips overdue periodic callbacks.
 * These application-created timers select task dispatch on the shared service.
 */
typedef struct EspTimer {
    /* ESP32-S3 is little endian. Word/byte views retain native access widths. */
    union {
        unsigned long long alarm;
        struct { unsigned int alarm_low; unsigned int alarm_high; };
    };
    union {
        unsigned long long period_and_flags;
        struct { unsigned int period_low; unsigned int period_high_and_flags; };
        struct { unsigned char period_bytes[7]; unsigned char flags; };
    };
    union {
        EspTimerCallback callback;
        unsigned int event_id;          /* 0xf0de1e1e requests deferred deletion. */
    };
    void *argument;
    struct EspTimer *volatile next;
    struct EspTimer *volatile *previous; /* Address of the predecessor's next/head slot. */
} EspTimer;

/* ESP-IDF timer creation arguments: callback, context, task dispatch, name, skip flag. */
typedef struct EspTimerCreateArgs {
    EspTimerCallback callback; /* +0 */
    void *argument;                       /* +4 */
    unsigned int dispatch;                /* +8: only task dispatch0 is admitted. */
    const char *name;                      /* +12: unused in this build. */
    unsigned char skip_unhandled_events;   /* +16: raw byte doubled into timer flags. */
    unsigned char padding17[3];
} EspTimerCreateArgs;

/* Two software-dispatch classes share SYSTIMER comparator2. Deadlines are
 * explicit little-endian WORDs; accesses are not atomic 64-bit snapshots. */
typedef struct TimerDeadlineWords {
    volatile unsigned int low;
    volatile unsigned int high;
} TimerDeadlineWords;
#define ESP_TIMER_DEADLINES ((TimerDeadlineWords *)0x3fcaa6d8U)
#define ESP_TIMER_DEADLINE_LOCK ((PortMuxWords *)0x3fcaa6e8U)
#define ESP_TIMER_LISTS ((EspTimer *volatile *)0x3fcd8694U)
#define ESP_TIMER_LIST_LOCKS ((PortMuxWords *)0x3fcaba88U)
#define ESP_TIMER_DELETE_EVENT 0xf0de1e1eU
void esp_timer_impl_set_alarm_id(unsigned long long timestamp,unsigned int alarm_id);
void timer_insert(EspTimer *timer,int without_update_alarm);
void timer_remove(EspTimer *timer);
unsigned long long esp_timer_impl_get_min_period_us(void);

/* CLIP input binding storage at 0x3fcc7d20; eight slots, stride eight. */
typedef struct ClipInputTrigger {
    unsigned char input_class;       /* 0 */
    unsigned char padding1;
    unsigned short usage;            /* 2 */
    union {
        struct {
            unsigned char edge;      /* 4: 0 any, 1/2 selected edge */
            unsigned char action;    /* 5: playback verb 0..5 */
        };
        unsigned short edge_action;  /* Native combined HALFWORD store. */
    };
    unsigned char consume;           /* 6 */
    unsigned char padding7;
} ClipInputTrigger;

/* Packet trigger storage at 0x3fcc7b98; eight slots, stride 48.
 * Match length is at most 16 per record and 112 summed across admitted rules.
 */
typedef struct ClipPacketTrigger {
    unsigned short id;               /* 0 */
    unsigned char traffic_class;     /* 2 */
    unsigned char direction;         /* 3 */
    unsigned char match_length;      /* 4 */
    unsigned char selector_length;   /* 5 */
    union {
        struct {
            unsigned char action;    /* 6 */
            unsigned char flags;     /* 7: stored bits 1/2 */
        };
        unsigned short action_flags; /* Native combined HALFWORD store. */
    };
    unsigned char match[16];         /* 8 */
    unsigned char mask[16];          /* 24 */
    unsigned int hits;               /* 40: saturates at UINT32_MAX */
    unsigned char previous_match;    /* 44: RUN edge state */
    unsigned char padding45[3];
} ClipPacketTrigger;
#define CLIP_PACKET_TRIGGERS ((const volatile ClipPacketTrigger *)0x3fcc7b98U)

/* Native CATCH subscription table entry at 0x3fcc7a1c, stride six bytes.
 * The updater holds at most 32 entries and publishes a double-buffered snapshot.
 * This is a storage view; wire records omit padding and append a drop count.
 */
typedef struct CaptureSubscription {
    unsigned short id;             /* 0: 0xffff is the wildcard ID */
    unsigned char traffic_class;   /* 2: 0xff is the all-class sentinel */
    unsigned char direction;       /* 3 */
    unsigned char capture_length;  /* 4 */
    unsigned char padding5;
} CaptureSubscription;
#define CAPTURE_SUBSCRIPTION_COUNT (*(const volatile unsigned char *)0x3fcc7b1eU)
#define CAPTURE_SUBSCRIPTION_FULL (*(const volatile unsigned char *)0x3fcc7b1fU)
#define CAPTURE_EDITABLE_SUBSCRIPTIONS ((const volatile CaptureSubscription *)0x3fcc7a1cU)

/* QUERY(CATCH) uses BYTE stores, including its unaligned multibyte fields. */
typedef struct CaptureStatusWireHeader {
    unsigned char selector,table_full,total_drops_le[4],clock_offset_us_le[4];
    unsigned char drift_ppb_le[4],round_trip_us_le[2],sample_age_ms_le[2],count;
} CaptureStatusWireHeader;
typedef struct CaptureStatusWireRecord {
    unsigned char traffic_class,id_le[2],direction,capture_length,drops_le[2];
} CaptureStatusWireRecord;

/* Decoded CLIP entry, 80 bytes. Record pointers borrow the input scratch window.
 * Usage target_kind is passed through to the input-update dispatch; padding is
 * zeroed by the parser. Motion fields are signed16-bit values in playback.
 */
typedef struct ClipUsageChange {
    unsigned char target_kind;             /* 0 */
    unsigned char padding1;
    unsigned short usage;                  /* 2 */
    unsigned char value;                    /* 4 */
    unsigned char padding5;
} ClipUsageChange;

typedef struct ClipDecodedEntry {
    unsigned char is_delay;                 /* 0x00 */
    unsigned char padding01;
    unsigned short delay_ticks;             /* 0x02: playback steps, not microseconds */
    union {
        struct {
            unsigned char has_xy;           /* 0x04 */
            unsigned char has_wheel;
            unsigned char has_pan;
            unsigned char padding07;
        };
        unsigned int motion_presence;
    };
    short x;                               /* 0x08 */
    short y;
    short wheel;
    short pan;
    unsigned char usage_count;              /* 0x10 */
    unsigned char padding11;
    ClipUsageChange usage_changes[8];  /* 0x12..0x41 */
    unsigned char packet_count;             /* 0x42 */
    unsigned char control_count;
    const unsigned char *packet_records;    /* 0x44 */
    const unsigned char *control_records;   /* 0x48 */
    unsigned short packet_bytes;            /* 0x4c */
    unsigned short control_bytes;
} ClipDecodedEntry;

/* CLIP playback byte ring: 32-bit Xtensa layout, 0x1c bytes.
 * Positions are monotonically incremented unsigned counters; physical offsets use
 * position & (capacity-1), so the owning initializer supplies a power of two.
 * Retained playback keeps retained_start fixed to permit rewind. Streaming mode
 * releases decoded bytes. These helpers do not lock; their callers serialize use.
 */
typedef struct ClipRing {
    unsigned char *storage;                /* 0x00 */
    unsigned char *scratch;                /* 0x04: contiguous decode window, 512 bytes */
    unsigned int capacity;                 /* 0x08 */
    unsigned int retained_start;           /* 0x0c */
    unsigned int read_position;            /* 0x10 */
    unsigned int write_position;           /* 0x14 */
    unsigned char finalized;               /* 0x18 */
    unsigned char padding_19[3];
} ClipRing;
int clip_ring_decode_next(ClipRing *ring,ClipDecodedEntry *decoded);
bool clip_ring_at_end(const ClipRing *ring);
unsigned char clip_ring_is_finalized(const ClipRing *ring);
void clip_ring_release_consumed(ClipRing *ring);
unsigned int clip_ring_free_bytes(const ClipRing *ring);
unsigned int clip_ring_consumed_bytes(const ClipRing *ring);

/* QUERY(CLIP) has a31-byte header, then3-byte held usages,3 bytes of
 * playback flags/input count,6-byte input records and10-byte packet prefixes.
 * All arrays below represent little-endian BYTE fields, without native padding. */
typedef struct ClipStatusWireHeader {
    unsigned char selector,mode,free_bytes_le[4],retained_bytes_le[4];
    unsigned char consumed_bytes_le[4],steps_le[4],underflows_le[2];
    unsigned char short_writes_le[2],sequence_errors_le[2],control_successes_le[2];
    unsigned char control_errors_le[2],dropped_le[2],held_count;
} ClipStatusWireHeader;
typedef struct ClipHeldUsageWire {
    unsigned char input_class,usage_le[2];
} ClipHeldUsageWire;
typedef struct ClipInputTriggerWire {
    unsigned char input_class,usage_le[2],edge,action,consume;
} ClipInputTriggerWire;
typedef struct ClipPacketTriggerWire {
    unsigned char traffic_class,id_le[2],direction,action,flags,selector_length;
    unsigned char match_length,hits_le[2];
} ClipPacketTriggerWire;
typedef struct InputLockWireRecord {
    unsigned char input_class,usage_le[2],direction,scale_le[2];
} InputLockWireRecord;

/* ESP-IDF FreeRTOS layout recovered for these 32-bit Xtensa images.
 * TCB size 0x154; notification index 0 is the only compiled slot. Offsets come
 * from task construction, list/notification/mutex code and debugger TCB samples.
 * One TLS value at 0x54, its deletion callback at 0x58 and a 240-byte Newlib context at 0x5c.
 */
typedef struct RtosTask RtosTask;
typedef struct RtosListItem RtosListItem;
typedef struct RtosList RtosList;

typedef struct RtosMiniListItem {
    volatile unsigned int value;
    RtosListItem *volatile next;
    RtosListItem *volatile previous;
} RtosMiniListItem;

struct RtosListItem {
    volatile unsigned int value;
    RtosListItem *volatile next;
    RtosListItem *volatile previous;
    void *owner;
    RtosList *volatile container;
};

struct RtosList {
    volatile unsigned int count;
    RtosListItem *volatile index;
    RtosMiniListItem end_marker;
};

/* Native one-slot notification state BYTE and action WORD encodings. */
enum NotificationState {
    RTOS_NOTIFICATION_IDLE = 0,
    RTOS_NOTIFICATION_WAITING = 1,
    RTOS_NOTIFICATION_RECEIVED = 2
};
enum NotificationAction {
    RTOS_NOTIFY_NO_ACTION = 0,
    RTOS_NOTIFY_SET_BITS = 1,
    RTOS_NOTIFY_INCREMENT = 2,
    RTOS_NOTIFY_OVERWRITE = 3,
    RTOS_NOTIFY_SET_IF_NOT_PENDING = 4
};

typedef struct RtosTimeout {
    int overflow_count;
    unsigned int entered_at_tick;
} RtosTimeout;

struct RtosTask {
    void *top_of_stack;                    /* 0x000 */
    RtosListItem state_item;          /* 0x004 */
    RtosListItem event_item;          /* 0x018 */
    unsigned int priority;                 /* 0x02c */
    void *stack_base;                      /* 0x030 */
    char name[16];                         /* 0x034 */
    int core_id;                           /* 0x044: 0, 1, or no affinity 0x7fffffff */
    void *stack_end;                       /* 0x048 */
    unsigned int base_priority;            /* 0x04c */
    unsigned int mutexes_held;              /* 0x050 */
    union {
        struct {
            void *thread_local_storage;    /* 0x054: one application TLS slot */
            TlsDeleteCallback tls_delete_callback; /* 0x058 */
        };
        void *raw_tls_words[2];            /* Native TLS getter exposes both words. */
    };
    NewlibReent libc_reent;           /* 0x05c..0x14b */
    volatile unsigned int notification_value; /* 0x14c */
    volatile unsigned char notification_state; /* 0x150: 0 idle, 1 waiting, 2 received */
    unsigned char allocation_kind;         /* 0x151: 0 dynamic, 1 static stack, 2 static stack+TCB */
    unsigned char delay_aborted;            /* 0x152 */
    unsigned char padding_153;              /* 0x153 */
};

/* ESP-IDF esp_mmu_map.c / ESP32-S3: one linear-address region, 32-bit pointers. */
typedef struct MmuBlock MmuBlock;
typedef struct MmuRegion {
    unsigned int bus_id;                   /* 0x00 */
    unsigned int start;                    /* 0x04: linear address */
    unsigned int end;                      /* 0x08 */
    unsigned int region_size;              /* 0x0c: bytes */
    unsigned int free_head;                /* 0x10 */
    unsigned int max_slot_size;            /* 0x14: bytes */
    unsigned int caps;                     /* 0x18 */
    unsigned int targets;                  /* 0x1c */
    MmuBlock *blocks_first;           /* 0x20: TAILQ head */
    MmuBlock **blocks_last;           /* 0x24: pointer to tail next link */
} MmuRegion;
typedef struct MmuContext {
    unsigned int num_regions;
    MmuRegion regions[1];
    struct __lock *mutex;                  /* newlib lock handle; untouched by init */
} MmuContext;

typedef void (*FrameCallback)(unsigned char type, unsigned char flags, const unsigned char *payload, unsigned short length, void *context);

typedef struct LinkParser {
     FrameCallback on_frame;
    void *context;
    unsigned int state;
    unsigned char type;
    unsigned char flags;
    unsigned short payload_length;
    unsigned short payload_used;
    unsigned short received_crc;
    unsigned int last_rx_time_us_low; /* +0x14: timestamp of the last timeout check */
    unsigned char payload[512];

} LinkParser;

/* Native framing states, shared by the control and inter-chip UART parsers. */
enum LinkParserState {
    FRAME_WAIT_MARKER = 0,
    FRAME_READ_TYPE = 1,
    FRAME_READ_FLAGS = 2,
    FRAME_READ_LENGTH_LOW = 3,
    FRAME_READ_LENGTH_HIGH = 4,
    FRAME_READ_PAYLOAD = 5,
    FRAME_READ_CRC_LOW = 6,
    FRAME_READ_CRC_HIGH = 7
};

void link_parser_feed(LinkParser *parser, const unsigned char *data,
                              unsigned int length);
void link_parser_reset(LinkParser *parser);
void link_parser_init(LinkParser *parser, FrameCallback callback,
                              void *context);
void link_parser_check_rx_gap(LinkParser *parser,
                                     unsigned int now_us_low, int timeout_us);
unsigned short crc16_update(unsigned short crc, const unsigned char *data,
                                    unsigned int length);
int link_frame_encode(unsigned char *output, unsigned int capacity,
                              unsigned char type, unsigned char flags,
                              const void *payload, unsigned short length);
int link_frame_patch_payload(unsigned char *frame, unsigned int frame_length,
                                     unsigned short payload_offset, const void *patch,
                                     unsigned short patch_length);

#define FUN_4037f09c link_parser_check_rx_gap

/* Access view of registered USB class objects, not a claimed full library layout.
 * Native dispatcher forwards full register words to this callback. */
typedef void (*MediusUsbdClassEventHandler)(unsigned int bus,unsigned int event,void *descriptor);
typedef struct {
    unsigned char opaque0[12];
    MediusUsbdClassEventHandler volatile notify;
    unsigned char opaque16[8];
    volatile unsigned char interface_number;
} MediusUsbdClassEventView;

/* Eight consecutive core state bytes at core+0x81c, verified through
 * reset, SET_ADDRESS, GET_STATUS, configuration attributes and wakeup paths. */
typedef struct {
    volatile unsigned char configuration;
    volatile unsigned char device_address;
    volatile unsigned char ep0_next_state;
    volatile unsigned char self_powered;
    volatile unsigned char remote_wakeup_support;
    volatile unsigned char remote_wakeup_enabled;
    volatile unsigned char is_suspend;
    volatile unsigned char speed;
} MediusUsbdCoreState;

typedef const unsigned char *(*MediusUsbDeviceDescriptorCallback)(unsigned int speed);
/* Only the first verified descriptor-table word is described here. */
typedef struct {
    MediusUsbDeviceDescriptorCallback volatile device_descriptor;
} MediusUsbdDescriptorPrefix;
typedef void (*MediusUsbdApplicationEvent)(unsigned int bus,unsigned int event);

/* Seven EP0 descriptor wire bytes, plus one unsent C alignment-padding byte. */
typedef struct {
    volatile unsigned int header;
    volatile unsigned short maximum_packet_size;
    volatile unsigned char interval;
} MediusUsbdEp0DescriptorPacket;

/* Seven snapshot-fragment wire bytes. Native code deliberately reads
 * separate bytes, not aligned/packed halfwords, and caches them before reset. */
typedef struct {
    unsigned char section;
    unsigned char total_low;
    unsigned char total_high;
    unsigned char offset_low;
    unsigned char offset_high;
    unsigned char count_low;
    unsigned char count_high;
} MediusCloneFragmentHeader;

typedef struct CloneAssembly {
     unsigned char section_0[18];
    unsigned char section_1[2048];
    unsigned char section_2[6144];
    unsigned char section_3[127];
    unsigned char section_4[127];
    unsigned char section_5[127];
    unsigned char section_7[256];
    unsigned char section_13[1536];
    unsigned char section_14[1039];
    unsigned char section_10[1];
    unsigned char section_11[6144];
    unsigned char section_12[1];
    unsigned char section_15[3];
    unsigned char section_16[512];
    unsigned char unknown_46a3;
    unsigned short lengths[17];
    unsigned short received[17];
    unsigned short expected[17];
    unsigned char present[17];
    unsigned char end_seen;
    unsigned char complete;
    unsigned char error;

} CloneAssembly;

typedef unsigned long long (*SystimerConvert)(unsigned long long value);

typedef struct SystimerHal {
     volatile unsigned int *dev;
    SystimerConvert ticks_to_us;
    SystimerConvert us_to_ticks;

} SystimerHal;

typedef struct SystimerTickOps {
     SystimerConvert ticks_to_us;
    SystimerConvert us_to_ticks;

} SystimerTickOps;

/* HAL register indices are 32-bit WORD indices, not byte offsets.
 * Counter pairs have a two-word stride; alarm configuration/load have one. */
#define SYSTIMER_REGISTER_BASE 0x60023000U
#define SYSTIMER_WORD_CONFIGURATION 0U
#define SYSTIMER_WORD_COUNTER_OPERATION 1U
#define SYSTIMER_WORD_COUNTER_LOAD_HIGH 3U
#define SYSTIMER_WORD_COUNTER_LOAD_LOW 4U
#define SYSTIMER_WORD_ALARM_TARGET_HIGH 7U
#define SYSTIMER_WORD_ALARM_TARGET_LOW 8U
#define SYSTIMER_WORD_ALARM_CONFIGURATION 13U
#define SYSTIMER_WORD_COUNTER_VALUE_HIGH 16U
#define SYSTIMER_WORD_COUNTER_VALUE_LOW 17U
#define SYSTIMER_WORD_ALARM_LOAD 20U
#define SYSTIMER_WORD_COUNTER_LOAD 23U
#define SYSTIMER_WORD_INTERRUPT_ENABLE 25U
#define SYSTIMER_WORD_INTERRUPT_CLEAR 27U
#define SYSTIMER_WORD_INTERRUPT_STATUS 28U
#define SYSTIMER_CLOCK_ENABLE 0x80000000U
#define SYSTIMER_COUNTER_SNAPSHOT_UPDATE 0x40000000U
#define SYSTIMER_COUNTER_VALUE_VALID 0x20000000U
#define SYSTIMER_HIGH_VALUE_MASK 0xfffffU
#define SYSTIMER_ALARM_PERIOD_MASK 0x3ffffffU
#define SYSTIMER_ALARM_PERIODIC_MODE 0x40000000U
#define SYSTIMER_BUS_CLOCK_RESET_MASK 0x20000000U
#define SYSTIMER_TICK_INTERRUPT_SOURCE 57U
#define SYSTIMER_TICK_INTERRUPT_FLAGS 1026U
#define SYSTIMER_TICK_PERIOD_US 1000U
#define SYSTIMER_TICK_PHASE_US 500U

/* Shared hardware tick state, distinct from esp_timer's counter0/alarm2 context. */
#define SYSTEM_TICK_HAL ((SystimerHal *)0x3fcbdd4cU)
#define SYSTEM_HANDLED_TICKS ((volatile unsigned int *)0x3fcbdd58U)
#define SYSTEM_TICK_CONVERSION_OPS ((const volatile SystimerTickOps *)0x3c046358U)
void SysTickIsrHandler(void *argument);
void vSystimerSetup(void);
void esp_vApplicationTickHook(void);
int xTaskIncrementTick(void);
int xTaskIncrementTickOtherCores(void);
void systimer_hal_set_alarm_period(SystimerHal *hal,unsigned int alarm_id,unsigned int period_us);
void systimer_hal_counter_value_advance(SystimerHal *hal,unsigned int counter_id,long long delta_us);
void systimer_hal_set_alarm_target(SystimerHal *hal,unsigned int alarm_id,unsigned long long target_us);

/* A 48-byte rewrite slot. Paired class/direction and payload length/offset
 * views retain the native HALFWORD/WORD stores used by the rule updater. */
typedef struct RewriteRule {
    unsigned short endpoint;
    union {
        struct { unsigned char traffic_class,direction; };
        unsigned short class_direction;
    };
    unsigned char prefix_length;
    unsigned char prefix[16];
    unsigned char mask[16];
    unsigned char action;
    unsigned short patch_offset;
    union {
        struct { unsigned short payload_length,payload_offset; };
        unsigned int payload_extent;
    };
    unsigned int hits;

} RewriteRule;

typedef RewriteRule RewriteRuleTable[32];
/* The whole0xe08-byte span is cleared by the all-rule sentinel. */
typedef struct RewriteRuleStore {
    RewriteRule rules[32];
    unsigned char payload[2048];
    unsigned short payload_used;
    union {
        struct { unsigned char count,generation; };
        unsigned short count_generation;
    };
    unsigned char full,reserved_e05[3];
} RewriteRuleStore;
#define REWRITE_STORE ((volatile RewriteRuleStore *)0x3fcc8f88U)
void rewrite_compact_payload(void);
void rewrite_update_rule(unsigned int traffic_class,unsigned int endpoint,
    unsigned int direction,int enabled,unsigned int action,unsigned short patch_offset,
    unsigned char prefix_length,const unsigned char *prefix,const unsigned char *mask,
    const unsigned char *payload,unsigned short payload_length);
void rewrite_command(unsigned char traffic_class,unsigned short id,
    unsigned char direction,unsigned char present,unsigned char action,unsigned short offset,
    unsigned char match_length,const unsigned char *match_bytes,const unsigned char *mask_bytes,
    const unsigned char *replacement,unsigned short replacement_length);
unsigned int rewrite_summary_encode(unsigned char *output);
unsigned int rewrite_rule_encode(unsigned char *output,unsigned char index);

typedef struct {
     unsigned short max_packet;
    unsigned char transfer_type;
    unsigned char unknown3;
    unsigned char *buffer;
    unsigned int requested;
    unsigned int actual;
    unsigned char fifo_index;
    unsigned char interval;
    unsigned char last_packet_count;
    unsigned char disable_pending;
    unsigned char cancelled;
    unsigned char unknown21;
    unsigned short last_progress_frame;
    unsigned char *initial_buffer;

} MediusDwc2Endpoint;

typedef MediusDwc2Endpoint MediusDwc2Endpoints[16];

/* Device controller parameters copied from the live64-byte template. */
typedef struct {
    unsigned char phy_type;
    unsigned char phy_width;
    unsigned char dma_enabled;
    unsigned char uninterpreted3;
    unsigned short receive_fifo_words;
    unsigned short transmit_fifo_words[16];
    unsigned char uninterpreted38[10];
    unsigned int general_core_configuration;
    unsigned char uninterpreted52[4];
    unsigned char session_override;
    unsigned char uninterpreted57[3];
    unsigned int fifo_capacity;
} MediusDwc2DeviceParameters;

/* Native0x3e4-byte context; packed capabilities retain their verified bit layout. */
typedef struct {
    unsigned char uninterpreted0[12];
    unsigned int core_id;
    unsigned int endpoint_directions;
    unsigned int core_capabilities;
    unsigned int max_transfer_size;
    unsigned int packet_fifo_capabilities;
    unsigned int device_capabilities;
    MediusDwc2DeviceParameters parameters;
    MediusDwc2Endpoint input_endpoints[16];
    MediusDwc2Endpoint output_endpoints[16];
} MediusDwc2DeviceContext;

/* Accessed DWC2 core/device register layout. Volatility is supplied by the
 * pointer at each access; reserved ranges carry no inferred behaviour. */
typedef struct {
    unsigned int otg_control;
    unsigned int otg_interrupt;
    unsigned int ahb_configuration;
    unsigned int usb_configuration;
    unsigned int reset_control;
    unsigned int interrupt_status;
    unsigned int interrupt_mask;
    unsigned int receive_status;
    unsigned int receive_status_pop;
    unsigned int receive_fifo_size;
    unsigned int nonperiodic_tx_fifo_size;
    unsigned char reserved2c[12];
    unsigned int general_core_configuration;
    unsigned int reserved3c;
    unsigned int core_id;
    unsigned int hardware_config1;
    unsigned int hardware_config2;
    unsigned int hardware_config3;
    unsigned int hardware_config4;
    unsigned char reserved54[176];
    unsigned int dedicated_tx_fifo_size[15];
    unsigned char reserved140[1728];
    unsigned int device_configuration;
    unsigned int device_control;
    unsigned int device_status;
    unsigned int reserved80c;
    unsigned int device_in_endpoint_mask;
    unsigned int out_endpoint_mask;
    unsigned int all_endpoint_status;
    unsigned int all_endpoint_mask;
    unsigned char reserved820[20];
    unsigned int device_in_fifo_empty_mask;
    unsigned int reserved838;
    unsigned int each_endpoint_mask; /* DEACHINTMSK at 0x83c. */
    unsigned char reserved840[1472];
    unsigned int power_clock_gate;
} MediusDwc2CoreRegisters;


/* DWC2 device IN endpoint registers: base + 0x900 + endpoint * 0x20.
 * Offsets follow the primary CherryUSB DWC2 register declaration. MMIO members
 * are volatile so repeated reads remain inside polling/service loops.
 */
typedef struct Dwc2InEndpointRegisters {
    volatile unsigned int control;          /* 0x00: DIEPCTL */
    unsigned int reserved04;
    volatile unsigned int interrupt_status; /* 0x08: DIEPINT */
    unsigned int reserved0c;
    volatile unsigned int transfer_size;    /* 0x10: DIEPTSIZ */
    volatile unsigned int dma_address;      /* 0x14: DIEPDMA */
    volatile unsigned int fifo_space;       /* 0x18: DTXFSTS, low 16 bits are words */
    unsigned int reserved1c;
} Dwc2InEndpointRegisters;


/* DWC2 OUT endpoint registers, controller+0xb00+index*0x20.
 * Verified against native accesses and primary CherryUSB usb_dwc2_reg.h. */
typedef struct MediusDwc2OutEndpointRegisters {
    volatile unsigned int control;
    unsigned int reserved04;
    volatile unsigned int interrupt_status;
    unsigned int reserved0c;
    volatile unsigned int transfer_size;
    volatile unsigned int dma_address;
    unsigned int reserved18[2];
} MediusDwc2OutEndpointRegisters;

typedef struct {
     unsigned char entries[16];
    unsigned char count;

} MediusEndpointQueue;

typedef struct {
     unsigned char address;
    unsigned char multiplier;
    unsigned short max_packet;
    unsigned int unknown4;
    void (*complete)(unsigned char bus, unsigned char endpoint, unsigned int bytes);

} MediusUsbEndpointMetadata;

typedef MediusUsbEndpointMetadata MediusUsbEndpointMetadataTable[16];

/* Seven endpoint-descriptor bytes; native MPS reads are high then low. */
typedef struct {
    unsigned char length;
    unsigned char descriptor_type;
    unsigned char address;
    unsigned char attributes;
    unsigned char max_packet_low;
    unsigned char max_packet_high;
    unsigned char interval;
} MediusUsbEndpointDescriptor;


typedef void (*MediusUsbEndpointCompletion)(unsigned char bus,
                                           unsigned char endpoint,
                                           unsigned int bytes);
/* CherryUSB registration object, distinct from the 12-byte metadata table. */
typedef struct {
    unsigned char address;
    unsigned char padding1[3];
    MediusUsbEndpointCompletion complete;       /* 0x04 */
} MediusUsbEndpointRegistration;

/* Eight-byte clone record; this consumer does not interpret bytes 4..7. */
typedef struct {
    unsigned char address;
    unsigned char transfer_type;
    unsigned short max_packet;
    unsigned char uninterpreted4[4];
} MediusCloneVendorEndpoint;


typedef struct {
     unsigned char endpoint;
    unsigned char unknown1;
    unsigned short max_packet;
    unsigned char state;
    unsigned char generation;
    unsigned char setup[8];
    unsigned short requested;
    unsigned short actual;
    unsigned char direction_in;
    unsigned char needs_zlp;

} MediusNonzeroControlState;

typedef MediusNonzeroControlState MediusNonzeroControlStates[2];

/* Eight-byte callback registrations, published in HID IN/OUT, vendor, then
 * paired control OUT/IN order. Callers supply valid live endpoint counts.
 */
#define USB_CLONE_HID_IN_REGISTRATIONS ((volatile MediusUsbEndpointRegistration *)0x3fccc8c0U)
#define USB_CLONE_HID_OUT_REGISTRATIONS ((volatile MediusUsbEndpointRegistration *)0x3fccc7d8U)
#define USB_CLONE_VENDOR_REGISTRATIONS ((volatile MediusUsbEndpointRegistration *)0x3fccbd4cU)
#define USB_CLONE_CONTROL_REGISTRATIONS ((volatile MediusUsbEndpointRegistration *)0x3fcc4c84U)

/* Assembly state requires only halfword alignment. Native starts/errors
 * store active/error together; completion clears the active byte alone. */
typedef struct ControlAssembly {
    unsigned char payload[2058];
    unsigned short total;
    unsigned short used;
    union {
        struct { unsigned char active,error; };
        unsigned short flags;
    };
} ControlAssembly;

typedef void (*FragmentCallback)(const unsigned char *fragment, unsigned short length, void *context);

typedef unsigned char MediusControlByte;

typedef unsigned short MediusControlCount;

typedef unsigned int MediusUsbResourceHandle;

/* PHY handle and I/O types shared with the recovered lifecycle below. */
typedef struct MediusUsbPhyContext *MediusUsbPhyHandle;
typedef struct MediusUsbPhyExtIoConfig MediusUsbPhyExtIoConfig;
typedef struct MediusUsbPhyOtgIoConfig MediusUsbPhyOtgIoConfig;

/* IDF usb_phy_config_t view verified against the native 24-byte argument.
 * controller/target/mode/speed have 32-bit enum representation on ESP32-S3.
 */
typedef struct MediusUsbPhyConfig {
    int controller;                         /* 0: 0 = OTG */
    int target;                             /* 4: 0 = internal PHY */
    int otg_mode;                           /* 8: 2 = device */
    int otg_speed;                          /* 12: 0 = default/undefined */
    union {
        const MediusUsbPhyExtIoConfig *external_io; /* 16 */
        const MediusUsbPhyExtIoConfig *external_io_configuration;
    };
    union {
        const MediusUsbPhyOtgIoConfig *otg_io; /* 20 */
        const MediusUsbPhyOtgIoConfig *otg_io_configuration;
    };
} MediusUsbPhyConfig;


/* Fixed RAM defaults are natively word-aligned at 0x3fcbcbf8. */
typedef unsigned char MediusDwc2ParameterBytes[64] __attribute__((aligned(4)));

typedef struct {
     unsigned int low;
    int high;

} MediusLinkActivityWords;

/* Four independent byte flags at 0x3fcd18b4; no atomic aggregate operation. */
typedef struct CloneHandoffFlags {
    unsigned char active;
    unsigned char retry;
    unsigned char dropped_while_busy;
    unsigned char busy;
} CloneHandoffFlags;


typedef struct {
     unsigned char *device;
    unsigned char *configuration;
    unsigned char *section_11;
    unsigned char *section_2;
    unsigned char *section_7;
    unsigned short device_length;
    unsigned short configuration_length;
    unsigned short section_11_length;
    unsigned short section_2_length;
    unsigned short section_7_length;
    unsigned char configuration_index;
    unsigned char reserved;

} MediusCloneSource;

/* Validated section16 cache:59 categories, two opaque words and borrowed records. */
typedef struct {
    unsigned char categories[59];
    unsigned char reserved59;
    volatile unsigned int word60;
    volatile unsigned int word64;
    unsigned char * volatile records;
    volatile unsigned short records_length;
    unsigned char reserved74[2];
} MediusCloneParsedMetadata;

/* Native raw metadata base3fccf444 permits the reviewed aligned word reads. */
typedef unsigned char MediusCloneRawMetadata[512] __attribute__((aligned(4)));

/* Shared words at0x3fcd1878. Startup clears seen/up with one16-bit store.
   Runtime updates and comparisons use distinct32-bit activity/timeout reads. */
typedef struct DeviceLinkMonitor {
    unsigned int timeout_low;
    unsigned int timeout_high;
    unsigned int activity_low;
    unsigned int activity_high;
    union {
        struct { unsigned char seen,up; };
        unsigned short seen_and_up;
    };
    unsigned char padding[2];
} DeviceLinkMonitor;

/* Recovery view of app_main's named stack state, not a firmware global
   layout. The native current_up slot is reused for the next iteration count. */
typedef struct DeviceMainLoopState {
    unsigned int configuration_result;
    unsigned int pending;
    unsigned int current_up;
    unsigned int previous_up;
    unsigned int iteration;
    unsigned long long detach_deadline;
    unsigned long long last_periodic;
    unsigned int generation;
    unsigned int request_count;
    unsigned int notification_threshold;
    unsigned int refresh;
    unsigned int last_refresh_iteration;
    unsigned long long now;
    unsigned int rising;
} DeviceMainLoopState;

/* Device application's cached diagnostics and clone/liveness handoff fields.
 * These are independent native accesses, not one atomic state structure. */
#define DEVICE_PSRAM_SETUP_LOCK (*(PortMuxWords *)0x3fcab518U)
#define DEVICE_LINK_MONITOR_LOCK (*(PortMuxWords *)0x3fcab520U)
#define DEVICE_CLONE_HANDOFF_LOCK (*(PortMuxWords *)0x3fcab528U)
#define DEVICE_CLONE_HANDOFF_FLAGS ((volatile CloneHandoffFlags *)0x3fcd18b4U)
#define DEVICE_CACHED_PSRAM_BYTES (*(volatile unsigned int *)0x3fcd0754U)
#define DEVICE_PSRAM_INIT_ERROR (*(volatile unsigned int *)0x3fcd0750U)
#define DEVICE_LOGGED_BOUNCE_COUNT (*(volatile unsigned int *)0x3fcd074cU)
#define DEVICE_HOST_PANIC_LOG ((volatile char *)0x3fcd0758U)
#define DEVICE_PROFILE_NOTICE_COUNT (*(volatile unsigned int *)0x3fcd07f8U)
#define DEVICE_STARTUP_LOG_EMITTED (*(volatile unsigned char *)0x3fcd07fcU)
#define DEVICE_STARTUP_BANNER ((char *)0x3fcd0800U)
#define DEVICE_CLONE_EVENT_QUEUE (*(RtosQueue *volatile *)0x3fcd1890U)
#define DEVICE_CACHED_CLONE_DIGEST ((unsigned char *)0x3fcd1894U)
#define DEVICE_REFRESH_REQUESTED (*(volatile unsigned char *)0x3fcd18b4U)
#define DEVICE_RETRY_FLAG ((unsigned char *)0x3fcd18b5U)
#define DEVICE_CLONE_ASSEMBLY ((CloneAssembly *)0x3fcd18b8U)
#define DEVICE_LINK_MONITOR ((volatile DeviceLinkMonitor *)0x3fcd1878U)
#define DEVICE_HOST_LOG_TAG ((const char *)0x3fcbce04U)
/* Native startup prepares a reboot-function pointer for this empty entry.
 * The callee neither consumes it nor registers/invokes a callback. */
void startup_reboot_callback_noop(void (*unused_callback)(void))
    __asm__("return_without_work_42020dec");


/* Consumer view of the1190-byte patch table. Record interpretation is delegated. */
typedef struct {
    unsigned char record_storage[1186];
    volatile unsigned char enabled;
    volatile unsigned char generation;
    unsigned char uninterpreted1188[2];
} MediusClonePatchTable;

typedef struct {
    unsigned char * volatile data;
    volatile unsigned int length;
} MediusCloneExtraDescriptor;


typedef struct {
     unsigned char *data;
    unsigned short capacity;
    unsigned short used;

} MediusReportArchive;

typedef unsigned char *MediusReportArchiveData;

typedef unsigned short MediusReportArchiveLength;

/* ESP-IDF interrupt allocator objects in this 32-bit Xtensa build.
 * Packed words retain the verified native bitfield layout without Ghidra C
 * bitfield INSERT artifacts. Vector source starts at byte4; a shared node
 * packs disabled/source into its first word. Sizes and pointers are 32-bit ABI.
 */
typedef void (*InterruptHandler)(void *argument);
int rtc_isr_register(InterruptHandler handler, void *handler_argument,
                     unsigned int status_mask, unsigned int flags);
typedef struct InterruptVector InterruptVector;
typedef struct SharedInterrupt SharedInterrupt;
typedef struct InterruptVector {
    union {
        unsigned int flags_cpu_intno;    /* flags bits0..15, CPU bit16, IRQ17..21 */
        struct {
            unsigned short flags_low16; /* native halfword writes at0x00 */
            unsigned short cpu_intno_high16;
        };
    };
    short source;                        /* 0x04; signed SDK source, non-shared */
    unsigned short source_padding;
    SharedInterrupt *shared_vec_info;     /* 0x08 */
    InterruptVector *next;                /* 0x0c */
} InterruptVector;                       /* 16 bytes */
typedef struct SharedInterrupt {
    unsigned int disabled_source;        /* 0x00: disabled bit0, signed source bits1..16;
                                           bits17..31 are unused padding. Decode source with
                                           (int)(word << 15) >> 16 on Xtensa. */
    volatile unsigned int *statusreg;     /* 0x04; NULL means no status filter */
    unsigned int statusmask;              /* 0x08 */
    InterruptHandler isr;                 /* 0x0c */
    void *argument;                       /* 0x10 */
    SharedInterrupt *next;                /* 0x14 */
} SharedInterrupt;                       /* 24 bytes */
typedef struct InterruptHandle {
    InterruptVector *vector_desc;        /* 0x00 */
    SharedInterrupt *shared_vector_desc;  /* 0x04; NULL for non-shared */
} InterruptHandle;                       /* 8 bytes */
/* Read-only per-interrupt table row: one priority/type and two CPU flag words. */
typedef struct CpuInterruptTableEntry {
    int priority;
    int type;
    unsigned int flags[2];
} CpuInterruptTableEntry;                 /* 16 bytes */

typedef struct CpuInterruptDescription {
    int priority;                         /* fixed Xtensa interrupt level */
    int type;                             /* level=0, edge=1, not-applicable=2 */
    unsigned int flags;                   /* special=1, reserved=2 */
} CpuInterruptDescription;                      /* 12 bytes */
typedef struct CpuIsrEntry {
    InterruptHandler handler;
    void *argument;
} CpuIsrEntry;                      /* 8 bytes */
typedef CpuIsrEntry CpuIsrTable[32][2];
typedef unsigned int CpuInterruptMasks[2];
typedef unsigned char CpuInterruptDisabledFlags[2];

typedef InterruptVector *InterruptVectorHead;

/* RTC interrupt callback node in this 32-bit ESP-IDF build. */
typedef struct RtcIsrHandler {
    unsigned int mask;                    /* 0x00; matched against one status snapshot */
    InterruptHandler handler;            /* 0x04; invoked with handler_arg */
    void *handler_arg;                    /* 0x08 */
    unsigned int flags;                   /* 0x0c; bit0 permits execution without cache */
    struct RtcIsrHandler *next;      /* 0x10 */
} RtcIsrHandler;                    /* 20 bytes, internal RAM allocation */
typedef RtcIsrHandler *RtcIsrListHead;
typedef InterruptHandle *RtcInterruptHandle;
typedef unsigned int RtcInterruptMask;
typedef int RtcInterruptCpu;
/* Dual-core portMUX: 8 bytes, verified at native offsets 0 and 4.
 * owner holds the full PRID (normally 0xcdcd or 0xabab), or 0xb33fffff
 * when free. count is recursion for this lock, not per-CPU nesting. */
typedef struct PortMux {
    unsigned int owner;                 /* +0x00 */
    unsigned int count;                 /* +0x04 */
} PortMux;
typedef PortMux PortMuxWords;

/* Contiguous interrupt-allocator state; flags retain raw byte values. */
typedef struct InterruptAllocatorState {
    volatile unsigned char non_iram_disabled[2];  /* +0 */
    unsigned char padding_2[2];
    volatile unsigned int saved_non_iram_enabled[2]; /* +4 */
    volatile unsigned int non_iram_mask[2];       /* +12 */
    InterruptVector *volatile vector_head;       /* +20 */
} InterruptAllocatorState;                 /* 24 bytes */
typedef struct RtcInterruptState {
    PortMuxWords lock;                      /* +0 */
    RtcIsrHandler *volatile handlers;       /* +8 */
    volatile int owner_cpu;                       /* +12 */
    volatile unsigned int saved_enables;          /* +16 */
    volatile unsigned int cache_safe_mask;        /* +20 */
} RtcInterruptState;                       /* 24 bytes */
#define INTERRUPT_ALLOCATOR_STATE ((InterruptAllocatorState *)0x3fcbda0cU)
#define INTERRUPT_ALLOCATOR_LOCK ((PortMuxWords *)0x3fcaa56cU)
#define RTC_INTERRUPT_STATE ((RtcInterruptState *)0x3fcabddcU)
#define RTC_ISR_HANDLE (*(InterruptHandle *volatile *)0x3fcbda50U)
#define CPU_ISR_TABLE ((volatile CpuIsrEntry (*)[2])0x3fcab598U)
#define CPU_INTERRUPT_DESCRIPTIONS ((const CpuInterruptTableEntry *)0x3c04612cU)
#define CPU_INTERRUPT_LEVELS ((const unsigned char *)0x3c047408U)
#define INTERRUPT_SOURCE_NAMES ((const char *const *)0x3c046930U)
#define INTERRUPT_ALLOCATION_FAILURE_FORMAT ((const char *)0x3c040fd8U)
void shared_intr_isr(void *argument);
int esp_intr_disable(InterruptHandle *handle);
void esp_intr_noniram_disable(void);
void esp_intr_noniram_enable(void);
unsigned int xt_ints_on(unsigned int mask);
void rtc_isr(void *argument);
void rtc_isr_noniram_disable(unsigned int cpu);
void rtc_isr_noniram_enable(unsigned int cpu);
void xt_unhandled_interrupt(void *argument);
void esp_crosscore_int_send(int cpu,unsigned int reason_mask);
void esp_crosscore_int_send_yield(int cpu);
void esp_crosscore_int_send_print_backtrace(int cpu);
void esp_crosscore_int_send_twdt_abort(int cpu);
int is_vect_desc_usable(InterruptVector *vector,int flags,int cpu,int forced_number);
InterruptVector *get_desc_for_int(int interrupt_number,int cpu);
int esp_intr_alloc_intrstatus(int source,int flags,unsigned int status_reg,
    unsigned int status_mask,InterruptHandler handler,void *argument,InterruptHandle **result);
void intr_free_for_current_cpu(InterruptHandle *handle);
void intr_free_for_other_cpu(void *argument);
void esp_cpu_intr_get_desc(int cpu,int interrupt_number,CpuInterruptDescription *description);
int esp_intr_get_cpu(InterruptHandle *handle);
int xt_int_has_handler(int interrupt_number,int cpu);
InterruptHandler xt_set_interrupt_handler(unsigned int interrupt_number,InterruptHandler handler,void *argument);
void xthal_set_intclear(unsigned int mask);
int esp_ipc_call_blocking(unsigned int cpu,IpcCallback callback,void *argument);
int esp_ipc_call_and_wait(unsigned int cpu_id,IpcCallback callback,
                          void *argument,unsigned int wait_for);

/* Accessed fields of this image's 84-byte FreeRTOS Queue_t allocation.
 * Queue storage pointers overlap semaphore owner/recursion state. Constructors
 * identify the static-allocation byte at +0x44; its alignment padding is retained. */
typedef struct RtosQueue {
    unsigned char *head;                        /* +0x00: NULL denotes mutex */
    unsigned char *write_to;                    /* +0x04 */
    union {
        struct {
            unsigned char *tail;                /* +0x08 */
            unsigned char *read_from;           /* +0x0c */
        } queue;
        struct {
            RtosTask *holder;              /* +0x08 */
            unsigned int recursion_count;        /* +0x0c */
        } semaphore;
    } storage;
    RtosList waiting_to_send;               /* +0x10 */
    RtosList waiting_to_receive;            /* +0x24 */
    volatile unsigned int messages_waiting;       /* +0x38 */
    unsigned int capacity;                       /* +0x3c: items, not bytes */
    unsigned int item_size;                      /* +0x40: bytes per item */
    unsigned char statically_allocated;          /* +0x44: 0 dynamic, 1 static */
    unsigned char padding_45[3];
    struct RtosQueue *set_container;         /* +0x48 */
    PortMuxWords lock;                     /* +0x4c */
} RtosQueue;

int prvCopyDataToQueue(RtosQueue *queue, const void *item, int position);
int prvNotifyQueueSetContainer(const RtosQueue *member);
int xQueueGiveFromISR(RtosQueue *queue, int *higher_priority_task_woken);
int xTaskPriorityDisinherit(RtosTask *mutex_holder);
int xTaskRemoveFromEventList(RtosList *event_list);
int xPortInIsrContext(void);
int xQueueReceive(RtosQueue *queue, void *item, unsigned int wait_ticks);
int xQueuePeek(RtosQueue *queue, void *item, unsigned int wait_ticks);
int xQueueSemaphoreTake(RtosQueue *queue, unsigned int wait_ticks);
int xTaskPriorityInherit(RtosTask *mutex_holder);
void vTaskPriorityDisinheritAfterTimeout(RtosTask *mutex_holder,
                                          unsigned int highest_waiter_priority);
RtosTask *pvTaskIncrementMutexHeldCount(void);
#define RTOS_PRIORITY_LEVELS 25U
void __assert_func(const char *file, int line, const char *function,
                     const char *expression) __attribute__((noreturn));

#define FUN_40385fa0 prvCopyDataToQueue
#define FUN_40386028 prvNotifyQueueSetContainer
#define FUN_40386498 xQueueGiveFromISR

enum QueueCopyPosition {
    QUEUE_SEND_TO_BACK = 0,
    QUEUE_SEND_TO_FRONT = 1,
    QUEUE_OVERWRITE = 2
};
enum SchedulerState {
    SCHEDULER_STATE_SUSPENDED = 0,
    SCHEDULER_STATE_NOT_STARTED = 1,
    SCHEDULER_STATE_RUNNING = 2
};
int xQueueGenericSend(RtosQueue *queue, const void *item,
                       unsigned int wait_ticks, int copy_position);
RtosQueue *xQueueGenericCreate(unsigned int capacity, unsigned int item_size);
RtosQueue *xQueueGenericCreateStatic(unsigned int capacity, unsigned int item_size,
                                           unsigned char *storage,
                                           RtosQueue *control);
RtosQueue *xQueueCreateMutex(void);
RtosQueue *xQueueCreateMutexStatic(unsigned char queue_type,
                                         RtosQueue *control);
int xQueueGenericSendFromISR(RtosQueue *queue, const void *item,
                              int *higher_priority_task_woken, int copy_position);
int xQueueReceiveFromISR(RtosQueue *queue, void *item,
                          int *higher_priority_task_woken);
void vQueueDelete(RtosQueue *queue);
void vPortFree(void *buffer);
#define FUN_40386380 xQueueCreateMutexStatic
#define FUN_403863e0 xQueueGenericSendFromISR
#define FUN_403867e8 xQueueReceiveFromISR
#define FUN_40386888 vQueueDelete
int xQueueGenericReset(RtosQueue *queue, int new_queue);
unsigned int uxQueueMessagesWaiting(RtosQueue *queue);
void vListInitialise(RtosList *list);
void *pvPortMalloc(unsigned int size);
void *heap_caps_malloc(unsigned int size, unsigned int caps);
#define MALLOC_CAP_8BIT 0x004U
#define MALLOC_CAP_INTERNAL 0x800U
#define PORTMUX_FREE_OWNER 0xb33fffffU
#define FUN_4038608c xQueueGenericReset
#define FUN_40386120 xQueueGenericCreateStatic
int xTaskGetSchedulerState(void);
void vTaskInternalSetTimeOutState(RtosTimeout *timeout);
void *pvTaskGetThreadLocalStoragePointer(RtosTask *task,int index);
int xTaskCheckForTimeOut(RtosTimeout *timeout, unsigned int *ticks_remaining);
void vTaskPlaceOnEventList(RtosList *event_list, unsigned int ticks_to_wait);
void esp_crosscore_int_send_yield(int core_id);
unsigned int _xtos_set_intlevel(int interrupt_level);
#define RTOS_SCHEDULER_RUNNING (*(volatile unsigned int *)0x3fcbda94U)
#define RTOS_SCHEDULER_SUSPEND_COUNTS ((volatile unsigned int *)0x3fcbda6cU)
typedef unsigned int MediusInterruptNesting[2];
/* ESP32-S3 RTC controller: enable, masked status and write-one-to-clear. */
#define RTC_INT_ENA (*(volatile unsigned int *)0x60008040U)
#define RTC_INT_ST  (*(volatile unsigned int *)0x60008048U)
#define RTC_INT_CLR (*(volatile unsigned int *)0x6000804cU)

#include <stdbool.h>
/* Native brownout configuration: five bytes, no hidden padding.
 * Flag fields are raw bytes; the HAL uses bit0 rather than bool conversion. */
typedef struct BrownoutConfig {
    unsigned char threshold;             /* 0x00: three-bit analog threshold code */
    unsigned char enabled;               /* 0x01 */
    unsigned char reset_enabled;         /* 0x02: hardware-reset enable */
    unsigned char flash_power_down;      /* 0x03 */
    unsigned char rf_power_down;          /* 0x04 */
} BrownoutConfig;
typedef unsigned int ResetReason;
#define CACHED_RESET_REASON (*(volatile ResetReason *)0x3fcbd7e8U)
void brownout_hal_config(const BrownoutConfig *configuration);
void esp_brownout_init(void);
void esp_reset_reason_init(void);
void rtc_brownout_isr_handler(void *unused_argument) __attribute__((noreturn));
void uart_tx_wait_idle(unsigned char uart); /* ROM 0x4000069c. */
typedef bool FlashStateFlag;
/* esp_rom_spiflash_chip_t and S3 legacy-data ABI. */
typedef struct RomFlashChip {
    unsigned int device_id;              /* JEDEC vendor in bits16..23 */
    unsigned int chip_size;
    unsigned int block_size;
    unsigned int sector_size;
    unsigned int page_size;
    unsigned int status_mask;
} RomFlashChip;
typedef struct RomFlashLegacy {
    RomFlashChip chip;              /* 0x00..0x17 */
    unsigned char dummy_len_plus[3];      /* 0x18..0x1a; SPI1 correction at0x19 */
    unsigned char sig_matrix;            /* 0x1b */
} RomFlashLegacy;
typedef RomFlashLegacy *RomFlashLegacyPointer;
typedef unsigned int LogDefaultLevel;
#define MMIO32(address) (*(volatile unsigned int *)(address))
#define RTC_RESET_HINT MMIO32(0x600080c8U)
#define RTC_BROWNOUT_REGISTER MMIO32(0x600080e8U)
#define RTC_FIB_SELECT_REGISTER MMIO32(0x60008148U)
#define RTC_OPTIONS0_REGISTER MMIO32(0x60008000U)
#define RTC_CPU_STALL_REGISTER MMIO32(0x600080bcU)
#define SYSTEM_CLOCK_ENABLE0 MMIO32(0x600c0018U)
#define SYSTEM_RESET_ENABLE0 MMIO32(0x600c0020U)
#define SYSTEM_RESET_ENABLE1 MMIO32(0x600c0024U)
#define SYSTEM_EDMA_CONTROL MMIO32(0x600c0044U)
#define SYSTEM_CORE_RESET_ENABLE MMIO32(0x60026018U)

/* ESP-IDF application flash OS context, 16 bytes. Time fields are low32 us. */
typedef struct FlashOsContext {
    void *device_lock;                    /* 0x00; unused on this SPI1 cache-lock path */
    union {
        struct {
            bool no_protect;              /* 0x04; bypass main-image safety check only */
            unsigned char padding[3];
        };
        unsigned int protection_word;    /* Native startup clears all four bytes. */
    };
    unsigned int acquired_since_us;       /* 0x08; last explicit/implicit yield */
    unsigned int released_since_us;       /* 0x0c; last operation end */
} FlashOsContext;
/* Loaded main-flash OS callback table. Context pointers are refined to this
 * build's concrete application context; every entry still uses the SDK ABI. */
typedef struct MainFlashOsFunctions {
    int (*start)(FlashOsContext *context);
    int (*end)(FlashOsContext *context);
    int (*region_protected)(FlashOsContext *context, unsigned int address, unsigned int size);
    int (*delay_us)(void *unused, unsigned int microseconds);
    void *(*get_temp_buffer)(void *unused, unsigned int requested_size, unsigned int *actual_size);
    void (*release_temp_buffer)(void *unused, void *buffer);
    int (*check_yield)(FlashOsContext *context, unsigned int chip_status, unsigned int *request);
    int (*yield)(FlashOsContext *context, unsigned int *unused_status);
    long long (*get_system_time)(void *context); /* NULL in the loaded table */
    void (*set_flash_op_status)(unsigned int flags);
} MainFlashOsFunctions;              /* 40 bytes */
typedef struct MultiHeapInfo {
    unsigned int total_free_bytes;
    unsigned int total_allocated_bytes;
    unsigned int largest_free_block;
    unsigned int minimum_free_bytes;
    unsigned int allocated_blocks;
    unsigned int free_blocks;
    unsigned int total_blocks;
} MultiHeapInfo;                     /* 28 bytes */
typedef long long MediusSystemTimeCorrection;
typedef void *FlashOperationMutex;
typedef volatile bool FlashHandshakeFlag;
typedef volatile int FlashOwnerCpu;

/* ROM pointer slot and application flash state, bound to native literals.
 * Handshake flags are bytes; the owner CPU marker is a signed word (-1 idle).
 */
#define rom_spiflash_legacy_data (*(RomFlashLegacy *volatile *)0x3fceffe4U)
#define s_flash_op_cpu (*(FlashOwnerCpu *)0x3fcab9fcU)
#define s_flash_op_complete (*(FlashHandshakeFlag *)0x3fcd865aU)
#define s_flash_op_can_start (*(FlashHandshakeFlag *)0x3fcd865bU)
#define s_flash_op_mutex (*(FlashOperationMutex *)0x3fcd865cU)
#define flash_brownout_needs_reset (*(volatile FlashStateFlag *)0x3fcd8659U)
#define flash_erasing (*(volatile FlashStateFlag *)0x3fcd8658U)

unsigned int bootloader_flash_execute_command_common(unsigned char command,
    unsigned int address_bits,unsigned int address,unsigned char dummy_bits,
    unsigned char mosi_bits,unsigned int mosi_data,unsigned char miso_bits);
unsigned int bootloader_read_flash_id(void);
int bootloader_flash_reset_chip(void);
void spi_flash_disable_cache(void);
void spi_flash_op_block_func(void *unused_cpu_argument);
void spi_flash_disable_interrupts_caches_and_other_cpu(void);
void spi_flash_enable_interrupts_caches_and_other_cpu(void);
int spi_flash_os_yield(FlashOsContext *context,unsigned int *unused_status);
int spi_flash_os_check_yield(FlashOsContext *context,unsigned int chip_status,
    unsigned int *request);
int flash_os_delay_us(void *unused,unsigned int microseconds);
void main_flash_op_status(unsigned int flags);
int main_flash_region_protected(FlashOsContext *context,unsigned int address,
    unsigned int size);
void flash_os_cache_disable(void);
void flash_os_cache_enable(void);
int spi1_start(FlashOsContext *unused_context);
int spi1_end(FlashOsContext *context);
void spi_flash_needs_reset_check(void);
void spi_flash_set_erasing_flag(bool erasing);
bool spi_flash_brownout_need_reset(void);
void flash_update_rom_chip_id(void);
void spi_flash_init_lock(void);
void spi_flash_op_lock(void);
void spi_flash_op_unlock(void);
int esp_ipc_call_nonblocking(unsigned int cpu_id,IpcCallback callback,void *argument);
int xTaskResumeAll(void);

/* ESP32-S3 has one cache level. DATA=0, INSTRUCTION=1, ALL=2. */
typedef enum CacheType {
    CACHE_TYPE_DATA = 0,
    CACHE_TYPE_INSTRUCTION = 1,
    CACHE_TYPE_ALL = 2
} CacheType;
/* CACHE_LL_ENABLE_DISABLE_STATE_SW is false for this S3 implementation. */
typedef struct CacheHalLevelState {
    bool instruction_autoload_enabled;
    bool data_autoload_enabled;
} CacheHalLevelState;                 /* 2 bytes */
typedef struct CacheHalContext {
    CacheHalLevelState l1;
    CacheHalLevelState l2;             /* retained SDK context slot */
} CacheHalContext;                    /* 4 bytes */
typedef volatile unsigned int CacheStateRegister;
#define EXTMEM_CACHE_STATE (*(volatile unsigned int *)0x600c4130U)

/* TLSF revision 2867f6883a12920b1969ff9624c0ab0e4185c2ce, 32-bit layout.
 * Only the size word is overhead for an allocated block. The previous-physical
 * pointer overlaps the previous block; the free-list links occupy free payload.
 */
typedef struct TlsfBlock {
    struct TlsfBlock *previous_physical;
    unsigned int size_flags;              /* size & ~3; free bit0, previous-free bit1 */
    struct TlsfBlock *next_free;
    struct TlsfBlock *previous_free;
} TlsfBlock;                         /* 16 bytes; payload begins at +8 */
typedef struct TlsfControl {
    TlsfBlock null_block;            /* 0x00 */
    unsigned int configuration;           /* 0x10, packed SDK bitfields below */
    unsigned int metadata_size;           /* 0x14: control + bitmaps + free-list heads */
    unsigned int first_level_bitmap;      /* 0x18 */
    unsigned int *second_level_bitmaps;   /* 0x1c */
    TlsfBlock **free_lists;          /* 0x20 */
} TlsfControl;                       /* fixed control prefix: 36 bytes */
/* configuration: fl_count[4:0], fl_shift[7:5], fl_max[13:8],
 * sl_count[19:14], sl_log2[22:20], small_block_size[30:23].
 * Bit31 is padding retained from the incoming storage by tlsf_create.
 * Construction leaves null_block.previous_physical and size_flags untouched.
 * The two dynamic tables follow this prefix: fl_count bitmap WORDs, then
 * fl_count * sl_count free-list pointer WORDs. metadata_size includes both.
 * Store configuration as one word to retain the native masking operations.
 */
typedef bool (*TlsfWalker)(void *payload, unsigned int size, int used, void *user);

/* Raw-byte view of the existing cache HAL context's first two bytes. Unlike
   a C bool view, this retains the native shift of a noncanonical byte. */
typedef struct CacheHalRawAutoloadState {
    unsigned char instruction_autoload_enabled;
    unsigned char data_autoload_enabled;
} CacheHalRawAutoloadState;

/* EXTMEM register prefix at 0x600c4000. Only CTRL1 words are used here. */
typedef struct CacheBusControlRegisters {
    unsigned int dcache_control;
    unsigned int dcache_bus_control;       /* +0x04, EXTMEM_DCACHE_CTRL1 */
    unsigned int unmodeled08[23];
    unsigned int icache_bus_control;       /* +0x64, EXTMEM_ICACHE_CTRL1 */
} CacheBusControlRegisters;

/* ROM entries: 0x4000186c, 0x40001878, 0x40001884 and 0x40001890. */
unsigned int Cache_Disable_ICache(void);
void Cache_Enable_ICache(unsigned int autoload);
unsigned int Cache_Disable_DCache(void);
void Cache_Enable_DCache(unsigned int autoload);
void cache_hal_disable(unsigned int cache_level, CacheType cache_type);
void cache_hal_enable(unsigned int cache_level, CacheType cache_type);
void do_multicore_settings(void);

/* Saved cache HAL autoload bytes at the native application address. */
#define CACHE_AUTOLOAD_STATE (*(volatile CacheHalRawAutoloadState *)0x3fcbd8f0U)
#define CACHE_HAL_CONTEXT (*(volatile CacheHalContext *)0x3fcbd8f0U)
#define CACHE_DATA_AUTOLOAD_CONTROL MMIO32(0x600c404cU)
#define CACHE_INSTRUCTION_AUTOLOAD_CONTROL MMIO32(0x600c40a0U)
void s_cache_hal_init_ctx(void);
void cache_hal_init(void);
#define FUN_403890d4 s_cache_hal_init_ctx
#define FUN_40389110 cache_hal_init

/* Native primary-boot objects. Raw flag bytes retain their full BYTE semantics. */
typedef struct BootChipInfo {
    int model;
    unsigned int features;
    unsigned short revision;
    unsigned char cores,reserved11;
} BootChipInfo;
typedef struct BootMemoryProtectionConfiguration {
    unsigned char invoke_panic_handler,lock_feature;
    unsigned char reserved2[2];
    void *split_address;
    unsigned int memory_type_mask,target_cpu_count;
    int target_cpu[2];
} BootMemoryProtectionConfiguration;
typedef union BootImageHeader {
    unsigned int words[6];
    struct {
        unsigned char magic;
        unsigned char remaining_header_bytes[23]; /* copied, unused by this body */
    };
} BootImageHeader;
typedef struct BootTimestamp {unsigned int low,high;} BootTimestamp;
#define BOOT_BSS_START ((void *)0x3fcbd7b8U)
#define BOOT_BSS_LENGTH 0x1b0a0U
#define BOOT_PROTECTION_DEFAULTS ((const BootMemoryProtectionConfiguration *)0x3c045dd4U)
#define BOOT_TIMESTAMP (*(volatile BootTimestamp *)0x3fcbd808U)
#define BOOT_CORE1_CONTROL MMIO32(0x600c0000U)
#define PSRAM_INITIALIZED (*(volatile unsigned char *)0x3fcbde90U)
void firmware_entry(void);
void esp_chip_info(BootChipInfo *information);
void mspi_timing_flash_tuning(void);
unsigned char esp_psram_is_initialized(void);
/* Linked dependency boundaries; their own bodies retain separate review state. */
void esp_rtc_init(void);
#define FUN_42002b00 esp_rtc_init
void esp_clk_init(void);
#define FUN_42002b34 esp_clk_init
void esp_perip_clk_init(void);
#define FUN_42002c30 esp_perip_clk_init
void esp_deep_sleep_wakeup_io_reset(void);
int esp_mprot_is_conf_locked_any(unsigned char *locked);
int esp_mprot_set_prot(const BootMemoryProtectionConfiguration *configuration);
const char *esp_err_to_name(int error) __asm__("FUN_42003bfc");
int esp_psram_init(void) __asm__("FUN_4200812c");
int esp_psram_extram_test(void) __asm__("FUN_420083d0"); /* native full-WORD result */
int rtc_get_reset_reason(int core); /* ROM4000057c */
void flash_update_rom_chip_id(void);
unsigned int Cache_Suspend_ICache(void);
unsigned int Cache_Suspend_DCache(void);
unsigned int rom_Cache_Suspend_ICache(void); /* ROM4000189c */
unsigned int rom_Cache_Suspend_DCache(void); /* ROM400018b4 */
void Cache_Resume_ICache(unsigned int autoload); /* ROM400018a8 */
void Cache_Resume_DCache(unsigned int autoload); /* ROM400018c0 */
void rom_config_instruction_cache_mode(unsigned int size,unsigned char ways,unsigned char line_size);
void rom_config_data_cache_mode(unsigned int size,unsigned char ways,unsigned char line_size);
void Cache_Set_IDROM_MMU_Size(unsigned int instruction_bytes,unsigned int data_bytes);
void Cache_Set_IDROM_MMU_Info(unsigned int instruction_entries,unsigned int data_entries,
    unsigned int rodata_start,unsigned int rodata_end,int instruction_psram_offset,int rodata_psram_offset);
#define FUN_42005548 esp_chip_info
#define FUN_4038456c mspi_timing_flash_tuning
#define FUN_403771b4 esp_psram_is_initialized

/* Address-name compatibility for existing recovered callers. */
#define FUN_4038919c cache_hal_disable
#define FUN_403891c4 cache_hal_enable
#define FUN_40375740 do_multicore_settings

typedef void (*RomPutc)(char character);
typedef void (*SystemStartupFunction)(void);

/* Shared startup flags: only the named bytes are accessed by this group. */
typedef struct CpuStartupFlags {
    unsigned char resume_cores;
    unsigned char reserved1[3];
    unsigned char initialized[2];
    unsigned char reserved6[2];
    unsigned char up[2];
} CpuStartupFlags;

/* EXTMEM error-event registers. CLEAR receives the native read/OR/write;
   this declaration does not simulate its hardware write-one-to-clear effect. */
typedef struct CacheErrorEventRegisters {
    unsigned int enable;
    unsigned int clear;
    unsigned int status;
} CacheErrorEventRegisters;
typedef struct CacheErrorRegisters {
    CacheErrorEventRegisters illegal;
    CacheErrorEventRegisters core[2];
} CacheErrorRegisters;

void call_start_cpu1(void);
void bootloader_init_mem(void);
void esp_cpu_configure_region_protection(void);
void esp_cache_err_int_init(void);
void esp_rom_install_channel_putc(int channel, RomPutc putc);
void esp_rom_install_uart_printf(void);
void ets_install_putc1(RomPutc putc);
void ets_install_putc2(RomPutc putc);
void ets_install_uart_printf(void);
void ets_write_char_uart(char character);
void ets_set_appcpu_boot_addr(unsigned int address);
void esp_rom_delay_us(unsigned int microseconds);
void uart_tx_switch(unsigned char uart_number);
void intr_matrix_set(int core, int source, int interrupt_number);
void esp_intr_disable_source(unsigned int interrupt_number);
void esp_intr_enable_source(unsigned int interrupt_number);

#define CPU_STARTUP_FLAGS (*(volatile CpuStartupFlags *)0x3fcbd7dcU)
#define SYSTEM_STARTUP_FUNCTIONS ((const SystemStartupFunction *)0x3c045e18U)
#define ROM_PUTC1_CACHE (*(RomPutc volatile *)0x3fcaa548U)
#define ROM_PUTC2_CACHE (*(RomPutc volatile *)0x3fcbd8ecU)

/* Address-name compatibility for existing recovered startup callers. */
#define FUN_40375694 call_start_cpu1
#define FUN_4200f534 bootloader_init_mem
#define FUN_40385f64 esp_rom_install_channel_putc
#define FUN_42002e98 esp_cache_err_int_init
#define FUN_420116a4 esp_cpu_configure_region_protection

/* ESP32-S3 MPU permissions; RO/WO variants are not compiled for this target. */
typedef enum MpuAccess {
    MPU_REGION_ILLEGAL = 0,
    MPU_REGION_RW = 1,
    MPU_REGION_X = 2,
    MPU_REGION_RWX = 3
} MpuAccess;
void mpu_hal_set_region_access(int region, MpuAccess access);

#define ILLEGAL_MPU_REGIONS ((const unsigned int *)0x3c04712cU)

#define FUN_42021330 mpu_hal_set_region_access

typedef int (*SystemInitFunction)(void);
typedef struct SystemInitEntry {
    SystemInitFunction function;
    unsigned short core_mask;
    unsigned short stage;
} SystemInitEntry;
void do_system_init_fn(unsigned int stage);
int system_init_stage_zero_noop(void) __asm__("FUN_42020bd4");
int system_init_stage_one_noop(void) __asm__("FUN_42020ca0");
void xt_highint4(void) __asm__("FUN_40375bd0");
void start_cpu_other_cores_default(void) __attribute__((noreturn));
void esp_startup_start_app_other_cores(void);

#define SYSTEM_INIT_ENTRIES ((const volatile SystemInitEntry *)0x3c0481ccU)
#define SYSTEM_CORE_INITIALIZED ((volatile unsigned char *)0x3fcbd800U)
#define SYSTEM_FULL_INITIALIZED (*(volatile unsigned char *)0x3fcbd7fdU)
#define SYSTEM_EARLY_LOG_LEVEL (*(volatile unsigned int *)0x3fcaa550U)

/* Native address aliases, including the resolved startup weak alias. */
#define FUN_420032a4 do_system_init_fn
#define FUN_40375fbc start_cpu_other_cores_default
#define start_cpu_other_cores start_cpu_other_cores_default
#define FUN_420243bc esp_startup_start_app_other_cores

typedef void (*FreertosTickHook)(void);
typedef unsigned int CrosscoreReasonMask;
void esp_int_wdt_cpu_init(void);
void esp_crosscore_int_init(void);
int esp_register_freertos_tick_hook_for_cpu(FreertosTickHook hook, unsigned int core);
void esp_int_wdt_tick_hook(void);
void esp_crosscore_isr(void *reason_word);

#define SCHEDULER_RUNNING ((volatile unsigned int *)0x3fcbdd44U)
#define CROSSCORE_REASONS ((volatile CrosscoreReasonMask *)0x3fcd8670U)
#define CROSSCORE_REASON_LOCK ((PortMuxWords *)0x3fcaba64U)

/* Native address aliases; the app-start alias was defined above. */
#define FUN_4200300c esp_int_wdt_cpu_init
#define FUN_42010900 esp_crosscore_int_init
#define FUN_40375f3c esp_int_wdt_tick_hook
#define FUN_42003b70 esp_register_freertos_tick_hook_for_cpu
#define FUN_4037eb48 esp_crosscore_isr

/* ROM watchdog HAL ABI: instance word followed by a register pointer.
 * Register blocks are opaque here; these callbacks delegate access to ROM. */
typedef enum WatchdogInstance {
    WDT_RWDT = 0,
    WDT_MWDT0 = 1,
    WDT_MWDT1 = 2
} WatchdogInstance;
typedef enum WatchdogStage {
    WDT_STAGE0 = 0,
    WDT_STAGE1 = 1,
    WDT_STAGE2 = 2,
    WDT_STAGE3 = 3
} WatchdogStage;
typedef enum WatchdogStageAction {
    WDT_STAGE_ACTION_OFF = 0,
    WDT_STAGE_ACTION_INT = 1,
    WDT_STAGE_ACTION_RESET_CPU = 2,
    WDT_STAGE_ACTION_RESET_SYSTEM = 3,
    WDT_STAGE_ACTION_RESET_RTC = 4
} WatchdogStageAction;
typedef struct TimerGroupRegisters TimerGroupRegisters;
typedef struct RtcWatchdogRegisters RtcWatchdogRegisters;
typedef struct WatchdogHalContext {
    WatchdogInstance instance;
    union {
        TimerGroupRegisters *mwdt_registers;
        RtcWatchdogRegisters *rwdt_registers;
    };
} WatchdogHalContext;
typedef FreertosTickHook FreertosTickHookSlots[8];
typedef FreertosTickHookSlots FreertosTickHookTable[2];
void wdt_hal_write_protect_disable(WatchdogHalContext *context);
void wdt_hal_write_protect_enable(WatchdogHalContext *context);
void wdt_hal_config_stage(WatchdogHalContext *context, WatchdogStage stage,
    unsigned int timeout_ticks, WatchdogStageAction action);
void wdt_hal_feed(WatchdogHalContext *context);
int esp_backtrace_print(int depth);
/* Native low-BYTE truth test; SDK callers supply bool 0/1. */
void task_wdt_timeout_abort(unsigned char current_core_received_timeout);

#define INTERRUPT_WATCHDOG_CPU1_TICKED (*(volatile unsigned char *)0x3fcbd7ecU)
#define INTERRUPT_WATCHDOG_CONTEXT ((WatchdogHalContext *)0x3fcbd7f0U)
#define FREERTOS_TICK_HOOKS (*(volatile FreertosTickHookTable *)0x3fcbd86cU)
#define CPU_INTERRUPT_FROM_CPU ((volatile unsigned int *)0x600c0030U)

/* Identified direct dependencies; their own body reviews follow separately. */
#define FUN_403762f8 esp_backtrace_print
#define FUN_42010af8 task_wdt_timeout_abort

typedef void (*ApbBackupLockCallback)(void);
void apb_backup_dma_lock(void);
void apb_backup_dma_unlock(void);
void esp_apb_backup_dma_lock_init(void);
void ets_apb_backup_init_lock_func(ApbBackupLockCallback lock,
    ApbBackupLockCallback unlock);

#define APB_BACKUP_DMA_MUX (*(PortMuxWords *)0x3fcaa51cU)

#define FUN_40375f18 apb_backup_dma_unlock
#define FUN_40375f28 apb_backup_dma_lock
#define FUN_42002f54 esp_apb_backup_dma_lock_init

void start_cpu0_default(void);
void startup_resume_other_cores(void);
void esp_startup_start_app(void);

#define GLOBAL_CONSTRUCTORS ((SystemStartupFunction const *)0x3c048188U)

#define FUN_42003310 start_cpu0_default
#define FUN_420029dc startup_resume_other_cores
#define FUN_42024370 esp_startup_start_app

/* Register prefixes used by watchdog startup; unrelated words are unmodeled. */
typedef struct SystemClockRegistersPrefix {
    unsigned int unmodeled_00[6];
    unsigned int peripheral_clock_enable0; /* +0x18 */
    unsigned int unmodeled_1c;
    unsigned int peripheral_reset_enable0; /* +0x20 */
} SystemClockRegistersPrefix;
typedef struct TimerGroupWatchdogRegistersPrefix {
    unsigned int unmodeled_00[18];
    unsigned int watchdog_config0; /* +0x48 */
} TimerGroupWatchdogRegistersPrefix;
void esp_int_wdt_init(void);
void wdt_hal_init(WatchdogHalContext *context, WatchdogInstance instance,
    unsigned int prescaler, bool enable_interrupt);
void wdt_hal_enable(WatchdogHalContext *context);
unsigned char periph_rcc_acquire_enter(int peripheral);
void periph_rcc_acquire_exit(int peripheral, unsigned char reference_count);

#define WATCHDOG_SYSTEM_CLOCK_REGISTERS ((volatile SystemClockRegistersPrefix *)0x600c0000U)
#define WATCHDOG_TIMER_GROUP1_REGISTERS ((volatile TimerGroupWatchdogRegistersPrefix *)0x60020000U)

#define FUN_42002f68 esp_int_wdt_init

typedef bool (*FreertosIdleHook)(void);
typedef FreertosIdleHook FreertosIdleHookSlots[8];
typedef FreertosIdleHookSlots FreertosIdleHookTable[2];
bool other_cpu_startup_idle_hook_cb(void);
int esp_register_freertos_idle_hook_for_cpu(FreertosIdleHook hook,
    unsigned int core);
void esp_deregister_freertos_idle_hook_for_cpu(FreertosIdleHook hook,
    unsigned int core);

#define OTHER_CPU_STARTUP_DONE (*(volatile unsigned char *)0x3fcbda68U)
#define FREERTOS_IDLE_HOOKS (*(volatile FreertosIdleHookTable *)0x3fcbd8acU)
/* Idle and tick registries share this same mux. */
#define FREERTOS_HOOKS_LOCK ((PortMuxWords *)0x3fcaa540U)

#define FUN_420242a4 other_cpu_startup_idle_hook_cb
#define FUN_42003b1c esp_register_freertos_idle_hook_for_cpu
#define FUN_42003bc4 esp_deregister_freertos_idle_hook_for_cpu

/* ESP-IDF task-watchdog configuration copied as three native words.
 * The explicit tail bytes retain this firmware's initialized padding. */
typedef struct TaskWatchdogConfig {
    unsigned int timeout_ms;       /* +0x00 */
    unsigned int idle_core_mask;   /* +0x04 */
    bool trigger_panic;            /* +0x08 */
    unsigned char reserved9[3];    /* +0x09: all zero in the startup template */
} TaskWatchdogConfig;
void main_task(void *unused_argument);
void app_main(void);
void heap_caps_enable_nonos_stack_heaps(void);
int esp_task_wdt_init(const TaskWatchdogConfig *configuration);

#define FUN_42003f8c heap_caps_enable_nonos_stack_heaps

MultiHeap *multi_heap_register(void *start, unsigned int bytes);
void multi_heap_set_lock(MultiHeap *heap, void *lock);

#define REGISTERED_HEAPS (*(RegisteredHeapPointer *)0x3fcbda08U)

/* ESP-IDF task-watchdog state; offsets verified in both application images.
 * Flags use their byte storage type so reconstruction preserves every native
 * byte value without imposing the C bool representation on firmware memory. */
typedef struct TaskWatchdogEntry TaskWatchdogEntry;
typedef void *TaskWatchdogTimerContext;
typedef void (*TaskWatchdogIsr)(void *argument);

typedef struct TaskWatchdogState {
    TaskWatchdogTimerContext timer_context; /* +0x00: opaque timer backend */
    TaskWatchdogEntry *entries;             /* +0x04: subscription list head */
    unsigned int idle_core_mask;            /* +0x08 */
    unsigned char panic;                    /* +0x0c: copied configuration byte */
    unsigned char waiting_for_task;         /* +0x0d: timer has no subscribers */
    unsigned char padding14[2];             /* +0x0e: zero from calloc */
} TaskWatchdogState;

int esp_task_wdt_impl_timer_allocate(const TaskWatchdogConfig *configuration,
                                   TaskWatchdogIsr callback,
                                   TaskWatchdogTimerContext *context_out);
int esp_task_wdt_impl_timer_restart(TaskWatchdogTimerContext context);
void task_wdt_isr(void *argument);
void subscribe_idle(unsigned int core_mask);

#define TASK_WATCHDOG_STATE (*(TaskWatchdogState **)0x3fcd8678U)

typedef struct TaskWatchdogHardwareContext {
    WatchdogHalContext hal;        /* +0x00: 8-byte timer-group HAL context */
    InterruptHandle *interrupt_handle; /* +0x08: esp_intr_alloc output */
} TaskWatchdogHardwareContext;

RtosTask *xTaskGetIdleTaskHandleForCore(int core_id);
int esp_task_wdt_add(RtosTask *task);
bool task_wdt_idle_hook_cb(void);

#define FUN_42010bf0 subscribe_idle
#define FUN_42011188 esp_task_wdt_impl_timer_restart
#define FUN_42010dfc task_wdt_idle_hook_cb

int esp_intr_alloc(int source, int flags, InterruptHandler callback,
                   void *argument, InterruptHandle **handle_out);

#define TASK_WATCHDOG_HARDWARE_CONTEXT ((TaskWatchdogHardwareContext *)0x3fcd8680U)
#define WATCHDOG_SYSTEM_CLOCK_ENABLE (*(volatile unsigned int *)0x600c0018U)
#define WATCHDOG_SYSTEM_RESET (*(volatile unsigned int *)0x600c0020U)
#define TIMER_GROUP0_WATCHDOG_CONFIGURATION0 (*(volatile unsigned int *)0x6001f048U)
#define FUN_42011078 esp_task_wdt_impl_timer_allocate

int esp_task_wdt_reset(void);
int esp_task_wdt_impl_timer_feed(TaskWatchdogTimerContext context);
void esp_task_wdt_impl_timeout_triggered(TaskWatchdogTimerContext context);
void wdt_hal_handle_intr(WatchdogHalContext *context);

#define FUN_42011140 esp_task_wdt_impl_timer_feed
#define FUN_42011168 esp_task_wdt_impl_timeout_triggered

/* Subscription node. Byte storage preserves the native flag representation. */
struct TaskWatchdogEntry {
    TaskWatchdogEntry *next;       /* +0x00 */
    RtosTask *task;           /* +0x04: NULL for a user subscription */
    const char *user_name;          /* +0x08: NULL for a task subscription */
    unsigned char has_reset;       /* +0x0c: normal values are 0 and 1 */
    unsigned char padding13[3];    /* +0x0d: zeroed on allocation */
};

/* Native full-WORD truth test; SDK callers supply bool 0/1. */
int task_wdt_add_entry(unsigned int is_task, void *entry_data,
                          TaskWatchdogEntry **entry_out);
int xPortEnterCriticalTimeout(PortMuxWords *lock, int timeout_cycles);
void vPortExitCritical(PortMuxWords *lock);

/* Newlib lock slots contain a 32-bit FreeRTOS mutex handle. Retargetable
 * locking passes the handle by value and takes a local slot when needed. */
struct __lock;
typedef struct __lock *NewlibLock;
#define MEDIUS_NEWLIB_INIT_LOCK ((PortMuxWords *)0x3fcaa628U)
#define MEDIUS_NEWLIB_COMMON_MUTEX ((NewlibLock)0x3fcbddb4U)
#define MEDIUS_NEWLIB_COMMON_RECURSIVE_MUTEX ((NewlibLock)0x3fcbdd60U)
#define MEDIUS_NEWLIB_ROM_MUTEX_MAGIC 0xbb10c433U
RtosTask *xQueueGetMutexHolder(RtosQueue *queue);
int xQueueGiveMutexRecursive(RtosQueue *mutex);
int xQueueTakeMutexRecursive(RtosQueue *mutex,unsigned int wait_ticks);
int lock_acquire_generic(NewlibLock *lock,unsigned int wait_ticks,unsigned int mutex_type);
void lock_release_generic(NewlibLock *lock,unsigned int mutex_type);
void _lock_close(NewlibLock *lock);
void _lock_acquire(NewlibLock *lock);
void _lock_release(NewlibLock *lock);
void __retarget_lock_init(NewlibLock *lock);
void __retarget_lock_init_recursive(NewlibLock *lock);
void __retarget_lock_close(NewlibLock lock);
void __retarget_lock_close_recursive(NewlibLock lock);
void __retarget_lock_acquire(NewlibLock lock);
void __retarget_lock_acquire_recursive(NewlibLock lock);
int __retarget_lock_try_acquire(NewlibLock lock);
int __retarget_lock_try_acquire_recursive(NewlibLock lock);
void __retarget_lock_release(NewlibLock lock);
void __retarget_lock_release_recursive(NewlibLock lock);
/* Address aliases for caller bodies awaiting typed review. */
#define FUN_40376dcc lock_release_generic
#define FUN_40376e20 _lock_close
#define FUN_40376ea8 __retarget_lock_init
#define FUN_40376ed0 __retarget_lock_init_recursive
#define FUN_40376ef8 __retarget_lock_close
#define FUN_40376f08 __retarget_lock_close_recursive
#define FUN_40376f18 __retarget_lock_acquire
#define FUN_40376f44 __retarget_lock_acquire_recursive
#define FUN_40376f70 __retarget_lock_try_acquire
#define FUN_40376fa0 __retarget_lock_try_acquire_recursive
#define FUN_40376fd0 __retarget_lock_release
#define FUN_40376ff0 __retarget_lock_release_recursive
#define FUN_403861d8 xQueueGetMutexHolder
void vPortTCBPreDeleteHook(RtosTask *task);
/* Retained architectural entry points; yield returns when its task resumes. */
void vPortYield(void);
void vPortYieldFromInt(void);
bool esp_ptr_executable(const void *pointer);
unsigned char esp_psram_check_ptr_addr(void *pointer);
unsigned char esp_ptr_byte_accessible(void *pointer);
void _xt_coproc_release(XtensaCoprocessorHeader *header, int target_core);
void abort(void) __attribute__((noreturn));
int ets_printf(const char *format, ...);
#define PORT_TLS_DIAGNOSTIC_GATE (*(volatile unsigned int *)0x3fcaa550U)
bool esp_cpu_compare_and_set(volatile unsigned int *address,
                             unsigned int expected, unsigned int desired);
void vTaskPrioritySet(RtosTask *task, unsigned int priority);
unsigned int uxTaskPriorityGet(RtosTask *task);
int xTaskGenericNotify(RtosTask *task, unsigned int index,
                        unsigned int value, unsigned int action,
                        unsigned int *previous_value);
/* Per-CPU arrays; these do not belong to an individual portMUX. */
#define PORT_CRITICAL_NESTING ((volatile unsigned int *)0x3fcbdd34U)
#define PORT_SAVED_PS ((volatile unsigned int *)0x3fcbdd2cU)
#define PORT_INTERRUPT_NESTING ((volatile unsigned int *)0x3fcbdd3cU)
#define EXTERNAL_RAM_CAS_GUARD (*(volatile unsigned int *)0x3fcabdd8U)
#define ATOMIC_BYTE_EXCHANGE_LOCK ((PortMuxWords *)0x3fcaba80U)
RtosTask *xTaskGetCurrentTaskHandle(void);


#define TASK_WATCHDOG_LOCK (*(PortMuxWords *)0x3fcaba6cU)
#define TASK_WATCHDOG_DIAGNOSTICS (*(unsigned int *)0x3fcaa550U)

/* ESP-IDF TaskSnapshot_t layout used by the panic path. */
typedef struct TaskSnapshot {
    void *task_control_block;          /* +0x00 */
    unsigned char *top_of_stack;        /* +0x04: exception-frame address */
    unsigned char *end_of_stack;        /* +0x08 */
} TaskSnapshot;

int vTaskGetSnapshot(RtosTask *task, TaskSnapshot *snapshot);
/* Raw WORD view preserves the snapshot caller's exact low-BYTE ==1 test. */
unsigned int rtos_check_tcb_memory_raw(void *address) __asm__("xPortCheckValidTCBMem");
void vPortYieldOtherCore(int core_id);
void vApplicationStackOverflowHook(RtosTask *unused_task,char *task_name)
    __attribute__((noreturn));
int xTimerCreateTimerTask(void);
#define FUN_40386ae4 vPortYieldOtherCore
#define FUN_40386af0 vApplicationStackOverflowHook
#define FUN_4038909c vTaskGetSnapshot
#define FUN_403890cc xTimerCreateTimerTask
void esp_reset_reason_set_hint(unsigned int hint);
void xt_unhandled_exception(XtensaExceptionFrame *frame);

#define TASK_WATCHDOG_ISR_ACTIVE (*(unsigned char *)0x3fcd867cU)

/* Optional watchdog reporting sink: each call supplies one text fragment. */
typedef void (*TaskWatchdogMessageHandler)(void *opaque, const char *message);
char *pcTaskGetName(RtosTask *task);
int xTaskGetCoreID(RtosTask *task);
int esp_task_wdt_print_triggered_tasks(TaskWatchdogMessageHandler handler,
                                      void *opaque, int *failed_core_mask);
#define FUN_42010e08 esp_task_wdt_print_triggered_tasks
#define FUN_403879c8 pcTaskGetName

/* UART0 control receive record: little-endian header followed by payload. */
typedef struct ControlRxRecordHeader {
    union {
        unsigned short opcode_sequence; /* +0x00: native 16-bit store */
        struct {
            unsigned char opcode;       /* +0x00 */
            unsigned char sequence;     /* +0x01 */
        };
    };
    unsigned short payload_length;      /* +0x02: 0xffff marks a wrapped tail */
    unsigned int timestamp_us_low;       /* +0x04: low 32 microsecond bits */
} ControlRxRecordHeader;

#define CONTROL_RX_RING_BYTES 0x4000U
#define CONTROL_RX_CURSOR_MASK 0x3fffU
#define CONTROL_RX_RING ((unsigned char *)0x3fcb526cU)
#define CONTROL_RX_TASK (*(RtosTask *volatile *)0x3fcd641cU)
#define CONTROL_RX_OVERFLOW_COUNT (*(volatile unsigned int *)0x3fcd6424U)
#define CONTROL_RX_READ_OFFSET (*(volatile unsigned int *)0x3fcd6428U)
#define CONTROL_RX_WRITE_OFFSET (*(volatile unsigned int *)0x3fcd642cU)

void control_receive_publish(unsigned char opcode, unsigned char sequence,
                               const unsigned char *payload, unsigned short length,
                               void *context);
long long esp_timer_get_time(void);
void vTaskGenericNotifyGiveFromISR(RtosTask *task, unsigned int index,
                                  int *higher_priority_task_woken);
void _frxt_setup_switch(void);

/* UART0 receive-task callbacks and state. */
typedef void (*ControlRxHook)(void);
#define CONTROL_RX_FIRST_FRAME_HOOK (*(ControlRxHook volatile *)0x3fcd61e0U)
#define CONTROL_RX_HAS_RECEIVED_FRAME (*(volatile unsigned char *)0x3fcd61e4U)
#define CONTROL_RX_FRAME_CONTEXT (*(void *volatile *)0x3fcd61e8U)
#define CONTROL_RX_EMPTY_RING_HOOK (*(ControlRxHook volatile *)0x3fcd61ecU)
#define CONTROL_RX_FRAME_HANDLER (*(FrameCallback volatile *)0x3fcd61f0U)
#define CONTROL_UART_RX_FIFO_OVERFLOW_COUNT (*(volatile unsigned int *)0x3fcd6420U)
#define CONTROL_RX_LAST_TIMESTAMP_US_LOW (*(volatile unsigned int *)0x3fcd6430U)

void control_receive_task(void *argument);
unsigned int ulTaskGenericNotifyTake(unsigned int index, int clear_count_on_exit,
                                     unsigned int ticks_to_wait);
unsigned int control_rx_drop_count(void);
unsigned char control_pc_has_sent_frame(void);
void control_set_frame_handler(FrameCallback callback, void *context);
unsigned int control_rx_last_timestamp_us_low(void);
void control_set_rx_empty_hook(ControlRxHook callback);
void control_set_first_frame_hook(ControlRxHook callback);

#define FUN_4200a21c control_rx_last_timestamp_us_low
#define FUN_4200a240 control_set_rx_empty_hook
#define FUN_4200a528 control_set_first_frame_hook

void control_send_initial_version(void);
void query_version_send(unsigned char sequence);
#define FUN_4200b4c0 control_send_initial_version

/* Partial UART register view through CLK_CONF. Unused offsets are retained so
 * field offsets match the ESP32-S3 UART MMIO map; this is not the full block. */
typedef struct UartRegisterView {
    volatile unsigned int fifo;               /* +0x00: byte FIFO access */
    volatile unsigned int interrupt_raw;      /* +0x04 */
    volatile unsigned int interrupt_status;   /* +0x08: enabled pending sources */
    volatile unsigned int interrupt_enable;   /* +0x0c */
    volatile unsigned int interrupt_clear;    /* +0x10: write-one-to-clear */
    volatile unsigned int clkdiv;             /* +0x14: integer bits0..11, fraction20..23 */
    volatile unsigned int rx_filt;             /* +0x18: RX pulse filter */
    volatile unsigned int status;             /* +0x1c: RX/TX FIFO counts */
    volatile unsigned int conf0;              /* +0x20: includes FIFO reset */
    volatile unsigned int conf1;              /* +0x24: FIFO thresholds, RX timeout enable */
    unsigned int unused_28[8];
    volatile unsigned int idle_conf;          /* +0x48: TX idle count */
    volatile unsigned int rs485_conf;         /* +0x4c */
    unsigned int unused_50[4];
    volatile unsigned int mem_conf;           /* +0x60: RX timeout threshold and FIFO sizes */
    unsigned int unused_64[5];
    volatile unsigned int clk_conf;           /* +0x78: source/coarse divider */
} UartRegisterView;

#define CONTROL_UART0 ((UartRegisterView *)0x60000000U)
#define CONTROL_RX_PARSER ((LinkParser *)0x3fcd61f4U)
#define CONTROL_TX_LOCK (*(PortMuxWords *)0x3fcab530U)
#define CONTROL_TX_MUTEX (*(void *volatile *)0x3fcd640cU)
#define CONTROL_TX_RING ((unsigned char *)0x3fcb426cU)
#define CONTROL_TX_READ_OFFSET (*(volatile unsigned int *)0x3fcd6410U)
#define CONTROL_TX_WRITE_OFFSET (*(volatile unsigned int *)0x3fcd6414U)
#define CONTROL_TX_RING_BYTES 0x1000U
#define CONTROL_TX_CURSOR_MASK 0x0fffU
#define UART_FIFO_CAPACITY 128U
#define UART_FIFO_COUNT_MASK 0x3ffU
#define UART_RX_FULL_IRQ 0x001U
#define UART_TX_EMPTY_IRQ 0x002U
#define UART_RX_ERROR_IRQS 0x00cU
#define UART_RX_OVERFLOW_IRQ 0x010U
#define UART_RX_TIMEOUT_IRQ 0x100U
#define UART_RX_FIFO_RESET 0x20000U

void control_uart_interrupt_handler(void *argument);
int control_tx_enqueue(const unsigned char *bytes, unsigned int length);
unsigned int control_tx_pending_bytes(void);
unsigned int control_tx_budget_bytes(void);

#define FUN_4200a37c control_tx_pending_bytes
#define FUN_4200a42c control_tx_budget_bytes

/* 32-byte uart_config_t layout consumed by the native UART driver.
 * Explicit padding and native enum words retain the ESP32-S3 field offsets. */
typedef struct UartConfig {
    int baud_rate;                          /* +0x00 */
    unsigned int data_bits;                  /* +0x04 */
    unsigned int parity;                     /* +0x08 */
    unsigned int stop_bits;                  /* +0x0c */
    unsigned int flow_control;               /* +0x10 */
    unsigned char rx_flow_control_threshold; /* +0x14 */
    unsigned char padding_15[3];
    unsigned int source_clock;               /* +0x18 */
    unsigned int flags;                      /* +0x1c */
} UartConfig;

#define UART_DATA_8_BITS 3U
#define UART_STOP_BITS_1 1U
#define UART_CLOCK_APB 4U
#define INTR_FLAG_IRAM 0x400
#define CONTROL_UART_CONF1 (*(volatile unsigned int *)0x60000024U)
#define CONTROL_UART_MEM_CONF (*(volatile unsigned int *)0x60000060U)
/* uart_periph_signal[0].irq, read from the image's constant peripheral table. */
#define UART0_INTERRUPT_SOURCE (*(const unsigned char *)0x3c046b90U)
#define CONTROL_UART_IRQ_HANDLE (*(void *volatile *)0x3fcd6418U)
#define CRC16_TABLE ((const unsigned short *)0x3fcbb89cU)

int uart_param_config(unsigned int uart_number,const UartConfig *configuration);
int uart_set_pin(int port,int tx_gpio,int rx_gpio,int rts_gpio,int cts_gpio);
int xTaskCreatePinnedToCore(TaskEntry entry, char *name,
                             unsigned int stack_bytes, void *argument,
                             unsigned int priority, RtosTask **created_task,
                             int core_id);
void control_uart_init(void);

/* UART1 inter-chip link state. The TX cursor borrows its sender's buffer;
 * it is separate from the control UART0 software transmit ring. */
#define LINK_UART1 ((UartRegisterView *)0x60010000U)
#define LINK_RX_PARSER ((LinkParser *)0x3fcd828cU)
#define LINK_TX_LOCK (*(PortMuxWords *)0x3fcab560U)
#define LINK_TX_INITIAL_FIFO_LIMIT (*(volatile unsigned int *)0x3fcab55cU)
#define LINK_TX_COMPLETION_SEMAPHORE (*(RtosQueue *volatile *)0x3fcd84c0U)
#define LINK_TX_REMAINING_BYTES (*(volatile unsigned short *)0x3fcd84c4U)
#define LINK_TX_CURSOR (*(const unsigned char *volatile *)0x3fcd84c8U)
#define LINK_RX_FIFO_OVERFLOW_COUNT (*(volatile unsigned int *)0x3fcd84dcU)
#define LINK_LOG_TAG ((const char *)0x3fcbce28U)
#define UART_TX_DONE_IRQ 0x4000U

void link_uart_interrupt_handler(void *argument);
void link_uart_transmit_wait(unsigned char *frame, unsigned int frame_length);
unsigned int esp_log_timestamp(void);
void esp_log_write(unsigned int level, const char *tag, const char *format, ...);


/* Native TX queue item: 16-bit encoded length, followed by a 520-byte frame
 * storage area. Queue copies include all 522 bytes, not just encoded_length.
 * Channel order is opcode 0x10, other opcodes, opcode 0x1c. */
typedef struct LinkTxQueueItem {
    unsigned short encoded_length;             /* +0x000 */
    unsigned char encoded_frame[520];            /* +0x002 */
} LinkTxQueueItem;

/* Separate 12-byte arrays of queue handles, used as mutexes and TX queues.
 * These are fixed-address storage views, not allocated queue control blocks. */
typedef struct LinkTxHandleSlots {
    RtosQueue *slot[3];
} LinkTxHandleSlots;

#define LINK_UART_NUMBER 1
#define LINK_STARTUP_BAUD 20000000
#define LINK_TX_QUEUE_CAPACITY 8U
#define RTOS_NO_CORE_AFFINITY 0x7fffffff
#define ESP_INTR_FLAG_LEVEL2 0x004
#define ESP_INTR_FLAG_LEVEL3 0x008
#define LINK_UART_RX_IRQS 0x11dU

void link_receive_publish(unsigned char type, unsigned char flags,
    const unsigned char *payload, unsigned short length, void *unused_context);
void link_receive_task(void *unused_argument);
void link_transmit_task(void *unused_argument);
void link_baud_task(void *unused_argument);
void link_init(int role);
#define LINK_TX_MUTEX_HANDLES (*(volatile LinkTxHandleSlots *)0x3fcd84a4U)
#define LINK_TX_QUEUE_HANDLES (*(volatile LinkTxHandleSlots *)0x3fcd8280U)
#define LINK_TX_TASK_HANDLE (*(RtosTask *volatile *)0x3fcd827cU)
#define LINK_RX_TASK_HANDLE (*(RtosTask *volatile *)0x3fcd84d0U)
#define LINK_UART_IRQ_HANDLE (*(void *volatile *)0x3fcd84ccU)
/* uart_periph_signal[1].irq; native code reads this byte, not a literal 28. */
#define UART1_INTERRUPT_SOURCE (*(const unsigned char *)0x3c046ba4U)


/* Inter-chip receive storage views, not allocator objects. Policy occupies
 * 48 bytes immediately before the 96 descriptors; each descriptor is 16 bytes
 * and the 8192-byte payload ring follows the descriptor array. Unused bytes
 * are retained in place and are not initialized by the publish routine. */
typedef int (*LinkRxDirectHandler)(unsigned int flags,
    const unsigned char *payload, unsigned int length, int has_counted_pending);
typedef void (*LinkRxObserver)(unsigned int type, unsigned int flags,
    const unsigned char *payload, unsigned int length);

typedef struct LinkRxPolicy {
    unsigned char accounting_enabled;             /* +0x00: raw marker byte */
    unsigned char unmodeled_01[3];
    unsigned int uncounted_types[8];               /* +0x04: one bit per opcode */
    unsigned char direct_type;                    /* +0x24: also accounting-exempt */
    unsigned char unmodeled_25[3];
    LinkRxDirectHandler direct_handler;      /* +0x28: nonzero result consumes */
    LinkRxObserver observer;                 /* +0x2c: return value unused */
} LinkRxPolicy;

typedef struct LinkRxDescriptor {
    union {
        unsigned short type_and_flags;           /* +0x00: one native S16I store */
        struct {
            unsigned char type;
            unsigned char flags;
        };
    };
    unsigned short length;                       /* +0x02 */
    unsigned short payload_offset;               /* +0x04 */
    unsigned short unmodeled_06;
    unsigned int received_at_us_low;             /* +0x08: only types 2/0x25 timed */
    unsigned char counted;                       /* +0x0c: nonzero decrements pending */
    unsigned char unmodeled_0d[3];
} LinkRxDescriptor;

typedef struct LinkRxCursors {
    unsigned int payload_read;                   /* +0x00: byte offset */
    unsigned int payload_write;                  /* +0x04: reservation cursor */
    unsigned int descriptor_read;                /* +0x08 */
    unsigned int descriptor_write;               /* +0x0c: publication cursor */
} LinkRxCursors;

/* Optional queue's exact 100-byte copy view; consumer does not check length. */
typedef struct LinkRxQueueItem {
    union {
        unsigned short type_and_flags;
        struct { unsigned char type, flags; };
    };
    unsigned short length;
    unsigned char payload[96];
} LinkRxQueueItem;

#define LINK_RX_DESCRIPTOR_SLOTS 96U
#define LINK_RX_PAYLOAD_BYTES 8192U
#define LINK_RX_PAYLOAD_MASK 8191U
void link_frame_dispatch(int type, unsigned int flags, void *payload,
    unsigned int length, unsigned int received_at_us_low);
#define LINK_RX_POLICY (*(volatile LinkRxPolicy *)0x3fcb926cU)
#define LINK_RX_DESCRIPTORS ((volatile LinkRxDescriptor *)0x3fcb929cU)
#define LINK_RX_PAYLOAD ((unsigned char *)0x3fcb989cU)
#define LINK_RX_CURSOR_STATE (*(volatile LinkRxCursors *)0x3fcd84e8U)
#define LINK_RX_COUNTED_PENDING (*(volatile unsigned int *)0x3fcd84d8U)
#define LINK_RX_SELECTED_TYPE_DROPS (*(volatile unsigned int *)0x3fcd84e4U)
#define LINK_RX_OTHER_TYPE_DROPS (*(volatile unsigned int *)0x3fcd84e0U)
#define LINK_LAST_DIRECT_RX_US (*(volatile unsigned int *)0x3fcd84bcU)
#define LINK_RX_OPTIONAL_QUEUE (*(RtosQueue *volatile *)0x3fcd84d4U)
#define LINK_RX_QUEUE_SCRATCH ((LinkRxQueueItem *)0x3fcd7704U)
#define LINK_RX_COUNT_LOCK (*(PortMuxWords *)0x3fcab568U)

/* TX worker interfaces recovered from the native call sites. Callback lengths
 * are full words; the frame encoder itself narrows the fast length to 16 bits.
 * Context is an opaque 32-bit word, not an inferred pointer ownership claim. */
typedef unsigned int (*LinkFastTxHandler)(unsigned char *type_out,
                                               unsigned char *payload_out,
                                               unsigned int capacity);
typedef int (*LinkTxAdmissionHandler)(unsigned int encoded_length,
                                           unsigned int context);
/* Minimum fixed-address view touched by this worker, not an allocation size. */
typedef struct LinkFastTxFrame {
    unsigned short encoded_length;
    unsigned char encoded_frame[72];
} LinkFastTxFrame;
void vTaskDelay(unsigned int ticks);
int uart_set_baudrate(unsigned int port, unsigned int baud_rate);
unsigned int link_frame_enqueue(int type, unsigned char flags,
    void *payload, unsigned int length, unsigned int wait_ticks, char suppress_drop_log);
#define LINK_TX_FAST_PENDING (*(volatile unsigned char *)0x3fcd7c4cU)
#define LINK_TX_FAST_HANDLER (*(LinkFastTxHandler volatile *)0x3fcd7c50U)
#define LINK_TX_ADMISSION_CONTEXT (*(volatile unsigned int *)0x3fcd7c54U)
#define LINK_TX_ADMISSION (*(LinkTxAdmissionHandler volatile *)0x3fcd7c58U)
#define LINK_TX_QUEUE_SCRATCH ((LinkTxQueueItem *)0x3fcd7768U)
#define LINK_TX_FAST_FRAME ((LinkFastTxFrame *)0x3fcd7974U)
#define LINK_BAUD_PROBE_INHIBIT (*(volatile unsigned char *)0x3fcd84b8U)
#define LINK_BAUD_TABLE ((const unsigned int *)0x3c047fb0U)

/* Link routing interfaces; old address aliases retain existing call sites. */
void link_set_receive_observer(LinkRxObserver observer);
#define FUN_42022590 link_set_receive_observer
void link_configure_receive(unsigned char direct_type,
    LinkRxDirectHandler handler, const unsigned char *uncounted_types,
    unsigned char count);
#define FUN_4202259c link_configure_receive
int link_enqueue_rx_copy(unsigned char type, unsigned char flags,
                                const void *payload, unsigned short length);
#define FUN_42022620 link_enqueue_rx_copy
void link_set_fast_transmit_handler(LinkFastTxHandler handler);
#define FUN_42022770 link_set_fast_transmit_handler

/* Opcode0x40 credit payload: count byte, then up to15 four-byte records.
 * The host accepts at most64 bytes; three trailing bytes are not records. */
typedef struct CreditRecord {
    unsigned char endpoint, sequence, load, flags;
} CreditRecord;
typedef struct CreditPacket {
    unsigned char record_count;
    CreditRecord records[15];
    unsigned char trailing[3];
} CreditPacket;

typedef struct TimestampWords { unsigned int low, high; } TimestampWords;
/* Fixed-address views; unused fields and stride padding are retained. */
typedef struct CreditEndpointState {
    unsigned char pending_flags[16];                /* +0x00 */
    TimestampWords last_rx[16];               /* +0x10 */
    unsigned char load_observations[16];            /* +0x90 */
    unsigned char last_sequence_minus_load[16];      /* +0xa0 */
    unsigned short tracked_endpoints;              /* +0xb0 */
    unsigned char reserved_b2[2];
    unsigned char sequence[16];                     /* +0xb4 */
} CreditEndpointState;
typedef struct CreditInterfaceMap {
    unsigned char endpoint[36];
    int count;                                      /* +0x24 */
} CreditInterfaceMap;
typedef struct CreditBinding {
    unsigned char endpoint, kind;
    unsigned short packet_length;
    unsigned char unknown4[2];
    unsigned char queue_slot, unknown7;
} CreditBinding;
typedef struct CreditBindings {
    CreditBinding entry[12];
    int count;                                      /* +0x60 */
} CreditBindings;
typedef struct CreditInterfaceRecord {
    unsigned char data[64];
    union {
        unsigned short length_and_kind;
        struct {
            unsigned char length;
            union { unsigned char kind,credit_marker; };
        };
    };
    unsigned char metadata42;
    unsigned char score;
    unsigned char metadata44,unmodeled_45[3];
    unsigned int metadata48;
    unsigned char special,unmodeled_4d;
    unsigned short epoch_tag;
    union { unsigned int metadata50; struct InputStateView *input_state; };
} CreditInterfaceRecord;
typedef struct CreditInterfaceQueue {
    CreditInterfaceRecord records[8];
    unsigned char record_count,unknown2a1[3];
    unsigned char extra_pending,unknown2a5[3];
    unsigned int history_write_count,history_read_count;
    TimestampWords history_time[4];
    unsigned char history_sample[4],unknown2d4[4];
    TimestampWords latest_time;
    unsigned int effective_delay,minimum_delay;
    unsigned char history_hits,unknown2e9[7];
    TimestampWords last_history_time;
    unsigned char sample_mode,mode_count,empty_run,pending_kind;
    unsigned char unknown2fc[4];
    TimestampWords last_mode_time;             /* +0x300 */
    unsigned char recent_ids[4],unknown30c[4];
    TimestampWords recent_time[4];
    unsigned int recent_minimum[4];
    unsigned short interval_scale;
    union {
        unsigned char unknown342[4];
        struct { unsigned short last_frame_number,short_interval_candidate; };
    };
    unsigned short epoch_tag;
    union {
        struct {
            union { unsigned char unknown348,frame_number_valid; };
            unsigned char epoch_gate;
        };
        unsigned short frame_validity_flags;
    };
    unsigned char window_active,deferred;
    unsigned char expiry_defer_enabled;
    unsigned char combine_deadline_inhibited;         /* +0x34d */
    union {
        struct {
            unsigned char combine_window_enabled;
            union { unsigned char unknown34f,deferred_frame_count; };
        };
        unsigned short combine_window_flags;
    };                                              /* +0x34e */
    unsigned short pending_sample,comparison_limit;
    union {
        struct { unsigned char pending_split,pending_short_multiple; };
        unsigned short pending_split_flags;
    };
    unsigned char unknown356[2];
    TimestampWords window_deadline,window_start,window_end,window_strict;
    unsigned char reservation,unknown379[7];
    TimestampWords pending_start;
    unsigned char minimum_ids[4],minimum_hits[4];
    unsigned int minimum_delay_by_id[4];
    TimestampWords minimum_last_seen[4];
} CreditInterfaceQueue;                        /* stride0x3c0 */
typedef struct CreditSecondaryRecord {
    unsigned char data[64],length;
    unsigned char credit_marker;                    /* +0x41: nonzero counts */
} CreditSecondaryRecord;
typedef struct CreditSecondaryQueue {
    CreditSecondaryRecord records[8];
} CreditSecondaryQueue;                        /* stride0x210 */
#define CREDIT_STATE (*(volatile CreditEndpointState *)0x3fcc0fa0U)
#define CREDIT_DIRTY ((unsigned char *)0x3fcc0ed9U)
#define CREDIT_LOCK (*(PortMuxWords *)0x3fcab4d8U)
#define CREDIT_INTERFACES (*(const volatile CreditInterfaceMap *)0x3fccc9c4U)
#define CREDIT_BINDINGS (*(const volatile CreditBindings *)0x3fccbe20U)
#define CREDIT_ENDPOINT_INTERFACE ((volatile signed char *)0x3fcab4f0U)
#define CREDIT_INTERFACE_QUEUES ((const volatile CreditInterfaceQueue *)0x3fcc1150U)
#define CREDIT_INTERFACE_EXTRA_HELD ((const volatile unsigned char *)0x3fccc8b0U)
#define CREDIT_SECONDARY_QUEUES ((const volatile CreditSecondaryQueue *)0x3fcc01b8U)
#define CREDIT_SECONDARY_COUNTS ((const volatile unsigned char *)0x3fcc01a8U)
#define CREDIT_SECONDARY_HEADS ((const volatile unsigned char *)0x3fcc01b0U)
#define CREDIT_SECONDARY_IN_FLIGHT ((const volatile unsigned char *)0x3fcc01a0U)
#define CREDIT_SECONDARY_IN_FLIGHT_WEIGHT ((const volatile unsigned char *)0x3fcc0120U)
unsigned int atomic_exchange_byte(unsigned char *address,
    unsigned int desired, unsigned int memory_order);
unsigned int atomic_exchange_byte_s32c1i(unsigned char *address,
    unsigned int desired,unsigned int ignored_memory_order);
unsigned int endpoint_canonicalize(unsigned int endpoint);
unsigned int credit_endpoint_load(unsigned int endpoint,
                                          unsigned long long now_us);
unsigned int credit_build_packet(unsigned char *type_out,
    unsigned char *payload_out, unsigned int capacity);
int credit_state_changed(unsigned long long now_us);
#define FUN_40378528 credit_endpoint_load
#define FUN_4037880c credit_build_packet
#define FUN_4202c88c credit_state_changed

/* IN completion periods are separate from the inter-chip credit RX clock.
 * The native observer ignores A3: it is alignment padding before the two
 * 64-bit times in A4/A5 and A6/A7. Tail length is the first stack argument. */
#define CREDIT_IN_INTERVAL_US ((volatile unsigned int *)0x3fcc0edcU)
#define CREDIT_LAST_IN_COMPLETION ((volatile TimestampWords *)0x3fcc0f20U)
void credit_observe_in_completion(unsigned int endpoint,
    unsigned long long now_us,unsigned long long submitted_us,
    unsigned int tail_length);
/* Preserve the pending vendor caller's split-word view of this same entry. */
void FUN_40377210(unsigned int endpoint,unsigned int padding,
    unsigned int now_low,int now_high,unsigned int submitted_low,
    int submitted_high,unsigned int tail_length)
    __asm__("credit_observe_in_completion");

/* Report RX views and interfaces; gate-byte names describe local tests,
 * not an inferred application ownership or synchronization guarantee. */

typedef struct FastReportRingItem {
    unsigned char sequence, length, classification;
    unsigned char payload[96];
} FastReportRingItem;
/* Sparse 304-byte interface stride; unmodeled spans are retained verbatim.
 * Admission short-circuits block4, block_db, then block_11f as BYTE flags.
 * Adjacent block_da/block_11e views belong to other report-policy consumers. */
typedef struct ReportInterfaceMode {
    unsigned char unmodeled_0[4],block4,unmodeled_5[213];
    unsigned char block_da;
    unsigned char block_db,unmodeled_dc[66];
    unsigned char block_11e;
    unsigned char block_11f,unmodeled_120[16];
} ReportInterfaceMode;
/* Native routing reads only the leading interface WORD at each904-byte
 * stride. The remaining bytes are an opaque retained policy view. */
typedef struct ReportBlockListEntry {
    int interface;
    unsigned char unmodeled4[900];
} ReportBlockListEntry;
/* Modeled first 100 bytes of EXTMEM: two enable controls with an opaque
 * intervening span. The span is not asserted to be reserved hardware. */
typedef struct ExtmemCacheControls {
    volatile unsigned int dcache_ctrl;
    unsigned char unmodeled_between_controls[92];
    volatile unsigned int icache_ctrl;
} ExtmemCacheControls;
#define EXTMEM_CACHE ((ExtmemCacheControls *)0x600c4000U)
#define REPORT_PENDING ((volatile unsigned char *)0x3fcc0e24U)
#define REPORT_FAST_TASK (*(RtosTask *volatile *)0x3fcbfee0U)
#define REPORT_FAST_RING_COUNT (*(volatile unsigned char *)0x3fcbfee4U)
#define REPORT_FAST_RING_HEAD (*(volatile unsigned char *)0x3fcbfee5U)
#define REPORT_FAST_RING ((FastReportRingItem *)0x3fcace28U)
#define REPORT_HISTORY_QUEUES ((volatile CreditInterfaceQueue *)0x3fcc1150U)
#define REPORT_INTERFACE_BLOCKED ((volatile unsigned char *)0x3fccc580U)
#define REPORT_BLOCK0_INTERFACE (*(const volatile int *)0x3fcaa848U)
#define REPORT_BLOCK0_ACTIVE (*(const volatile unsigned char *)0x3fcaa84cU)
#define REPORT_BLOCK1_INTERFACE (*(const volatile int *)0x3fcaac30U)
#define REPORT_BLOCK2_INTERFACE (*(const volatile int *)0x3fcab018U)
#define REPORT_INTERFACE_MODES ((const volatile ReportInterfaceMode *)0x3fccb610U)
#define REPORT_BLOCK_LIST_COUNT (*(const volatile int *)0x3fcc9dd4U)
#define REPORT_BLOCK_LIST ((const volatile ReportBlockListEntry *)0x3fcc9dd8U)
#define REPORT_FAST_GLOBAL_BLOCK (*(const volatile unsigned char *)0x3fccbfa8U)
#define REPORT_FAST_ENABLED (*(const volatile unsigned char *)0x3fcc4cdcU)
#define REPORT_FAST_BLOCK97 (*(const volatile unsigned char *)0x3fccbe97U)
#define REPORT_FAST_BLOCK98 (*(const volatile unsigned char *)0x3fccbe98U)
#define REPORT_FAST_GATE96 (*(volatile unsigned char *)0x3fccbe96U)
#define REPORT_FAST_EXTRA_BLOCK (*(const volatile unsigned char *)0x3fcc0ec0U)
#define REPORT_MODE_BLOCK_7D18 (*(const volatile unsigned char *)0x3fcc7d18U)
#define REPORT_MODE_BLOCK_9D8A (*(const volatile unsigned char *)0x3fcc9d8aU)
#define REPORT_MODE_BLOCK_8F84 (*(const volatile unsigned char *)0x3fcc8f84U)
int report_find_fast_interface(unsigned int endpoint);
unsigned int report_fast_fallback_allowed(const unsigned char *payload, unsigned int length);
int report_fast_route_allowed(const unsigned char *payload, unsigned int length);
int report_pending_for_endpoint(unsigned int endpoint);
void report_track_rx(unsigned int sequence,const unsigned char *payload,unsigned int length,int count_pending);
void report_receive_observer(unsigned int type,unsigned int flags,const unsigned char *payload,unsigned int length);
int report_receive_direct(unsigned int flags,const unsigned char *payload,unsigned int length,int has_counted_pending);
void link_kick_fast_tx(void);
void report_complete(unsigned int endpoint);
bool cache_hal_is_cache_enabled(unsigned int cache_level,CacheType type);
bool spi_flash_cache_enabled(void);
bool usb_device_is_configured(unsigned int bus_id);
#define FUN_403773bc report_find_fast_interface
#define FUN_4037744c report_fast_fallback_allowed
#define FUN_403774bc report_track_rx
#define FUN_40377718 report_receive_observer
#define FUN_40377854 report_fast_route_allowed
#define FUN_40377ef4 report_pending_for_endpoint
#define FUN_40377f60 report_receive_direct
#define FUN_40383e74 link_kick_fast_tx
#define FUN_420336f8 report_complete
#define FUN_4037de48 spi_flash_cache_enabled
#define FUN_40389254 cache_hal_is_cache_enabled

/* Per-bus field views begin at configuration, not CherryUSB object start. */
typedef struct MediusUsbConfiguredView {
    unsigned char configuration;
    unsigned char unknown1[2803];
} MediusUsbConfiguredView;
#define MEDIUS_USB_CONFIGURED_VIEWS ((const volatile MediusUsbConfiguredView *)0x3fcbc2b8U)


/* Shared scratch views. Word fields read four bytes even for short frames. */
typedef struct FastReportScratchWords {
    unsigned char sequence,length,classification,endpoint;
    unsigned int source_stamp,flags_and_prefix;
} FastReportScratchWords;
typedef struct MediusCaptureWire {
    union {
        unsigned char source_stamp[4];
        struct { unsigned short stamp_low; unsigned char stamp_byte2,stamp_byte3; };
    };
    unsigned short subtype_and_class;
    unsigned char endpoint,reserved7,version,flags,original_length,reserved11;
    unsigned char payload[64];
} MediusCaptureWire;
typedef struct CaptureEvent {
    unsigned char ready,reserved1[3];
    unsigned int subscriptions;
    unsigned short wire_length;
    MediusCaptureWire wire;
} CaptureEvent;
#define REPORT_FAST_SCRATCH ((FastReportRingItem *)0x3fcbf17cU)
#define REPORT_FAST_SCRATCH_WORDS (*(volatile FastReportScratchWords *)0x3fcbf17cU)
#define REPORT_LAST_WORKER_TIME (*(volatile TimestampWords *)0x3fcbfed8U)
long long fast_report_get_activity_time(void);
/* Secondary routing reads one flags BYTE; primary routing uses the WORD view. */
#define REPORT_FAST_FLAGS_BYTE (*(const volatile unsigned char *)0x3fcbf184U)
#define REPORT_FAST_ACTIVE (*(volatile unsigned char *)0x3fccbe95U)
#define REPORT_CAPTURE_INTERFACE_IDS ((const volatile unsigned char *)0x3fccc9ccU)
#define REPORT_INTERFACE_PERIODS ((const volatile unsigned short *)0x3fccc9b8U)
#define REPORT_RECOVERY_EPOCH (*(const volatile TimestampWords *)0x3fcc1128U)
#define REPORT_RECOVERY_MODE (*(const volatile unsigned char *)0x3fcc1149U)
#define REPORT_PRIMARY_FALLBACK_DROPS (*(volatile unsigned int *)0x3fccbd38U)
#define REPORT_SECONDARY_FALLBACK_DROPS (*(volatile unsigned int *)0x3fccc488U)
#define CAPTURE_TASK (*(RtosTask *volatile *)0x3fcc4d28U)
void report_fast_task(void *unused_argument);
void capture_notify_task(void);
void capture_event_build(CaptureEvent *event,unsigned int traffic_class,
    unsigned short subtype,unsigned int endpoint,unsigned char flags,
    unsigned int source_stamp,const unsigned char *payload,unsigned short length);
void link_report_decode(unsigned char *payload,unsigned short length);
/* Compatibility aliases for existing word/pointer caller views. The canonical
 * reviewed signatures are declared alongside them. */
void report_service_interface(unsigned int interface,int force);
unsigned int FUN_4037a754(int interface,char *report,unsigned int length,int mode0,int mode1,unsigned int mode2,
    char *event,unsigned int arg8,unsigned char arg9,unsigned char arg10,
    unsigned char *status,char arg12,unsigned int arg13) __asm__("report_process_interface");
unsigned int report_process_interface(unsigned int interface,
    const unsigned char *report,unsigned int length,int force_kind2,int derive_kind1,
    unsigned int metadata44,CaptureEvent *event,unsigned int metadata48,
    unsigned char options,unsigned char short_multiple,unsigned char *status,
    unsigned char reject_if_inhibited,unsigned int epoch);
int FUN_40399be8(char endpoint,unsigned int source_stamp,unsigned char *report,short length,unsigned int flags)
    __asm__("report_intercept_secondary");
#define medius_rptfast_service_interface report_service_interface
#define FUN_4037a50c report_service_interface
#define medius_rptfast_submit_interface FUN_4037a754
#define medius_rptfast_submit_secondary FUN_40399be8
#define FUN_40393128 capture_notify_task


/* Native capture banks: six-byte rules,260-byte stride. Kind0/1 affects
 * matching priority; no direction comparison occurs in the builder. */
typedef struct MediusCaptureRule {
    unsigned short endpoint;
    unsigned char traffic_class,kind,payload_limit,reserved5;
} MediusCaptureRule;
typedef struct MediusCaptureSubscriptionBank {
    MediusCaptureRule rules[43];
    unsigned char count,reserved103;
} MediusCaptureSubscriptionBank;
typedef struct MediusCaptureRing {
    unsigned char *storage;
    unsigned short item_size,capacity;
    union {
        unsigned int write_and_used;
        struct { unsigned short write_index,used; };
    };
} MediusCaptureRing;
typedef struct MediusCaptureQueuedRecord {
    unsigned char kind,reserved;
    unsigned short length;
    unsigned char payload[192];
} MediusCaptureQueuedRecord;
#define MEDIUS_CAPTURE_RINGS ((volatile MediusCaptureRing *)0x3fcaa7f4U)
#define MEDIUS_CAPTURE_LOCK (*(PortMuxWords *)0x3fcaa824U)
#define CAPTURE_TOTAL_DROPS (*(volatile unsigned int *)0x3fcc4d20U)
#define CAPTURE_SUBSCRIBER_DROPS ((volatile unsigned short *)0x3fcc77d0U)
#define CAPTURE_ACTIVE_BANK (*(volatile unsigned char *)0x3fcc7810U)
#define CAPTURE_ENABLED_CLASSES (*(volatile unsigned short *)0x3fcc77ccU)
#define MEDIUS_CAPTURE_BANKS ((const volatile MediusCaptureSubscriptionBank *)0x3fcc7814U)
int medius_capture_ring_has_room(unsigned int traffic_class,unsigned int subscribers);
unsigned int capture_submit_event(unsigned int traffic_class,
    unsigned int subscribers,unsigned char record_kind,const void *wire,unsigned int length);
#define medius_capture_quota_available medius_capture_ring_has_room
#define FUN_40392c98 capture_submit_event


void report_history_retire(CreditInterfaceQueue *queue,
    unsigned long long now_us,unsigned int update_statistics);
void report_try_schedule(CreditInterfaceQueue *queue,int allow_gating,
    unsigned long long now_us,unsigned int period,unsigned int interface);
unsigned int report_select_candidate(CreditInterfaceQueue *queue,
    unsigned int period,unsigned long long now_us);
void report_schedule_candidate(CreditInterfaceQueue *queue,
    unsigned long long now_us,unsigned long long deadline_us,
    unsigned short period,unsigned int interface,unsigned char strict);
int report_submit_record(unsigned int interface,
    const CreditInterfaceRecord *record);
int usb_device_write_aligned(unsigned char bus,unsigned char endpoint,
    unsigned char *buffer,unsigned int length);
/* Historical word signatures remain for pending caller bodies. GNU symbol
 * aliases bind them to the same native entries as the typed interfaces above.
 * Queue/period occupy A2/A3 for selection; scheduler A3 is unused alignment
 * padding before A4/A5 now and A6/A7 deadline. No extra firmware code is added. */
unsigned int FUN_40378060(char *queue,unsigned int period,unsigned int now_low,int now_high)
    __asm__("report_select_candidate");
void FUN_403788d4(unsigned char *queue,unsigned int padding,unsigned int now_low,int now_high,
    unsigned int deadline_low,int deadline_high,unsigned short period,unsigned int interface,char strict)
    __asm__("report_schedule_candidate");
/* Compatibility for existing split-word decompilations;unused word was padding. */
#define FUN_40377d1c(q,u,l,h,m) \
    report_history_retire((CreditInterfaceQueue *)(q), \
        ((unsigned long long)(unsigned int)(h)<<32)|(unsigned int)(l),(m))
#define FUN_40378ee0(q,a,l,h,p,i) \
    report_try_schedule((CreditInterfaceQueue *)(q),(a), \
        ((unsigned long long)(unsigned int)(h)<<32)|(unsigned int)(l), \
        (unsigned int)(p),(i))

/* Submit-side global views preserve each native address and access width. */
#define REPORT_SUBMIT_BLOCKED ((const volatile unsigned char *)0x3fccc748U)
#define REPORT_SUBMIT_STORAGE ((unsigned char *)0x3fcaf0d8U)
#define REPORT_SUBMIT_METADATA42 ((volatile unsigned char *)0x3fccc8b8U)
#define REPORT_SUBMIT_KIND ((volatile unsigned char *)0x3fccc8b0U)
#define REPORT_SUBMIT_METADATA44 ((volatile unsigned char *)0x3fccc8a8U)
#define REPORT_SUBMIT_METADATA48 ((volatile unsigned int *)0x3fccc890U)
#define REPORT_SUBMIT_METADATA50 ((volatile unsigned int *)0x3fccc878U)
#define REPORT_SUBMIT_SPECIAL ((volatile unsigned char *)0x3fccc860U)
#define REPORT_SUBMIT_LENGTH ((volatile unsigned char *)0x3fccc870U)
#define REPORT_SUBMIT_SPLIT ((volatile unsigned char *)0x3fccc868U)
#define REPORT_SUBMIT_TIME ((volatile TimestampWords *)0x3fccc810U)
#define REPORT_SUBMIT_CLEAR ((volatile unsigned char *)0x3fcc1064U)

/* These are offset views of input/descriptor state, not original full types. */
typedef struct BitClearField {
    unsigned short bit_offset;
    unsigned char width,ignored_field_data[9];
} BitClearField;
typedef struct BitClearLayout {
    unsigned char ignored_header[5],count,ignored_header_tail[2];
    BitClearField fields[];
} BitClearLayout;
/* Descriptor prefix view: BYTE mode selects no/primary/primary+secondary
 * normalization; HALF offsets index the bounded local report copy. The prefix
 * also supplies BitClearLayout's flexible fields; this is an overlapping view,
 * not a fixed-size bound on that descriptor's backing allocation. */
typedef struct ReportNormalizationView {
    unsigned char unmodeled_0[204];
    unsigned short primary_byte;
    unsigned char unmodeled_ce[4];
    unsigned short secondary_byte;
    unsigned char unmodeled_d4[4],mode;
} ReportNormalizationView;
typedef struct InputMotionSample {
    union {
        unsigned int packed_xy;
        struct { short x,y; };
    };
    unsigned int preserved_word4; /* Not written by history admission. */
    TimestampWords due;
} InputMotionSample;
typedef struct InputAxisLimits {
    int maximum,minimum;
    unsigned char enabled,preserved9[3];
} InputAxisLimits;

/* Report mapping is applied sequentially to the already-scaled mouse report.
 * operation1 swaps numeric source/destination fields. operation0/subtype3 adds
 * source into destination then clears source; other operation0 subtypes use
 * button_mode0 for button remap,1/2 for condition-bit-gated button clear.
 * The byte at +3 is not read by this processor. */
typedef struct InputMapRule {
    unsigned char operation,subtype,button_mode,unknown3;
    unsigned short source,destination;
} InputMapRule;
typedef struct InputMapTable {
    InputMapRule entries[32];
    unsigned char count;              /* +0x100; native walker does not cap32 */
} InputMapTable;
typedef struct InputStateView {
    union {
        ReportNormalizationView *descriptor;
        struct HidReportLayout *hid_layout;
    };
    unsigned int primary_words[4],secondary_words[4];
    union {
        unsigned char unknown24[148];
        struct {
            unsigned char reserved24[4];
            TimestampWords motion_deadline,motion_origin;
            InputMotionSample motion_history[8];
        };
    };
    union {
        unsigned short motion_history_state;
        struct {
            union { unsigned char primary_active,motion_history_count; };
            unsigned char motion_window_multiple;
        };
    };
    unsigned char unknownba[2];
    unsigned int motion_last_elapsed;
    TimestampWords motion_history_pace_time;
    union {
        unsigned short normalization_flags; /* paired native reset at +0xc8 */
        struct { unsigned char primary_normalization_flags,secondary_normalization_flags; };
    };
    unsigned short forced_buttons,cleared_buttons;
    unsigned char forced_keys[32],cleared_keys[32];
    unsigned short forced_consumers[8],cleared_consumers[8];
    unsigned char unknown12e[2];
    union {
        unsigned int primary_scale_pairs[8];
        unsigned short primary_scales[4][4];
    };
    int axis_scale_remainders[4][2];    /* [axis][positive/negative], divisor10000 */
    int bearing_remainder_x,bearing_remainder_y;
    unsigned int filter_runtime[4];
    unsigned char filter_active,unknown189[3];
    InputAxisLimits axis_limits[4];
    union {
        unsigned int button_scale_pairs[32];
        unsigned short button_scales[16][4];
    };
    unsigned short button_scale_state;
    unsigned char key_rising_suppression[32],key_falling_retention[32];
    unsigned char key_transition_state[32],keyboard_transform_flags,unknown29f;
    unsigned short consumer_transforms[8];
    unsigned char transform_mode,unknown2b1[3];
    InputMapTable *mapping_table;
    unsigned char mapping_conditions,saved_keys[32],unknown2d9;
    unsigned short saved_consumers[8];
    unsigned char changed,unknown2eb;
    struct InputEventStorage *event_storage;
    union {
        unsigned int publication_pair;
        struct {
            union {
                unsigned short active_count_and_flags;
                struct { unsigned char active_event_count,active_event_blocked; };
            };
            union {
                unsigned short published_count_and_flags;
                struct { unsigned char published_event_count,published_event_blocked; };
            };
        };
    };
    unsigned char dirty,events_published;
    union {
        unsigned short queued_cursor;
        struct { unsigned char queued_event_count,queued_event_head; };
    };
} InputStateView;
/* Native early return at 0x403793c0 does not initialize status3 or the upper
 * 24 bits of auxiliary. Their zero value must not be assumed on that path. */
typedef struct ReportQueueResult {
    unsigned char status0,dropped,secondary,status3;
    InputStateView *dirty_state;
    unsigned int auxiliary,zero;
} ReportQueueResult;

void input_mark_dirty(InputStateView *state);
int input_has_primary_activity(const InputStateView *state);
int input_has_secondary_activity(const InputStateView *state);
void report_clear_layout_bits(const BitClearLayout *layout,
    unsigned char *report,unsigned int length);
int report_prefix_has_pending_kind(const CreditInterfaceQueue *queue);
/* Historical pointer/word declarations for caller bodies still queued. */
void FUN_4038c838(int state) __asm__("input_mark_dirty");
int FUN_4038caa0(int *state) __asm__("input_has_primary_activity");
unsigned int FUN_4038cac0(int state) __asm__("input_has_secondary_activity");
void FUN_4039a0e4(int layout,int report,unsigned int length)
    __asm__("report_clear_layout_bits");
int FUN_403771c0(int queue) __asm__("report_prefix_has_pending_kind");

/* Queue admission returns four register words A2..A5. */
ReportQueueResult report_queue_update(CreditInterfaceQueue *queue,
    const unsigned char *report,unsigned int length,unsigned int kind,
    unsigned int metadata44,unsigned int metadata48,unsigned char mode,
    unsigned char options,unsigned int normalized_hash,unsigned char short_multiple,
    unsigned int source_interface,unsigned char allow_recovery,
    unsigned long long now_us,unsigned short period,unsigned int interface,
    unsigned int epoch);

/* Reconstructed source utility, not an additional native firmware entry.
 * Keep LOW-before-HIGH sampling explicit for the queue timestamp views. */
static inline unsigned long long report_read_time(
    const volatile TimestampWords *time)
{
    unsigned int low = time->low;
    unsigned int high = time->high;
    return ((unsigned long long)high << 32) | low;
}
int usb_device_set_stall(unsigned char bus,unsigned char endpoint);
void decision_timer_arm(unsigned int deadline_low,int deadline_high);
/* Alarm request shared with the recovered GPTimer driver. Native caller
 * zeros the trailing alignment WORD as well. */
typedef struct Gptimer Gptimer;
typedef struct GptimerAlarmConfig {
    unsigned long long alarm_count,reload_count;
    unsigned int flags,padding20;
} GptimerAlarmConfig;
int gptimer_get_raw_count(Gptimer *timer,unsigned long long *count);
int gptimer_set_alarm_action(Gptimer *timer,const GptimerAlarmConfig *alarm);
#define DECISION_TIMER_HANDLE (*(Gptimer *volatile *)0x3fcc0ed4U)
#define DECISION_TIMER_DEADLINE (*(volatile TimestampWords *)0x3fcc0eb8U)
#define INPUT0_STATE ((InputStateView *)0x3fcaa850U)
#define REPORT_SERVICE_ACTIVE ((volatile unsigned char *)0x3fccc740U)
#define REPORT_BUFFERED_LENGTH ((volatile unsigned char *)0x3fccc5b8U)
#define REPORT_BUFFERED_STORAGE ((unsigned char *)0x3fccc5c0U)
#define REPORT_LAST_INPUT ((volatile TimestampWords *)0x3fccc588U)
#define REPORT_DEPTH_HIGH_WATER (*(volatile unsigned int *)0x3fccbd34U)
#define REPORT_QUEUES_DIRTY (*(volatile unsigned char *)0x3fcc0edaU)
#define REPORT_COMPARISON_LIMITS ((const volatile unsigned short *)0x3fccc9acU)

typedef struct ReportExtension26 {
    union {
        unsigned short words[13];
        struct {
            unsigned char override_bytes[16];
            short motion[4];
            unsigned char session_tag,flags;
        };
    };
} ReportExtension26;
typedef struct ReportSequenceEntry {
    unsigned int time_low;
    union {
        struct { unsigned char sequence,endpoint; };
        unsigned short sequence_endpoint;
    };
    unsigned char unmodeled6[2];
} ReportSequenceEntry;
typedef struct ReportSequenceWindow {
    ReportSequenceEntry entries[16];
    unsigned char latest_sequence;
} ReportSequenceWindow;
int report_sequence_allowed(unsigned int endpoint,unsigned char sequence);
int report_intercept_secondary(unsigned char endpoint,unsigned int source_stamp,
    unsigned char *report,unsigned short length,unsigned char flags);
void report_pump_secondary(unsigned int binding_index);
void report_enqueue_secondary(unsigned int endpoint,unsigned char *report,
    unsigned int length,unsigned int kind,unsigned int source_stamp,
    unsigned char synthetic,unsigned char flags);
void report_buffer_primary(unsigned int endpoint,unsigned char *report,unsigned short length);
unsigned int report_apply_rewrite(unsigned int traffic_class,unsigned int endpoint,
    unsigned int direction,unsigned char *report,unsigned int length,unsigned char *scratch,
    unsigned char **report_out,unsigned short *length_out,unsigned char *flags_out);
unsigned char clip_packet_rules_evaluate(unsigned int traffic_class,unsigned int endpoint,
    unsigned int direction,const unsigned char *payload,unsigned int length);
int __popcountsi2(unsigned int value);
void report_process(unsigned char endpoint,unsigned int source_stamp,
    unsigned char *report,unsigned short length,const unsigned char *extension,unsigned char flags);
/* Caller view of the raw capture emitter; no payload ownership is transferred. */
void capture_emit_raw(unsigned int traffic_class,unsigned int endpoint,unsigned int direction,
    unsigned char flags,unsigned int source_stamp,unsigned int subtype,void *payload,unsigned short length)
    __asm__("FUN_403783a8");
unsigned int FUN_420299c0(unsigned int endpoint,char sequence) __asm__("report_sequence_allowed");
void FUN_40399e40(int binding_index) __asm__("report_pump_secondary");
void FUN_4202e26c(unsigned int endpoint,void *report,unsigned int length,int kind,
    unsigned int stamp,unsigned char synthetic,unsigned char flags) __asm__("report_enqueue_secondary");
void FUN_420334c4(unsigned int endpoint,unsigned char *report,unsigned short length)
    __asm__("report_buffer_primary");
#define REPORT_SEQUENCE_WINDOW (*(volatile ReportSequenceWindow *)0x3fccc754U)
#define REPORT_SEQUENCE_LOCK (*(PortMuxWords *)0x3fcab500U)
#define REPORT_SECONDARY_QUEUES ((volatile CreditSecondaryQueue *)0x3fcc01b8U)
#define REPORT_SECONDARY_COUNTS ((volatile unsigned char *)0x3fcc01a8U)
#define REPORT_SECONDARY_HEADS ((volatile unsigned char *)0x3fcc01b0U)
#define REPORT_SECONDARY_IN_FLIGHT ((volatile unsigned char *)0x3fcc01a0U)
#define REPORT_SECONDARY_WEIGHT ((volatile unsigned char *)0x3fcc0120U)
#define REPORT_SECONDARY_EXPECTED_LENGTH ((volatile unsigned char *)0x3fcc0128U)
#define REPORT_SECONDARY_LENGTH ((volatile unsigned char *)0x3fcc0130U)
#define REPORT_SECONDARY_STALL_PENDING ((volatile unsigned char *)0x3fcc0158U)
#define REPORT_SECONDARY_STALLED ((volatile unsigned char *)0x3fcc0160U)
#define REPORT_SECONDARY_BLOCKED ((const volatile unsigned char *)0x3fcc0150U)
#define REPORT_SECONDARY_TIME ((volatile TimestampWords *)0x3fcc0168U)
#define REPORT_SECONDARY_STORAGE ((unsigned char *)0x3fcad458U)
#define REWRITE_RULES ((volatile RewriteRule *)0x3fcc8f88U)
#define REWRITE_COUNT (*(const volatile unsigned char *)0x3fcc9d8aU)
#define REWRITE_PAYLOAD_POOL ((const unsigned char *)0x3fcc9588U)
#define REWRITE_MUTEX (*(RtosQueue *volatile *)0x3fccbd3cU)
#define PACKET_TRIGGER_COUNT (*(const volatile unsigned char *)0x3fcc7d18U)

typedef struct ReportNumericField {
    union {
        unsigned int packed;
        struct { unsigned short bit_offset; unsigned char width,enabled; };
    };
    int minimum,maximum;
} ReportNumericField;
typedef struct ReportByteClamp {
    unsigned short byte_offset;
    short minimum,maximum;
} ReportByteClamp;

void report_insert_record(CreditInterfaceQueue *queue,unsigned int index,
    const unsigned char *report,unsigned int length,unsigned int kind,
    unsigned char metadata42,unsigned char metadata44,unsigned int metadata48,
    unsigned char special,unsigned int metadata50,int epoch);
/* Word signatures retained for pending callers; no implementation shims. */
void FUN_40377790(int queue,unsigned int index,void *report,unsigned int length,short kind,
    unsigned char metadata42,unsigned char metadata44,unsigned int metadata48,
    unsigned char special,unsigned int metadata50,int epoch) __asm__("report_insert_record");
#define REPORT_MERGE_ACCUMULATORS ((volatile int *)0x3fcc0ec4U)
#define REPORT_MERGE_PENDING (*(volatile unsigned char *)0x3fcc0ec0U)
#define REPORT_MERGE_COUNT (*(volatile unsigned int *)0x3fccb60cU)

typedef struct HidBitmapRange {
    unsigned short bit_offset,count,usage_base;
} HidBitmapRange;
typedef struct HidKeyboardLayout {
    unsigned char enabled,report_id;
    unsigned short expected_length,modifier_bit_offset;
    unsigned char modifier_width,bitmap_mode;
    unsigned short key_bit_offset;
    unsigned char key_count,key_width;
    union {
        unsigned char unknownc[4];
        struct { unsigned short usage_minimum,usage_maximum; };
    };
    HidBitmapRange ranges[8];
    union {
        struct { unsigned char range_count,unknown41[3]; };
        /* Parser's aggregate bitmap-key count, read at report-layout+0x11c. */
        struct { unsigned char reserved40[2]; unsigned short bitmap_key_count; };
    };
} HidKeyboardLayout;
typedef struct HidConsumerLayout {
    unsigned char enabled,report_id;
    unsigned short expected_length,bit_offset;
    unsigned char width,count;
} HidConsumerLayout;
typedef struct HidReportLayout {
    unsigned char enabled,unknown1;
    unsigned short expected_length;
    unsigned char report_id,field_count,unknown6[2];
    ReportNumericField fields[12],axes[4];
    unsigned short button_bit_offset;
    unsigned char button_count,unknowncb;
    ReportByteClamp byte_clamps[2];
    unsigned char output_count,unknownd9;
    HidKeyboardLayout keyboard;
    HidConsumerLayout consumer;
    union {
        unsigned char unknown126[10];
        /* Name describes the baseline request's byte gate at0x12a. */
        struct { unsigned char reserved126[4],baseline_capture_blocked,reserved12b[5]; };
        struct {
            unsigned short consumer_usage_minimum,consumer_usage_maximum;
            unsigned char raw_capture_safe,raw_reserved12b;
            unsigned short unsupported_bits,first_unsupported_bit;
        };
    };
} HidReportLayout;                             /* stride0x130 */

int report_buttons_equal(const HidReportLayout *layout,
    const unsigned char *stored,const unsigned char *incoming,unsigned short length);
void report_merge_fields(const HidReportLayout *layout,
    const unsigned char *selectors,unsigned char *stored,const unsigned char *incoming,
    unsigned short length,int *overflow);
int report_merge_interface(unsigned int interface_index,unsigned char *stored,
    const unsigned char *incoming,unsigned short length,unsigned char stored_kind,
    unsigned char incoming_kind);

/* Dynamic report binding, distinct from the1000-byte fixed primary/keyboard/
 * consumer blocks. The pending pipeline uses state+8, cached output+303 and
 * last input+343; the lookup itself reads only interface/length/layout ID. */
typedef struct ReportLayoutBinding {
    int interface;
    unsigned short expected_length;
    unsigned char unknown6[2];
    InputStateView state;
    unsigned short observed_buttons;
    unsigned char observed_buttons_valid;
    unsigned char previous_output[64],last_input[64];
    unsigned char last_input_valid;
    union {
        unsigned short suppression_pair; /* native reset at +0x384 */
        struct { unsigned char unchanged_count,suppress_until_change; };
    };
    unsigned short last_buttons;
} ReportLayoutBinding;                         /* stride0x388 */
#define REPORT_BINDING_COUNT (*(volatile int *)0x3fcc9dd4U)
/* First observed-buttons-valid byte; subsequent bindings are904 bytes apart. */
#define REPORT_BINDING_CAPTURE_VALID_BYTES ((volatile unsigned char *)0x3fcca0daU)
#define REPORT_BINDINGS ((ReportLayoutBinding *)0x3fcc9dd8U)
ReportLayoutBinding *report_layout_find(int interface_index,
    const unsigned char *report,unsigned int length);
unsigned int report_controls_differ(const InputStateView *input_state,
    const unsigned char *current,const unsigned char *previous,unsigned int length);
unsigned int report_apply_output_rules(unsigned int interface_index,
    const unsigned char *input,unsigned int length,unsigned char *scratch,
    const unsigned char **report_out,unsigned short *length_out);

typedef struct InputTriggerRule {
    unsigned char traffic_class,ignored_byte1;
    unsigned short usage;
    unsigned char edge,action,suppress,ignored_byte7;
} InputTriggerRule;
#define INPUT_TRIGGER_COUNT (*(volatile unsigned char *)0x3fcc7d1cU)
#define CLIP_INPUT_TRIGGERS ((volatile ClipInputTrigger *)0x3fcc7d20U)
void clip_input_trigger_update(unsigned char input_class,unsigned short usage,
    unsigned char edge,unsigned char action,unsigned char flags);
#define INPUT_TRIGGERS ((InputTriggerRule *)0x3fcc7d20U)
#define INPUT_SUPPRESSION_COUNT (*(volatile unsigned char *)0x3fcc7b60U)
#define INPUT_SUPPRESSED_CONSUMERS ((volatile unsigned short *)0x3fcc7b64U)
#define INPUT_SUPPRESSED_KEYS ((volatile unsigned char *)0x3fcc7b74U)
#define INPUT_SUPPRESSED_BUTTONS (*(volatile unsigned short *)0x3fcc7b94U)
#define INPUT1_STATE ((InputStateView *)0x3fcaac38U)
#define INPUT2_STATE ((InputStateView *)0x3fcab020U)
#define INPUT1_ENABLED (*(const volatile unsigned char *)0x3fcaac34U)
#define INPUT2_ENABLED (*(const volatile unsigned char *)0x3fcab01cU)
InputTriggerRule *input_find_trigger(unsigned int traffic_class,
    unsigned int usage,unsigned int edge);
void input_suppress_button(unsigned int button,int suppress);
void input_suppress_key(unsigned int usage,int suppress);
void input_suppress_consumer(unsigned int usage,int suppress);
unsigned char *FUN_42028388(unsigned int traffic_class,unsigned int usage,unsigned int edge)
    __asm__("input_find_trigger");
void FUN_42028e1c(unsigned int button,int suppress) __asm__("input_suppress_button");
void FUN_42028f2c(unsigned int usage,int suppress) __asm__("input_suppress_key");
void FUN_42028fcc(unsigned int usage,int suppress) __asm__("input_suppress_consumer");
typedef struct InputEvent {
    union {
        unsigned short header;
        struct { unsigned char kind,action; };
    };
    unsigned short value;
} InputEvent;
typedef struct InputEventStorage {
    InputEvent active[16];
    InputEvent *queued;
    unsigned char capacity,ignored_padding[3];
} InputEventStorage;

/* Source utility for repeated inlined native extraction,not another entry.
 * Bits wrap16, word positions wrap32; an out-of-span bit stops extraction. */
static inline unsigned int hid_read_bits(const unsigned char *report,
    unsigned int length,unsigned int bit_offset,unsigned int width)
{
    unsigned int value = 0;
    const volatile unsigned char *bytes = report;
    for (unsigned int index = 0; index < width; ++index) {
        unsigned int bit = (bit_offset + index) & 65535U;
        unsigned int byte = bit >> 3;
        if (byte >= length)
            break;
        if (((bytes[byte] >> (bit & 7U)) & 1U) != 0)
            value |= 1U << (index & 31U);
    }
    return value;
}
static inline int hid_sign_extend(unsigned int value,unsigned int width)
{
    if (width != 0 && width < 32 && (value & (1U << (width - 1))) != 0)
        value |= 0xffffffffU << width;
    return (int)value;
}

int input_has_forced_controls(const InputStateView *state);
unsigned char input_has_transforms(const InputStateView *state);
int hid_report_needs_update(const HidReportLayout *layout,
    const unsigned char *incoming,const unsigned char *previous,unsigned int length);
unsigned char input_publish_events(InputStateView *state);
unsigned char input_events_were_published(const InputStateView *state);
void hid_decode_mouse(const InputStateView *state,const unsigned char *report,
    unsigned short *buttons,short *x,short *y,short *wheel,short *pan);
void input_accumulate_motion(InputStateView *state,short x,short y,short wheel,short pan);
void input_select_normalization_channels(InputStateView *state,const unsigned char *report);
unsigned long long input_motion_magnitude(const InputStateView *state);
int input_has_saved_controls(const InputStateView *state);
void input_drain_queued_events(InputStateView *state);
unsigned char input_event_would_block(const InputStateView *state,
    unsigned int kind,unsigned int value);
unsigned int hid_decode_keyboard(const HidKeyboardLayout *layout,
    const unsigned char *report,unsigned int length,unsigned char *modifiers,
    unsigned char *keys,unsigned int capacity);
unsigned char hid_keyboard_has_rollover(const HidKeyboardLayout *layout,
    const unsigned char *report,int length);
unsigned int hid_decode_consumer(const HidConsumerLayout *layout,
    const unsigned char *report,unsigned int length,unsigned short *usages,unsigned int capacity);
/* Legacy native-word callers remain until their own bodies are recovered. */
int FUN_4038c508(int state) __asm__("input_has_forced_controls");
unsigned char FUN_4038c55c(int state) __asm__("input_has_transforms");
int FUN_4038c5dc(int layout,const void *incoming,const void *previous,unsigned int length)
    __asm__("hid_report_needs_update");
unsigned char FUN_4038c7f4(int state) __asm__("input_publish_events");
unsigned char FUN_4038c848(int state) __asm__("input_events_were_published");
void FUN_4038c854(void *state,int report,unsigned short *buttons,short *x,short *y,short *wheel,short *pan)
    __asm__("hid_decode_mouse");
void FUN_4038cadc(int state,short x,short y,short wheel,short pan)
    __asm__("input_accumulate_motion");
void FUN_4038cbcc(int *state,int report) __asm__("input_select_normalization_channels");
unsigned long long FUN_4038cd28(int state) __asm__("input_motion_magnitude");
int FUN_4038f298(int state) __asm__("input_has_saved_controls");
void FUN_4038f2d4(int state) __asm__("input_drain_queued_events");
unsigned char FUN_42025d00(int state,unsigned int kind,unsigned int value)
    __asm__("input_event_would_block");
unsigned int FUN_42026a60(int layout,int report,unsigned int length,unsigned char *modifiers,
    void *keys,unsigned int capacity) __asm__("hid_decode_keyboard");
unsigned char FUN_42026bc0(int layout,int report,int length) __asm__("hid_keyboard_has_rollover");
unsigned int FUN_42027230(int layout,int report,unsigned int length,unsigned short *usages,
    unsigned int capacity) __asm__("hid_decode_consumer");
void input_apply_event(InputStateView *state,unsigned int kind,
    unsigned int value,int action);
typedef struct InputScaleSnapshot {
    unsigned short primary[4][4],buttons[16][4];
} InputScaleSnapshot;
void input_usage_set_update(unsigned short *slots,unsigned int value,int enabled);
void input_enqueue_event(InputStateView *state,unsigned short kind,
    unsigned short value,unsigned char action);
unsigned int input_update_saved_control(InputStateView *state,
    unsigned char kind,unsigned int value,unsigned int requested);
unsigned int input_clear_saved_controls(InputStateView *state);
unsigned char *input_reset_scales(InputStateView *state);
void input_reset_runtime(InputStateView *state);
void input_clear_forced_controls(InputStateView *state);
unsigned int input_publication_is_blocked(const InputStateView *state);
void input_set_consumer_transform(InputStateView *state,
    short value,unsigned char enabled);
void input_copy_scales(const InputStateView *state,InputScaleSnapshot *output);
void input_restore_scales(InputStateView *state,const InputScaleSnapshot *input);
void input_bind_event_storage(InputStateView *state,InputEventStorage *storage);
unsigned char input_has_pending_work(const InputStateView *state);
unsigned char input_needs_service(const InputStateView *state);
unsigned int input_has_button_overrides(const InputStateView *state);
unsigned short input_forced_buttons(const InputStateView *state);
unsigned int input_set_keyboard_transform_flags(InputStateView *state,
    unsigned char selection,unsigned char enabled);
void input_set_transform_mode(InputStateView *state,unsigned char enabled);
void input_scale_snapshot_defaults(InputScaleSnapshot *snapshot);
/* Native-word aliases for callers still queued for reconstruction. */
void FUN_42025d54(int *state,int kind,unsigned int value,int action)
    __asm__("input_apply_event");
void FUN_42026bf8(unsigned short *slots,unsigned int value,int enabled)
    __asm__("input_usage_set_update");
void FUN_420264ac(int state,unsigned short kind,unsigned short value,unsigned char action)
    __asm__("input_enqueue_event");
unsigned int FUN_42026584(int state,char kind,unsigned int value,unsigned int requested)
    __asm__("input_update_saved_control");
unsigned int FUN_42026648(int state) __asm__("input_clear_saved_controls");
int FUN_42025bdc(int state) __asm__("input_reset_scales");
void FUN_420266ac(int state) __asm__("input_reset_runtime");
void FUN_42026854(int state) __asm__("input_clear_forced_controls");
unsigned int FUN_42026988(int state) __asm__("input_publication_is_blocked");
void FUN_420269a8(int state,short value,unsigned char enabled)
    __asm__("input_set_consumer_transform");
void FUN_420269c0(int state,void *output) __asm__("input_copy_scales");
void FUN_420269e8(int state,const void *input) __asm__("input_restore_scales");
void FUN_42026c38(int state,int storage) __asm__("input_bind_event_storage");
unsigned char FUN_42026c50(int state) __asm__("input_has_pending_work");
unsigned char FUN_42026c68(int state) __asm__("input_needs_service");
unsigned int FUN_42026c84(int state) __asm__("input_has_button_overrides");
unsigned short FUN_42026c9c(int state) __asm__("input_forced_buttons");
unsigned int FUN_42026f58(int state,unsigned char selection,char enabled)
    __asm__("input_set_keyboard_transform_flags");
void FUN_42026f90(int state,char enabled) __asm__("input_set_transform_mode");
void FUN_42026fa4(unsigned short *snapshot) __asm__("input_scale_snapshot_defaults");

/* Reconstructed helper for repeated native signed 64-bit saturation.
 * value is the complete sum; return an int clamped to +/-0x40000000.
 * No firmware state is read or written; no lock or barrier is taken. */
static inline int input_clamp_motion_sum(long long value)
{
    if (value < -0x40000000LL)
        value = -0x40000000LL;
    if (value > 0x40000000LL)
        value = 0x40000000LL;
    return (int)value;
}
void input_accumulate_timed_motion(InputStateView *state,
    short x,short y,short wheel,short pan,unsigned long long now_us,unsigned int window_us);
void input_admit_timed_motion(InputStateView *state,short x,short y,
    unsigned long long now_us,unsigned int delay_us,unsigned int interval_us,unsigned int elapsed_us);
void input_flush_motion_history(InputStateView *state);
void input_refresh_axis_limits(InputStateView *state);
void input_bind_layout(InputStateView *state,HidReportLayout *layout);
void input_initialize(InputStateView *state,HidReportLayout *layout);
void input_update_axis_limits(InputStateView *state);
void hid_apply_numeric_delta(unsigned char *report,unsigned int length,
    ReportNumericField field,int *remaining,int delta);
/* Legacy word boundaries for caller bodies still pending. A7 is alignment
 * padding in the first signature,A5 in the second; neither is a logical input. */
void FUN_420260c4(int state,short x,short y,short wheel,short pan,unsigned int padding,
    unsigned int now_low,int now_high,unsigned int window_us)
    __asm__("input_accumulate_timed_motion");
void FUN_420261d8(int state,short x,short y,unsigned int padding,
    unsigned int now_low,int now_high,unsigned int delay,unsigned int interval,unsigned int elapsed)
    __asm__("input_admit_timed_motion");
void FUN_42026384(unsigned int *state) __asm__("input_flush_motion_history");
void FUN_42025c58(int *state) __asm__("input_refresh_axis_limits");
void FUN_42025fac(int *state,int layout) __asm__("input_bind_layout");
void FUN_420260a4(void *state,unsigned int layout) __asm__("input_initialize");
void FUN_42026a10(unsigned int state) __asm__("input_update_axis_limits");
void FUN_4038c298(int report,unsigned int length,unsigned int packed,int minimum,
    int maximum,int *remaining,int delta) __asm__("hid_apply_numeric_delta");

unsigned int input_set_scale_group(InputStateView *state,
    unsigned int channel,unsigned int selector,short value);
unsigned int input_set_key_transform(InputStateView *state,
    unsigned int usage,unsigned int mode,short value);
int input_get_scale(const InputStateView *state,
    unsigned int channel,unsigned int column);
void input_set_scale(InputStateView *state,
    unsigned int channel,unsigned int column,short value);
unsigned char input_get_keyboard_transform_flags(const InputStateView *state);
unsigned char input_get_transform_mode(const InputStateView *state);
unsigned int input_key_is_transformed(const InputStateView *state,unsigned int usage);
unsigned char input_consumer_is_transformed(const InputStateView *state,unsigned int usage);
unsigned int input_list_key_transforms(const InputStateView *state,
    unsigned short *usages,unsigned char *kinds,unsigned int capacity);
unsigned int input_list_consumer_transforms(const InputStateView *state,
    unsigned short *usages,unsigned int capacity);
unsigned int input_list_forced_keys(const InputStateView *state,
    unsigned short *usages,unsigned int capacity);
unsigned int input_list_forced_consumers(const InputStateView *state,
    unsigned short *usages,unsigned int capacity);
/* Legacy word-pointer names for callers whose bodies remain queued. */
unsigned int FUN_42026ca4(int state,unsigned int channel,unsigned int selector,short value)
    __asm__("input_set_scale_group");
unsigned int FUN_42026e1c(int state,unsigned int usage,unsigned int mode,short value)
    __asm__("input_set_key_transform");
int FUN_42027004(int state,unsigned int channel,unsigned int column)
    __asm__("input_get_scale");
void FUN_4202704c(int state,unsigned int channel,unsigned int column,short value)
    __asm__("input_set_scale");
unsigned char FUN_420270b0(int state) __asm__("input_get_keyboard_transform_flags");
unsigned char FUN_420270bc(int state) __asm__("input_get_transform_mode");
unsigned int FUN_420270c8(int state,unsigned int usage) __asm__("input_key_is_transformed");
unsigned char FUN_42027100(int state,unsigned int usage) __asm__("input_consumer_is_transformed");
unsigned int FUN_4202712c(int state,int usages,int kinds,unsigned int capacity)
    __asm__("input_list_key_transforms");
unsigned int FUN_42027190(int state,int usages,unsigned int capacity)
    __asm__("input_list_consumer_transforms");
unsigned int FUN_420271c4(int state,int usages,unsigned int capacity)
    __asm__("input_list_forced_keys");
unsigned int FUN_420271fc(int state,int usages,unsigned int capacity)
    __asm__("input_list_forced_consumers");

/* Motion configuration and independent views of shared runtime storage. */
typedef struct MotionOptions {
    unsigned char profile,unknown1;
    unsigned short spread;
    unsigned int bearing_window_us;
} MotionOptions;
typedef struct EmissionOptions {
    unsigned char unknown0[2];
    unsigned short learned_period;
    unsigned char unknown4,served_interval;
    unsigned short forced_hz;
    unsigned int period_us,learned_period_us;
    unsigned short configured_hz;
    unsigned char unknown12,scope,pace,unknown15[3];
} EmissionOptions;
typedef struct MotionResetView {
    unsigned char preserved_00[4];
    unsigned int primary_words[4];
    unsigned char preserved_14[20];
    unsigned int riding_words[4];
    unsigned char riding_history[144],preserved_c8[136];
    int axis_scale_remainders[8];
    int bearing_remainder_x,bearing_remainder_y;
    unsigned char preserved_178[528];
} MotionResetView;                             /* auxiliary stride0x388 */
typedef struct MotionHistoryView {
    TimestampWords last_riding;
    unsigned char history16[16],history32[32];
} MotionHistoryView;
typedef struct SpreadObservationView {
    unsigned int observations;
    unsigned short mode_bucket,reserved6;
} SpreadObservationView;
#define MOTION_OPTIONS (*(volatile MotionOptions *)0x3fcaa840U)
#define EMISSION_OPTIONS (*(volatile EmissionOptions *)0x3fcc8054U)
#define MOVEMENT_RIDING_US (*(volatile unsigned int *)0x3fcc852cU)
#define BEARING_COUPLED (*(volatile unsigned char *)0x3fcc8528U)
#define MOTION_HISTORY (*(volatile MotionHistoryView *)0x3fcaabb0U)
#define SPREAD_OBSERVATIONS (*(const volatile SpreadObservationView *)0x3fcc820cU)
#define MOTION_RENDER_STATE (*(volatile unsigned char *)0x3fccb308U)
#define MOTION_INJECTION_PENDING (*(volatile unsigned char *)0x3fcc8066U)
void move_cursor(short dx,short dy,unsigned char flags);
void move_wheel(short delta,unsigned char flags);
void move_pan(short delta,unsigned char flags);
void inject_usage(unsigned char input_class,unsigned short usage,unsigned char action);
void lock_input(unsigned char input_class,unsigned short usage,
    unsigned char direction,short percent);
unsigned int input_set_motion_scale_group(unsigned int channel,
    unsigned int selector,short value);
#define FUN_42028dc8 input_set_motion_scale_group
void input_process_local_motion(int x,int y,int wheel,int pan,unsigned int flags);
#define FUN_4202df60 input_process_local_motion
/* Separate from the report interval learner: 128 command-gap buckets in
 * 250us units and a 128-entry ring of their BYTE indices. */
typedef struct InjectionIntervalHistory {
    unsigned short buckets[128];
    unsigned char ring[128];
    unsigned short cursor,sample_count;
    unsigned int observations;
    unsigned short mode,reserved18a;
} InjectionIntervalHistory;
#define INJECTION_INTERVAL_HISTORY (*(volatile InjectionIntervalHistory *)0x3fcc8088U)
#define INJECTION_LAST_TIME (*(volatile TimestampWords *)0x3fcc8080U)
#define MOTION_EFFECTIVE_SPREAD (*(const volatile unsigned int *)0x3fcc0118U)
#define MOTION_AUX_COUNT (*(const volatile int *)0x3fcc9dd4U)
#define MOTION_AUX_STATES ((MotionResetView *)0x3fcc9de0U)
#define MOTION_PRIMARY_STATE ((MotionResetView *)0x3fcaa850U)
#define IMPERFECT_FORWARDING_ALLOWED (*(const volatile unsigned char *)0x3fccbd41U)
#define CLONE_CAPACITY_EXCEEDED (*(volatile unsigned char *)0x3fccbd42U)
#define CLONE_OTHER_PROBLEM (*(const volatile unsigned char *)0x3fccbd47U)
#define CLONE_IMPERFECT (*(volatile unsigned char *)0x3fccbd40U)
#define CLONE_LOW_SPEED (*(const volatile unsigned char *)0x3fccbd48U)
#define CLONE_ACTIVE (*(volatile unsigned char *)0x3fcc4cdcU)
#define BOX_NAME ((char *)0x3fcc8034U)
#define BOX_DEFAULT_NAME ((const char *)0x3fcc8010U)
#define BOX_NAME_LOCK ((PortMuxWords *)0x3fcaa838U)
#define MOTION_REVISION ((volatile unsigned int *)0x3fcc0108U)
#define MOTION_TXWD_TASK (*(RtosTask *volatile *)0x3fcc0100U)
#define MOTION_RENDER_TOKEN (*(volatile unsigned char *)0x3fcaa7c0U)
#define MOTION_RENDER_ACK (*(volatile unsigned char *)0x3fcbfef6U)

void option_get_imperfect(unsigned char *allow,unsigned char *over_capacity,
    unsigned char *imperfect_clone);
void option_set_movement_riding(unsigned short window_ms);
void option_set_bearing(unsigned int window_ms,unsigned char coupled);
unsigned int option_set_emit(unsigned char pace,unsigned short rate_hz,unsigned int force_hz);
unsigned int option_set_render(unsigned char profile,unsigned char scope);
unsigned int option_set_spread(unsigned short spread);
void option_get_render(unsigned char *profile,unsigned char *scope,unsigned char *armed);
void option_get_emit(unsigned char *pace,unsigned short *rate_hz,
    unsigned short *effective_hz,unsigned short *force_hz,unsigned short *learned_period,
    unsigned char *forced_active);
void option_set_name(const unsigned char *name,unsigned int length);
unsigned int option_copy_name(char *output,unsigned int capacity);
void option_get_spread(unsigned short *configured,unsigned int *effective_duration);
void motion_reset_riding(MotionResetView *state);
unsigned char *motion_reset_bearing(MotionResetView *state);
unsigned int clone_forced_interval(void);
void motion_configuration_changed(void);
void motion_send_render_state(unsigned int state);
/* Existing caller bodies retain word signatures until their own review. */
void FUN_42026480(int state) __asm__("motion_reset_riding");
int FUN_42026fdc(int state) __asm__("motion_reset_bearing");
unsigned int FUN_42029070(void) __asm__("clone_forced_interval");
void FUN_40394a9c(void) __asm__("motion_configuration_changed");
void FUN_42029bd0(unsigned int state) __asm__("motion_send_render_state");
/* Profile settings use their reviewed typed boundaries. */
unsigned char settings_store_u16(const char *key,unsigned short value);
unsigned char settings_store_string(const char *key,const char *value);
int motion_link_send(unsigned int opcode,unsigned int sequence,
    const void *payload,unsigned int length) __asm__("FUN_420229e8");
int xTaskGenericNotifyFromISR(RtosTask *task,unsigned int index,
    unsigned int value,unsigned int action,unsigned int *previous_value,
    int *higher_priority_task_woken);

/* Split clock storage retains native32 access order and deliberately avoids
 * pretending that a pair is an atomic64 load/store. */
typedef struct ClockWords {
    unsigned int low,high;
} ClockWords;
typedef void (*ClockAlarmHandler)(void *argument);
#define CLOCK_TIME_LOCK ((NewlibLock *)0x3fcbde08U)
#define CLOCK_ADJUST_START ((volatile ClockWords *)0x3fcbde18U)
#define CLOCK_ADJUST_REMAINING ((volatile ClockWords *)0x3fcbde10U)
#define CLOCK_BOOT_LOCK ((NewlibLock *)0x3fcbde20U)
#define CLOCK_MICROSECONDS_OFFSET ((volatile ClockWords *)0x3fcbde28U)
#define CLOCK_SYSTEM_CORRECTION ((volatile ClockWords *)0x3fcbde38U)
#define CLOCK_HAL ((SystimerHal *)0x3fcbde40U)
#define CLOCK_ALARM_HANDLER ((ClockAlarmHandler volatile *)0x3fcbde4cU)
#define CLOCK_TICK_COUNT ((volatile unsigned int *)0x3fcbda9cU)
#define CLOCK_RTC_BOOT ((volatile ClockWords *)0x60008058U)
unsigned long long systimer_hal_get_counter_value(SystimerHal *hal,unsigned int counter_id);
unsigned long long systimer_ticks_to_us(unsigned long long ticks);
unsigned long long systimer_us_to_ticks(unsigned long long microseconds);
unsigned int xTaskGetTickCount(void);
long long esp_system_get_time(void);
unsigned long long adjust_boot_time(void);
unsigned long long esp_time_impl_get_time_since_boot(void);
void esp_time_impl_set_boot_time(unsigned long long boot_us);
unsigned long long esp_time_impl_get_boot_time(void);
void timer_alarm_isr(void *argument);
clock_t _times_r(struct _reent *reentrancy,struct tms *times);
int _gettimeofday_r(struct _reent *reentrancy,struct timeval *time,void *timezone);
int input_read_pending_axis(const InputStateView *state,
    unsigned int axis,unsigned int include_primary);
unsigned int input_filter_key_transition(InputStateView *state,
    unsigned int usage,unsigned int pressed);
void input_rewrite_report_timed(InputStateView *state,
    const unsigned char *input,unsigned int length,unsigned char *output,
    unsigned int flags,unsigned long long now_us);
void input_rewrite_report_defaults(InputStateView *state,
    const unsigned char *input,unsigned int length,unsigned char *output);
/* Native call view: A7 is unused64-bit alignment padding. */
void input_rewrite_report_native(InputStateView *state,
    const unsigned char *input,unsigned int length,unsigned char *output,
    unsigned int flags,unsigned long long now_us,const int *axis_override);
/* Legacy nine-word view for callers awaiting their own typed reconstruction. */
void FUN_4038ce28(int *state,char *input,unsigned int length,void *output,
    unsigned int flags,unsigned int padding,unsigned int now_low,
    unsigned int now_high,unsigned int *axis_override)
    __asm__("input_rewrite_report_native");
int FUN_4038cd8c(int state,unsigned int axis,unsigned int include_primary)
    __asm__("input_read_pending_axis");
unsigned int FUN_4038f37c(int state,unsigned int usage,unsigned int pressed)
    __asm__("input_filter_key_transition");
void FUN_42026a1c(unsigned int state,unsigned int input,unsigned int length,
    unsigned int output,unsigned int flags,unsigned int padding,
    unsigned int now_low,unsigned int now_high) __asm__("input_rewrite_report_timed");
void FUN_42026a40(unsigned int state,unsigned int input,unsigned int length,unsigned int output)
    __asm__("input_rewrite_report_defaults");
/* Native address aliases retain raw caller word boundaries pending review. */
clock_t FUN_4037703c(unsigned int reentrancy,void *times) __asm__("_times_r");
int FUN_40377084(unsigned int reentrancy,void *time) __asm__("_gettimeofday_r");
void FUN_403770f8(unsigned int argument) __asm__("timer_alarm_isr");
unsigned long long FUN_42007620(void) __asm__("adjust_boot_time");
unsigned long long FUN_42007780(void) __asm__("esp_time_impl_get_time_since_boot");
unsigned int FUN_40387998(void) __asm__("xTaskGetTickCount");
void FUN_4200779c(unsigned int low,unsigned int high) __asm__("esp_time_impl_set_boot_time");
unsigned long long FUN_420077c4(void) __asm__("esp_time_impl_get_boot_time");

/* Fixed primary, keyboard and consumer bindings. Dynamic bindings above have
 * a different904-byte layout; these blocks are1000 bytes apart. */
typedef struct FixedInputBinding {
    int interface;
    unsigned char enabled,unknown5;
    unsigned short expected_length;
    InputStateView state;                     /* +0x008 */
    unsigned char last_input[64];                   /* +0x300 */
    unsigned char last_input_valid,updated,unknown342[6];
    TimestampWords last_input_time;           /* +0x348 */
    unsigned short short_gap_run;
    unsigned char motion_seen,unknown353[5];
    TimestampWords last_processed;            /* +0x358 */
    TimestampWords extension_event_time;      /* +0x360 */
    TimestampWords idle_motion_anchor;        /* +0x368 */
    int retained_motion[4];                         /* +0x370 */
    TimestampWords retained_motion_time[4];   /* +0x380 */
    unsigned char previous_output[64];              /* +0x3a0 */
    union {
        unsigned short suppression_pair;
        struct { unsigned char unchanged_count,suppress_until_change; };
    };
    unsigned short last_buttons;
    unsigned char output_valid,unknown3e5[3];
} FixedInputBinding;
#define FIXED_INPUTS ((volatile FixedInputBinding *)0x3fcaa848U)
#define MOTION_REFERENCE_MODE (*(const volatile unsigned char *)0x3fcc8528U)
#define MOTION_HOLD_WINDOW (*(const volatile unsigned int *)0x3fcaa844U)

typedef struct CaptureProfileRule {
    unsigned short usage;
    unsigned char traffic_class,edge,ignored_field_data[2];
} CaptureProfileRule;
typedef struct CaptureProfile {
    CaptureProfileRule rules[43];
    unsigned char count,ignored_tail;                /* count +0x102 */
} CaptureProfile;
/* Control records0x0fxx use zero12/class13/edge14/count15. Motion record0x0c03
 * overlays bytes12..20 with class0 and four unaligned little-endian axes. */
typedef struct BufferedInputCapture {
    union {
        unsigned int header;
        struct { unsigned short kind,payload_length; };
    };
    unsigned int rule_mask,source_stamp;
    union {
        struct {
            union {
                unsigned short class_and_reserved;
                struct { unsigned char zero12,traffic_class; };
            };
            unsigned char edge,usage_count,usages[120];
        };
        struct {
            unsigned char motion_class,motion_axes[4][2],motion_reserved[115];
        };
    };
} BufferedInputCapture;                        /* stride136 */
#define CAPTURE_PROFILE_INDEX (*(volatile unsigned char *)0x3fcc7810U)
#define CAPTURE_CLASS_MASK (*(volatile unsigned short *)0x3fcc77ccU)
#define CAPTURE_PROFILES ((const volatile CaptureProfile *)0x3fcc7814U)
typedef struct ObservedButtonRule {
    unsigned short source_kind;
    unsigned char target_kind,ignored_byte3;
    unsigned short button,target_usage;
} ObservedButtonRule;
#define OBSERVED_BUTTON_RULES ((const volatile ObservedButtonRule *)0x3fcc8e84U)
#define OBSERVED_BUTTON_RULE_COUNT (*(const volatile unsigned char *)0x3fcc8f84U)
/* Configuration view of the same eight-byte rows used by report mapping. */
typedef struct TransformRule {
    union {
        unsigned int header;
        struct {
            union {
                unsigned short mode_source;
                struct { unsigned char mode,source_class; };
            };
            unsigned char destination_class,reserved3;
        };
    };
    union {
        unsigned int usages;
        struct { unsigned short source_usage,destination_usage; };
    };
} TransformRule;
#define TRANSFORM_RULES ((volatile TransformRule *)0x3fcc8e84U)
#define TRANSFORM_COUNT (*(volatile unsigned char *)0x3fcc8f84U)
#define TRANSFORM_FULL (*(volatile unsigned char *)0x3fcc8f85U)
void transform_update(unsigned char mode,unsigned char source_class,
    unsigned short source_usage,unsigned char destination_class,
    unsigned short destination_usage,unsigned char present);
unsigned int transforms_encode(unsigned char *output);
unsigned char transform_usage_supported(unsigned int input_class,unsigned int usage,
    const HidReportLayout *primary,const HidReportLayout *keyboard,
    const HidReportLayout *consumer);
#define FUN_42039a44 transform_usage_supported
#define OUTPUT_RESET_PENDING (*(volatile unsigned char *)0x3fcbfee8U)
#define FIXED_OUTPUT_MASK (*(volatile unsigned char *)0x3fcc7dc4U)
#define INPUT_TIMER_MUTEX (*(RtosQueue *volatile *)0x3fcc9db4U)
#define INPUT_TIMER_ARMED (*(volatile unsigned char *)0x3fcc9db0U)
#define PLAYBACK_ACTIVE (*(volatile unsigned char *)0x3fcc7fe9U)
#define PLAYBACK_MODE (*(volatile unsigned char *)0x3fcc7fe8U)
#define PLAYBACK_TIME (*(volatile TimestampWords *)0x3fcc7fe0U)
void input_set_motion_reference(InputStateView *state,
    int x,int y,int wheel,int pan,unsigned int mode);
void input_refresh_motion_reference(InputStateView *destination,
    unsigned long long now_us);
void input_update_idle_motion_anchor(unsigned long long now_us);
int capture_find_motion_rule(int x,int y,int wheel,int pan);
void capture_append_buttons(BufferedInputCapture *records,
    int *record_count,unsigned int source_stamp,unsigned int buttons,
    unsigned int edge,unsigned int button_count);
void input_reset_output_reports(void);
void input_refresh_endpoint_priorities(void);
void input_update_button_mappings(void);
void input_ensure_timer_armed(void);
unsigned int playback_apply_action(unsigned int action);
void dwc2_set_priority_mask(unsigned char bus,unsigned short mask);
void input_timer_rearm(void);
#define INPUT_TIMER_TARGET (*(volatile TimestampWords *)0x3fcc0e18U)
unsigned char input_get_timing_deadline(unsigned long long now_us,
    TimestampWords *deadline_ns);
void catch_action_timer_cb(void *unused_argument);
/* Retain the TX worker's pending split-word calling view. */
unsigned char FUN_4202aa4c(unsigned int now_low,int now_high,unsigned int *deadline_ns)
    __asm__("input_get_timing_deadline");
/* Legacy word signatures for older callers of the reviewed service/playback
 * entries. The typed interfaces below preserve their native calling ABI. */
void fixed_input_service_native(int binding,unsigned int source_stamp)
    __asm__("fixed_input_service");
/* Raw caller views retained until those calling bodies are reconstructed. */
void FUN_4038f280(int state,int x,int y,int wheel,int pan,unsigned int mode)
    __asm__("input_set_motion_reference");
void FUN_403925ac(int state,unsigned int padding,unsigned int low,unsigned int high)
    __asm__("input_refresh_motion_reference");
int FUN_403927a4(int x,int y,int wheel,int pan) __asm__("capture_find_motion_rule");
void FUN_4202aef0(void *records,int *count,unsigned int stamp,unsigned int buttons,
    unsigned int edge,unsigned int button_count) __asm__("capture_append_buttons");
void FUN_42029128(void) __asm__("input_reset_output_reports");
void FUN_42028c30(void) __asm__("input_refresh_endpoint_priorities");
void FUN_420290d0(unsigned int low,unsigned int high) __asm__("input_update_idle_motion_anchor");
void FUN_4202d948(void) __asm__("input_update_button_mappings");
void FUN_4202ac40(void) __asm__("input_ensure_timer_armed");
unsigned int FUN_4202a9ac(unsigned int action) __asm__("playback_apply_action");

/* Interval learner inlined into report_process, native40397469 onward.
 * Histogram bins are250 us; raw and multiplier rings each have256 slots.
 * The native code trusts cursor/count fields instead of bounding them. */
typedef struct ReportIntervalHistory {
    unsigned short histogram[128];
    unsigned char raw_buckets[256],multipliers[256];
    unsigned short cursor,sample_count;
    unsigned int total_count;
    unsigned short base_bucket,first_frequent,harmonic_bucket;
    unsigned char gap,classified,last_ratio,same_ratio_count;
} ReportIntervalHistory;
#define REPORT_INTERVAL_HISTORY (*(volatile ReportIntervalHistory *)0x3fcc8214U)
#define REPORT_INTERVAL_SEEN (*(volatile unsigned char *)0x3fcc8075U)
#define REPORT_INTERVAL_STAMP (*(volatile unsigned int *)0x3fcc8078U)
#define REPORT_LEARNED_PERIOD (*(volatile unsigned int *)0x3fcc807cU)
#define REPORT_PERIOD_DEBOUNCE (*(volatile unsigned short *)0x3fcc806aU)
#define REPORT_PENDING_THRESHOLD (*(volatile unsigned int *)0x3fcc806cU)
#define REPORT_ACTIVE_THRESHOLD (*(volatile unsigned int *)0x3fcc8070U)
#define PROFILE_PERIOD_PENDING (*(volatile unsigned char *)0x3fcc8074U)
#define PROFILE_BASELINE_PENDING (*(volatile unsigned char *)0x3fcc9dc4U)
#define PROFILE_NORMALIZATION_PENDING (*(volatile unsigned char *)0x3fcc9dbcU)
#define REPORT_CAPTURE_BUTTONS_VALID (*(volatile unsigned char *)0x3fcc4d25U)
#define REPORT_CAPTURE_BUTTONS (*(volatile unsigned short *)0x3fcc4d26U)
#define REPORT_TRIGGER_BUTTONS_VALID (*(volatile unsigned char *)0x3fcc7b5cU)
#define REPORT_TRIGGER_BUTTONS (*(volatile unsigned short *)0x3fcc7b5eU)
void report_merge_drain_motion(void);
void FUN_4202a1e4(void) __asm__("report_merge_drain_motion");
/* Keyboard baseline layout is shared by independently maintained capture and
 * live-trigger state. Native users trust the byte count when walking keys. */
typedef struct ReportKeyboardBaseline {
    unsigned char valid,count,modifiers,unknown3,keys[32];
} ReportKeyboardBaseline;
#define REPORT_KEYBOARD_CAPTURE (*(volatile ReportKeyboardBaseline *)0x3fcc4cf8U)
#define REPORT_KEYBOARD_TRIGGERS (*(volatile ReportKeyboardBaseline *)0x3fcc7b38U)
#define HID_REPORT_LAYOUTS ((HidReportLayout *)0x3fccb610U)
typedef struct ReportConsumerCapture {
    unsigned char valid,count;
    unsigned short usages[8];
} ReportConsumerCapture;
typedef struct ReportConsumerBaseline {
    unsigned char valid,count,unknown2[2];
    unsigned short usages[8];
} ReportConsumerBaseline;
#define REPORT_CONSUMER_CAPTURE (*(volatile ReportConsumerCapture *)0x3fcc4ce6U)
#define REPORT_CONSUMER_TRIGGERS (*(volatile ReportConsumerBaseline *)0x3fcc7b24U)

/* Shared report-pipeline controls; byte/word widths follow native accesses. */
#define REPORT_MUTEX (*(RtosQueue *volatile *)0x3fcc4cd8U)
#define REPORT_PROCESS_STATUS (*(unsigned char *)0x3fcc0e20U)
#define REPORT_WAKE_REQUEST (*(volatile unsigned char *)0x3fcc4ce4U)
#define REPORT_WAKE_RESUMES (*(volatile unsigned int *)0x3fcc4ce0U)
/* Host opcode0x37 carries these stale-until-refreshed telemetry values. */
typedef struct HostMotionStatusPacket {
    unsigned char flags,session;
    unsigned short metric_low,metric_high;
    unsigned short counted_drops_low,counted_drops_high;
    unsigned short other_drops_low,other_drops_high;
} HostMotionStatusPacket;
#define REPORTED_HOST_SESSION (*(volatile unsigned char *)0x3fcc010cU)
#define REPORTED_HOST_INTERVAL_METRIC (*(volatile unsigned int *)0x3fcc0118U)
#define REPORTED_HOST_COUNTED_RX_DROPS (*(volatile unsigned int *)0x3fcc0114U)
#define REPORTED_HOST_OTHER_RX_DROPS (*(volatile unsigned int *)0x3fcc0110U)
#define REPORT_BUSY_WATCHDOG_OBSERVATIONS (*(volatile unsigned int *)0x3fccbd30U)
void motion_receive_host_status(const void *payload,unsigned short length);
unsigned int report_merge_accept_count(void);
unsigned int report_primary_fallback_drop_count(void);
unsigned int forwarding_drop_count(void);
unsigned int report_queue_depth_high_water(void);
unsigned int report_busy_watchdog_count(void);
unsigned int report_wakeup_resume_count(void);
int primary_input_interface_is_selected(void);
#define FUN_42035f28 motion_receive_host_status
#define FUN_420394b0 report_merge_accept_count
#define FUN_420394c0 report_primary_fallback_drop_count
#define FUN_420394d0 forwarding_drop_count
#define FUN_420394f8 report_queue_depth_high_water
#define FUN_42039508 report_busy_watchdog_count
#define FUN_42039518 report_wakeup_resume_count
#define FUN_42039690 primary_input_interface_is_selected
/* Only bytes16..23 of the borrowed host feedback are read by this consumer. */
typedef struct HostMotionFeedback {
    unsigned char ignored_prefix[16];
    unsigned char x_le[2],y_le[2],wheel_le[2],pan_le[2];
} HostMotionFeedback;
void link_publish_poll_interval(void);
bool clone_is_configured(void);
unsigned int option_get_movement_riding_ms(void);
unsigned int option_get_bearing_window_ms(void);
unsigned char option_get_bearing_coupled(void);
void request_power_state_publish(void);
void request_remote_wakeup(void);
void input_apply_host_motion_feedback(const HostMotionFeedback *feedback);
void motion_reset_host_session(void);
#define FUN_420354ec link_publish_poll_interval
#define FUN_420355c8 clone_is_configured
#define FUN_420358dc option_get_movement_riding_ms
#define FUN_420359b8 option_get_bearing_window_ms
#define FUN_420359d0 option_get_bearing_coupled
#define FUN_42035db0 request_power_state_publish
#define FUN_42035e04 request_remote_wakeup
#define FUN_42035ef4 motion_reset_host_session
int usbd_send_remote_wakeup(unsigned char bus);
void usbd_event_resume_handler(unsigned char bus);

/* USB bus storage view used by wake/resume; native stride0xaf4. */
typedef void (*MediusUsbdBusEventHandler)(unsigned int bus,unsigned int event);
/* SETUP wire layout; consumers choose native BYTE/HALF/WORD access widths. */
typedef union {
    struct {
        unsigned char request_type,request;
        unsigned short value,index,length;
    };
    unsigned int words[2];
    unsigned char bytes[8];
} MediusUsbSetupPacket;
typedef struct MediusUsbdWakeBusView {
    union {
        unsigned char unknown0[0x81c];
        struct {
            union {
                unsigned char opaque0[24];
                struct {
                    MediusUsbSetupPacket setup;
                    unsigned char *transfer_cursor;
                    unsigned int transfer_remaining;
                    unsigned int response_length;
                    unsigned char send_zlp;
                    unsigned char padding15[3];
                };
            };
            MediusUsbdDescriptorPrefix *descriptors;
            union {
                unsigned char opaque1c[0x800];
                unsigned char request_buffer[2048];
            };
        };
    };
    MediusUsbdCoreState state;
    union {
        unsigned char unknown824[0x2cc];
        struct {
            void *ep0_queue;
            void *ep0_task;
            /* Native storage extents; registration/dispatch do not enforce bounds. */
            union {
                unsigned char interface_pointer_storage[0x140];
                struct {
                    MediusUsbdClassEventView *interface_objects[16];
                    unsigned char alternate_settings[256];
                };
            };
            unsigned char interface_count;
            unsigned char padding96d[3];
            MediusUsbEndpointMetadata input_metadata[16];
            MediusUsbEndpointMetadata output_metadata[16];
        };
    };
    MediusUsbdBusEventHandler event_handler;
} MediusUsbdWakeBusView;
#define MEDIUS_USBD_WAKE_BUSES ((volatile MediusUsbdWakeBusView *)0x3fcbba9cU)
int usbd_set_remote_wakeup(unsigned char bus);

/* Playback records describe native storage, not an original SDK structure. */
typedef struct PlaybackTransformState {
    unsigned char timed_motion; /* 0: timed-motion playback enabled */
    unsigned char retain;
    unsigned char repeat; /* 2: repeat recorded playback */
    unsigned char selection; /* 3: axes/buttons/keyboard/consumer selection bits */
    unsigned char applied; /* 4: overrides have been applied */
    unsigned char consumer; /* 5: consumer mode enabled by playback */
    unsigned char keyboard; /* 6: keyboard flags enabled by playback */
    unsigned char preserved7; /* 7: untouched by playback reset */
    unsigned char scale_columns[20];
} PlaybackTransformState;
#define PLAYBACK_TRANSFORMS (*(volatile PlaybackTransformState *)0x3fcc7d60U)
#define PLAYBACK_RING ((ClipRing *)0x3fcc7fecU)
#define PLAYBACK_PROGRESS (*(volatile unsigned int *)0x3fcc7fdcU)
#define PLAYBACK_STATUS (*(volatile unsigned char *)0x3fcbfef4U)
#define PLAYBACK_ACTION_TIME (*(volatile TimestampWords *)0x3fcc7db0U)
#define PLAYBACK_ACTION_COUNT (*(volatile unsigned char *)0x3fcc7db8U)
#define PLAYBACK_ACTIONS ((const volatile unsigned char *)0x3fcc7dbcU)
#define PLAYBACK_ACTION_STORAGE ((volatile unsigned char *)0x3fcc7dbcU)
#define CLIP_ACTION_TIMER (*(EspTimer *volatile *)0x3fcc7dacU)
#define PLAYBACK_UNDERFLOWS (*(volatile unsigned short *)0x3fcc7fc8U)
#define PLAYBACK_STEPS (*(volatile unsigned int *)0x3fcc7fd4U)
#define CLIP_APPEND_SEQUENCE_VALID (*(volatile unsigned char *)0x3fcc7fd8U)
#define CLIP_APPEND_NEXT_SEQUENCE (*(volatile unsigned char *)0x3fcc7fd9U)
#define CLIP_APPEND_SHORT_WRITES (*(volatile unsigned short *)0x3fcc7fcaU)
#define CLIP_APPEND_SEQUENCE_ERRORS (*(volatile unsigned short *)0x3fcc7fccU)
unsigned int clip_ring_append(ClipRing *ring,const unsigned char *bytes,unsigned int length);
void clip_ring_finalize(ClipRing *ring);
void clip_append(const unsigned char *bytes,unsigned short length,unsigned char sequence);
void clip_control(unsigned char operation);
void clip_set(unsigned char setting,unsigned char value);
void input_timer_cb(void *unused_argument);
#define INPUT_CHANGE_WAKE_TIME (*(volatile TimestampWords *)0x3fcbe348U)
void clip_ring_clear(ClipRing *ring);
void clip_ring_rewind(ClipRing *ring);
unsigned int clip_ring_retained_bytes(const ClipRing *ring);
void playback_stop(int discard_pending_controls);
void playback_start(int restart);
void fixed_input_service(unsigned int index,unsigned int epoch);
void input_service_after_change(int changed);
#define FUN_4202a368 playback_stop
#define FUN_4202a3cc playback_start
#define FUN_4202ca54 fixed_input_service
#define FUN_4202dd98 input_service_after_change
/* Legacy word views retained for callers awaiting typed reconstruction. */
void fixed_input_emit_native(unsigned int index,unsigned int epoch) __asm__("fixed_input_emit");
void primary_input_emit_native(unsigned int low,unsigned int high,unsigned int mode,unsigned int epoch) __asm__("primary_input_emit");

void playback_release_controls(void);
void playback_restore_transforms(void);
void fixed_input_emit(unsigned int index,unsigned int epoch);
void primary_input_emit(unsigned long long now_us,int force,unsigned int epoch);
#define PRIMARY_INPUT_EMISSIONS (*(volatile unsigned int *)0x3fcc9d90U)
void FUN_4202a2e8(void) __asm__("playback_release_controls");
void FUN_420293f4(void) __asm__("playback_restore_transforms");
void FUN_4202c8d8(unsigned int index,unsigned int epoch) __asm__("fixed_input_emit");
void FUN_4202dab0(unsigned int low,unsigned int high,int force,unsigned int epoch)
    __asm__("primary_input_emit");

/* USB PHY storage/layout recovered from device-native lifecycle instructions. */
struct MediusUsbPhyExtIoConfig {
    int vp,vm,receive,suspend_n,output_enable_n,vp_out,vm_out,full_speed_edge;
};
typedef MediusUsbPhyExtIoConfig MediusUsbPhyExternalPins;
struct MediusUsbPhyOtgIoConfig {
    int iddig,avalid,vbusvalid,idpullup,dp_pulldown,dm_pulldown,drive_vbus;
    int bvalid,session_end,charge_vbus,discharge_vbus;
};
typedef MediusUsbPhyOtgIoConfig MediusUsbPhyOtgPins;
typedef struct { volatile unsigned int *dev; } MediusUsbWrapHal;
typedef struct MediusUsbPhyContext {
    unsigned int target,controller,status,otg_mode;
    MediusUsbPhyExternalPins *external_pins;
    MediusUsbWrapHal wrap;
} MediusUsbPhyContext;
typedef struct {
    MediusUsbPhyContext *internal,*utmi,*external;
    unsigned int references;
} MediusUsbPhyController;
typedef struct {
    int dp,dm;
} MediusUsbPhyInternalPins;
typedef struct {
    int iddig,avalid,bvalid,vbusvalid,session_end,idpullup,dp_pulldown;
    int dm_pulldown,drive_vbus,charge_vbus,discharge_vbus;
} MediusUsbPhyOtgSignals;
typedef struct {
    const MediusUsbPhyExternalPins *external;
    const MediusUsbPhyOtgSignals *otg;
    const MediusUsbPhyInternalPins *internal;
} MediusUsbPhySignalTable;

typedef MediusUsbPhyConfig MediusUsbPhyConfiguration;

unsigned int usb_new_phy(const MediusUsbPhyConfiguration *configuration,MediusUsbPhyContext **handle_out);
unsigned int usb_del_phy(MediusUsbPhyContext *handle);
unsigned int usb_phy_get_phy_status(unsigned int target,unsigned int *status_out);
unsigned int usb_phy_otg_set_mode(MediusUsbPhyContext *handle,unsigned int mode);
void _usb_wrap_hal_init(MediusUsbWrapHal *hal);
void _usb_wrap_hal_disable(void);
void usb_wrap_hal_phy_set_external(MediusUsbWrapHal *hal,unsigned char external);
void usb_serial_jtag_hal_phy_set_external(void *unused_hal,unsigned char external);
unsigned int phy_configure_pin_input(unsigned int pin,unsigned int signal);
unsigned int phy_configure_pin_output(unsigned int pin,unsigned int signal);
unsigned int gpio_set_drive_capability(unsigned int pin,unsigned int strength);
unsigned int rtc_gpio_is_valid_gpio(int pin);
void gpio_pad_select_gpio(unsigned int pin);
void gpio_matrix_in(unsigned int pin,unsigned int signal,unsigned int inverted);
void gpio_matrix_out(unsigned int pin,unsigned int signal,unsigned int inverted,unsigned int output_enable_inverted);
unsigned int gpio_input_enable(unsigned int pin);
void gpio_pad_unhold(unsigned int pin);
void periph_rcc_enter(void);
void periph_rcc_exit(void);
#define MEDIUS_USB_PHY_CONTROLLER (*(MediusUsbPhyController *volatile *)0x3fcd860cU)
#define MEDIUS_USB_PHY_LOCK (*(PortMuxWords *)0x3fcab58cU)
#define MEDIUS_USB_PHY_SIGNALS ((const volatile MediusUsbPhySignalTable *)0x3c046bbcU)
#define MEDIUS_USB_PHY_RTC_SELECTION (*(volatile unsigned int *)0x60008120U)
#define USB_SERIAL_JTAG_CONFIGURATION (*(volatile unsigned int *)0x60038018U)
#define MEDIUS_USB_WRAP_CLOCK_ENABLE (*(volatile unsigned int *)0x600c0018U)
#define MEDIUS_USB_WRAP_RESET_ENABLE (*(volatile unsigned int *)0x600c0020U)
#define GPIO_CONFIGURATION_LOCK (*(PortMuxWords *)0x3fcab9ccU)
#define GPIO_LOG_TAG ((const char *)0x3c04379cU)
/* Source reconstruction utility for the three native shifted GPIO masks.
 * The native signed rejection plus six-bit mask aliases positive pins>=64;
 * preserving that behavior is deliberate, rather than adding a range check. */
static __inline__ int gpio_native_pin_valid(unsigned int pin)
{
    unsigned int index = pin & 63U;
    return (pin & 0x80000000U) == 0 && (index <= 21U || (index >= 26U && index <= 48U));
}
#define FUN_4200d1c0 phy_configure_pin_input
#define FUN_4200ddf4 gpio_set_drive_capability
#define FUN_4200e3a4 rtc_gpio_is_valid_gpio
#define FUN_4201151c usb_serial_jtag_hal_phy_set_external
#define FUN_420115ac _usb_wrap_hal_init
#define FUN_420115e8 _usb_wrap_hal_disable
#define FUN_42011600 usb_wrap_hal_phy_set_external

/* Published20-byte link-clock estimate; fields are sampled under its mux. */
typedef struct LinkClockEstimate {
    unsigned int offset_us;
    int drift_ppb;
    unsigned int round_trip_us;
    unsigned int reference_us_low;
    union {
        unsigned short flags;
        struct { unsigned char ready,drift_valid; };
    };
    unsigned char reserved18[2];
} LinkClockEstimate;
#define LINK_CLOCK_ESTIMATE ((volatile LinkClockEstimate *)0x3fcd79c4U)
#define LINK_CLOCK_LOCK (*(PortMuxWords *)0x3fcab554U)
#define LINK_SYNC_FILTER_SCRATCH ((unsigned char *)0x3fcd79dcU)
#define LINK_SYNC_QUEUE (*(RtosQueue * volatile *)0x3fcd79d8U)
void link_start_sync_task(unsigned int startup_role);
void link_read_sync_status(unsigned int *offset_us,unsigned int *drift_ppb,
    unsigned short *round_trip_us,unsigned short *sample_age_ms,
    unsigned char *ready,unsigned char *drift_valid);
#define FUN_420226dc link_read_sync_status

/* VFS descriptor rows and the accessed prefixes of registered objects.
 * The status-buffer layout and later operation/entry fields are not accessed
 * by these dispatchers. Pointer widths and all used offsets are native32. */
/* SDK-compatible Newlib stat layout. Buffer sizing consumes mode+4 and
 * block_size+72. Other field names/types describe the checked SDK ABI; they do
 * not assert which fields any particular VFS backend populates. */
typedef struct VfsTimespec {
    long long seconds;
    long nanoseconds;
    unsigned int tail_padding;
} __attribute__((aligned(8))) VfsTimespec;
typedef struct VfsStat {
    short device;                           /* +0x00 */
    unsigned short inode;                   /* +0x02 */
    unsigned long mode;                     /* +0x04 */
    union {
        struct {unsigned short link_count;unsigned short user_id;}; /* +0x08/+0x0a */
        unsigned int link_user_word;         /* native combined store */
    };
    unsigned short group_id;                /* +0x0c */
    short special_device;                   /* +0x0e */
    long size;                              /* +0x10 */
    unsigned int time_alignment_padding;    /* +0x14 */
    VfsTimespec accessed;              /* +0x18 */
    VfsTimespec modified;              /* +0x28 */
    VfsTimespec changed;               /* +0x38 */
    long block_size;                        /* +0x48 */
    long block_count;                       /* +0x4c */
    long spare[2];                          /* +0x50 */
} __attribute__((aligned(8))) VfsStat;   /* 88 bytes */
typedef struct {
    unsigned char flags;
    signed char driver_index;
    unsigned char local_descriptor;
} MediusVfsDescriptor;
typedef union VfsWriteOperation {
    ssize_t (*plain)(int descriptor,const void *data,size_t length);
    ssize_t (*with_context)(void *context,int descriptor,const void *data,size_t length);
} VfsWriteOperation;
typedef union VfsSeekOperation {
    off_t (*plain)(int descriptor,off_t offset,int origin);
    off_t (*with_context)(void *context,int descriptor,off_t offset,int origin);
} VfsSeekOperation;
typedef union VfsReadOperation {
    ssize_t (*plain)(int descriptor,void *data,size_t length);
    ssize_t (*with_context)(void *context,int descriptor,void *data,size_t length);
} VfsReadOperation;
typedef union VfsCloseOperation {
    int (*plain)(int descriptor);
    int (*with_context)(void *context,int descriptor);
} VfsCloseOperation;
typedef union VfsStatOperation {
    int (*plain)(int descriptor,VfsStat *status);
    int (*with_context)(void *context,int descriptor,VfsStat *status);
} VfsStatOperation;
typedef union VfsControlOperation {
    int (*plain)(int descriptor,int command,int argument);
    int (*with_context)(void *context,int descriptor,int command,int argument);
} VfsControlOperation;
typedef union VfsOpenOperation {
    int (*plain)(const char *path,int flags,int mode);
    int (*with_context)(void *context,const char *path,int flags,int mode);
} VfsOpenOperation;
typedef union VfsPathStatOperation {
    int (*plain)(const char *path,VfsStat *status);
    int (*with_context)(void *context,const char *path,VfsStat *status);
} VfsPathStatOperation;
typedef union VfsPathPairOperation {
    int (*plain)(const char *first,const char *second);
    int (*with_context)(void *context,const char *first,const char *second);
} VfsPathPairOperation;
typedef union VfsPathOperation {
    int (*plain)(const char *path);
    int (*with_context)(void *context,const char *path);
} VfsPathOperation;
typedef union VfsPathAccessOperation {
    int (*plain)(const char *path,int access_mode);
    int (*with_context)(void *context,const char *path,int access_mode);
} VfsPathAccessOperation;
/* Full 64-byte directory callback table. Each union overlays context-free and
 * context-first SDK signatures. This registration code copies their raw words. */
typedef struct VfsDirectoryOperations {
    VfsPathStatOperation status;        /* +0x00 */
    VfsPathPairOperation link;          /* +0x04 */
    VfsPathOperation unlink;            /* +0x08 */
    VfsPathPairOperation rename;        /* +0x0c */
    union {
        DIR *(*plain)(const char *path);
        DIR *(*with_context)(void *context,const char *path);
    } open_directory;                         /* +0x10 */
    union {
        struct dirent *(*plain)(DIR *directory);
        struct dirent *(*with_context)(void *context,DIR *directory);
    } read_directory;                         /* +0x14 */
    union {
        int (*plain)(DIR *directory,struct dirent *entry,struct dirent **result);
        int (*with_context)(void *context,DIR *directory,struct dirent *entry,struct dirent **result);
    } read_directory_reentrant;               /* +0x18 */
    union {
        long (*plain)(DIR *directory);
        long (*with_context)(void *context,DIR *directory);
    } tell_directory;                         /* +0x1c */
    union {
        void (*plain)(DIR *directory,long offset);
        void (*with_context)(void *context,DIR *directory,long offset);
    } seek_directory;                         /* +0x20 */
    union {
        int (*plain)(DIR *directory);
        int (*with_context)(void *context,DIR *directory);
    } close_directory;                        /* +0x24 */
    union {
        int (*plain)(const char *path,mode_t mode);
        int (*with_context)(void *context,const char *path,mode_t mode);
    } make_directory;                         /* +0x28 */
    VfsPathOperation remove_directory;        /* +0x2c */
    VfsPathAccessOperation access;            /* +0x30 */
    union {
        int (*plain)(const char *path,long length);
        int (*with_context)(void *context,const char *path,long length);
    } truncate_path;                          /* +0x34 */
    union {
        int (*plain)(int descriptor,long length);
        int (*with_context)(void *context,int descriptor,long length);
    } truncate_descriptor;                    /* +0x38 */
    union {
        int (*plain)(const char *path,const struct utimbuf *times);
        int (*with_context)(void *context,const char *path,const struct utimbuf *times);
    } set_times;                              /* +0x3c */
} VfsDirectoryOperations;

typedef union VfsPositionedReadOperation {
    ssize_t (*plain)(int descriptor,void *data,size_t length,off_t offset);
    ssize_t (*with_context)(void *context,int descriptor,void *data,size_t length,off_t offset);
} VfsPositionedReadOperation;
typedef union VfsPositionedWriteOperation {
    ssize_t (*plain)(int descriptor,const void *data,size_t length,off_t offset);
    ssize_t (*with_context)(void *context,int descriptor,const void *data,size_t length,off_t offset);
} VfsPositionedWriteOperation;
typedef union VfsIoctlOperation {
    int (*plain)(int descriptor,int command,va_list arguments);
    int (*with_context)(void *context,int descriptor,int command,va_list arguments);
} VfsIoctlOperation;
typedef union VfsSyncOperation {
    int (*plain)(int descriptor);
    int (*with_context)(void *context,int descriptor);
} VfsSyncOperation;

/* Borrowed terminal structures are passed through, not dereferenced here. */
struct termios;
typedef union VfsSetAttributesOperation {
    int (*plain)(int descriptor,int action,const struct termios *attributes);
    int (*with_context)(void *context,int descriptor,int action,const struct termios *attributes);
} VfsSetAttributesOperation;
typedef union VfsGetAttributesOperation {
    int (*plain)(int descriptor,struct termios *attributes);
    int (*with_context)(void *context,int descriptor,struct termios *attributes);
} VfsGetAttributesOperation;
typedef union VfsControlOneOperation {
    int (*plain)(int descriptor,int value);
    int (*with_context)(void *context,int descriptor,int value);
} VfsControlOneOperation;
typedef struct VfsTerminalOperations {
    VfsSetAttributesOperation set_attributes; /* +0x00 */
    VfsGetAttributesOperation get_attributes; /* +0x04 */
    VfsSyncOperation drain;                  /* +0x08 */
    VfsControlOneOperation flush;            /* +0x0c */
    VfsControlOneOperation flow;             /* +0x10: flow action */
    VfsSyncOperation session_id;             /* +0x14: signed pid_t result */
    VfsControlOneOperation send_break;       /* +0x18: break duration */
} VfsTerminalOperations;
typedef struct VfsSelectSemaphore {
    union {
        struct {bool is_sem_local;unsigned char padding[3];};
        unsigned int flags_word;
    };
    void *handle;
} VfsSelectSemaphore;
typedef int (*VfsStartSelectOperation)(int count,fd_set *read_set,
    fd_set *write_set,fd_set *error_set,VfsSelectSemaphore semaphore,void **end_arguments);
typedef int (*VfsEndSelectOperation)(void *arguments);
typedef struct VfsSelectOperations {
    VfsStartSelectOperation start;      /* +0x00 */
    int (*socket_select)(int count,fd_set *read_set,fd_set *write_set,
        fd_set *error_set,struct timeval *timeout); /* +0x04 */
    void (*stop_socket_select)(void *semaphore);    /* +0x08 */
    void (*stop_socket_select_from_isr)(void *semaphore,int *woken); /* +0x0c */
    void *(*get_socket_select_semaphore)(void);     /* +0x10 */
    VfsEndSelectOperation end;                     /* +0x14 */
} VfsSelectOperations;

typedef struct VfsOperations {
    VfsWriteOperation write;             /* +0x00 */
    VfsSeekOperation seek;               /* +0x04 */
    VfsReadOperation read;               /* +0x08 */
    VfsPositionedReadOperation read_at;  /* +0x0c */
    VfsPositionedWriteOperation write_at; /* +0x10 */
    VfsOpenOperation open;              /* +0x14 */
    VfsCloseOperation close;             /* +0x18 */
    VfsStatOperation status;             /* +0x1c */
    VfsControlOperation control;         /* +0x20 */
    VfsIoctlOperation ioctl;             /* +0x24 */
    VfsSyncOperation sync;               /* +0x28 */
    const volatile VfsDirectoryOperations *directory; /* +0x2c */
    const volatile VfsTerminalOperations *terminal; /* +0x30 */
    const volatile VfsSelectOperations *select;    /* +0x34 */
} VfsOperations;
typedef struct VfsDriverEntry {
    int flags;
    const volatile VfsOperations *operations;
    char path_prefix[15];                     /* +0x08 */
    unsigned char prefix_alignment_padding;
    unsigned int path_prefix_length;          /* +0x18 */
    void *context;                            /* +0x1c */
    int offset;                              /* +0x20: index in driver table */
} VfsDriverEntry;

int medius_vfs_write(NewlibReent *reent,int descriptor,const void *data,unsigned int length);
int medius_vfs_seek(NewlibReent *reent,int descriptor,int offset,int origin);
int medius_vfs_read(NewlibReent *reent,int descriptor,void *data,unsigned int length);
int medius_vfs_close(NewlibReent *reent,int descriptor);
int medius_vfs_status(NewlibReent *reent,int descriptor,VfsStat *status);
int medius_vfs_control(NewlibReent *reent,int descriptor,int command,int argument);
#define MEDIUS_VFS_DESCRIPTORS ((volatile MediusVfsDescriptor *)0x3fcaa6f0U)
#define VFS_DRIVER_COUNT (*(volatile unsigned int *)0x3fcbde68U)
#define VFS_DRIVERS ((const volatile VfsDriverEntry * volatile *)0x3fcbde6cU)
#define MEDIUS_VFS_DESCRIPTOR_LOCK (*(NewlibLock *)0x3fcbde64U)
#define FUN_42039fa4 medius_vfs_write
#define FUN_4203a010 medius_vfs_seek
#define FUN_4203a07c medius_vfs_read
#define FUN_4203a0e8 medius_vfs_close
#define FUN_4203a184 medius_vfs_status
#define FUN_4203a1ec medius_vfs_control

int vfs_close_current(int descriptor);
int vfs_status_current(int descriptor,VfsStat *status);
int vfs_read_current(int descriptor,void *data,unsigned int length);
int vfs_write_current(int descriptor,const void *data,unsigned int length);
int medius_newlib_stream_close(NewlibReent *reent,void *cookie);
#define FUN_42019000 vfs_close_current
#define FUN_42019018 vfs_status_current
#define FUN_42019094 vfs_read_current
#define FUN_420190b0 vfs_write_current
#define FUN_42018b00 medius_newlib_stream_close

/* Recovered Newlib small-reentrancy FILE layout, 104 bytes on Xtensa32.
 * Field offsets match the firmware accesses and the installed Newlib headers.
 * String-stream formatting initializes only its original prefix; naming the
 * remaining fields does not initialize them or change their ownership. */
struct __lock;
typedef struct {
    int count;
    union {unsigned int wide_value;unsigned char bytes[4];} value;
} MediusNewlibMultibyteState;
typedef struct NewlibFile {
    char *cursor;                              /* +0x00 */
    int read_remaining;                         /* +0x04 */
    int write_remaining;                        /* +0x08 */
    union {
        struct {unsigned short flags;short file_descriptor;}; /* +0x0c/+0x0e */
        unsigned int descriptor_flags;          /* native 32-bit reservation word */
    };
    char *buffer_base;                          /* +0x10 */
    int buffer_capacity;                        /* +0x14 */
    int line_write_remaining;                   /* +0x18 */
    NewlibReent *owner_reent;              /* +0x1c */
    void *cookie;                              /* +0x20 */
    int (*read_callback)(NewlibReent *,void *,char *,int);
    int (*write_callback)(NewlibReent *,void *,const char *,int);
    long (*seek_callback)(NewlibReent *,void *,long,int);
    int (*close_callback)(NewlibReent *,void *);
    char *ungetc_buffer;                        /* +0x34 */
    int ungetc_capacity;                        /* +0x38 */
    char *saved_cursor;                         /* +0x3c */
    int saved_read_remaining;                   /* +0x40 */
    unsigned char inline_ungetc[3];             /* +0x44 */
    unsigned char emergency_byte;               /* +0x47 */
    char *line_buffer;                          /* +0x48 */
    int line_buffer_capacity;                   /* +0x4c */
    int block_size;                             /* +0x50 */
    union {long cached_offset;unsigned long cached_offset_bits;}; /* +0x54 */
    struct __lock *lock;                        /* +0x58 */
    MediusNewlibMultibyteState multibyte_state;  /* +0x5c */
    int secondary_flags;                        /* +0x64 */
} NewlibFile;
typedef NewlibFile MediusNewlibStringStream;

/* Newlib FILE callbacks: lengths and offsets retain the native 32-bit ABI. */
int medius_newlib_stream_read(NewlibReent *reent,void *cookie,char *buffer,int length);
int medius_newlib_stream_write(NewlibReent *reent,void *cookie,const char *buffer,int length);
long medius_newlib_stream_seek(NewlibReent *reent,void *cookie,long offset,int origin);
#define FUN_42018a54 medius_newlib_stream_read
#define FUN_42018a88 medius_newlib_stream_write
#define FUN_42018ac4 medius_newlib_stream_seek

/* Global Newlib FILE pool and the four-FILE extension allocation. */
typedef int (*MediusNewlibFileVisitor)(NewlibReent *,NewlibFile *);
typedef void (*MediusNewlibGlobalCleanup)(void);
typedef struct {NewlibGlue glue;NewlibFile files[4];} MediusNewlibFileBlock;
void medius_newlib_initialize_file(NewlibFile *file,unsigned int flags,int descriptor);
void medius_newlib_cleanup_global_streams(void);
void medius_newlib_cleanup_context(NewlibReent *reent);
void medius_newlib_initialize_standard_streams(void);
void medius_newlib_file_pool_lock(void);
void medius_newlib_file_pool_unlock(void);
NewlibFile *medius_newlib_allocate_file(NewlibReent *reent);
void medius_newlib_initialize_stdio_context(NewlibReent *reent);
int medius_newlib_walk_streams(NewlibReent *reent,MediusNewlibFileVisitor visitor,NewlibGlue *root);
#define MEDIUS_NEWLIB_STANDARD_FILES ((NewlibFile *)0x3fcd871cU)
#define MEDIUS_NEWLIB_GLOBAL_CLEANUP (*(MediusNewlibGlobalCleanup volatile *)0x3fcd8854U)
#define MEDIUS_NEWLIB_STDIO_GLUE ((NewlibGlue *)0x3fcabb4cU)
#define MEDIUS_NEWLIB_STARTUP_REENT ((NewlibReent *)0x3fcabb5cU)
#define FUN_420183f4 medius_newlib_initialize_file
#define FUN_42018464 medius_newlib_cleanup_global_streams
#define FUN_42018478 medius_newlib_cleanup_context
#define FUN_420184b0 medius_newlib_initialize_standard_streams
#define FUN_420184e4 medius_newlib_file_pool_lock
#define FUN_420184f4 medius_newlib_file_pool_unlock
#define FUN_42018504 medius_newlib_allocate_file
#define FUN_420185b8 medius_newlib_initialize_stdio_context
#define FUN_420214a0 medius_newlib_walk_streams

/* Newlib FILE flushing and closure; callbacks use the complete FILE layout. */
int medius_newlib_close_file(NewlibReent *reent,NewlibFile *file);
int medius_newlib_flush_file_unlocked(NewlibReent *reent,NewlibFile *file);
int medius_newlib_flush_file(NewlibReent *reent,NewlibFile *file);
#define FUN_420181a0 medius_newlib_close_file
#define FUN_42018268 medius_newlib_flush_file_unlocked
#define FUN_4201839c medius_newlib_flush_file

/* FILE opening, mode decoding and buffer/write preparation. */
NewlibFile *medius_newlib_open_file(NewlibReent *reent,const char *path,const char *mode);
NewlibFile *medius_newlib_open_file_current(const char *path,const char *mode);
int medius_newlib_prepare_write(NewlibReent *reent,NewlibFile *file);
unsigned int medius_newlib_parse_file_mode(NewlibReent *reent,const char *mode,unsigned int *open_flags);
unsigned int medius_newlib_select_buffer_size(NewlibReent *reent,NewlibFile *file,int *capacity,unsigned int *is_character);
void medius_newlib_make_file_buffer(NewlibReent *reent,NewlibFile *file);
int medius_newlib_isatty_unsupported(NewlibReent *reent,int descriptor);
#define FUN_420185e4 medius_newlib_open_file
#define FUN_4201869c medius_newlib_open_file_current
#define FUN_42018bbc medius_newlib_prepare_write
#define FUN_420214d8 medius_newlib_parse_file_mode
#define FUN_4201f398 medius_newlib_select_buffer_size
#define FUN_4201f404 medius_newlib_make_file_buffer
#define FUN_42020ce8 medius_newlib_isatty_unsupported

/* VFS mount/path dispatch and native root-path literal. */
const char *medius_vfs_translate_path(const volatile VfsDriverEntry *entry,const char *path);
const volatile VfsDriverEntry *medius_vfs_find_path(const char *path);
int medius_vfs_open(NewlibReent *reent,const char *path,int flags,int mode);
int vfs_open_current(const char *path,int flags,...);
int medius_vfs_stat_path(NewlibReent *reent,const char *path,VfsStat *status);
int medius_vfs_link_path(NewlibReent *reent,const char *old_path,const char *new_path);
int medius_vfs_unlink_path(NewlibReent *reent,const char *path);
int medius_vfs_rename_path(NewlibReent *reent,const char *source,const char *destination);
int vfs_access_current(const char *path,int access_mode);
#define MEDIUS_VFS_ROOT_PATH ((const char *)0x3c041cf4U)
#define FUN_42039ca4 medius_vfs_translate_path
#define FUN_42039e40 medius_vfs_find_path
#define FUN_42039ebc medius_vfs_open
#define FUN_42019048 vfs_open_current
#define FUN_4203a2c8 medius_vfs_stat_path
#define FUN_4203a318 medius_vfs_link_path
#define FUN_4203a390 medius_vfs_unlink_path
#define FUN_4203a3e4 medius_vfs_rename_path
#define FUN_4203a464 vfs_access_current

/* Null-device callbacks and native static registration data. */
int null_vfs_open(const char *path,int flags,int mode);
int null_vfs_seek(int descriptor,int offset,int origin);
int null_vfs_status(int descriptor,VfsStat *status);
int null_vfs_control(int descriptor,int command,int argument);
int null_vfs_write(int descriptor,const void *data,unsigned int length);
int null_vfs_read(int descriptor,void *data,unsigned int length);
int null_vfs_read_at(int descriptor,void *data,unsigned int length,long offset);
int null_vfs_write_at(int descriptor,const void *data,unsigned int length,long offset);
int null_vfs_ioctl(int descriptor,int command,va_list arguments);
int null_vfs_close(int descriptor);
int null_vfs_sync(int descriptor);
int null_vfs_stat_path(const char *path,VfsStat *status);
int null_vfs_register(void);
int *__errno(void);
#define NULL_VFS_ACCESS_BITMAP (*(volatile unsigned int *)0x3fcbde8cU)
#define NULL_VFS_OPERATIONS ((const VfsOperations *)0x3c046414U)
#define FUN_42007de0 null_vfs_open
#define FUN_42007e90 null_vfs_seek
#define FUN_42007ecc null_vfs_status
#define FUN_42007f04 null_vfs_control
#define FUN_42007f28 null_vfs_write
#define FUN_42007fb8 null_vfs_read
#define FUN_42008008 null_vfs_read_at
#define FUN_42007fdc null_vfs_write_at
#define FUN_42007f94 null_vfs_ioctl
#define FUN_4200802c null_vfs_close
#define FUN_42008048 null_vfs_sync
#define FUN_42007f54 null_vfs_stat_path
#define FUN_42008064 null_vfs_register
#define FUN_42019030 gettimeofday

/* Console selection, shared descriptor/reference count and table callbacks. */
int console_start_select(int count,fd_set *read_set,fd_set *write_set,fd_set *error_set,VfsSelectSemaphore semaphore,void **end_select_arguments);
int console_end_select(void *arguments);
int console_write(int descriptor,const void *data,unsigned int length);
int console_status(int descriptor,VfsStat *status);
int console_read(int descriptor,void *data,unsigned int length);
int console_control(int descriptor,int command,int argument);
int console_sync(int descriptor);
int console_access(const char *path,int access_mode);
int console_set_attributes(int descriptor,int action,const struct termios *attributes);
int console_get_attributes(int descriptor,struct termios *attributes);
int console_drain(int descriptor);
int console_flush(int descriptor,int queue);
int console_open(const char *path,int flags,int mode);
int console_close(int descriptor);
int console_register(void);
int vfs_get_attributes_current(int descriptor,struct termios *attributes);
int vfs_set_attributes_current(int descriptor,int action,const struct termios *attributes);
int vfs_drain_current(int descriptor);
int vfs_flush_current(int descriptor,int queue);
int vfs_sync_current(int descriptor);
int vfs_control_current(int descriptor,int command,...);
const VfsOperations *null_vfs_get_operations(void);
#define CONSOLE_GET_BACKEND null_vfs_get_operations
#define CONSOLE_BACKEND_OPERATIONS (*(const volatile VfsOperations * volatile *)0x3fcbde60U)
#define CONSOLE_DESCRIPTOR (*(volatile int *)0x3fcbde58U)
#define CONSOLE_REFERENCE_COUNT (*(volatile unsigned int *)0x3fcbde54U)
#define CONSOLE_OPERATIONS ((const VfsOperations *)0x3c046368U)
#define CONSOLE_INITIAL_BACKEND ((const VfsOperations *)0x3c046414U)
#define CONSOLE_BACKING_PATH "/dev/null"
#define FUN_42007c44 console_start_select
#define FUN_42007c74 console_end_select
#define FUN_42007c90 console_write
#define FUN_42007ca8 console_status
#define FUN_42007cbc console_read
#define FUN_42007cd4 console_control
#define FUN_42007cec console_sync
#define FUN_42007d00 console_access
#define FUN_42007d14 console_set_attributes
#define FUN_42007d2c console_get_attributes
#define FUN_42007d40 console_drain
#define FUN_42007d54 console_flush
#define FUN_42007d68 console_open
#define FUN_42007d90 console_close
#define FUN_42007dc0 console_register
#define FUN_42008078 null_vfs_get_operations
#define FUN_4203a4c0 vfs_get_attributes_current
#define FUN_4203a538 vfs_set_attributes_current
#define FUN_4203a5b4 vfs_drain_current
#define FUN_4203a628 vfs_flush_current
#define FUN_4203a258 vfs_sync_current
#define FUN_420075ec vfs_control_current
#define CONSOLE_ACCESS_PATH "/dev/uart/-1"

/* Complete static UART context shape in this build: 48 bytes, stride0x30.
 * HAL device pointer is sampled at the native call boundary. */
typedef struct UartHal {
    UartRegisterView * volatile dev;
} UartHal;
typedef struct UartDriverContext {
    NewlibLock module_lock;             /* +0x00: lazy lock SLOT */
    int port;                                /* +0x04 */
    UartHal hal;                        /* +0x08 */
    PortMuxWords spinlock;              /* +0x0c */
    unsigned char hardware_enabled;          /* +0x14 */
    unsigned char padding_15[3];
    int tx_gpio;                             /* +0x18: -1 unassigned */
    int rx_gpio;                             /* +0x1c */
    int rts_gpio;                            /* +0x20 */
    int cts_gpio;                            /* +0x24 */
    unsigned long long reserved_gpio_mask;   /* +0x28 */
} UartDriverContext;
/* Reconstructed native QUOU boundary. Inline assembly retains the instruction's
 * behavior for a zero divisor and prevents motion across native memory reads. */
static __inline__ __attribute__((always_inline)) unsigned int uart_unsigned_divide(
    unsigned int numerator,unsigned int denominator)
{
    unsigned int quotient;
    __asm__ volatile ("quou %0, %1, %2" : "=a"(quotient) : "a"(numerator),"a"(denominator) : "memory");
    return quotient;
}
#define UART_DRIVER_CONTEXTS ((UartDriverContext *)0x3fcaba90U)
#define UART_LOG_TAG ((const char *)0x3c045210U)
void uart_hal_get_sclk(UartHal *hal,unsigned int *source_clock);
void uart_hal_set_stop_bits(UartHal *hal,unsigned int stop_bits);
void uart_hal_set_data_bit_num(UartHal *hal,unsigned int data_bits);
void uart_hal_set_parity(UartHal *hal,unsigned int parity_mode);
#define FUN_4202137c uart_hal_get_sclk

/* Native packed UART signal word: signed GPIO15/mux4, input1, matrix signal12.
 * Field packing is checked against the pinned ESP-IDF target declarations. */
typedef union UartSignalPin {
    unsigned int raw;
    struct {
        signed long default_gpio : 15;
        signed long iomux_function : 4;
        unsigned long input : 1;
        unsigned long signal : 12;
    };
} UartSignalPin;
typedef struct UartSignalConnection {
    UartSignalPin pins[4];
    unsigned char interrupt;
    unsigned char padding_11[3];
} UartSignalConnection;                  /* 20-byte stride */
#define UART_BUS_CLOCK0 (*(volatile unsigned int *)0x600c0018U)
#define UART_BUS_CLOCK1 (*(volatile unsigned int *)0x600c001cU)
#define UART_BUS_RESET0 (*(volatile unsigned int *)0x600c0020U)
#define UART_BUS_RESET1 (*(volatile unsigned int *)0x600c0024U)
int uart_try_set_iomux_pin(unsigned int port,unsigned int gpio,int signal_index);
void uart_release_pin(int port,int release_tx,int release_rx,int release_rts,int release_cts);
void uart_module_enable(unsigned int port);
#define UART_SIGNAL_CONNECTIONS ((const volatile UartSignalConnection *)0x3c046b80U)
#define UART_CONSOLE_PORT -1

void uart_hal_txfifo_rst(UartHal *hal);
void uart_hal_set_hw_flow_ctrl(UartHal *hal,unsigned int mode,unsigned char threshold);
void uart_hal_set_tx_idle_num(UartHal *hal,unsigned int idle_count);
void uart_hal_init(UartHal *hal,unsigned int port);
bool periph_rtc_dig_clk8m_enable(void);
void rtc_dig_clk8m_enable(void);
void rtc_dig_clk8m_disable(void);
int esp_clk_tree_enable_src(unsigned int source_clock,bool enable);
#define RTC_DIGITAL_CLOCK_REGISTER (*(volatile unsigned int *)0x60008074U)
void uart_hal_rxfifo_rst(UartHal *hal);
#define RTC_DIGITAL_RC_FAST_LOCK ((PortMuxWords *)0x3fcabb28U)
#define RTC_DIGITAL_RC_FAST_REFERENCE_COUNT (*(volatile unsigned char *)0x3fcd8700U)
#define RTC_DIGITAL_RC_FAST_FREQUENCY_HZ (*(volatile unsigned int *)0x3fcd86fcU)
#define FUN_4038af00 uart_hal_txfifo_rst
#define FUN_4038af28 uart_hal_rxfifo_rst
#define FUN_420178c4 uart_hal_set_hw_flow_ctrl
#define FUN_42017934 uart_hal_set_tx_idle_num
#define FUN_42017958 uart_hal_init
#define FUN_42017b58 periph_rtc_dig_clk8m_enable
#define FUN_42021444 esp_clk_tree_enable_src
#define FUN_40384e88 rtc_dig_clk8m_enable
#define FUN_40384ea8 rtc_dig_clk8m_disable

/* Scheduler delay-list globals, protected by kernel mux. */
#define RTOS_CURRENT_TASKS ((RtosTask * volatile *)0x3fcbdd1cU)
#define RTOS_TERMINATION_LIST ((RtosList *)0x3fcbdabcU)
#define RTOS_SUSPENDED_LIST ((RtosList *)0x3fcbdaa4U)
#define RTOS_OVERFLOW_DELAYED_LIST (*(RtosList * volatile *)0x3fcbdaf8U)
#define RTOS_ACTIVE_DELAYED_LIST (*(RtosList * volatile *)0x3fcbdafcU)
#define RTOS_NEXT_UNBLOCK_TICK (*(volatile unsigned int *)0x3fcbda7cU)
#define RTOS_KERNEL_LOCK ((PortMuxWords *)0x3fcaa620U)
/* Native scheduler objects and counters. The ready array has25 lists; it
 * ends immediately before the separate two current-task pointer slots. */
#define RTOS_READY_LISTS ((RtosList *)0x3fcbdb28U)
#define RTOS_DELAYED_LIST1 ((RtosList *)0x3fcbdb14U)
#define RTOS_DELAYED_LIST2 ((RtosList *)0x3fcbdb00U)
#define RTOS_PENDING_READY_LISTS ((RtosList *)0x3fcbdad0U)
#define RTOS_TASK_COUNT (*(volatile unsigned int *)0x3fcbdaa0U)
#define RTOS_TASK_NUMBER (*(volatile unsigned int *)0x3fcbda80U)
#define RTOS_IDLE_TASK_HANDLES ((RtosTask * volatile *)0x3fcbda74U)
/* ESP-IDF uxTopUsedPriority=24: retained for OpenOCD list enumeration. */
#define RTOS_DEBUGGER_TOP_USED_PRIORITY (*(const volatile unsigned int *)0x3c046354U)
#define RTOS_TICK_OVERFLOWS (*(volatile unsigned int *)0x3fcbda84U)
#define RTOS_YIELD_PENDING ((volatile unsigned int *)0x3fcbda88U)
#define RTOS_PENDED_TICKS (*(volatile unsigned int *)0x3fcbda90U)
#define RTOS_TOP_READY_PRIORITY (*(volatile unsigned int *)0x3fcbda98U)
int prvIsYieldRequiredSMP(RtosTask *task,unsigned int priority,int yield_equal_priority);
void prvAddNewTaskToReadyList(RtosTask *task);
void prvInitialiseNewTask(TaskEntry entry,char *name,unsigned int stack_bytes,
    void *argument,unsigned int priority,RtosTask **created_task,RtosTask *task,int core_id);
RtosTask *xTaskCreateStaticPinnedToCore(TaskEntry entry,char *name,unsigned int stack_bytes,
    void *argument,unsigned int priority,unsigned char *stack,RtosTask *task_buffer,int core_id);
void vTaskStartScheduler(void);
void vApplicationGetIdleTaskMemory(RtosTask **task_buffer,
    unsigned char **stack_buffer,unsigned int *stack_bytes);
void vTaskSetThreadLocalStoragePointerAndDelCallback(RtosTask *task,int index,
    void *value,TlsDeleteCallback callback);
void vTaskSwitchContext(void);
void prvAddCurrentTaskToDelayedList(unsigned int ticks_to_wait,int can_block_indefinitely);
unsigned int xTaskGetTickCountFromISR(void);
void vListInsert(RtosList *list,RtosListItem *item);
void vListInsertEnd(RtosList *list,RtosListItem *item);
unsigned int uxListRemove(RtosListItem *item);

/* Idle-task deferred deletion and IPC worker globals; native per-core slots. */
#define RTOS_PENDING_DELETIONS (*(volatile unsigned int *)0x3fcbdab8U)
#define RTOS_DELETION_TASK_COUNT RTOS_TASK_COUNT
#define RTOS_TERMINATION_END ((RtosListItem *)0x3fcbdac4U)
#define IPC_DISPATCH_STATE ((IpcDispatchState *)0x3fcbd828U)
#define IPC_ISR_STALL_STATE (*(volatile unsigned int *)0x3fcbd818U)
void prvIdleTask(void *argument);
void prvDeleteTCB(RtosTask *task);
void newlib_reclaim_reent(NewlibReent *reent) __asm__("_reclaim_reent");
void esp_reent_init(NewlibReent *reent);
void vListInitialiseItem(RtosListItem *item);
void ipc_task(void *argument);
void esp_ipc_isr_init(void);
void esp_ipc_isr_port_init(int core);
void esp_vApplicationIdleHook(void);
void esp_cpu_wait_for_intr(void);
#define FUN_42003560 esp_ipc_isr_init
#define FUN_42003580 esp_ipc_isr_port_init
#define FUN_42003ae8 esp_vApplicationIdleHook
#define FUN_40384268 esp_cpu_wait_for_intr

/* Cache sync/freeze locks and S3 hardware/ROM interfaces. */
#define CACHE_SYNC_LOCK ((PortMuxWords *)0x3fcab9ecU)
#define CACHE_FREEZE_LOCK ((PortMuxWords *)0x3fcab9f4U)
#define CACHE_LOG_TAG ((const char *)0x3fcbce90U)
void esp_cache_sync_ops_enter_critical_section(void);
void esp_cache_sync_ops_exit_critical_section(void);
int esp_cache_get_alignment(unsigned int heap_capabilities,size_t *alignment);
void esp_cache_freeze_ext_mem_cache(void);
void esp_cache_unfreeze_ext_mem_cache(void);
void esp_cache_freeze_caches_disable_interrupts(void);
void esp_cache_unfreeze_caches_enable_interrupts(void);
void cache_hal_freeze(unsigned int level,CacheType type);
void cache_hal_unfreeze(unsigned int level,CacheType type);
unsigned int cache_hal_get_cache_line_size(unsigned int level,CacheType type);
void Cache_Freeze_ICache_Enable(unsigned int mode);
void Cache_Freeze_DCache_Enable(unsigned int mode);
void rom_Cache_Freeze_ICache_Enable(unsigned int mode); /* ROM400018e4 */
void rom_Cache_Freeze_DCache_Enable(unsigned int mode); /* ROM400018fc */
void Cache_Freeze_ICache_Disable(void); /* ROM400018f0 */
void Cache_Freeze_DCache_Disable(void); /* ROM40001908 */
unsigned int Cache_Get_ICache_Line_Size(void); /* ROM400015fc */
unsigned int Cache_Get_DCache_Line_Size(void); /* ROM40001608 */
void esp_intr_noniram_disable(void);
void esp_intr_noniram_enable(void);
#define FUN_403854d8 esp_cache_sync_ops_enter_critical_section
#define FUN_403854ec esp_cache_sync_ops_exit_critical_section
#define FUN_403856d4 esp_cache_get_alignment
#define FUN_40385730 esp_cache_freeze_ext_mem_cache
#define FUN_40385740 esp_cache_unfreeze_ext_mem_cache
#define FUN_40385750 esp_cache_freeze_caches_disable_interrupts
#define FUN_40385790 esp_cache_unfreeze_caches_enable_interrupts
#define FUN_40389358 cache_hal_freeze
#define FUN_4038937c cache_hal_unfreeze
#define FUN_403893a4 cache_hal_get_cache_line_size
#define FUN_40385d68 Cache_Freeze_ICache_Enable
#define FUN_40385d84 Cache_Freeze_DCache_Enable

/* Device cache synchronization and reviewed HAL range interfaces. */
bool cache_hal_vaddr_to_cache_level_id(unsigned int start,unsigned int length,
    unsigned int *level,unsigned int *cache_id);
bool cache_hal_writeback_addr(unsigned int start,unsigned int length);
int esp_cache_msync(void *address,size_t length,unsigned int flags);
#define FUN_403854fc esp_cache_msync

/* Partial EXTMEM window at peripheral+0x28 through freeze register+0x150. */
typedef struct CacheWritebackRegisters {
    volatile unsigned int sync_control; /* absolute offset+0x28 */
    volatile unsigned int sync_address; /* +0x2c */
    volatile unsigned int sync_items;   /* +0x30: cache-line count */
    unsigned int unmodeled_34[71];
    volatile unsigned int freeze_control; /* +0x150 */
} CacheWritebackRegisters;          /* 300-byte partial window */
int Cache_WriteBack_Addr(unsigned int start,unsigned int length);
void cache_writeback_items_freeze(unsigned int address,unsigned int items);
unsigned int Cache_Suspend_DCache_Autoload(void); /* ROM40001734 */
void Cache_Resume_DCache_Autoload(unsigned int autoload); /* ROM40001740 */
int rom_Cache_WriteBack_Addr(unsigned int start,unsigned int length); /* ROM400016c8 */

bool cache_hal_invalidate_addr(unsigned int start,unsigned int length);
int Cache_Invalidate_Addr(unsigned int start,unsigned int length); /* ROM400016b0 */
#define FUN_4038928c cache_hal_vaddr_to_cache_level_id
#define FUN_403892dc cache_hal_invalidate_addr
#define FUN_4038931c cache_hal_writeback_addr
#define FUN_40385da8 Cache_WriteBack_Addr
#define FUN_40385e30 cache_writeback_items_freeze

/* Partial RTC counter-snapshot window starting at peripheral offset+0x0c. */
typedef struct RtcTimeSnapshotRegisters {
    volatile unsigned int update;
    volatile unsigned int low;
    volatile unsigned int high;
} RtcTimeSnapshotRegisters;
#define RTC_TIME_SNAPSHOT_REGISTERS ((RtcTimeSnapshotRegisters *)0x6000800cU)
#define CALIBRATION_TIMER_GROUP0_REGISTERS ((volatile TimerGroupWatchdogRegistersPrefix *)0x6001f000U)
unsigned long long rtc_time_us_to_slowclk(unsigned long long time_in_us,unsigned int period_q19);
unsigned long long rtc_time_get(void);
unsigned int rtc_clk_freq_cal(unsigned int calibration);
void enable_timer_group0_for_calibration(void);
#define FUN_40385398 rtc_time_us_to_slowclk
#define FUN_40385414 rtc_time_get
#define FUN_4038543c rtc_clk_freq_cal
#define FUN_40385458 enable_timer_group0_for_calibration

/* Partial RTC clock register prefix and TIMG0 calibration window. */
typedef struct RtcCalibrationClockRegisters {
    unsigned int unmodeled_00[7];
    volatile unsigned int timer1;       /* +0x1c: RC_FAST wait count */
    unsigned int unmodeled_20[16];
    volatile unsigned int xtal_control; /* +0x60: crystal power/control */
    unsigned int unmodeled_64[4];
    volatile unsigned int clock_conf;   /* +0x74: source/enables */
    unsigned int unmodeled_78[18];
    volatile unsigned int xtal_store;   /* +0xc0: duplicate16-bit MHz */
    unsigned int unmodeled_c4[5];
    volatile unsigned int pad_hold;     /* +0xd8: RTC pad holds */
} RtcCalibrationClockRegisters;   /* 220-byte partial prefix */
typedef struct RtcCalibrationTimerRegisters {
    volatile unsigned int configuration; /* TIMG0+0x68 */
    volatile unsigned int value;         /* +0x6c */
    unsigned int unmodeled_70[4];
    volatile unsigned int timeout;       /* +0x80 */
} RtcCalibrationTimerRegisters;
enum RtcCalibrationSource {
    RTC_CAL_RTC_MUX = 0,
    RTC_CAL_8MD256 = 1,
    RTC_CAL_32K_XTAL = 2,
    RTC_CAL_INTERNAL_OSC = 3
};
#define RTC_CALIBRATION_CLOCK_REGISTERS ((RtcCalibrationClockRegisters *)0x60008000U)
#define RTC_CALIBRATION_TIMER_REGISTERS ((RtcCalibrationTimerRegisters *)0x6001f068U)
#define RTC_CLOCK_LOG_TAG ((const char *)0x3fcbcc5cU)
void rtc_clk_8m_enable(unsigned char fast_enabled,unsigned char divided_enabled);
unsigned int rtc_clk_slow_src_get(void);
unsigned int rtc_clk_xtal_freq_get(void);
unsigned int rtc_clk_cal_internal(unsigned int selection,unsigned int cycles);
unsigned int rtc_clk_cal(unsigned int selection,unsigned int cycles);
/* ROM40002544: two unsigned64 arguments and unsigned64 result, not four
 * invented scalar parameters. Named call retains native division boundaries. */
extern unsigned long long rom_unsigned_divide_u64(unsigned long long numerator,
    unsigned long long denominator) __asm__("__udivdi3");
/* ROM40002574: unsigned64 remainder, preserving the native call boundary. */
extern unsigned long long rom_unsigned_remainder_u64(unsigned long long numerator,
    unsigned long long denominator) __asm__("__umoddi3");
#define FUN_403846a0 rtc_clk_8m_enable
#define FUN_403847f4 rtc_clk_slow_src_get
#define FUN_40384880 rtc_clk_xtal_freq_get
#define FUN_40385048 rtc_clk_cal_internal
#define FUN_403852f8 rtc_clk_cal

/* Four-word SDK CPU frequency description; constructing it changes no clock. */
typedef struct RtcCpuFrequencyConfig {
    unsigned int source;     /* 0 XTAL,1 PLL,2 RC_FAST */
    unsigned int source_mhz;
    unsigned int divider;
    unsigned int cpu_mhz;
} RtcCpuFrequencyConfig;
#define RTC_XTAL32K_INPUT_PAD (*(volatile unsigned int *)0x60009040U)
void rtc_clk_32k_disable_external(void);
bool rtc_clk_8md256_enabled(void);
unsigned int rtc_clk_slow_freq_get_hz(void);
void rtc_clk_fast_src_set(unsigned int source);
bool rtc_clk_cpu_freq_mhz_to_config(unsigned int requested_mhz,RtcCpuFrequencyConfig *configuration);
#define FUN_40384650 rtc_clk_32k_disable_external
#define FUN_40384728 rtc_clk_8md256_enabled
#define FUN_40384814 rtc_clk_slow_freq_get_hz
#define FUN_4038483c rtc_clk_fast_src_set
#define FUN_403848c0 rtc_clk_cpu_freq_mhz_to_config

/* Seven signed32 sleep references live in RTC slow RAM. Array pointer is
 * borrowed/mutable; individual native accesses retain their volatility. */
#define SLEEP_SUBMODE_COUNT 7U
enum SleepSubmode {
    ESP_SLEEP_RTC_USE_RC_FAST_MODE = 0,
    ESP_SLEEP_DIG_USE_RC_FAST_MODE = 1,
    ESP_SLEEP_USE_ADC_TSEN_MONITOR_MODE = 2,
    ESP_SLEEP_ULTRA_LOW_MODE = 3,
    ESP_SLEEP_RTC_FAST_USE_XTAL_MODE = 4,
    ESP_SLEEP_DIG_USE_XTAL_MODE = 5,
    ESP_SLEEP_LP_USE_XTAL_MODE = 6,
    ESP_SLEEP_MODE_MAX = 7
};
typedef int SleepSubmodeCounts[7];
#define SLEEP_SUBMODE_COUNTS ((int *)0x500000a8U)
#define SLEEP_SUBMODE_NAMES ((const char * const volatile *)0x3c04632cU)
#define SLEEP_CONFIGURATION_LOCK ((PortMuxWords *)0x3fcaa5e0U)
int sleep_submode_adjust(unsigned int submode,unsigned int activate_word);
void sleep_submode_clear(unsigned int submode);
int esp_sleep_sub_mode_config(unsigned int mode,unsigned char activate);
int esp_sleep_sub_mode_force_disable(unsigned int mode);
int *esp_sleep_sub_mode_dump_config(NewlibFile *stream);
void rtc_clk_slow_src_set(unsigned int source);
#define FUN_40384740 rtc_clk_slow_src_set
#define FUN_42007210 sleep_submode_adjust
#define FUN_42007278 sleep_submode_clear
#define FUN_420072ac esp_sleep_sub_mode_config
#define FUN_420072c4 esp_sleep_sub_mode_force_disable
#define FUN_420072d8 esp_sleep_sub_mode_dump_config

/* Partial SYSTEM clock-control prefix, not the complete peripheral. */
typedef struct RtcCpuSystemRegisters {
    unsigned int unmodeled_00[4];
    volatile unsigned int cpu_period; /* +0x10: period/PLL-frequency bits */
    volatile unsigned int memory_power_mask; /* +0x14 */
    unsigned int unmodeled_18[18];
    volatile unsigned int system_clock; /* +0x60: divider/source */
} RtcCpuSystemRegisters;
/* Low-byte view of four aligned 32-bit SDK trim globals at 0/4/8/12.
 * The upper three bytes of each value are not read by these clock switches. */
typedef struct RtcCpuBiasCalibrationBytes {
    volatile unsigned char rtc_non240;
    unsigned char unread_rtc_non240_upper[3];
    volatile unsigned char digital_non240;
    unsigned char unread_digital_non240_upper[3];
    volatile unsigned char rtc_240;
    unsigned char unread_rtc_240_upper[3];
    volatile unsigned char digital_240;
    unsigned char unread_digital_240_upper[3];
} __attribute__((aligned(4))) RtcCpuBiasCalibrationBytes;
#define RTC_CPU_SYSTEM_REGISTERS ((RtcCpuSystemRegisters *)0x600c0000U)
#define RTC_CPU_DATE_REGISTER (*(volatile unsigned int *)0x600081fcU)
#define RTC_CACHED_APB_HZ (*(volatile unsigned int *)0x3fcbda58U)
#define RTC_CACHED_PLL_MHZ (*(volatile unsigned int *)0x3fcbda5cU)
#define RTC_CPU_BIAS_CALIBRATION ((RtcCpuBiasCalibrationBytes *)0x3fcaa584U)
void rtc_clk_cpu_freq_get_config(RtcCpuFrequencyConfig *configuration);
void rtc_clk_cpu_freq_to_xtal(unsigned int target_mhz,unsigned int divider);
void rtc_clk_cpu_set_to_default_config(void);
void rtc_clk_cpu_freq_set_xtal(void);
void esp_rom_set_cpu_ticks_per_us(unsigned int ticks); /* ROM40001a4c */
void regi2c_ctrl_write_reg_mask(unsigned char block,unsigned char host_id,
    unsigned char reg_address,unsigned char msb,unsigned char lsb,unsigned char value);
#define FUN_40384920 rtc_clk_cpu_freq_get_config
#define FUN_40384bb0 rtc_clk_cpu_freq_to_xtal
#define FUN_40384e4c rtc_clk_cpu_set_to_default_config
#define FUN_40384e5c rtc_clk_cpu_freq_set_xtal

/* RTC PLL configuration and its single-read consumer-count decision. */
#define RTC_PLL_CONSUMER_COUNT (*(volatile unsigned int *)0x3fcbda54U)
#define RTC_PLL_ANALOG_CONFIGURATION (*(volatile unsigned int *)0x6000e040U)
void rtc_clk_cpu_freq_to_pll_mhz(unsigned int target_mhz);
void rtc_clk_cpu_freq_set_config(const RtcCpuFrequencyConfig *configuration);
void rtc_reconfigure_active_pll(void);
void regi2c_ctrl_write_reg(unsigned char block,unsigned char host_id,
    unsigned char reg_address,unsigned char value);
#define FUN_403849d4 rtc_clk_cpu_freq_to_pll_mhz
#define FUN_40384c60 rtc_clk_cpu_freq_set_config
#define FUN_40375c60 rtc_reconfigure_active_pll

/* Native packed rtc_sleep_pu_config_t flags. CPU/I2S are unused here. */
enum SleepPowerUpFlags {
    SLEEP_FORCE_DIGITAL = 1U << 0,
    SLEEP_FORCE_RTC = 1U << 1,
    SLEEP_FORCE_CPU = 1U << 2,
    SLEEP_FORCE_I2S = 1U << 3,
    SLEEP_FORCE_BASEBAND = 1U << 4,
    SLEEP_FORCE_RECEIVER = 1U << 5,
    SLEEP_FORCE_FRONTEND = 1U << 6,
    SLEEP_FORCE_SRAM = 1U << 7,
    SLEEP_FORCE_ROM = 1U << 8
};
typedef struct SleepPowerRegisters {
    unsigned int reserved_00[34];
    volatile unsigned int rtc_memory; /* RTC_CNTL +0x88 */
    unsigned int reserved_8c;
    volatile unsigned int digital_memory; /* +0x90 */
} SleepPowerRegisters;
typedef struct SleepSysconRegisters {
    unsigned int reserved_00[39];
    volatile unsigned int frontend_memory; /* SYSCON +0x9c */
    unsigned int reserved_a0[2];
    volatile unsigned int clock_gate_force_on; /* +0xa8 */
    unsigned int reserved_ac;
    volatile unsigned int memory_power_up; /* +0xb0 */
} SleepSysconRegisters;
typedef struct RtcXtal32kPadRegisters {
    volatile unsigned int positive; /* RTC_IO +0xc0: GPIO15 */
    volatile unsigned int negative; /* RTC_IO +0xc4: GPIO16 */
} RtcXtal32kPadRegisters;
#define SLEEP_POWER_REGISTERS ((SleepPowerRegisters *)0x60008000U)
#define SLEEP_SYSCON_REGISTERS ((SleepSysconRegisters *)0x60026000U)
#define SLEEP_BASEBAND_POWER_REGISTER (*(volatile unsigned int *)0x6001d054U)
#define SLEEP_RECEIVER_POWER_REGISTER (*(volatile unsigned int *)0x6001ccd4U)
#define SLEEP_IQ_ESTIMATOR_POWER_REGISTER (*(volatile unsigned int *)0x60006090U)
#define SLEEP_TX_INTERPOLATOR_POWER_REGISTER (*(volatile unsigned int *)0x600050f0U)
#define RTC_XTAL32K_PAD_REGISTERS ((RtcXtal32kPadRegisters *)0x600084c0U)
void rtc_sleep_pu(unsigned int configuration);
void rtc_clk_32k_enable(unsigned char enabled);
#define FUN_40384ec8 rtc_sleep_pu
#define FUN_40384584 rtc_clk_32k_enable

/* MSPI register view through DATE (+0x3fc). The reserved_* members cover
 * unmodeled registers and gaps; they do not imply hardware-reserved space. */
typedef struct MspiRegisters {
    volatile unsigned int cmd,addr,ctrl;
    volatile unsigned int ctrl1,ctrl2;
    volatile unsigned int flash_clock; /* +0x14 */
    volatile unsigned int user,user1,user2,mosi_dlen,miso_dlen;
    unsigned int reserved_2c[2];
    volatile unsigned int misc; /* +0x34 */
    unsigned int reserved_38;
    volatile unsigned int cache_fctrl; /* +0x3c */
    volatile unsigned int cache_sctrl; /* +0x40 */
    unsigned int reserved_44;
    volatile unsigned int sram_drd_cmd,sram_dwr_cmd; /* +0x48, +0x4c */
    volatile unsigned int psram_clock; /* +0x50 */
    unsigned int reserved_54;
    volatile unsigned int data[16]; /* +0x58..0x94 */
    volatile unsigned int wait_idle_ctrl; /* +0x98 */
    volatile unsigned int flash_suspend_command; /* +0x9c, FLASH_PER/PES */
    volatile unsigned int flash_suspend_control; /* +0xa0 */
    volatile unsigned int suspend_status; /* +0xa4 */
    volatile unsigned int timing_cali; /* +0xa8 */
    unsigned int reserved_ac[12];
    volatile unsigned int smem_ac; /* +0xdc */
    volatile unsigned int ddr; /* +0xe0 */
    unsigned int reserved_e4;
    volatile unsigned int clock_gate; /* +0xe8 */
    volatile unsigned int core_clock; /* +0xec */
    unsigned int reserved_f0[195];
    volatile unsigned int date; /* +0x3fc: includes pad driver fields */
} MspiRegisters;
#define MSPI0 ((MspiRegisters *)0x60003000U)
#define MSPI1 ((MspiRegisters *)0x60002000U)
void mspi_timing_config_set_flash_clock(unsigned int frequency_mhz,
    unsigned int speed_mode,unsigned char control_spi1);
void mspi_timing_config_set_psram_clock(unsigned int frequency_mhz,
    unsigned int speed_mode,unsigned char control_spi1);
void mspi_set_all_pin_drive_3(void);
void *memcpy(void *destination,const void *source,size_t length);
void mspi_timing_enter_low_speed_mode(unsigned char control_spi1);
#define MSPI_DRIVE_PAD_TABLE ((const void *)0x3fcbcc38U)
#define FUN_403843cc mspi_timing_config_set_flash_clock
#define FUN_40384438 mspi_timing_config_set_psram_clock
#define FUN_40384490 mspi_timing_enter_low_speed_mode
#define FUN_4038450c mspi_set_all_pin_drive_3

/* ESP32-S3 SDK LDO model constants; voltages are scaled by 10000. */
#define K_RTC_MID_MUL10000 198
#define K_DIG_MID_MUL10000 211
#define V_RTC_MID_MUL10000 10181U
#define V_DIG_MID_MUL10000 10841U

/* rtc_config_t packed word: wait bytes 0/1/2, then options at bits 24..30. */
enum RtcInitFlags {
    RTC_INIT_CLOCK_CONTROL = 1U << 24,
    RTC_INIT_POWER_CONTROL = 1U << 25,
    RTC_INIT_BOOST_FORCE_OFF = 1U << 26,
    RTC_INIT_XTAL_FORCE_ON = 1U << 27,
    RTC_INIT_PLL_FORCE_ON = 1U << 28,
    RTC_INIT_CPU_WAIT_GATE = 1U << 29,
    RTC_INIT_CALIBRATE_OCODE = 1U << 30
};
/* Sparse register prefixes, not complete hardware blocks. The reserved_*
 * arrays stand for unmodeled register slots, not a claim they are reserved by
 * the hardware. Every exposed register is a volatile 32-bit word. */
typedef struct RtcInitRegisters {
    volatile unsigned int options0;
    unsigned int reserved_04[6];
    volatile unsigned int timer1;
    volatile unsigned int timer2;
    volatile unsigned int timer3;
    volatile unsigned int timer4;
    volatile unsigned int timer5;
    volatile unsigned int timer6;
    volatile unsigned int analog;
    unsigned int reserved_38[2];
    volatile unsigned int interrupt_enable;
    unsigned int reserved_44[2];
    volatile unsigned int interrupt_clear;
    unsigned int reserved_50[9];
    volatile unsigned int clock_config;
    unsigned int reserved_78[3];
    volatile unsigned int regulator;
    volatile unsigned int rtc_power;
    unsigned int reserved_8c;
    volatile unsigned int digital_power;
    volatile unsigned int digital_isolation;
} RtcInitRegisters;
typedef struct RtcEfuseRegisters {
    unsigned int reserved_00[20];
    volatile unsigned int version_minor; /* +0x50 */
    volatile unsigned int ldo_low; /* +0x54 */
    volatile unsigned int ldo_high; /* +0x58 */
    unsigned int reserved_5c[4];
    volatile unsigned int version_major; /* +0x6c: also bandgap OCode */
} RtcEfuseRegisters;
typedef struct RtcCachePowerRegisters {
    unsigned int reserved_00[2];
    volatile unsigned int data_tag_power;
    unsigned int reserved_0c[23];
    volatile unsigned int instruction_tag_power;
    unsigned int reserved_6c[48];
    volatile unsigned int mmu_power;
} RtcCachePowerRegisters;
typedef struct RtcSarRegisters {
    unsigned int reserved_00[15];
    volatile unsigned int power;
    unsigned int reserved_40[49];
    volatile unsigned int peripheral_clock;
} RtcSarRegisters;
/* Full-word write view; clock switching reads only the low trim bytes. */
typedef struct RtcCpuBiasCalibrationWords {
    volatile unsigned int rtc_non240;
    volatile unsigned int digital_non240;
    volatile unsigned int rtc_240;
    volatile unsigned int digital_240;
} RtcCpuBiasCalibrationWords;
#define RTC_INIT_REGISTERS ((RtcInitRegisters *)0x60008000U)
#define RTC_EFUSE_REGISTERS ((RtcEfuseRegisters *)0x60007000U)
#define RTC_CACHE_POWER_REGISTERS ((RtcCachePowerRegisters *)0x600c4000U)
#define RTC_SAR_REGISTERS ((RtcSarRegisters *)0x60008800U)
#define RTC_CPU_BIAS_WORDS ((RtcCpuBiasCalibrationWords *)RTC_CPU_BIAS_CALIBRATION)
unsigned int rtc_bias_from_efuse(unsigned int digital_bias);
void rtc_init(unsigned int configuration_word);
void sar_periph_ctrl_init(void);
unsigned char regi2c_ctrl_read_reg_mask(unsigned char block,unsigned char host_id,
    unsigned char reg_address,unsigned char msb,unsigned char lsb);
void mspi_timing_enter_high_speed_mode(unsigned char control_spi1);
void mspi_timing_change_speed_mode_cache_safe(unsigned char switch_down);
#define FUN_42023ac0 rtc_bias_from_efuse
#define FUN_42023b70 rtc_init
#define FUN_42024278 sar_periph_ctrl_init
#define FUN_403844ac mspi_timing_enter_high_speed_mode
#define FUN_403844c8 mspi_timing_change_speed_mode_cache_safe

/* ESP32-S3 AHB GDMA channel register views; RX/TX halves occupy 0x60 each. */
enum GdmaDirection { GDMA_DIRECTION_TRANSMIT = 0, GDMA_DIRECTION_RECEIVE = 1 };
typedef struct GdmaDirectionRegisters {
    volatile unsigned int configuration0;
    volatile unsigned int configuration1;
    volatile unsigned int interrupt_raw;
    volatile unsigned int interrupt_status;
    volatile unsigned int interrupt_enable;
    volatile unsigned int interrupt_clear;
    volatile unsigned int fifo_status;
    volatile unsigned int fifo_data;
    volatile unsigned int link;
    volatile unsigned int state;
    volatile unsigned int eof_descriptor;
    volatile unsigned int error_or_previous_eof_descriptor;
    volatile unsigned int current_descriptor;
    volatile unsigned int previous_descriptor;
    volatile unsigned int previous_previous_descriptor;
    volatile unsigned int weight; /* bits 8..11; unused by these HAL routines */
    unsigned int reserved_40;
    volatile unsigned int priority;
    volatile unsigned int peripheral;
    unsigned int reserved_4c[5];
} GdmaDirectionRegisters;
typedef struct GdmaChannelRegisters {
    GdmaDirectionRegisters rx;
    GdmaDirectionRegisters tx;
} GdmaChannelRegisters;
/* Partial device prefix; global DMA registers after these channels omitted. */
typedef struct GdmaDeviceRegisters {
    GdmaChannelRegisters channel[5];
} GdmaDeviceRegisters;
typedef struct GdmaHalConfig { int group_id; } GdmaHalConfig;
typedef struct GdmaPrivateData {
    unsigned int memory_to_memory_free_peripheral_mask;
} GdmaPrivateData;
typedef struct GdmaHal GdmaHal;
struct GdmaHal {
    GdmaDeviceRegisters *device;
    const GdmaPrivateData *private_data;
    void (*start_with_desc)(GdmaHal *hal,int channel_id,int direction,unsigned int descriptor_address);
    void (*stop)(GdmaHal *hal,int channel_id,int direction);
    void (*append)(GdmaHal *hal,int channel_id,int direction);
    void (*reset)(GdmaHal *hal,int channel_id,int direction);
    void (*set_priority)(GdmaHal *hal,int channel_id,int direction,unsigned int priority);
    void (*connect_peripheral)(GdmaHal *hal,int channel_id,int direction,int peripheral_type,int peripheral_id);
    void (*disconnect_peripheral)(GdmaHal *hal,int channel_id,int direction);
    void (*enable_burst)(GdmaHal *hal,int channel_id,int direction,unsigned char data_burst,unsigned char descriptor_burst);
    void (*set_burst_size)(GdmaHal *hal,int channel_id,int direction,unsigned int burst_bytes);
    void (*set_strategy)(GdmaHal *hal,int channel_id,int direction,unsigned char owner_check,unsigned char descriptor_writeback,unsigned char eof_till_popped);
    unsigned int (*get_interrupt_status_register)(GdmaHal *hal,int channel_id,int direction);
    void (*enable_interrupt)(GdmaHal *hal,int channel_id,int direction,unsigned int events,unsigned char enabled);
    void (*clear_interrupt)(GdmaHal *hal,int channel_id,int direction,unsigned int events);
    unsigned int (*read_interrupt_status)(GdmaHal *hal,int channel_id,int direction,unsigned char raw);
    unsigned int (*get_eof_descriptor)(GdmaHal *hal,int channel_id,int direction,unsigned char success);
};
#define GDMA_DEVICE ((GdmaDeviceRegisters *)0x6003f000U)
void gdma_ahb_hal_append(GdmaHal *hal,int channel_id,int direction);
void gdma_ahb_hal_clear_intr(GdmaHal *hal,int channel_id,int direction,unsigned int events);
unsigned int gdma_ahb_hal_get_eof_desc_addr(GdmaHal *hal,int channel_id, int direction,unsigned char success);
unsigned int gdma_ahb_hal_read_intr_status(GdmaHal *hal,int channel_id, int direction,unsigned char raw);
void gdma_ahb_hal_reset(GdmaHal *hal,int channel_id,int direction);
void gdma_ahb_hal_start_with_desc(GdmaHal *hal,int channel_id,int direction, unsigned int descriptor_address);
void gdma_ahb_hal_stop(GdmaHal *hal,int channel_id,int direction);
void gdma_ahb_hal_set_strategy(GdmaHal *hal,int channel_id,int direction, unsigned char owner_check,unsigned char descriptor_writeback,unsigned char eof_till_popped);
void gdma_ahb_hal_set_burst_size(GdmaHal *hal,int channel_id,int direction, unsigned int burst_bytes);
void gdma_ahb_hal_init(GdmaHal *hal,const GdmaHalConfig *configuration);
void gdma_ahb_hal_set_priority(GdmaHal *hal,int channel_id,int direction,unsigned int priority);
void gdma_ahb_hal_disconnect_peri(GdmaHal *hal,int channel_id,int direction);
void gdma_ahb_hal_enable_burst(GdmaHal *hal,int channel_id,int direction, unsigned char data_burst,unsigned char descriptor_burst);
unsigned int gdma_ahb_hal_get_intr_status_reg(GdmaHal *hal,int channel_id,int direction);
void gdma_ahb_hal_enable_intr(GdmaHal *hal,int channel_id,int direction, unsigned int events,unsigned char enabled);
void gdma_ahb_hal_connect_peri(GdmaHal *hal,int channel_id,int direction, int peripheral_type,int peripheral_id);
#define GDMA_AHB_PRIVATE ((const GdmaPrivateData *)0x3fcabb40U)
#define FUN_403893d8 gdma_ahb_hal_append
#define FUN_40389414 gdma_ahb_hal_clear_intr
#define FUN_40389434 gdma_ahb_hal_get_eof_desc_addr
#define FUN_40389468 gdma_ahb_hal_read_intr_status
#define FUN_403894a0 gdma_ahb_hal_reset
#define FUN_403894f4 gdma_ahb_hal_start_with_desc
#define FUN_40389560 gdma_ahb_hal_stop
#define FUN_420243ec gdma_ahb_hal_set_strategy
#define FUN_42024474 gdma_ahb_hal_set_burst_size
#define FUN_420244e8 gdma_ahb_hal_init
#define FUN_4202454c gdma_ahb_hal_set_priority
#define FUN_42024590 gdma_ahb_hal_disconnect_peri
#define FUN_420245dc gdma_ahb_hal_enable_burst
#define FUN_4202465c gdma_ahb_hal_get_intr_status_reg
#define FUN_4202467c gdma_ahb_hal_enable_intr
#define FUN_420246d4 gdma_ahb_hal_connect_peri

/* GDMA dispatch layer: typed calls through the native HAL slots. */
void gdma_hal_clear_intr(GdmaHal *hal,int channel_id,int direction,unsigned int events);
void gdma_hal_start_with_desc(GdmaHal *hal,int channel_id,int direction, unsigned int descriptor_address);
void gdma_hal_deinit(GdmaHal *hal);
void gdma_hal_set_priority(GdmaHal *hal,int channel_id,int direction,unsigned int priority);
void gdma_hal_connect_peri(GdmaHal *hal,int channel_id,int direction, int peripheral_type,int peripheral_id);
void gdma_hal_disconnect_peri(GdmaHal *hal,int channel_id,int direction);
void gdma_hal_enable_burst(GdmaHal *hal,int channel_id,int direction, unsigned char data_burst,unsigned char descriptor_burst);
void gdma_hal_set_burst_size(GdmaHal *hal,int channel_id,int direction,unsigned int burst_bytes);
void gdma_hal_enable_intr(GdmaHal *hal,int channel_id,int direction, unsigned int events,unsigned char enabled);
#define FUN_4038959c gdma_hal_clear_intr
#define FUN_403895b0 gdma_hal_start_with_desc
#define FUN_42024778 gdma_hal_deinit
#define FUN_42024784 gdma_hal_set_priority
#define FUN_42024798 gdma_hal_connect_peri
#define FUN_420247ac gdma_hal_disconnect_peri
#define FUN_420247bc gdma_hal_enable_burst
#define FUN_420247d4 gdma_hal_set_burst_size
#define FUN_420247e8 gdma_hal_enable_intr

/* GDMA native driver ownership objects. Volatile members retain live accesses;
 * synchronization remains the explicit native spinlock operations, not volatile. */
typedef struct GdmaChannel GdmaChannel;
typedef struct GdmaPair GdmaPair;
typedef struct GdmaGroup GdmaGroup;
typedef union GdmaChannelFlags {
    unsigned int word;
    struct { volatile unsigned char bits; unsigned char reserved[3]; };
} GdmaChannelFlags;
/* Common 40-byte prefix; RX/TX callback tails are outside this view. */
struct GdmaChannel {
    GdmaPair *volatile pair;
    InterruptHandle *volatile interrupt;
    PortMuxWords lock;
    volatile int direction;
    volatile int peripheral_id;
    volatile unsigned int internal_alignment;
    volatile unsigned int external_alignment;
    int (*volatile destroy)(GdmaChannel *channel);
    GdmaChannelFlags flags;
};
struct GdmaPair {
    GdmaGroup *volatile group;
    volatile int pair_id;
    GdmaChannel *volatile tx_channel;
    GdmaChannel *volatile rx_channel;
    volatile unsigned int occupancy;
    PortMuxWords lock;
};
struct GdmaGroup {
    volatile int group_id;
    volatile int bus_id;
    GdmaHal hal;
    PortMuxWords lock;
    volatile unsigned int tx_peripherals;
    volatile unsigned int rx_peripherals;
    GdmaPair *volatile pairs[5];
    volatile unsigned int pair_references[5]; /* native modulo-32 arithmetic */
};
typedef struct GdmaPlatform {
    PortMuxWords lock;
    GdmaGroup *volatile groups[1];
    volatile unsigned int group_references[1];
} GdmaPlatform;
typedef struct GdmaTransferConfig {
    volatile unsigned int max_data_burst_size;
    volatile unsigned char access_external_memory;
    unsigned char reserved[3];
} GdmaTransferConfig;
typedef struct GdmaTrigger {
    int peripheral_type;
    int instance_id;
    int bus_id;
} GdmaTrigger;
typedef struct GdmaRccRegisters {
    unsigned int reserved_00[7];
    volatile unsigned int clock_enable1; /* SYSTEM +0x1c */
    unsigned int reserved_20;
    volatile unsigned int reset_enable1; /* +0x24 */
} GdmaRccRegisters;
#define GDMA_RCC ((GdmaRccRegisters *)0x600c0000U)
int gdma_start(GdmaChannel *channel,unsigned int descriptor_address);
int gdma_del_channel(GdmaChannel *channel);
int gdma_get_group_channel_id(GdmaChannel *channel,int *group_id,int *channel_id);
int gdma_disconnect(GdmaChannel *channel);
int gdma_config_transfer(GdmaChannel *channel,const GdmaTransferConfig *configuration);
void gdma_release_group_handle(GdmaGroup *group);
void gdma_release_pair_handle(GdmaPair *pair);
int gdma_del_rx_channel(GdmaChannel *channel);
int gdma_del_tx_channel(GdmaChannel *channel);
int gdma_connect(GdmaChannel *channel,GdmaTrigger trigger);
int esp_intr_free(InterruptHandle *handle);
void free(void *memory);
#define GDMA_PLATFORM ((GdmaPlatform *)0x3fcabb30U)
#define FUN_42023080 gdma_release_group_handle
#define FUN_420230f8 gdma_release_pair_handle
#define FUN_42023154 gdma_del_rx_channel
#define FUN_420231cc gdma_del_tx_channel
#define FUN_420237f8(channel,type,id,bus) gdma_connect((GdmaChannel *)(uintptr_t)(channel),(GdmaTrigger){(type),(id),(bus)})

/* Allocation ABI and the SDK callback tails following the common prefix. */
typedef union GdmaAllocFlags {
    volatile unsigned int word;
    struct { volatile unsigned char bits; unsigned char reserved[3]; };
} GdmaAllocFlags;
typedef struct GdmaAllocConfig {
    GdmaChannel *volatile sibling;
    volatile int direction;
    GdmaAllocFlags flags;
} GdmaAllocConfig;
typedef struct GdmaEventData {
    unsigned int descriptor_address;
    unsigned int flags; /* bit 0 abnormal EOF, bit 1 normal EOF */
} GdmaEventData;
typedef unsigned char (*GdmaEventCallback)(GdmaChannel *,GdmaEventData *,void *);
typedef struct GdmaTxChannel {
    GdmaChannel base;
    void *user_data;
    GdmaEventCallback on_transmit_eof;
    GdmaEventCallback on_descriptor_error;
} GdmaTxChannel;
typedef struct GdmaRxChannel {
    GdmaChannel base;
    void *user_data;
    GdmaEventCallback on_receive_eof;
    GdmaEventCallback on_descriptor_error;
    GdmaEventCallback on_receive_done;
} GdmaRxChannel;
int do_allocate_gdma_channel(const GdmaAllocConfig *configuration,GdmaChannel **output_channel);
void *heap_caps_calloc(size_t count,size_t size,unsigned int capabilities);

/* ESP32-S3 LEDC channel and the single low-speed group's register prefix. */
typedef struct LedcChannelRegisters {
    volatile unsigned int configuration0;
    volatile unsigned int hpoint;
    volatile unsigned int duty;
    volatile unsigned int configuration1;
    volatile unsigned int duty_read;
} LedcChannelRegisters;
typedef struct LedcGroupRegisters {
    LedcChannelRegisters channel[8];
} LedcGroupRegisters;
typedef struct LedcTimerRegisters {
    volatile unsigned int configuration;
    volatile unsigned int counter;
} LedcTimerRegisters;
typedef struct LedcDeviceRegistersPrefix {
    LedcGroupRegisters channel_group[1];
    struct { LedcTimerRegisters timer[4]; } timer_group[1]; /* 0xa0 */
    volatile unsigned int interrupt_raw;     /* 0xc0 */
    volatile unsigned int interrupt_status;  /* 0xc4 */
    volatile unsigned int interrupt_enable;  /* 0xc8 */
    volatile unsigned int interrupt_clear;   /* 0xcc */
    volatile unsigned int configuration;     /* 0xd0: mux; later registers omitted */
} LedcDeviceRegistersPrefix;
typedef struct LedcHal {
    LedcDeviceRegistersPrefix *volatile device;
    volatile int speed_mode;
} LedcHal;
void ledc_hal_set_duty_start(LedcHal *hal,int channel_id);
void ledc_hal_set_duty_int_part(LedcHal *hal,int channel_id,unsigned int duty);
void ledc_hal_set_fade_param(const LedcHal *hal,int channel_id,unsigned int range, unsigned int direction,unsigned int cycle,unsigned int scale,unsigned int step);
void ledc_hal_ls_channel_update(LedcHal *hal,int channel_id);
void ledc_hal_set_hpoint(LedcHal *hal,int channel_id,unsigned int hpoint);
#define FUN_403895c4 ledc_hal_set_duty_start
#define FUN_403895ec ledc_hal_set_duty_int_part
#define FUN_40389624 ledc_hal_set_fade_param
#define FUN_403896bc ledc_hal_ls_channel_update
#define FUN_403896e4 ledc_hal_set_hpoint

/* LEDC driver context: native calloc size 40; no timer-specific mux array on S3. */
typedef struct LedcDriverContext {
    LedcHal hal;                         /* 0x00 */
    volatile int global_clock;                 /* 0x08: -1 uninitialized */
    volatile unsigned char timer_stopped[4];   /* 0x0c */
    volatile unsigned char global_clock_acquired[4]; /* 0x10 */
    volatile int sleep_mode;                   /* 0x14 */
    volatile unsigned char channel_keep_alive[8]; /* 0x18 */
    volatile unsigned char timer_power_references[4]; /* 0x20, wrapping bytes */
    volatile unsigned char global_clock_powered; /* 0x24 */
    unsigned char padding25[3];                /* 0x25: allocation alignment */
} LedcDriverContext;
/* Only the SDK fade prefix through its hardware semaphore is recovered here. */
typedef struct LedcFadePrefix {
    int speed_mode;
    int direction;
    unsigned int target_duty;
    int cycle_count;
    int scale;
    int fade_mode;
    RtosQueue *volatile hardware_semaphore; /* 0x18 */
} LedcFadePrefix;
#define LEDC_SYSTEM_CLOCK_ENABLE_REGISTER (*(volatile unsigned int *)0x600c0018U)
#define LEDC_SYSTEM_RESET_REGISTER (*(volatile unsigned int *)0x600c0020U)
void ledc_hal_init(LedcHal *hal,int speed_mode);
unsigned int ledc_speed_mode_ctx_create(void);
void ledc_fade_hw_acquire(unsigned int speed_mode,unsigned int channel_id);
unsigned char ledc_timer_clk_src_set_xpd_in_sleep(unsigned int timer_id);
int ledc_timer_set(int speed_mode,unsigned int timer_id,unsigned int divider,unsigned int resolution);
int ledc_bind_channel_timer(int speed_mode,int channel_id,unsigned int timer_id);
int ledc_timer_rst(int speed_mode,unsigned int timer_id);
int ledc_timer_resume(int speed_mode,unsigned int timer_id);
int ledc_update_duty(int speed_mode,unsigned int channel_id);
int ledc_set_duty_with_hpoint(int speed_mode,unsigned int channel_id,unsigned int duty,unsigned int hpoint);
int ledc_set_duty(int speed_mode,unsigned int channel_id,unsigned int duty);
int ledc_set_pin_internal(unsigned int pin,unsigned int output_inverted,int speed_mode,int channel_id);
/* Existing separately identified GPIO callees; declarations, not completed reviews. */
int gpio_func_sel(unsigned int pin,unsigned int function);
unsigned long long esp_gpio_reserve(unsigned long long mask);
#define LEDC_CONTEXT_SLOT ((LedcDriverContext *volatile *)0x3fcd86f0U)
#define LEDC_FADE_SLOTS ((LedcFadePrefix *volatile *)0x3fcd86d0U)
#define LEDC_ALLOCATION_MUTEX ((NewlibLock *)0x3fcd86ccU)
#define LEDC_SPINLOCK ((PortMuxWords *)0x3fcabb20U)
#define LEDC_SIGNAL_BASES ((const unsigned char *)0x3c0473ccU)
#define FUN_42017a08 ledc_hal_init
#define FUN_420162d4 ledc_speed_mode_ctx_create
#define FUN_42016350 ledc_fade_hw_acquire
#define FUN_420163a8 ledc_timer_clk_src_set_xpd_in_sleep
#define FUN_42016c50 ledc_set_pin_internal

/* Native configuration loads retain byte/word widths and deliberate reloads. */
typedef struct LedcTimerConfig {
    volatile unsigned int speed_mode;
    volatile unsigned int duty_resolution;
    volatile unsigned int timer_id;
    volatile unsigned int frequency_hz;
    volatile int clock_choice;
    volatile unsigned char deconfigure;
    unsigned char padding15[3];
} LedcTimerConfig;
typedef struct LedcChannelConfig {
    volatile int gpio_pin;
    volatile unsigned int speed_mode;
    volatile unsigned int channel_id;
    volatile unsigned int interrupt_type;
    volatile unsigned int timer_id;
    volatile unsigned int duty;
    volatile int hpoint;
    volatile unsigned int sleep_mode;
    volatile unsigned int flags; /* output inversion bit 0 */
} LedcChannelConfig;
int ledc_slow_clk_calibrate(void);
int ledc_set_timer_div(unsigned int timer_id,int clock_choice,unsigned int frequency_hz,unsigned int resolution);
int ledc_timer_config(const LedcTimerConfig *configuration);
int ledc_channel_config(const LedcChannelConfig *configuration);
int esp_clk_tree_src_get_freq_hz(unsigned int source,unsigned int precision,unsigned int *frequency_hz);
int gpio_sleep_sel_dis(unsigned int pin);
#define LEDC_RC_FAST_HZ (*(volatile unsigned int *)0x3fcd86c8U)
#define LEDC_CLOCK_CHOICES ((const int *)0x3c047368U)
/* Existing RC_FAST frequency getter; its body has a separate queued review. */
unsigned int periph_rtc_dig_clk8m_get_freq(void);
#define FUN_42017bb4 periph_rtc_dig_clk8m_get_freq
#define FUN_420162a0 ledc_slow_clk_calibrate

#define ATOMIC_OPERATION_LOCK ((PortMuxWords *)0x3fcaba80U)
#define GPIO_RESERVED_MASK ((volatile unsigned long long *)0x3fcaba78U)
unsigned long long atomic_fetch_or_u64(volatile unsigned long long *address,unsigned long long mask,int memory_order);

/* Partial GPIO register view through all 54 output-route words; intervening
 * registers not used by these bodies remain explicit unmodeled words. */
typedef struct GpioRegisters {
    unsigned int unmodeled_00[10];
    volatile unsigned int output_enable_clear;        /* 0x028: W1TC */
    unsigned int unmodeled_2c[2];
    volatile unsigned int output_enable_high_clear;   /* 0x034: low 22 bits */
    unsigned int unmodeled_38[71];
    volatile unsigned int input_route[256];           /* 0x154 */
    volatile unsigned int output_route[54];           /* 0x554 */
} GpioRegisters;
typedef struct GpioHal {
    GpioRegisters *volatile device;
} GpioHal;
unsigned long long atomic_fetch_and_u64(volatile unsigned long long *address,unsigned long long mask,int memory_order);
unsigned long long esp_gpio_revoke(unsigned long long mask);
void gpio_sleep_pulldown_dis(unsigned int pin);
void gpio_sleep_pulldown_en(unsigned int pin);
void gpio_sleep_pullup_dis(unsigned int pin);
void gpio_sleep_pullup_en(unsigned int pin);
unsigned int gpio_pullup_en(unsigned int pin);
unsigned int gpio_output_disable(unsigned int pin);
void gpio_iomux_in(unsigned int pin,unsigned int signal);
void gpio_iomux_out(unsigned int pin,unsigned int function);
int gpio_sleep_set_direction(unsigned int pin,unsigned int mode);
unsigned int gpio_sleep_sel_en(unsigned int pin);
#define GPIO_HAL_SLOT ((GpioHal *volatile *)0x3fcab9c8U)
#define GPIO_SLEEP_LOCK ((PortMuxWords *)0x3fcab9ccU)
#define GPIO_IOMUX_TABLE ((volatile unsigned int * const *)0x3c046abcU)

/* Application LED state: byte intensity/ownership and word pattern/status. */
typedef struct LedRuntime {
    volatile unsigned char override_brightness; /* +0 */
    unsigned char reserved_01[3];
    volatile unsigned int override_pattern;     /* +4: off0,steady1,slow2 */
    volatile unsigned char override_owned;      /* +8 */
    unsigned char reserved_09[3];
    volatile unsigned int status;               /* +12: slow1,steady2,fast3 */
} LedRuntime;
typedef struct LedOutputCache {
    volatile unsigned int logical_brightness;
    volatile unsigned char active_high;         /* nonzero means active-high */
    unsigned char reserved_05[3];
} LedOutputCache;
void led_timer_cb(void *unused_argument);
void led_initialize(int gpio_pin,unsigned char active_high);
void led_set_status(unsigned int status);
extern long long signed_remainder_i64(long long numerator,long long denominator) __asm__("__moddi3");
#define LED_RUNTIME ((LedRuntime *)0x3fcd85a8U)
#define LED_OUTPUT ((LedOutputCache *)0x3fcab578U)
void led_override_set(unsigned char mode,unsigned char brightness);
typedef struct ControlLedFlags {
    volatile unsigned char host_override_owned;
    volatile unsigned char device_override_owned;
    union {
        unsigned char primary_interface_selected_raw; /* Same byte, layout alias. */
        volatile unsigned char primary_interface_selected;
    };
    volatile unsigned char host_connected;
} ControlLedFlags;
#define LED_CONTROL_FLAGS ((ControlLedFlags *)0x3fcd7680U)
#define LED_CONTROL_LOCK ((PortMuxWords *)0x3fcab538U)
#define CONTROL_LAST_COMMAND_US ((volatile ClockWords *)0x3fcd7678U)
void control_publish_link_and_interface_state(unsigned char host_connected,
    unsigned char primary_interface_selected);
void FUN_4200a718(unsigned char host_connected,unsigned char primary_interface_selected)
    __asm__("control_publish_link_and_interface_state");
void control_service_led_expiry(unsigned int now_low,unsigned int now_high,
    unsigned char host_connected);
void FUN_4200b4cc(unsigned int now_low,unsigned int now_high,unsigned char host_connected)
    __asm__("control_service_led_expiry");
unsigned char control_release_led_overrides(void);
#define FUN_4200cff4 led_initialize
#define FUN_4200d080 led_set_status

/* Existing native call boundaries used by LED setup/release; separate queued bodies. */
int esp_timer_create(const EspTimerCreateArgs *args,EspTimer **result);
int esp_timer_start_periodic(EspTimer *timer,unsigned long long period_us);
unsigned int link_send_wait100(unsigned char opcode,unsigned char metadata,const void *payload,unsigned short length);

/* Caller-visible OTA operation ABI; lengths arrive as zero-extended LOW16.
 * Volatile pointer/field views retain native reloads, not atomicity. */
typedef int (*UpdateBegin)(void *context,unsigned int image_size);
typedef int (*UpdateWrite)(void *context,const void *payload,unsigned short length);
typedef int (*UpdateFinish)(void *context);
typedef void (*UpdateAbort)(void *context);
typedef struct UpdateStorageOps {
    UpdateBegin volatile begin;
    UpdateWrite volatile write;
    UpdateFinish volatile finish;
    UpdateAbort volatile abort;
} UpdateStorageOps;
typedef struct UpdateHashOps {
    void (*volatile reset)(void *context);
    void (*volatile update)(void *context,const void *payload,unsigned short length);
    unsigned char (*volatile digest)(void *context,unsigned char output[32]);
} UpdateHashOps;
typedef union UpdateState {
    volatile unsigned short word;
    struct { volatile unsigned char active,staged; } bytes;
} UpdateState;
typedef union UpdateSequence {
    volatile unsigned int word;
    struct {
        volatile unsigned short next;
        volatile unsigned short pending_acknowledgement;
    } fields;
} UpdateSequence;
typedef struct UpdateSession {
    const UpdateStorageOps *volatile storage; /* +0 */
    const UpdateHashOps *volatile hash;       /* +4 */
    void *volatile backend_context;                /* +8 */
    UpdateState state;                       /* +0x0c */
    unsigned char reserved_0e[2];
    volatile unsigned int image_size;              /* +0x10 */
    volatile unsigned int bytes_written;           /* +0x14 */
    UpdateSequence sequence;                 /* +0x18: two16-bit counters */
    volatile unsigned char acknowledgement_interval; /* +0x1c;0 means16 */
    unsigned char expected_sha256[32];             /* +0x1d;not word-aligned */
    unsigned char reserved_3d[3];
} UpdateSession;
void update_session_initialize(UpdateSession *session,const UpdateStorageOps *storage,const UpdateHashOps *hash,void *backend_context);
unsigned int update_session_begin(UpdateSession *session,unsigned int image_size,const unsigned char *expected_sha256,unsigned int *detail);
unsigned int update_session_write(UpdateSession *session,unsigned int sequence,const void *payload,unsigned int length,unsigned int *detail,unsigned char *acknowledge);
unsigned int update_session_finish(UpdateSession *session,unsigned int *detail);
void update_session_abort(UpdateSession *session);
unsigned char update_session_is_staged(const UpdateSession *session);
unsigned char update_session_is_active(const UpdateSession *session);
const UpdateStorageOps *update_storage_operations(void);
const UpdateHashOps *update_hash_operations(void);
void *update_backend_context(void);
#define UPDATE_STORAGE_OPERATIONS ((const UpdateStorageOps *)0x3c0464c4U)
#define UPDATE_HASH_OPERATIONS ((const UpdateHashOps *)0x3c0464b8U)
#define UPDATE_SESSION ((UpdateSession *)0x3fcd76c4U)
#define FUN_4200c924 update_session_initialize
#define FUN_4200c93c update_session_begin
#define FUN_4200c9d0 update_session_finish
#define FUN_42020fc4 update_session_write
#define FUN_420210f0 update_session_abort
#define FUN_4202110c update_session_is_staged
#define FUN_42021114 update_session_is_active
#define FUN_4200ccec update_storage_operations
#define FUN_4200ccf4 update_hash_operations
#define FUN_4202111c update_backend_context

/* ESP-IDF DMA/resumable SHA context, verified against the pinned ALT layout. */
typedef struct Sha256Context {
    unsigned int total[2];
    unsigned int state[8];
    unsigned char buffer[64];
    int first_block;
    unsigned int mode;
    unsigned int engine_state;
} Sha256Context;
typedef struct EspPartition {
    struct EspFlash *flash_chip;
    unsigned int type;
    unsigned int subtype;
    unsigned int address;
    unsigned int size;
    unsigned int erase_size;
    char label[17];
    unsigned char encrypted;
    unsigned char readonly;
    unsigned char padding_2b;
} EspPartition;
/* Contiguous MCU-local update backend state; no per-session allocation. */
typedef struct UpdateBackend {
    volatile unsigned char hash_active;           /* +0 */
    unsigned char reserved_01[3];
    Sha256Context hash_context;             /* +4,116 bytes */
    volatile unsigned char write_active;          /* +0x78 */
    unsigned char reserved_79[3];
    const EspPartition *volatile staged_partition; /* +0x7c */
    const EspPartition *volatile candidate_partition; /* +0x80 */
    volatile unsigned int ota_handle;             /* +0x84 */
} UpdateBackend;
int update_flash_begin(void *context,unsigned int image_size);
int update_flash_write(void *context,const void *payload,unsigned short length);
int update_flash_finish(void *context);
void update_flash_abort(void *context);
void update_hash_reset(void *context);
void update_hash_update(void *context,const void *payload,unsigned short length);
unsigned char update_hash_digest(void *context,unsigned char output[32]);
void mbedtls_sha256_init(Sha256Context *context);
int mbedtls_sha256_starts(Sha256Context *context,int is224);
void mbedtls_sha256_free(Sha256Context *context);
#define UPDATE_BACKEND ((UpdateBackend *)0x3fcd8520U)
#define UPDATE_LOG_TAG ((const char *)0x3c0432e0U)
/* Existing SDK call boundaries; their implementations have separate reviews. */
const EspPartition * esp_ota_get_next_update_partition(const EspPartition *start);
int esp_ota_begin(const EspPartition *partition,unsigned int size,volatile unsigned int *handle);
int esp_ota_write(unsigned int handle,const void *payload,unsigned int length);
int esp_ota_end(unsigned int handle);
int esp_ota_abort(unsigned int handle);
int mbedtls_sha256_update(Sha256Context *context,const unsigned char *payload,size_t length);
int mbedtls_sha256_finish(Sha256Context *context,unsigned char output[32]);
#define FUN_4200caec update_flash_begin
#define FUN_4200cac8 update_flash_write
#define FUN_4200ca70 update_flash_finish
#define FUN_4200cbd4 update_flash_abort
#define FUN_4200cba8 update_hash_reset
#define FUN_4200cc38 update_hash_update
#define FUN_4200cc0c update_hash_digest
#define FUN_42017208 mbedtls_sha256_init
#define FUN_4201721c mbedtls_sha256_starts
#define FUN_42021310 mbedtls_sha256_free

/* Application probation globals; claim is one BYTE, timer is one 32-bit slot. */
typedef struct OtaProbation {
    volatile unsigned char claimed;
    unsigned char reserved_01[3];
    EspTimer *volatile timer;
} OtaProbation;
typedef void (*OtaLogHook)(const char *format,...);
#define ROM_DOWNLOAD_REQUEST (*(volatile unsigned int *)0x6000812cU)
void esp_restart(void) __attribute__((noreturn));
int update_activate_staged(void);
void update_running_slot_info(unsigned char *slot,unsigned char *state);
void ota_grace_timer_cb(void *argument);
void ota_start_grace(unsigned int milliseconds);
void confirm_running_image(void);
int esp_ota_mark_app_valid_cancel_rollback(void);
int esp_ota_mark_app_invalid_rollback_and_reboot(void);
int esp_timer_start_once(EspTimer *timer,unsigned long long timeout_us);
int esp_timer_delete(EspTimer *timer);
int esp_timer_stop(EspTimer *timer);
#define OTA_PROBATION ((OtaProbation *)0x3fcd8518U)
#define OTA_PROBATION_LOCK ((PortMuxWords *)0x3fcab570U)
#define OTA_LOG_HOOK ((OtaLogHook)0)
int esp_ota_set_boot_partition(const EspPartition *partition);
int esp_ota_get_state_partition(const EspPartition *partition,unsigned int *state);
const EspPartition *esp_ota_get_running_partition(void);
int esp_ota_current_ota_is_workable(unsigned int valid);
void reboot_to_download(void);
void reboot_to_run(void);
bool ota_running_image_is_pending(void);
void ota_fail_probation(const char *reason);
#define FUN_4200ccb4 update_activate_staged
#define FUN_4200ccfc update_running_slot_info
#define FUN_4200cd74 ota_start_grace
#define FUN_4200eae0 esp_ota_mark_app_valid_cancel_rollback
#define FUN_4200eaec esp_ota_mark_app_invalid_rollback_and_reboot
#define FUN_4200cd50 ota_running_image_is_pending
#define FUN_4200ce08 ota_fail_probation

/* Device update globals: offset/width views proven by original instructions.
 * Reserved bytes have no behavioral name inferred by this review. */
typedef union UpdateVersion {
    volatile unsigned short major_minor;
    struct { volatile unsigned char major,minor,patch; unsigned char reserved; } bytes;
} UpdateVersion;
typedef struct DeviceUpdateBridge {
    volatile unsigned char activation_sequence;       /* +00 */
    unsigned char reserved_01[3];
    volatile unsigned int staging_query_us;           /* +04 */
    volatile unsigned int host_info_query_us;         /* +08 */
    volatile unsigned int mode_refresh_us;            /* +0c */
    volatile unsigned int activation_poll_us;         /* +10 */
    volatile unsigned int activation_started_us;      /* +14 */
    volatile unsigned char activation_state;          /* +18 */
    unsigned char reserved_19[3];
    UpdateVersion host_version;                 /* +1c */
    volatile unsigned short activation_initial_generation; /* +20 */
    volatile unsigned char host_info_known;           /* +22 */
    unsigned char reserved_23;
    volatile unsigned short host_info_generation;     /* +24 */
    volatile unsigned char host_link_state;           /* +26 */
    volatile unsigned char notification_sequence;     /* +27 */
    volatile unsigned int last_activity_us;           /* +28 */
    volatile unsigned int abort_sent_us;              /* +2c */
    volatile unsigned char ignored_abort_answers;     /* +30 */
    volatile unsigned char host_staged;               /* +31 */
    unsigned char reserved_32[2];
    volatile unsigned int activation_error_detail;     /* +34 */
    volatile unsigned char activation_error;          /* +38 */
    volatile unsigned char activation_answer_pending; /* +39 */
    volatile unsigned char local_begin_in_progress;   /* +3a */
    volatile unsigned char relay_active;              /* +3b */
    volatile unsigned char reclone_requested;         /* +3c */
    volatile unsigned char clone_suspended;           /* +3d */
    unsigned char reserved_3e[2];
} DeviceUpdateBridge;
typedef struct UpdateHostCache {
    volatile unsigned char activation_initial_slot;
    volatile unsigned char state;
    volatile unsigned char slot;
    unsigned char reserved_03;
    volatile unsigned short pending_reply;
    unsigned char reserved_06[2];
} UpdateHostCache;
typedef struct UpdateResponse {
    unsigned char operation,target,status,detail[4];
} UpdateResponse;
#define DEVICE_UPDATE ((DeviceUpdateBridge *)0x3fcd7684U)
#define UPDATE_HOST_CACHE ((UpdateHostCache *)0x3fcab540U)
#define DEVICE_UPDATE_LOCK ((PortMuxWords *)0x3fcab548U)
#define DEVICE_UPDATE_TAG ((const char *)0x3c043028U)
void update_relay_abort(void);
unsigned int update_relay_request(unsigned int opcode,unsigned int operation,unsigned int sequence,const void *payload,unsigned int length);
void update_resume_clone(int request_reclone);
void update_resume_clone_if_idle(void);
void update_suspend_clone(void);
unsigned char update_take_reclone_request(void);
void device_update_session_init(void);
unsigned char update_clone_is_suspended(void);
void update_receive_host_reply(unsigned char opcode,const unsigned char *payload,unsigned short length);
void update_set_host_link_state(unsigned char state);
unsigned int firmware_info_encode(unsigned char *output);
void control_send_frame(unsigned char opcode,unsigned char sequence,const void *payload,unsigned int length);
/* Reset body recovered in usb/clone_reset.c; lower-level callees stay queued. */
void clone_reset_and_notify_host(void);
#define FUN_4200b58c update_relay_abort
#define FUN_4200b5dc update_relay_request
#define FUN_4200b648 update_resume_clone
#define FUN_4200b6c4 update_resume_clone_if_idle
#define FUN_4200b700 update_suspend_clone
#define FUN_4200b750 update_take_reclone_request
#define FUN_4200b774 device_update_session_init
#define FUN_4200b794 update_clone_is_suspended
#define FUN_4200bd18 update_receive_host_reply
#define FUN_4200bf0c update_set_host_link_state

void update_command_dispatch(unsigned int sequence,const unsigned char *payload,unsigned short length);
void update_service(unsigned int now_us);
#define FUN_4200c060 update_service

/* Native512-byte stack fragment, word + halfword header stores. */
typedef struct ControlFragmentFrame {
    unsigned int total_and_offset;
    unsigned short count;
    unsigned char data[506];
} ControlFragmentFrame;
#define CONTROL_TX_SCRATCH ((unsigned char *)0x3fcd5fd8U)
#define CONTROL_OPERATION_ACTIVE (*(volatile unsigned int *)0x3fccbfa4U)
void control_fragment_emit(const unsigned char *data,unsigned short total,unsigned short chunk_limit,FragmentCallback callback,void *context);
int control_fragment_accept(ControlAssembly *assembly,const unsigned char *fragment,unsigned short length);
void control_wait_idle_50ms(void);
int control_try_send_encoded(const unsigned char *bytes,unsigned int length);

/* Event-ring descriptors are12 bytes; their storage has a4-byte item header. */
typedef struct ControlEventRing {
    unsigned char *volatile storage;
    volatile unsigned short stride,capacity;
    union {
        struct { volatile unsigned short next_write,count; };
        volatile unsigned int cursor_and_count;
    };
} ControlEventRing;
typedef struct ControlEventRecord {
    unsigned char opcode,reserved;
    unsigned short length;
    unsigned char payload[192];
} ControlEventRecord;
/* Native ctrlevt stack layout: data first, then length, sequence and opcode. */
typedef struct ControlEventWork {
    unsigned char payload[192];
    unsigned short length;
    unsigned char sequence,opcode;
} ControlEventWork;
typedef unsigned int (*ReceiveTimestampReader)(void);
#define CONTROL_EVENT_RINGS ((ControlEventRing *)0x3fcaa7f4U)
#define CONTROL_EVENT_LOCK ((PortMuxWords *)0x3fcaa824U)
#define CONTROL_EVENT_SEQUENCE (*(volatile unsigned char *)0x3fcc4d24U)
#define CONTROL_EVENT_GENERATION (*(volatile unsigned int *)0x3fcc4d1cU)
#define CONTROL_EVENT_TX_BUFFER ((unsigned char *)0x3fcd7274U)
#define INPUT_RECEIVE_TIMESTAMP_READER (*(ReceiveTimestampReader volatile *)0x3fcc00fcU)
#define INPUT_REARM_COALESCED (*(volatile unsigned char *)0x3fcbfef7U)
#define WORKER_WATCHDOG_LOG_TAG ((const char *)0x3c0432b4U)
void control_event_task(void *argument);
void control_protocol_init(void);
void watch_current_task(void);
void feed_current_task_watchdog(void);
unsigned int control_event_generation(void);
void input_set_receive_timestamp_reader(ReceiveTimestampReader reader);
void control_rx_idle_service(void);
void control_event_set_task(RtosTask *task);
int control_event_take(unsigned char *opcode,unsigned char *sequence,void *payload,unsigned short *length,unsigned int pressure);
int control_event_select(unsigned char *opcode,unsigned char *sequence,void *payload,unsigned short *length,int skip_last_ring);
int control_event_ring_pop(ControlEventRing *ring,void *output);
void input_flush_pending(void);
/* Control command callback ABI; recovered body is in app/commands.c. */
void control_command_dispatch(unsigned char opcode,unsigned char sequence,const unsigned char *payload,unsigned short length,void *context);
/* Recovered body: app/input_publication.c. */
int input_publish_pending(int may_read_report_state);
#define FUN_4200c8e8 watch_current_task
#define FUN_4200c91c feed_current_task_watchdog
#define FUN_4203347c control_event_generation
#define FUN_42033bb4 input_set_receive_timestamp_reader
#define FUN_42033bc0 control_rx_idle_service
#define FUN_420389a4 control_event_set_task
#define FUN_420389b0 control_event_take
#define FUN_420294e4 control_event_select
#define FUN_420284ec control_event_ring_pop
#define FUN_4202b100 input_flush_pending

#define MEDIUS_CLONE_CONFIGURATION_COUNT (*(volatile unsigned char *)0x3fcab514U)
#define MEDIUS_CLONE_CONFIGURATION_INDEX (*(volatile unsigned char *)0x3fcd01e0U)
#define CLONE_QUIESCING (*(volatile unsigned char *)0x3fccbfa8U)
#define MEDIUS_REPORT_ARCHIVE ((volatile MediusReportArchive *)0x3fcab508U)
#define MEDIUS_CLONE_REPORT_ASSEMBLY (*(unsigned char *volatile *)0x3fccc9f4U)
#define MEDIUS_CLONE_SERVED_PATCH ((MediusClonePatchTable *)0x3fcc8534U)
#define CLONE_PATCH_REFUSED (*(volatile unsigned char *)0x3fcc8532U)
#define MEDIUS_CLONE_PATCH_IDENTITY_READY (*(volatile unsigned char *)0x3fcc8531U)
/* Recovered clone reset boundaries: usb/clone_reset.c. */
void usb_clone_clear_runtime_state(void);
#define FUN_4202a820 usb_clone_clear_runtime_state
void medius_usb_clone_quiesce_and_clear(void);
#define FUN_4202d3c0 medius_usb_clone_quiesce_and_clear
#define FUN_4203550c clone_reset_and_notify_host

#define USB_INTERFACE_COUNT (*(volatile int *)0x3fccc9e8U)
#define USB_INTERFACE_REPORT_LENGTHS ((const volatile unsigned short *)0x3fccc9dcU)
#define USB_INTERFACE_ENDPOINTS ((const volatile unsigned char *)0x3fccc9c4U)
int link_queue_encoded_frame(LinkTxQueueItem *item,unsigned char opcode,unsigned char metadata,const void *payload,unsigned int length);
void rewrite_unlock(void);
void rewrite_lock(void);
unsigned int medius_report_record_sequence_event(unsigned int endpoint);
void transmit_watchdog_timer_callback(void *argument);
void medius_nonzero_control_stall(const MediusNonzeroControlState *state);
void medius_usb_log_interface_slots(const char *label);
#define FUN_42022a04 link_queue_encoded_frame
#define FUN_420284a0 medius_report_record_sequence_event
#define FUN_42028590 medius_usb_log_interface_slots

/* This publisher copies pending records verbatim; it never decodes their13 bytes. */
typedef struct PendingInputRecord { unsigned char bytes[13]; } PendingInputRecord;
typedef union InputPublishedAxisFields {
    struct { unsigned short offset[4]; unsigned char width[4]; };
    unsigned int words[3];
} InputPublishedAxisFields;
/* Logical wire payload is101 bytes. Three trailing alignment bytes are NOT
 * cleared or transmitted by the publisher. All unaligned bounds use BYTE stores. */
typedef struct InputPublicationWire {
    unsigned short endpoint_report_id,expected_length;
    InputPublishedAxisFields axis_fields;
    unsigned char enabled_axes;
    unsigned char maximum_le[4][4],minimum_le[4][4],primary_scales[32];
    unsigned char profile,scope,bearing_coupled;
    unsigned short bearing_window_ms,riding_window_ms,spread;
    unsigned short period_low,period_high,learned_period_low,learned_period_high;
    unsigned char usb_suspended,observed_axes,render_token;
    unsigned char unused_alignment[3];
} InputPublicationWire;
#define INPUT_PUBLICATION_MUTEX (*(RtosQueue *volatile *)0x3fcbfef8U)
#define INPUT_PENDING_LOCK ((PortMuxWords *)0x3fcaa7b8U)
#define INPUT_PENDING_COUNT (*(volatile unsigned char *)0x3fcbfefcU)
#define INPUT_PENDING_RECORDS ((PendingInputRecord *)0x3fcbff00U)
#define INPUT_PENDING_SNAPSHOT ((PendingInputRecord *)0x3fcbfb70U)
#define INPUT_PENDING_ITEM ((LinkTxQueueItem *)0x3fcbf6f0U)
#define INPUT_METADATA_ITEM ((LinkTxQueueItem *)0x3fcbf8fcU)
#define INPUT_PUBLICATION_WIRE ((volatile InputPublicationWire *)0x3fcbfb08U)
#define INPUT_PUBLISHED_REVISION (*(volatile unsigned int *)0x3fcc0104U)
#define FUN_420295c8 input_publish_pending

/* Auxiliary collector layout: 12 eight-byte noncontrol records, two control
 * endpoint numbers/MPS, counts and separately latched transfer diagnostics.
 * Counts alone determine active records. Reset retains all record payloads. */
typedef struct MediusCloneEndpointTable {
    MediusCloneVendorEndpoint noncontrol[12];
    int noncontrol_count;
    unsigned char control_endpoint[2];
    unsigned short control_max_packet[2];
    unsigned char unknown106[2];
    int control_count;
    union {
        struct { unsigned char has_bulk,has_isochronous; };
        unsigned short transfer_flags;
    };
    unsigned char conflict,unknown115;
} MediusCloneEndpointTable;
/* Four bytes per retained IN binding; first HALFWORD identifies the endpoint
 * and its descriptor byte, second HALFWORD is the saved max-packet size. */
typedef struct MediusCloneRetainedInBinding {
    unsigned short endpoint_descriptor,max_packet;
} MediusCloneRetainedInBinding;
#define MEDIUS_CLONE_AUX_ENDPOINTS ((volatile MediusCloneEndpointTable *)0x3fccbdacU)
#define MEDIUS_CLONE_SERVED_ENDPOINTS ((volatile MediusCloneEndpointTable *)0x3fccbe20U)
#define MEDIUS_CLONE_RETAINED_IN_BINDINGS ((MediusCloneRetainedInBinding *)0x3fcc0138U)
#define MEDIUS_CLONE_ENDPOINT_INDEX_EXCEEDED (*(volatile unsigned char *)0x3fccbfa2U)
#define MEDIUS_CLONE_PACKET_SIZE_EXCEEDED (*(volatile unsigned char *)0x3fccbfa1U)
#define MEDIUS_CLONE_OUT_ENDPOINT_CONFLICT (*(volatile unsigned char *)0x3fccc7f8U)
#define MEDIUS_CLONE_BAD_CONFIGURATION_CHAIN (*(volatile unsigned char *)0x3fccbfa0U)
#define MEDIUS_CLONE_HID_ISOCHRONOUS (*(volatile unsigned char *)0x3fccbf9eU)
#define MEDIUS_CLONE_REPORT_CAPTURE_EXCEEDED (*(volatile unsigned char *)0x3fccbf9dU)
#define MEDIUS_CLONE_REPORT_MISSING (*(volatile unsigned char *)0x3fccbf9cU)
#define MEDIUS_CLONE_CONFIGURATION_TRUNCATED (*(volatile unsigned char *)0x3fccbf9fU)
#define MEDIUS_CLONE_HIGH_SPEED (*(volatile unsigned char *)0x3fccbd47U)
#define MEDIUS_CLONE_CONFIGURATIONS_MISSING (*(volatile unsigned char *)0x3fccbd43U)
#define MEDIUS_CLONE_EXCESS_ENDPOINT_INFO ((unsigned char *)0x3fccbd44U)

/* Native bus0 deinitialization storage; callback table entries are borrowed. */
#define MEDIUS_USBD_EP0_THREAD (*(void *volatile *)0x3fcbc2c4U)
#define MEDIUS_USBD_EP0_QUEUE (*(void *volatile *)0x3fcbc2c0U)
#define MEDIUS_USBD_CLASS_COUNT (*(volatile unsigned char *)0x3fcbc408U)
#define MEDIUS_USBD_CLASS_TABLE ((MediusUsbdClassEventView *volatile *)0x3fcbc2c8U)
int usb_dc_deinit(unsigned int bus);
void medius_usb_osal_thread_delete(void *thread);
void usb_osal_mq_delete(void *queue);
int usbd_deinitialize(unsigned char bus);
/* Reset publication reads only the mask field of this260-byte storage view. */
typedef struct CaptureEditableRule {
    unsigned short id;
    union {
        struct { unsigned char traffic_class,direction; };
        unsigned short class_direction;
    };
    union {
        struct { unsigned char capture_length,reserved5; };
        unsigned short capture_word;
    };
} CaptureEditableRule;
typedef struct CaptureEditableProfile {
    union {
        unsigned char records[256];
        struct {
            CaptureEditableRule rules[32];
            unsigned short rule_drops[32];
        };
    };
    unsigned short class_mask;
    unsigned char count;
    union { unsigned char unknown259,full; };
} CaptureEditableProfile;
#define CAPTURE_SUBSCRIPTION_LOCK ((PortMuxWords *)0x3fcaa82cU)
#define CAPTURE_EDITABLE_PROFILE ((CaptureEditableProfile *)0x3fcc7a1cU)
#define CAPTURE_BANK_STORAGE ((unsigned char *)0x3fcc7814U)
void capture_subscription_update(unsigned char traffic_class,unsigned short id,
    unsigned char direction,unsigned char present,unsigned char capture_length);
#define PACKET_TRIGGER_RESET_STORAGE ((unsigned char *)0x3fcc7b98U)
void capture_clear_subscriptions(void);
void playback_reset_runtime(void);
void input_clear_last_controls(void);
#define FUN_42021a18 usbd_deinitialize
#define FUN_4202a254 capture_clear_subscriptions
#define FUN_42028614 playback_reset_runtime
#define FUN_4202caa8 input_clear_last_controls

/* HID completion interval learner: sampled intervals are in microseconds. */
typedef struct ReportIntervalLearner {
    unsigned int minimum_us,candidate_minimum_us;
    unsigned char sample_count,unknown9[3];
} ReportIntervalLearner;
#define REPORT_CONFIGURED_PERIOD_US ((const volatile unsigned int *)0x3fccc848U)
#define REPORT_INTERVAL_LEARNERS ((ReportIntervalLearner *)0x3fcc10e0U)
#define REPORT_LAST_IN_COMPLETION ((volatile TimestampWords *)0x3fcc10b0U)
#define REPORT_LAST_IN_ACTIVITY ((volatile TimestampWords *)0x3fcc1070U)
#define REPORT_LAST_IN_LENGTH ((volatile unsigned short *)0x3fcc10a0U)
#define MEDIUS_REPORT_COMPLETION_PHASE_REFERENCE (*(const volatile TimestampWords *)0x3fcc1140U)
#define MEDIUS_REPORT_COMPLETION_PHASE_SAMPLES (*(const volatile unsigned char *)0x3fcc114aU)
#define MEDIUS_HID_COMPLETION_DSTS (*(const volatile unsigned int *)0x60080808U)
/* DWC2 frame callback's clock/phase state; reference is in nanoseconds,
 * last_frame_time and the separately published recovery epoch are in us. */
typedef struct UsbFramePhaseState {
    unsigned short frame;
    unsigned char reserved2[6];
    TimestampWords last_frame_time;
    TimestampWords reference_ns;
    unsigned char valid,recovery_mode;
    union {
        struct { unsigned char samples,duplicate_latch; };
        unsigned short samples_and_latch;
    };
    unsigned char double_frame_deferrals,reserved1d[3];
} UsbFramePhaseState;
#define USB_FRAME_PHASE (*(volatile UsbFramePhaseState *)0x3fcc1130U)
#define MEDIUS_USB_FRAME_RECOVERY_EPOCH (*(volatile TimestampWords *)0x3fcc1128U)
#define MEDIUS_USB_FRAME_CREDIT_COUNTDOWN (*(volatile unsigned char *)0x3fcc0ed8U)
#define USB_FRAME_CREDIT_DIRTY (*(volatile unsigned char *)0x3fcc0ed9U)
void medius_usb_frame_schedule_reports(unsigned char bus);
#define FUN_4037b3c4 medius_usb_frame_schedule_reports
void medius_hid_device_in_complete(unsigned char bus,unsigned char endpoint,
    unsigned int actual);
void medius_vendor_device_in_complete(unsigned char bus,unsigned char endpoint,
    unsigned int actual);
#define REPORT_SUBMIT_INPUT_STATES ((InputStateView *volatile *)0x3fccc878U)
void report_discard_interface_pending(unsigned int interface,int clear_submitted);
void report_reset_interface_runtime(unsigned int interface);
#define FUN_40395268 report_discard_interface_pending
#define FUN_42029228 report_reset_interface_runtime

/* EP0 reply assembly fields touched by cancellation, not a full packet view. */
typedef struct MediusEp0ReplyResetView {
    unsigned char unknown0[10];
    unsigned short length;
    unsigned int state;
} MediusEp0ReplyResetView;
#define NONZERO_CONTROL_WORKER_SIGNAL (*(RtosQueue *volatile *)0x3fcc4c7cU)
#define EP0_REPLY_WAITING (*(volatile unsigned char *)0x3fcc4cceU)
#define CONTROL_ENDPOINT_REPLY_SIGNAL (*(RtosQueue *volatile *)0x3fcc4cd0U)
#define MEDIUS_EP0_REPLY_RESULT (*(volatile unsigned int *)0x3fcc445cU)
#define MEDIUS_EP0_REPLY_ASSEMBLY ((volatile MediusEp0ReplyResetView *)0x3fcc3430U)
#define MEDIUS_EP0_WORKER_BUSY (*(volatile unsigned char *)0x3fcc4ccdU)
#define MEDIUS_REPORT_FAST_WORKER_BUSY (*(volatile unsigned char *)0x3fcbfee7U)
#define REPORT_MAINTENANCE_BUSY (*(volatile unsigned char *)0x3fcbfef5U)
#define CLONE_ALTERNATE_SETTINGS ((unsigned char *)0x3fccbe9cU)
#define CLONE_ALTERNATE_PENDING (*(volatile unsigned char *)0x3fccbe94U)
#define MEDIUS_USB_REMOTE_WAKE_ENABLED (*(volatile unsigned char *)0x3fcc4cddU)
#define USB_SUSPENDED (*(volatile unsigned char *)0x3fcc4ce5U)
void out_publish_power_state(void);
#define FUN_42029348 out_publish_power_state
int factory_reset_storage(void);
#define MEDIUS_NONZERO_CONTROL_STATES ((volatile MediusNonzeroControlState *)0x3fcc4ca4U)
#define NONZERO_CONTROL_WORKER_BUSY (*(volatile unsigned char *)0x3fcc4cccU)
#define MEDIUS_REPORT_COMPLETION_BUCKETS ((unsigned char *)0x3fcc1030U)
#define MEDIUS_REPORT_PENDING_ENDPOINTS (*(volatile unsigned short *)0x3fcc1050U)
#define REPORT_INTERFACE_COMPLETING ((volatile unsigned char *)0x3fccc840U)
#define INPUT_CHANGE_SEQUENCE (*(volatile unsigned int *)0x3fcc9d94U)
#define INPUT_CHANGE_EPOCH (*(volatile unsigned short *)0x3fcc9d98U)
#define INPUT_CHANGE_ACKNOWLEDGED (*(volatile unsigned int *)0x3fcc9d9cU)
#define INPUT_ACTIVE_IDENTITY ((volatile unsigned short *)0x3fcc9dd0U)
#define INPUT_PENDING_IDENTITY ((volatile unsigned short *)0x3fcc9dbeU)
#define INPUT_IDENTITY_PENDING (*(volatile unsigned char *)0x3fcc9dc2U)
#define INPUT_IDENTITY_LOADED (*(volatile unsigned char *)0x3fcc9dc3U)
#define INPUT_TIMER_HANDLE (*(EspTimer *volatile *)0x3fcc9db8U)
void medius_out_reconcile_endpoints(const unsigned char *endpoints,const unsigned short *maximum_packet_sizes,int count);

/* Reconstructed instruction utility, not an additional native entry. Preserve
 * QUOU's IntegerDivideByZero exception for denominator0; C's undefined /0 and
 * a fabricated quotient would lose that behavior. No MEMW is introduced. */
static __inline__ __attribute__((always_inline)) unsigned int
xtensa_unsigned_divide(unsigned int numerator,unsigned int denominator)
{
    unsigned int quotient;
    __asm__ volatile ("quou %0, %1, %2" : "=a"(quotient)
                      : "a"(numerator),"a"(denominator) : "memory");
    return quotient;
}

#define INPUT_CHANGE_TIME (*(volatile TimestampWords *)0x3fcc9da8U)
#define INPUT_CHANGE_COMMITTED (*(volatile unsigned char *)0x3fcc9da0U)
unsigned int input_emission_count(void);
void input_begin_change(unsigned char increment_sequence);
void input_advance_change_sequence(void);
void input_commit_change(void);
unsigned short input_change_epoch(void);
#define FUN_420389c8 input_emission_count
#define FUN_420389e8 input_begin_change
#define FUN_42038a40 input_advance_change_sequence
#define FUN_42038a54 input_commit_change
#define FUN_42038aa0 input_change_epoch

/* ESP-IDF NVS API boundaries identified against pinned v5.4.4 nvs_api.cpp.
 * Their separate native implementation bodies are still queued for review. */
typedef unsigned int NvsHandle;
int nvs_open(const char *namespace_name,int mode,NvsHandle *handle);
void nvs_close(NvsHandle handle);
int nvs_commit(NvsHandle handle);
int nvs_get_blob(NvsHandle handle,const char *key,void *output,size_t *length);
int nvs_set_blob(NvsHandle handle,const char *key,const void *payload,size_t length);
int profile_evict_one(int preserve_current,unsigned int identity_first,unsigned int identity_second);
#define FUN_42008b48 profile_evict_one
/* Split identity arrays: these are not an array of interleaved pairs. */
typedef struct ProfileStampQueue {
    unsigned char count,reserved1;
    unsigned short identity_first[8],identity_second[8];
} ProfileStampQueue;
#define PROFILE_STORE_READY (*(volatile unsigned char *)0x3fcd0748U)
#define PROFILE_STORE_MUTEX (*(RtosQueue *volatile *)0x3fcd06bcU)
#define PROFILE_STAMP_QUEUE ((volatile ProfileStampQueue *)0x3fcd0714U)
unsigned char profile_store_blob(unsigned int prefix,unsigned int identity_first,unsigned int identity_second,const void *payload,size_t length);
unsigned char profile_load_baseline(unsigned short identity_first,unsigned short identity_second,void *output,unsigned short *length_out,unsigned short capacity);
unsigned char profile_store_baseline(unsigned short identity_first,unsigned short identity_second,const void *payload,unsigned short length);
unsigned char profile_load_normalization(unsigned short identity_first,unsigned short identity_second,void *output,unsigned short *length_out,unsigned short capacity);
unsigned char profile_store_normalization(unsigned short identity_first,unsigned short identity_second,const void *payload,unsigned short length);
unsigned char profile_load_patches(unsigned short identity_first,unsigned short identity_second,void *output,unsigned short *length_out,unsigned short capacity);
unsigned char profile_load_period(unsigned short identity_first,unsigned short identity_second,unsigned short *period_out);
unsigned char profile_store_period(unsigned short identity_first,unsigned short identity_second,unsigned short period);
unsigned char profile_capture_is_stored(unsigned short identity_first,unsigned short identity_second);
unsigned char profile_store_capture_flag(unsigned short identity_first,unsigned short identity_second);
unsigned char profile_stamp_pending(void);
#define FUN_420099b8 profile_store_baseline
#define FUN_42009a38 profile_store_normalization
#define FUN_42009c40 profile_load_period
#define FUN_42009ca4 profile_store_period
#define FUN_42009cc4 profile_capture_is_stored
#define FUN_42009d2c profile_store_capture_flag
#define FUN_4200927c profile_stamp_pending
#define FUN_42008dac profile_store_blob

int profile_request_baseline(unsigned char *interface_out,unsigned char *report_id_out,unsigned short *length_out);
void profile_refresh_capture_flag(void);
void profile_accept_baseline(unsigned char action,const unsigned char *payload,unsigned short length);
#define FUN_42038ad8 profile_request_baseline
#define FUN_42038b90 profile_refresh_capture_flag
#define FUN_42038bc4 profile_accept_baseline

int nvs_erase_key(NvsHandle handle,const char *key);
int nvs_find_key(NvsHandle handle,const char *key,unsigned int *type);
int nvs_get_u32(NvsHandle handle,const char *key,unsigned int *value);
int nvs_set_u32(NvsHandle handle,const char *key,unsigned int value);
#define PROFILE_PATCH_SCRATCH ((unsigned char *)0x3fcd0208U)
#define PROFILE_STAMP_CACHE_VALID (*(volatile unsigned char *)0x3fcd0740U)
#define PROFILE_STAMP_CACHED_FIRST (*(volatile unsigned short *)0x3fcd073eU)
#define PROFILE_STAMP_CACHED_SECOND (*(volatile unsigned short *)0x3fcd073cU)
#define PROFILE_STAMP_COUNTER (*(volatile unsigned int *)0x3fcd0744U)
unsigned char profile_store_patches(unsigned short identity_first,unsigned short identity_second,const void *payload,unsigned short length);
void profile_process_pending_stamp(void);
#define FUN_42009acc profile_store_patches
#define FUN_42009294 profile_process_pending_stamp

/* Retry counters are independent wrapping BYTEs, not a shared attempt count. */
typedef struct ProfilePersistenceRetries {
    unsigned char period,normalization,baseline,capture_flag;
} ProfilePersistenceRetries;
#define PROFILE_RETRIES (*(volatile ProfilePersistenceRetries *)0x3fcbdeccU)
void profile_persistence_service(void);
#define FUN_42038d30 profile_persistence_service

/* Native NVS entry metadata matches pinned ESP-IDF v5.4.4 nvs.h. */
typedef void *NvsIterator;
typedef struct NvsEntryInfo {
    char namespace_name[16],key[16];
    unsigned int type;
} NvsEntryInfo;
int nvs_flash_init(void);
int nvs_flash_erase(void);
int nvs_entry_find(const char *partition,const char *namespace_name,unsigned int type,NvsIterator *iterator);
int nvs_entry_next(NvsIterator *iterator);
int nvs_entry_info(NvsIterator iterator,NvsEntryInfo *info);
void nvs_release_iterator(NvsIterator iterator);
int nvs_get_u8(NvsHandle handle,const char *key,unsigned char *output);
int nvs_get_u16(NvsHandle handle,const char *key,unsigned short *output);
int nvs_set_u8(NvsHandle handle,const char *key,unsigned char value);
int nvs_set_u16(NvsHandle handle,const char *key,unsigned short value);
int nvs_get_str(NvsHandle handle,const char *key,char *output,size_t *length);
int nvs_set_str(NvsHandle handle,const char *key,const char *value);
#define PROFILE_STORE_STARTED (*(volatile unsigned char *)0x3fcd06b8U)
#define PROFILE_STORE_MUTEX_CONTROL ((RtosQueue *)0x3fcd06c0U)
#define PROFILE_PROTECTED_FIRST (*(volatile unsigned short *)0x3fcd0738U)
#define PROFILE_PROTECTED_SECOND (*(volatile unsigned short *)0x3fcd0736U)
#define PROFILE_PROTECTED_VALID (*(volatile unsigned char *)0x3fcd073aU)
void profile_storage_initialize(void);
void profile_protect_and_queue_stamp(unsigned short identity_first,unsigned short identity_second);
int profile_storage_erase(void);
unsigned char settings_load_flag(const char *key,unsigned char *output);
unsigned char settings_load_u16(const char *key,unsigned short *output);
int settings_load_string(const char *key,char *output,size_t capacity);
unsigned char settings_store_flag(const char *key,unsigned char value);
#define FUN_42009030 profile_storage_initialize
#define FUN_42009188 profile_protect_and_queue_stamp
#define FUN_420094ac profile_storage_erase

/* Native C++ NVS views. Prefixes describe only accessed bytes, not full class
 * sizes. The SDK lock class has no instance members; one byte models its
 * addressable RAII object while construct/destroy use the shared SDK lock. */
typedef struct NvsLockScope { unsigned char empty_object; } NvsLockScope;
struct NvsObject;
/* Item-type arguments use the observed 32-bit register carrier. The upstream
 * C++ ItemType enum has an 8-bit underlying type; no extra truncation is added
 * at these recovered call sites. Size/count outputs are full 32-bit words. */
typedef int (*NvsSetTyped)(struct NvsObject *object,unsigned int type,
    const char *key,const void *data,size_t data_size);
typedef int (*NvsGetTyped)(struct NvsObject *object,unsigned int type,
    const char *key,void *data,size_t data_size);
typedef struct NvsVtable {
    void (*destructor)(struct NvsObject *object);
    void (*deleting_destructor)(struct NvsObject *object);
    int (*set_string)(struct NvsObject *object,const char *key,const char *value);
    int (*set_blob)(struct NvsObject *object,const char *key,const void *data,size_t data_size);
    int (*get_string)(struct NvsObject *object,const char *key,char *output,size_t capacity);
    int (*get_blob)(struct NvsObject *object,const char *key,void *output,size_t capacity);
    int (*get_item_size)(struct NvsObject *object,unsigned int type,const char *key,size_t *size);
    int (*find_key)(struct NvsObject *object,const char *key,unsigned int *type);
    int (*erase_item)(struct NvsObject *object,const char *key);
    int (*erase_all)(struct NvsObject *object);
    int (*commit)(struct NvsObject *object);
    int (*get_used_entry_count)(struct NvsObject *object,size_t *used_entries);
    NvsSetTyped set_typed_item;
    NvsGetTyped get_typed_item;
} NvsVtable;
typedef struct NvsObject {
    const NvsVtable *volatile vtable;
} NvsObject;
typedef struct NvsHandleEntryView {
    union { unsigned int link0; struct NvsHandleEntryView *previous; };
    struct NvsHandleEntryView *next;
    NvsObject *object;
    NvsHandle handle;
    const char *partition_name;
} NvsHandleEntryView;
typedef struct NvsIteratorPrefix {
    union {
        unsigned char unknown0[20];
        struct {
            union {
                unsigned int type;
                struct { unsigned char type_low_byte,reserved_type1[3]; };
            };
            unsigned char namespace_index,reserved5[3];
            unsigned int entry_index;
            struct NvsStorageView *storage;
            void *page;
        };
    };
    NvsEntryInfo entry_info;
} NvsIteratorPrefix;
#define NVS_OPEN_HANDLES (*(NvsHandleEntryView *volatile *)0x3fcd86acU)
void nvs_lock_construct(NvsLockScope *scope);
void nvs_lock_destroy(NvsLockScope *scope);
int nvs_get_str_or_blob(NvsHandle handle,unsigned int type,const char *key,void *output,size_t *length);
#define FUN_42012af0 nvs_get_str_or_blob
#define FUN_42012c6c nvs_find_key
#define FUN_42012cb4 nvs_erase_key
#define FUN_42012db0 nvs_commit
#define FUN_42012de8 nvs_set_str
#define FUN_42012e20 nvs_set_blob
#define FUN_42012ce8 nvs_set_u8
#define FUN_42012d2c nvs_set_u16
#define FUN_42012d70 nvs_set_u32
#define FUN_42012e5c nvs_get_u8
#define FUN_42012e98 nvs_get_u16
#define FUN_42012ed4 nvs_get_u32
#define FUN_42012f10 nvs_get_str
#define FUN_42012f24 nvs_get_blob
#define FUN_42012fec nvs_entry_info
#define FUN_42013018 nvs_release_iterator

/* Native NVS objects, virtual interfaces and RAM layouts. */
struct NvsPartitionObject;
typedef int (*NvsPartitionWriteRaw)(struct NvsPartitionObject *object,size_t offset,const void *data,size_t size);
typedef int (*NvsPartitionEraseRange)(struct NvsPartitionObject *object,size_t offset,size_t size);
typedef int (*NvsPartitionRead)(struct NvsPartitionObject *object,size_t offset,void *data,size_t size);
typedef int (*NvsPartitionWrite)(struct NvsPartitionObject *object,size_t offset,const void *data,size_t size);
typedef struct NvsPartitionVtable {
    union {unsigned int destructor_slot;void (*destroy)(struct NvsPartitionObject *object);};
    void (*deleting_destructor)(struct NvsPartitionObject *object);
    const char *(*get_partition_name)(struct NvsPartitionObject *object);
    union { unsigned int read_raw_slot; NvsPartitionRead read_raw; };
    union { unsigned int read_slot; NvsPartitionRead read; };
    union { unsigned int write_raw_slot; NvsPartitionWriteRaw write_raw; };
    union { unsigned int write_slot; NvsPartitionWrite write; };
    union { unsigned int erase_range_slot; NvsPartitionEraseRange erase_range; };
    union {unsigned int get_address_slot;unsigned int (*get_address)(struct NvsPartitionObject *object);};
    unsigned int (*get_size)(struct NvsPartitionObject *object);
    /* Native callback returns a zero-extended raw BYTE in a 32-bit register;
     * callers test the full register. Preserve noncanonical flag values. */
    unsigned int (*get_readonly)(struct NvsPartitionObject *object);
} NvsPartitionVtable;
typedef struct NvsPartitionObject {
    const NvsPartitionVtable *volatile vtable;
    struct NvsPartitionObject *previous,*next;
} NvsPartitionObject;
typedef struct NvsObjectList { void *head,*tail; unsigned int count; } NvsObjectList;
typedef struct NvsPageManagerView {
    NvsObjectList pages,free_pages;
    void *page_array;
    unsigned int base_sector,managed_page_count,page_sequence;
} NvsPageManagerView;
/* Storage104: PageManager40, namespace-list12, compressed256-bit usage map. */
#define NVS_STORAGE_STATE_ACTIVE 1U
#define NVS_STORAGE_STATE_INVALID 0U
typedef struct NvsStorageView {
    union { unsigned int previous_link; struct NvsStorageView *previous; };
    union { unsigned int next_link; struct NvsStorageView *next; };
    NvsPartitionObject *partition;
    unsigned int page_count;
    union {
        NvsPageManagerView page_manager;
        struct {
            NvsObjectList pages,free_pages;
            void *page_array;
            unsigned int base_sector,managed_page_count,page_sequence;
        };
    };
    NvsObjectList namespaces;
    union {
        unsigned char namespace_usage[32];
        unsigned int namespace_usage_words[8];
    };
    unsigned int storage_state;
} NvsStorageView;
typedef struct NvsSimpleObjectView {
    NvsObject base;
    union { unsigned int previous_link; struct NvsSimpleObjectView *previous; };
    union { unsigned int next_link; struct NvsSimpleObjectView *next; };
    NvsStorageView *storage;
    union {
        unsigned short namespace_and_read_only;
        struct { unsigned char namespace_index,read_only; };
    };
    unsigned char valid,reserved19;
} NvsSimpleObjectView;
typedef struct NvsPartitionManager NvsPartitionManager;
#define NVS_HANDLE_TAIL (*(NvsHandleEntryView *volatile *)0x3fcd86b0U)
#define NVS_HANDLE_COUNT (*(volatile unsigned int *)0x3fcd86b4U)
#define NVS_NEXT_HANDLE (*(volatile unsigned int *)0x3fcd86b8U)
NvsPartitionManager *nvs_partition_manager_get(void);
int nvs_manager_open_handle(NvsPartitionManager *manager,const char *partition,const char *namespace_name,int mode,NvsObject **object);
NvsStorageView *nvs_manager_lookup_storage(NvsPartitionManager *manager,const char *partition);
int nvs_manager_init_partition(NvsPartitionManager *manager,const char *partition);
int nvs_manager_deinit_partition(NvsPartitionManager *manager,const char *partition);
unsigned int nvs_storage_find_entry(NvsStorageView *storage,NvsIteratorPrefix *iterator,const char *namespace_name);
unsigned int nvs_storage_next_entry(NvsStorageView *storage,NvsIteratorPrefix *iterator);
const EspPartition *esp_partition_find_first(unsigned int type,unsigned int subtype,const char *label);
int esp_partition_erase_range(const EspPartition *partition,size_t offset,size_t length);
int nvs_open_from_partition(const char *partition,const char *namespace_name,int mode,NvsHandle *handle);
int nvs_unlink_handles_and_deinit_partition(const char *partition);
int nvs_flash_erase_partition(const char *partition);
const char *nvs_simple_get_partition_name(const NvsSimpleObjectView *handle);
int nvs_lock_initialize(void);
#define FUN_42012a0c nvs_open_from_partition
#define FUN_42012a80 nvs_unlink_handles_and_deinit_partition
#define FUN_42012b64 nvs_flash_init
#define FUN_42012b88 nvs_flash_erase_partition
#define FUN_42012bdc nvs_flash_erase
#define FUN_42012bec nvs_open
#define FUN_42012c0c nvs_close
#define FUN_42012f38 nvs_entry_find
#define FUN_42012fb4 nvs_entry_next
#define FUN_42014b24 nvs_lock_construct
#define FUN_42014b34 nvs_lock_destroy
#define FUN_420211b8 nvs_simple_get_partition_name
#define FUN_42021204 nvs_lock_initialize

typedef struct NvsPartitionManagerVtable {
    void (*destroy)(NvsPartitionManager *object);
    void (*deleting_destructor)(NvsPartitionManager *object);
} NvsPartitionManagerVtable;
struct NvsPartitionManager {
    const NvsPartitionManagerVtable *vtable;
    NvsSimpleObjectView *handle_head,*handle_tail;
    unsigned int handle_count;
    NvsStorageView *storage_head,*storage_tail;
    unsigned int storage_count;
    NvsPartitionObject *partition_head,*partition_tail;
    unsigned int partition_count;
};
#define NVS_MANAGER (*(NvsPartitionManager *volatile *)0x3fcd86bcU)
#define NVS_MANAGER_VTABLE ((const NvsPartitionManagerVtable *)0x3c047288U)
int nvs_manager_close_handle(NvsPartitionManager *manager,NvsSimpleObjectView *handle);
int nvs_manager_init_custom(NvsPartitionManager *manager,NvsPartitionObject *partition,unsigned int base_sector,unsigned int sector_count);
int nvs_storage_initialize(NvsStorageView *storage,unsigned int base_sector,unsigned int sector_count);
void nvs_storage_destroy(NvsStorageView *storage);
int nvs_storage_open_namespace(NvsStorageView *storage,const char *name,unsigned int create,volatile unsigned char *namespace_index);
unsigned int esp_partition_get_main_flash_sector_size(void);
int nvs_lookup_partition(const char *name,NvsPartitionObject *volatile *partition);
#define FUN_42014674 nvs_partition_manager_get
#define FUN_420146a8 nvs_manager_close_handle
#define FUN_420146e0 nvs_manager_lookup_storage
#define FUN_42014704 nvs_manager_init_custom
#define FUN_420147d0 nvs_manager_init_partition
#define FUN_42014854 nvs_manager_deinit_partition
#define FUN_42014918 nvs_manager_open_handle

#define NVS_SIMPLE_VTABLE ((const NvsVtable *)0x3c047214U)
int nvs_simple_commit(NvsObject *object);
void nvs_simple_destroy(NvsObject *object);
void nvs_simple_delete(NvsObject *object);
int nvs_simple_get_used_entry_count(NvsObject *object,size_t *output);
int nvs_simple_erase_item(NvsObject *object,const char *key);
int nvs_simple_erase_all(NvsObject *object);
int nvs_simple_find_key(NvsObject *object,const char *key,unsigned int *output);
int nvs_simple_get_item_size(NvsObject *object,unsigned int type,const char *key,size_t *size);
int nvs_simple_set_string(NvsObject *object,const char *key,const char *value);
int nvs_simple_get_blob(NvsObject *object,const char *key,void *output,size_t size);
int nvs_simple_get_string(NvsObject *object,const char *key,char *output,size_t size);
int nvs_simple_get_typed_item(NvsObject *object,unsigned int type,const char *key,void *output,size_t size);
int nvs_simple_set_blob(NvsObject *object,const char *key,const void *value,size_t size);
int nvs_simple_set_typed_item(NvsObject *object,unsigned int type,const char *key,const void *value,size_t size);
/* These storage callees are typed boundaries; their native bodies have their
 * own review entries, independently from the concrete methods above. */
int nvs_storage_count_entries(NvsStorageView *storage,unsigned int namespace_index,size_t *output);
int nvs_storage_erase_item(NvsStorageView *storage,unsigned int namespace_index,unsigned int type,const char *key);
int nvs_storage_erase_namespace(NvsStorageView *storage,unsigned int namespace_index);
int nvs_storage_find_key(NvsStorageView *storage,unsigned int namespace_index,const char *key,unsigned char *type);
int nvs_storage_get_item_size(NvsStorageView *storage,unsigned int namespace_index,unsigned int type,const char *key,size_t *size);
int nvs_storage_read_item(NvsStorageView *storage,unsigned int namespace_index,unsigned int type,const char *key,void *output,size_t size);
int nvs_storage_write_item(NvsStorageView *storage,unsigned int namespace_index,unsigned int type,const char *key,const void *value,size_t size);
#define FUN_420143c0 nvs_simple_commit
#define FUN_420143d0 nvs_simple_destroy
#define FUN_420145ac nvs_simple_delete
#define FUN_420143e4 nvs_simple_get_used_entry_count
#define FUN_4201440c nvs_simple_erase_item
#define FUN_42014434 nvs_simple_erase_all
#define FUN_42014458 nvs_simple_find_key
#define FUN_4201448c nvs_simple_get_item_size
#define FUN_420144b0 nvs_simple_set_string
#define FUN_420144e8 nvs_simple_get_blob
#define FUN_4201450c nvs_simple_get_string
#define FUN_42014530 nvs_simple_get_typed_item
#define FUN_42014554 nvs_simple_set_blob
#define FUN_42014580 nvs_simple_set_typed_item

/* On-flash NVS item: fixed32 bytes. Blob-index WORD24 and legacy variable
 * HALFWORD24 are distinct views with native access widths preserved. */
#define NVS_ITEM_TYPE_U8         0x01U
#define NVS_ITEM_TYPE_U16        0x02U
#define NVS_ITEM_TYPE_U32        0x04U
#define NVS_ITEM_TYPE_U64        0x08U
#define NVS_ITEM_TYPE_I8         0x11U
#define NVS_ITEM_TYPE_I16        0x12U
#define NVS_ITEM_TYPE_I32        0x14U
#define NVS_ITEM_TYPE_I64        0x18U
#define NVS_ITEM_TYPE_STRING     0x21U
#define NVS_ITEM_TYPE_BLOB       0x41U /* legacy internal blob, not public BLOB */
#define NVS_ITEM_TYPE_BLOB_DATA  0x42U
#define NVS_ITEM_TYPE_BLOB_INDEX 0x48U
#define NVS_ITEM_TYPE_ANY        0xffU
#define NVS_ITEM_CHUNK_ANY       0xffU
#define NVS_ITEM_VERSION_ANY     0xffU
#define NVS_BLOB_VERSION_0_OFFSET 0U
#define NVS_BLOB_VERSION_1_OFFSET 0x80U
#define NVS_ITEM_CHUNK_NUMBER_MASK 0x7fU
#define NVS_NAMESPACE_ANY         0xffU
#define NVS_ENTRY_STATE_ERASED    0U
#define NVS_ENTRY_STATE_WRITTEN   2U
#define NVS_ENTRY_STATE_ILLEGAL   1U
#define NVS_ENTRY_STATE_EMPTY     3U
typedef struct NvsItem {
    union {
        unsigned int header;
        struct {
            union {
                unsigned short namespace_and_type;
                struct { unsigned char namespace_index,type; };
            };
            unsigned char span,chunk_index;
        };
    };
    unsigned int crc32;
    char key[16];
    union {
        struct { unsigned short data_size,reserved; unsigned int data_crc32; } variable;
        struct { unsigned int data_size; unsigned char chunk_count,chunk_start; unsigned short reserved; } blob_index;
        unsigned char data[8];
    };
} NvsItem;
#define NVS_PAGE_STATE_INVALID       0U
#define NVS_PAGE_STATE_UNINITIALIZED 0xffffffffU
#define NVS_PAGE_STATE_ACTIVE        0xfffffffeU
#define NVS_PAGE_STATE_FULL          0xfffffffcU
#define NVS_PAGE_STATE_FREEING       0xfffffff8U
#define NVS_PAGE_STATE_CORRUPT       0xfffffff0U
#define NVS_PAGE_FORMAT_VERSION      0xfeU
#define NVS_PAGE_INVALID_ENTRY       0xffffffffU
#define NVS_PAGE_ENTRY_SIZE          32U
#define NVS_PAGE_ENTRY_COUNT         126U
#define NVS_PAGE_ENTRY_DATA_OFFSET   64U
#define NVS_PAGE_ENTRY_TABLE_OFFSET  32U
#define NVS_PAGE_ERASE_SCAN_SIZE     512U
#define NVS_BLOB_CHUNK_MAX_SIZE ((NVS_PAGE_ENTRY_COUNT - 1U) * NVS_PAGE_ENTRY_SIZE)

/* Complete 84-byte RAM Page, including intrusive links. The flash header
 * is a separate layout. Entry states pack 126 two-bit values into eight
 * words; constructor and erase leave that cached table untouched. */
typedef struct NvsPage {
    struct NvsPage *previous,*next;
    unsigned int base_address,state,sequence;
    unsigned char version,reserved21[3];
    unsigned int entry_state_table[8];
    size_t next_free_entry,first_used_entry;
    union {
        unsigned int entry_counts;
        struct { unsigned short used_entry_count,erased_entry_count; };
    };
    NvsObjectList hash_blocks;
    NvsPartitionObject *partition;
} NvsPage;
int nvs_storage_open_namespace_impl(NvsStorageView *storage,const char *name,unsigned int create,volatile unsigned char *namespace_index);
int nvs_storage_read_multi_page_blob(NvsStorageView *storage,unsigned int namespace_index,const char *key,void *output,size_t size);
int nvs_storage_erase_multi_page_blob(NvsStorageView *storage,unsigned int namespace_index,const char *key,unsigned int chunk_start);
int nvs_page_find_item(NvsPage *page,unsigned int namespace_index,unsigned int type,const char *key,size_t *position,NvsItem *item,unsigned int chunk_index,unsigned int version_offset);
int nvs_page_read_item(NvsPage *page,unsigned int namespace_index,unsigned int type,const char *key,void *output,size_t size,unsigned int chunk_index,unsigned int version_offset);
int nvs_page_erase_entry_and_span(NvsPage *page,size_t position);
int nvs_page_erase_item(NvsPage *page,unsigned int namespace_index,unsigned int type,const char *key,unsigned int chunk_index,unsigned int version_offset);
#define FUN_42013fbc nvs_storage_open_namespace
#define FUN_42013fd8 nvs_storage_read_item
#define FUN_42014068 nvs_storage_erase_item
#define FUN_420140ec nvs_storage_erase_namespace
#define FUN_42014134 nvs_storage_find_key
#define FUN_42014188 nvs_storage_get_item_size
#define FUN_42014244 nvs_storage_count_entries
#define FUN_4201437c nvs_storage_find_entry

typedef struct NvsNamespaceEntry {
    struct NvsNamespaceEntry *previous,*next;
    char name[16];
    unsigned char index,reserved25[3];
} NvsNamespaceEntry;
/* Temporary RAM node40 used to reconcile on-flash blob indexes and chunks.
 * Namespace, stored chunk count and version start are bytes. Sizes and the
 * observed chunk count are 32-bit words; padding byte27 is not initialized. */
typedef struct NvsBlobIndexNode {
    struct NvsBlobIndexNode *previous,*next;
    char key[16];
    unsigned char namespace_index,chunk_count,chunk_start,reserved27;
    unsigned int data_size,observed_data_size,observed_chunk_count;
} NvsBlobIndexNode;
int nvs_storage_populate_blob_indexes(NvsStorageView *storage,NvsObjectList *indexes);
void nvs_storage_erase_mismatched_blob_indexes(NvsStorageView *storage,NvsObjectList *indexes);
void nvs_storage_erase_orphan_blob_data(NvsStorageView *storage,NvsObjectList *indexes);
#define FUN_420131ac nvs_storage_destroy
#define FUN_4201320c nvs_storage_populate_blob_indexes
#define FUN_420132b4 nvs_storage_erase_mismatched_blob_indexes
#define FUN_42013474 nvs_storage_erase_orphan_blob_data
#define FUN_42013580 nvs_storage_initialize
#define FUN_42013ec4 nvs_storage_open_namespace_impl
#define FUN_420142b4 nvs_storage_next_entry

/* Blob index payload8: size WORD0, count/start packed into HALFWORD4,
 * reserved HALFWORD6. Temporary UsedPage12 separately tracks a borrowed Page. */
typedef struct NvsBlobIndexPayload {
    unsigned int data_size;
    unsigned short count_and_start,reserved;
} NvsBlobIndexPayload;
typedef struct NvsUsedPage {
    struct NvsUsedPage *previous,*next;
    NvsPage *page;
} NvsUsedPage;
int nvs_storage_write_multi_page_blob(NvsStorageView *storage,unsigned int namespace_index,const char *key,const void *value,size_t size,unsigned int chunk_start);
int nvs_storage_compare_multi_page_blob(NvsStorageView *storage,unsigned int namespace_index,const char *key,const void *value,size_t size);
unsigned int nvs_crc32_data(const void *data,size_t size,const unsigned int *initial_crc);
/* ESP32-S3 ROM crc32_le at 0x40001c98. The overlapping Bluetooth ROM alias
 * in the raw export does not describe this call's CRC arguments or result. */
unsigned int esp_rom_crc32_le(unsigned int initial_crc,const void *data,unsigned int size) __asm__("crc32_le");
int nvs_page_write_item(NvsPage *page,unsigned int namespace_index,unsigned int type,const char *key,const void *value,size_t size,unsigned int chunk_index);
int nvs_page_compare_item(NvsPage *page,unsigned int namespace_index,unsigned int type,const char *key,const void *value,size_t size,unsigned int chunk_index,unsigned int version_offset);
int nvs_page_read_variable_data(NvsPage *page,const NvsItem *item,size_t position,void *output);
int nvs_page_get_sequence(NvsPage *page,unsigned int *sequence);
int nvs_page_mark_full(NvsPage *page);
unsigned int nvs_page_get_variable_tailroom(NvsPage *page);
int nvs_page_manager_request_new_page(NvsPageManagerView *manager);
#define FUN_42013028 nvs_storage_erase_multi_page_blob
#define FUN_42013724 nvs_storage_write_multi_page_blob
#define FUN_4201395c nvs_storage_read_multi_page_blob
#define FUN_42013a90 nvs_storage_compare_multi_page_blob
#define FUN_42013bb4 nvs_storage_write_item
#define FUN_42014a20 nvs_crc32_data

#define NVS_SECTOR_SIZE (*(volatile unsigned int *)0x3fcd86c4U)
int nvs_page_set_sequence(NvsPage *page,unsigned int sequence);
int nvs_page_erase(NvsPage *page);
int nvs_page_mark_freeing(NvsPage *page);
void nvs_page_initialize_sector_size(void);
int nvs_page_manager_activate_page(NvsPageManagerView *manager);
void nvs_hash_list_clear(NvsObjectList *list);
#define FUN_42015c78 nvs_page_get_sequence
#define FUN_42015ca4 nvs_page_set_sequence
#define FUN_42015cb8 nvs_page_erase
#define FUN_42015cf0 nvs_page_mark_freeing
#define FUN_42015d24 nvs_page_mark_full
#define FUN_42015d54 nvs_page_get_variable_tailroom
#define FUN_42015d84 nvs_page_initialize_sector_size
#define FUN_42015d94 nvs_page_manager_activate_page

/* Link prefix used when clearing blocks; the complete allocation is the
 * 128-byte NvsHashBlock declared below. */
typedef struct NvsHashBlockLinks {
    struct NvsHashBlockLinks *previous,*next;
} NvsHashBlockLinks;
/* Native readItem stack view, based at its item buffer: fixed-size copies
 * with an unusual type's low nibble >8 can also read the cursor and up to
 * three uninitialized stack bytes. Explicit adjacency retains that behavior. */
typedef struct NvsPageReadFrame {
    NvsItem item;
    size_t position;
    unsigned char uninitialized_stack[12];
    size_t capacity;
} NvsPageReadFrame;
void nvs_hash_list_construct(NvsObjectList *list);
void nvs_page_construct(NvsPage *page);
#define FUN_42014b44 nvs_hash_list_clear
#define FUN_42014ce8 nvs_page_construct
#define FUN_42015264 nvs_page_read_variable_data
#define FUN_42015564 nvs_page_read_item
#define FUN_42015740 nvs_page_erase_item
#define FUN_4202120c nvs_hash_list_construct

/* Hash nodes pack an entry-index byte below a 24-bit hash in one word.
 * Counts are words; the native scan does not bound corrupted counts to29. */
typedef union NvsHashSlot {
    unsigned int encoded;
    struct { unsigned char index,hash_bytes[3]; };
} NvsHashSlot;
typedef struct NvsHashBlock {
    struct NvsHashBlock *previous,*next;
    unsigned int count;
    NvsHashSlot slots[29];
} NvsHashBlock;
unsigned int nvs_item_crc32(const NvsItem *item);
unsigned int nvs_item_identity_crc32(const NvsItem *item);
bool nvs_item_header_is_consistent(const NvsItem *item,unsigned int entry_index);
void nvs_hash_list_destroy(NvsObjectList *list);
int nvs_hash_list_insert(NvsObjectList *list,const NvsItem *item,size_t entry_index);
bool nvs_hash_list_erase(NvsObjectList *list,size_t entry_index);
size_t nvs_hash_list_find(NvsObjectList *list,size_t start,const NvsItem *item);
#define FUN_420149cc nvs_item_crc32
#define FUN_420149f8 nvs_item_identity_crc32
#define FUN_42014a38 nvs_item_header_is_consistent
#define FUN_42014b7c nvs_hash_list_destroy
#define FUN_42014b88 nvs_hash_list_insert
#define FUN_42014c04 nvs_hash_list_erase
#define FUN_42014ca0 nvs_hash_list_find

/* Page comparison's native stack view, based at its 32-byte scratch block.
 * running_crc starts uninitialized; a zero-iteration variable comparison
 * reads it. Fixed-size comparisons >8 can also read that word and cursor. */
typedef struct NvsPageCompareFrame {
    unsigned char scratch[32];
    NvsItem item;
    unsigned int running_crc;
    size_t position;
    unsigned char uninitialized_stack[8];
    size_t capacity;
    unsigned int success_status;
} NvsPageCompareFrame;
int nvs_page_initialize(NvsPage *page);
int nvs_page_write_entry(NvsPage *page,const void *entry32);
int nvs_page_write_entry_data(NvsPage *page,const void *data,size_t size);
int nvs_page_alter_entry_state(NvsPage *page,size_t position,unsigned int entry_state);
int nvs_page_alter_entry_range(NvsPage *page,size_t first,size_t end,unsigned int entry_state);
#define FUN_42014f44 nvs_page_write_item
#define FUN_42015108 nvs_page_erase_entry_and_span
#define FUN_420152f8 nvs_page_find_item
#define FUN_42015600 nvs_page_compare_item

typedef struct NvsPageHeader {
    unsigned int state,sequence;
    unsigned char version,reserved[19];
    unsigned int crc32;
} NvsPageHeader;
#define FUN_42014d14 nvs_page_initialize
#define FUN_42014d80 nvs_page_write_entry
#define FUN_42014ecc nvs_page_write_entry_data
#define FUN_4202121c nvs_page_alter_entry_state
#define FUN_42021274 nvs_page_alter_entry_range

int nvs_page_copy_items(NvsPage *source,NvsPage *destination);
int nvs_page_load(NvsPage *page,NvsPartitionObject *partition,unsigned int sector_number);
int nvs_page_load_entry_table(NvsPage *page);
void *cxx_operator_new_array_nothrow(size_t size,const void *nothrow_tag) __asm__("FUN_42017d04");
#define CXX_NOTHROW_TAG ((const void *)0x3c047428U)
#define FUN_42014ddc nvs_page_copy_items
#define FUN_42015b30 nvs_page_load
#define FUN_42015e04 nvs_page_manager_request_new_page
#define FUN_4201577c nvs_page_load_entry_table

/* Concrete ESP partition backend; other Partition implementations retain
 * the base view and their own implementation-specific trailing fields. */
#define ESP_ENCRYPT_BLOCK_SIZE 16U
#define ESP_PARTITION_TYPE_DATA 1U
#define ESP_PARTITION_SUBTYPE_DATA_NVS 2U
typedef struct NvsEspPartition {
    NvsPartitionObject base;
    const EspPartition *descriptor;
} NvsEspPartition;
#define NVS_ESP_PARTITION_VTABLE ((const NvsPartitionVtable *)0x3c047254U)
int nvs_esp_partition_read_raw(NvsPartitionObject *object,size_t offset,void *output,size_t size);
int nvs_esp_partition_write_raw(NvsPartitionObject *object,size_t offset,const void *data,size_t size);
int nvs_esp_partition_erase_range(NvsPartitionObject *object,size_t offset,size_t size);
int nvs_esp_partition_write(NvsPartitionObject *object,size_t offset,const void *data,size_t size);
int nvs_esp_partition_read(NvsPartitionObject *object,size_t offset,void *output,size_t size);
void nvs_esp_partition_construct(NvsEspPartition *partition,const EspPartition *descriptor);
void nvs_exceptionless_delete(void *memory);
int esp_partition_read_raw(const EspPartition *,size_t offset,void *output,size_t size);
int esp_partition_write_raw(const EspPartition *,size_t offset,const void *data,size_t size);
int esp_partition_write(const EspPartition *,size_t offset,const void *data,size_t size);
int esp_partition_read(const EspPartition *,size_t offset,void *output,size_t size);
#define FUN_420145c8 nvs_esp_partition_read_raw
#define FUN_420145e0 nvs_esp_partition_write_raw
#define FUN_420145f8 nvs_esp_partition_erase_range
#define FUN_42014608 nvs_esp_partition_write
#define FUN_42014628 nvs_esp_partition_read
#define FUN_42014648 nvs_esp_partition_construct
#define FUN_42014664 nvs_exceptionless_delete
#define FUN_4201625c nvs_lookup_partition

/* The native Page[] allocation carries a four-byte element-count cookie
 * immediately before the first84-byte Page. page_array points at pages[0]. */
#define NVS_PAGE_ARRAY_MAX_COUNT 0x01861861U
typedef struct NvsPageArrayAllocation {
    unsigned int count;
    NvsPage pages[];
} NvsPageArrayAllocation;

/* Partition list node52 and separately allocated iterator20. The label filter
 * is borrowed; the iterator does not copy the string or own partition nodes. */
typedef struct PartitionListNode {
    EspPartition info;
    unsigned char user_registered,padding_2d[3];
    struct PartitionListNode *next;
} PartitionListNode;
typedef struct PartitionIterator {
    unsigned int type,subtype;
    const char *label;
    PartitionListNode *next_item;
    const EspPartition *info;
} PartitionIterator;
#define PARTITION_LIST (*(PartitionListNode *volatile *)0x3fcd8620U)
#define PARTITION_LIST_LOCK ((NewlibLock *)0x3fcd861cU)
#define DEFAULT_FLASH_CHIP (*(void *volatile *)0x3fcd8664U)
PartitionIterator *esp_partition_find(unsigned int type,unsigned int subtype,const char *label);
PartitionIterator *esp_partition_next(PartitionIterator *iterator);
void esp_partition_iterator_release(PartitionIterator *iterator);
const EspPartition *esp_partition_get(PartitionIterator *iterator);
const EspPartition *esp_partition_verify(const EspPartition *partition);
int esp_partition_mmap(const EspPartition *partition,size_t offset,size_t size,unsigned int memory,
    const void **out_pointer,unsigned int *out_handle);
void esp_partition_munmap(unsigned int handle);
bool esp_partition_is_flash_region_writable(size_t address,size_t size);
bool esp_partition_main_flash_region_safe(size_t address,size_t size);
/* Typed dependencies, with independent review entries for their own bodies. */
int ensure_partitions_loaded(void);
int esp_flash_read(void *chip,void *output,unsigned int address,unsigned int length);
int esp_flash_write(void *chip,const void *data,unsigned int address,unsigned int length);
int esp_flash_write_encrypted(void *chip,unsigned int address,const void *data,unsigned int length);
int esp_flash_erase_region(void *chip,unsigned int address,unsigned int length);
int spi_flash_mmap(size_t address,size_t size,unsigned int memory,const void **out_pointer,
    unsigned int *out_handle);
void spi_flash_munmap(unsigned int handle);
#define FUN_4200ee8c esp_partition_next
#define FUN_4200ef10 esp_partition_find
#define FUN_4200ef60 esp_partition_find_first
#define FUN_4200ef80 esp_partition_iterator_release
#define FUN_4200ef90 esp_partition_get
#define FUN_4200efa8 esp_partition_verify
#define FUN_4200f00c esp_partition_write
#define FUN_4200f074 esp_partition_read_raw
#define FUN_4200f0b0 esp_partition_write_raw
#define FUN_4200f0f4 esp_partition_erase_range
#define FUN_4200f140 esp_partition_mmap
#define FUN_4200f198 esp_partition_read
#define FUN_4200f20c esp_partition_munmap
#define FUN_4200f218 esp_partition_is_flash_region_writable
#define FUN_4200f268 esp_partition_main_flash_region_safe
#define FUN_4200f2a0 esp_partition_get_main_flash_sector_size

/* Aligned RAM copy of a packed 32-byte flash record. Natural alignment 4
 * preserves the native WORD reads after memcpy; disk byte offsets are exact. */
#define PARTITION_TABLE_FLASH_OFFSET 0x8000U
#define PARTITION_TABLE_SCAN_SIZE 0x1000U
#define ESP_PARTITION_MAGIC 0x50aaU
#define ESP_PARTITION_MAGIC_MD5 0xebebU
typedef struct PartitionTableEntry {
    unsigned short magic;
    unsigned char type,subtype;
    unsigned int address,size;
    char label[16];
    unsigned int flags;
} PartitionTableEntry;
/* ESP32-S3 ROM MD5Context88: four state words, two bit-count words,64-byte input. */
typedef struct RomMd5Context {
    unsigned int state[4],bit_count[2];
    unsigned char input[64];
} RomMd5Context;
typedef struct FlashMappingHandle {
    unsigned int *virtual_addresses;
    int count;
} FlashMappingHandle;
/* Native SDK MMU boundaries are declared with their upstream names below. */
bool esp_flash_encryption_enabled(void) __asm__("FUN_4037d7cc");
void MD5Init(RomMd5Context *context); /* ROM0x40001c5c */
void MD5Update(RomMd5Context *context,const void *data,unsigned int length); /* ROM0x40001c68 */
void MD5Final(unsigned char digest[16],RomMd5Context *context); /* ROM0x40001c74 */
#define FUN_4200ec9c ensure_partitions_loaded
#define FUN_42010508 spi_flash_mmap
#define FUN_420105d4 spi_flash_munmap

typedef struct EspFlash EspFlash;
typedef struct FlashHostView FlashHostView;
/* ID dispatch erases the first-argument class: either a chip or a host. */
typedef int (*FlashReadIdOperation)(void *target,unsigned int *flash_id);
/* Native common-command transaction: all 28 bytes, including padding. */
typedef struct FlashTransaction {
    unsigned char reserved,mosi_len,miso_len,address_bitlen;
    unsigned int address;
    const void *mosi_data;
    unsigned char *miso_data;
    unsigned int flags;
    unsigned short command;
    unsigned char dummy_bitlen,reserved23;
    unsigned int io_mode;
} FlashTransaction;
struct FlashSuspendCommands;
typedef struct FlashHostDriverView {
    int (*dev_config)(FlashHostView *);
    int (*common_command)(FlashHostView *host,FlashTransaction *transaction);
    FlashReadIdOperation read_id;
    void (*erase_chip)(FlashHostView *host);
    void (*erase_sector)(FlashHostView *host,unsigned int address);
    void (*erase_block)(FlashHostView *host,unsigned int address);
    int (*read_status)(FlashHostView *host,unsigned char *status);
    int (*set_write_protect)(FlashHostView *host,unsigned char protect);
    void (*program_page)(FlashHostView *host,const void *data,unsigned int address,unsigned int length);
    bool (*supports_direct_write)(FlashHostView *host,const void *data);
    int (*write_data_slicer)(FlashHostView *host,unsigned int address,unsigned int length,
        unsigned int *aligned_address,unsigned int page_size);
    int (*read)(FlashHostView *host,void *output,unsigned int address,unsigned int length);
    bool (*supports_direct_read)(FlashHostView *host,const void *output);
    int (*read_data_slicer)(FlashHostView *host,unsigned int address,unsigned int length,
        unsigned int *aligned_address,unsigned int page_size);
    unsigned int (*host_status)(FlashHostView *host);
    int (*configure_host_io_mode)(FlashHostView *,unsigned int command,
        unsigned int address_bits,int dummy_base,unsigned int io_mode);
    void (*poll_cmd_done)(FlashHostView *);
    int (*flush_cache)(FlashHostView *,unsigned int address,unsigned int length);
    unsigned int check_suspend_slot;
    void (*resume)(FlashHostView *);
    void (*suspend)(FlashHostView *);
    int (*sus_setup)(FlashHostView *host,const struct FlashSuspendCommands *commands);
} FlashHostDriverView; /* accessed prefix88 */
/* ESP32-S3 suspend-command storage and complete48-byte HAL context. */
typedef struct FlashSuspendCommands {
    unsigned int mask;
    unsigned char read_status_command,suspend_command,resume_command,reserved;
} FlashSuspendCommands;
struct FlashHostView {
    const volatile FlashHostDriverView *driver; /* 0x00 */
    volatile unsigned int *spi;              /* 0x04 */
    int cs_num;                             /* 0x08 */
    unsigned char extra_dummy,cs_setup,cs_hold,reserved15;
    unsigned int clock_conf,base_io_mode,flags; /* 0x10,0x14,0x18 */
    FlashSuspendCommands suspend;       /* 0x1c */
    unsigned int slicer_flags;               /* 0x24 */
    int freq_mhz;                            /* 0x28 */
    unsigned char tsus_val,auto_waiti_pes,reserved46[2];
};
typedef struct FlashProtectedRegion { unsigned int offset,size; } FlashProtectedRegion;
typedef int (*FlashEraseOperation)(EspFlash *chip,unsigned int address);
typedef int (*FlashWriteOperation)(EspFlash *chip,const void *data,unsigned int address,unsigned int length);
typedef int (*FlashYieldOperation)(EspFlash *chip,unsigned int status);
typedef struct FlashTimeouts {
    unsigned int idle_timeout,chip_erase_timeout,block_erase_timeout;
    unsigned int sector_erase_timeout,page_program_timeout;
} FlashTimeouts; /* Five unsigned 32-bit delay budgets, in microseconds. */
typedef struct FlashChipDriverView {
    const char *name;
    const volatile FlashTimeouts *timeout;
    int (*probe)(EspFlash *,unsigned int flash_id);
    int (*reset)(EspFlash *);
    int (*detect_size)(EspFlash *,unsigned int *size);
    int (*erase_chip)(EspFlash *);
    FlashEraseOperation erase_sector,erase_block;
    unsigned int sector_size,block_erase_size;
    int (*get_chip_write_protect)(EspFlash *chip,bool *protected);
    int (*set_chip_write_protect)(EspFlash *chip,unsigned char protect);
    unsigned char num_protectable_regions,reserved49[3];
    const FlashProtectedRegion *protectable_regions;
    int (*get_protected_regions)(EspFlash *chip,unsigned long long *mask);
    unsigned int set_protected_regions_slot;
    int (*read)(EspFlash *chip,void *output,unsigned int address,unsigned int length);
    FlashWriteOperation write;
    FlashWriteOperation program_page;
    unsigned int page_size;
    FlashWriteOperation write_encrypted;
    int (*wait_idle)(EspFlash *chip,unsigned int timeout_us);
    int (*set_io_mode)(EspFlash *);
    int (*get_io_mode)(EspFlash *,unsigned int *);
    FlashReadIdOperation read_id;
    int (*read_reg)(EspFlash *chip,unsigned int register_id,unsigned int *value);
    FlashYieldOperation yield;
    int (*suspend_setup)(EspFlash *);
    int (*read_unique_id)(EspFlash *chip,unsigned long long *unique_id);
    unsigned int (*get_chip_caps)(EspFlash *);
    int (*config_host_io_mode)(EspFlash *chip,unsigned int flags);
} FlashChipDriverView; /* accessed prefix124, not the complete driver */
struct EspFlash {
    FlashHostView *host;
    const volatile FlashChipDriverView *chip_driver;
    const volatile MainFlashOsFunctions *os_functions;
    FlashOsContext *os_context;
    unsigned int read_mode,size,chip_id,flags;
};
typedef struct FlashApiFunctions {
    int (*start)(EspFlash *chip);
    int (*end)(EspFlash *chip,int status);
    int (*chip_check)(EspFlash **chip);
    int (*flash_end_flush_cache)(EspFlash *chip,int status,unsigned int bus_acquired,
        unsigned int address,unsigned int length);
} FlashApiFunctions;
/* Loaded table initially contains start4037f0c4,end4037f0f0,chip_check4037df94,
 * flash_end_flush_cache4037df44. Reload it at native callback boundaries. */
#define FLASH_API (*(const volatile FlashApiFunctions *volatile *)0x3fcbca58U)
#define FUN_4037e278 esp_flash_erase_region
#define FUN_4037e490 esp_flash_read
#define FUN_4037e5d4 esp_flash_write
#define FUN_4037e7bc esp_flash_write_encrypted

#define REGISTERED_FLASH_DRIVERS (*(const volatile FlashChipDriverView *const *volatile *)0x3fcaba3cU)
#define ROM_FLASH_LEGACY (*(RomFlashLegacy *volatile *)0x3fceffe4U)
int flash_flush_cache_and_end(EspFlash *,int status,unsigned int bus_acquired,
    unsigned int address,unsigned int length);
int flash_check_chip_pointer(EspFlash **);
int flash_detect_chip_driver(EspFlash *);
int flash_read_id_core(EspFlash *,unsigned int *flash_id,unsigned int sanity_check);
int esp_flash_get_physical_size(void *chip,unsigned int *size);
int esp_flash_read_encrypted(void *chip,unsigned int address,void *output,unsigned int length);
int flash_start_default(EspFlash *);
int flash_end_default(EspFlash *,int status);
bool esp_flash_chip_driver_initialized(const EspFlash *);
#define FUN_4037df44 flash_flush_cache_and_end
#define FUN_4037df94 flash_check_chip_pointer
#define FUN_4037dfb8 flash_detect_chip_driver
#define FUN_4037e048 flash_read_id_core
#define FUN_4037e0ac esp_flash_get_physical_size
#define FUN_4037e750 esp_flash_read_encrypted
#define FUN_4037f0c4 flash_start_default
#define FUN_4037f0f0 flash_end_default
#define FUN_4037f110 esp_flash_chip_driver_initialized

/* Native log table uses a ten-byte stride and an unchecked live mode index. */
#define FLASH_IO_MODE_LABELS ((const char *)0x3c04680cU)
int esp_flash_init_main(void *opaque_chip);
int esp_flash_read_chip_id(EspFlash *chip,unsigned int *flash_id);
#define FUN_4037e114 esp_flash_init_main
#define FUN_42010738 esp_flash_read_chip_id

/* MMU allocator block44. previous_next points to the link which owns this
 * node, rather than directly to the previous node (BSD TAILQ layout). */
struct MmuBlock {
    unsigned int linear_start,linear_end,virtual_start,virtual_end,size,caps;
    unsigned int physical_start,physical_end,target;
    MmuBlock *next;
    MmuBlock **previous_next;
};
typedef struct MmuHardwareRegion {
    unsigned int start,end,size,bus_id,targets,caps;
} MmuHardwareRegion;
#define MMU_CONTEXT ((volatile MmuContext *)0x3fcd8628U)
#define MMU_LOCK ((NewlibLock *)0x3fcd8654U)
#define MMU_LOG_TAG (*(const char *volatile *)0x3fcbc974U)
void esp_mmu_map_init(void);
int esp_mmu_map_get_max_consecutive_free_block_size(unsigned int caps,unsigned int target,size_t *length);
int esp_mmu_map_reserve_block_with_caps(size_t size,unsigned int caps,unsigned int target,const void **output);
int esp_mmu_map(unsigned int address,size_t size,unsigned int target,unsigned int caps,int flags,void **output);
int esp_mmu_unmap(void *address);
int esp_mmu_vaddr_to_paddr(void *address,unsigned int *physical_address,unsigned int *target);
/* Hardware mapping/translation routines have their own review entries. */
void mmu_map_region_with_cache(unsigned int target,unsigned int virtual_address,
    unsigned int physical_address,unsigned int size);
void mmu_unmap_region_with_cache(unsigned int virtual_address,unsigned int size);
bool mmu_hal_check_valid_ext_vaddr_region(unsigned int mmu,unsigned int address,
    unsigned int length,unsigned int type_mask);
bool mmu_hal_vaddr_to_paddr(unsigned int mmu,unsigned int address,
    unsigned int *physical_address,unsigned int *target);
#define FUN_4200fdc0 esp_mmu_map_get_max_consecutive_free_block_size
#define FUN_4200fe48 esp_mmu_map_reserve_block_with_caps

void mmu_freeze_cache(void);
void mmu_invalidate_cache_range(unsigned int virtual_address,unsigned int size);
void mmu_unfreeze_cache(void);
void mmu_hal_map_region(unsigned int mmu,unsigned int target,unsigned int virtual_address,
    unsigned int physical_address,unsigned int length,unsigned int *mapped_length);
void mmu_hal_unmap_region(unsigned int mmu,unsigned int virtual_address,unsigned int length);
unsigned int spi_flash_mmap_get_free_pages(unsigned int memory);
size_t spi_flash_cache2phys(const void *cached);
#define FUN_4037db28 mmu_freeze_cache
#define FUN_4037db30 mmu_invalidate_cache_range
#define FUN_4037db44 mmu_unfreeze_cache
#define FUN_4037db4c mmu_map_region_with_cache
#define FUN_4037dbfc mmu_unmap_region_with_cache
#define FUN_40389714 mmu_hal_map_region
#define FUN_4038979c mmu_hal_unmap_region
#define FUN_40389804 mmu_hal_vaddr_to_paddr
#define FUN_403898b4 mmu_hal_check_valid_ext_vaddr_region
#define FUN_42010618 spi_flash_mmap_get_free_pages
#define FUN_42010638 spi_flash_cache2phys
int esp_mmu_paddr_find_caps(unsigned int physical_address,unsigned int *caps);
bool mmu_hal_paddr_to_vaddr(unsigned int mmu,unsigned int physical_address,
    unsigned int target,unsigned int type,unsigned int *virtual_address);
void esp_cache_suspend_ext_mem_cache(void);
void esp_cache_resume_ext_mem_cache(void);
void flash_suspend_cache(void);
void flash_resume_cache(void);
#define FUN_4037dc14 esp_mmu_paddr_find_caps
#define FUN_4037dcec flash_suspend_cache
#define FUN_4037dcfc flash_resume_cache
#define FUN_40389854 mmu_hal_paddr_to_vaddr
/* ESP32-S3 XTS-AES register prefix: addresses confirmed by native literals. */
typedef struct XtsAesRegisters {
    unsigned char plaintext[64];
    unsigned int size;                     /* 0x40: block bytes >>5 */
    unsigned int destination;              /* 0x44: 0 FLASH */
    unsigned int physical_address;         /* 0x48 */
    unsigned int trigger;                  /* 0x4c */
    unsigned int release;                  /* 0x50 */
    unsigned int destroy;                  /* 0x54 */
    unsigned int state;                    /* 0x58 */
} XtsAesRegisters;
#define XTS_AES_REGISTERS ((volatile XtsAesRegisters *)0x600cc000U)
#define SYSTEM_EXTERNAL_ENCRYPT_CONTROL ((volatile unsigned int *)0x600c004cU)
void spi_flash_encryption_hal_enable(void);
void spi_flash_encryption_hal_disable(void);
void spi_flash_encryption_hal_prepare(unsigned int address,const unsigned int *buffer,unsigned int size);
void spi_flash_encryption_hal_done(void);
void spi_flash_encryption_hal_destroy(void);
bool spi_flash_encryption_hal_check(unsigned int address,unsigned int length);
#define FUN_403898fc spi_flash_encryption_hal_enable
#define FUN_40389920 spi_flash_encryption_hal_disable
#define FUN_40389938 spi_flash_encryption_hal_prepare
#define FUN_40389978 spi_flash_encryption_hal_done
#define FUN_4038999c spi_flash_encryption_hal_destroy
#define FUN_403899ac spi_flash_encryption_hal_check
typedef struct FlashEncryptionFunctions {
    void (*enable)(void);
    void (*disable)(void);
    void (*prepare)(unsigned int address,const unsigned int *buffer,unsigned int size);
    void (*done)(void);
    void (*destroy)(void);
    bool (*check)(unsigned int address,unsigned int length);
} FlashEncryptionFunctions;
/* Native fixed table address; reload each callback slot at its call site. */
#define FLASH_ENCRYPTION_FUNCTIONS ((const volatile FlashEncryptionFunctions *)0x3fcbcb3cU)
int spi_flash_chip_generic_write_encrypted(EspFlash *chip,const void *buffer,
    unsigned int address,unsigned int length);
#define FUN_403905e0 spi_flash_chip_generic_write_encrypted
typedef struct FlashGuardFunctions {
    void (*start)(void);
    void (*end)(void);
} FlashGuardFunctions;
#define FLASH_GUARD (*(const FlashGuardFunctions *volatile *)0x3fcd8660U)
bool bootloader_flash_is_octal_mode_enabled(void);
void spi_flash_restore_cache(void);
void spi_flash_enable_interrupts_caches_no_os(void);
/* Native panic callers put PRID bit 13 in A10; this callee ignores it. */
void panic_restore_caches_boundary(unsigned int ignored_core)
    __asm__("spi_flash_enable_interrupts_caches_no_os");
bool flash_page_is_mapped(unsigned int physical_address,unsigned int *virtual_address);
bool spi_flash_check_and_flush_cache(size_t start_address,size_t length);
void spi_flash_guard_set(const FlashGuardFunctions *functions);
void esp_mspi_pin_init(void);
int spi_flash_init_chip_state(void);
int spi_flash_enable_high_performance_mode(void);
int esp_opiflash_init(unsigned int chip_id) __asm__("FUN_40391720");
#define FUN_40391720 esp_opiflash_init
/* ESP32-S3 ROM octal command descriptors and legacy dispatch table. */
typedef struct OpiFlashCommand {
    unsigned char mode,command_bits;
    unsigned short command;
    unsigned int address;
    unsigned char address_bits,dummy_bits,data_bits;
    unsigned char cs_and_operation; /* chip-select low nibble, write/erase high */
} OpiFlashCommand;
typedef struct OpiFlashCacheRead {
    unsigned char address_bits,dummy_bits;
    unsigned short command;
    unsigned char command_bits,variable_dummy;
} OpiFlashCacheRead;
typedef struct OpiFlashCommandSet {
    OpiFlashCommand read_id,read_status,write_enable,erase_sector;
    OpiFlashCommand erase_block_64k,read,program_page;
    OpiFlashCacheRead cache_read; /* +0x54; total92 bytes including padding */
} OpiFlashCommandSet;
typedef struct RomFlashLegacyFunctions {
    unsigned char program_address_bits,sector_address_bits,block_address_bits,read_address_bits;
    unsigned int read_sub_length,write_sub_length;
    int (*unlock)(void);
    int (*erase_sector)(unsigned int address);
    int (*erase_block)(unsigned int address);
    int (*read)(unsigned int address,void *buffer,int length);
    int (*write)(unsigned int address,const unsigned int *buffer,int length);
    int (*encrypted_write)(unsigned int address,const void *buffer,unsigned int length);
    void (*check_suspend)(void);
    int (*write_enable)(void *chip);
    int (*wait_idle)(void);
    int (*erase_area)(unsigned int address,unsigned int length);
} RomFlashLegacyFunctions;
typedef struct OpiFlashChipFunctions {
    int (*probe)(unsigned int chip_id,unsigned char *vendor);
    void (*initialize)(int read_mode);
    void (*set_required_registers)(unsigned int chip_id);
} OpiFlashChipFunctions;
typedef const volatile OpiFlashChipFunctions *OpiFlashChipFunctionsPointer;
typedef OpiFlashChipFunctionsPointer volatile *OpiFlashChipSlot;
typedef struct OpiFlashSetupRegisters {
    union {unsigned short status_configuration;struct {unsigned char mode,configuration_high;};};
    unsigned char configuration,status;
} OpiFlashSetupRegisters;
#define OPI_FLASH_CHIP_REGISTRY ((OpiFlashChipSlot)0x3fcaba34U)
#define OPI_FLASH_SELECTED_SLOT (*(OpiFlashChipSlot volatile *)0x3fcd8668U)
#define OPI_FLASH_CHIP_ID (*(volatile unsigned int *)0x3fcd866cU)
#define MXIC_STR_COMMANDS ((const volatile OpiFlashCommandSet *)0x3fcbd74cU)
#define OPI_FLASH_LEGACY_FUNCTIONS ((const volatile RomFlashLegacyFunctions *)0x3fcaba00U)
#define ROM_OPI_FLASH_COMMANDS (*(const volatile OpiFlashCommandSet *volatile *)0x3fcefff4U)
#define ROM_FLASH_LEGACY_FUNCTIONS (*(const volatile RomFlashLegacyFunctions *volatile *)0x3fceffe8U)
void esp_rom_spi_set_op_mode(int spi,int read_mode); /* ROM0x400008a0 */
void esp_rom_spi_set_address_bit_len(int spi,unsigned char address_bits); /* ROM0x40000c60 */
void esp_rom_spi_set_dtr_swap_mode(int spi,bool write_swap,bool read_swap); /* ROM0x4000093c */
void esp_rom_opiflash_legacy_driver_init(const volatile OpiFlashCommandSet *commands); /* ROM0x40000954 */
void esp_rom_opiflash_exec_cmd(int spi,int read_mode,unsigned int command,int command_bits,
    unsigned int address,int address_bits,int dummy_bits,unsigned char *mosi,int mosi_bits,
    unsigned char *miso,int miso_bits,unsigned int chip_select_mask,bool write_erase); /* ROM0x400008b8 */
int esp_rom_spiflash_wait_idle(RomFlashChip *chip); /* ROM0x40000960 */
int esp_rom_spiflash_write_enable(RomFlashChip *chip) __asm__("SPI_write_enable"); /* ROM0x40000a44 */
int esp_rom_opiflash_wait_idle(void); /* ROM0x400008e8 */
void esp_rom_opiflash_cache_mode_config(int read_mode,const volatile OpiFlashCacheRead *cache);
int mxic_probe_octal_flash(unsigned int chip_id,unsigned char *vendor);
void mxic_disable_dtr_byte_swaps(unsigned int unused_chip_id);
void mxic_initialize_str_flash(int read_mode);
#define FUN_40385e88 esp_rom_opiflash_cache_mode_config
#define FUN_4039157c mxic_probe_octal_flash
#define FUN_403915c0 mxic_disable_dtr_byte_swaps
#define FUN_403915e0 mxic_initialize_str_flash
void esp_rom_opiflash_pin_config(void); /* ROM0x40000894 */
#define FUN_4037db18 bootloader_flash_is_octal_mode_enabled
#define FUN_4037de40 spi_flash_enable_interrupts_caches_no_os
#define FUN_4037de5c flash_page_is_mapped
#define FUN_4037dea4 spi_flash_check_and_flush_cache
#define FUN_4037df00 spi_flash_guard_set
#define FUN_4037df0c esp_mspi_pin_init
#define FUN_4037df24 spi_flash_init_chip_state
#define FUN_40391574 spi_flash_enable_high_performance_mode
#define MSPI_DEFAULT_PINS ((const volatile unsigned char *)0x3c046800U)
unsigned char esp_psram_impl_get_cs_io(void);
unsigned char esp_psram_io_get_cs_io(void);
unsigned char esp_mspi_get_io(unsigned int signal_role);
void esp_mspi_pin_reserve(void);
unsigned int esp_rom_efuse_get_opiconfig(void);
unsigned int esp_rom_efuse_get_flash_wp_gpio(void); /* ROM0x40001fa4 */
unsigned int esp_rom_efuse_get_flash_gpio_info(void); /* ROM0x40001f74 */
#define FUN_403857a8 esp_psram_impl_get_cs_io
#define FUN_420083c0 esp_psram_io_get_cs_io
#define FUN_4201065c esp_mspi_get_io
#define FUN_420106e0 esp_mspi_pin_reserve
#define FUN_420111b8 esp_rom_efuse_get_opiconfig
int flash_no_os_delay_us(void *unused_context,unsigned int microseconds);
int flash_no_os_end(FlashOsContext *unused_context);
int flash_no_os_start(FlashOsContext *unused_context);
void cache_hal_suspend(unsigned int level,CacheType type);
void cache_hal_resume(unsigned int level,CacheType type);
#define FUN_4037eb10 flash_no_os_delay_us
#define FUN_4037eb20 flash_no_os_end
#define FUN_4037eb34 flash_no_os_start
int nvs_page_manager_load(NvsPageManagerView *manager,NvsPartitionObject *partition,unsigned int base_sector,unsigned int sector_count);
#define FUN_42015ecc nvs_page_manager_load

/* ESP32-S3 spi_flash_hal config: native56-byte stack object, explicit padding. */
typedef struct FlashTimingConfig {
    unsigned int extra_dummy,cs_hold;
    unsigned char cs_setup,reserved9[3];
    unsigned int clock_config;
} FlashTimingConfig;
typedef struct MemspiHostConfig {
    FlashTimingConfig timing;          /* 0x00..0x0f */
    unsigned char iomux,reserved17[3];      /* 0x10 */
    int input_delay_ns,speed,host_id,cs_num; /* 0x14,0x18,0x1c,0x20 */
    unsigned char auto_sus_en,octal_mode_en,using_timing_tuning,reserved39;
    unsigned int default_io_mode;          /* 0x28 */
    int freq_mhz,clock_src_freq;            /* 0x2c,0x30 */
    unsigned char tsus_val,auto_waiti_pes,reserved54[2];
} MemspiHostConfig;
int esp_flash_init_default_chip(void);
void flash_choose_default_io_mode(MemspiHostConfig *config);
void spi_timing_get_flash_timing_param(FlashTimingConfig *unused_output) __attribute__((noreturn));
bool spi_flash_timing_is_tuned(void);
int memspi_host_init_pointers(FlashHostView *host,const MemspiHostConfig *config);
int esp_mspi_32bit_address_flash_feature_check(void);
#define DEFAULT_FLASH_OBJECT ((volatile EspFlash *)0x3fcbca78U)
#define FLASH_DEFAULT_GUARD ((const FlashGuardFunctions *)0x3fcbc978U)
#define MAIN_FLASH_OS_FUNCTIONS ((const volatile MainFlashOsFunctions *)0x3fcbcac8U)
#define MAIN_FLASH_OS_CONTEXT ((volatile FlashOsContext *)0x3fcbcaf0U)
#define MAIN_FLASH_DEVICE_LOCK (*(void *const volatile *)0x3c047140U)
int __esp_system_init_fn_init_disable_rtc_wdt(void);
int __esp_system_init_fn_init_flash(void);
int esp_flash_app_init(void);
int esp_flash_app_enable_os_functions(EspFlash *chip);
void spi_flash_init_lock(void);
void spi_flash_needs_reset_check(void);
#define FUN_4200298c __esp_system_init_fn_init_disable_rtc_wdt
#define FUN_420029b4 __esp_system_init_fn_init_flash
#define FUN_420108c4 esp_flash_app_init
#define FUN_420108e0 esp_flash_app_enable_os_functions

#define DEFAULT_FLASH_HOST ((FlashHostView *)0x3fcbca98U)
#define DEFAULT_MEMSPI_DRIVER ((const volatile FlashHostDriverView *)0x3fcbcb6cU)
#define GPSPI_FLASH_DRIVER ((const volatile FlashHostDriverView *)0x3fcbd2c0U)
/* HAL initializer and divider retain independent native review entries. */
int spi_flash_hal_init(FlashHostView *host,const MemspiHostConfig *config);
#define FUN_4201074c flash_choose_default_io_mode
#define FUN_40384504 spi_timing_get_flash_timing_param
#define FUN_4038457c spi_flash_timing_is_tuned
#define FUN_4038ff70 memspi_host_init_pointers
#define FUN_4037f0bc esp_mspi_32bit_address_flash_feature_check

unsigned int flash_get_clock_divider(const MemspiHostConfig *config);
#define FUN_420111f0 flash_get_clock_divider
#define FUN_42011250 spi_flash_hal_init

/* GPSPI SPI2/SPI3 register prefix through CLOCK_GATE; not the MSPI layout. */
typedef struct GpspiFlashRegisters {
    unsigned int cmd,addr,ctrl,clock,user,user1,user2,ms_dlen,misc;
    unsigned int reserved24[3];
    unsigned int dma_conf;
    unsigned int reserved34[25];
    unsigned int data[16]; /* W0..W15, 0x98..0xd4 */
    unsigned int reserved_d8[4];
    unsigned int clock_gate;
} GpspiFlashRegisters;
int spi_flash_hal_gpspi_device_config(FlashHostView *host);
bool spi_flash_hal_gpspi_supports_direct_write(FlashHostView *unused_host,const void *unused_buffer);
bool spi_flash_hal_gpspi_supports_direct_read(FlashHostView *unused_host,const void *unused_buffer);
unsigned int spi_flash_hal_gpspi_check_status(FlashHostView *host);
void spi_flash_hal_gpspi_poll_cmd_done(FlashHostView *host);
bool spi_flash_hal_supports_direct_write(FlashHostView *host,const void *unused_buffer);
bool spi_flash_hal_supports_direct_read(FlashHostView *host,const void *unused_buffer);
#define FUN_403899bc spi_flash_hal_gpspi_device_config
#define FUN_4038a08c spi_flash_hal_gpspi_supports_direct_write
#define FUN_4038a094 spi_flash_hal_gpspi_supports_direct_read
#define FUN_4038a09c spi_flash_hal_gpspi_check_status
#define FUN_4038a07c spi_flash_hal_gpspi_poll_cmd_done
#define FUN_420113bc spi_flash_hal_supports_direct_write
#define FUN_420113d0 spi_flash_hal_supports_direct_read

unsigned int spi_flash_hal_check_status(FlashHostView *host);
void spi_flash_hal_poll_cmd_done(FlashHostView *host);
void spi_flash_hal_resume(FlashHostView *host);
void spi_flash_hal_suspend(FlashHostView *host);
int memspi_host_read_id_hs(FlashHostView *host,unsigned int *id);
void memspi_host_erase_chip(FlashHostView *host);
void memspi_host_erase_sector(FlashHostView *host,unsigned int address);
void memspi_host_erase_block(FlashHostView *host,unsigned int address);
int memspi_host_read_status_hs(FlashHostView *host,unsigned char *status);
int memspi_host_set_write_protect(FlashHostView *host,unsigned char protect);
void memspi_host_program_page(FlashHostView *host,const void *buffer, unsigned int address,unsigned int length);
int memspi_host_write_data_slicer(FlashHostView *host,unsigned int address, unsigned int length,unsigned int *aligned_address,unsigned int page_size);
int memspi_host_read_data_slicer(FlashHostView *host,unsigned int address, unsigned int length,unsigned int *aligned_address,unsigned int unused_page_size);
#define FUN_4038abdc spi_flash_hal_check_status
#define FUN_4038abcc spi_flash_hal_poll_cmd_done
#define FUN_4038abfc spi_flash_hal_resume
#define FUN_4038ac20 spi_flash_hal_suspend
#define FUN_4038fe0c memspi_host_read_id_hs
#define FUN_40390010 memspi_host_erase_chip
#define FUN_4038fef4 memspi_host_erase_sector
#define FUN_4038ff30 memspi_host_erase_block
#define FUN_4038ffd8 memspi_host_read_status_hs
#define FUN_40390034 memspi_host_set_write_protect
#define FUN_4038feac memspi_host_program_page
#define FUN_40390064 memspi_host_write_data_slicer
#define FUN_4039009c memspi_host_read_data_slicer

void spi_flash_hal_erase_chip(FlashHostView *host);
void spi_flash_hal_erase_sector(FlashHostView *host,unsigned int address);
void spi_flash_hal_erase_block(FlashHostView *host,unsigned int address);
int spi_flash_hal_set_write_protect(FlashHostView *host,unsigned char protect);
void spi_flash_hal_program_page(FlashHostView *host,const void *buffer,unsigned int address,unsigned int length);
int spi_flash_hal_read(FlashHostView *host,void *buffer,unsigned int address,unsigned int length);
int memspi_host_flush_cache(FlashHostView *host,unsigned int address,unsigned int length);
#define FUN_4038a654 spi_flash_hal_erase_chip
#define FUN_4038a67c spi_flash_hal_erase_sector
#define FUN_4038a6ec spi_flash_hal_erase_block
#define FUN_4038a804 spi_flash_hal_set_write_protect
#define FUN_4038a754 spi_flash_hal_program_page
#define FUN_4038a598 spi_flash_hal_read
#define FUN_4038fe90 memspi_host_flush_cache

int spi_flash_hal_device_config(FlashHostView *host);
int spi_flash_hal_setup_read_suspend(FlashHostView *host, const FlashSuspendCommands *commands);
void spi_flash_hal_setup_auto_suspend_mode(FlashHostView *host);
int spi_flash_hal_gpspi_read(FlashHostView *host,void *buffer, unsigned int address,unsigned int length);
#define FUN_4038aa44 spi_flash_hal_device_config
#define FUN_4038a83c spi_flash_hal_setup_read_suspend
#define FUN_40389f84 spi_flash_hal_gpspi_read
#define FUN_4038a8b0 spi_flash_hal_setup_auto_suspend_mode

int spi_flash_hal_gpspi_configure_host_io_mode(FlashHostView *host,unsigned int command,
    unsigned int address_bits,int dummy_base,unsigned int io_mode);
int spi_flash_hal_gpspi_common_command(FlashHostView *host,FlashTransaction *transaction);
#define FUN_40389af8 spi_flash_hal_gpspi_configure_host_io_mode
#define FUN_40389d5c spi_flash_hal_gpspi_common_command

int spi_flash_hal_configure_host_io_mode(FlashHostView *host,unsigned int command,
    unsigned int address_bits,int dummy_base,unsigned int io_mode);
int spi_flash_hal_common_command(FlashHostView *host,FlashTransaction *transaction);
#define FUN_4038a0b0 spi_flash_hal_configure_host_io_mode
#define FUN_4038a3e8 spi_flash_hal_common_command

enum {
    FLASH_CAP_SUSPEND = 1U,
    FLASH_CAP_32MB_SUPPORT = 2U,
    FLASH_CAP_UNIQUE_ID = 4U
};
int spi_flash_chip_issi_probe(EspFlash *unused_chip,unsigned int flash_id);
#define FUN_40390c7c spi_flash_chip_issi_probe
int spi_flash_chip_generic_detect_size(EspFlash *chip,unsigned int *size);
#define FUN_403901d4 spi_flash_chip_generic_detect_size
unsigned int spi_flash_chip_issi_get_caps(EspFlash *unused_chip);
#define FUN_40390ccc spi_flash_chip_issi_get_caps
int spi_flash_chip_gd_probe(EspFlash *unused_chip,unsigned int flash_id);
#define FUN_40390164 spi_flash_chip_gd_probe
int spi_flash_chip_gd_detect_size(EspFlash *chip,unsigned int *size);
#define FUN_403900f4 spi_flash_chip_gd_detect_size
unsigned int spi_flash_chip_gd_get_caps(EspFlash *chip);
#define FUN_403901c0 spi_flash_chip_gd_get_caps
int spi_flash_chip_mxic_probe(EspFlash *chip,unsigned int flash_id);
#define FUN_40390d14 spi_flash_chip_mxic_probe
int spi_flash_chip_mxic_detect_size(EspFlash *chip,unsigned int *size);
#define FUN_40390cd4 spi_flash_chip_mxic_detect_size
unsigned int spi_flash_chip_mxic_get_caps(EspFlash *unused_chip);
#define FUN_40390d34 spi_flash_chip_mxic_get_caps
int spi_flash_chip_winbond_probe(EspFlash *unused_chip,unsigned int flash_id);
#define FUN_40391548 spi_flash_chip_winbond_probe
unsigned int spi_flash_chip_winbond_get_caps(EspFlash *chip);
#define FUN_40391560 spi_flash_chip_winbond_get_caps
int spi_flash_chip_boya_probe(EspFlash *unused_chip,unsigned int flash_id);
#define FUN_403900cc spi_flash_chip_boya_probe
unsigned int spi_flash_chip_boya_get_caps(EspFlash *unused_chip);
#define FUN_403900ec spi_flash_chip_boya_get_caps
int spi_flash_chip_th_probe(EspFlash *unused_chip,unsigned int flash_id);
#define FUN_403912d8 spi_flash_chip_th_probe
unsigned int spi_flash_chip_th_get_caps(EspFlash *unused_chip);
#define FUN_403912f8 spi_flash_chip_th_get_caps
int spi_flash_chip_mxic_opi_probe(EspFlash *chip,unsigned int flash_id);
#define FUN_403912ac spi_flash_chip_mxic_opi_probe
int spi_flash_chip_mxic_opi_detect_size(EspFlash *chip,unsigned int *size);
#define FUN_40390d3c spi_flash_chip_mxic_opi_detect_size
unsigned int spi_flash_chip_mxic_opi_get_caps(EspFlash *unused_chip);
#define FUN_403912c8 spi_flash_chip_mxic_opi_get_caps
int spi_flash_chip_generic_probe(EspFlash *unused_chip,unsigned int unused_id);
#define FUN_403906e0 spi_flash_chip_generic_probe
unsigned int spi_flash_chip_generic_get_caps(EspFlash *chip);
#define FUN_40390358 spi_flash_chip_generic_get_caps

typedef int (*FlashReadStatusOperation)(EspFlash *chip,unsigned int *status);
typedef int (*FlashWriteStatusOperation)(EspFlash *chip,unsigned int status);
int spi_flash_chip_issi_set_io_mode(EspFlash *chip);
#define FUN_40390c9c spi_flash_chip_issi_set_io_mode
int spi_flash_chip_issi_get_io_mode(EspFlash *chip,unsigned int *mode);
#define FUN_40390cb0 spi_flash_chip_issi_get_io_mode
int spi_flash_chip_generic_suspend_cmd_conf(EspFlash *chip);
#define FUN_403903bc spi_flash_chip_generic_suspend_cmd_conf
int spi_flash_chip_gd_set_io_mode(EspFlash *chip);
#define FUN_40390184 spi_flash_chip_gd_set_io_mode
int spi_flash_chip_gd_get_io_mode(EspFlash *chip,unsigned int *mode);
#define FUN_40390148 spi_flash_chip_gd_get_io_mode
int spi_flash_chip_gd_suspend_cmd_conf(EspFlash *chip);
#define FUN_40390128 spi_flash_chip_gd_suspend_cmd_conf
int spi_flash_chip_generic_set_io_mode(EspFlash *chip);
#define FUN_403906c8 spi_flash_chip_generic_set_io_mode
int spi_flash_chip_generic_get_io_mode(EspFlash *chip,unsigned int *mode);
#define FUN_40390a74 spi_flash_chip_generic_get_io_mode
int spi_flash_chip_mxic_opi_set_io_mode(EspFlash *unused_chip);
#define FUN_403912d0 spi_flash_chip_mxic_opi_set_io_mode
int spi_flash_chip_mxic_opi_get_io_mode(EspFlash *chip,unsigned int *mode);
#define FUN_40391230 spi_flash_chip_mxic_opi_get_io_mode
int spi_flash_common_read_status_8b_rdsr(EspFlash *chip,unsigned int *status);
#define FUN_40390b5c spi_flash_common_read_status_8b_rdsr
int spi_flash_common_write_status_8b_wrsr(EspFlash *chip,unsigned int status);
#define FUN_40390b90 spi_flash_common_write_status_8b_wrsr
int spi_flash_common_read_status_16b_rdsr_rdsr2(EspFlash *chip,unsigned int *status);
#define FUN_40390ab0 spi_flash_common_read_status_16b_rdsr_rdsr2
int spi_flash_common_write_status_16b_wrsr(EspFlash *chip,unsigned int status);
#define FUN_40390a44 spi_flash_common_write_status_16b_wrsr
int spi_flash_common_read_status_8b_rdsr2(EspFlash *chip,unsigned int *status);
#define FUN_40390b28 spi_flash_common_read_status_8b_rdsr2
int spi_flash_common_write_status_8b_wrsr2(EspFlash *chip,unsigned int status);
#define FUN_40390bc0 spi_flash_common_write_status_8b_wrsr2
int spi_flash_common_set_io_mode(EspFlash *chip,FlashWriteStatusOperation write_status, FlashReadStatusOperation read_status,unsigned int qe_mask);
#define FUN_40390bf0 spi_flash_common_set_io_mode
int spi_flash_chip_generic_read_reg(EspFlash *chip,unsigned int unused_reg_id,unsigned int *out_reg);
#define FUN_40390948 spi_flash_chip_generic_read_reg
int spi_flash_chip_mxic_read_unique_id(EspFlash *unused_chip,unsigned long long *unused_unique_id);
#define FUN_40390b20 spi_flash_chip_mxic_read_unique_id

void *memset(void *buffer,int byte_value,size_t length); /* ROM 0x400011e8 */
int spi_flash_chip_generic_reset(EspFlash *chip);
#define FUN_403906e8 spi_flash_chip_generic_reset
int spi_flash_chip_generic_erase_chip(EspFlash *chip);
#define FUN_40390744 spi_flash_chip_generic_erase_chip
int spi_flash_chip_generic_erase_sector(EspFlash *chip,unsigned int address);
#define FUN_403907cc spi_flash_chip_generic_erase_sector
int spi_flash_chip_generic_erase_block(EspFlash *chip,unsigned int address);
#define FUN_40390860 spi_flash_chip_generic_erase_block
int spi_flash_chip_generic_get_write_protect(EspFlash *chip,bool *protected);
#define FUN_40390694 spi_flash_chip_generic_get_write_protect
int spi_flash_chip_generic_set_write_protect(EspFlash *chip,unsigned char protect);
#define FUN_403908f4 spi_flash_chip_generic_set_write_protect
int spi_flash_chip_generic_read(EspFlash *chip,void *buffer,unsigned int address,unsigned int length);
#define FUN_403903dc spi_flash_chip_generic_read
int spi_flash_chip_generic_write(EspFlash *chip,const void *buffer,unsigned int address,unsigned int length);
#define FUN_40390478 spi_flash_chip_generic_write
int spi_flash_chip_generic_page_program(EspFlash *chip,const void *buffer,unsigned int address,unsigned int length);
#define FUN_403909dc spi_flash_chip_generic_page_program
int spi_flash_chip_generic_wait_idle(EspFlash *chip,unsigned int timeout_us);
#define FUN_4039095c spi_flash_chip_generic_wait_idle
int spi_flash_chip_generic_read_unique_id(EspFlash *chip,unsigned long long *unique_id);
#define FUN_4039054c spi_flash_chip_generic_read_unique_id
int spi_flash_chip_generic_yield(EspFlash *chip,unsigned int wip);
#define FUN_4039050c spi_flash_chip_generic_yield

/* ROM flash dummy-cycle profile; six independent mode bytes. */
typedef struct FlashDummyCycles {
    unsigned char dual_io,quad_io,quad_output,dual_output,fast_read,slow_read;
} FlashDummyCycles;
#define FLASH_DUMMY_CYCLES_HIGH_PERFORMANCE (*(const volatile FlashDummyCycles *volatile *)0x3fcbcb54U)
#define FLASH_DUMMY_CYCLES_NORMAL (*(const volatile FlashDummyCycles *volatile *)0x3fcbcb58U)
int spi_flash_chip_generic_config_host_io_mode(EspFlash *chip,unsigned int flags);
#define FUN_40390214 spi_flash_chip_generic_config_host_io_mode

int spi_flash_chip_winbond_read(EspFlash *chip,void *buffer,unsigned int address,unsigned int length);
#define FUN_40391300 spi_flash_chip_winbond_read
int spi_flash_chip_winbond_erase_sector(EspFlash *chip,unsigned int address);
#define FUN_40391448 spi_flash_chip_winbond_erase_sector
int spi_flash_chip_winbond_erase_block(EspFlash *chip,unsigned int address);
#define FUN_403913b4 spi_flash_chip_winbond_erase_block
int spi_flash_chip_winbond_page_program(EspFlash *chip,const void *buffer,unsigned int address,unsigned int length);
#define FUN_403914d8 spi_flash_chip_winbond_page_program

int spi_flash_chip_mxic_opi_erase_chip(EspFlash *chip);
#define FUN_40390ddc spi_flash_chip_mxic_opi_erase_chip
int spi_flash_chip_mxic_opi_erase_sector(EspFlash *chip,unsigned int address);
#define FUN_40390e64 spi_flash_chip_mxic_opi_erase_sector
int spi_flash_chip_mxic_opi_erase_block(EspFlash *chip,unsigned int address);
#define FUN_40390ef0 spi_flash_chip_mxic_opi_erase_block
int spi_flash_chip_mxic_opi_get_write_protect(EspFlash *chip,bool *protected);
#define FUN_4039119c spi_flash_chip_mxic_opi_get_write_protect
int spi_flash_chip_mxic_opi_set_write_protect(EspFlash *chip,unsigned char protect);
#define FUN_40390d70 spi_flash_chip_mxic_opi_set_write_protect
int spi_flash_chip_mxic_opi_write(EspFlash *chip,const void *buffer, unsigned int address,unsigned int length);
#define FUN_40390fb0 spi_flash_chip_mxic_opi_write
int spi_flash_chip_mxic_opi_page_program(EspFlash *chip,const void *buffer, unsigned int address,unsigned int length);
#define FUN_40391044 spi_flash_chip_mxic_opi_page_program
int spi_flash_chip_mxic_opi_read_id(void *chip_pointer,unsigned int *chip_id);
#define FUN_403910c8 spi_flash_chip_mxic_opi_read_id
int spi_flash_chip_mxic_opi_read_reg(EspFlash *chip,unsigned int reg_id, unsigned int *status);
#define FUN_403911d0 spi_flash_chip_mxic_opi_read_reg

int spi_flash_chip_mxic_opi_config_host_io_mode(EspFlash *chip,unsigned int flags);
#define FUN_40390f7c spi_flash_chip_mxic_opi_config_host_io_mode

/* Native Newlib string-write vector (8 bytes) and request (12 bytes).
 * The writer consumes residual, ignores count, and keeps vectors unchanged. */
typedef struct MediusNewlibInputVector {
    const void *base;
    unsigned int length;
} MediusNewlibInputVector;
typedef struct MediusNewlibStringWriteRequest {
    const MediusNewlibInputVector *vectors;
    int count;
    unsigned int residual;
} MediusNewlibStringWriteRequest;
extern void *medius_newlib_malloc_r(NewlibReent *,unsigned int size) __asm__("_malloc_r");
extern void *medius_newlib_realloc_r(NewlibReent *,void *buffer,unsigned int size) __asm__("_realloc_r");
extern void medius_newlib_free_r(NewlibReent *,void *buffer) __asm__("_free_r");
int medius_newlib_write_string_vectors(NewlibReent *,NewlibFile *,
    MediusNewlibStringWriteRequest *);
#define FUN_42020ac8 medius_newlib_write_string_vectors

extern NewlibReent *medius_current_newlib_reent(void) __asm__("__getreent");
extern int medius_newlib_vformat_stream(NewlibReent *,NewlibFile *,
    const char *format,va_list arguments);
int vprintf(const char *format,va_list arguments);
int medius_single_byte_decode_u16(void *,volatile unsigned short *,
    const volatile unsigned char *,unsigned int available);
int medius_single_byte_encode_u16(NewlibReent *,volatile unsigned char *,
    unsigned short character);
#define FUN_42021654 medius_single_byte_decode_u16
#define FUN_42021674 medius_single_byte_encode_u16

/* Linker/ROM heap reservation records: unsigned address bits, eight-byte stride. */
typedef struct ReservedMemoryRegion {
    unsigned int start,end;
} ReservedMemoryRegion;
#define SOC_MEMORY_REGION_COUNT (*(const volatile unsigned int *)0x3c045fc4U)
#define RESERVED_MEMORY_START 0x3c04819cU
#define RESERVED_MEMORY_END 0x3c0481ccU
unsigned int panic_get_address(const void *);
#define FUN_42020c54 panic_get_address
unsigned int panic_get_cause(const void *);
#define FUN_42020c5c panic_get_cause
void panic_set_address(void *,unsigned int);
#define FUN_42020c64 panic_set_address
bool heap_caps_match(const HeapRegion *,unsigned int);
#define FUN_42020c6c heap_caps_match
int heap_compare_reserved_regions(const void *,const void *);
#define FUN_42020c94 heap_compare_reserved_regions
unsigned int soc_get_available_memory_region_max_count(void);
#define FUN_42004320 soc_get_available_memory_region_max_count

/* Device controller binding: only the second word is interpreted here. */
typedef struct {
    unsigned int uninterpreted0;
    volatile MediusDwc2CoreRegisters *registers;
} MediusUsbdControllerBinding;
#define MEDIUS_USBD_CONTROLLERS ((volatile MediusUsbdControllerBinding *)0x3fcd85c4U)

/* Shared unaligned-IN diagnostics, written even before size rejection. */
typedef struct {
    unsigned char endpoint;
    unsigned char padding1[3];
    unsigned int length;
    unsigned char *source_buffer;
    unsigned int unaligned_count;
} UsbdUnalignedWriteDiagnostics;
#define USBD_UNALIGNED_WRITE ((volatile UsbdUnalignedWriteDiagnostics *)0x3fcc27d8U)
#define MEDIUS_USBD_IN_BOUNCE ((unsigned char *)0x3fcad6d8U)
#define MEDIUS_USBD_EP0_STALL_FLAG (*(volatile unsigned char *)0x3fcd01f6U)

int usbd_ep_start_write(unsigned char bus,unsigned char endpoint,unsigned char *buffer,unsigned int length);
void medius_usb_scheduler_delay_u8(unsigned int delay);
int usbd_ep_set_stall(unsigned char bus,unsigned char endpoint);
int usbd_set_address(unsigned char bus,unsigned char address);
unsigned char usbd_get_port_speed(unsigned char bus);
unsigned char usbd_get_ep_mult(unsigned char bus,unsigned char endpoint);
void usbd_event_suspend_handler(unsigned char bus);
void usbd_desc_register(unsigned char bus,void *descriptors);
void usbd_add_interface(unsigned char bus,unsigned char *interface_storage);
void usbd_add_endpoint(unsigned char bus,MediusUsbEndpointRegistration *registration);
unsigned char usbd_get_ep0_next_state(unsigned char bus);
int medius_usbd_ep0_task_exists(unsigned char bus);
/* Callback ABI views; these alias the existing native EP0 handlers. */
extern void medius_usbd_ep0_in_callback(unsigned char,unsigned char,unsigned int)
    __asm__("usbd_event_ep0_in_complete_handler");
extern void medius_usbd_ep0_out_callback(unsigned char,unsigned char,unsigned int)
    __asm__("usbd_event_ep0_out_complete_handler");

#define MEDIUS_USBD_EP0_STATUS_FLAGS ((volatile unsigned char *)0x3fcd85ccU)
int usb_osal_mq_recv(void *queue,void *output,int timeout);
int usb_osal_mq_send(void *queue,unsigned int value);
void *usb_osal_mq_create(unsigned int length);
void *medius_usb_osal_thread_create(char *name,unsigned int stack_bytes,
    unsigned int priority,TaskEntry task_entry,void *argument);
int usbd_ep_start_read(unsigned char bus,unsigned char endpoint,unsigned char *buffer,unsigned int length);
void medius_dwc2_abort_ep0_in(unsigned char bus);
void usbd_event_ep0_in_complete_handler(unsigned char bus,unsigned int unused_endpoint,unsigned int bytes);
void usbd_event_ep0_out_complete_handler(unsigned char bus,unsigned int unused_endpoint,unsigned int bytes);
void usbd_event_ep0_setup_complete_handler(unsigned int bus,const void *setup);
void usbd_event_ep_in_complete_handler(unsigned char bus,unsigned char endpoint,unsigned int bytes);
void usbd_event_ep_out_complete_handler(unsigned char bus,unsigned char endpoint,unsigned int bytes);
int medius_usbd_open_descriptor_endpoint(unsigned int bus,unsigned char *descriptor);
int usbd_initialize(unsigned char bus,void *controller_registers,MediusUsbdBusEventHandler callback);
int usb_dc_init(unsigned int bus);
void usb_dc_low_level_init(unsigned int bus);
void usb_dc_low_level_deinit(void);
void medius_dwc2_device_params(unsigned int register_base,unsigned char *parameters);
extern int medius_usbd_open_endpoint(unsigned char bus,const MediusUsbEndpointDescriptor *descriptor)
    __asm__("usbd_ep_open");
extern void medius_usbd_ep0_task_entry(void *argument) __asm__("usbd_ep0_thread");

/* Per-bus BYTE flags consumed by the EP0 worker, not controller registers. */
#define MEDIUS_EP0_HANDLER_CONSUMED_FLAGS ((volatile unsigned char *)0x3fcd85c0U)
#define MEDIUS_EP0_SETUP_CONSUMED_FLAGS ((volatile unsigned char *)0x3fcd85bcU)
#define MEDIUS_EP0_LENGTH_OVERRIDE_FLAGS ((volatile unsigned char *)0x3fcd85b8U)
void usbd_ep0_thread(void *argument);
/* Typed caller view of the pending native request dispatcher. */
extern unsigned int medius_usbd_dispatch_request(unsigned int bus,
    MediusUsbSetupPacket *setup,unsigned char **data,unsigned int *length)
    __asm__("usbd_setup_request_handler");

/* DWC2 scheduler RAM: queue stride is 17, not the gap between bus-0 globals. */
#define MEDIUS_DWC2_CONTEXT_BASE 0x3fcbc590U
#define MEDIUS_DWC2_ALLOCATED ((volatile unsigned char *)0x3fcd8600U)
#define MEDIUS_DWC2_PRIORITY_MASKS ((volatile unsigned short *)0x3fcd85d0U)
#define MEDIUS_DWC2_READY_BASE 0x3fcd85e8U
#define MEDIUS_DWC2_TOKEN_WAIT_BASE 0x3fcd85d4U
#define MEDIUS_DWC2_DRIVER_LOCK ((PortMuxWords *)0x3fcab580U)
unsigned int medius_dwc2_find_free_fifo(unsigned int bus,unsigned int preferred);
int medius_dwc2_fifo_priority_eligible(unsigned int bus,unsigned int endpoint);
int medius_dwc2_endpoint_is_queued(unsigned int bus,unsigned int endpoint);
void medius_dwc2_endpoint_queue_insert(unsigned char *queue,unsigned int endpoint,int at_front);
void medius_dwc2_arm_setup_size(unsigned char bus,unsigned char endpoint);
void dwc2_ep_write(unsigned char bus,unsigned char endpoint,unsigned char *source,unsigned short length);
void medius_dwc2_assign_fifo_and_start(unsigned int bus,unsigned int endpoint,unsigned int fifo);
void medius_dwc2_drain_ready_queue(unsigned int bus);
void dwc2_tx_fifo_empty_process(unsigned char bus,unsigned char endpoint);
unsigned int usbd_dwc2_get_system_clock(void);

#define MEDIUS_DWC2_DYNAMIC_FIFO_MODE ((const volatile unsigned char *)0x3fcd85fcU)
void medius_dwc2_release_idle_fifo(unsigned int bus,unsigned int endpoint);
void medius_dwc2_remove_scheduled_transfer(unsigned int bus,unsigned int endpoint,int force_release);
void medius_dwc2_rewind_partial_in(unsigned int bus,unsigned int endpoint,unsigned int packets_remaining);
void medius_dwc2_schedule_in(unsigned int bus,unsigned int endpoint,unsigned int length);
void dwc2_ep_read(unsigned char bus,unsigned char *destination,unsigned short length);
void medius_dwc2_cancel_in(unsigned char bus,unsigned char endpoint);
int dwc2_in_endpoint_is_busy(unsigned char bus,unsigned char endpoint);

/* Logger RAM recovered from native loads; cache is 31 eight-byte entries.
 * packed_level_generation uses level bits0..2 and generation bits3..31.
 */
typedef struct LogTagListNode {
    struct LogTagListNode *next;
    unsigned char level;
    char tag[];
} LogTagListNode;
typedef struct LogCacheEntry {
    const char *tag;
    unsigned int packed_level_generation;
} LogCacheEntry;
/* Contiguous logger globals; this storage view is not an allocated SDK object. */
typedef struct LogState {
    unsigned int early_base_ms;
    LogTagListNode *list;
    unsigned int cache_misses;
    unsigned int cache_count;
    unsigned int cache_generation;
    LogCacheEntry entries[31];
    RtosQueue *mutex;
} LogState;
/* The print hook receives a native va_list by value and borrowed format/data.
 * Its signed result is ignored by esp_log_write. */
typedef int (*LogVprintf)(const char *format,va_list arguments);
typedef struct LogOutputConfig {
    LogVprintf print;
    unsigned int default_level;
} LogOutputConfig;
void esp_log_impl_lock(void);
bool esp_log_impl_lock_timeout(void);
void esp_log_impl_unlock(void);
unsigned int esp_log_level_get_timeout(const char *tag);
LogVprintf esp_log_set_vprintf(LogVprintf callback);
bool esp_log_linked_list_get_level(const char *tag,unsigned int *level);
void esp_log_cache_heap_bubble_down(int index);
bool esp_log_cache_get_level(const char *tag,unsigned int *level);
void esp_log_cache_add(const char *tag,unsigned int level);
/* Native constructor prepares source queue-type1; optimized callee ignores it. */
extern RtosQueue *log_create_mutex(unsigned char queue_type)
    __asm__("xQueueCreateMutex");
unsigned int ets_get_cpu_frequency(void);
/* Read this CPU's wrapping 32-bit CCOUNT once; no memory fence or synchronization. */
static __inline__ __attribute__((always_inline)) unsigned int esp_cpu_get_cycle_count(void)
{
    unsigned int cycles;
    __asm__ volatile ("rsr.ccount %0" : "=a"(cycles));
    return cycles;
}
#define LOG_STATE ((volatile LogState *)0x3fcbd8f4U)
#define LOG_OUTPUT ((volatile LogOutputConfig *)0x3fcaa54cU)
#define FUN_42003d1c esp_log_linked_list_get_level
#define FUN_42003d48 esp_log_cache_heap_bubble_down
#define FUN_42003d9c esp_log_cache_get_level
#define FUN_42003e54 esp_log_cache_add

/* Device boot-log ring: text slots are copied bytes, not guaranteed strings. */
typedef struct DeviceLogHistory {
    unsigned char flushed,next,count,padding3;
    unsigned short lengths[24];
    unsigned char text[24][160];
} DeviceLogHistory;
typedef struct ControlLogPacket {
    unsigned char severity;
    unsigned char text[160];
} ControlLogPacket;
#define DEVICE_LOG_HISTORY ((volatile DeviceLogHistory *)0x3fcd0940U)
#define DEVICE_LOG_BUSY (*(volatile unsigned char *)0x3fcd0749U)
void control_log_emit(const unsigned char *text,int length);
int device_log_hook(const char *format,va_list arguments);
int vsnprintf(char *destination,size_t capacity,const char *format,va_list arguments);

/* Accessed ESP32-S3 eFuse readback WORDs; gaps remain uninterpreted. */
typedef struct EfuseReadRegisters {
    unsigned char unmodeled_00[0x34];
    unsigned int repeat_data1;
    unsigned char unmodeled_38[8];
    unsigned int repeat_data4;
    unsigned char unmodeled_44[12];
    unsigned int mac_spi_sys3,mac_spi_sys4,mac_spi_sys5;
    unsigned char unmodeled_5c[16];
    unsigned int sys_part1_data4;
} EfuseReadRegisters;
#define EFUSE_READ_REGISTERS ((const volatile EfuseReadRegisters *)0x60007000U)
/* eFuse descriptors are four native bytes. The block occupies a byte in the
 * SDK enum bitfield; preserve its four-byte aggregate alignment while using
 * explicit byte/halfword fields for the native read widths.
 */
typedef struct EfuseDescriptor {
    unsigned char block;
    unsigned char bit_start;
    unsigned short bit_count;
} __attribute__((aligned(4))) EfuseDescriptor;
typedef struct EfuseRegisterRange {
    unsigned int start;
    unsigned int end; /* Inclusive address of the last readable WORD. */
} EfuseRegisterRange;
typedef int (*EfuseChunkProcessor)(unsigned int register_index,unsigned int block,
    int bit_start,int bit_count,void *output,int *processed_bits);
enum EfuseReadStatus {
    ESP_ERR_INVALID_ARG = 0x102,
    ESP_ERR_CODING = 0x1604,
    ESP_ERR_DAMAGED_READING = 0x1606
};
#define EFUSE_REGISTER_RANGES ((const volatile EfuseRegisterRange *)0x3c045d7cU)
#define EFUSE_BURN_COUNTER (*(volatile unsigned int *)0x3fcbd7c4U)
/* Six consecutive descriptors: block1, bits40,32,24,16,8,0, eight bits each.
 * The pointer list ends with NULL; the descriptors also happen to be contiguous.
 */
#define EFUSE_MAC_FACTORY ((const EfuseDescriptor *const *)0x3fcaa500U)
int efuse_read_blob_retry(const EfuseDescriptor *const *field,
    void *destination,size_t destination_bits);
int esp_efuse_read_field_blob(const EfuseDescriptor *const *field,
    void *destination,size_t destination_bits);
int esp_efuse_utility_count_once(unsigned int register_index,unsigned int block,
    int bit_start,int bit_count,void *output,int *processed_bits);
int esp_efuse_utility_process(const EfuseDescriptor *const *field,
    void *output,size_t output_bits,EfuseChunkProcessor process);
unsigned int esp_efuse_utility_read_reg(unsigned int block,unsigned int register_index);
int esp_efuse_utility_fill_buff(unsigned int register_index,unsigned int block,
    int bit_start,int bit_count,void *output,int *processed_bits);
int esp_efuse_get_field_size(const EfuseDescriptor *const *field);
int esp_efuse_utility_get_number_of_items(int bits,int item_bits);
int esp_efuse_mac_get_default(unsigned char *mac);
void identity_initialize(void);
/* This caller supplies SDK queue-type1; the specialized callee ignores it. */
RtosQueue *identity_create_mutex(unsigned char queue_type)
    __asm__("xQueueCreateMutex");
#define FUN_420025c4 efuse_read_blob_retry
#define FUN_42002600 esp_efuse_read_field_blob
#define FUN_42002640 esp_efuse_utility_count_once
#define FUN_420026a4 esp_efuse_utility_process
#define FUN_420027e0 esp_efuse_utility_read_reg
#define FUN_42002818 esp_efuse_utility_fill_buff
#define FUN_42020be4 esp_efuse_get_field_size
#define FUN_42020c08 esp_efuse_utility_get_number_of_items
#define FUN_420116d0 esp_efuse_mac_get_default
#define FUN_42035ca0 identity_initialize

unsigned int efuse_hal_chip_revision(void);
unsigned int efuse_hal_blk_version(void);
bool efuse_hal_get_disable_wafer_version_major(void);
bool efuse_hal_get_disable_blk_version_major(void);
bool efuse_hal_flash_encryption_enabled(void);
unsigned int efuse_hal_get_major_chip_version(void);
unsigned int efuse_hal_get_minor_chip_version(void);
#define FUN_40376440 efuse_hal_chip_revision
#define FUN_40376458 efuse_hal_blk_version
#define FUN_4037647c efuse_hal_get_disable_wafer_version_major
#define FUN_40376490 efuse_hal_get_disable_blk_version_major
#define FUN_403764a4 efuse_hal_flash_encryption_enabled
#define FUN_403764cc efuse_hal_get_major_chip_version
#define FUN_4037650c efuse_hal_get_minor_chip_version

/* Clock queries: register prefixes contain only the accessed named WORDs. */
/* Modeled SYSTEM prefix: intervening hardware words are opaque here. */
typedef struct ClockSystemRegisters {
    unsigned char unmodeled_00[0x10];
    volatile unsigned int cpu_per_conf;       /* SYSTEM +0x10 */
    unsigned char unmodeled_14[0x4c];
    volatile unsigned int sysclk_conf;        /* SYSTEM +0x60 */
} ClockSystemRegisters;
typedef struct ClockFrequencyCache {
    unsigned int rc_fast_d256_hz;
    unsigned int xtal32k_hz;
} ClockFrequencyCache;
enum ClockPrecision {
    ESP_CLK_TREE_SRC_FREQ_PRECISION_CACHED = 0,
    ESP_CLK_TREE_SRC_FREQ_PRECISION_APPROX = 1,
    ESP_CLK_TREE_SRC_FREQ_PRECISION_EXACT = 2,
    ESP_CLK_TREE_SRC_FREQ_PRECISION_INVALID = 3
};
enum ModuleClock {
    SOC_MOD_CLK_CPU = 1, SOC_MOD_CLK_RTC_FAST = 2,
    SOC_MOD_CLK_RTC_SLOW = 3, SOC_MOD_CLK_APB = 4,
    SOC_MOD_CLK_PLL_F80M = 5, SOC_MOD_CLK_PLL_F160M = 6,
    SOC_MOD_CLK_PLL_D2 = 7, SOC_MOD_CLK_XTAL32K = 8,
    SOC_MOD_CLK_RC_FAST = 9, SOC_MOD_CLK_RC_FAST_D256 = 10,
    SOC_MOD_CLK_XTAL = 11, SOC_MOD_CLK_TEMP_SENSOR = 12,
    SOC_MOD_CLK_INVALID = 13
};
#define CLOCK_SYSTEM_REGISTERS ((ClockSystemRegisters *)0x600c0000U)
#define RTC_SLOW_PERIOD_Q19 (*(volatile unsigned int *)0x60008054U)
unsigned int esp_clk_tree_rc_fast_d256_get_freq_hz(unsigned int precision);
unsigned int esp_clk_tree_xtal32k_get_freq_hz(unsigned int precision);
unsigned int esp_clk_tree_lp_slow_get_freq_hz(unsigned int precision);
unsigned int esp_clk_tree_rc_fast_get_freq_hz(unsigned int precision);
unsigned int esp_clk_tree_lp_fast_get_freq_hz(unsigned int precision);
unsigned int clk_hal_xtal_get_freq_mhz(void);
unsigned int clk_hal_cpu_get_freq_hz(void);
unsigned int clk_hal_apb_get_freq_hz(void);
unsigned int clk_hal_lp_slow_get_freq_hz(void);
void esp_clk_slowclk_cal_set(unsigned int new_period_q19);
#define CLOCK_FREQUENCY_CACHE ((ClockFrequencyCache *)0x3fcbda60U)
#define PERIPHERAL_RCC_LOCK ((PortMuxWords *)0x3fcaa574U)
#define REGI2C_LOCK ((PortMuxWords *)0x3fcaa57cU)
#define PERIPHERAL_RCC_REFERENCE_COUNTS ((volatile unsigned char *)0x3fcbda24U)
unsigned char periph_rcc_release_enter(int peripheral);
void periph_rcc_release_exit(int peripheral,unsigned char remaining_count);
/* External ROM boundaries: 0x40005d54, 0x40005d60, 0x40005d6c. */
unsigned char rom_i2c_readReg_Mask(unsigned char block,unsigned char host_id,
    unsigned char register_address,unsigned char most_significant_bit,unsigned char least_significant_bit);
void rom_i2c_writeReg(unsigned char block,unsigned char host_id,
    unsigned char register_address,unsigned char value);
void rom_i2c_writeReg_Mask(unsigned char block,unsigned char host_id,
    unsigned char register_address,unsigned char most_significant_bit,unsigned char least_significant_bit,
    unsigned char value);
/* RTC accounting returns 64 bits; the calibration setter discards them. */
#define FUN_4200730c esp_clk_tree_rc_fast_d256_get_freq_hz
#define FUN_42007358 esp_clk_tree_xtal32k_get_freq_hz
#define FUN_420073a4 esp_clk_tree_lp_slow_get_freq_hz
#define FUN_420073f4 esp_clk_tree_rc_fast_get_freq_hz
#define FUN_42007448 esp_clk_tree_lp_fast_get_freq_hz
#define FUN_42011410 clk_hal_xtal_get_freq_mhz
#define FUN_42011450 clk_hal_cpu_get_freq_hz
#define FUN_420114fc clk_hal_apb_get_freq_hz
#define FUN_420113e4 clk_hal_lp_slow_get_freq_hz
#define FUN_4200460c esp_clk_slowclk_cal_set

/* SDK retain_mem_t as ordered WORDs, with its original 8-byte alignment.
 * reserved is preserved after initialization and participates in the checksum. */
typedef struct RtcRetainedTime {
    unsigned int time_us_low, time_us_high;
    unsigned int last_ticks_low, last_ticks_high;
    unsigned int reserved;
    unsigned int checksum;
} __attribute__((aligned(8))) RtcRetainedTime;
#define RTC_RETAINED_TIME ((volatile RtcRetainedTime *)0x600fffe8U)
unsigned long long esp_rtc_get_time_us(void);
#define RTC_TIME_FIRST_CALL (*(volatile unsigned char *)0x3fcaa560U)
#define RTC_TIME_LOCK ((PortMuxWords *)0x3fcaa564U)
#define FUN_42004524 esp_rtc_get_time_us

/* GPTimer objects recovered from allocation sizes and native field accesses. */
typedef struct GptimerRegisters {
    volatile unsigned int configuration, count_low, count_high, update;
    volatile unsigned int alarm_low, alarm_high, reload_low, reload_high, load;
} GptimerRegisters;                 /* 0x24 per counter */
typedef struct GptimerGroupRegisters {
    GptimerRegisters timers[2];
    volatile unsigned int watchdog_config0;
    unsigned char uninterpreted4c[0x24];
    volatile unsigned int interrupt_enable, interrupt_raw, interrupt_status, interrupt_clear;
} GptimerGroupRegisters;            /* accessed prefix0x80 */
typedef struct TimerHal {
    GptimerGroupRegisters *volatile dev;
    volatile unsigned int timer_id;
} TimerHal;
typedef struct GptimerAlarmEvent {
    unsigned long long count_value, alarm_value;
} GptimerAlarmEvent;
unsigned int decision_timer_alarm_callback(Gptimer *timer,
    const GptimerAlarmEvent *event,void *context);
/* Native ISR consumes a full-WORD nonzero return when requesting a yield. */
typedef unsigned int (*GptimerAlarmCallback)(Gptimer *timer,const GptimerAlarmEvent *event,void *user_context);
typedef struct {
    GptimerAlarmCallback on_alarm;
} GptimerCallbacks;
typedef struct GptimerGroup {
    volatile int group_id;
    PortMuxWords lock;
    Gptimer *volatile timers[2];
} GptimerGroup;
typedef union GptimerFlags {
    volatile unsigned int word;
    volatile unsigned char low_byte;
} GptimerFlags;
struct Gptimer {
    GptimerGroup *volatile group;   /* +0x00 */
    volatile unsigned int timer_id;      /* +0x04 */
    volatile unsigned int resolution_hz; /* +0x08 */
    unsigned int padding0c;
    union { unsigned long long reload_count; struct { volatile unsigned int reload_low,reload_high; }; };
    union { unsigned long long alarm_count; struct { volatile unsigned int alarm_low,alarm_high; }; };
    volatile unsigned int direction;     /* +0x20 */
    TimerHal hal;                  /* +0x24 */
    volatile unsigned int fsm;           /* +0x2c */
    volatile unsigned int intr_priority; /* +0x30 */
    InterruptHandle *volatile intr;     /* +0x34 */
    PortMuxWords lock;             /* +0x38 */
    GptimerAlarmCallback volatile on_alarm; /* +0x40 */
    void *volatile user_context;         /* +0x44 */
    volatile unsigned int clock_source;  /* +0x48 */
    void *volatile pm_lock;              /* +0x4c */
    GptimerFlags flags;            /* +0x50 */
    unsigned int padding54;              /* +0x54; unused trailing ABI padding */
};                                      /* allocated0x58 */
typedef struct {
    unsigned int clock_source,direction,resolution_hz,intr_priority,flags;
} GptimerConfig;
typedef struct GptimerAlarmWords {
    unsigned int alarm_low,alarm_high,reload_low,reload_high,flags,padding20;
} GptimerAlarmWords;
typedef struct GptimerPlatform {
    NewlibLock mutex;
    GptimerGroup *volatile groups[2];
    volatile unsigned int reference_counts[2];
} GptimerPlatform;
typedef struct GptimerSignals { int module; unsigned int irq[2]; } GptimerSignals;
#define GPTIMER_PLATFORM ((GptimerPlatform *)0x3fcd8698U)
#define GPTIMER_SIGNALS ((const GptimerSignals *)0x3c0473d0U)
#define GPTIMER_SYSTEM ((volatile SystemClockRegistersPrefix *)0x600c0000U)
#define GPTIMER_GROUP0 ((GptimerGroupRegisters *)0x6001f000U)
#define GPTIMER_GROUP1 ((GptimerGroupRegisters *)0x60020000U)
void timer_hal_init(TimerHal *hal,unsigned int group_id,unsigned int timer_id);
void timer_hal_set_counter_value(TimerHal *hal,unsigned long long value);
unsigned long long timer_hal_capture_and_get_counter_value(TimerHal *hal);
void gptimer_default_isr(void *argument);
GptimerGroup *gptimer_acquire_group_handle(unsigned int group_id);
void gptimer_release_group_handle(GptimerGroup *group);
int gptimer_select_periph_clock(Gptimer *timer,unsigned int source,unsigned int requested_hz);
int gptimer_destroy(Gptimer *timer);
int gptimer_new_timer(const GptimerConfig *config,Gptimer **output);
int gptimer_register_event_callbacks(Gptimer *timer,const GptimerCallbacks *callbacks,void *user_context);
int gptimer_enable(Gptimer *timer);
int gptimer_start(Gptimer *timer);
int esp_pm_lock_acquire(void *handle);
int esp_pm_lock_delete(void *handle);
int esp_intr_enable(InterruptHandle *handle);
/* Five-argument compiler call boundary retained. This build's generic
 * helper also forwards a sixth incoming register; weak/order fields have
 * no effect on either path. Fourth/fifth caller WORDs are both5. */
extern unsigned int gptimer_compare_exchange(volatile unsigned int *object,
    unsigned int *expected,unsigned int desired,int success_order,int failure_order) __asm__("atomic_compare_exchange_u32");
extern int gptimer_alloc_interrupt(unsigned int irq,unsigned int flags,unsigned int status_address,unsigned int status_mask,void (*handler)(void *),void *argument,InterruptHandle **output) __asm__("esp_intr_alloc_intrstatus");
#define FUN_40383f68 gptimer_default_isr
#define FUN_4038aec4 timer_hal_capture_and_get_counter_value
#define FUN_42024800 timer_hal_init
#define FUN_42024848 timer_hal_set_counter_value
#define FUN_42011a04 gptimer_acquire_group_handle
#define FUN_42011b00 gptimer_release_group_handle
#define FUN_42022a7c gptimer_destroy
#define FUN_42022fb8 gptimer_start
#define FUN_4037f11c esp_pm_lock_acquire
#define FUN_42021328 esp_pm_lock_delete
unsigned char periph_rcc_release_enter(int peripheral);
void periph_rcc_release_exit(int peripheral,unsigned char reference_count);

/* Xtensa conditional store: returns the observed WORD, storing desired only
 * when it equals expected. The memory clobber adds no explicit MEMW. */
static __inline__ __attribute__((always_inline)) unsigned int xtensa_compare_store_u32(
    volatile unsigned int *address,unsigned int expected,unsigned int desired)
{
    __asm__ volatile (
        "wsr.scompare1 %2\n"
        "s32c1i %0, %3, 0\n"
        : "+a"(desired), "+m"(*address)
        : "a"(expected), "a"(address)
        : "memory");
    return desired;
}
unsigned int atomic_compare_exchange_byte(volatile unsigned char *address,unsigned char *expected,
    unsigned int desired,unsigned char ignored_weak,int ignored_success_order,int ignored_failure_order);
unsigned int atomic_compare_exchange_u32(volatile unsigned int *address,unsigned int *expected,
    unsigned int desired,unsigned char ignored_weak,int ignored_success_order,int ignored_failure_order);
unsigned int atomic_compare_exchange_u8_s32c1i(volatile unsigned char *address,unsigned char *expected,
    unsigned int desired,unsigned char ignored_weak,int ignored_success_order,int ignored_failure_order);
unsigned int atomic_compare_exchange_u32_s32c1i(volatile unsigned int *address,unsigned int *expected,
    unsigned int desired,unsigned char ignored_weak,int ignored_success_order,int ignored_failure_order);
unsigned int atomic_fetch_add_u32(volatile unsigned int *address,unsigned int value,int ignored_memory_order);
unsigned int atomic_fetch_sub_u32(volatile unsigned int *address,unsigned int value,int ignored_memory_order);
unsigned int atomic_fetch_add_u32_s32c1i(volatile unsigned int *address,unsigned int value,int ignored_memory_order);
unsigned int atomic_fetch_sub_u32_s32c1i(volatile unsigned int *address,unsigned int value,int ignored_memory_order);
#define FUN_4038fadc atomic_compare_exchange_byte
#define FUN_4038fb48 atomic_compare_exchange_u32
#define FUN_4038fbac atomic_fetch_add_u32
#define FUN_4038fbf0 atomic_fetch_sub_u32
#define FUN_4038fd14 atomic_compare_exchange_u8_s32c1i
#define FUN_4038fd80 atomic_compare_exchange_u32_s32c1i
#define FUN_4038fd9c atomic_fetch_add_u32_s32c1i
#define FUN_4038fdb8 atomic_fetch_sub_u32_s32c1i

/* Native timeval WORD view: signed64 seconds, signed32 microseconds, padding. */
typedef struct {
    unsigned int seconds_low,seconds_high;
    int microseconds;
    unsigned int padding12;
} MediusTimevalWords;
typedef void (*ShutdownHandler)(void);
void medius_settimeofday_nonnull(const struct timeval *time);
void esp_time_impl_init(void);
void esp_sync_timekeeping_timers(void);
void esp_set_time_from_rtc(void);
int esp_timer_early_init(void);
void esp_timer_impl_init_system_time(void);
int esp_timer_impl_early_init(void);
int esp_register_shutdown_handler(ShutdownHandler handler);
long long esp_timer_get_time(void);
void systimer_hal_init(SystimerHal *hal);
void systimer_hal_set_tick_rate_ops(SystimerHal *hal,const SystimerTickOps *ops);
void systimer_hal_enable_counter(SystimerHal *hal,unsigned int counter_id);
void systimer_hal_select_alarm_mode(SystimerHal *hal,unsigned int alarm_id,int mode);
void systimer_hal_connect_alarm_counter(SystimerHal *hal,unsigned int alarm_id,unsigned int counter_id);
void systimer_hal_counter_can_stall_by_cpu(SystimerHal *hal,unsigned int counter_id,unsigned int cpu_id,unsigned char can_stall);
#define TIME_RCC_SYSTEM ((volatile SystemClockRegistersPrefix *)0x600c0000U)
#define TIME_STARTUP_WORDS ((const volatile ClockWords *)0x3fcbd808U)
#define SHUTDOWN_HANDLERS ((ShutdownHandler volatile *)0x3fcbd7c8U)
#define TIME_TICK_CONVERSION_OPS ((const volatile SystimerTickOps *)0x3c046360U)
#define FUN_42007704 medius_settimeofday_nonnull
#define FUN_42007768 settimeofday
#define FUN_42007778 esp_time_impl_init
#define FUN_420077ec esp_sync_timekeeping_timers
#define FUN_42007880 esp_set_time_from_rtc
#define FUN_42007a88 esp_timer_early_init
#define FUN_42007a98 esp_timer_impl_init_system_time
#define FUN_420028c8 esp_register_shutdown_handler

/* Named opaque ROM callback table: initialization publishes its address only. */
typedef struct MediusNewlibRomSyscalls MediusNewlibRomSyscalls;
/* Local storage view, 80 bytes; the complete native abort frame is 112.
 * message ends at 49, explicit alignment bytes 50..51, fragment pointers
 * 52..67, address text 68..76, core text 77..78; tail byte 79 is unused. */
typedef struct NewlibAbortFrame {
    char message[50];
    unsigned char message_padding[2];
    const char *fragments[4];
    char address_text[9];
    char core_text[2];
} NewlibAbortFrame;
#define MEDIUS_NEWLIB_ROM_SYSCALL_POINTER (*(const MediusNewlibRomSyscalls *volatile *)0x3fceffd4U)
#define MEDIUS_NEWLIB_ROM_GLOBAL_REENT (*(NewlibReent *volatile *)0x3fceffd0U)
void esp_newlib_locks_init(void);
void panic_abort(const char *details) __attribute__((noreturn));
void esp_system_abort(const char *details) __attribute__((noreturn));
void esp_cleanup_r(NewlibReent *reent);
void raise_r_stub(NewlibReent *reent);
void esp_newlib_init(void);
int init_newlib(void);
void esp_newlib_init_global_stdio(const char *device_path);
int init_newlib_stdio(void);
int _raise_r(struct _reent *reent,int signal);
void esp_rom_newlib_init_common_mutexes(void *mutex,void *recursive_mutex);
char *itoa(int value,char *buffer,int radix);
/* These caller boundaries intentionally omit noreturn attributes, retaining
 * the explicit native ILL fallback after a panic/abort call. */
extern void medius_newlib_abort_boundary(void) __asm__("abort");
extern void newlib_system_abort_boundary(const char *message) __asm__("esp_system_abort");
#define MEDIUS_NEWLIB_SYSCALL_TABLE ((const MediusNewlibRomSyscalls *)0x3fcaa630U)
#define MEDIUS_NEWLIB_ENVIRONMENT (*(char **volatile *)0x3fcabb48U)
#define NEWLIB_ABORT_PREFIX ((const char *)0x3fcbccd4U)
#define NEWLIB_ASSERT_PREFIX_WORDS ((const volatile unsigned int *)0x3fcbd29cU)
#define NEWLIB_ABORT_CORE_SEPARATOR ((const char *)0x3fcbccf0U)
#define FUN_42007488 esp_newlib_locks_init
#define FUN_420074d0 esp_cleanup_r
#define FUN_42007504 raise_r_stub
#define FUN_42007514 esp_newlib_init
#define FUN_42007560 init_newlib
#define FUN_4200756c esp_newlib_init_global_stdio
#define FUN_420075d0 init_newlib_stdio
#define FUN_420075e0 _raise_r

void timer_alarm_handler(void *argument);
int esp_timer_impl_init(ClockAlarmHandler alarm_handler);
int esp_timer_init(void);
int esp_timer_init_os(void);
void esp_timer_task(void *argument);
void systimer_hal_enable_alarm_int(SystimerHal *hal,unsigned int alarm_id);
int esp_intr_enable(InterruptHandle *handle);
#define ESP_TIMER_TASK_SLOT ((RtosTask *volatile *)0x3fcd8690U)
#define ESP_TIMER_INTERRUPT_SLOT ((InterruptHandle *volatile *)0x3fcbde50U)
#define FUN_4037ec64 timer_alarm_handler
#define FUN_42007b9c esp_timer_impl_init
#define FUN_42011954 esp_timer_init
#define FUN_420119f8 esp_timer_init_os
void vTaskDelete(RtosTask *task);

typedef struct RestartWatchdogFrame {
    WatchdogHalContext timer1,timer0,rtc;
} RestartWatchdogFrame;
/* GPIO input selectors 0..5 at 0x60004154; only this 24-byte range is modeled. */
typedef struct RestartGpioDefaults { volatile unsigned int select[6]; } RestartGpioDefaults;
/* SYSTEM prefix through core-1 entry at offset 4; not the full register block. */
typedef struct RestartSystemPrefix { unsigned int uninterpreted00; volatile unsigned int core1_entry; } RestartSystemPrefix;
#define RESTART_GPIO_DEFAULTS ((RestartGpioDefaults *)0x60004154U)
#define RESTART_SYSTEM_REGISTERS ((RestartSystemPrefix *)0x600c0000U)
unsigned int xt_ints_off(unsigned int mask);
void wdt_hal_disable(WatchdogHalContext *context);
void wdt_hal_set_flashboot_en(WatchdogHalContext *context,bool enable);
void software_reset_cpu(unsigned int cpu);
void esp_cpu_stall(int cpu);
void esp_cpu_unstall(int cpu);
unsigned int Cache_Disable_ICache(void);
unsigned int Cache_Disable_DCache(void);
void esp_system_reset_modules_on_exit(void);
void vTaskSuspendAll(void);
void esp_restart_noos(void) __attribute__((noreturn));
void esp_restart(void) __attribute__((noreturn));
#define RESTART_WATCHDOG0_TEMPLATE ((const volatile WatchdogHalContext *)0x3c045df8U)
#define RESTART_WATCHDOG1_TEMPLATE ((const volatile WatchdogHalContext *)0x3c045e00U)
unsigned char esp_ptr_external_ram(void *pointer);
#define RESTART_INTERNAL_STACK_TOP ((const volatile unsigned int *)0x3fcd8858U)

/* Query views use the original BYTE/HALF/WORD accesses. The descriptor prefix
 * ends at bcdDevice; no complete descriptor allocation is inferred from it. */
typedef struct UsbDeviceDescriptorPrefix {
    unsigned char length,type;
    unsigned short bcd_usb;
    unsigned char device_class,subclass,protocol,ep0_max_packet;
    unsigned short vendor,product,bcd_device;
} UsbDeviceDescriptorPrefix;
typedef struct BootInterfaceHint {
    unsigned char boot_subclass,protocol;
} BootInterfaceHint;
#define QUERY_DEVICE_DESCRIPTOR ((const volatile UsbDeviceDescriptorPrefix *)0x3fcb4258U)
#define QUERY_DEVICE_LENGTH (*(const volatile unsigned short *)0x3fcd005eU)
#define QUERY_STRINGS_PRESENT (*(const volatile unsigned char *)0x3fcd0060U)
#define QUERY_BOS_PRESENT (*(const volatile unsigned int *)0x3fcaa7e4U)
#define QUERY_PRODUCT ((const char *)0x3fcd00e0U)
#define QUERY_EMPTY_PRODUCT ((const char *)0x3c040d70U)
#define QUERY_CONFIGURATION_LENGTH (*(const volatile unsigned short *)0x3fcd005cU)
#define QUERY_CONFIGURATION (*(const unsigned char *volatile *)0x3fcab510U)
#define QUERY_BOOT_INTERFACES ((const volatile BootInterfaceHint *)0x3fccc998U)
#define QUERY_MOTION_RECENT_TIME (*(volatile unsigned int *)0x3fcc7b20U)
#define QUERY_PATCH_COUNT (*(const volatile unsigned char *)0x3fcc89d6U)

unsigned char device_info_get(unsigned short *vendor_id,unsigned short *product_id,
    unsigned short *bcd_device,unsigned short *bcd_usb,unsigned char *flags);
unsigned int device_kind_get(void);
const char *device_product_get(void);
unsigned char mouse_caps_get(unsigned char *button_count,
    unsigned char *capability_flags,unsigned char *interface_count);
unsigned int keyboard_caps_get(unsigned char *key_limit,unsigned char *capability_flags);
unsigned int rate_get(unsigned short *measured_period_us,unsigned short *endpoint_period_us,
    unsigned char *confident,unsigned char *keyboard_fallback);
unsigned int health_flags_get(void);
unsigned char classify_report_interfaces(const volatile HidReportLayout *layouts,
    const volatile BootInterfaceHint *boot_interfaces,int count);
unsigned char classify_boot_interfaces(const volatile unsigned char *configuration,
    unsigned short length);
unsigned char clone_endpoint_interval_byte(unsigned int endpoint);
/* Existing callers retain this exact full-WORD endpoint boundary. */
unsigned char FUN_420282b8(unsigned int endpoint) __asm__("clone_endpoint_interval_byte");

/* Six copied prefix bytes overlap MAC byte0 at wire offset5. */
typedef union VersionQueryWire {
    unsigned char bytes[43];
    struct { unsigned char version[5],base_mac[6]; char name[32]; };
} VersionQueryWire;
typedef struct EfuseMacWords { volatile unsigned int low,high; } EfuseMacWords;
#define VERSION_QUERY_PREFIX ((const unsigned char *)0x3c0464b0U)
#define VERSION_QUERY_MAC ((const EfuseMacWords *)0x60007044U)
#define REPORT_SECONDARY_COMPLETION_SEEN ((volatile unsigned char *)0x3fcc0198U)
#define MEDIUS_REPORT_SECONDARY_BLOCKED_RW ((volatile unsigned char *)0x3fcc0150U)
#define MEDIUS_CLONE_INTERVAL_EDITED (*(const volatile unsigned char *)0x3fcc8058U)
typedef struct DescriptorPatchRecord {
    union {
        unsigned short identity;
        struct { unsigned char kind,configuration; };
    };
    unsigned char descriptor_index,reserved3;
    unsigned short offset,length,payload_offset;
} DescriptorPatchRecord;
typedef struct DescriptorPatchTable {
    DescriptorPatchRecord records[16];
    unsigned char payload[1024];
    unsigned short payload_used;
    union {
        unsigned short count_and_generation;
        struct {
            unsigned char count;
            union { unsigned char generation,reserved4a3; };
        };
    };
    union { unsigned char admission_failed,apply; };
    unsigned char reserved4a5;
} DescriptorPatchTable;
#define DESCRIPTOR_PATCH_STORED ((const volatile DescriptorPatchTable *)0x3fcc89dcU)
#define DESCRIPTOR_PATCH_SERVED ((const volatile DescriptorPatchTable *)0x3fcc8534U)
void medius_interface_clear_runtime_flags(unsigned int interface_index);
unsigned char clone_degradation_status(void);
unsigned int patches_encode(unsigned char *output);
unsigned int patch_entry_encode(unsigned char *output,unsigned char index);
void raw_endpoint_send(unsigned char endpoint,unsigned char direction,
    const unsigned char *bytes,unsigned short length);
/* Six-WORD raw-router boundary; wrapper supplies NULL update mask/UINT_MAX epoch. */
void FUN_4203118c(unsigned int endpoint,int direction,const unsigned char *bytes,
    unsigned int length,unsigned char *updated_mask,unsigned int epoch)
    __asm__("raw_endpoint_route");

typedef struct ClipPacketTriggerTable {
    ClipPacketTrigger records[8];
    unsigned char count,run_edge_count;
    unsigned short total_match_length;
} ClipPacketTriggerTable;
typedef struct ImperfectClipQueue {
    unsigned char *storage;
    unsigned int capacity,write_cursor,read_cursor;
    unsigned short pending_count,reserved18;
} ImperfectClipQueue;
#define CLIP_PACKET_TRIGGER_TABLE ((volatile ClipPacketTriggerTable *)0x3fcc7b98U)
void clip_packet_trigger_update(unsigned char traffic_class,unsigned short id,
    unsigned char direction,unsigned char action,unsigned char flags,
    unsigned char selector_length,unsigned char match_length,
    const unsigned char *match_bytes,const unsigned char *mask_bytes);
#define IMPERFECT_CLIP_QUEUE ((volatile ImperfectClipQueue *)0x3fcc7d98U)
#define IMPERFECT_CLIP_DROPPED (*(volatile unsigned short *)0x3fcc7fd2U)
#define REWRITE_ALLOWED (*(volatile unsigned char *)0x3fccbd41U)
#define IMPERFECT_REWRITE_STORAGE ((unsigned char *)0x3fcc8f88U)
#define IMPERFECT_PATCH_REFRESH (*(volatile unsigned char *)0x3fcc8530U)
#define IMPERFECT_SERVED_INTERVAL (*(const volatile unsigned char *)0x3fcc8059U)
unsigned int option_set_imperfect(unsigned char allow);
unsigned char descriptor_patches_need_refresh(void);
unsigned char FUN_42029a30(void) __asm__("descriptor_patches_need_refresh");

#define SESSION_BUTTON_MAP ((InputMapTable *)0x3fcc8e84U)
unsigned char primary_input_refresh_activity_time(unsigned long long now_us);
unsigned char FUN_4202a770(unsigned int low,unsigned int high)
    __asm__("primary_input_refresh_activity_time");
void session_reset(void);
/* Motion queue takes six native WORDs; session reset sends
 * four zero axes, flags4 and time LOW only, with no64-bit alignment argument. */
void FUN_4202b150(int x,int y,int wheel,int pan,int flags,unsigned int stamp)
    __asm__("input_queue_motion");

/* Readable view of the final pending motion slot (record38), whose base is
 * HALFWORD aligned. Only bytes0..12 are used; final C alignment padding is not
 * part of the13-byte wire record. This is the last normal slot, not extra RAM. */
typedef struct PendingMotionMergeView {
    short x,y,wheel,pan;
    unsigned char flags,stamp_le[4];
} PendingMotionMergeView;
#define PENDING_MOTION_TAIL ((volatile PendingMotionMergeView *)0x3fcc00eeU)
#define PENDING_INPUT_DROPS (*(volatile unsigned short *)0x3fcbfefeU)
#define MEDIUS_RAW_INTERFACE_LENGTH_LIMITS ((const volatile unsigned short *)0x3fccc9b8U)
#define MEDIUS_RAW_CONTROL_ENDPOINT_COUNT (*(const volatile int *)0x3fccc7fcU)
#define MEDIUS_RAW_CONTROL_ENDPOINT_LIMITS ((const volatile unsigned short *)0x3fccc800U)
#define MEDIUS_RAW_CONTROL_ENDPOINT_ADDRESSES ((const volatile unsigned char *)0x3fccc808U)
/* Device-side accounting is distinct from the host OUT relay state. */
typedef struct DeviceOutEndpoint {
    unsigned char endpoint,reserved1;
    unsigned short max_packet;
    unsigned char armed,pending,produced,acknowledged;
    unsigned char sent_sequence,rebase_sequence;
    union {
        unsigned short sequence_and_debt; /* native HALFWORD store at +10 */
        struct { unsigned char sequence_marker,completion_debt; };
    };
    unsigned char blocked;
    union {unsigned char reset_flag13,halt_requested;};
    union {unsigned char reset_flag14,completion_recovery_pending;};
    unsigned char uninterpreted15;
    unsigned int last_forward_us_low,last_forward_us_high;
} DeviceOutEndpoint;
typedef struct MediusDeviceOutPending {
    unsigned int stamp,generation;
    union {
        unsigned short endpoint_type;
        struct { unsigned char endpoint,transfer_type; };
    };
    unsigned char length,payload[64],unused75;
} MediusDeviceOutPending;
typedef struct MediusDeviceOutMessage {
    unsigned int stamp,generation;
    union {
        unsigned short endpoint_type;
        struct { unsigned char endpoint,transfer_type; };
    };
    unsigned char length,accounted;
    union {
        unsigned int route;
        unsigned char reserved12[4];
        struct { unsigned char event_kind,state_action,control_type,state_sequence; };
    };
    unsigned char payload[64];
} MediusDeviceOutMessage;
#define DEVICE_OUT_ENDPOINTS ((volatile DeviceOutEndpoint *)0x3fccc490U)
#define DEVICE_OUT_LOCK ((PortMuxWords *)0x3fcab4e8U)
#define DEVICE_OUT_OUTER_MUTEX (*(RtosQueue *volatile *)0x3fccbfc0U)
#define MEDIUS_DEVICE_OUT_PENDING_COUNT (*(volatile unsigned char *)0x3fccbfc4U)
#define MEDIUS_DEVICE_OUT_PENDING ((volatile MediusDeviceOutPending *)0x3fccbfc8U)
#define DEVICE_OUT_GENERATION (*(const volatile unsigned int *)0x3fccbfbcU)
#define DEVICE_OUT_DROPS (*(volatile unsigned int *)0x3fccc488U)
#define DEVICE_OUT_FORWARD_QUEUE (*(RtosQueue *volatile *)0x3fccc750U)
#define MEDIUS_DEVICE_OUT_READ_BUFFERS ((unsigned char *)0x3fcaeed8U)
void raw_endpoint_route(unsigned int endpoint,int direction,const unsigned char *bytes,
    unsigned int length,unsigned char *updated_mask,unsigned int epoch);
void input_queue_motion(int x,int y,int wheel,int pan,int flags,unsigned int stamp);
void medius_out_append_pending(unsigned int endpoint,unsigned int transfer_type,
    const unsigned char *payload,unsigned int length,unsigned int stamp);
void out_drain_pending(unsigned int endpoint);
void medius_out_release_accounting(unsigned int endpoint);
void medius_out_try_rearm(unsigned int endpoint);

void medius_out_filter_pending(unsigned int discard_all);
void medius_out_reconcile_endpoints(const unsigned char *endpoints,
    const unsigned short *maximum_packet_sizes,int count);
void medius_out_complete_enqueue(unsigned int endpoint,unsigned int actual,
    unsigned short transfer_type,unsigned int event_kind);
void medius_out_rebase_accounting(void);
void FUN_40394b60(void) __asm__("medius_out_rebase_accounting");

#define DEVICE_DWC2_IN_REGISTERS ((volatile Dwc2InEndpointRegisters *)0x60080900U)
void medius_vendor_device_out_complete(unsigned char bus,unsigned char endpoint,unsigned int actual);
void medius_hid_device_out_complete(unsigned char bus,unsigned char endpoint,unsigned int actual);
void medius_dwc2_wait_in_endpoints_disabled(unsigned int endpoint_mask);
void FUN_40394a40(unsigned int mask) __asm__("medius_dwc2_wait_in_endpoints_disabled");

/* Dispatcher uses five native WORD arguments. The installed chip handler can
 * consume fewer/narrower logical arguments and ignore the final context WORD. */
typedef void (*LinkApplicationFrameHandler)(int type,unsigned int flags,
    void *payload,unsigned int length,void *context);
typedef struct LinkSyncReply {
    unsigned int request_words[2],received_at_low,zero;
} LinkSyncReply;
typedef struct LinkSyncSample {
    unsigned int payload_words[3],received_at_low;
} LinkSyncSample;
void link_set_frame_handler(LinkApplicationFrameHandler callback,void *context);
/* Installed device callback consumes the low8/low8/pointer/low16 inputs and
 * ignores the fifth context WORD. This caller view uses the dispatcher's
 * five-WORD ABI and binds to the existing four-logical-argument native entry. */
void device_link_message_boundary(int type,unsigned int flags,void *payload,
    unsigned int length,void *ignored_context) __asm__("device_link_message");
void device_link_message(unsigned char opcode,unsigned char sequence,
    unsigned char *payload,unsigned short length);
#define LINK_TX_CHANNEL_ITEMS ((volatile LinkTxQueueItem *)0x3fcd7c5cU)
#define LINK_APPLICATION_HANDLER (*(LinkApplicationFrameHandler volatile *)0x3fcd84b4U)
#define LINK_APPLICATION_CONTEXT (*(void *volatile *)0x3fcd84b0U)

/* Forwarding gate, published marker generation and active OUT worker generation
 * are separate WORDs from the current session generation at 0x3fccbfbc. */
#define CONTROL_FORWARD_GATE (*(RtosQueue *volatile *)0x3fccbfb4U)
#define CONTROL_FORWARDED_GENERATION (*(volatile unsigned int *)0x3fccbfb8U)
#define MEDIUS_OUT_ACTIVE_GENERATION (*(volatile unsigned int *)0x3fcab4e4U)
#define MEDIUS_CONTROL_ENQUEUE_BUSY (*(volatile unsigned char *)0x3fcbfee7U)
/* Shared link payload storage; writes must retain the native access widths. */
typedef union MediusOutForwardWire {
    unsigned char bytes[72];
    unsigned short halfwords[36];
    unsigned int words[18];
} MediusOutForwardWire;
#define MEDIUS_OUT_FORWARD_WIRE (*(volatile MediusOutForwardWire *)0x3fcbf6a8U)
int link_low_priority_queue_empty(void);
void control_forward_generations(unsigned int target_generation,int skip_out_wait);
void reset_relay_task(void *unused_argument);
int medius_control_forward_take(void);
int control_forward_acquire_generation(unsigned int generation);
void medius_control_forward_release(void);
void outbound_forward_task(void *unused_argument);
unsigned int medius_out_enqueue_control_message(unsigned char control_type,
    const void *payload,unsigned int length,unsigned int generation,unsigned int sequence);
unsigned int FUN_40394ef8(unsigned char control_type,void *payload,unsigned int length,
    unsigned int generation,unsigned int sequence) __asm__("medius_out_enqueue_control_message");

void medius_clone_assembly_check(CloneAssembly *assembly);
void clone_assembly_reset(CloneAssembly *assembly);
unsigned char clone_section_accept(CloneAssembly *assembly,
    const unsigned char *frame,unsigned short length);
unsigned char *clone_section_get(CloneAssembly *assembly,
    unsigned char section,unsigned short *length);
unsigned int clone_release_assembly(unsigned int notify);
unsigned int usb_clone_configure(
    unsigned char *device_descriptor,unsigned short device_length,
    unsigned char *configuration,unsigned short configuration_length,
    unsigned char *section_11,unsigned short section_11_length,
    unsigned char *section_2,unsigned short section_2_length,
    char *string_3,char *string_4,char *string_5,
    unsigned char *section_7,unsigned short section_7_length,
    unsigned char *section_13,unsigned short section_13_length,
    unsigned char *section_14,unsigned short section_14_length,
    unsigned char speed,unsigned char configuration_index,
    unsigned char *section_15,unsigned short section_15_length,
    unsigned char *section_16,unsigned short section_16_length);
unsigned int esp_reset_reason(void);

/* Worker-private filter/history: exact624-byte reset span. Times are raw low32
 * microseconds; signed interpretation is chosen explicitly at each difference.
 * Unmodeled bytes retain their positions; reset coverage does not give them
 * an inferred purpose. The two publication flags overlap the native HALFWORD. */
typedef struct LinkSyncWindowSample {
    unsigned int time_us_low,round_trip_us,offset_us;
} LinkSyncWindowSample;
typedef struct LinkSyncFilterState {
    unsigned int offsets_us[16];             /* 0x000 */
    unsigned int round_trips_us[16];         /* 0x040 */
    unsigned int times_us_low[16];           /* 0x080 */
    unsigned char recent_count,recent_head; /* 0x0c0/0x0c1 */
    unsigned char unmodeled194[2];
    LinkSyncWindowSample history[32];  /* 0x0c4,12-byte stride */
    unsigned char history_count,history_head; /* 0x244/0x245 */
    unsigned char unmodeled582[2];
    unsigned int window_time_us_low;         /* 0x248 */
    unsigned int window_round_trip_us;       /* 0x24c */
    unsigned int window_offset_us;           /* 0x250 */
    unsigned int window_started_us_low;      /* 0x254 */
    unsigned char window_valid,unmodeled601[3]; /* 0x258 */
    unsigned int estimated_offset_us;        /* 0x25c */
    unsigned int reference_us_low;           /* 0x260 */
    unsigned int estimated_round_trip_us;    /* 0x264 */
    int estimated_drift_ppb;                 /* 0x268 */
    union {
        unsigned short flags;               /* published as one HALFWORD */
        struct { unsigned char ready,drift_valid; };
    };
    unsigned char unmodeled622[2];
} LinkSyncFilterState;
typedef struct LinkSyncExchange {
    unsigned int local_start_us,remote_start_us,remote_end_us,local_end_us;
} LinkSyncExchange;
void link_sync_task(void *startup_role);
/* Filter estimator is a separate body review; this is its zero-argument ABI. */
void link_sync_recompute_estimate(void);
void FUN_42021c30(void) __asm__("link_sync_recompute_estimate");
#define LINK_SYNC_FILTER ((volatile LinkSyncFilterState *)0x3fcd79dcU)
#define LINK_SYNC_PROBE_SEQUENCE (*(volatile unsigned int *)0x3fcd79c0U)
#define LINK_SYNC_PERIOD (*(volatile unsigned int *)0x3fcab550U)

/* Explicit ROM division call preserves the native load ordering around it. */
long long link_sync_signed_divide(long long dividend,long long divisor) __asm__("__divdi3");

/* Architectural exception entries use saved special registers, not C arguments. */
void _xt_debugexception(void) __asm__("FUN_4037d1e0");
void _xt_kernel_exc(void) __asm__("FUN_4037d1f8");
void _xt_highint5(void) __asm__("FUN_4037d7bc");
void _xt_nmi(void) __asm__("FUN_4037d7c4");
bool esp_flash_encryption_enabled(void);
#define FUN_4037d7cc esp_flash_encryption_enabled
void _xt_panic(void) __asm__("FUN_4037ec24");

/* Saved-frame panic handoff; the downstream dispatcher is reviewed separately. */
void panic_dispatch_frame(XtensaExceptionFrame *frame,unsigned int exception_context) __asm__("FUN_420033ac");
void panic_from_exception(XtensaExceptionFrame *frame) __asm__("FUN_40375ff4");
#define FUN_40375ff4 panic_from_exception
#define FUN_40376018 xt_unhandled_exception
void panic_clear_ipc_stall(void);
#define FUN_4037603c panic_clear_ipc_stall

/* Complete 16-byte backtrace cursor, including the optional saved-frame pointer.
 * pc/next_pc retain encoded Xtensa return addresses until local classification. */
typedef struct BacktraceFrame {
    unsigned int pc,sp,next_pc;
    XtensaExceptionFrame *exception_frame;
} BacktraceFrame;
bool esp_backtrace_get_next_frame(volatile BacktraceFrame *cursor);
bool esp_stack_ptr_in_extram(unsigned int stack_pointer);
void esp_backtrace_get_start(unsigned int *pc,unsigned int *sp,unsigned int *next_pc);
#define FUN_403760b0 esp_backtrace_get_next_frame
#define FUN_40376320 esp_backtrace_get_start

/* Reviewed panic output and copied-cursor backtrace printing. */
int esp_backtrace_print_from_frame(int depth,const BacktraceFrame *frame,unsigned char panic);
void panic_print_str(const char *text);
void panic_print_hex(unsigned int value);
#define FUN_40376120 esp_backtrace_print_from_frame
#define FUN_42020c34 panic_print_str
#define FUN_42020c3c panic_print_hex
int esp_clk_cpu_freq(void);
#define FUN_4037694c esp_clk_cpu_freq

/* Reviewed panic watchdog/re-entry helpers and diagnostic callbacks. */
#define PANIC_WDT0_TEMPLATE ((const volatile WatchdogHalContext *)0x3c045e08U)
#define PANIC_WDT1_TEMPLATE ((const volatile WatchdogHalContext *)0x3c045e10U)
#define PANIC_RTC_WDT ((WatchdogHalContext *)0x3fcaa524U)
#define PANIC_ENTRY_COUNTS ((volatile unsigned int *)0x3fcabc80U)
/* Native caller tests a full ROM result WORD. ROM body is outside this review. */
unsigned int panic_wdt_is_enabled(WatchdogHalContext *context) __asm__("wdt_hal_is_enabled");
/* Returnable alias retains the wrapper's explicit native ILL fallback. */
void panic_restart_boundary(void) __asm__("esp_restart_noos");
void panic_feed_enabled_wdts(void);
void panic_print_abort_details(const void *unused_frame);
void panic_print_dec(int value);
void esp_panic_handler_disable_timg_wdts(void);
void esp_panic_handler_enable_rtc_wdt(unsigned int timeout_ms);
void esp_panic_handler_feed_wdts(void);
void esp_panic_handler_increment_entry_count(void);
void panic_restart(void) __attribute__((noreturn));
#define FUN_42003040 panic_feed_enabled_wdts
#define FUN_42020c2c panic_print_abort_details
#define FUN_42020c44 panic_print_dec
#define FUN_420030c8 esp_panic_handler_disable_timg_wdts
#define FUN_42003114 esp_panic_handler_enable_rtc_wdt
#define FUN_4200316c esp_panic_handler_feed_wdts
#define FUN_42003188 esp_panic_handler_increment_entry_count
#define FUN_42003554 panic_restart

/* Reviewed panic diagnostics, frame tables and classification layout. */
/* Panic information layout: offsets0..24 are used by these classifiers.
 * The frame/pseudo-cause tail agrees with the pinned ESP-IDF panic_info_t and
 * its caller's36-byte initialization; these helpers leave that tail untouched. */
typedef enum PanicException {
    PANIC_EXCEPTION_DEBUG=0,
    PANIC_EXCEPTION_INTERRUPT_WATCHDOG=1,
    PANIC_EXCEPTION_TASK_WATCHDOG=2,
    PANIC_EXCEPTION_ABORT=3,
    PANIC_EXCEPTION_FAULT=4
} PanicException;
typedef void (*PanicDumpCallback)(const void *frame);
typedef struct PanicInfo {
    int core;                           /* +0 */
    PanicException exception;      /* +4 */
    const char *reason;                 /* +8 */
    const char *description;            /* +12 */
    PanicDumpCallback details;     /* +16 */
    PanicDumpCallback state;       /* +20 */
    const void *address;                /* +24 */
    const void *frame;                  /* +28 */
    unsigned char pseudo_exception;     /* +32: raw BYTE */
    unsigned char padding_33[3];
} PanicInfo;

/* Accessed ESP32-S3 EXTMEM register prefix at0x600c4000. Reserved spans
 * retain native offsets; volatile WORD fields require explicit MEMW in code. */
typedef struct PanicCacheRegisters {
    unsigned int unused_00[17];
    volatile unsigned int dcache_preload_address; /* +0x44 */
    volatile unsigned int dcache_preload_size;    /* +0x48 */
    unsigned int unused_4c[19];
    volatile unsigned int icache_preload_address; /* +0x98 */
    volatile unsigned int icache_preload_size;    /* +0x9c */
    unsigned int unused_a0[17];
    volatile unsigned int debug_status;           /* +0xe4 */
    unsigned int unused_e8[2];
    volatile unsigned int core0_access_fault;     /* +0xf0 */
    unsigned int unused_f4[2];
    volatile unsigned int core1_access_fault;     /* +0xfc */
    unsigned int unused_100[8];
    volatile unsigned int mmu_fault_content;      /* +0x120 */
    volatile unsigned int mmu_fault_address;      /* +0x124 */
} PanicCacheRegisters;
#define PANIC_CACHE_ACCESS_FAULT_MASK 0x1fU
#define PANIC_REGISTER_LABEL_COUNT 24U
#define PANIC_ARCH_REASON_COUNT 40U
#define PANIC_PSEUDO_REASON_COUNT 8U
#define PANIC_CACHE ((PanicCacheRegisters *)0x600c4000U)
int xPortInterruptedFromISRContext(void);
int esp_cache_err_get_cpuid(void);
void panic_dump_frames(const void *current_frame);
void panic_debug_details(const void *unused_frame);
void panic_illegal_instruction_details(const void *saved_frame);
void panic_cache_details(const void *unused_frame);
void panic_print_registers(const void *saved_frame,int core);
void panic_arch_fill_info(const XtensaExceptionFrame *frame,PanicInfo *info);
void panic_soc_fill_info(const XtensaExceptionFrame *frame,PanicInfo *info);
void panic_print_frame_backtrace(const void *saved_frame,int unused_core);
#define PANIC_FRAMES ((const XtensaExceptionFrame * volatile *)0x3fcbd810U)
#define PANIC_ABORT_IN_PROGRESS (*(volatile unsigned char *)0x3fcbd7fcU)
/*24 pointers: PC, PS, A0..A15, SAR, EXCCAUSE, EXCVADDR, LBEG, LEND, LCOUNT. */
#define PANIC_REGISTER_LABELS ((const char * const *)0x3c045e20U)
#define PANIC_PSEUDO_REASONS ((const char * const volatile *)0x3c045e80U)
#define PANIC_ARCH_REASONS ((const char * const volatile *)0x3c045ea0U)
#define FUN_42002f2c esp_cache_err_get_cpuid
#define FUN_420034e8 panic_dump_frames
#define FUN_420035a4 panic_debug_details
#define FUN_420035f4 panic_illegal_instruction_details
#define FUN_42003648 panic_cache_details
#define FUN_42003724 panic_print_registers
#define FUN_42003814 panic_arch_fill_info
#define FUN_4200384c panic_soc_fill_info
#define FUN_420038b4 panic_print_frame_backtrace

/* Panic-entry local storage and the no-override SoC check hook. */
#define PANIC_INVALID_PC_PLACEHOLDER 0x40374400U
typedef union PanicInfoStorage {
    PanicInfo info;
    unsigned int words[9];
} PanicInfoStorage;
unsigned int panic_soc_check_pseudo_cause(const void *unused_frame,PanicInfo *unused_info);
#define FUN_42020c4c panic_soc_check_pseudo_cause
/* Retained crash-record capture followed by reviewed system panic handling. */
void panic_record_and_handle(PanicInfo *info) __asm__("FUN_42008610");

/* System panic handler, debugger semihosting payload and breakpoint API. */
typedef struct PanicSemihostArguments {
    const char *text;
    size_t length;
} PanicSemihostArguments;
void esp_panic_handler(PanicInfo *info);
int esp_cpu_set_breakpoint(unsigned int index,const void *address);
unsigned int esp_reset_reason_get_hint(void);
#define PANIC_ABORT_DETAILS (*(const char * volatile *)0x3fcbd7f8U)
#define FUN_420031a8 esp_panic_handler
#define FUN_4202305c esp_cpu_set_breakpoint

/* ESP-IDF5.4 application description; pinned DROM object is256 bytes.
 * Field offsets and total size match esp_app_desc.h and the image metadata. */
typedef struct EspAppDescription {
    unsigned int magic_word;
    unsigned int secure_version;
    unsigned int reserved_1[2];
    char version[32];                         /* 0x10 */
    char project_name[32];                    /* 0x30 */
    char build_time[16];                      /* 0x50 */
    char build_date[16];                      /* 0x60 */
    char idf_version[32];                     /* 0x70 */
    unsigned char app_elf_sha256[32];          /* 0x90 */
    unsigned short minimum_efuse_block_revision;
    unsigned short maximum_efuse_block_revision;
    unsigned char mmu_page_size;
    unsigned char reserved_3[3];
    unsigned int reserved_2[18];
} EspAppDescription;

/* Only bytes0..9 are written in this aligned12-byte cache view. The WORD
 * alias is the lazy-initialization probe; the final two padding bytes are not
 * read, cleared or owned by the formatting functions.
 */
typedef union AppElfShaCache {
    unsigned int initialized_word;
    char text[10];
} AppElfShaCache;
#define APPLICATION_DESCRIPTION ((const EspAppDescription *)0x3c040020U)
#define APP_ELF_SHA_CACHE ((volatile AppElfShaCache *)0x3fcbd7b8U)
void app_format_elf_sha256(void);
int __esp_system_init_fn_init_show_app_info(void);
int __esp_system_init_fn_init_efuse_check(void);
int __esp_system_init_fn_init_efuse_show_app_info(void);
int esp_efuse_check_errors(void);
int esp_efuse_utility_check_errors(void);
int __esp_system_init_fn_init_show_cpu_freq(void);
int __esp_system_init_fn_init_brownout(void);
int __esp_system_init_fn_init_newlib_time(void);
int __esp_system_init_fn_init_apb_dma(void);
void esp_brownout_init(void);
#define FUN_42002418 app_format_elf_sha256
#define FUN_42002460 __esp_system_init_fn_init_show_app_info
#define FUN_42002520 __esp_system_init_fn_init_efuse_check
#define FUN_42002530 __esp_system_init_fn_init_efuse_show_app_info
#define FUN_42002634 esp_efuse_check_errors
#define FUN_42020c1c esp_efuse_utility_check_errors
#define FUN_42002920 __esp_system_init_fn_init_show_cpu_freq
#define FUN_42002968 __esp_system_init_fn_init_brownout
#define FUN_42002974 __esp_system_init_fn_init_newlib_time
#define FUN_42002980 __esp_system_init_fn_init_apb_dma


/* Reviewed retained panic records and task-watchdog text capture. */
/* Application-owned RTC crash record at0x50000000,168 bytes. All record
 * WORD/BYTE accesses in the reviewed code are volatile with explicit MEMW. */
typedef struct RetainedPanicRecord {
    unsigned int magic;                 /* +0x00: commit marker */
    unsigned int checksum;              /* +0x04: additive weighted sum */
    unsigned int image_id;              /* +0x08: first ELF-SHA WORD */
    unsigned int kind;                  /* +0x0c: panic type+1,0 unknown */
    unsigned int core;                  /* +0x10: 255 for absent info */
    unsigned int pc;                    /* +0x14 */
    unsigned int a0;                    /* +0x18 */
    unsigned int exception_address;     /* +0x1c */
    unsigned int exception_cause;       /* +0x20 */
    unsigned int return_pc[6];          /* +0x24..0x38 */
    unsigned int return_count;          /* +0x3c */
    unsigned int watchdog_pending;      /* +0x40 */
    unsigned int watchdog_validated;    /* +0x44 */
    unsigned char watchdog_text[96];    /* +0x48..0xa7 */
} RetainedPanicRecord;
typedef union PanicTextCursor {
    unsigned int packed;
    struct {
        unsigned short length;
        unsigned short ordinal;
    };
} PanicTextCursor;
#define RETAINED_PANIC_RECORD ((volatile RetainedPanicRecord *)0x50000000U)
unsigned int panic_record_checksum(void);
void panic_append_unfed_task(void *cursor_context,const char *fragment);
void panic_capture_watchdog_tasks(void);
RtosTask *xTaskGetCurrentTaskHandleForCore(int core_id);
const EspAppDescription *get_app_description(void);
#define DEVICE_VERSION_BUFFER ((char *)0x3fcd84f8U)
const char *device_version_string(void);
const char *FUN_4200c8b4(void) __asm__("device_version_string");
#define PANIC_IMAGE_ID (*(volatile unsigned int *)0x3fcbdec8U)
int boot_read_previous_panic(char *buffer,unsigned int capacity);
#define FUN_420083f0 panic_record_checksum
#define FUN_4200845c panic_append_unfed_task
#define FUN_420084f4 panic_capture_watchdog_tasks
#define FUN_42008610 panic_record_and_handle
#define FUN_420087d4 boot_read_previous_panic
#define FUN_42002518 get_app_description

/* Reviewed PSRAM size, sparse diagnostics and heap-registration helpers. */
typedef struct PsramRegion {
    unsigned int start,end,size;
} PsramRegion;
typedef struct PsramContext {
    unsigned char initialized;          /* +0: raw BYTE */
    unsigned char padding_1[3];
    PsramRegion heap_regions[2];   /* +4, +16 */
    PsramRegion mapped_regions[2]; /* +28, +40 */
} PsramContext;                    /* 52 bytes */
typedef struct PsramHeapCapabilities {
    unsigned int priority[3];
} PsramHeapCapabilities;
#define PSRAM_CONTEXT ((volatile PsramContext *)0x3fcbde90U)
#define PSRAM_PHYSICAL_SIZE (*(volatile unsigned int *)0x3fcbdec4U)
#define PSRAM_PRIMARY_CAPABILITIES ((const volatile PsramHeapCapabilities *)0x3c04648cU)
#define PSRAM_SECONDARY_CAPABILITIES ((const volatile PsramHeapCapabilities *)0x3c046498U)
#define PSRAM_LOG_LEVEL (*(volatile unsigned int *)0x3fcaa550U)
#define PSRAM_LOG_TAG ((const char *)0x3fcace1cU)
int psram_sparse_memory_test(unsigned int start_address,unsigned int byte_length);
int esp_psram_extram_add_to_heap_allocator(void);
int psram_add_heap_if_initialized(void);
size_t esp_psram_get_size(void);
int esp_psram_impl_get_physical_size(unsigned int *output);
int esp_psram_impl_get_available_size(unsigned int *output);
#define FUN_42008080 psram_sparse_memory_test
#define FUN_420082f0 esp_psram_extram_add_to_heap_allocator
#define FUN_42008370 psram_add_heap_if_initialized
#define FUN_420083a8 esp_psram_get_size
#define FUN_420083d0 esp_psram_extram_test
#define FUN_40385ce8 esp_psram_impl_get_physical_size
#define FUN_40385d08 esp_psram_impl_get_available_size
#define FUN_42003bfc esp_err_to_name

/* Reviewed quad PSRAM ROM command ABI and cache-bus view. */
typedef struct RomSpiCommand {
    unsigned short opcode,opcode_bits; /* +0, +2 */
    unsigned int *address;             /* +4 */
    unsigned int address_bits;         /* +8 */
    unsigned int *transmit_data;       /* +12 */
    unsigned int transmit_bits;        /* +16 */
    unsigned int *receive_data;        /* +20 */
    unsigned int receive_bits,dummy_bits; /* +24, +28 */
} RomSpiCommand;                 /* 32 bytes */
typedef union PsramCommandStorage {
    RomSpiCommand command;
    unsigned int words[8];
} PsramCommandStorage;
typedef struct PsramCacheBusRegistersPrefix {
    unsigned int unmodeled00;
    volatile unsigned int data_control1;        /* +0x04: DCACHE core bus gates */
    unsigned int unmodeled08[23];
    volatile unsigned int instruction_control1; /* +0x64: ICACHE core bus gates */
} PsramCacheBusRegistersPrefix;
#define PSRAM_CACHE_BUSES ((PsramCacheBusRegistersPrefix *)0x600c4000U)
#define PSRAM_CS_IOMUX (*(volatile unsigned int *)0x6000906cU)
#define PSRAM_CS_GPIO (*(volatile unsigned char *)0x3fcaa7b0U)
#define QUAD_PSRAM_LOG_TAG ((const char *)0x3fcbccfcU)
/* ROM entry contracts; ROM bodies are outside the application review count. */
void esp_rom_spi_cmd_config(int spi,RomSpiCommand *command); /* 0x4000087c */
void esp_rom_spi_cmd_start(int spi,unsigned char *rx,unsigned short rx_length,
    unsigned char cs_mask,bool write_erase); /* 0x40000888 */
void esp_rom_spiflash_select_qio_pins(unsigned char wp,unsigned int configuration); /* 0x40000a68 */
unsigned int ets_efuse_get_spiconfig(void); /* 0x40001f74 */
unsigned int ets_efuse_get_wp_pad(void);   /* 0x40001fa4 */
bool psram_has_aps3204_2t_id(void);
int esp_psram_impl_enable(void);
void mspi_timing_psram_tuning(void);
#define FUN_4200812c esp_psram_init
#define FUN_403857b4 psram_has_aps3204_2t_id
#define FUN_40385834 esp_psram_impl_enable
#define FUN_40384574 mspi_timing_psram_tuning

/* Reviewed startup heap region/type records and registration boundaries. */
typedef struct SocMemoryRegion {
    unsigned int start, size;    /* +0, +4: address bits / byte count */
    int type;                    /* +8: descriptor index, -1 means coalesced */
    unsigned int iram_address;   /* +12: alias retained unchanged on trimming */
    unsigned char startup_stack;/* +16: raw BYTE */
    unsigned char padding_17[3];
} SocMemoryRegion;         /* 20 bytes */
typedef struct SocMemoryType {
    const char *name;
    unsigned int caps[3];
} SocMemoryType;           /* 16 bytes */
typedef struct RomDramLayoutPrefix {
    unsigned int uninterpreted_00;
    unsigned int dram0_rtos_reserved_start; /* +4 */
} RomDramLayoutPrefix;           /* Only the accessed prefix is described. */
#define HEAP_ROM_LAYOUT (*(const volatile RomDramLayoutPrefix *const volatile *)0x3ff1fffcU)
#define SOC_MEMORY_REGIONS ((const SocMemoryRegion *)0x3c045fc8U)
#define SOC_MEMORY_TYPES ((const SocMemoryType *)0x3c0460a4U)
#define HEAP_REGISTRATION_HEAD (*(HeapRegion *volatile *)0x3fcbda08U)
#define HEAP_LOG_LEVEL (*(const volatile unsigned int *)0x3fcaa550U)
#define HEAP_INIT_LOG_TAG ((const char *)0x3c040de8U)
#define MEMORY_LAYOUT_LOG_TAG ((const char *)0x3c040f34U)
void qsort(void *base, size_t count, size_t width, int (*compare)(const void *, const void *));
void *multi_heap_malloc(MultiHeap *heap, size_t bytes);
size_t soc_get_available_memory_regions(SocMemoryRegion *output);
void heap_caps_init(void);
int heap_startup_init(void);
#define HEAP_REGISTRATION_LOCK ((PortMuxWords *)0x3fcaa558U)
int heap_caps_add_region_with_caps(const PsramHeapCapabilities *capabilities, int start, int end)
    __asm__("FUN_42004228");
#define FUN_42003fd0 heap_caps_init
#define FUN_4200421c heap_startup_init
#define FUN_42004228 heap_caps_add_region_with_caps
#define FUN_4200433c soc_get_available_memory_regions

/* Reviewed per-core IPC static storage and startup constructor. */
typedef struct IpcTaskName {
    union { unsigned int word; unsigned char bytes[4]; } initial;
    unsigned char terminator;
    unsigned char padding_5[3];
} IpcTaskName; /* The native task name uses only the first five bytes. */
#define IPC_INITIAL_TASK_NAME ((const volatile IpcTaskName *)0x3c040de0U)
#define IPC_MUTEX_STORAGE ((RtosQueue *)0x3fcabd30U)
#define IPC_ACKNOWLEDGEMENT_STORAGE ((RtosQueue *)0x3fcabc88U)
void esp_ipc_init(void);
#define MEDIUS_USB_EP0_TASK_RESOURCES ((MediusUsbEp0TaskResources *)0x3fcd01fcU)
void control_endpoint_reserve_task_storage(void);
void heap_caps_free(void *buffer);
#define FUN_42003988 esp_ipc_init
#define FUN_42008a44 control_endpoint_reserve_task_storage

/* Reviewed capability-filtered free-byte query. */
size_t heap_caps_get_free_size(unsigned int caps);
size_t multi_heap_free_size(const MultiHeap *heap);
void heap_caps_alloc_failed(unsigned int size,unsigned int caps,const char *function_name);
void *heap_caps_malloc_default(unsigned int size);
void *heap_caps_realloc_default(void *buffer,unsigned int size);
void *heap_caps_calloc(unsigned int count,unsigned int size,unsigned int caps);
void *heap_caps_aligned_alloc_base(unsigned int alignment,unsigned int size,unsigned int caps);
void *heap_caps_malloc_base(unsigned int size,unsigned int caps);
void *heap_caps_realloc_base(void *buffer,unsigned int size,unsigned int caps);
void *heap_caps_calloc_base(unsigned int count,unsigned int size,unsigned int caps);
void esp_heap_adjust_alignment_to_hw(unsigned int *alignment,unsigned int *size,unsigned int *caps);
void multi_heap_assert_valid_block(const MultiHeap *heap,const TlsfBlock *block);
void *multi_heap_aligned_alloc_offs(MultiHeap *heap,unsigned int size,unsigned int alignment,unsigned int offset);
void multi_heap_free(MultiHeap *heap,void *buffer);
unsigned int multi_heap_get_allocated_size(MultiHeap *heap,void *buffer);
void *multi_heap_realloc(MultiHeap *heap,void *buffer,unsigned int size);
void heap_caps_get_info(MultiHeapInfo *information,unsigned int capabilities);
unsigned int heap_caps_get_largest_free_block(unsigned int capabilities);
void multi_heap_get_info(MultiHeap *heap,MultiHeapInfo *information);
bool multi_heap_get_info_tlsf(void *unused_payload,unsigned int size,int used,void *user);
void *tlsf_get_pool(TlsfControl *control);
unsigned int tlsf_size(TlsfControl *control);
unsigned int tlsf_alloc_overhead(void);
unsigned int tlsf_block_size(const void *buffer);
void *tlsf_malloc(TlsfControl *control,unsigned int size);
void *tlsf_memalign_offs(TlsfControl *control,unsigned int alignment,unsigned int size,unsigned int offset);
void tlsf_free(TlsfControl *control,void *buffer);
void *tlsf_realloc(TlsfControl *control,void *buffer,unsigned int size);
void tlsf_walk_pool(void *pool,TlsfWalker walker,void *user);
unsigned int tlsf_fit_size(TlsfControl *control,unsigned int size);
TlsfControl *tlsf_create_with_pool(void *memory,unsigned int bytes,unsigned int maximum_bytes);
bool tlsf_default_walker(void *payload,unsigned int size,int used,void *user);
void *tlsf_add_pool(TlsfControl *control,void *memory,unsigned int bytes);
TlsfControl *tlsf_create(void *memory,unsigned int maximum_bytes);
#define FUN_42003ed0 heap_caps_get_free_size
#define FUN_42024998 multi_heap_free_size

/* Reviewed EP0 reply channel, request routing and clone descriptor selection. */
typedef struct MediusEp0RequestState {
    volatile unsigned char stall, previous_in, out_payload_suppressed, route;
} MediusEp0RequestState;
typedef struct MediusCloneDescriptorSelection {
    volatile unsigned char index, mode; /* byte addresses 0x3fcc27e9, 0x3fcc27ea */
} MediusCloneDescriptorSelection;
typedef struct MediusEp0ReplyChannel {
    volatile unsigned char nonzero_worker_busy, ep0_worker_busy, waiting, sequence;
    RtosQueue *volatile signal;
} MediusEp0ReplyChannel;
typedef struct MediusEp0ReplyStorage {
    unsigned char payload[2048];
    unsigned char reserved_800[16];
    volatile unsigned short length;       /* +0x810 */
    unsigned char reserved_812[2];
    volatile int status;                  /* +0x814: sign-extended wire BYTE */
} MediusEp0ReplyStorage;
typedef struct MediusEp0ReplyLifetime {
    volatile unsigned char quiescing, cancelled;
    unsigned char reserved_2[2];
    volatile unsigned int request_generation;
} MediusEp0ReplyLifetime;
#define MEDIUS_EP0_REQUEST_STATE ((MediusEp0RequestState *)0x3fcd01f6U)
#define MEDIUS_CLONE_DESCRIPTOR_SELECTION ((MediusCloneDescriptorSelection *)0x3fcc27e9U)
#define MEDIUS_CLONE_CONFIGURATION_LENGTHS ((const volatile unsigned short *)0x3fcd01e4U)
#define MEDIUS_CLONE_CONFIGURATION_OFFSETS ((const volatile unsigned short *)0x3fcd01ecU)
#define MEDIUS_CLONE_CONFIGURATION_POOL ((const volatile unsigned char *)0x3fcb2258U)
#define MEDIUS_EP0_REPLY_CHANNEL ((MediusEp0ReplyChannel *)0x3fcc4cccU)
#define MEDIUS_EP0_REPLY_STORAGE ((MediusEp0ReplyStorage *)0x3fcc3c48U)
#define MEDIUS_EP0_REPLY_LIFETIME ((MediusEp0ReplyLifetime *)0x3fccbfa8U)
#define MEDIUS_EP0_FRAGMENT_ASSEMBLY ((ControlAssembly *)0x3fcc2c30U)
#define MEDIUS_CLONE_REQUESTED_CONFIGURATION (*(volatile unsigned char *)0x3fcc2800U)
#define MEDIUS_CLONE_CONFIGURATION_OVERRIDE_COUNT (*(volatile unsigned char *)0x3fcc27ecU)
#define MEDIUS_CLONE_VIRTUAL_CONFIGURATION (*(volatile unsigned char *)0x3fcc27ebU)
#define MEDIUS_CLONE_CONFIGURATION_LOCK ((PortMuxWords *)0x3fcaa7e8U)
void medius_ep0_mark_handler_consumed(unsigned char bus);
void medius_ep0_mark_setup_consumed(unsigned char bus);
void medius_ep0_mark_length_override(unsigned char bus);
void medius_ep0_clear_stall_and_consume(unsigned char bus);
unsigned char medius_ep0_get_route(void);
unsigned char medius_ep0_get_out_payload_suppressed(void);
void medius_clone_set_descriptor_selection(unsigned char mode, unsigned char index);
unsigned char medius_clone_get_attached(void);
unsigned char medius_clone_configuration_has_remote_wakeup(void);
unsigned char medius_clone_configuration_value_exists(unsigned char value);
unsigned char medius_clone_endpoint_is_in_active_alternate(unsigned char endpoint);
unsigned char medius_clone_get_configuration_count(void);
const unsigned char *medius_clone_selected_configuration_descriptor(void);
void ep0_accept_short_reply(unsigned char sequence, const unsigned char *, unsigned short length);
void ep0_accept_fragmented_reply(unsigned char sequence, const unsigned char *, unsigned short length);
void medius_ep0_cancel_pending_reply(void);
void medius_report_set_endpoint_transition_pending(unsigned char pending);
void medius_clone_note_set_configuration(unsigned char configuration);
void link_wake_fast_transmit_from_isr(void);
#define FUN_40382a90 medius_ep0_mark_handler_consumed
#define FUN_40382aa8 medius_ep0_mark_setup_consumed
#define FUN_40382ac0 medius_ep0_mark_length_override
#define FUN_40391788 medius_ep0_clear_stall_and_consume
#define FUN_40391b98 medius_ep0_get_route
#define FUN_40391bac medius_ep0_get_out_payload_suppressed
#define FUN_403967c4 medius_clone_set_descriptor_selection
#define FUN_403967e4 medius_clone_get_attached
#define FUN_403967f8 medius_clone_configuration_has_remote_wakeup
#define FUN_40396824 medius_clone_configuration_value_exists
#define FUN_4039687c ep0_accept_short_reply
#define FUN_403968f4 ep0_accept_fragmented_reply
#define FUN_40396ac8 medius_report_set_endpoint_transition_pending
#define FUN_40396adc medius_clone_endpoint_is_in_active_alternate
#define FUN_40396bc8 medius_clone_get_configuration_count
#define FUN_40396be4 medius_clone_note_set_configuration
#define FUN_40396c20 medius_ep0_cancel_pending_reply
#define FUN_4037d16c link_wake_fast_transmit_from_isr
#define FUN_40393150 medius_clone_selected_configuration_descriptor

/* Reviewed standard-control-request policy prefix: 60 raw BYTE settings. */
typedef union MediusEp0RequestPolicy {
    struct {
        unsigned char zero_length_in_mode; /* +0 */
        unsigned char wrong_direction_mode; /* +1 */
        unsigned char reserved_recipient_mode; /* +2 */
        unsigned char reserved_recipient_action; /* +3 */
        unsigned char invalid_recipient_out_mode; /* +4 */
        unsigned char invalid_recipient_out_data_mode; /* +5 */
        unsigned char standard_device_recipient; /* +6 */
        unsigned char device_hid_descriptor_recipient_mode; /* +7 */
        unsigned char unknown_descriptor_mode; /* +8 */
        unsigned char configuration_index_fallback; /* +9 */
        unsigned char endpoint_get_descriptor_mode; /* +10 */
        unsigned char unknown_request_mode; /* +11 */
        unsigned char device_status_override_mode; /* +12 */
        unsigned char short_length_device; /* +13 */
        unsigned char zero_length_status_device; /* +14 */
        unsigned char long_status_device; /* +15 */
        unsigned char long_get_configuration; /* +16 */
        unsigned char zero_length_get_configuration; /* +17 */
        unsigned char get_status_interface_mode; /* +18 */
        unsigned char short_length_interface; /* +19 */
        unsigned char zero_length_status_interface; /* +20 */
        unsigned char get_interface_mode; /* +21 */
        unsigned char zero_length_get_interface; /* +22 */
        unsigned char short_length_endpoint; /* +23 */
        unsigned char zero_length_status_endpoint; /* +24 */
        unsigned char missing_interface_mode; /* +25 */
        unsigned char large_missing_interface_mode; /* +26 */
        unsigned char missing_endpoint_mode; /* +27 */
        unsigned char missing_endpoint_feature_mode; /* +28 */
        unsigned char reverse_endpoint_status_mode; /* +29 */
        unsigned char configured_synch_frame_mode; /* +30 */
        unsigned char device_interface_request_mode; /* +31 */
        unsigned char missing_alternate_mode; /* +32 */
        unsigned char missing_alternate_followup; /* +33 */
        unsigned char clear_feature_device_mode; /* +34 */
        unsigned char set_feature_device_mode; /* +35 */
        unsigned char clear_feature_interface_mode; /* +36 */
        unsigned char set_feature_interface_mode; /* +37 */
        unsigned char clear_feature_endpoint_selector_mode; /* +38 */
        unsigned char set_feature_endpoint_selector_mode; /* +39 */
        unsigned char remote_wakeup_unsupported_mode; /* +40 */
        unsigned char remote_wakeup_nonzero_index_mode; /* +41 */
        unsigned char remote_wakeup_status_mode; /* +42 */
        unsigned char out_data_suppression_mode; /* +43 */
        unsigned char unconfigured_interface_mode; /* +44 */
        unsigned char unconfigured_hid_descriptor_mode; /* +45 */
        unsigned char unconfigured_synch_frame_mode; /* +46 */
        unsigned char unconfigured_ep0_mode; /* +47 */
        unsigned char missing_configuration_mode; /* +48 */
        unsigned char missing_configuration_followup; /* +49 */
        unsigned char clear_ep0_halt_mode; /* +50 */
        unsigned char set_ep0_out_halt_mode; /* +51 */
        unsigned char set_ep0_in_halt_mode; /* +52 */
        unsigned char long_status_interface; /* +53 */
        unsigned char long_get_interface; /* +54 */
        unsigned char long_status_endpoint; /* +55 */
        unsigned char set_descriptor_gate; /* +56 */
        unsigned char set_descriptor_mode; /* +57 */
        unsigned char set_descriptor_out_data_mode; /* +58 */
        unsigned char zero_length_other_request; /* +59 */
    };
    unsigned char bytes[60]; /* Raw native offset view; no field normalization. */
} MediusEp0RequestPolicy;
#define MEDIUS_EP0_REQUEST_POLICY ((const volatile MediusEp0RequestPolicy *)0x3fccf3f8U)
unsigned int medius_ep0_policy_route_or_default(const volatile MediusEp0RequestPolicy *,
    unsigned int offset, unsigned int default_route);
unsigned int medius_ep0_policy_route_for_length(const volatile MediusEp0RequestPolicy *,
    unsigned int request, unsigned int recipient, int length, unsigned int fallback_offset);
unsigned int medius_ep0_policy_refine_unavailable_route(unsigned int route,
    const volatile MediusEp0RequestPolicy *, unsigned int request,
    unsigned int recipient, int length, unsigned int fallback_offset);
unsigned char medius_ep0_effective_recipient(unsigned int unused_bus,
    const volatile MediusUsbSetupPacket *setup);
#define FUN_4037eed0 medius_ep0_policy_route_or_default
#define FUN_4037eef4 medius_ep0_policy_route_for_length
#define FUN_4037efec medius_ep0_policy_refine_unavailable_route
#define FUN_40396108 medius_ep0_effective_recipient

/* Reviewed EP0 setup context and clone descriptor-presence boundaries. */
typedef struct MediusEp0PolicyMasks {
    unsigned short missing_interface_default_mask; /* absolute 0x3fccf436 */
    unsigned short endpoint_status_stall_mask;
    unsigned short set_interface_stall_mask;
} MediusEp0PolicyMasks;
typedef struct MediusEp0HidOverrides {
    const unsigned char *data;
    unsigned short length;
    unsigned char padding_6[2];
} MediusEp0HidOverrides;
typedef struct MediusEp0HidOverrideRecord {
    unsigned char configuration, interface, action, length;
} MediusEp0HidOverrideRecord;
typedef struct MediusEp0PolicyContext {
    const volatile MediusEp0RequestPolicy *policy; /* +0 */
    unsigned short missing_interface_default_mask;/* +4: unavailable GET_INTERFACE route7 mask */
    unsigned short endpoint_status_stall_mask;    /* +6: GET_STATUS/endpoint route1 mask */
    unsigned short set_interface_stall_mask;      /* +8: existing SET_INTERFACE route1 mask */
    unsigned char configured, configuration_count, remote_wakeup, bos_present; /* +10..13 */
    unsigned char padding_14[2]; /* Native does not initialize these bytes. */
    unsigned char (*configuration_exists)(unsigned char); /* +16 */
    bool (*alternate_exists)(unsigned char, unsigned char); /* +20 */
    bool (*interface_exists)(unsigned char);               /* +24 */
    unsigned char (*endpoint_active)(unsigned char);       /* +28 */
    bool (*report_descriptor_exists)(unsigned char);       /* +32 */
    unsigned char (*hid_descriptor_exists)(unsigned int);  /* +36 */
    unsigned char previous_in_stall;                       /* +40 */
    unsigned char padding_41[3]; /* Native does not initialize these bytes. */
} MediusEp0PolicyContext; /* 44 bytes, native WORD-aligned stack object. */
#define MEDIUS_EP0_POLICY_MASKS ((const volatile MediusEp0PolicyMasks *)0x3fccf436U)
#define MEDIUS_EP0_HID_OVERRIDES ((const volatile MediusEp0HidOverrides *)0x3fccf43cU)
unsigned short medius_ep0_get_set_interface_stall_mask(void);
const volatile MediusEp0RequestPolicy *medius_ep0_get_request_policy(void);
unsigned short medius_ep0_get_endpoint_status_stall_mask(void);
unsigned short medius_ep0_get_missing_interface_default_mask(void);
bool medius_clone_has_bos_descriptor(void);
bool medius_clone_interface_exists(unsigned char interface);
bool medius_clone_interface_alternate_exists(unsigned char interface, unsigned char alternate);
bool medius_clone_has_report_descriptor(unsigned char interface);
unsigned char medius_clone_has_hid_descriptor(unsigned int interface);
unsigned int medius_ep0_resolve_setup_policy(const volatile MediusUsbSetupPacket *,
    unsigned char *suppress_out_payload, unsigned char *configuration_index);
void medius_ep0_process_setup(unsigned int bus, volatile MediusUsbSetupPacket *);
/* Reviewed standard classifier; preserves two indirect context predicates. */
unsigned int medius_ep0_classify_standard_request(const volatile MediusUsbSetupPacket *,
    MediusEp0PolicyContext *) __asm__("FUN_4037bd98");
#define FUN_403917c0 medius_ep0_process_setup
#define FUN_403919a8 medius_ep0_resolve_setup_policy
#define FUN_40396a9c medius_ep0_get_set_interface_stall_mask
#define FUN_40396aa8 medius_ep0_get_request_policy
#define FUN_40396ab0 medius_ep0_get_endpoint_status_stall_mask
#define FUN_40396abc medius_ep0_get_missing_interface_default_mask
#define FUN_40399cfc medius_clone_has_bos_descriptor
#define FUN_40396b60 medius_clone_interface_exists
#define FUN_4037bd28 medius_clone_interface_alternate_exists
#define FUN_40399dfc medius_clone_has_report_descriptor
#define FUN_40399d0c medius_clone_has_hid_descriptor

#define FUN_4037bd98 medius_ep0_classify_standard_request


/* Alternate-setting endpoint transition and secondary-IN recovery. */
/* Native consumers trust the signed count rather than clamping to 12 slots. */
#define CREDIT_BINDING_RECORDS ((const volatile CreditBinding *)0x3fccbe20U)
extern int medius_usbd_close_endpoint(unsigned char bus,unsigned char endpoint)
    __asm__("usbd_ep_close");
void medius_clone_apply_interface_alternate_endpoints(unsigned int interface_number,
    unsigned int alternate_setting,unsigned int phase);
unsigned char medius_report_recover_secondary_in(unsigned int endpoint,void *output,
    unsigned char *length_output);
#define FUN_40391bc0 medius_clone_apply_interface_alternate_endpoints
#define FUN_40399f90 medius_report_recover_secondary_in


/* Native kind-0x16 capture wire: initial timestamp is one WORD store. */
typedef struct MediusCaptureTransferWire {
    unsigned int source_stamp;
    unsigned short subtype_and_class;
    unsigned char endpoint,reserved7,source_kind,flags,original_length,reserved11;
    unsigned char payload[64];
} MediusCaptureTransferWire;
#define REPORT_CONFIGURED_PERIOD_WRITABLE ((volatile unsigned int *)0x3fccc848U)
#define REPORT_DESCRIPTOR_RATE_HZ (*(volatile unsigned short *)0x3fcc8056U)
#define REPORT_EFFECTIVE_PERIOD_US (*(volatile unsigned int *)0x3fcc805cU)
#define REPORT_SELECTED_PERIOD_US (*(volatile unsigned int *)0x3fcc8060U)
#define REPORT_REQUESTED_RATE_HZ (*(const volatile unsigned short *)0x3fcc8064U)
#define REPORT_POLL_PERIOD_MODE (*(const volatile unsigned char *)0x3fcc8068U)
void medius_capture_record_transfer(unsigned int traffic_class,unsigned int endpoint,
    unsigned int source_kind,unsigned char flags,unsigned int source_stamp,
    unsigned int subtype,const unsigned char *payload,unsigned short length);
void out_drain_all_served_endpoints(void);
bool report_recover_interface_in(unsigned int interface,unsigned char *flags_out);
void report_refresh_poll_timing(int selected_interface);
#define FUN_403783a8 medius_capture_record_transfer
#define FUN_40392564 out_drain_all_served_endpoints
#define FUN_40395318 report_recover_interface_in
#define FUN_4202a620 report_refresh_poll_timing


/* Alternate-transition views: 256-bit selection, native eight-byte scratch,
 * and unchecked 67-byte-stride capture staging. */
typedef struct UsbInterfaceSelection { unsigned int words[8]; } UsbInterfaceSelection;
typedef union MediusAlternateEndpointScratch {
    struct {
        unsigned int first_four;
        unsigned short last_two;
        unsigned char recovered_flags,unused7;
    };
    unsigned char bytes[8];
} MediusAlternateEndpointScratch;
typedef struct MediusAlternateCaptureRecord {
    unsigned char endpoint,flags,length,payload[64];
} MediusAlternateCaptureRecord;
#define MEDIUS_CLONE_ALTERNATE_TRANSITION_BLOCK (*(volatile unsigned char *)0x3fccbe98U)
#define MEDIUS_CLONE_ALTERNATE_SNAPSHOT ((unsigned char *)0x3fcbf5a8U)
#define MEDIUS_CLONE_ALTERNATE_CAPTURE ((volatile MediusAlternateCaptureRecord *)0x3fcbf284U)
#define MEDIUS_REPORT_SECONDARY_BLOCKED_WRITABLE ((volatile unsigned char *)0x3fcc0150U)
#define REPORT_SUBMIT_BLOCKED_WRITABLE ((volatile unsigned char *)0x3fccc748U)
#define MEDIUS_REPORT_PENDING_BUCKETS ((volatile unsigned char *)0x3fcc1054U)
void usb_clone_apply_alternate_changes(const volatile UsbInterfaceSelection *selection,
    const volatile unsigned char *alternates);
void medius_clone_parse_configuration_reports(unsigned int copy_reports);
void medius_usb_register_clone_endpoints(void);
/* Reviewed native 0x4202cb20 binding-refresh implementation. */
void clone_refresh_report_bindings(unsigned int reset,int preserve_pending);
#define FUN_40391df4 usb_clone_apply_alternate_changes


/* CherryUSB interface layout, matched to usbd_core.h and the native
 * usbd_hid_init_intf constructor. Request callbacks retain their native
 * full-WORD status result; the setup packet is borrowed. */
typedef unsigned int (*UsbdRequestHandler)(unsigned char bus,
    const MediusUsbSetupPacket *setup,unsigned char **data,unsigned int *length);
typedef struct UsbdInterface {
    UsbdRequestHandler class_interface_handler;
    UsbdRequestHandler class_endpoint_handler;
    UsbdRequestHandler vendor_handler;
    void (*notify_handler)(unsigned char bus,unsigned char event,void *argument);
    const unsigned char *hid_report_descriptor;
    unsigned int hid_report_descriptor_len;
    unsigned char intf_num,padding25[3];
} UsbdInterface;
typedef struct ReportInterfaceSelection {
    int primary,other[6],other_count;
} ReportInterfaceSelection;
/* Reviewed HID default class-request dispatcher stored by initialization. */
unsigned int medius_hid_dispatch_class_request(unsigned char bus,
    const MediusUsbSetupPacket *setup,unsigned char **data,unsigned int *length);
#define medius_report_buffer_control_boundary medius_hid_dispatch_class_request
UsbdInterface *usbd_hid_init_intf(unsigned int unused,
    UsbdInterface *state,const unsigned char *report_descriptor,unsigned int descriptor_length);
void report_choose_primary_interface(const volatile HidReportLayout *layouts,
    const volatile unsigned char *preferred_interfaces,int interface_count,ReportInterfaceSelection *selection);
#define FUN_4200d110 usbd_hid_init_intf
#define FUN_42020df4 report_choose_primary_interface


/* Binding refresh owns these writable offset views; other users may borrow
 * const views of the same native fields. */
#define REPORT_PRIMARY_PREFERENCES ((const volatile unsigned char *)0x3fccc9a4U)
#define FIXED_INPUT_EVENT_STORAGE ((InputEventStorage *)0x3fcab400U)
#define INPUT_GLOBAL_MAP ((InputMapTable *)0x3fcc8e84U)
#define REPORT_PRIMARY_AXIS_SNAPSHOT ((unsigned int *)0x3fcbf1e0U)
#define INPUT_REQUESTED_IDENTITY ((const volatile unsigned short *)0x3fcc9dccU)
#define REPORT_NORMALIZATION_EPOCH (*(volatile unsigned int *)0x3fcc9dc8U)
#define HID_INTERFACES ((UsbdInterface *)0x3fccc8f0U)
#define REPORT_BUFFER_ENABLED ((const volatile unsigned char *)0x3fccc9d4U)
#define REPORT_BUFFER_STORAGE ((unsigned char *)0x3fcaf258U)
void hid_refresh_reports(void);
#define FUN_4202cb20 clone_refresh_report_bindings


void medius_hid_default_get_report(unsigned char bus,unsigned char interface,
    unsigned char report_id,unsigned char report_type,unsigned char **data,unsigned int *length);
unsigned char medius_hid_default_get_idle(unsigned char bus,unsigned char interface,unsigned char report_id);
unsigned char medius_hid_default_get_protocol(unsigned char bus,unsigned char interface);
void medius_hid_default_set_report(unsigned char bus,unsigned char interface,
    unsigned char report_id,unsigned char report_type,const unsigned char *payload,unsigned int length);
void medius_hid_default_set_idle(unsigned char bus,unsigned char interface,
    unsigned char report_id,unsigned char duration);
void medius_hid_default_set_protocol(unsigned char bus,unsigned char interface,unsigned char protocol);

#define FUN_4200d128 medius_hid_dispatch_class_request
#define FUN_42021124 medius_hid_default_get_report
#define FUN_42021134 medius_hid_default_get_idle
#define FUN_4202113c medius_hid_default_get_protocol
#define FUN_42021144 medius_hid_default_set_report
#define FUN_4202114c medius_hid_default_set_idle
#define FUN_42021154 medius_hid_default_set_protocol


/* Local EP0 alternate overrides are published as one little-endian HALFWORD. */
typedef union MediusCloneAlternateOverride {
    unsigned short pair;
    struct { unsigned char interface,alternate; };
} MediusCloneAlternateOverride;
#define MEDIUS_CLONE_ALTERNATE_OVERRIDES ((volatile MediusCloneAlternateOverride *)0x3fcc27f0U)
#define MEDIUS_EP0_DEVICE_STATUS_OVERRIDE (*(const volatile unsigned short *)0x3fccf434U)
int medius_ep0_apply_request_override(unsigned char bus,const MediusUsbSetupPacket *setup,
    unsigned char **data,unsigned int *length);
/* Reviewed relay accepts a native WORD bus; helpers use its low BYTE. */
int medius_ep0_relay_request(unsigned int bus,const MediusUsbSetupPacket *setup,
    unsigned char **data,unsigned int *length);
#define medius_ep0_relay_request_boundary medius_ep0_relay_request
#define FUN_40396168 medius_ep0_apply_request_override


/* One WORD per interface: signed HALFWORD protocol/idle, -1 means invalid.
 * Reset uses WORD stores; per-request lookups/updates use HALFWORD accesses. */
typedef union MediusEp0HidCacheEntry {
    unsigned int pair;
    struct { short protocol,idle; };
} MediusEp0HidCacheEntry;
typedef struct MediusEp0RelayStatistics {
    volatile unsigned int completed;
    unsigned char reserved_4[4];
    volatile unsigned int elapsed_low,elapsed_high;
} MediusEp0RelayStatistics;
#define MEDIUS_EP0_HID_CACHE ((volatile MediusEp0HidCacheEntry *)0x3fcc280cU)
#define MEDIUS_EP0_CACHE_GENERATION (*(volatile unsigned int *)0x3fcc2808U)
#define MEDIUS_EP0_CACHE_HITS (*(volatile unsigned int *)0x3fcc2804U)
#define MEDIUS_EP0_RELAY_STATS ((MediusEp0RelayStatistics *)0x3fcc4448U)
#define MEDIUS_EP0_CAPTURE_PREIMAGE ((unsigned char *)0x3fcbfd6cU)
#define MEDIUS_EP0_REQUEST_BUFFER ((unsigned char *)0x3fcc3440U)
int medius_ep0_forward_unhandled_request(unsigned int bus,const MediusUsbSetupPacket *,
    unsigned char **data,unsigned int *length);
void medius_capture_nonzero_control(unsigned int endpoint,unsigned char *setup,
    unsigned char direction_out,unsigned char flags,unsigned char *payload,unsigned short length);
/* Callback reads its fragment, then passes it to transport without mutation. */
#define medius_ep0_send_request_fragment_boundary medius_ep0_send_request_fragment
int memcmp(const void *left,const void *right,size_t length);
#define FUN_40393504 medius_ep0_relay_request
#define FUN_403960f0 medius_ep0_forward_unhandled_request


/* Native blob is a HALFWORD byte count, two padding bytes, then encoded records:
 * action0,length0,payload0[length0],action1,length1_le16,payload1[length1]. */
typedef struct MediusEp0DescriptorPolicyStorage {
    unsigned short length;
    unsigned char reserved2[2];
    unsigned char bytes[];
} MediusEp0DescriptorPolicyStorage;
typedef struct MediusEp0DescriptorPolicyReply {
    unsigned char action,padding1;
    unsigned short length;
    const unsigned char *payload;
} MediusEp0DescriptorPolicyReply;
#define MEDIUS_EP0_DESCRIPTOR_POLICY ((const volatile MediusEp0DescriptorPolicyStorage *)0x3fccf644U)
#define MEDIUS_NONZERO_ENDPOINT_COUNT (*(const volatile int *)0x3fccbe8cU)
#define MEDIUS_NONZERO_ENDPOINT_IDS ((const volatile unsigned char *)0x3fccbe84U)
#define NONZERO_CONTROL_QUEUE (*(RtosQueue *volatile *)0x3fcc4c80U)
#define MEDIUS_NONZERO_CONTROL_BUFFERS ((unsigned char *)0x3fcaded8U)
int medius_ep0_apply_descriptor_policy(unsigned int bus,const MediusUsbSetupPacket *,
    unsigned char **data,unsigned int *length,unsigned int use_second);
void medius_ep0_send_request_fragment(const unsigned char *fragment,unsigned short length,void *sequence);
void medius_nonzero_send_request_fragment(const unsigned char *fragment,unsigned short length,void *sequence);
void medius_nonzero_control_out_complete(unsigned char bus,unsigned char endpoint,unsigned int actual);
void medius_nonzero_control_in_complete(unsigned char bus,unsigned char endpoint,unsigned int actual);
#define FUN_40395180 medius_ep0_apply_descriptor_policy


/* Lifecycle-event wire has14 used bytes; trailing C alignment is not emitted. */
typedef struct MediusCaptureBusEvent {
    unsigned int time_low,endpoint_class;
    unsigned char zero,event;
    unsigned short original_length;
    unsigned char payload[2];
} MediusCaptureBusEvent;
#define MEDIUS_CLONE_ALTERNATE_REQUEST_STAGING ((unsigned char *)0x3fcbe7c4U)
unsigned int medius_clone_handle_set_interface(unsigned char bus,unsigned int interface,
    unsigned char alternate);
unsigned int medius_ep0_filter_device_status(unsigned int bus,unsigned short status);
void usb_clone_reset_transfer_accounting(void);
void capture_usb_bus_event(unsigned int event,unsigned int value0,unsigned int value1);
#define FUN_403954d8 medius_clone_handle_set_interface
#define FUN_40395b68 medius_ep0_filter_device_status
#define FUN_40393484 usb_clone_reset_transfer_accounting
#define FUN_403782b4 capture_usb_bus_event


/* Variable-length raw string records use BYTE language fields in native order;
 * their containing HALFWORD length is cached by the descriptor lookup. */
typedef struct MediusStringOverrideRecord {
    unsigned char index,language_low,language_high,action,length;
    unsigned char payload[];
} MediusStringOverrideRecord;
typedef struct MediusStringOverrideTable {
    unsigned short length;
    unsigned char reserved2[2];
    unsigned char records[];
} MediusStringOverrideTable;
#define MEDIUS_STRING_OVERRIDE_TABLE ((const volatile MediusStringOverrideTable *)0x3fccfa58U)
#define MEDIUS_CLONE_ENGLISH_LANGUAGE_DESCRIPTOR ((const unsigned char *)0x3c04815cU)
#define MEDIUS_EP0_UNCONFIGURED_DESCRIPTOR_REFUSED (*(volatile unsigned char *)0x3fcc27e8U)
int medius_ep0_get_special_descriptor(unsigned char bus,const MediusUsbSetupPacket *,
    unsigned char **data,unsigned int *length);
#define FUN_40395694 medius_ep0_get_special_descriptor


/* Request-dispatch views of the registered class and descriptor callback tables.
 * These describe native32-bit offsets; registration counts remain unchecked. */
typedef int (*MediusUsbdRequestCallback)(unsigned int bus,MediusUsbSetupPacket *,
    unsigned char **data,unsigned int *length);
typedef struct MediusUsbdRequestInterface {
    MediusUsbdRequestCallback interface_request,endpoint_request,vendor_request;
    MediusUsbdClassEventHandler notify;
    const unsigned char *report_descriptor;
    unsigned int report_length;
    unsigned char interface_number,reserved19[3];
} MediusUsbdRequestInterface;
typedef const unsigned char *(*MediusUsbDescriptorCallback)(unsigned int speed);
typedef const char *(*MediusUsbStringDescriptorCallback)(unsigned int speed,unsigned int index);
typedef struct MediusUsbDescriptorSpan {
    const unsigned char *data;
    unsigned int length;
} MediusUsbDescriptorSpan;
typedef struct MediusUsbdOs10Descriptors {
    const unsigned char *string_descriptor;
    unsigned char vendor_code,reserved5[3];
    const unsigned char *compatible_id;
    const unsigned char *const *properties;
} MediusUsbdOs10Descriptors;
typedef struct MediusUsbdOs20Descriptors {
    const unsigned char *data;
    unsigned short length;
    unsigned char vendor_code,reserved7;
} MediusUsbdOs20Descriptors;
typedef struct MediusUsbdWebUsbDescriptor {
    unsigned char vendor_code,address_le[4],length_le[4];
} MediusUsbdWebUsbDescriptor;
typedef struct MediusUsbdDescriptorTable {
    MediusUsbDescriptorCallback device,configuration;
    void *unread_qualifier_callback;
    MediusUsbDescriptorCallback other_speed;
    MediusUsbStringDescriptorCallback string;
    const MediusUsbdOs10Descriptors *os10;
    const MediusUsbdOs20Descriptors *os20;
    const MediusUsbdWebUsbDescriptor *webusb;
    const MediusUsbDescriptorSpan *bos;
} MediusUsbdDescriptorTable;
unsigned int usbd_setup_request_handler(unsigned int bus,MediusUsbSetupPacket *,
    unsigned char **data,unsigned int *length);
void medius_usbd_class_event_notify(unsigned int bus,unsigned int event,unsigned char *descriptor);
void medius_usb_in_endpoint_activity_update(unsigned int ignored_bus,unsigned int endpoint);
void medius_usbd_reset_event(unsigned char bus);
unsigned int medius_usb_low_speed_requested(void);
int usbd_ep_open(unsigned char bus,const MediusUsbEndpointDescriptor *descriptor);
int usbd_ep_is_stalled(unsigned char bus,unsigned char endpoint,unsigned char *stalled);
int usbd_ep_clear_stall(unsigned char bus,unsigned char endpoint);
size_t strlen(const char *text);
/* Reviewed endpoint-halt acknowledgement and local transition handlers. */
int medius_clone_prepare_endpoint_halt(unsigned char bus,unsigned int endpoint,unsigned char halted);
void medius_clone_endpoint_halt_changed(unsigned int bus,unsigned int endpoint,unsigned char halted);
#define medius_clone_prepare_endpoint_halt_boundary medius_clone_prepare_endpoint_halt
#define medius_clone_endpoint_halt_changed_boundary medius_clone_endpoint_halt_changed


typedef struct EndpointHaltReply {
    volatile unsigned char result,sequence,waiting;
} EndpointHaltReply;
#define ENDPOINT_HALT_REPLY ((EndpointHaltReply *)0x3fcc011cU)
#define MEDIUS_REPORT_ENDPOINT_TRANSITION_PENDING (*(volatile unsigned char *)0x3fccbe96U)
#define REPORT_INTERFACE_QUEUES_WRITABLE ((volatile CreditInterfaceQueue *)0x3fcc1150U)
/* This native path reads the fixed bus0 DIEPCTL address, not the binding table. */
#define DWC2_IN_CONTROL(endpoint) (*(const volatile unsigned int *)(0x60080900U + (endpoint) * 32U))
void medius_dwc2_in_fifo_cancel(unsigned char bus,unsigned char endpoint);
#define FUN_420338ac medius_clone_prepare_endpoint_halt
#define FUN_40395b94 medius_clone_endpoint_halt_changed

/* Nonzero-control reply publication. Separate from the per-endpoint records. */
typedef struct MediusNonzeroControlReply {
    volatile unsigned char completed_sequence,reserved1;
    volatile unsigned short actual;
    volatile unsigned char status,expected_generation,expected_sequence,reserved7;
    RtosQueue *volatile signal;
    RtosQueue *volatile queue;
} MediusNonzeroControlReply;
/* External TRANSFER command storage, distinct from the USB worker's buffers. */
typedef struct MediusExternalControlRequest {
    unsigned char endpoint,setup[8],out_payload[504];
} MediusExternalControlRequest;
typedef struct ExternalControlReply {
    unsigned char payload[504];
    volatile unsigned short actual;
    unsigned char unmodeled506[2];
    volatile unsigned int status;
    volatile unsigned char completed_sequence,sequence,waiting,unmodeled515;
    RtosQueue *volatile signal;
} ExternalControlReply;
#define MEDIUS_NONZERO_REPLY ((MediusNonzeroControlReply *)0x3fcc4c74U)
#define MEDIUS_NONZERO_ACTIVE_SLOT (*(volatile unsigned char *)0x3fcaa7f0U)
#define MEDIUS_NONZERO_RESPONSE_ASSEMBLY ((ControlAssembly *)0x3fcc4464U)
/* This particular assembly has WORD-aligned used/active/error storage. */
#define MEDIUS_NONZERO_ASSEMBLY_PROGRESS (*(volatile unsigned int *)0x3fcc4c70U)
#define MEDIUS_EXTERNAL_CONTROL_REQUEST ((MediusExternalControlRequest *)0x3fcc2824U)
#define EXTERNAL_CONTROL_REPLY ((ExternalControlReply *)0x3fcc2a28U)
void nonzero_control_response(unsigned char sequence,unsigned char *payload,unsigned short length);
void nonzero_control_response_fragment(unsigned char sequence,unsigned char *fragment,unsigned short length);
void medius_nonzero_control_setup(unsigned char bus,unsigned char endpoint,const unsigned char *setup);
unsigned int control_transfer_request(unsigned char endpoint,const unsigned char *setup,
    const void *out_data,unsigned int out_length,void *response,unsigned int response_capacity,
    unsigned short *response_length);

/* Serialized ctrln wire and its original OUT-data capture snapshot. */
typedef struct MediusNonzeroControlRequest {
    unsigned char endpoint,setup[8],out_payload[2048];
} MediusNonzeroControlRequest;
#define MEDIUS_NONZERO_REQUEST ((MediusNonzeroControlRequest *)0x3fcbe970U)
#define MEDIUS_NONZERO_CAPTURE_PREIMAGE ((unsigned char *)0x3fcbe8c4U)
#define MEDIUS_NONZERO_NEXT_SEQUENCE (*(volatile unsigned char *)0x3fcc4460U)
void nonzero_control_task(void);

/* Reviewed shared control-capture builder and its stack workspace. */
typedef struct MediusControlCaptureWorkspace {
    unsigned char output[192],scratch[224];
} MediusControlCaptureWorkspace;
void medius_capture_control_build(unsigned int traffic_class,
    unsigned int endpoint,unsigned char *setup,unsigned char direction_out,
    unsigned char flags,unsigned char *payload,unsigned short length,
    unsigned char *scratch,unsigned char *output);
#define medius_capture_control_builder_boundary medius_capture_control_build
#define FUN_40392ad4 medius_capture_control_build
unsigned char *medius_report_archive_reserve(unsigned int configuration,
    unsigned int interface_id,unsigned int payload_length,unsigned int protected_configuration);

/* Packed control-capture header: every native field is written as BYTEs. */
typedef struct MediusControlCaptureWire {
    unsigned char time_le[4],version,traffic_class,endpoint,reserved7;
    unsigned char source_kind,flags,original_length_le[2],payload[180];
} MediusControlCaptureWire;
typedef struct PlaybackControlRequest {
    unsigned char setup[8],endpoint,reserved9[3];
    TimestampWords started;
    unsigned char waiting,reserved21[3];
} PlaybackControlRequest;
#define PLAYBACK_CONTROL_REQUEST ((volatile PlaybackControlRequest *)0x3fcc7d7cU)
#define PLAYBACK_CONTROL_SUCCESSES (*(volatile unsigned short *)0x3fcc7fceU)
#define PLAYBACK_CONTROL_ERRORS (*(volatile unsigned short *)0x3fcc7fd0U)
#define PLAYBACK_CONTROL_CAPTURE_SCRATCH ((unsigned char *)0x3fcc7dc8U)
#define MEDIUS_PLAYBACK_CONTROL_CAPTURE_OUTPUT ((unsigned char *)0x3fcc7e84U)
void playback_control_complete(int status,unsigned char *payload,unsigned int length);
void playback_control_try_start(void);
#define FUN_4202ac84 playback_control_try_start
#define FUN_4202c080 playback_control_complete

#define PLAYBACK_CONTROL_STAGING (*(unsigned char *volatile *)0x3fcc7d94U)
#define PLAYBACK_CONTROL_SEQUENCE (*(volatile unsigned char *)0x3fcaa834U)
unsigned int link_enqueue_nowait_silent(unsigned char opcode,unsigned char metadata,
    void *payload,unsigned short length);
#define FUN_420229e8 link_enqueue_nowait_silent

/* Descriptor-patch command publication and persistence views. */
#define MEDIUS_DESCRIPTOR_PATCH_STORED_RW ((volatile DescriptorPatchTable *)0x3fcc89dcU)
#define MEDIUS_DESCRIPTOR_PATCH_CACHE_LOADED (*(volatile unsigned char *)0x3fcc89daU)
#define MEDIUS_DESCRIPTOR_PATCH_PERSISTENCE_MARKER (*(volatile unsigned char *)0x3fcc89dbU)
#define MEDIUS_DESCRIPTOR_PATCH_SAVE_BUFFER ((unsigned char *)0x3fcbded0U)
unsigned int medius_descriptor_patch_mutate(unsigned int kind,unsigned int configuration,
    unsigned int index,unsigned int offset,const void *bytes,unsigned short length);
void medius_descriptor_patch_compact_payloads(void);
#define medius_descriptor_patch_mutate_boundary medius_descriptor_patch_mutate
#define FUN_42029c14 medius_descriptor_patch_mutate
#define FUN_42029ad8 medius_descriptor_patch_compact_payloads
void descriptor_patch_store(unsigned char kind,unsigned char configuration,
    unsigned char index,unsigned short offset,const void *bytes,unsigned short length);
void descriptor_patch_apply(void);
void descriptor_patch_clear(void);
typedef struct MediusCloneAuxEndpoint {
    union {
        unsigned short address_and_type;
        struct { unsigned char address,transfer_type; };
    };
    unsigned short max_packet,cleared4;
    union {
        unsigned char retained6[2];
        struct { unsigned char channel,reserved7; };
    };
} MediusCloneAuxEndpoint;
typedef struct MediusCloneAuxEndpointState {
    MediusCloneAuxEndpoint endpoints[12];
    int endpoint_count;
    unsigned char control_endpoint[2];
    unsigned short control_max_packet[2];
    unsigned char reserved106[2];
    int control_count;
    union {
        struct { unsigned char has_bulk,has_isochronous; };
        unsigned short transfer_flags;
    };
    unsigned char conflict,reserved115;
} MediusCloneAuxEndpointState;
void medius_clone_collect_aux_endpoint(MediusCloneAuxEndpointState *state,
    unsigned int endpoint_address,unsigned int attributes,unsigned int maximum_packet_size);

typedef struct MediusCloneReportUpload {
    unsigned char interface_number,configuration;
    unsigned short total,next_offset;
    unsigned char reserved6[2];
    unsigned char *payload;
} MediusCloneReportUpload;
#define MEDIUS_CLONE_REPORT_UPLOAD ((volatile MediusCloneReportUpload *)0x3fccc9ecU)
void clone_accept_report_fragment(const unsigned char *packet,unsigned int length);
#define FUN_4203456c clone_accept_report_fragment

/* Writable descriptor-build publication views; borrowed tables remain shared. */
#define MEDIUS_CLONE_DEVICE_BYTES ((unsigned char *)0x3fcb4258U)
#define MEDIUS_CLONE_DEVICE_LENGTH (*(volatile unsigned short *)0x3fcd005eU)
#define MEDIUS_CLONE_CONFIGURATION_BYTES ((unsigned char *)0x3fcb2258U)
#define MEDIUS_CLONE_CONFIGURATION_TOTAL (*(volatile unsigned short *)0x3fcd01f4U)
#define MEDIUS_CLONE_CONFIGURATION_OFFSETS_RW ((volatile unsigned short *)0x3fcd01ecU)
#define MEDIUS_CLONE_CONFIGURATION_LENGTHS_RW ((volatile unsigned short *)0x3fcd01e4U)
#define MEDIUS_CLONE_SELECTED_CONFIGURATION (*(unsigned char *volatile *)0x3fcab510U)
#define MEDIUS_CLONE_SELECTED_LENGTH (*(volatile unsigned short *)0x3fcd005cU)
#define MEDIUS_CLONE_BOS_BYTES ((unsigned char *)0x3fcad5d8U)
#define MEDIUS_CLONE_DECLARED_CONFIGURATIONS (*(volatile unsigned char *)0x3fcab4e0U)
#define MEDIUS_CLONE_INTERVAL_EDITED_RW (*(volatile unsigned char *)0x3fcc8058U)
#define MEDIUS_CLONE_SERVED_AUXILIARY ((volatile MediusCloneAuxEndpointState *)0x3fccbe20U)
#define MEDIUS_CLONE_OVER_CAPACITY (*(volatile unsigned char *)0x3fccbd42U)
#define MEDIUS_CLONE_DEGRADED (*(volatile unsigned char *)0x3fccbd40U)
#define MEDIUS_CLONE_ERROR_BUFFER ((char *)0x3fcbfe18U)
#define MEDIUS_CLONE_PRIMARY_REPORT_WIRE_LENGTH(index) \
    (((const volatile HidReportLayout *)HID_REPORT_LAYOUTS)[index].expected_length)
char *medius_clone_build_descriptors(MediusCloneSource *source,unsigned int interval_selector,
    int *interval_result,unsigned int patch_mode,unsigned char *imperfect,unsigned char *problem_bits);

/* Lifecycle callback publication views. Counter updates are wrapping WORD
 * load/store pairs, not atomic increments. The phase-valid BYTE gates the
 * completion-time correction; clearing it retains the phase reference bytes. */
#define MEDIUS_USB_DEVICE_IN_INTERRUPT_MASK (*(volatile unsigned int *)0x60080810U)
#define DEVICE_OUT_GENERATION_RW (*(volatile unsigned int *)0x3fccbfbcU)
#define MEDIUS_USB_RESET_COUNT (*(volatile unsigned int *)0x3fcbfef0U)
#define MEDIUS_USB_CONFIGURATION_EVENT_COUNT (*(volatile unsigned int *)0x3fcbfeecU)
#define CLIP_RULES_RESET_PENDING (*(volatile unsigned char *)0x3fcc7b96U)
#define MEDIUS_REPORT_COMPLETION_PHASE_VALID (*(volatile unsigned char *)0x3fcc1148U)
#define RESET_RELAY_TASK (*(RtosTask *volatile *)0x3fccbfb0U)
#define MEDIUS_REPORT_FAST_BLOCK97_RW (*(volatile unsigned char *)0x3fccbe97U)
#define USB_PUBLISHED_CONFIGURATION_INDEX (*(volatile unsigned char *)0x3fcbfee6U)
#define USB_PUBLISHED_CONFIGURATION_GENERATION (*(volatile unsigned int *)0x3fcaa7b4U)
void medius_usb_device_event(unsigned int bus,unsigned int event);
void medius_clone_transition_configuration_endpoints(const unsigned char *configuration,
    int length,unsigned int default_alternates_only,unsigned int open);
#define FUN_42028cbc medius_clone_transition_configuration_endpoints

/* Inline HID Input-length estimator storage: native64-byte counter block
 * followed by16 report-ID bytes, zeroed with four WORD stores. */
typedef struct MediusHidInputEstimateScratch {
    unsigned int bits[16];
    union { unsigned char ids[16]; unsigned int id_words[4]; };
} MediusHidInputEstimateScratch;
#define MEDIUS_HID_REPORT_DESCRIPTOR_BYTES ((const volatile unsigned char *)0x3fcaf258U)
#define MEDIUS_HID_REPORT_DESCRIPTOR_LENGTHS ((const volatile unsigned short *)0x3fccc9dcU)
#define MEDIUS_REPORT_COMPARISON_LIMITS_WRITABLE ((volatile unsigned short *)0x3fccc9acU)
/* Both names resolve to the reviewed decoder; retain the boundary spelling
 * used by report refresh without inserting a wrapper function. */
extern unsigned int medius_hid_decode_report_metadata_boundary(const unsigned char *descriptor,
    unsigned short length,HidReportLayout *layout) __asm__("medius_hid_decode_report_metadata");
unsigned int medius_hid_decode_report_metadata(const unsigned char *descriptor,
    unsigned short length,HidReportLayout *layout);

/* Decoder's independently keyed unsupported-part table; native clear is82
 * bytes. The report-offset cache is separate and has its own sixteen-ID cap. */
typedef struct MediusHidUnsupportedParts {
    unsigned char report_ids[16];
    unsigned short bits[16],first_offset[16];
    unsigned char count,overflow;
} MediusHidUnsupportedParts;

/* Configuration-parser working/published views. Record payload tails and unused
 * slots survive a parse; counts and the separately latched flags govern use. */
#define MEDIUS_CLONE_ACTIVE_AUXILIARY ((volatile MediusCloneAuxEndpointState *)0x3fcbf210U)
#define MEDIUS_CLONE_ALL_ALTERNATE_AUXILIARY ((volatile MediusCloneAuxEndpointState *)0x3fccbdacU)
#define MEDIUS_CLONE_NEW_CHANNELS (*(volatile unsigned char *)0x3fcc0136U)
#define MEDIUS_CLONE_HID_INTERFACE_IDS ((volatile unsigned char *)0x3fccc9ccU)
#define MEDIUS_CLONE_HID_REPORT_LENGTHS ((volatile unsigned short *)0x3fccc9dcU)
#define MEDIUS_CLONE_HID_REPORT_EMPTY ((volatile unsigned char *)0x3fccc9d4U)
#define MEDIUS_CLONE_HID_BOOT_INTERFACES ((volatile BootInterfaceHint *)0x3fccc998U)
#define MEDIUS_CLONE_HID_MOUSE_PROTOCOL ((volatile unsigned char *)0x3fccc9a4U)
#define MEDIUS_CLONE_PRIMARY_ADDRESSES ((unsigned char *)0x3fccc9c4U)
#define MEDIUS_CLONE_PRIMARY_PACKETS ((unsigned short *)0x3fccc9b8U)
#define MEDIUS_CLONE_INTERFACE_COUNT (*(volatile int *)0x3fccc9e8U)
#define MEDIUS_CLONE_HID_OUT_PACKETS ((unsigned short *)0x3fccc800U)
#define MEDIUS_CLONE_HID_OUT_ADDRESSES ((unsigned char *)0x3fccc808U)
#define MEDIUS_CLONE_HID_OUT_COUNT (*(volatile int *)0x3fccc7fcU)

/* ESP-IDF early peripheral startup uses only this SYSTEM register prefix. */
typedef struct SystemPeripheralRegistersPrefix {
    unsigned int unmodeled00[6];
    volatile unsigned int clock_enable0;    /* +0x18 */
    volatile unsigned int clock_enable1;    /* +0x1c */
    volatile unsigned int reset_enable0;    /* +0x20 */
    volatile unsigned int reset_enable1;    /* +0x24 */
    volatile unsigned int bluetooth_clock_integer;  /* +0x28 */
    volatile unsigned int bluetooth_clock_fractional; /* +0x2c */
} SystemPeripheralRegistersPrefix;
#define SYSTEM_PERIPHERAL_REGISTERS ((SystemPeripheralRegistersPrefix *)0x600c0000U)
#define PERIPHERAL_WIFI_CLOCK MMIO32(0x60026014U)
#define RTC_DEFAULT_CONFIGURATION (*(const volatile unsigned int *)0x3c045df4U)
void select_rtc_slow_clk(unsigned int requested_source);
/* Dependency's own implementation is reviewed separately. */
void periph_module_enable(unsigned int module);
/* Write the low 32-bit CCOUNT value on this CPU. Compiler memory clobber only; no ISYNC. */
static __inline__ __attribute__((always_inline)) void
esp_cpu_set_cycle_count(unsigned int cycles)
{
    __asm__ volatile ("wsr.ccount %0" : : "a"(cycles) : "memory");
}
#define FUN_42002a38 select_rtc_slow_clk

/* ESP-IDF v5.4.4 ESP32-S3 peripheral IDs; not every ID has a hardware mask. */
enum PeripheralModule {
    PERIPH_LEDC_MODULE = 0,
    PERIPH_UART0_MODULE = 1,
    PERIPH_UART1_MODULE = 2,
    PERIPH_UART2_MODULE = 3,
    PERIPH_USB_MODULE = 4,
    PERIPH_I2C0_MODULE = 5,
    PERIPH_I2C1_MODULE = 6,
    PERIPH_I2S0_MODULE = 7,
    PERIPH_I2S1_MODULE = 8,
    PERIPH_LCD_CAM_MODULE = 9,
    PERIPH_TIMG0_MODULE = 10,
    PERIPH_TIMG1_MODULE = 11,
    PERIPH_PWM0_MODULE = 12,
    PERIPH_PWM1_MODULE = 13,
    PERIPH_PWM2_MODULE = 14,
    PERIPH_PWM3_MODULE = 15,
    PERIPH_UHCI0_MODULE = 16,
    PERIPH_UHCI1_MODULE = 17,
    PERIPH_RMT_MODULE = 18,
    PERIPH_PCNT_MODULE = 19,
    PERIPH_SPI_MODULE = 20,
    PERIPH_SPI2_MODULE = 21,
    PERIPH_SPI3_MODULE = 22,
    PERIPH_SDMMC_MODULE = 23,
    PERIPH_TWAI_MODULE = 24,
    PERIPH_RNG_MODULE = 25,
    PERIPH_WIFI_MODULE = 26,
    PERIPH_BT_MODULE = 27,
    PERIPH_WIFI_BT_COMMON_MODULE = 28,
    PERIPH_BT_BASEBAND_MODULE = 29,
    PERIPH_BT_LC_MODULE = 30,
    PERIPH_AES_MODULE = 31,
    PERIPH_SHA_MODULE = 32,
    PERIPH_HMAC_MODULE = 33,
    PERIPH_DS_MODULE = 34,
    PERIPH_RSA_MODULE = 35,
    PERIPH_SYSTIMER_MODULE = 36,
    PERIPH_GDMA_MODULE = 37,
    PERIPH_DEDIC_GPIO_MODULE = 38,
    PERIPH_SARADC_MODULE = 39,
    PERIPH_TEMPSENSOR_MODULE = 40,
    PERIPH_PHY_CALIBRATION_MODULE = 41,
    PERIPH_MODULE_MAX = 42
};
typedef unsigned char PeripheralReferenceCounts[PERIPH_MODULE_MAX];
typedef struct PeripheralRegisterPair {
    volatile unsigned int *clock;
    volatile unsigned int *reset;
} PeripheralRegisterPair;
#define PERIPHERAL_REFERENCES (*(volatile PeripheralReferenceCounts *)0x3fcbda24U)
unsigned int periph_ll_get_clk_en_mask(unsigned int module);
/* Raw native enable WORD: zero versus any nonzero value. */
unsigned int periph_ll_get_rst_en_mask(unsigned int module,unsigned int enable);
#define FUN_42004d88 periph_ll_get_clk_en_mask
#define FUN_42004f1c periph_ll_get_rst_en_mask
#define FUN_42005128 periph_module_enable

/* Native GPIO49-pin set: bits0..21 and26..48. */
#define GPIO_SLEEP_VALID_MASK 0x1fffffc3fffffULL
enum GpioSleepPullMode {
    GPIO_SLEEP_PULLUP_ONLY = 0,
    GPIO_SLEEP_PULLDOWN_ONLY = 1,
    GPIO_SLEEP_PULL_BOTH = 2,
    GPIO_SLEEP_FLOATING = 3
};
enum MspiPinRole {
    ESP_MSPI_IO_CLK = 0, ESP_MSPI_IO_Q = 1, ESP_MSPI_IO_D = 2,
    ESP_MSPI_IO_CS0 = 3, ESP_MSPI_IO_HD = 4, ESP_MSPI_IO_WP = 5,
    ESP_MSPI_IO_DQS = 6, ESP_MSPI_IO_D4 = 7, ESP_MSPI_IO_D5 = 8,
    ESP_MSPI_IO_D6 = 9, ESP_MSPI_IO_D7 = 10, ESP_MSPI_IO_CS1 = 11,
    ESP_MSPI_IO_MAX = 12
};
/* Complete 56-byte ESP32-S3 rtc_io_desc_t layout, indexed by RTC channel.
 * These are register addresses, masks and shifts; only force_hold_mask is
 * read by wake cleanup. gpio_number is the SDK's signed int field. */
typedef struct RtcPadDescriptor {
    unsigned int register_address;
    unsigned int mux_mask;
    unsigned int function_shift;
    unsigned int input_enable_mask;
    unsigned int pullup_mask;
    unsigned int pulldown_mask;
    unsigned int sleep_select_mask;
    unsigned int sleep_input_enable_mask;
    unsigned int sleep_output_enable_mask;
    unsigned int hold_mask;
    unsigned int force_hold_mask; /* +0x28 */
    unsigned int drive_value_mask;
    unsigned int drive_shift;
    int gpio_number;
} RtcPadDescriptor;
typedef struct RtcSleepWakeRegisters {
    volatile unsigned int pad_hold;        /* RTC_CNTL+0xd8 */
    unsigned int uninterpreted_dc;
    volatile unsigned int ext1_selection;  /* RTC_CNTL+0xe0, pins0..21 */
} RtcSleepWakeRegisters;
#define RTC_SLEEP_WAKE_REGISTERS ((RtcSleepWakeRegisters *)0x600080d8U)
#define RTC_GPIO_CHANNEL_MAP ((const volatile signed char *)0x3c0470f8U)
#define RTC_PAD_DESCRIPTORS ((const volatile RtcPadDescriptor *)0x3c046c28U)
void esp_sleep_config_gpio_isolate(void);
/* Native entry consumes the low BYTE; values beyond0/1 are not normalized. */
void esp_sleep_enable_gpio_switch(unsigned char enable);
int __esp_system_init_fn_esp_sleep_startup_init(void);
int gpio_sleep_set_pull_mode(unsigned int pin,unsigned int mode);
#define FUN_42005344 esp_sleep_config_gpio_isolate
#define FUN_4200541c esp_sleep_enable_gpio_switch
#define FUN_420054b8 __esp_system_init_fn_esp_sleep_startup_init
#define FUN_420054cc esp_deep_sleep_wakeup_io_reset
#define FUN_4200e110 gpio_sleep_set_pull_mode

enum ShaMode {
    SHA_MODE_SHA1 = 0, SHA_MODE_SHA224 = 1, SHA_MODE_SHA256 = 2,
    SHA_MODE_SHA384 = 3, SHA_MODE_SHA512 = 4, SHA_MODE_SHA512_224 = 5,
    SHA_MODE_SHA512_256 = 6, SHA_MODE_SHA512_T = 7
};
/* Only fields used by these native HAL entries are named. */
typedef struct ShaRegistersPrefix {
    volatile unsigned int mode;           /* +0x00 */
    unsigned int unmodeled04[2];
    volatile unsigned int block_count;    /* +0x0c */
    volatile unsigned int start;          /* +0x10 */
    volatile unsigned int continue_block; /* +0x14 */
    volatile unsigned int busy;           /* +0x18 */
    volatile unsigned int dma_start;      /* +0x1c */
    volatile unsigned int dma_continue;   /* +0x20 */
    unsigned int unmodeled24[7];
    volatile unsigned int digest[16];     /* +0x40 */
    volatile unsigned int text[32];       /* +0x80 */
} ShaRegistersPrefix;
#define SHA_REGISTERS ((ShaRegistersPrefix *)0x6003b000U)
#define SHA256_PADDING ((const unsigned char *)0x3c047374U)
#define CRYPTO_SHA_AES_LOCK ((NewlibLock *)0x3fcd868cU)
void esp_sha_write_digest_state(unsigned int mode,const void *state);
void esp_sha_read_digest_state(unsigned int mode,void *state);
void esp_sha_acquire_hardware(void);
void esp_sha_release_hardware(void);
void sha_hal_hash_block(unsigned int mode,const void *input,unsigned int word_count,unsigned char first_block);
void sha_hal_hash_dma(unsigned int mode,unsigned int block_count,unsigned char first_block);
void sha_hal_wait_idle(void);
void sha_hal_read_digest(unsigned int mode,void *state);
void sha_hal_write_digest(unsigned int mode,const void *state);
void esp_crypto_sha_aes_lock_acquire(void);
void esp_crypto_sha_aes_lock_release(void);
void esp_dport_access_read_buffer(unsigned int *destination,unsigned int source_address,unsigned int word_count);
/* Shared SHA backend; lengths and first_block retain their native widths. */
int esp_sha_dma(unsigned int mode,const void *input,unsigned int input_length,
    const void *buffer,unsigned int buffer_length,unsigned char first_block);
#define FUN_4201723c mbedtls_sha256_update
#define FUN_42017328 mbedtls_sha256_finish
#define FUN_420173b4 esp_sha_write_digest_state
#define FUN_420173c4 esp_sha_read_digest_state
#define FUN_420173d4 esp_sha_acquire_hardware
#define FUN_42017438 esp_sha_release_hardware
#define FUN_42017a14 sha_hal_hash_block
#define FUN_42017a70 sha_hal_hash_dma
#define FUN_42017aac sha_hal_wait_idle
#define FUN_42017abc sha_hal_read_digest
#define FUN_42017b18 sha_hal_write_digest
#define FUN_42011684 esp_crypto_sha_aes_lock_acquire
#define FUN_42011694 esp_crypto_sha_aes_lock_release
#define FUN_42021418 esp_dport_access_read_buffer

/* ESP32-S3 DMA descriptor: two 12-bit lengths, success EOF at bit30,
 * DMA ownership at bit31. Keep raw control bits24..29 on field updates.
 * These are shared native storage, not per-call descriptor allocations.
 */
typedef struct CryptoDmaDescriptor {
    volatile unsigned int control;
    const void *volatile buffer;
    struct CryptoDmaDescriptor *volatile next;
} CryptoDmaDescriptor;
#define SHA_PREFIX_DESCRIPTOR ((CryptoDmaDescriptor *)0x3fcbcbe0U)
#define SHA_INPUT_DESCRIPTOR ((CryptoDmaDescriptor *)0x3fcbcbecU)
#define CRYPTO_TX_CHANNEL (*(GdmaChannel *volatile *)0x3fcd86f4U)
#define CRYPTO_RX_CHANNEL (*(GdmaChannel *volatile *)0x3fcd86f8U)
#define CRYPTO_AES_TRIGGER ((const volatile GdmaTrigger *)0x3c0473b4U)
#define CRYPTO_SHA_TRIGGER ((const volatile GdmaTrigger *)0x3c0473c0U)
unsigned char esp_ptr_dma_ext_capable(void *pointer);
int esp_sha_dma_start(const CryptoDmaDescriptor *input);
int crypto_shared_gdma_init(void);
int esp_crypto_shared_gdma_start(const CryptoDmaDescriptor *input,
    const CryptoDmaDescriptor *output,unsigned int peripheral);
#define FUN_42017464 esp_sha_dma
#define FUN_42017754 esp_sha_dma_start
#define FUN_42017764 crypto_shared_gdma_init
#define FUN_42017830 esp_crypto_shared_gdma_start

/* Complete GCC 14.2 Xtensa C++ ABI records. Native catches use the common
 * primary/dependent suffix. An arbitrary foreign unwind object has no valid
 * preceding C++ header: its saved pseudo-prefix may only be used to recover
 * unwind_header, until its class is proven GNU. Explicit padding is storage,
 * never an initialized field or extra allocation. */
struct CxxTypeInfo;
struct CxxUnwindException;
typedef void (*CxxHandler)(void);
typedef void (*CxxExceptionDestructor)(void *object);
typedef enum CxxUnwindReason {
    CXX_UNWIND_NO_REASON = 0,
    CXX_UNWIND_FOREIGN_EXCEPTION_CAUGHT = 1,
    CXX_UNWIND_FATAL_PHASE2_ERROR = 2,
    CXX_UNWIND_FATAL_PHASE1_ERROR = 3,
    CXX_UNWIND_NORMAL_STOP = 4,
    CXX_UNWIND_END_OF_STACK = 5,
    CXX_UNWIND_HANDLER_FOUND = 6,
    CXX_UNWIND_INSTALL_CONTEXT = 7,
    CXX_UNWIND_CONTINUE_UNWIND = 8
} CxxUnwindReason;
typedef void (*CxxUnwindCleanup)(CxxUnwindReason reason,
    struct CxxUnwindException *exception);
typedef struct CxxUnwindClass {
    volatile unsigned int low;              /* +0: native LOW read first */
    volatile unsigned int high;             /* +4 */
} __attribute__((aligned(8))) CxxUnwindClass;
typedef struct CxxUnwindException {
    CxxUnwindClass exception_class;         /* +0, 8 bytes */
    CxxUnwindCleanup exception_cleanup;     /* +8 */
    unsigned int private_1;                 /* +12: unwinder-owned */
    unsigned int private_2;                 /* +16: unwinder-owned */
    unsigned int padding_20[3];             /* +20..31: maximum alignment */
} __attribute__((aligned(16))) CxxUnwindException;
typedef struct CxxException {
    struct CxxTypeInfo *exception_type;     /* +0: type_info pointer */
    CxxExceptionDestructor exception_destructor; /* +4 */
    CxxHandler unexpected_handler;          /* +8 */
    CxxHandler terminate_handler;           /* +12 */
    struct CxxException *volatile next_exception; /* +16 */
    volatile int handler_count;             /* +20: negative means rethrow */
    int handler_switch_value;               /* +24 */
    const unsigned char *action_record;     /* +28 */
    const unsigned char *language_specific_data; /* +32 */
    unsigned int catch_temporary;           /* +36: _Unwind_Ptr */
    void *volatile adjusted_pointer;        /* +40 */
    unsigned int padding_44;                /* +44: unwind alignment */
    CxxUnwindException unwind_header;       /* +48..79 */
} __attribute__((aligned(16))) CxxException;
typedef struct CxxDependentException {
    void *primary_exception;                /* +0: primary object pointer */
    CxxExceptionDestructor unused_destructor; /* +4: ABI __padding slot */
    CxxHandler unexpected_handler;          /* +8 */
    CxxHandler terminate_handler;           /* +12 */
    CxxException *volatile next_exception;  /* +16: common catch chain */
    volatile int handler_count;             /* +20 */
    int handler_switch_value;               /* +24 */
    const unsigned char *action_record;     /* +28 */
    const unsigned char *language_specific_data; /* +32 */
    unsigned int catch_temporary;           /* +36 */
    void *volatile adjusted_pointer;        /* +40 */
    unsigned int padding_44;                /* +44 */
    CxxUnwindException unwind_header;       /* +48..79 */
} __attribute__((aligned(16))) CxxDependentException;
typedef struct CxxRefcountedException {
    int reference_count;                    /* +0: _Atomic_word storage */
    unsigned int padding_4[3];              /* +4..15: exception alignment */
    CxxException exception;                 /* +16..95: must be last */
} __attribute__((aligned(16))) CxxRefcountedException;
typedef struct CxxEhGlobals {
    CxxException *volatile caught_exceptions; /* +0 */
    volatile unsigned int uncaught_exceptions; /* +4 */
} CxxEhGlobals;
typedef void (*CxxTerminationDispatch)(CxxHandler handler) __attribute__((noreturn));
#define CXX_NEW_HANDLER (*(CxxHandler volatile *)0x3fcd8704U)
#define CXX_EH_KEY (*(volatile unsigned int *)0x3fcd8708U)
#define CXX_EH_TLS_ENABLED (*(volatile unsigned char *)0x3fcd870cU)
#define CXX_EH_FALLBACK ((CxxEhGlobals *)0x3fcd8710U)
#define CXX_TERMINATE_HANDLER (*(CxxHandler volatile *)0x3fcabb44U)
void *malloc(size_t bytes);
int pthread_key_create(unsigned int *key,PthreadDestructor destructor);
void *pthread_getspecific(unsigned int key);
void cxx_operator_delete_array(void *memory);
CxxHandler cxx_get_new_handler(void);
void cxx_operator_delete(void *memory);
void *__cxa_begin_catch(CxxUnwindException *unwind_header);
void __cxa_end_catch(void);
void cxx_eh_globals_destroy(void *storage);
CxxEhGlobals *__cxa_get_globals_fast(void);
CxxEhGlobals *__cxa_get_globals(void);
void cxx_eh_globals_initialize(void);
CxxHandler cxx_get_terminate(void);
void cxx_terminate(void) __attribute__((noreturn));
void *cxx_operator_new_array(size_t bytes);
void *cxx_operator_new(size_t bytes);
void cxx_operator_delete_sized(void *memory,size_t ignored_size);
void cxx_unwind_delete_exception_abort(CxxUnwindException *ignored_header) __attribute__((noreturn));
void cxx_allocate_exception_abort(void) __attribute__((noreturn));
void cxx_throw_abort(void) __attribute__((noreturn));
/* Typed boundary only; handler call and native catch landing pad await their
 * separate source reconstruction. No completion claim for0x42017e98 here.
 */
void cxx_terminate_with_handler(CxxHandler handler) __asm__("FUN_42017e98") __attribute__((noreturn));
#define FUN_42017ce4 cxx_operator_delete_array
#define FUN_42017cf4 cxx_get_new_handler
#define FUN_42017d28 cxx_operator_delete
#define FUN_42017d38 __cxa_begin_catch
#define FUN_42017d90 __cxa_end_catch
#define FUN_42017df0 cxx_eh_globals_destroy
#define FUN_42017e14 __cxa_get_globals_fast
#define FUN_42017e34 __cxa_get_globals
#define FUN_42017e78 cxx_eh_globals_initialize
#define FUN_42017eb4 cxx_get_terminate
#define FUN_42017ec4 cxx_terminate
#define FUN_42017ed4 cxx_operator_new_array
#define FUN_42017ee4 cxx_operator_new
#define FUN_42018160 cxx_operator_delete_sized
#define FUN_42018170 cxx_unwind_delete_exception_abort
#define FUN_42018188 cxx_allocate_exception_abort
#define FUN_42018194 cxx_throw_abort

/* C views of GCC C++ RTTI objects. Vptr is the vtable ADDRESS POINT, after
 * offset-to-top/typeinfo metadata. Only the first16 bytes of dynamic-cast
 * results are accessed here; this view omits later ABI bookkeeping.
 */
typedef struct CxxTypeInfo CxxTypeInfo;
typedef struct MediusCxxUpcastResult {
    const void *volatile destination_pointer;
    volatile unsigned int part_to_destination;
    volatile int source_details;
    const CxxTypeInfo *volatile base_type;
} MediusCxxUpcastResult;
typedef struct MediusCxxDynamicCastResultView {
    const void *volatile destination_pointer;
    volatile unsigned int whole_to_destination;
    volatile unsigned int whole_to_source;
    volatile unsigned int destination_to_source;
} MediusCxxDynamicCastResultView;
typedef struct MediusCxxClassVtable {
    void (*destroy)(void *object);                            /* +0x00 */
    void (*delete_object)(void *object);                      /* +0x04 */
    bool (*is_pointer)(const CxxTypeInfo *self);         /* +0x08 */
    bool (*is_function)(const CxxTypeInfo *self);        /* +0x0c */
    bool (*do_catch)(const CxxTypeInfo *self,const CxxTypeInfo *thrown,void **object,unsigned int outer); /* +0x10 */
    bool (*upcast_object)(const CxxTypeInfo *self,const CxxTypeInfo *target,void **object); /* +0x14 */
    bool (*upcast_result)(const CxxTypeInfo *self,const CxxTypeInfo *target,const void *object,MediusCxxUpcastResult *result); /* +0x18 */
    bool (*dynamic_cast_search)(const CxxTypeInfo *self,int source_to_destination,unsigned int access_path,const CxxTypeInfo *target,const void *object,const CxxTypeInfo *source,const void *source_object,MediusCxxDynamicCastResultView *result); /* +0x1c */
    unsigned int (*find_public_source)(const CxxTypeInfo *self,int source_to_destination,const void *object,const CxxTypeInfo *source,const void *source_object); /* +0x20 */
} MediusCxxClassVtable;
struct CxxTypeInfo {
    const MediusCxxClassVtable *volatile vtable;
    const char *volatile name;
};
typedef struct MediusCxxSingleBaseTypeInfo {
    CxxTypeInfo type;
    const CxxTypeInfo *volatile base_type;
} MediusCxxSingleBaseTypeInfo;
typedef struct MediusCxxExceptionVtable {
    void (*destroy)(void *object);
    void (*delete_object)(void *object);
    const char *(*what)(const void *object);
} MediusCxxExceptionVtable;
typedef struct MediusCxxExceptionObject {
    const MediusCxxExceptionVtable *volatile vtable;
} MediusCxxExceptionObject;
#define MEDIUS_CXX_SI_VTABLE ((const MediusCxxClassVtable *)0x3c047464U)
#define MEDIUS_CXX_CLASS_VTABLE ((const MediusCxxClassVtable *)0x3c0475d0U)
#define MEDIUS_CXX_BAD_ALLOC_VTABLE ((const MediusCxxExceptionVtable *)0x3c0475bcU)
void cxx_si_type_info_destroy(MediusCxxSingleBaseTypeInfo *self);
void cxx_si_type_info_delete(MediusCxxSingleBaseTypeInfo *self);
bool cxx_si_type_name_equal(const char *left,const char *right);
bool cxx_si_type_info_do_dyncast(const MediusCxxSingleBaseTypeInfo *self,int source_to_destination,unsigned int access_path,const CxxTypeInfo *target,const void *object,const CxxTypeInfo *source,const void *source_object,MediusCxxDynamicCastResultView *result);
unsigned int cxx_si_type_info_find_public_source(const MediusCxxSingleBaseTypeInfo *self,int source_to_destination,const void *object,const CxxTypeInfo *source,const void *source_object);
bool cxx_si_type_info_do_upcast(const MediusCxxSingleBaseTypeInfo *self,const CxxTypeInfo *target,const void *object,MediusCxxUpcastResult *result);
const char *cxx_bad_alloc_what(const void *ignored_self);
void cxx_bad_alloc_destroy(MediusCxxExceptionObject *self);
void cxx_bad_alloc_delete(MediusCxxExceptionObject *self);
void cxx_class_type_info_destroy(CxxTypeInfo *self);
void cxx_class_type_info_delete(CxxTypeInfo *self);
bool cxx_class_type_name_equal(const char *left,const char *right);
bool cxx_class_type_info_do_upcast(const CxxTypeInfo *self,const CxxTypeInfo *target,const void *object,MediusCxxUpcastResult *result);
bool cxx_class_type_info_do_dyncast(const CxxTypeInfo *self,int ignored_source_to_destination,unsigned int access_path,const CxxTypeInfo *target,const void *object,const CxxTypeInfo *source,const void *source_object,MediusCxxDynamicCastResultView *result);
bool cxx_class_type_info_do_catch(const CxxTypeInfo *self,const CxxTypeInfo *thrown,void **object,unsigned int outer);
void cxx_type_info_destroy(CxxTypeInfo *ignored_self);
void cxx_exception_destroy(MediusCxxExceptionObject *ignored_self);
int strcmp(const char *left,const char *right);
#define FUN_42017f24 cxx_si_type_info_destroy
#define FUN_42017f38 cxx_si_type_info_delete
#define FUN_42017f50 cxx_si_type_name_equal
#define FUN_42017f80 cxx_si_type_info_do_dyncast
#define FUN_42017ff8 cxx_si_type_info_find_public_source
#define FUN_42018024 cxx_si_type_info_do_upcast
#define FUN_42018050 cxx_bad_alloc_what
#define FUN_42018058 cxx_bad_alloc_destroy
#define FUN_4201806c cxx_bad_alloc_delete
#define FUN_42018084 cxx_class_type_info_destroy
#define FUN_42018098 cxx_class_type_info_delete
#define FUN_420180b0 cxx_class_type_name_equal
#define FUN_420180e0 cxx_class_type_info_do_upcast
#define FUN_42018100 cxx_class_type_info_do_dyncast
#define FUN_42018138 cxx_class_type_info_do_catch
#define FUN_4202144c cxx_type_info_destroy
#define FUN_42021498 cxx_exception_destroy

/* Pointer/function predicates share one native false-return entry. */
bool cxx_type_info_is_pointer_or_function(const CxxTypeInfo *ignored_self);
bool cxx_class_type_info_upcast_object(const CxxTypeInfo *self,const CxxTypeInfo *target,void **object);
unsigned int cxx_class_type_info_find_public_source(const CxxTypeInfo *ignored_self,int ignored_source_to_destination,const void *object,const CxxTypeInfo *ignored_source,const void *source_object);
#define FUN_42021454 cxx_type_info_is_pointer_or_function
#define FUN_4202145c cxx_class_type_info_upcast_object
#define FUN_4202148c cxx_class_type_info_find_public_source

/* Native OTA selection records: CRC covers ONLY the4-byte sequence field. */
typedef struct OtaSelectEntry {
    volatile unsigned int sequence;
    unsigned char sequence_label[20];
    volatile unsigned int state;
    volatile unsigned int crc;
} OtaSelectEntry;
/* Full packed ESP-IDF image header; paired bytes preserve native
 * HIGH-before-LOW reads of unaligned little-endian revision fields.
 * spi_speed_and_size uses the low nibble for frequency and high nibble for size.
 */
typedef struct RevisionPairBytes {
    volatile unsigned char low,high;
} RevisionPairBytes;
typedef struct ImageRevisionHeader {
    unsigned char magic;
    unsigned char segment_count;
    unsigned char spi_mode;
    unsigned char spi_speed_and_size;
    unsigned int entry_address;              /* +4 */
    unsigned char write_protect_pin;
    unsigned char spi_drive[3];
    RevisionPairBytes chip_id;                /* +12 */
    unsigned char legacy_minimum_revision;   /* +14 */
    RevisionPairBytes minimum_revision;      /* +15 */
    RevisionPairBytes maximum_revision;      /* +17 */
    unsigned char reserved[4];
    unsigned char hash_appended;             /* +23 */
} __attribute__((packed)) ImageRevisionHeader;
unsigned int bootloader_common_ota_select_crc(const OtaSelectEntry *entry);
bool bootloader_common_ota_select_valid(const OtaSelectEntry *entry);
int bootloader_common_check_efuse_blk_validity(unsigned int minimum_revision,unsigned int maximum_revision);
int bootloader_common_check_chip_validity(const ImageRevisionHeader *header,unsigned int image_type);
int bootloader_common_get_active_otadata(const OtaSelectEntry entries[2]);
int bootloader_common_select_otadata(const OtaSelectEntry entries[2],const unsigned char validity[2],unsigned char select_maximum);
unsigned int bootloader_mmap_get_free_pages(void);
const void *bootloader_mmap(unsigned int flash_address,unsigned int length);
void bootloader_munmap(const void *mapped_address);
#define BOOT_MMAP_HANDLE (*(volatile unsigned int *)0x3fcd8624U)
#define BOOT_EARLY_LOG_ENABLED (*(volatile unsigned int *)0x3fcaa550U)
#define FUN_4200f2a8 bootloader_common_ota_select_crc
#define FUN_4200f2bc bootloader_common_ota_select_valid
#define FUN_4200f2e8 bootloader_common_check_efuse_blk_validity
#define FUN_4200f3a4 bootloader_common_check_chip_validity
#define FUN_4200f4c4 bootloader_common_get_active_otadata
#define FUN_4202115c bootloader_common_select_otadata
#define FUN_4200f53c bootloader_mmap_get_free_pages
#define FUN_4200f548 bootloader_mmap
#define FUN_4200f5b8 bootloader_munmap

/* OTA operation, 44 bytes. Link at +36 is a BSD LIST entry; previous_link
 * addresses the head slot or a preceding node's next field, not a node.
 * Bytes 9..11 and 17..19 are not interpreted by these lifetime entries.
 */
typedef struct OtaOperation {
    volatile unsigned int handle;
    const EspPartition *volatile partition;
    volatile unsigned char need_erase;
    unsigned char uninterpreted9[3];
    volatile unsigned int written_size;
    volatile unsigned char partial_bytes;
    unsigned char uninterpreted17[3];
    unsigned char partial_data[16];
    struct OtaOperation *volatile next;
    struct OtaOperation *volatile *volatile previous_link;
} OtaOperation;
typedef struct ImagePosition {
    unsigned int offset,size;
} ImagePosition;
typedef struct ImageHeader {
    unsigned char magic,segment_count,spi_mode,spi_speed_and_size;
    unsigned int entry_address;
    unsigned char write_protect_pin,spi_drive[3];
    RevisionPairBytes chip_id;
    unsigned char legacy_minimum_revision;
    RevisionPairBytes minimum_revision,maximum_revision;
    unsigned char reserved19[4],hash_appended;
} __attribute__((packed)) ImageHeader;
typedef struct ImageSegmentHeader {
    unsigned int load_addr,data_len;
} ImageSegmentHeader;
/* Native metadata264; secure_version is zeroed but not assigned by this image. */
typedef struct ImageMetadata {
    unsigned int start_addr;
    ImageHeader image;
    ImageSegmentHeader segments[16];
    unsigned int segment_data[16],image_len;
    unsigned char image_digest[32];
    unsigned int secure_version,mmu_page_size;
} ImageMetadata;
/* Retain the existing byte/scratch view for reviewed OTA callers. */
typedef union ImageMetadataScratch {
    unsigned int alignment_word;
    unsigned char bytes[264];
    ImageMetadata value;
} ImageMetadataScratch;
/* Only these descriptor HALF fields are read here; no larger shape inferred. */
typedef struct AppEfuseRevisionFields {
    unsigned char uninterpreted0[176];
    unsigned short minimum_revision,maximum_revision;
} AppEfuseRevisionFields;
OtaOperation *esp_ota_init_entry(const EspPartition *partition);
const EspPartition *ota_read_otadata(OtaSelectEntry entries[2]);
int ota_rewrite_sequence(OtaSelectEntry *entries,unsigned int sequence,unsigned int sector_index,const EspPartition *partition);
const EspPartition *ota_cache_running_partition(void);
int ota_validate_image_region(unsigned int address,unsigned int size,unsigned int mode);
void *calloc(size_t count,size_t size);
int esp_image_verify(unsigned int mode,const ImagePosition *position,ImageMetadataScratch *metadata);
#define ESP_PARTITION_TYPE_APP 0U
#define ESP_PARTITION_SUBTYPE_DATA_OTA 0U
#define ESP_PARTITION_SUBTYPE_ANY 0xffU
#define ESP_PARTITION_MMAP_DATA 0U
#define ESP_IMAGE_VERIFY 0U
#define ESP_IMAGE_VERIFY_SILENT 1U
#define ESP_PARTITION_SUBTYPE_APP_FACTORY 0U
#define ESP_PARTITION_SUBTYPE_APP_OTA_MIN 0x10U
#define ESP_PARTITION_SUBTYPE_APP_OTA_MAX 0x20U
#define ESP_OTA_IMG_NEW 0U
#define ESP_OTA_IMG_PENDING_VERIFY 1U
#define OTA_SIZE_UNKNOWN 0xffffffffU
#define OTA_WITH_SEQUENTIAL_WRITES 0xfffffffeU
#define ESP_IMAGE_HEADER_MAGIC 0xe9U
#define ESP_OTA_IMG_VALID 2U
#define ESP_OTA_IMG_INVALID 3U
#define OTA_OPERATIONS (*(OtaOperation *volatile *)0x3fcd8618U)
#define OTA_LAST_HANDLE (*(volatile unsigned int *)0x3fcd8614U)
#define OTA_RUNNING_PARTITION (*(const EspPartition *volatile *)0x3fcd8610U)
#define FUN_4200e3c4 esp_ota_init_entry
#define FUN_4200e3f8 ota_read_otadata
#define FUN_4200e484 ota_rewrite_sequence
#define FUN_4200e4bc ota_cache_running_partition
#define FUN_4200e51c esp_ota_get_running_partition
#define FUN_4200e530 ota_validate_image_region
#define FUN_4200e6d4 esp_ota_abort
#define FUN_4200e710 esp_ota_end
#define FUN_4200e554 esp_ota_write
#define FUN_4200ebc8 esp_ota_begin
bool esp_ota_check_rollback_is_possible(void);
#define FUN_4200e798 esp_ota_set_boot_partition
#define FUN_4200e880 esp_ota_get_next_update_partition
#define FUN_4200e8e4 esp_ota_check_rollback_is_possible
#define FUN_4200e9d4 esp_ota_current_ota_is_workable
#define FUN_4200eaf8 esp_ota_get_state_partition

/* Application image parsing and corruption-hash verification boundaries. */
int bootloader_flash_read(unsigned int address,void *output,unsigned int size,unsigned char allow_decrypt);
int image_process_checksum(Sha256Context *sha,unsigned int checksum_word,ImageMetadataScratch *metadata,unsigned int silent,unsigned int skip_checksum);
int image_process_header(ImageMetadataScratch *metadata,unsigned int address,Sha256Context **out_sha,unsigned int verify,unsigned int silent);
int image_process_segments(ImageMetadataScratch *metadata,unsigned int silent,Sha256Context *sha,unsigned int *checksum);
int image_process_appended_hash(ImageMetadataScratch *metadata,unsigned int partition_size,unsigned int silent);
int image_load(unsigned int mode,const ImagePosition *position,ImageMetadataScratch *metadata);
Sha256Context *bootloader_sha256_start(void);
void bootloader_sha256_data(Sha256Context *sha,const void *data,unsigned int size);
void bootloader_sha256_finish(Sha256Context *sha,unsigned char *output);
void bootloader_debug_buffer(const void *data,unsigned int size,const char *label);
void bzero(void *storage,size_t length);
#define FUN_4200f5d0 bootloader_flash_read
#define FUN_4200f61c image_process_checksum
#define FUN_4200f6bc image_process_header
#define FUN_4200f77c image_process_segments
#define FUN_4200fa5c image_process_appended_hash
#define FUN_4200fab4 image_load
#define FUN_4200fbc8 esp_image_verify
#define FUN_4200fbd8 bootloader_sha256_start
#define FUN_4200fc00 bootloader_sha256_data
#define FUN_4200fc24 bootloader_sha256_finish
#define FUN_420211a8 bootloader_debug_buffer

void esp_crosscore_int_send_print_backtrace(int core_id);
void esp_crosscore_int_send_twdt_abort(int core_id);
#define FUN_42010f10 task_wdt_isr

void medius_cxx_fatal_stub(void) __attribute__((noreturn));
#define FUN_4201817c medius_cxx_fatal_stub

/* Newlib general FILE vector output and buffer refill. */
int medius_newlib_write_vectors(NewlibReent *,NewlibFile *,MediusNewlibStringWriteRequest *);
int medius_newlib_flush_vectors(NewlibReent *,NewlibFile *,MediusNewlibStringWriteRequest *);
int medius_newlib_flush_line_visitor(NewlibReent *,NewlibFile *);
int medius_newlib_refill_file(NewlibReent *,NewlibFile *);
void *memchr(const void *input,int byte_value,size_t length);
#define FUN_42018700 medius_newlib_write_vectors
#define FUN_4201f374 medius_newlib_flush_vectors
#define FUN_4201f490 medius_newlib_flush_line_visitor
#define FUN_4201f4b0 medius_newlib_refill_file

int newlib_fprintf(NewlibFile *stream,const char *format,...);
int newlib_printf(const char *format,...);
int newlib_snprintf(char *output,size_t capacity,const char *format,...);
int medius_newlib_vformat_string(NewlibReent *,NewlibFile *,const char *,va_list);
int medius_newlib_vsnprintf_r(NewlibReent *,char *output,size_t capacity,const char *format,va_list arguments);
#define FUN_420186b4 newlib_fprintf
#define FUN_420189ac newlib_printf
#define FUN_420189e0 newlib_snprintf
#define FUN_42018b38 medius_newlib_vsnprintf_r
#define FUN_42018b90 vsnprintf

/* Installed Newlib lconv layout; pointer fields precede fourteen BYTE fields. */
typedef struct MediusNewlibLocaleConversion {
    char *decimal_point,*thousands_sep,*grouping;
    char *int_curr_symbol,*currency_symbol,*mon_decimal_point,*mon_thousands_sep;
    char *mon_grouping,*positive_sign,*negative_sign;
    char int_frac_digits,frac_digits,p_cs_precedes,p_sep_by_space;
    char n_cs_precedes,n_sep_by_space,p_sign_posn,n_sign_posn;
    char int_n_cs_precedes,int_n_sep_by_space,int_n_sign_posn;
    char int_p_cs_precedes,int_p_sep_by_space,int_p_sign_posn;
} MediusNewlibLocaleConversion;
typedef union MediusBinary64Words {
    double value;
    struct {unsigned int low,high;};
} MediusBinary64Words;
int medius_newlib_format_temporary_stream(NewlibReent *,NewlibFile *,const char *,va_list);
MediusNewlibLocaleConversion *medius_newlib_localeconv(void);
double medius_newlib_frexp(double value,int *exponent);
#define MEDIUS_NEWLIB_GLOBAL_LOCALE (*(const void *volatile *)0x3fcabc4cU)
#define FUN_4201f2dc medius_newlib_format_temporary_stream
#define FUN_4201f5a4 medius_newlib_localeconv
#define FUN_4201f5b4 medius_newlib_frexp

/* Reviewed Newlib 32-bit file positioning. */
int medius_newlib_seek_file(NewlibReent *,NewlibFile *,long,int);
#define FUN_420186e8 medius_newlib_seek_file
int medius_newlib_seek_file_offset(NewlibReent *,NewlibFile *,long,int);
#define FUN_42018c60 medius_newlib_seek_file_offset

/* ESP32-S3 memory protection: saved 24-byte boot configuration and MMIO. */
enum MemoryProtectionType {MEMPROT_IRAM=1,MEMPROT_DRAM=2,MEMPROT_RTCFAST=4};
typedef struct MemoryProtectionMonitor {
    volatile unsigned int lock;
    volatile unsigned int control; /* bit 0: interrupt clear; bit 1: enable */
} MemoryProtectionMonitor; /* register prefix, not the complete peripheral */
#define MEMPROT_CONFIGURATION (*(volatile BootMemoryProtectionConfiguration *)0x3fcaa594U)
#define MEMPROT_SPLIT_LOCK MMIO32(0x600c10c0U)
#define MEMPROT_IRAM_PMS_LOCK MMIO32(0x600c10d8U)
#define MEMPROT_DRAM_PMS_LOCK MMIO32(0x600c10fcU)
#define MEMPROT_RTC_PMS_LOCK0 MMIO32(0x600c1124U)
#define MEMPROT_RTC_PMS_LOCK1 MMIO32(0x600c11d0U)
#define MEMPROT_IRAM_MONITOR0 ((MemoryProtectionMonitor *)0x600c10e4U)
#define MEMPROT_IRAM_MONITOR1 ((MemoryProtectionMonitor *)0x600c10f0U)
#define MEMPROT_DRAM_MONITOR0 ((MemoryProtectionMonitor *)0x600c1104U)
#define MEMPROT_DRAM_MONITOR1 ((MemoryProtectionMonitor *)0x600c1114U)
#define MEMPROT_RTC_MONITOR0 ((MemoryProtectionMonitor *)0x600c119cU)
#define MEMPROT_RTC_MONITOR1 ((MemoryProtectionMonitor *)0x600c1248U)
int esp_mprot_set_pms_lock(unsigned int memory_type,int core);
#define FUN_42005a0c esp_mprot_set_pms_lock
int esp_mprot_set_monitor_lock(unsigned int memory_type,int core);
#define FUN_42005fb4 esp_mprot_set_monitor_lock
int esp_mprot_get_monitor_lock(unsigned int memory_type,unsigned char *locked,int core);
#define FUN_4200605c esp_mprot_get_monitor_lock
int esp_mprot_set_monitor_en(unsigned int memory_type,unsigned char enable,int core);
#define FUN_42006144 esp_mprot_set_monitor_en
int esp_mprot_get_monitor_en(unsigned int memory_type,unsigned char *enabled,int core);
#define FUN_42006254 esp_mprot_get_monitor_en
int esp_mprot_monitor_clear_intr(unsigned int memory_type,int core);
#define FUN_42006320 esp_mprot_monitor_clear_intr
#define FUN_42006404 esp_mprot_is_conf_locked_any
int esp_mprot_ll_err_to_esp_err(int hal_error);
#define FUN_42007190 esp_mprot_ll_err_to_esp_err

/* Exact, single memory-protection area IDs; combinations are not accepted. */
enum MemoryProtectionArea {
 MEMPROT_AREA_IRAM0=1,MEMPROT_AREA_IRAM1=2,
 MEMPROT_AREA_IRAM2=4,MEMPROT_AREA_IRAM3=8,
 MEMPROT_AREA_DRAM0=0x10,MEMPROT_AREA_DRAM1=0x20,
 MEMPROT_AREA_DRAM2=0x40,MEMPROT_AREA_DRAM3=0x80,
 MEMPROT_AREA_RTC_LOW=0x100,MEMPROT_AREA_RTC_HIGH=0x200,
 MEMPROT_AREA_ICACHE0=0x400,MEMPROT_AREA_ICACHE1=0x800
};
typedef struct MemoryProtectionRtcRegion {
 volatile unsigned int split_address;
 volatile unsigned int permissions;
} MemoryProtectionRtcRegion; /* observed two-register prefix */
#define MEMPROT_IRAM_PERMISSIONS MMIO32(0x600c10e0U)
#define MEMPROT_DRAM_PERMISSIONS MMIO32(0x600c1100U)
#define MEMPROT_RTC_REGION0 ((MemoryProtectionRtcRegion *)0x600c1148U)
#define MEMPROT_RTC_REGION1 ((MemoryProtectionRtcRegion *)0x600c11f4U)
int esp_mprot_set_pms_area(unsigned int area,unsigned int permissions,int core);
#define FUN_42005a8c esp_mprot_set_pms_area
int esp_mprot_get_pms_area(unsigned int area,unsigned int *permissions,int core);
#define FUN_42005d80 esp_mprot_get_pms_area

/* SRAM split-line constraint words and native stack workspace. */
enum MemoryProtectionSplitLine {MEMPROT_SPLIT_MAIN=1,MEMPROT_SPLIT_IRAM0=2,
 MEMPROT_SPLIT_IRAM1=4,MEMPROT_SPLIT_DRAM0=8,
 MEMPROT_SPLIT_DRAM1=16};
typedef struct MemoryProtectionSplitRegisters {
 volatile unsigned int main;
 volatile unsigned int iram[2];
 volatile unsigned int dram[2];
} MemoryProtectionSplitRegisters;
typedef struct MemoryProtectionSplitWorkspace {
 unsigned int high_limits[7];
 unsigned int categories[7];
} MemoryProtectionSplitWorkspace;
#define MEMPROT_SPLIT_REGISTERS ((MemoryProtectionSplitRegisters *)0x600c10c4U)
int esp_mprot_set_split_addr(unsigned int memory_type,unsigned int line_type,const void *line_address,int core);
#define FUN_42005570 esp_mprot_set_split_addr
#define MEMPROT_SPLIT_DEFAULTS ((const unsigned int *)0x3c0460f4U)
#define MEMPROT_SPLIT_HIGH_LIMITS ((const unsigned int *)0x3c046110U)

#define FUN_42006678 esp_mprot_set_prot
#define MEMPROT_DEFAULT_SRAM_SPLIT 0x4039a500U
void software_reset(void); /* ROM 0x400006d8; fault path follows with ILL. */

/* Native Xtensa va_list storage used by the positional-format scanners. */
typedef struct MediusXtensaVaListCursor {
 unsigned char *stack_base;   /* +0: stack pointer biased for register spill */
 unsigned char *register_save; /* +4: six saved argument registers */
 unsigned int offset;         /* +8: native signed comparisons, wrapping bits */
} MediusXtensaVaListCursor;
enum MediusNewlibArgumentType {
 MEDIUS_NEWLIB_ARG_INT,MEDIUS_NEWLIB_ARG_LONG,MEDIUS_NEWLIB_ARG_QUAD,
 MEDIUS_NEWLIB_ARG_POINTER,MEDIUS_NEWLIB_ARG_DOUBLE,
 MEDIUS_NEWLIB_ARG_LONG_DOUBLE,MEDIUS_NEWLIB_ARG_WIDE_CHAR
};
typedef union MediusNewlibArgumentValue {
 int integer;
 unsigned int unsigned_integer;
 unsigned long unsigned_long_integer;
 unsigned long long unsigned_quad_integer;
 void *pointer;
 int *integer_pointer;
 short *short_pointer;
 long *long_pointer;
 long long *quad_pointer;
 long long_integer;
 long long quad_integer;
 char *string;
 double floating;
 long double extended_floating;
 unsigned int wide_character;
 unsigned int words[2];
} MediusNewlibArgumentValue;
MediusNewlibArgumentValue *medius_newlib_get_string_argument(int,const unsigned char *,MediusXtensaVaListCursor *,unsigned int *,MediusNewlibArgumentValue *,int *,const unsigned char **);
#define FUN_420190cc medius_newlib_get_string_argument
MediusNewlibArgumentValue *medius_newlib_get_stream_argument(int,const unsigned char *,MediusXtensaVaListCursor *,unsigned int *,MediusNewlibArgumentValue *,int *,const unsigned char **);
#define FUN_4201c174 medius_newlib_get_stream_argument

void nvs_esp_partition_destroy(NvsPartitionObject *object);
#define FUN_420211b0 nvs_esp_partition_destroy

void nvs_esp_partition_delete(NvsPartitionObject *object);
#define FUN_420129fc nvs_esp_partition_delete

const char * nvs_esp_partition_get_name(NvsPartitionObject *object);
#define FUN_420211cc nvs_esp_partition_get_name

unsigned int nvs_esp_partition_get_address(NvsPartitionObject *object);
#define FUN_420211d8 nvs_esp_partition_get_address

unsigned int nvs_esp_partition_get_size(NvsPartitionObject *object);
#define FUN_420211e4 nvs_esp_partition_get_size

unsigned int nvs_esp_partition_get_readonly(NvsPartitionObject *object);
#define FUN_420211f0 nvs_esp_partition_get_readonly

void nvs_partition_manager_destroy(NvsPartitionManager *);
#define FUN_420211fc nvs_partition_manager_destroy

#define CLIP_ALLOCATION_CAPACITY (*(volatile unsigned int *)0x3fcc8008U)
const unsigned char * medius_clone_get_device_descriptor(unsigned int);
#define FUN_403942a0 medius_clone_get_device_descriptor
unsigned int link_get_other_rx_drops(void);
#define FUN_42022580 link_get_other_rx_drops
unsigned int usbd_get_unaligned_write_count(void);
#define FUN_4203348c usbd_get_unaligned_write_count
unsigned int report_get_normalization_epoch(void);
#define FUN_42033c94 report_get_normalization_epoch
unsigned int usbd_get_reset_count(void);
#define FUN_42033ca4 usbd_get_reset_count
unsigned int usbd_get_configuration_event_count(void);
#define FUN_42033cb4 usbd_get_configuration_event_count
unsigned int clip_get_allocation_capacity(void);
#define FUN_420370f0 clip_get_allocation_capacity
unsigned int status_get_host_counted_rx_drops(void);
#define FUN_420389d8 status_get_host_counted_rx_drops

#define FUN_4201959c medius_newlib_vformat_string

#define FUN_4201c644 medius_newlib_vformat_stream

/* Byte-aligned host-to-device USB message prefixes. Lengths remain supplied
 * separately; flexible payload members do not imply any capacity guarantee. */
typedef struct ForwardedInMessage {
    unsigned char endpoint,source_stamp_le[4],unmodeled5[2],flags;
    unsigned char report[];
} ForwardedInMessage;
typedef struct OutCompletionMessage {
    unsigned char endpoint,sequence,status;
} OutCompletionMessage;
typedef struct EndpointHaltAck {
    unsigned char sequence,result;
} EndpointHaltAck;
typedef struct ControlReplyMessage {
    unsigned char unmodeled0,status,payload[];
} ControlReplyMessage;
typedef struct CloneLimitNotice {
    unsigned char reason,value_le[2],vendor_le[2],product_le[2];
} CloneLimitNotice;

/* Keep native address-symbol bindings for already reconstructed callers. */
unsigned int link_get_selected_and_fifo_rx_drops(void) __asm__("FUN_42022568");
void control_forward_pending_generation(void) __asm__("FUN_4203345c");
void usbd_read_last_unaligned_write(unsigned char *,unsigned int *,unsigned int *) __asm__("FUN_4203349c");
void device_receive_in_report(unsigned char *,unsigned short) __asm__("FUN_420335c8");
void device_receive_out_completion(unsigned char *,unsigned short) __asm__("FUN_4203374c");
void device_receive_halt_reply(unsigned char *,unsigned short) __asm__("FUN_42033b4c");
void input_flush_if_pending(void) __asm__("FUN_42033be4");
void device_relay_current_configuration(void) __asm__("FUN_42033bf4");
void device_receive_control_reply(unsigned char,unsigned char *,unsigned short) __asm__("FUN_42033e50");
void capture_forward_usb_bus_event(unsigned char,unsigned char,unsigned char) __asm__("FUN_42037c40");
unsigned int descriptor_service_patch_refresh(void) __asm__("FUN_42038780");
void device_receive_clone_limit(unsigned char *,unsigned short) __asm__("FUN_42039960");



/* Native VFS registry; the exported table registration keeps its existing
 * address-symbol binding used by the console/UART driver declarations. */
int esp_vfs_register_fs_common(const char *,unsigned int,const volatile VfsOperations *,int,void *,int *);
int esp_vfs_register_fs(const char *,const volatile VfsOperations *,int,void *) __asm__("FUN_42039cdc");
#define FUN_42039bd0 esp_vfs_register_fs_common
#define FUN_42039cdc esp_vfs_register_fs

/* Device worker startup: typed call boundaries and fixed-address resources.
 * The optimized RTOS creators ignore the supplied SDK queue-type argument. */
RtosQueue *rtos_create_mutex_type(unsigned char queue_type) __asm__("xQueueCreateMutex");
RtosQueue *rtos_create_queue_type(unsigned int capacity,
    unsigned int item_size,unsigned char queue_type) __asm__("xQueueGenericCreate");
void device_workers_init(void);
void transmit_watchdog_task_entry(void *argument) __asm__("transmit_watchdog_task");
void nonzero_control_task_entry(void *argument) __asm__("nonzero_control_task");

void clip_ring_init(ClipRing *ring,unsigned char *storage,
    unsigned int capacity,unsigned char *scratch);
#define REPORT_UNCOUNTED_RECEIVE_TYPES ((const unsigned char *)0x3c04814cU)
#define AUXILIARY_BINARY_SEMAPHORE (*(RtosQueue *volatile *)0x3fcc2c2cU)
#define TRANSMIT_WATCHDOG_TIMER (*(EspTimer *volatile *)0x3fcc4cd4U)
#define CLIP_ALLOCATION_STORAGE (*(unsigned char *volatile *)0x3fcc800cU)

/* TX maintenance wire records use byte arrays: memcpy supplies the unaligned
 * little-endian fields. The native 56-byte scratch is not bounds checked. */
typedef struct MediusTimingWireHeader {
    unsigned char valid,whole_us_le[4],fractional_ns_le[2];
} MediusTimingWireHeader;
typedef struct MediusTimingWireInterface {
    unsigned char endpoint,interval,whole_us_le[4],fractional_ns_le[2];
} MediusTimingWireInterface;
/* Dynamic bindings are 904 bytes apart, unlike the fixed 1000-byte bindings.
 * Only the input-state prefix and capture-valid byte are used by TX cleanup. */
typedef struct AuxiliaryInputBinding {
    InputStateView state;                       /* +0x000, size0x2f8 */
    unsigned char unmodeled2f8[2],capture_valid; /* +0x2fa */
    unsigned char unmodeled2fb[0x388-0x2fb];
} AuxiliaryInputBinding;
#define AUXILIARY_INPUTS ((volatile AuxiliaryInputBinding *)0x3fcc9de0U)
#define CAPTURE_SESSION_ACTIVE (*(const volatile unsigned char *)0x3fcc7b1eU)
#define DWC2_IN_ENDPOINT_INTERRUPT_MASK (*(volatile unsigned int *)0x60080810U)
#define DWC2_IN_ENDPOINT_INTERRUPT(endpoint) (*(volatile unsigned int *)(0x60080908U+(endpoint)*32U))
#define CLONE_ZERO_ALTERNATES ((const volatile unsigned char *)0x3c04804cU)
/* This call site prepares five words. The atomic implementation ignores the
 * remaining order/weak register values; do not fabricate a sixth input. */
unsigned int atomic_compare_exchange_byte_task(volatile unsigned char *address,
    unsigned char *expected,unsigned int desired,unsigned int ignored_success_order,
    unsigned int ignored_failure_order) __asm__("atomic_compare_exchange_byte");
int xTaskGenericNotifyWait(unsigned int index,unsigned int clear_bits_on_entry,
    unsigned int clear_bits_on_exit,unsigned int *notification_value,unsigned int ticks_to_wait);

/* UART control command output areas; the borrowed reply has no private lock. */
typedef struct ControlTransferReply {
    unsigned char endpoint,status;
    unsigned char data[504];
} ControlTransferReply;
#define CONTROL_TRANSFER_REPLY ((volatile ControlTransferReply *)0x3fcd6434U)
#define CONTROL_REWRITE_QUERY_BUFFER ((unsigned char *)0x3fcd6a40U)
#define CONTROL_PATCH_QUERY_BUFFER ((unsigned char *)0x3fcd6630U)
unsigned int locks_encode(unsigned char *output);
unsigned int capture_status_encode(unsigned char *output);
unsigned int clip_status_encode(unsigned char *output);

/* Wire constants; dispatcher arguments stay BYTES to retain unknown opcodes. */
typedef enum ControlCommandOpcode {
    CONTROL_COMMAND_MOVE=0x01,CONTROL_COMMAND_INJECT=0x03,
    CONTROL_COMMAND_RESET=0x04,CONTROL_COMMAND_QUERY=0x05,
    CONTROL_COMMAND_REBOOT=0x07,CONTROL_COMMAND_LED=0x09,
    CONTROL_COMMAND_LOCK=0x0a,CONTROL_COMMAND_CATCH=0x0b,
    CONTROL_COMMAND_OPTION=0x11,CONTROL_COMMAND_CLIP_APPEND=0x12,
    CONTROL_COMMAND_CLIP_CONTROL=0x13,CONTROL_COMMAND_CLIP_SETTING=0x14,
    CONTROL_COMMAND_CLIP_TRIGGER=0x15,CONTROL_COMMAND_UPDATE=0x17,
    CONTROL_COMMAND_RAW_ENDPOINT=0x19,CONTROL_COMMAND_TRANSFER=0x1a,
    CONTROL_COMMAND_REWRITE=0x1c,CONTROL_COMMAND_PATCH=0x1d,
    CONTROL_COMMAND_TRANSFORM=0x1e
} ControlCommandOpcode;
typedef enum ControlQuerySelector {
    CONTROL_QUERY_VERSION=0,CONTROL_QUERY_HEALTH=1,CONTROL_QUERY_DEVICE=2,
    CONTROL_QUERY_CAPABILITIES=3,CONTROL_QUERY_RATE=4,CONTROL_QUERY_STATISTICS=5,
    CONTROL_QUERY_LOCKS=6,CONTROL_QUERY_CATCH=7,CONTROL_QUERY_OPTIONS=9,
    CONTROL_QUERY_CLIP=10,CONTROL_QUERY_FIRMWARE=11,CONTROL_QUERY_REWRITE_SUMMARY=12,
    CONTROL_QUERY_REWRITE_ENTRY=13,CONTROL_QUERY_PATCHES=14,
    CONTROL_QUERY_PATCH_ENTRY=15,CONTROL_QUERY_TRANSFORMS=16
} ControlQuerySelector;
typedef enum ControlOptionId {
    CONTROL_OPTION_IMPERFECT=0,CONTROL_OPTION_MOVEMENT_RIDING=1,
    CONTROL_OPTION_EMISSION=2,CONTROL_OPTION_NAME=3,CONTROL_OPTION_BEARING=4,
    CONTROL_OPTION_RENDER=5,CONTROL_OPTION_SPREAD=6
} ControlOptionId;

/* Empty native entry views; original prototypes are not implied. */
void return_without_work_4038fa88(void);
#define FUN_4038fa88 return_without_work_4038fa88
void return_without_work_42020bdc(void);
#define FUN_42020bdc return_without_work_42020bdc
void return_without_work_42020c24(void);
#define FUN_42020c24 return_without_work_42020c24
void return_without_work_42020ca8(void);
#define FUN_42020ca8 return_without_work_42020ca8
void return_without_work_42020cc8(void);
#define FUN_42020cc8 return_without_work_42020cc8
void return_without_work_42020cd0(void);
#define FUN_42020cd0 return_without_work_42020cd0
void return_without_work_42020cd8(void);
#define FUN_42020cd8 return_without_work_42020cd8
void return_without_work_42020ce0(void);
#define FUN_42020ce0 return_without_work_42020ce0
void return_without_work_42020cf4(void);
#define FUN_42020cf4 return_without_work_42020cf4
void return_without_work_42020cfc(void);
#define FUN_42020cfc return_without_work_42020cfc
void return_without_work_42020d04(void);
#define FUN_42020d04 return_without_work_42020d04
void return_without_work_42020d0c(void);
#define FUN_42020d0c return_without_work_42020d0c
void return_without_work_42020d14(void);
#define FUN_42020d14 return_without_work_42020d14
void return_without_work_42020d1c(void);
#define FUN_42020d1c return_without_work_42020d1c
void return_without_work_42020d24(void);
#define FUN_42020d24 return_without_work_42020d24
void return_without_work_42020d2c(void);
#define FUN_42020d2c return_without_work_42020d2c
void return_without_work_42020d34(void);
#define FUN_42020d34 return_without_work_42020d34
void return_without_work_42020d3c(void);
#define FUN_42020d3c return_without_work_42020d3c
void return_without_work_42020d44(void);
#define FUN_42020d44 return_without_work_42020d44
void return_without_work_42020d4c(void);
#define FUN_42020d4c return_without_work_42020d4c
void return_without_work_42020d54(void);
#define FUN_42020d54 return_without_work_42020d54
void return_without_work_42020dec(void);
#define FUN_42020dec return_without_work_42020dec
void return_without_work_4203a6a0(void);
#define FUN_4203a6a0 return_without_work_4203a6a0

/* Fixed clone-configuration state. Native widths and separate publications are
 * intentional; these views neither reserve storage nor provide synchronization. */
#define USB_CLONE_SPEED (*(volatile unsigned char *)0x3fccbd48U)
#define USB_CLONE_STRING3 ((char *)0x3fcd0160U)
#define USB_CLONE_STRING4 ((char *)0x3fcd00e0U)
#define USB_CLONE_STRING5 ((char *)0x3fcd0060U)
#define USB_CLONE_SECTION13_LENGTH (*(volatile unsigned short *)0x3fccfa58U)
#define USB_CLONE_SECTION13_BYTES ((unsigned char *)0x3fccfa5cU)
#define USB_CLONE_SECTION14_LENGTH (*(volatile unsigned short *)0x3fccf644U)
#define USB_CLONE_SECTION14_BYTES ((unsigned char *)0x3fccf648U)
#define USB_CLONE_RAW_METADATA (*(MediusCloneRawMetadata *)0x3fccf444U)
#define USB_CLONE_PARSED_METADATA (*(MediusCloneParsedMetadata *)0x3fccf3f8U)
#define USB_CLONE_PATCH_VENDOR (*(volatile unsigned short *)0x3fcc9dceU)
#define USB_CLONE_PATCH_PRODUCT (*(volatile unsigned short *)0x3fcc9dccU)
#define USB_CLONE_PATCH_LOAD_BUFFER ((unsigned char *)0x3fcbe350U)
#define USB_CLONE_CACHED_PATCH (*(DescriptorPatchTable *)0x3fcc89dcU)
#define USB_CLONE_ACTIVE_PATCH (*(DescriptorPatchTable *)0x3fcc8534U)
#define USB_CLONE_EXTRA_DESCRIPTOR (*(MediusCloneExtraDescriptor *)0x3fcc27d0U)
#define USB_CLONE_EXTRA_DESCRIPTOR_POINTER (*(MediusCloneExtraDescriptor *volatile *)0x3fcaa7e4U)
#define USB_CLONE_DESCRIPTOR_TABLE ((void *)0x3fcaa7c4U)
#define USB_CLONE_GENERATION_SLOTS ((volatile unsigned int *)0x3fcc280cU)
#define USB_CLONE_RESTORE_VENDOR (*(volatile unsigned short *)0x3fcc9dd2U)
#define USB_CLONE_RESTORE_PRODUCT (*(volatile unsigned short *)0x3fcc9dd0U)
#define USB_CLONE_REPORT_PRIMARY ((unsigned char *)0x3fcaab48U)
#define USB_CLONE_REPORT_SECONDARY ((unsigned char *)0x3fcaabe8U)
#define USB_CLONE_REPORT_RESTORED (*(volatile unsigned char *)0x3fcaab89U)
#define USB_CLONE_RESTORED_FEATURE ((volatile unsigned char *)0x3fcaa918U)
#define USB_CLONE_ADVERTISED_INTERVAL (*(volatile unsigned char *)0x3fcc8059U)
#define USB_IN_ACTIVITY_TIMESTAMPS ((volatile TimestampWords *)0x3fcc0e38U)
#define USB_DWC2_DYNAMIC_FIFO_MODES ((volatile unsigned char *)0x3fcd85fcU)

int usbd_ep_close(unsigned char bus,unsigned char endpoint);

void USBD_IRQHandler(unsigned char bus);

/* Shared device lifecycle output slots and mutable word-aligned native defaults. */
#define USB_DEVICE_IRQ_HANDLE_SLOT ((InterruptHandle *volatile *)0x3fcd8604U)
#define USB_DEVICE_PHY_HANDLE_SLOT ((MediusUsbPhyHandle volatile *)0x3fcd8608U)
#define USB_DWC2_DEFAULT_PARAMETER_WORDS ((const volatile unsigned int *)0x3fcbcbf8U)
void medius_usb_device_irq_trampoline(void *argument);
void dwc2_get_user_params(unsigned int unused_base,unsigned char *parameters);

#define USB_EP0_TASK_STORAGE_AVAILABLE (*(volatile unsigned char *)0x3fcab515U)
void *usb_osal_thread_create(char *name,unsigned int stack_bytes,unsigned int priority,TaskEntry task_entry,void *argument);
void usb_osal_thread_delete(void *thread);

unsigned int bootloader_flash_execute_command_common(unsigned char command,unsigned int address_bits,unsigned int address,unsigned char dummy_bits,unsigned char mosi_bits,unsigned int mosi_data,unsigned char miso_bits);

/* Decoding borrows variable-record spans from the caller-owned scratch input. */
int clip_parse_entry(const unsigned char *bytes,unsigned int available,ClipDecodedEntry *decoded);
void clip_ring_peek(const ClipRing *ring,unsigned int length);
