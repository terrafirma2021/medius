/* Medius v3.4.7 host: recovered 32-bit Xtensa type declarations.
 * Unknown fields remain explicit; these declarations do not make the decompilation buildable.
 * Application SHA-256: 255b1f3595f398b867da4f205516c074c3d4abaa87f6b054b737641257f0fc15
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
    __asm__ volatile ("rsr.intenable %0" : "=a"(value));
    return value;
}

/* ESP32-S3 task-entry frame: 192 bytes, including non-coprocessor state
 * and window spill storage. Offsets match xtensa_context.h and ESP32-S3 tie.h.
 * The separately allocated coprocessor block contains FPU and vector/AI state.
 */
typedef void (*TaskEntry)(void *argument);

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
    void (*exit_dispatch)(void);           /* 0x00 */
    TaskEntry pc;                    /* 0x04 */
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
unsigned int *pxPortInitialiseStack(unsigned int *top,TaskEntry entry,void *argument);
bool xPortCheckValidTCBMem(void *pointer);
bool xPortcheckValidStackMem(void *pointer);


/* Tick hooks execute in the kernel tick ISR, up to eight callbacks per CPU.
 * Coprocessor owners are per CPU/CP slot; neither table is a timer buffer.
 */
typedef void (*MediusTickHook)(void);
typedef MediusTickHook MediusTickHookTable[2][8];
typedef XtensaCoprocessorHeader *XtensaCoprocessorOwners[2][4];
/* Flat native initialization view of the same two rows of four slots. */
#define XTENSA_COPROCESSOR_OWNER_SLOTS ((XtensaCoprocessorHeader * volatile *)0x3fc9e260U)
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
#define PTHREAD_KEY_REGISTRY_LOCK ((PortMuxWords *)0x3fc9dbacU)
#define PTHREAD_REGISTERED_KEYS (*(PthreadKeyEntry * volatile *)0x3fca77d8U)

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
extern const double __mprec_tens[25]; /* 0x3c0520c0 */
extern const double __mprec_bigtens[5]; /* 0x3c052098 */

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

typedef void (*TlsDeleteCallback)(int index,void *value);
#define NEWLIB_STARTUP_CONTEXT ((volatile NewlibReent *)0x3fc9e388U)
#define NEWLIB_GLOBAL_CONTEXT_POINTER (*(NewlibReent *volatile *)0x3fc9e384U)

/* Newlib multi-precision conversion calls use this image's 32-bit ABI. */
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
    unsigned int capabilities, const char *function_name);
#define HEAP_ALLOCATION_FAILURE_CALLBACK (*(HeapAllocationFailureCallback volatile *)0x3fca73b0U)
#define HEAP_INTERNAL_ALLOCATION_THRESHOLD (*(const volatile unsigned int *)0x3fc9da3cU)

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

/* Explicit WORD observations; the two software-dispatch classes share comparator2. */
typedef struct TimerDeadlineWords {
    volatile unsigned int low;
    volatile unsigned int high;
} TimerDeadlineWords;
#define ESP_TIMER_DEADLINES ((TimerDeadlineWords *)0x3fc9dbb8U)
#define ESP_TIMER_DEADLINE_LOCK ((PortMuxWords *)0x3fc9dbc8U)
#define ESP_TIMER_LISTS ((EspTimer *volatile *)0x3fccbbacU)
#define ESP_TIMER_LIST_LOCKS ((PortMuxWords *)0x3fc9e350U)
#define ESP_TIMER_DELETE_EVENT 0xf0de1e1eU
void esp_timer_impl_set_alarm_id(unsigned long long timestamp,unsigned int alarm_id);
void timer_insert(EspTimer *timer,int without_update_alarm);
void timer_remove(EspTimer *timer);
unsigned long long esp_timer_impl_get_min_period_us(void);


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
    void *thread_local_storage;            /* 0x054: one application TLS slot */
    TlsDeleteCallback tls_delete_callback; /* 0x058 */
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
    int mutex;                             /* newlib lock word; untouched by init */
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
    unsigned char unknown_14[4];
    unsigned char payload[512];

} LinkParser;

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

unsigned short crc16_update(unsigned short crc, const unsigned char *data,
                                    unsigned int length);
int link_frame_encode(unsigned char *output, unsigned int capacity,
                              unsigned char type, unsigned char flags,
                              const void *payload, unsigned short length);
int link_frame_patch_payload(unsigned char *frame, unsigned int frame_length,
                                     unsigned short payload_offset, const void *patch,
                                     unsigned short patch_length);
#define CRC16_TABLE ((const unsigned short *)0x3fca6434U)

typedef unsigned long long (*SystimerConvert)(unsigned long long value);

typedef struct {
     volatile unsigned int *dev;
    SystimerConvert ticks_to_us;
    SystimerConvert us_to_ticks;

} SystimerHal;

typedef struct {
     SystimerConvert ticks_to_us;
    SystimerConvert us_to_ticks;

} SystimerTickOps;
#define SYSTEM_TICK_HAL ((SystimerHal *)0x3fca76f8U)
#define SYSTEM_HANDLED_TICKS ((volatile unsigned int *)0x3fca7704U)
#define SYSTEM_TICK_CONVERSION_OPS ((const volatile SystimerTickOps *)0x3c0458f4U)
void SysTickIsrHandler(void *argument);
void esp_vApplicationTickHook(void);
int xTaskIncrementTick(void);
int xTaskIncrementTickOtherCores(void);
void systimer_hal_set_alarm_period(SystimerHal *hal, unsigned int alarm_id, unsigned int period_us);
void systimer_hal_set_alarm_target(SystimerHal *hal, unsigned int alarm_id, unsigned long long target_us);
void systimer_hal_counter_value_advance(SystimerHal *hal, unsigned int counter_id, long long delta_us);


typedef struct {
    union {
        unsigned short endpoint_slot;
        struct { unsigned char endpoint,slot; };
    };
    union {
        unsigned short sequence_generation;
        struct { unsigned char sequence,generation; };
    };
    unsigned int source_stamp;
    unsigned short length;
    unsigned char report_flag;
    unsigned char special;
    unsigned char special_prefix;
    unsigned char data[64];
    unsigned char padding[3];

} MediusHidWork;

typedef struct {
    union {
        unsigned short sequence_response;
        struct { unsigned char sequence,response_type; };
    };
    unsigned char kind;
    unsigned char setup[8];
    unsigned char padding;
    unsigned int generation;
    unsigned short out_length;
    unsigned char data[2048];
    unsigned char tail_padding[2];

} MediusControlWork;

typedef struct {
     unsigned int unknown0;
    void *channel;
    void *hubport;
    unsigned char *endpoint;
    unsigned char toggle;
    unsigned char unknown17[3];
    unsigned int interval_us;
    unsigned char *setup;
    unsigned char *buffer;
    unsigned int remaining;
    unsigned int scheduling_flags;
    unsigned int actual;
    unsigned int timeout;
    int error;
    unsigned int unknown52;
    unsigned int unknown56;
    void (*complete)(void *context, int result);
    void *context;

} MediusHostUrb;

typedef struct {
     unsigned char control_state;
    unsigned char unknown1;
    unsigned short initial_packets;
    unsigned int programmed_bytes;
    unsigned char number;
    unsigned char in_use;
    union {
        unsigned short split_phase;
        struct { unsigned char split_enabled,complete_split; };
    };
    union {
        unsigned short split_route;
        struct { unsigned char hub_address,hub_port; };
    };
    unsigned short split_frame;
    void *semaphore;
    MediusHostUrb *urb;
    unsigned int unknown24;
    unsigned char *bounce_destination;
    unsigned char retry_count;
    unsigned char keep_frame_parity;
    unsigned char cancelling;
    unsigned char unknown35;

} MediusHostChannel;

typedef MediusHostChannel MediusHostChannels[16];

/* DWC2 host register views. Offsets are relative to bus.register_base.
   HCCHAR/HCINT/HCTSIZ are separate volatile hardware snapshots. */
typedef struct {
    volatile unsigned int characteristics;
    volatile unsigned int split;
    volatile unsigned int interrupt_status;
    volatile unsigned int interrupt_mask;
    volatile unsigned int transfer_size;
    volatile unsigned int dma_address;
    unsigned char reserved24[8];
} MediusDwc2HostChannelRegisters;

typedef struct {
    volatile unsigned int otg_control;
    unsigned char reserved4[4];
    volatile unsigned int ahb_configuration;
    volatile unsigned int usb_configuration;
    volatile unsigned int reset_control;
    volatile unsigned int interrupt_status;
    volatile unsigned int interrupt_mask;
    unsigned char reserved1c[8];
    volatile unsigned int rx_fifo_size;
    volatile unsigned int nonperiodic_tx_fifo_size;
    unsigned char reserved2c[12];
    volatile unsigned int general_configuration;
    unsigned char reserved3c[4];
    volatile unsigned int core_id;
    volatile unsigned int hardware_configuration[4];
    unsigned char reserved54[172];
    volatile unsigned int periodic_tx_fifo_size;
    unsigned char reserved104[764];
    volatile unsigned int configuration;
    volatile unsigned int frame_interval;
    volatile unsigned int frame_number;
    unsigned char reserved40c[8];
    volatile unsigned int channel_interrupt_status;
    volatile unsigned int channel_interrupt_mask;
    unsigned char reserved41c[36];
    volatile unsigned int port;
    unsigned char reserved444[0x9bc];
    volatile unsigned int clock_control;
} MediusDwc2HostRegisters;

/* Native 64-byte user-parameter image copied from host flash 0x3c045bf4.
 * FIFO sizes are in 32-bit words. Padding is retained in the copied image. */
typedef struct {
    unsigned char phy_type,phy_utmi_width;
    unsigned char device_dma_enable,device_dma_desc_enable;
    unsigned short device_rx_fifo_words,device_tx_fifo_words[16];
    unsigned char host_dma_desc_enable,padding39;
    unsigned short host_rx_fifo_words,host_nonperiodic_tx_fifo_words;
    unsigned short host_periodic_tx_fifo_words,padding46;
    unsigned int device_general_configuration,host_general_configuration;
    unsigned char b_session_valid_override,padding57[3];
    unsigned int total_fifo_words;
} MediusDwc2Parameters;

typedef struct {
    int vp,vm,receive,suspend_n,output_enable_n,vp_out,vm_out,full_speed_edge;
} MediusUsbPhyExternalPins;
typedef struct {
    int iddig,avalid,vbusvalid,idpullup,dp_pulldown,dm_pulldown,drive_vbus;
    int bvalid,session_end,charge_vbus,discharge_vbus;
} MediusUsbPhyOtgPins;
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

/* Six native 32-bit PHY configuration fields, including two pointer fields. */
typedef struct {
    unsigned int controller,target,otg_mode,otg_speed;
    const MediusUsbPhyExternalPins *external_io_configuration;
    const MediusUsbPhyOtgPins *otg_io_configuration;
} MediusUsbPhyConfiguration;

/* HCD base 0x3fca7c24 + bus.controller_id * 668. Channels start at
   +0x5c and have 36-byte stride. The native IRQ uses the raw hardware
   count (up to31), without a local sixteen-channel bounds check. */
typedef struct {
    unsigned char connect_changed;
    unsigned char enable_changed;
    unsigned char overcurrent_changed;
    unsigned char reserved3;
    unsigned int core_id,device_endpoint_directions;
    unsigned int hardware_capabilities;
    unsigned int transfer_limit_bits,fifo_capabilities;
    unsigned short hardware_features,padding26;
    union {
        MediusDwc2Parameters parameters;
        struct {
            unsigned char keep_clock_configuration;
            unsigned char reserved29[39];
            unsigned short rx_fifo_words,nonperiodic_tx_fifo_words,periodic_tx_fifo_words;
            unsigned char reserved74[18];
        };
    };
} MediusDwc2HostContextPrefix;


typedef struct {
     void *interface_handle;
    unsigned char endpoint;
    unsigned char generation;
    union {
        struct { unsigned char slot,interface_number; };
        unsigned short slot_and_interface;
    };
    unsigned short max_packet;
    unsigned short transfer_length;
    unsigned short poll_period;
    unsigned char descriptor_interval;
    unsigned char active;
    unsigned char armed;
    unsigned char needs_rearm;
    unsigned char in_callback;
    unsigned char halted;
    unsigned char special_retry;
    unsigned char special_valid;
    unsigned char special_length;
    unsigned char unknown23;
    union { unsigned int special_counter,suppressed_since_us; };
    unsigned int last_special_us;
    unsigned char paused;
    unsigned char unknown33[7];
    union { unsigned int unknown40,rearm_after_us_low; };
    union { unsigned int unknown44,rearm_after_us_high; };
    unsigned short poll_phase;
    unsigned char unknown50[6];
    unsigned char report_sequence;
    unsigned char credit_sequence_base;
    unsigned char retained_credit_count;
    unsigned char retained_credit_valid;
    unsigned char credit_progress_sequence;
    unsigned char credit_limit;
    unsigned char unknown62[2];
    long long credit_reference_us;
    long long boost_started_us;
    long long boost_duration_us;
    int history_window_us;
    union { unsigned char credit_flag92,history_protection_active; };
    union { unsigned char credit_sequence93,protection_base_sequence; };
    unsigned char unknown94[2];
    long long report_history[8];
    unsigned char credit_blocked;
    unsigned char unknown161;
    unsigned short last_report_frame;
    unsigned short last_callback_frame;
    unsigned short scheduled_frame;
    unsigned short slow_poll_frame;
    unsigned short participation_frame;
    unsigned char unknown172[4];

} MediusHidEndpointState;

typedef MediusHidEndpointState MediusHidEndpointStates[6];

typedef struct ControlAssembly {
     unsigned char payload[2058];
    unsigned short total;
    union {
        struct {
            unsigned short used;
            union {
                struct { unsigned char active,error; };
                unsigned short flags;
            };
        };
        unsigned int progress_flags;
    };

} ControlAssembly;

/* Little-endian512-byte stack fragment; native stores word then halfword. */
typedef struct {
    union {
        struct { unsigned short total,offset; };
        unsigned int total_and_offset;
    };
    unsigned short count;
    unsigned char data[506];
} ControlFragmentFrame;

typedef void (*FragmentCallback)(const unsigned char *fragment, unsigned short length, void *context);

typedef struct {
     unsigned char request_type;
    unsigned char request;
    unsigned short value;
    unsigned short index;
    unsigned short length;

} MediusUsbSetup;

typedef struct {
     union {
        unsigned char unknown0[4];
        struct { unsigned char descriptor_length,descriptor_type,interface_number,alternate_setting; };
    };
    unsigned char endpoint_count;
    unsigned char unknown5[7];
    unsigned char *endpoints;

} MediusHostAlternatePrefix;

typedef struct {
    union { unsigned char unknown0[16]; unsigned char name[16]; };
    void *class_driver;
    void *private_data;
    MediusHostAlternatePrefix *alternates;
    unsigned char alternate_count;
    unsigned char unknown29[3];

} MediusHostInterfacePrefix;

typedef struct {
     unsigned char connected;
    unsigned char is_root;
    union {
        unsigned char unknown2[686];
        struct { unsigned char index,device_address,unknown4[684]; };
    };
    void *upstream_port;

} MediusHostHubPrefix;

typedef void (*MediusHostEventHandler)(unsigned int bus, unsigned int hub, unsigned int port,
                                        unsigned int interface_index, unsigned int event);

typedef struct {
     void *next;
    unsigned char id;
    unsigned char padding5[3];
    unsigned int register_base;
    unsigned char controller_id;
    union {
        unsigned char unknown13[779];
        struct { unsigned char reserved13[7],root_speed,reserved21[771]; };
    };
    unsigned char last_address;
    unsigned char unknown793[3];
    unsigned int address_bitmap[4];
    void *hub_task;
    void *hub_queue;
    void *hub_shutdown_semaphore;
    MediusHostEventHandler event;

} MediusHostBusPrefix;

typedef struct {
     unsigned char connected;
    unsigned char port_number;
    unsigned char device_address;
    unsigned char speed;
    unsigned char depth;
    unsigned char unknown5[2];
    unsigned char device_descriptor[18];
    unsigned char unknown25[3];
    unsigned char configuration_header[4];
    unsigned char descriptor_interface_count;
    unsigned char configuration_value;
    unsigned char unknown34[6];
    MediusHostInterfacePrefix *interfaces;
    unsigned short interface_count;
    unsigned char unknown46[2];
    void *descriptor_storage;
    unsigned char unknown52[12];
    unsigned char *raw_configuration;
    unsigned char *setup;
    MediusHostHubPrefix *parent;
    unsigned char unknown76[4];
    MediusHostBusPrefix *bus_context;
    unsigned char ep0_descriptor[8];
    MediusHostUrb control_urb;
    void *control_mutex;

} MediusHostHubPortPrefix;

typedef MediusHostHubPortPrefix *MediusHostHubPortPointer;

typedef int (*MediusHostClassDisconnect)(MediusHostHubPortPrefix *port,
                                         unsigned char interface_index);
/* First three class-driver words only; connect is not interpreted here. */
typedef struct {
    const char *name;
    void *connect;
    MediusHostClassDisconnect disconnect;      /* 0x08 */
} MediusHostDisconnectDriverView;

typedef int (*MediusHostClassConnect)(MediusHostHubPortPrefix *port,
                                     unsigned char interface_index);
/* Connect consumer reads only the first two driver words. */
typedef struct {
    const char *name;
    MediusHostClassConnect connect;
} MediusHostConnectDriverView;

typedef struct {
    unsigned short vendor;
    unsigned short product;
} MediusHostDeviceIdPair;

typedef struct {
    unsigned char flags;
    unsigned char interface_class;
    unsigned char interface_subclass;
    unsigned char interface_protocol;
    unsigned char interface_number;
    unsigned char uninterpreted5[3];
    const MediusHostDeviceIdPair *ids;
    const MediusHostConnectDriverView *driver;
} MediusHostClassMatchEntry;

/* Eight-byte interface-descriptor prefix inside a 16-byte alternate object. */
typedef struct {
    unsigned char length;
    unsigned char descriptor_type;
    unsigned char interface_number;
    unsigned char alternate_setting;
    unsigned char endpoint_count;
    unsigned char interface_class;
    unsigned char interface_subclass;
    unsigned char interface_protocol;
} MediusHostAlternateClassView;



typedef unsigned char MediusHostControlByte;

typedef unsigned int MediusHostControlWord;

/* Native12-byte ordered record; overflow moves all three words. */
typedef union {
    struct {
        unsigned int generation;
        union {
            struct { unsigned char command,arg1; };
            unsigned short command_and_arg1;
        };
        unsigned char arg2,reserved7;
        short ack_tag;
        unsigned short reserved10;
    };
    unsigned int words[3];
} MediusOrderedChange;

typedef MediusOrderedChange MediusOrderedChangeRing[8];

typedef unsigned short MediusHostControlHalf;

typedef struct {
     unsigned char state;
    unsigned char requested_suspend;
    unsigned char desired_remote_wakeup;
    unsigned char applied_remote_wakeup;
    unsigned char preexisting_pause;

} MediusHostPowerStateView;

typedef int MediusHostControlInt;

typedef unsigned short MediusHidReportLengths[256];

typedef unsigned char MediusHidAlternateSelections[256];

typedef unsigned short MediusHidCacheLengths[6];

typedef unsigned char MediusHidCachedReports[6][64];

typedef long long MediusHostFrameSigned64;

typedef struct {
     long long base_ns;
    long long period_ns;
    unsigned int nominal_ticks_per_ms;
    unsigned int interval_ticks_minus_one;
    unsigned short frame;
    unsigned char unknown_padding[6];

} MediusHostFrameClockSnapshot;

typedef unsigned char MediusCreditPendingPacket[64];

typedef struct {
     unsigned char *descriptor;
    MediusHostUrb urb;
    union {
        struct { unsigned char endpoint,transfer_type; };
        unsigned short endpoint_type;
    };
    unsigned short transfer_length;
    union {
        struct { unsigned char interface_slot,endpoint_slot; };
        unsigned short interface_endpoint_slots;
    };
    unsigned char armed;
    unsigned char queued_report_pending;
    unsigned char stall_pending;
    unsigned char special_retry;
    unsigned short special_sequence;
    unsigned int special_time_us;
    union { unsigned char rearm_inhibit88, submission_inhibited; };
    union { unsigned char rearm_inhibit89, callback_rearm_inhibited; };
    unsigned char activity;
    unsigned char unknown91[5];
    unsigned char report_sequence;
    unsigned char credit_sequence_base;
    unsigned char retained_credit_count;
    unsigned char retained_credit_valid;
    unsigned char credit_progress_sequence;
    unsigned char credit_limit;
    unsigned char unknown102[2];
    long long credit_reference_us;
    long long boost_started_us;
    long long boost_duration_us;
    int history_window_us;
    union { unsigned char credit_flag132, history_protection_active; };
    union { unsigned char credit_sequence133, protection_base_sequence; };
    unsigned char unknown134[2];
    long long report_history[8];
    unsigned char credit_blocked;
    unsigned char unknown201;
    unsigned short last_report_frame;
    unsigned char unknown204[4];

} MediusVendorEndpointState;

typedef struct {
     void *hubport;
    unsigned char interface_number;
    unsigned char endpoint_count;
    unsigned char active;
    unsigned char mode;
    MediusVendorEndpointState endpoints[12];

} MediusVendorInterface;

typedef MediusVendorInterface MediusVendorInterfaceTable[12];

typedef unsigned char MediusVendorTransferSlots[16][64];

typedef struct {
    union {
        struct { unsigned char endpoint, transfer_type; };
        unsigned short endpoint_type; /* One native halfword snapshot. */
    };
    unsigned char flags;
    unsigned char unknown3;
    union {
        unsigned short sequence;
        struct { unsigned char sequence_low, sequence_high; };
    };
    unsigned char unknown6[2];
    union {
        unsigned int timestamp_us;
        unsigned short timestamp_halves[2];
        unsigned char timestamp_bytes[4];
    };
    unsigned short length;
    unsigned char payload[64];
    unsigned char unknown78[2];

} MediusVendorReport;

typedef MediusVendorReport MediusVendorReportCache[16];

typedef unsigned char MediusVendorDirectPacket[70];

typedef unsigned char MediusVendorTaskPacket[72];

typedef void *MediusVendorQueueHandle;

typedef struct {
     unsigned char report_sequence;
    unsigned char credit_sequence_base;
    unsigned char retained_credit_count;
    unsigned char retained_credit_valid;
    unsigned char credit_progress_sequence;
    unsigned char credit_limit;
    unsigned char unknown6[2];
    long long credit_reference_us;
    long long boost_started_us;
    long long boost_duration_us;
    int history_window_us;
    union { unsigned char credit_flag132,history_protection_active; };
    union { unsigned char credit_sequence133,protection_base_sequence; };
    unsigned char unknown38[2];
    long long report_history[8];

} MediusVendorSavedCredit;

typedef MediusVendorSavedCredit MediusVendorSavedCreditTable[16];

typedef unsigned char MediusVendorSavedTypes[16];

typedef unsigned char MediusVendorAlternateSelections[256];

typedef struct {
     unsigned int generation;
    union {
        struct { unsigned char sequence,length; };
        unsigned short sequence_length; /* native OR-packed HALF store at+4 */
    };
    unsigned char payload[64];
    unsigned char unknown70[2];

} MediusOutRelayPacket;

typedef struct {
     void *hubport;
    unsigned char *descriptor;
    MediusHostUrb urb;
    MediusOutRelayPacket packets[4];
    union {
        struct { unsigned char head,count; };
        unsigned short head_count; /* native paired head/count store at+364 */
    };
    unsigned char endpoint;
    unsigned char last_ack;
    union {
        struct { unsigned char nak_retry,error_retry; };
        unsigned short retry_counts; /* native retry reset at+368 */
    };
    unsigned char active;
    unsigned char halted;
    union { unsigned char inhibit372,submission_inhibited; };
    unsigned char completion_pending;
    unsigned char unknown374[2];
    int completion_result;
    unsigned char unknown380[4];
    long long retry_at_us;

} MediusOutRelayState;

typedef MediusOutRelayState MediusOutRelayTable[10];

typedef struct {
     unsigned char endpoint;
    unsigned char sequence;
    unsigned char status;

} MediusOutRelayAck;

typedef unsigned char MediusOutDmaSlots[10][64];

typedef void (*MediusUsbTimerCallback)(void *argument);

typedef struct {
     MediusUsbTimerCallback handler;
    void *argument;
    unsigned char periodic;
    unsigned char padding9[3];
    unsigned int milliseconds;
    EspTimer *timer;

} MediusUsbOsalTimer;

typedef struct {
     MediusUsbTimerCallback callback;
    void *argument;
    unsigned int dispatch;
    const char *name;
    unsigned char skip_unhandled_events;
    unsigned char padding17[3];

} EspTimerCreateArgs;

typedef unsigned int MediusHubSlotBitmap;

typedef struct {
     unsigned char connected;
    unsigned char is_root;
    unsigned char index;
    unsigned char device_address;
    unsigned char speed;
    unsigned char port_count;
    unsigned char power_on_delay_ms;
    unsigned char tt_think_time;
    unsigned char multi_tt;
    unsigned char hub_descriptor[9];
    unsigned char superspeed_descriptor[11];
    unsigned char padding29[3];
    MediusHostHubPortPrefix ports[4];
    MediusHostHubPortPrefix *upstream_port;
    MediusHostBusPrefix *bus;
    unsigned char *interrupt_endpoint;
    MediusHostUrb interrupt_urb;
    unsigned char *interrupt_buffer;
    MediusUsbOsalTimer *interrupt_timer;

} MediusHostHubState;

/* Borrowed four-byte GET_STATUS result; the worker explicitly reloads halves. */
typedef struct {
    volatile unsigned short status;
    volatile unsigned short changes;
} MediusHostHubPortStatus;


typedef struct {
     void *allocation;
    MediusHostHubPortPrefix *owner;

} MediusRetiredDescriptor;

typedef MediusRetiredDescriptor MediusRetiredDescriptors[8];

typedef unsigned char MediusRetiredCount;

typedef void *MediusHostListHead;

/* Native setup slots have four-byte-aligned bases and eight-byte strides. */
typedef unsigned char MediusHostSetupPool[64] __attribute__((aligned(4)));

/* Native scratch slots have four-byte-aligned bases and 2048-byte strides. */
typedef unsigned char MediusHostDescriptorScratch[2048] __attribute__((aligned(4)));

typedef struct {
     MediusHostHubPortPrefix *port;
    unsigned char *in_endpoint;
    unsigned char *out_endpoint;
    MediusHostUrb in_urb;
    MediusHostUrb out_urb;
    unsigned short report_length;
    unsigned char protocol;
    unsigned char interface_index;
    unsigned char minor;
    unsigned char unknown153[7];

} MediusHostHidClass;

typedef MediusHostHidClass MediusHostHidClasses[6];

typedef unsigned int MediusHostHidClassMask;

typedef unsigned char MediusHidDescriptorScratch[2048];

typedef unsigned char MediusHidDescriptorBlob[6144];

/* Native shared packet address is four-byte aligned. */
typedef unsigned char MediusHidDescriptorPacket[264] __attribute__((aligned(4)));

typedef struct MediusHidDescriptorArchive {
     unsigned char *data;
    unsigned short capacity;
    unsigned short used;

} MediusHidDescriptorArchive;

/* Four wire bytes; native readers access length_high before length_low. */
typedef struct {
    unsigned char configuration;
    unsigned char interface_id;
    unsigned char length_low;
    unsigned char length_high;
} MediusHidArchiveRecordHeader;


/* Shared pre-capture view at 0x3fcaff00. Other snapshot fields are opaque here. */
typedef struct {
    unsigned int timestamp_ms;                 /* 0x00 */
    unsigned short saved_product;              /* 0x04 */
    unsigned short saved_vendor;               /* 0x06 */
    unsigned char visited;                     /* 0x08 */
    unsigned char requested;                   /* 0x09 */
    unsigned char phase;                       /* 0x0a */
    unsigned char uninterpreted0b;
    unsigned short current_product;            /* 0x0c */
    unsigned short current_vendor;             /* 0x0e */
    void *wake;                                /* 0x10 */
    unsigned char other_snapshot_fields14[9];
    unsigned char selector;                    /* 0x1d */
    unsigned char padding1e[2];
} MediusConfigurationCaptureState;


/* Five archive-header bytes; language is accessed in separate native byte order. */
typedef struct {
    unsigned char index;
    unsigned char language_low;
    unsigned char language_high;
    unsigned char status;
    unsigned char payload_length;
} MediusStringArchiveRecordHeader;

typedef struct MediusStringCaptureBudget {
     unsigned int start_low;
    unsigned int start_high;
    unsigned char timeout_count;

} MediusStringCaptureBudget;

typedef unsigned char MediusStringDescriptorScratch[256];

typedef unsigned char MediusStringDescriptorArchive[1536];

/* Seven wire bytes, accessed as native word/halfword/byte stores. The eighth
 * byte is C alignment padding, never part of the header or commit marker. */
typedef struct {
    volatile unsigned int section_total_offset_low;
    volatile unsigned short offset_high_count_low;
    volatile unsigned char count_high;
} MediusSnapshotSectionHeader;

/* Two native word stores; bytes encode configuration/interface/total and
 * offset/count in little endian. Configuration/interface inputs remain uint32. */
typedef struct {
    volatile unsigned int configuration_interface_total;
    volatile unsigned int offset_count;
} MediusHidDescriptorFrameHeader;

/* Native shared packet address is four-byte aligned. */
typedef unsigned char MediusSnapshotSectionPacket[519] __attribute__((aligned(4)));

/* Seven diagnostic wire bytes; the final C padding byte is not transmitted. */
typedef struct {
    volatile unsigned int reason_detail_vendor_low;
    volatile unsigned short vendor_high_product_low;
    volatile unsigned char product_high;
} MediusEnumerationLimitPacket;

/* ESP-IDF5.4 application description; pinned DROM object is256 bytes.
 * Field offsets and total size match esp_app_desc.h and the image metadata. */
typedef struct {
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
#define APP_ELF_SHA_CACHE ((volatile AppElfShaCache *)0x3fca7170U)
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
#define FUN_42002048 app_format_elf_sha256
#define FUN_42002090 __esp_system_init_fn_init_show_app_info
#define FUN_42002150 __esp_system_init_fn_init_efuse_check
#define FUN_42002160 __esp_system_init_fn_init_efuse_show_app_info
#define FUN_420021f4 esp_efuse_check_errors
#define FUN_4201e750 esp_efuse_utility_check_errors
#define FUN_42002258 __esp_system_init_fn_init_show_cpu_freq
#define FUN_420022a0 __esp_system_init_fn_init_brownout
#define FUN_420022ac __esp_system_init_fn_init_newlib_time
#define FUN_420022b8 __esp_system_init_fn_init_apb_dma


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

typedef char MediusFirmwareLabel[32];

/* Native fixed storage supplies 4-byte alignment. */
typedef unsigned char MediusCloneMetadataBuffer[512] __attribute__((aligned(4)));

/* Native fixed storage supplies 4-byte alignment. */
typedef unsigned char MediusCloneMetadataSource[68] __attribute__((aligned(4)));

/* Native fixed storage supplies 2-byte alignment. */
typedef unsigned char MediusCloneSection15Data[3] __attribute__((aligned(2)));

typedef struct {
     void *stack_base;
    void *register_base;
    unsigned int offset;

} MediusXtensaVaList;

int medius_format_bounded_context(NewlibReent *,char *,unsigned int,
                                 const char *,MediusXtensaVaList);

/* ESP-IDF interrupt allocator objects in this 32-bit Xtensa build.
 * Packed words retain the verified native bitfield layout without Ghidra C
 * bitfield INSERT artifacts. Vector source starts at byte4; a shared node
 * packs disabled/source into its first word. Sizes and pointers are 32-bit ABI.
 */
typedef void (*InterruptHandler)(void *argument);
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
                                           bits17..31 reserved. Decode source with
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
    int flags[2];
} CpuInterruptTableEntry;                 /* 16 bytes */

typedef struct CpuInterruptDescription {
    int priority;                         /* fixed Xtensa interrupt level */
    int type;                             /* level=0, edge=1, NA=-1 */
    int flags;                            /* special=1, reserved=2 */
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

/* Contiguous native interrupt state; flags retain their raw byte values. */
typedef struct InterruptAllocatorState {
    volatile unsigned char non_iram_disabled[2];
    unsigned char padding_2[2];
    volatile unsigned int saved_non_iram_enabled[2];
    volatile unsigned int non_iram_mask[2];
    InterruptVector *volatile vector_head;
} InterruptAllocatorState;
typedef struct RtcInterruptState {
    PortMuxWords lock;
    RtcIsrHandler *volatile handlers;
    volatile int owner_cpu;
    volatile unsigned int saved_enables;
    volatile unsigned int cache_safe_mask;
} RtcInterruptState;
#define INTERRUPT_ALLOCATOR_STATE ((InterruptAllocatorState *)0x3fca73b8U)
#define INTERRUPT_ALLOCATOR_LOCK ((PortMuxWords *)0x3fc9da4cU)
#define RTC_INTERRUPT_STATE ((RtcInterruptState *)0x3fc9e604U)
#define RTC_ISR_HANDLE (*(InterruptHandle *volatile *)0x3fca73fcU)
#define CPU_ISR_TABLE ((volatile CpuIsrEntry (*)[2])0x3fc9de60U)
#define CPU_INTERRUPT_DESCRIPTIONS ((const CpuInterruptTableEntry *)0x3c0456c8U)
#define CPU_INTERRUPT_LEVELS ((const unsigned char *)0x3c0519c0U)
#define INTERRUPT_SOURCE_NAMES ((const char *const *)0x3c05104cU)
#define INTERRUPT_ALLOCATION_FAILURE_FORMAT ((const char *)0x3c041034U)
void shared_intr_isr(void *argument);
int esp_intr_disable(InterruptHandle *handle);
void esp_intr_noniram_disable(void);
void esp_intr_noniram_enable(void);
unsigned int xt_ints_on(unsigned int mask);
void rtc_isr(void *argument);
void rtc_isr_noniram_disable(unsigned int cpu);
void rtc_isr_noniram_enable(unsigned int cpu);
void xt_unhandled_interrupt(void *argument);
void esp_crosscore_int_send(int cpu, unsigned int reason_mask);
void esp_crosscore_int_send_yield(int cpu);
void esp_crosscore_int_send_print_backtrace(int cpu);
void esp_crosscore_int_send_twdt_abort(int cpu);
int is_vect_desc_usable(InterruptVector *vector, int flags, int cpu, int forced_number);
InterruptVector *get_desc_for_int(int interrupt_number, int cpu);
int esp_intr_alloc_intrstatus(int source, int flags, unsigned int status_reg,
    unsigned int status_mask, InterruptHandler handler, void *argument, InterruptHandle **result);
void intr_free_for_current_cpu(InterruptHandle *handle);
void intr_free_for_other_cpu(void *argument);
void esp_cpu_intr_get_desc(int cpu, int interrupt_number, CpuInterruptDescription *description);
int esp_intr_get_cpu(InterruptHandle *handle);
int xt_int_has_handler(int interrupt_number, int cpu);
InterruptHandler xt_set_interrupt_handler(unsigned int interrupt_number, InterruptHandler handler, void *argument);
void xthal_set_intclear(unsigned int mask);
int esp_ipc_call_blocking(unsigned int cpu, IpcCallback callback, void *argument);

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
void _frxt_setup_switch(void);
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

#define FUN_403811f4 prvCopyDataToQueue
#define FUN_4038127c prvNotifyQueueSetContainer
#define FUN_40381728 xQueueGiveFromISR

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
unsigned int uxQueueMessagesWaitingFromISR(const RtosQueue *queue);
void vQueueDelete(RtosQueue *queue);
void vPortFree(void *buffer);
#define FUN_40381610 xQueueCreateMutexStatic
#define FUN_40381670 xQueueGenericSendFromISR
#define FUN_40381a78 xQueueReceiveFromISR
#define FUN_40381b18 uxQueueMessagesWaitingFromISR
#define FUN_40381b30 vQueueDelete
int xQueueGenericReset(RtosQueue *queue, int new_queue);
unsigned int uxQueueMessagesWaiting(RtosQueue *queue);
void vListInitialise(RtosList *list);
void *pvPortMalloc(unsigned int size);
void *heap_caps_malloc(unsigned int size, unsigned int caps);
void heap_caps_free(void *buffer);
void *heap_caps_malloc_default(unsigned int size);
void *heap_caps_realloc_default(void *buffer, unsigned int size);
unsigned int heap_caps_get_largest_free_block(unsigned int caps);
void release_buffer_malloc(void *unused, void *buffer);
void *get_buffer_malloc(void *unused, unsigned int requested_size,
                        unsigned int *actual_size);
#define MALLOC_CAP_8BIT 0x004U
#define MALLOC_CAP_INTERNAL 0x800U
#define PORTMUX_FREE_OWNER 0xb33fffffU
#define FUN_403812e0 xQueueGenericReset
#define FUN_40381374 xQueueGenericCreateStatic
int xTaskGetSchedulerState(void);
void vTaskInternalSetTimeOutState(RtosTimeout *timeout);
int xTaskCheckForTimeOut(RtosTimeout *timeout, unsigned int *ticks_remaining);
void vTaskPlaceOnEventList(RtosList *event_list, unsigned int ticks_to_wait);
void esp_crosscore_int_send_yield(int core_id);
unsigned int _xtos_set_intlevel(int interrupt_level);
#define RTOS_SCHEDULER_RUNNING (*(volatile unsigned int *)0x3fca7440U)
#define RTOS_SCHEDULER_SUSPEND_COUNTS ((volatile unsigned int *)0x3fca7418U)
typedef unsigned int MediusInterruptNesting[2];
/* ESP32-S3 RTC controller: enable, masked status and write-one-to-clear. */
#define RTC_INT_ENA (*(volatile unsigned int *)0x60008040U)
#define RTC_INT_ST  (*(volatile unsigned int *)0x60008048U)
#define RTC_INT_CLR (*(volatile unsigned int *)0x6000804cU)

#include <stdbool.h>
/* Five raw bytes. Flag fields contribute bit0; noncanonical bytes are not normalized. */
typedef struct BrownoutConfig {
    unsigned char threshold;             /* 0x00: three-bit analog threshold code */
    unsigned char enabled;               /* 0x01 */
    unsigned char reset_enabled;         /* 0x02: hardware-reset enable */
    unsigned char flash_power_down;      /* 0x03 */
    unsigned char rf_power_down;         /* 0x04 */
} BrownoutConfig;
typedef unsigned int ResetReason;
#define CACHED_RESET_REASON (*(volatile ResetReason *)0x3fca719cU)
void brownout_hal_config(const BrownoutConfig *configuration);
void esp_brownout_init(void);
int rtc_isr_register(InterruptHandler handler, void *argument, unsigned int mask, unsigned int flags);
void esp_reset_reason_init(void);
void rtc_brownout_isr_handler(void *) __attribute__((noreturn));

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
 * sl_count[19:14], sl_log2[22:20], small_block_size[30:23]; bit31 unused.
 * Store as one word to retain the native extraction/masking operations clearly.
 */
typedef bool (*TlsfWalker)(void *payload, unsigned int size, int used, void *user);

/* Native host descriptor archives, probe caches and reused capture-frame views. */
typedef struct {
    unsigned char anomaly_available;           /* 0x3fcace08 */
    unsigned char reserved1[3];
    unsigned char endpoint_anomaly[3];
    unsigned char selected_index;
    unsigned char archived_count;
    unsigned char reserved9;
    unsigned short additional_length;
    unsigned short base_length;
    unsigned char reserved14[2];
    unsigned char base[2048];
} MediusHostCapturedConfigurations;

typedef struct {
    unsigned short length;                    /* 0x3fcad618 */
    unsigned char reserved2[2];
    unsigned char descriptor[18];
    unsigned char reserved22[2];
} MediusHostCapturedDevice;

typedef struct {
    unsigned char reserved0[17];              /* 0x3fca96d0 */
    unsigned char quirk_next;
    unsigned char quirk_count;
    unsigned char reserved19;
    unsigned char quirk_codes[4];
    unsigned int quirk_keys[4];
    unsigned int retry_key;
    unsigned char exclusion_next;
    unsigned char exclusion_count;
    unsigned char reserved46[2];
    unsigned int exclusion_keys[8];
} MediusHostControlProbeCache;

/* Exactly ten native DROM bytes per row, at0x3c045c54. */
typedef struct {
    unsigned char destination;
    unsigned char request_type;
    unsigned char request;
    unsigned char reserved3;
    unsigned short value;
    unsigned short length;
    unsigned char skip_when_primary_three;
    unsigned char padding_expected_length;
} MediusHostControlProbeRow;

/* Native frame reuses these48 bytes for temporary string IDs, qualifier
   bytes and, after the configuration scan, up to16 HID interface IDs. */
typedef union {
    unsigned int alignment[12];
    unsigned char string_ids[48];
    unsigned char qualifier[10];
    unsigned char hid_interfaces[16];
} MediusHostCaptureScratch;

/* A second48-byte native slot holds merged string IDs, then the full32-bit
   transfer result written by probe helpers. */
typedef union {
    unsigned int words[12];
    unsigned char string_ids[48];
    int transfer_result;
} MediusHostCaptureResults;

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
    unsigned int reserved08[23];
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
#define CACHE_AUTOLOAD_STATE (*(volatile CacheHalRawAutoloadState *)0x3fca729cU)
#define CACHE_HAL_CONTEXT (*(volatile CacheHalContext *)0x3fca729cU)
#define CACHE_DATA_AUTOLOAD_CONTROL MMIO32(0x600c404cU)
#define CACHE_INSTRUCTION_AUTOLOAD_CONTROL MMIO32(0x600c40a0U)
void s_cache_hal_init_ctx(void);
void cache_hal_init(void);
#define FUN_403840e0 s_cache_hal_init_ctx
#define FUN_4038411c cache_hal_init

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
#define BOOT_BSS_START ((void *)0x3fca7170U)
#define BOOT_BSS_LENGTH 0x24bc0U
#define BOOT_PROTECTION_DEFAULTS ((const BootMemoryProtectionConfiguration *)0x3c045384U)
#define BOOT_TIMESTAMP (*(volatile BootTimestamp *)0x3fca71b8U)
#define BOOT_CORE1_CONTROL MMIO32(0x600c0000U)
void firmware_entry(void);
void esp_chip_info(BootChipInfo *information);
void mspi_timing_flash_tuning(void);
/* Linked dependency boundaries; their own bodies retain separate review state. */
void esp_rtc_init(void);
#define FUN_42002438 esp_rtc_init
void esp_clk_init(void);
#define FUN_4200246c esp_clk_init
void esp_perip_clk_init(void);
#define FUN_42002570 esp_perip_clk_init
void esp_deep_sleep_wakeup_io_reset(void);
int esp_mprot_is_conf_locked_any(unsigned char *locked);
int esp_mprot_set_prot(const BootMemoryProtectionConfiguration *configuration);
const char *esp_err_to_name(int error) __asm__("FUN_42003930");
int rtc_get_reset_reason(int core); /* ROM4000057c */
void flash_update_rom_chip_id(void);
unsigned int Cache_Suspend_DCache(void);
void Cache_Resume_DCache(unsigned int autoload); /* ROM400018c0 */
void Cache_Resume_ICache(unsigned int autoload); /* ROM400018a8 */
void rom_config_instruction_cache_mode(unsigned int size,unsigned char ways,unsigned char line_size);
void rom_config_data_cache_mode(unsigned int size,unsigned char ways,unsigned char line_size);
void Cache_Set_IDROM_MMU_Size(unsigned int instruction_bytes,unsigned int data_bytes);
void Cache_Set_IDROM_MMU_Info(unsigned int instruction_entries,unsigned int data_entries,
    unsigned int rodata_start,unsigned int rodata_end,int instruction_psram_offset,int rodata_psram_offset);
void uart_tx_wait_idle(unsigned char uart);
unsigned long long medius_boot_unsigned_divide(unsigned long long numerator,
    unsigned long long denominator) __asm__("__udivdi3");
#define FUN_42005114 esp_chip_info
#define FUN_4037fca0 mspi_timing_flash_tuning

/* Address-name compatibility for existing recovered callers. */
#define FUN_403841a8 cache_hal_disable
#define FUN_403841d0 cache_hal_enable
#define FUN_4037534c do_multicore_settings

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

#define CPU_STARTUP_FLAGS (*(volatile CpuStartupFlags *)0x3fca7190U)
#define SYSTEM_STARTUP_FUNCTIONS ((const SystemStartupFunction *)0x3c0453c8U)
#define ROM_PUTC1_CACHE (*(RomPutc volatile *)0x3fc9da30U)

/* Address-name compatibility for existing recovered startup callers. */
#define FUN_403752a4 call_start_cpu1
#define FUN_42011940 bootloader_init_mem
#define FUN_403811c0 esp_rom_install_uart_printf
#define FUN_420027d8 esp_cache_err_int_init
#define FUN_42013b38 esp_cpu_configure_region_protection

/* ESP32-S3 MPU permissions; RO/WO variants are not compiled for this target. */
typedef enum MpuAccess {
    MPU_REGION_ILLEGAL = 0,
    MPU_REGION_RW = 1,
    MPU_REGION_X = 2,
    MPU_REGION_RWX = 3
} MpuAccess;
void mpu_hal_set_region_access(int region, MpuAccess access);

#define ILLEGAL_MPU_REGIONS ((const unsigned int *)0x3c051848U)

#define FUN_4201ebf8 mpu_hal_set_region_access

typedef int (*SystemInitFunction)(void);
typedef struct SystemInitEntry {
    SystemInitFunction function;
    unsigned short core_mask;
    unsigned short stage;
} SystemInitEntry;
void do_system_init_fn(unsigned int stage);
int system_init_stage_zero_noop(void) __asm__("FUN_4201e740");
int system_init_stage_one_noop(void) __asm__("FUN_4201e7b4");
void xt_highint4(void) __asm__("FUN_40375854");
void start_cpu_other_cores_default(void) __attribute__((noreturn));
void esp_startup_start_app_other_cores(void);

#define SYSTEM_INIT_ENTRIES ((const volatile SystemInitEntry *)0x3c0526f4U)
#define SYSTEM_CORE_INITIALIZED ((volatile unsigned char *)0x3fca71b4U)
#define SYSTEM_FULL_INITIALIZED (*(volatile unsigned char *)0x3fca71b1U)
#define SYSTEM_EARLY_LOG_LEVEL (*(volatile unsigned int *)0x3fc9da38U)

/* Native address aliases, including the resolved startup weak alias. */
#define FUN_42002fd8 do_system_init_fn
#define FUN_40375bec start_cpu_other_cores_default
#define start_cpu_other_cores start_cpu_other_cores_default
#define FUN_42023a8c esp_startup_start_app_other_cores

typedef void (*FreertosTickHook)(void);
typedef unsigned int CrosscoreReasonMask;
void esp_int_wdt_cpu_init(void);
void esp_crosscore_int_init(void);
int esp_register_freertos_tick_hook_for_cpu(FreertosTickHook hook, unsigned int core);
void esp_int_wdt_tick_hook(void);
void esp_crosscore_isr(void *reason_word);

#define SCHEDULER_RUNNING ((volatile unsigned int *)0x3fca76f0U)
#define CROSSCORE_REASONS ((volatile CrosscoreReasonMask *)0x3fccbb80U)
#define CROSSCORE_REASON_LOCK ((PortMuxWords *)0x3fc9e324U)

/* Native address aliases; the app-start alias was defined above. */
#define FUN_4200294c esp_int_wdt_cpu_init
#define FUN_42012c50 esp_crosscore_int_init
#define FUN_40375b6c esp_int_wdt_tick_hook
#define FUN_420038a4 esp_register_freertos_tick_hook_for_cpu
#define FUN_4037d2b0 esp_crosscore_isr

/* ROM watchdog HAL ABI: instance word followed by a register pointer.
 * Register blocks are opaque here; these callbacks delegate access to ROM. */
typedef enum {
    WDT_RWDT = 0,
    WDT_MWDT0 = 1,
    WDT_MWDT1 = 2
} WatchdogInstance;
typedef enum {
    WDT_STAGE0 = 0,
    WDT_STAGE1 = 1,
    WDT_STAGE2 = 2,
    WDT_STAGE3 = 3
} WatchdogStage;
typedef enum {
    WDT_STAGE_ACTION_OFF = 0,
    WDT_STAGE_ACTION_INT = 1,
    WDT_STAGE_ACTION_RESET_CPU = 2,
    WDT_STAGE_ACTION_RESET_SYSTEM = 3,
    WDT_STAGE_ACTION_RESET_RTC = 4
} WatchdogStageAction;
typedef struct TimerGroupRegisters TimerGroupRegisters;
typedef struct RtcWatchdogRegisters RtcWatchdogRegisters;
typedef struct {
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
void task_wdt_timeout_abort(bool current_core_received_timeout);

#define INTERRUPT_WATCHDOG_CPU1_TICKED (*(volatile unsigned char *)0x3fca71a0U)
#define INTERRUPT_WATCHDOG_CONTEXT ((WatchdogHalContext *)0x3fca71a4U)
#define FREERTOS_TICK_HOOKS (*(volatile FreertosTickHookTable *)0x3fca721cU)
#define CPU_INTERRUPT_FROM_CPU ((volatile unsigned int *)0x600c0030U)

/* Identified direct dependencies; their own body reviews follow separately. */
#define FUN_40375ef4 esp_backtrace_print
#define FUN_42012e48 task_wdt_timeout_abort

typedef void (*ApbBackupLockCallback)(void);
void apb_backup_dma_lock(void);
void apb_backup_dma_unlock(void);
void esp_apb_backup_dma_lock_init(void);
void ets_apb_backup_init_lock_func(ApbBackupLockCallback lock,
    ApbBackupLockCallback unlock);

#define APB_BACKUP_DMA_MUX (*(PortMuxWords *)0x3fc9da00U)

#define FUN_40375b48 apb_backup_dma_unlock
#define FUN_40375b58 apb_backup_dma_lock
#define FUN_42002894 esp_apb_backup_dma_lock_init

void start_cpu0_default(void);
void startup_resume_other_cores(void);
void esp_startup_start_app(void);

#define GLOBAL_CONSTRUCTORS ((SystemStartupFunction const *)0x3c0526b8U)

#define FUN_42003044 start_cpu0_default
#define FUN_42002314 startup_resume_other_cores
#define FUN_42023a40 esp_startup_start_app

/* Register prefixes used by watchdog startup; unrelated words are unmodeled. */
typedef struct SystemClockRegistersPrefix {
    unsigned int unmodeled_00[6];
    unsigned int peripheral_clock_enable0; /* +0x18 */
    unsigned int unmodeled_1c;
    unsigned int peripheral_reset_enable0; /* +0x20 */
} SystemClockRegistersPrefix;
typedef struct {
    unsigned int reserved0[18];
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

#define FUN_420028a8 esp_int_wdt_init

typedef bool (*FreertosIdleHook)(void);
typedef FreertosIdleHook FreertosIdleHookSlots[8];
typedef FreertosIdleHookSlots FreertosIdleHookTable[2];
bool other_cpu_startup_idle_hook_cb(void);
int esp_register_freertos_idle_hook_for_cpu(FreertosIdleHook hook,
    unsigned int core);
void esp_deregister_freertos_idle_hook_for_cpu(FreertosIdleHook hook,
    unsigned int core);

#define OTHER_CPU_STARTUP_DONE (*(volatile unsigned char *)0x3fca7414U)
#define FREERTOS_IDLE_HOOKS (*(volatile FreertosIdleHookTable *)0x3fca725cU)
/* Idle and tick registries share this same mux. */
#define FREERTOS_HOOKS_LOCK ((PortMuxWords *)0x3fc9da28U)

#define FUN_42023974 other_cpu_startup_idle_hook_cb
#define FUN_42003850 esp_register_freertos_idle_hook_for_cpu
#define FUN_420038f8 esp_deregister_freertos_idle_hook_for_cpu

/* ESP-IDF task-watchdog configuration copied as three native words.
 * The explicit tail bytes retain this firmware's initialized padding. */
typedef struct TaskWatchdogConfig {
    unsigned int timeout_ms;       /* +0x00 */
    unsigned int idle_core_mask;   /* +0x04 */
    bool trigger_panic;            /* +0x08 */
    unsigned char reserved9[3];    /* +0x09: all zero in the startup template */
} TaskWatchdogConfig;
void main_task(void *argument);
void heap_caps_enable_nonos_stack_heaps(void);
int esp_task_wdt_init(const TaskWatchdogConfig *configuration);

#define FUN_42003c8c heap_caps_enable_nonos_stack_heaps

MultiHeap *multi_heap_register(void *start, unsigned int bytes);
void multi_heap_set_lock(MultiHeap *heap, void *lock);

#define REGISTERED_HEAPS (*(RegisteredHeapPointer *)0x3fca73b4U)

void heap_caps_alloc_failed(unsigned int size, unsigned int caps, const char *function_name);
void *heap_caps_aligned_alloc_base(unsigned int alignment, unsigned int size, unsigned int caps);
void *heap_caps_malloc_base(unsigned int size, unsigned int caps);
void *heap_caps_realloc_base(void *buffer, unsigned int size, unsigned int caps);
void *heap_caps_calloc_base(unsigned int count, unsigned int size, unsigned int caps);
void esp_heap_adjust_alignment_to_hw(unsigned int *alignment, unsigned int *size, unsigned int *caps);
void multi_heap_assert_valid_block(const MultiHeap *heap, const TlsfBlock *block);
void *multi_heap_aligned_alloc_offs(MultiHeap *heap, unsigned int size, unsigned int alignment, unsigned int offset);
void multi_heap_free(MultiHeap *heap, void *buffer);
unsigned int multi_heap_get_allocated_size(MultiHeap *heap, void *buffer);
void *multi_heap_realloc(MultiHeap *heap, void *buffer, unsigned int size);
void heap_caps_get_info(MultiHeapInfo *information, unsigned int capabilities);
void multi_heap_get_info(MultiHeap *heap, MultiHeapInfo *information);
bool multi_heap_get_info_tlsf(void *unused_payload, unsigned int size, int used, void *user);
void *tlsf_get_pool(TlsfControl *control);
unsigned int tlsf_size(TlsfControl *control);
unsigned int tlsf_alloc_overhead(void);
unsigned int tlsf_block_size(const void *buffer);
void *tlsf_malloc(TlsfControl *control, unsigned int size);
void *tlsf_memalign_offs(TlsfControl *control, unsigned int alignment, unsigned int size, unsigned int offset);
void tlsf_free(TlsfControl *control, void *buffer);
void *tlsf_realloc(TlsfControl *control, void *buffer, unsigned int size);
void tlsf_walk_pool(void *pool, TlsfWalker walker, void *user);
unsigned int tlsf_fit_size(TlsfControl *control, unsigned int size);
TlsfControl *tlsf_create_with_pool(void *memory, unsigned int bytes, unsigned int maximum_bytes);
bool tlsf_default_walker(void *payload, unsigned int size, int used, void *user);
void *tlsf_add_pool(TlsfControl *control, void *memory, unsigned int bytes);
TlsfControl *tlsf_create(void *memory, unsigned int maximum_bytes);

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
    unsigned char reserved14[2];            /* +0x0e: zero from calloc */
} TaskWatchdogState;

int esp_task_wdt_impl_timer_allocate(const TaskWatchdogConfig *configuration,
                                   TaskWatchdogIsr callback,
                                   TaskWatchdogTimerContext *context_out);
int esp_task_wdt_impl_timer_restart(TaskWatchdogTimerContext context);
void task_wdt_isr(void *argument);
void subscribe_idle(unsigned int core_mask);

#define TASK_WATCHDOG_STATE (*(TaskWatchdogState **)0x3fccbb88U)

typedef struct TaskWatchdogHardwareContext {
    WatchdogHalContext hal;        /* +0x00: 8-byte timer-group HAL context */
    InterruptHandle *interrupt_handle; /* +0x08: esp_intr_alloc output */
} TaskWatchdogHardwareContext;

RtosTask *xTaskGetIdleTaskHandleForCore(int core);
int esp_task_wdt_add(RtosTask *task);
bool task_wdt_idle_hook_cb(void);

#define FUN_42012f40 subscribe_idle
#define FUN_420134d8 esp_task_wdt_impl_timer_restart
#define FUN_4201314c task_wdt_idle_hook_cb

int esp_intr_alloc(int source, int flags, InterruptHandler callback,
                   void *argument, InterruptHandle **handle_out);

#define TASK_WATCHDOG_HARDWARE_CONTEXT ((TaskWatchdogHardwareContext *)0x3fccbb90U)
#define WATCHDOG_SYSTEM_CLOCK_ENABLE (*(volatile unsigned int *)0x600c0018U)
#define WATCHDOG_SYSTEM_RESET (*(volatile unsigned int *)0x600c0020U)
#define TIMER_GROUP0_WATCHDOG_CONFIGURATION0 (*(volatile unsigned int *)0x6001f048U)
#define FUN_420133c8 esp_task_wdt_impl_timer_allocate

int esp_task_wdt_reset(void);
int esp_task_wdt_impl_timer_feed(TaskWatchdogTimerContext context);
void esp_task_wdt_impl_timeout_triggered(TaskWatchdogTimerContext context);
void wdt_hal_handle_intr(WatchdogHalContext *context);

#define FUN_42013490 esp_task_wdt_impl_timer_feed
#define FUN_420134b8 esp_task_wdt_impl_timeout_triggered

/* Subscription node. Byte storage preserves the native flag representation. */
struct TaskWatchdogEntry {
    TaskWatchdogEntry *next;       /* +0x00 */
    RtosTask *task;           /* +0x04: NULL for a user subscription */
    const char *user_name;          /* +0x08: NULL for a task subscription */
    unsigned char has_reset;       /* +0x0c: normal values are 0 and 1 */
    unsigned char reserved13[3];   /* +0x0d: zeroed on allocation */
};

int task_wdt_add_entry(bool is_task, void *entry_data,
                          TaskWatchdogEntry **entry_out);
int xPortEnterCriticalTimeout(PortMuxWords *lock, int timeout_cycles);
void vPortExitCritical(PortMuxWords *lock);

/* Newlib lock slots contain a 32-bit FreeRTOS mutex handle. Retargetable
 * locking passes the handle by value and takes a local slot when needed. */
struct __lock;
typedef struct __lock *NewlibLock;
#define MEDIUS_NEWLIB_INIT_LOCK ((PortMuxWords *)0x3fc9db08U)
#define MEDIUS_NEWLIB_COMMON_MUTEX ((NewlibLock)0x3fca7760U)
#define MEDIUS_NEWLIB_COMMON_RECURSIVE_MUTEX ((NewlibLock)0x3fca770cU)
#define MEDIUS_NEWLIB_ROM_MUTEX_MAGIC 0xbb10c433U
RtosTask *xQueueGetMutexHolder(RtosQueue *queue);
int xQueueGiveMutexRecursive(RtosQueue *mutex);
int xQueueTakeMutexRecursive(RtosQueue *mutex,unsigned int wait_ticks);
int lock_acquire_generic(NewlibLock *lock,unsigned int wait_ticks,unsigned int mutex_type);
void lock_release_generic(NewlibLock *lock,unsigned int mutex_type);
void _lock_close(NewlibLock *lock);
void _lock_acquire(NewlibLock *lock);
void _lock_acquire_recursive(NewlibLock *lock);
void _lock_release(NewlibLock *lock);
void _lock_release_recursive(NewlibLock *lock);
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
/* Word-oriented entry aliases for caller bodies awaiting typed review. */
#define FUN_40376a1c lock_release_generic
#define FUN_40376a70 _lock_close
#define FUN_40376b30 __retarget_lock_init
#define FUN_40376b58 __retarget_lock_init_recursive
#define FUN_40376b80 __retarget_lock_close
#define FUN_40376b90 __retarget_lock_close_recursive
#define FUN_40376ba0 __retarget_lock_acquire
#define FUN_40376bcc __retarget_lock_acquire_recursive
#define FUN_40376bf8 __retarget_lock_try_acquire
#define FUN_40376c28 __retarget_lock_try_acquire_recursive
#define FUN_40376c58 __retarget_lock_release
#define FUN_40376c78 __retarget_lock_release_recursive
#define FUN_4038142c xQueueGetMutexHolder
void vPortTCBPreDeleteHook(RtosTask *task);
/* Retained architectural entry points; yield returns when its task resumes. */
void vPortYield(void);
void vPortYieldFromInt(void);
bool esp_ptr_executable(const void *pointer);
bool esp_ptr_byte_accessible(const void *pointer);
void _xt_coproc_release(XtensaCoprocessorHeader *header, int target_core);
void abort(void) __attribute__((noreturn));
int ets_printf(const char *format, ...);
#define PORT_TLS_DIAGNOSTIC_GATE (*(volatile unsigned int *)0x3fc9da38U)
bool esp_cpu_compare_and_set(volatile unsigned int *address,
                             unsigned int expected, unsigned int desired);
void vTaskPrioritySet(RtosTask *task, unsigned int priority);
void vTaskGenericNotifyGiveFromISR(RtosTask *task, unsigned int index,
                                    int *higher_priority_task_woken);
int xTaskGenericNotify(RtosTask *task, unsigned int index,
                        unsigned int value, unsigned int action,
                        unsigned int *previous_value);
/* Per-CPU arrays; these do not belong to an individual portMUX. */
#define PORT_CRITICAL_NESTING ((volatile unsigned int *)0x3fca76e0U)
#define PORT_SAVED_PS ((volatile unsigned int *)0x3fca76d8U)
#define PORT_INTERRUPT_NESTING ((volatile unsigned int *)0x3fca76e8U)
RtosTask *xTaskGetCurrentTaskHandle(void);


#define TASK_WATCHDOG_LOCK (*(PortMuxWords *)0x3fc9e32cU)
#define TASK_WATCHDOG_DIAGNOSTICS (*(unsigned int *)0x3fc9da38U)

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
#define FUN_40381d8c vPortYieldOtherCore
#define FUN_40381d98 vApplicationStackOverflowHook
#define FUN_40384044 vTaskGetSnapshot
#define FUN_40384074 xTimerCreateTimerTask
void esp_reset_reason_set_hint(unsigned int hint);
void xt_unhandled_exception(XtensaExceptionFrame *frame);

#define TASK_WATCHDOG_ISR_ACTIVE (*(unsigned char *)0x3fccbb8cU)

/* Optional watchdog reporting sink: each call supplies one text fragment. */
typedef void (*TaskWatchdogMessageHandler)(void *opaque, const char *message);
char *pcTaskGetName(RtosTask *task);
int xTaskGetCoreID(RtosTask *task);
int esp_task_wdt_print_triggered_tasks(TaskWatchdogMessageHandler handler,
                                      void *opaque, int *failed_core_mask);
#define FUN_42013158 esp_task_wdt_print_triggered_tasks
#define FUN_40382ca8 pcTaskGetName

/* Partial ESP32-S3 UART MMIO view through CLK_CONF; intervening unused words
 * remain in place so the accessed fields retain their hardware offsets. */
typedef struct UartRegisterView {
    volatile unsigned int fifo;               /* +0x00 */
    volatile unsigned int interrupt_raw;      /* +0x04 */
    volatile unsigned int interrupt_status;   /* +0x08 */
    volatile unsigned int interrupt_enable;   /* +0x0c */
    volatile unsigned int interrupt_clear;    /* +0x10: write-one-to-clear */
    volatile unsigned int clkdiv;             /* +0x14: integer bits0..11, fraction20..23 */
    volatile unsigned int rx_filt;             /* +0x18: RX pulse filter */
    volatile unsigned int status;             /* +0x1c */
    volatile unsigned int conf0;              /* +0x20 */
    volatile unsigned int conf1;              /* +0x24: FIFO thresholds, RX timeout enable */
    unsigned int unused_28[8];
    volatile unsigned int idle_conf;          /* +0x48: TX idle count */
    volatile unsigned int rs485_conf;         /* +0x4c */
    unsigned int unused_50[4];
    volatile unsigned int mem_conf;           /* +0x60: RX timeout threshold and FIFO sizes */
    unsigned int unused_64[2];
    volatile unsigned int fsm_status;         /* +0x6c: RX bits0..3, TX bits4..7 */
    unsigned int unused_70[2];
    volatile unsigned int clk_conf;           /* +0x78: source/coarse divider */
} UartRegisterView;

#define LINK_UART1 ((UartRegisterView *)0x60010000U)
#define LINK_RX_PARSER ((LinkParser *)0x3fccb7f0U)
#define LINK_TX_LOCK (*(PortMuxWords *)0x3fc9de34U)
#define LINK_TX_INITIAL_FIFO_LIMIT (*(volatile unsigned int *)0x3fc9de30U)
#define LINK_TX_COMPLETION_SEMAPHORE (*(RtosQueue *volatile *)0x3fccba24U)
#define LINK_TX_REMAINING_BYTES (*(volatile unsigned short *)0x3fccba28U)
#define LINK_TX_CURSOR (*(const unsigned char *volatile *)0x3fccba2cU)
#define LINK_RX_FIFO_OVERFLOW_COUNT (*(volatile unsigned int *)0x3fccba40U)
#define LINK_LOG_TAG ((const char *)0x3fca69ecU)
#define UART_FIFO_CAPACITY 128U
#define UART_FIFO_COUNT_MASK 0x3ffU
#define UART_RX_FULL_IRQ 0x001U
#define UART_TX_EMPTY_IRQ 0x002U
#define UART_RX_ERROR_IRQS 0x00cU
#define UART_RX_OVERFLOW_IRQ 0x010U
#define UART_RX_TIMEOUT_IRQ 0x100U
#define UART_TX_DONE_IRQ 0x4000U
#define UART_RX_FIFO_RESET 0x20000U

void link_uart_interrupt_handler(void *argument);
void link_uart_transmit_wait(unsigned char *frame, unsigned int frame_length);
long long esp_timer_get_time(void);
unsigned int esp_log_timestamp(void);
void esp_log_write(unsigned int level, const char *tag, const char *format, ...);

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

int uart_param_config(unsigned int uart_number,const UartConfig *configuration);
int uart_set_pin(int uart, int tx, int rx, int rts, int cts);
int xTaskCreatePinnedToCore(TaskEntry entry, char *name,
                             unsigned int stack_bytes, void *argument,
                             unsigned int priority, RtosTask **created_task,
                             int core_id);


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
#define LINK_TX_MUTEX_HANDLES (*(volatile LinkTxHandleSlots *)0x3fccba08U)
#define LINK_TX_QUEUE_HANDLES (*(volatile LinkTxHandleSlots *)0x3fccb7e4U)
#define LINK_TX_TASK_HANDLE (*(RtosTask *volatile *)0x3fccb7e0U)
#define LINK_RX_TASK_HANDLE (*(RtosTask *volatile *)0x3fccba34U)
#define LINK_UART_IRQ_HANDLE (*(void *volatile *)0x3fccba30U)
/* uart_periph_signal[1].irq; native code reads this byte, not a literal 28. */
#define UART1_INTERRUPT_SOURCE (*(const unsigned char *)0x3c0512c0U)


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
    unsigned char unused_01[3];
    unsigned int uncounted_types[8];               /* +0x04: one bit per opcode */
    unsigned char direct_type;                    /* +0x24: also accounting-exempt */
    unsigned char unused_25[3];
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
    unsigned short unused_06;
    unsigned int received_at_us_low;             /* +0x08: only types 2/0x25 timed */
    unsigned char counted;                       /* +0x0c: nonzero decrements pending */
    unsigned char unused_0d[3];
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
#define LINK_RX_POLICY (*(volatile LinkRxPolicy *)0x3fca3e04U)
#define LINK_RX_DESCRIPTORS ((volatile LinkRxDescriptor *)0x3fca3e34U)
#define LINK_RX_PAYLOAD ((unsigned char *)0x3fca4434U)
#define LINK_RX_CURSOR_STATE (*(volatile LinkRxCursors *)0x3fccba4cU)
#define LINK_RX_COUNTED_PENDING (*(volatile unsigned int *)0x3fccba3cU)
#define LINK_RX_SELECTED_TYPE_DROPS (*(volatile unsigned int *)0x3fccba48U)
#define LINK_RX_OTHER_TYPE_DROPS (*(volatile unsigned int *)0x3fccba44U)
#define LINK_LAST_DIRECT_RX_US (*(volatile unsigned int *)0x3fccba20U)
#define LINK_RX_OPTIONAL_QUEUE (*(RtosQueue *volatile *)0x3fccba38U)
#define LINK_RX_QUEUE_SCRATCH ((LinkRxQueueItem *)0x3fccac68U)
#define LINK_RX_COUNT_LOCK (*(PortMuxWords *)0x3fc9de3cU)
unsigned int ulTaskGenericNotifyTake(unsigned int index, int clear_count_on_exit,
                                     unsigned int ticks_to_wait);

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
int uart_set_baudrate(unsigned int uart_number, unsigned int baud);
unsigned int link_frame_enqueue(int type, unsigned char flags,
    void *payload, unsigned int length, unsigned int wait_ticks, char suppress_drop_log);
#define LINK_TX_FAST_PENDING (*(volatile unsigned char *)0x3fccb1b0U)
#define LINK_TX_FAST_HANDLER (*(LinkFastTxHandler volatile *)0x3fccb1b4U)
#define LINK_TX_ADMISSION_CONTEXT (*(volatile unsigned int *)0x3fccb1b8U)
#define LINK_TX_ADMISSION (*(LinkTxAdmissionHandler volatile *)0x3fccb1bcU)
#define LINK_TX_QUEUE_SCRATCH ((LinkTxQueueItem *)0x3fccacccU)
#define LINK_TX_FAST_FRAME ((LinkFastTxFrame *)0x3fccaed8U)
#define LINK_BAUD_PROBE_INHIBIT (*(volatile unsigned char *)0x3fccba1cU)
#define LINK_BAUD_TABLE ((const unsigned int *)0x3c05261cU)

/* Link routing interfaces; old address aliases retain existing call sites. */
void link_configure_receive(unsigned char direct_type,
    LinkRxDirectHandler handler, const unsigned char *uncounted_types,
    unsigned char count);
#define FUN_42021598 link_configure_receive
void medius_link_set_tx_admission(LinkTxAdmissionHandler handler,
                                   unsigned int context);
#define FUN_42021790 medius_link_set_tx_admission
void medius_link_set_baud_probe_inhibit(unsigned char inhibit);
#define FUN_420217a0 medius_link_set_baud_probe_inhibit

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

#define MEDIUS_CREDIT_PENDING_PACKET ((volatile CreditPacket *)0x3fc9ffa8U)
#define MEDIUS_CREDIT_PENDING_LENGTH (*(volatile unsigned short *)0x3fc9ffa4U)
#define CREDIT_LOCK (*(PortMuxWords *)0x3fc9ddb0U)
#define MEDIUS_CREDIT_TASK (*(RtosTask *volatile *)0x3fca9728U)
int medius_credit_receive(unsigned int unused_flags, const unsigned char *payload,
    unsigned int length, int unused_has_counted_pending);

/* Split clock storage retains native32 access order and deliberately avoids
 * pretending that a pair is an atomic64 load/store. */
typedef struct ClockWords {
    unsigned int low,high;
} ClockWords;
typedef void (*ClockAlarmHandler)(void *argument);
#define CLOCK_TIME_LOCK ((NewlibLock *)0x3fca77b4U)
#define CLOCK_ADJUST_START ((volatile ClockWords *)0x3fca77c0U)
#define CLOCK_ADJUST_REMAINING ((volatile ClockWords *)0x3fca77b8U)
#define CLOCK_BOOT_LOCK ((NewlibLock *)0x3fca77c8U)
#define CLOCK_MICROSECONDS_OFFSET ((volatile ClockWords *)0x3fca77d0U)
#define CLOCK_SYSTEM_CORRECTION ((volatile ClockWords *)0x3fca77e0U)
#define CLOCK_HAL ((SystimerHal *)0x3fca77e8U)
#define CLOCK_ALARM_HANDLER ((ClockAlarmHandler volatile *)0x3fca77f4U)
#define CLOCK_TICK_COUNT ((volatile unsigned int *)0x3fca7448U)
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
/* Native address aliases retain raw caller word boundaries pending review. */
clock_t FUN_40376cc4(unsigned int reentrancy,void *times) __asm__("_times_r");
int FUN_40376d0c(unsigned int reentrancy,void *time) __asm__("_gettimeofday_r");
void FUN_40376d80(unsigned int argument) __asm__("timer_alarm_isr");
unsigned long long FUN_420071ec(void) __asm__("adjust_boot_time");
unsigned long long FUN_4200734c(void) __asm__("esp_time_impl_get_time_since_boot");
void FUN_42007368(unsigned int low,unsigned int high) __asm__("esp_time_impl_set_boot_time");
unsigned long long FUN_42007390(void) __asm__("esp_time_impl_get_boot_time");

/* Endpoint bytes are loaded individually; descriptor alignment is not assumed. */
typedef struct MediusHostEndpointDescriptor {
    unsigned char length,type,address,attributes,max_packet[2],interval;
} MediusHostEndpointDescriptor;
#define MEDIUS_HOST_BUSES ((volatile MediusHostBusPrefix *)0x3fca7f0cU)
#define MEDIUS_HOST_DRIVER_LOCK (*(PortMuxWords *)0x3fc9dda8U)
unsigned int medius_usbh_critical_enter(void);
void medius_usbh_critical_exit(unsigned int ignored_token);
void dwc2_host_channel_configure(MediusHostBusPrefix *bus,unsigned int channel,
    unsigned int device_address,unsigned int endpoint,unsigned int type,
    unsigned int max_packet,unsigned char multiplier,unsigned char speed);
void dwc2_host_start_noncontrol(MediusHostBusPrefix *bus,unsigned int channel,
    MediusHostUrb *urb,unsigned char *buffer,unsigned int length);
int medius_dwc2_host_suspend(unsigned char bus);
void medius_dwc2_host_resume_control(unsigned char bus,unsigned char signal_resume);
unsigned int medius_dwc2_host_port_raw(unsigned char bus);
void medius_dwc2_host_clock_gate(MediusHostBusPrefix *bus,int gated);

#define MEDIUS_HOST_IN_BOUNCE_BASE ((unsigned char *)0x3fc9f23cU)
#define MEDIUS_HOST_CONTROL_STATUS_BUFFER ((unsigned char *)0x3fc9f63cU)
#define MEDIUS_HOST_CONTROL_STATUS_ACTUAL (*(volatile unsigned int *)0x3fca7c20U)
int medius_usbh_rearm_in_with_alignment(MediusHostBusPrefix *bus,unsigned int channel,
    MediusHostChannel *state,MediusHostUrb *urb);
void medius_usbh_account_and_rearm_in(MediusHostBusPrefix *bus,unsigned int channel,
    MediusHostChannel *state,MediusHostUrb *urb);
void medius_usbh_complete_urb(MediusHostUrb *urb);
void medius_usbh_copy_received(unsigned char *destination,unsigned char *source,unsigned int length);
int usb_osal_sem_give(void *semaphore);
void dwc2_host_start_control(MediusHostBusPrefix *bus,unsigned int channel,
    MediusHostUrb *urb,unsigned char *setup,unsigned char *buffer,unsigned int length);
unsigned int dwc2_calc_frame_interval(MediusHostBusPrefix *bus);
void medius_usb_host_irq_trampoline(void *argument);
void USBH_IRQHandler(unsigned int bus);
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
#define MEDIUS_USB_PHY_CONTROLLER (*(MediusUsbPhyController *volatile *)0x3fccbb1cU)
#define MEDIUS_USB_PHY_LOCK (*(PortMuxWords *)0x3fc9de54U)
#define MEDIUS_USB_PHY_SIGNALS ((const volatile MediusUsbPhySignalTable *)0x3c0512d8U)
#define MEDIUS_USB_PHY_RTC_SELECTION (*(volatile unsigned int *)0x60008120U)
#define USB_SERIAL_JTAG_CONFIGURATION (*(volatile unsigned int *)0x60038018U)
#define MEDIUS_USB_WRAP_CLOCK_ENABLE (*(volatile unsigned int *)0x600c0018U)
#define MEDIUS_USB_WRAP_RESET_ENABLE (*(volatile unsigned int *)0x600c0020U)
#define GPIO_CONFIGURATION_LOCK (*(PortMuxWords *)0x3fc9e28cU)
/* Source reconstruction utility for the three native shifted GPIO masks.
 * The native signed rejection plus six-bit mask aliases positive pins>=64;
 * preserving that behavior is deliberate, rather than adding a range check. */
static __inline__ int gpio_native_pin_valid(unsigned int pin)
{
    unsigned int index = pin & 63U;
    return (pin & 0x80000000U) == 0 && (index <= 21U || (index >= 26U && index <= 48U));
}
#define FUN_4200f6c0 phy_configure_pin_input
#define FUN_420102f4 gpio_set_drive_capability
#define FUN_420108a4 rtc_gpio_is_valid_gpio
#define FUN_420139b0 usb_serial_jtag_hal_phy_set_external
#define FUN_42013a40 _usb_wrap_hal_init
#define FUN_42013a7c _usb_wrap_hal_disable
#define FUN_42013a94 usb_wrap_hal_phy_set_external
void usb_hc_low_level_init(MediusHostBusPrefix *bus);
void dwc2_get_user_params(unsigned int register_base,void *destination);
unsigned int usb_hc_init(MediusHostBusPrefix *bus);
void *usb_osal_sem_create(unsigned int initial_count);

int usbh_submit_urb(MediusHostUrb *urb);
int medius_usbh_cancel_urb(MediusHostUrb *urb,unsigned int *actual_out);
int usbh_kill_urb(MediusHostUrb *urb);
int medius_usbh_kill_urb_with_actual(MediusHostUrb *urb,unsigned int *actual_out);
int usb_osal_sem_take(void *semaphore,unsigned int timeout);
void usb_osal_msleep(unsigned int milliseconds);

/* Host status snapshots. Each accessor documents its native ordering; these
 * separate fields do not form an atomic configuration/USB-state snapshot. */
#define MEDIUS_HOST_ORDERED_LAST_ACK (*(volatile unsigned char *)0x3fca9787U)
#define MEDIUS_HOST_FORWARDING_INHIBIT (*(volatile unsigned char *)0x3fcaff25U)
#define MEDIUS_HOST_CURRENT_GENERATION (*(volatile unsigned int *)0x3fca9780U)
#define MEDIUS_HOST_APPLIED_GENERATION (*(volatile unsigned int *)0x3fca977cU)
#define MEDIUS_HOST_CONTROL_WORKER_TASK (*(RtosTask *volatile *)0x3fca9778U)
#define MEDIUS_HOST_ACTIVE_CONTROL_GENERATION (*(volatile unsigned int *)0x3fc9ddd0U)
#define MEDIUS_HOST_RESTART_GATE (*(volatile unsigned char *)0x3fcafefcU)
#define MEDIUS_HOST_CONFIGURATION_SWITCH_GATE (*(volatile unsigned char *)0x3fcaff1cU)
#define MEDIUS_HOST_PRECAPTURE_STATE (*(volatile unsigned char *)0x3fcaff0aU)
#define MEDIUS_HOST_HID_PAUSED (*(volatile unsigned char *)0x3fca9775U)
#define MEDIUS_HOST_HID_ENDPOINTS ((volatile MediusHidEndpointState *)0x3fcadad0U)
#define MEDIUS_HOST_SOF_MASK_GATE (*(volatile unsigned int *)0x3fc9de08U)
#define MEDIUS_HOST_SOF_MASK_LOCK (*(PortMuxWords *)0x3fc9de0cU)
#define MEDIUS_HOST_USB_REGISTERS ((volatile MediusDwc2HostRegisters *)0x60080000U)
unsigned char medius_ordered_get_last_ack(void);
unsigned int medius_host_get_frame(void);
int medius_host_frame_is_next(unsigned int previous_frame);
unsigned char medius_host_get_forwarding_inhibit(void);
unsigned char *medius_host_control_status_data(void);
unsigned int medius_host_control_status_length(void);
void medius_host_set_sof_interrupt(unsigned int enabled);
unsigned int medius_host_get_current_generation(void);
unsigned int medius_host_get_control_generation(void);
unsigned char medius_host_generation_is_applied(unsigned int generation);
unsigned char medius_hid_reserved_slots(void);
unsigned char medius_host_recovery_gate(void);

/* app_main's native scratch area: the 176-byte previous-panic text precedes
 * six separately written link-sync outputs. Their order matches the native
 * output pointers; only ready is cleared by app_main before each sample. */
typedef struct {
    unsigned int drift_ppb,offset_us; /* raw32 representations, including sign */
    unsigned short sample_age_ms,round_trip_us;
    unsigned char drift_valid,ready;
    unsigned char padding14[2];
} MediusLinkSyncStatus;
typedef struct {
    char previous_panic[176];
    MediusLinkSyncStatus sync;
} MediusHostMainScratch;

/* Call-site names identify existing entries; asm labels retain linkage to
 * their recovered definitions. Callback aliases express native word arguments;
 * the heartbeat ignores its task argument, and the event callback narrows
 * selected words to bytes. These declarations do not add native functions. */
typedef void (*MediusHostLinkMessageHandler)(unsigned char type,unsigned char flags,
    unsigned char *payload,unsigned short length);
void app_main(void);
void vTaskDelete(RtosTask *task);
void medius_link_set_sync_period(unsigned int period);
void link_read_sync_status(unsigned int *offset_us,unsigned int *drift_ppb,
    unsigned short *round_trip_us,unsigned short *sample_age_ms,
    unsigned char *ready,unsigned char *drift_valid);
void medius_host_release_sof_gate(void) __asm__("medius_host_resume_frame_interval_updates");
void medius_host_motion_init(void) __asm__("FUN_4202448c");
void medius_host_recovery_service(void);
unsigned char medius_host_forwarding_indicator(void);
unsigned int medius_host_report_drop_count(void);
int boot_read_previous_panic(char *buffer,unsigned int capacity) __asm__("FUN_42009318");
void medius_host_heartbeat_task(void *unused_argument) __asm__("medius_task_link_hb");
void medius_usb_host_event_callback(unsigned int bus,unsigned int hub,unsigned int port,
    unsigned int interface_index,unsigned int event) __asm__("medius_usb_host_event");
void medius_link_register_application_handler(MediusHostLinkMessageHandler callback,
    void *context) __asm__("link_set_frame_handler");
void medius_host_link_message(unsigned char type,unsigned char flags,unsigned char *payload,unsigned short length);
void link_start_sync_task(unsigned int argument);
void medius_host_log_init(void);
void medius_host_log_formatted(const char *format,...);
void medius_host_workers_init(void);
void medius_vendor_start_workers(void);
void medius_out_start_worker(void);
int usbh_initialize(unsigned char bus,unsigned int register_base,MediusHostEventHandler handler);
char *medius_get_firmware_label(void);
unsigned int esp_reset_reason(void);

/* HID class prefix has an embedded 68-byte URB at offset12. */
typedef struct {
    MediusHostHubPortPrefix *hubport;
    MediusHostEndpointDescriptor *endpoint;
    unsigned int reserved8;
    MediusHostUrb urb;
} MediusHidInterface;
/* Six-byte normal wire header, then up to26 metadata bytes and64 report
 * bytes. This view describes the native valid-report span, not a bounds check. */
typedef struct {
    unsigned int endpoint_and_stamp_low24;
    unsigned char stamp_high,flags,payload[90];
} MediusHidForwardFrame;
#define MEDIUS_HID_REPORT_QUEUE (*(RtosQueue *volatile *)0x3fcaff28U)
#define MEDIUS_HID_CREDIT_LOCK (*(PortMuxWords *)0x3fc9ddc4U)
#define MEDIUS_HID_RETRY_PENDING (*(volatile unsigned char *)0x3fcaff26U)
#define MEDIUS_HID_DMA_BASE ((unsigned char *)0x3fca3230U)
#define MEDIUS_HID_FORWARD_FRAME ((volatile MediusHidForwardFrame *)0x3fca8560U)
#define MEDIUS_HID_DROP_COUNT (*(volatile unsigned int *)0x3fcaff20U)
#define MEDIUS_HID_LAST_REPORT_US (*(volatile unsigned int *)0x3fca9748U)
#define MEDIUS_HID_MIN_REPORT_DELTA (*(volatile unsigned int *)0x3fc9ddccU)
#define MEDIUS_HID_TIMING_SAMPLES (*(volatile unsigned short *)0x3fca9738U)
#define MEDIUS_HID_PUBLISHED_REPORT_DELTA (*(volatile unsigned int *)0x3fca9744U)
#define MEDIUS_HID_ACTIVITY_SELECTOR (*(volatile unsigned short *)0x3fca9740U)
#define MEDIUS_HID_ACTIVITY_TIME (*(volatile unsigned int *)0x3fca973cU)
#define MEDIUS_HID_CACHED_REPORTS ((unsigned char (*)[64])0x3fcad644U)
#define MEDIUS_HID_CACHED_LENGTHS ((volatile unsigned short *)0x3fcad638U)
void medius_task_hidfwd(void *unused_argument);
void medius_hid_transfer_complete(void *context,int result);
int medius_hid_submit_read(MediusHidEndpointState *state,int keep_frame_parity);
void medius_hid_try_slow_poll(MediusHidEndpointState *state,int use_frame_phase);
void medius_hid_special_enqueue(MediusHidEndpointState *state,int from_isr,unsigned char prefix);
void medius_hid_report_enqueue(MediusHidEndpointState *state,int length,unsigned char report_flag,int from_isr);
int medius_hid_rearm_with_credit_gate(MediusHidEndpointState *state);
void medius_worker_watchdog_add(void);
void medius_worker_watchdog_feed(void);
int medius_endpoint_suppression_active(unsigned char endpoint);
void medius_hid_credit_release(MediusHidWork *work);
void medius_hid_release_frame_participation(MediusHidEndpointState *state);
void medius_motion_delta_restore(const unsigned char *metadata);
/* Verified five-word call boundary; the metadata formatter consumes low8
 * endpoint and low16 length. Metadata storage supplied by the worker is32 bytes. */
unsigned int medius_motion_prepare_hid_metadata(unsigned int endpoint,unsigned int stamp,
    const unsigned char *report,unsigned int length,unsigned char *metadata);
#define FUN_40387f0c medius_motion_prepare_hid_metadata
int link_send_wait100(unsigned char type,unsigned char flags,const void *payload,unsigned short length);

/* HID frame barrier: separate native word/byte/halfword storage, not a packed
 * or atomic aggregate. Snapshot/re-read order is documented by each caller. */
#define MEDIUS_HID_FRAME_LOCK (*(PortMuxWords *)0x3fc9ddb8U)
#define MEDIUS_HID_PENDING_POLLS (*(volatile unsigned int *)0x3fca9730U)
#define MEDIUS_HID_FRAME_PARTICIPANTS (*(volatile unsigned char *)0x3fca972cU)
#define MEDIUS_HID_PARTICIPATION_FRAME (*(volatile unsigned short *)0x3fc9ddc0U)
#define MEDIUS_VENDOR_INTERFACE_MASK (*(volatile unsigned int *)0x3fcb0c60U)
#define MEDIUS_VENDOR_INTERFACES ((volatile MediusVendorInterface *)0x3fcb0c68U)
void medius_hid_sof_schedule(void);
unsigned char medius_vendor_has_interrupt_in(void);

/* Vendor transport storage and the independent vendor credit lock. */
#define MEDIUS_VENDOR_CREDIT_LOCK (*(PortMuxWords *)0x3fc9dde8U)
#define MEDIUS_VENDOR_MUTEX (*(RtosQueue * volatile *)0x3fcb0754U)
#define MEDIUS_VENDOR_INTERRUPT_QUEUE (*(RtosQueue * volatile *)0x3fcb0758U)
#define MEDIUS_VENDOR_BULK_QUEUE (*(RtosQueue * volatile *)0x3fcb0c5cU)
#define MEDIUS_VENDOR_TRANSFER_SLOTS ((volatile unsigned char (*)[64])0x3fca3784U)
unsigned int medius_vendor_history_append(MediusVendorEndpointState *state);
void medius_vendor_history_drop(MediusVendorEndpointState *state, unsigned int sequence);
unsigned char medius_vendor_claim_arm(MediusVendorEndpointState *state);
void medius_vendor_wait_activity(void);
void medius_vendor_clear_interface(MediusVendorInterface *record);
int medius_vendor_disconnect(void *hubport, unsigned int interface_number);
void medius_vendor_queue_partial(MediusVendorEndpointState *state, unsigned int actual);
void medius_out_unregister(void *hubport, unsigned int endpoint);
void medius_copy_bytes(void *destination, void *source, unsigned int length);

#define MEDIUS_VENDOR_REPORT_CACHE ((volatile MediusVendorReport *)0x3fcb075cU)
#define MEDIUS_VENDOR_SELECTED_ALTERNATES ((volatile unsigned char *)0x3fcb0650U)
#define MEDIUS_VENDOR_SAVED_ENDPOINT_VALID (*(volatile unsigned short *)0x3fcaffbcU)
void medius_vendor_retry_cached(MediusVendorInterface *record, MediusVendorEndpointState *state);
int medius_vendor_claim_interface(void *hubport, unsigned int interface_number);
void medius_vendor_discard_saved_endpoint_state(unsigned int endpoint);
unsigned char medius_vendor_reserved_slots(void);
void medius_task_vendfwd(void *argument);
void medius_task_vintr(void *argument);
int medius_vendor_rearm(MediusVendorInterface *record, MediusVendorEndpointState *state);
int medius_vendor_initialize_interface(void *hubport, unsigned int interface_number,
    unsigned int alternate, int mode, unsigned char *exclude1, unsigned char *exclude2);

/* Vendor callback's shared ISR UART packet: native header stores are 32+16 bits. */
#define MEDIUS_VENDOR_GLOBAL_PAUSE (*(volatile unsigned char *)0x3fcb0750U)
#define MEDIUS_VENDOR_DIRECT_PACKET ((volatile unsigned char *)0x3fca373cU)
#define MEDIUS_VENDOR_DIRECT_PREFIX (*(volatile unsigned int *)0x3fca373cU)
#define MEDIUS_VENDOR_DIRECT_TAIL (*(volatile unsigned short *)0x3fca3740U)
#define MEDIUS_VENDOR_TX_SCRATCH ((LinkTxQueueItem *)0x3fca3530U)
#define MEDIUS_VENDOR_INTERRUPT_PACKET ((volatile unsigned char *)0x3fcaff74U)
void medius_vendor_complete(void *context, int result);
void medius_vendor_forward_report(MediusVendorReport *report, unsigned char *scratch);
int medius_link_send_from_isr(LinkTxQueueItem *scratch, unsigned char type,
    unsigned char flags, void *payload, unsigned int length, int *woken);

/* Saved credit bytes are the native 104-byte span at endpoint state offset96. */
#define MEDIUS_VENDOR_SAVED_CREDITS ((volatile MediusVendorSavedCredit *)0x3fcaffd0U)
#define MEDIUS_VENDOR_SAVED_TYPES ((volatile unsigned char *)0x3fcaffc0U)
void medius_vendor_pause_endpoint(MediusVendorEndpointState *state);
void medius_vendor_release_saved(unsigned int interface_number);
void medius_vendor_restore_alternate(MediusHostHubPortPrefix *port,
    unsigned int interface_number, unsigned int alternate);

#define MEDIUS_VENDOR_BULK_PACKET ((volatile unsigned char *)0x3fcaff2cU)
void medius_out_register(void *hubport, unsigned char *descriptor);

#define MEDIUS_HID_CREDIT_BUSY (*(volatile unsigned char *)0x3fca9734U)
int medius_host_phase_gate_open(void);
void medius_hid_apply_credit_records(unsigned char *payload, int length);
void medius_vendor_apply_credit_records(unsigned char *payload, int length,
    long long now_us, int initial_phase_open);

/* Source reconstruction utilities for native credit applications 4038aa0c and
 * 4202da18. These helpers consolidate repeated instruction sequences; they do
 * not represent additional native entries. All credit accesses require the
 * caller's corresponding credit lock. The 104-byte view starts at each
 * endpoint's report_sequence, matching the saved-credit layout. */
typedef MediusVendorSavedCredit MediusCreditState;

static inline int medius_credit_signed_less(unsigned long long a, unsigned long long b)
{
    return (a ^ 0x8000000000000000ULL) < (b ^ 0x8000000000000000ULL);
}

static inline void medius_credit_grow_from(volatile MediusCreditState *credit,
    unsigned long long now, unsigned long long epoch, unsigned int start_low,
    unsigned int start_high, int read_high_first, int write_high_first)
{
    unsigned long long start = ((unsigned long long)start_high << 32) | start_low;
    if (start == epoch) return;
    unsigned long long duration = 100000;
    if (start != 0) {
        const volatile ClockWords *old = (const volatile void *)&credit->boost_duration_us;
        unsigned int low, high;
        if (read_high_first) { high = old->high; low = old->low; }
        else { low = old->low; high = old->high; }
        unsigned long long previous = ((unsigned long long)high << 32) | low;
        if (medius_credit_signed_less(previous + 999999U, now - start)) duration = 100000;
        else if (medius_credit_signed_less(previous, 1500000U)) duration = previous << 1;
        else duration = 3000000;
    }
    volatile ClockWords *output = (volatile void *)&credit->boost_duration_us;
    if (write_high_first) { output->high = (unsigned int)(duration >> 32); output->low = (unsigned int)duration; }
    else { output->low = (unsigned int)duration; output->high = (unsigned int)(duration >> 32); }
    volatile ClockWords *stamp = (volatile void *)&credit->boost_started_us;
    stamp->low = (unsigned int)epoch;
    stamp->high = (unsigned int)(epoch >> 32);
}

static inline void medius_credit_grow(volatile MediusCreditState *credit,
    unsigned long long now, unsigned long long epoch, int write_high_first)
{
    const volatile ClockWords *start = (const volatile void *)&credit->boost_started_us;
    unsigned int low = start->low;
    unsigned int high = start->high;
    medius_credit_grow_from(credit, now, epoch, low, high, 0, write_high_first);
}

/* read_mode: 0 vendor(valid then sequence then conditional base), 1 matched
 * HID(sequence/base/valid), 2 unmatched HID(sequence only, force full history).
 * Seed is the CACHED packet count, not a fresh retained_credit_count read.
 * Reference is the CACHED applied epoch, not the live reference field. */
static inline int medius_credit_can_unblock(volatile MediusCreditState *credit,
    unsigned long long now, unsigned long long reference, unsigned int seed, int read_mode)
{
    unsigned int retained = 0, sequence, base = 0;
    if (read_mode == 0) {
        retained = credit->retained_credit_valid;
        sequence = credit->report_sequence;
        if (retained) base = credit->credit_sequence_base;
    } else {
        sequence = credit->report_sequence;
        if (read_mode == 1) { base = credit->credit_sequence_base; retained = credit->retained_credit_valid; }
    }
    unsigned int count = retained ? seed : 0, scan = 8;
    if (retained) { scan = (sequence - base) & 255U; if (scan > 8) scan = 8; }
    if (scan != 0) {
        unsigned int stop = (sequence - scan) & 255U;
        unsigned int protection = credit->history_protection_active;
        do {
            const volatile ClockWords *entry = (const volatile void *)&credit->report_history[sequence & 7U];
            unsigned int low = entry->low;
            unsigned int high = entry->high;
            int protected_entry = 0;
            if (protection) {
                unsigned int protected_base = credit->protection_base_sequence;
                protected_entry = protected_base != sequence && ((sequence - protected_base) & 255U) <= 8U;
            }
            if ((low | high) != 0) {
                if (protected_entry) ++count;
                else {
                    unsigned int window = (unsigned int)credit->history_window_us;
                    unsigned long long expiry = (((unsigned long long)high << 32) | low) +
                        (unsigned long long)(long long)(int)window;
                    if (medius_credit_signed_less(reference, expiry)) ++count;
                }
            }
            sequence = (sequence - 1U) & 255U;
        } while (sequence != stop);
    }
    const volatile ClockWords *start = (const volatile void *)&credit->boost_started_us;
    unsigned int low = start->low;
    unsigned int high = start->high;
    unsigned int limit = credit->credit_limit;
    if (count > 255U) count = 255U;
    if ((low | high) != 0) {
        unsigned long long elapsed = now - (((unsigned long long)high << 32) | low);
        const volatile ClockWords *duration = (const volatile void *)&credit->boost_duration_us;
        unsigned int duration_high = duration->high;
        unsigned int elapsed_high = (unsigned int)(elapsed >> 32);
        if ((int)elapsed_high < (int)duration_high ||
                (elapsed_high == duration_high && (unsigned int)elapsed < duration->low)) ++limit;
    }
    return count < limit;
}

static inline const volatile CreditRecord *medius_credit_find_record(
    const volatile unsigned char *payload, int length, unsigned int count, unsigned int endpoint)
{
    if (count == 0) return NULL;
    unsigned int offset = 1, visited = 0;
    for (;;) {
        visited = (visited + 1U) & 65535U;
        const volatile CreditRecord *record = (const volatile void *)(payload + offset);
        if ((int)(offset + 3U) >= length) return NULL;
        offset = (offset + 4U) & 65535U;
        if (record->endpoint == endpoint) return record;
        if (visited == count) return NULL;
    }
}

static inline int medius_hid_credit_single_packet(const volatile MediusHidEndpointState *state)
{
    unsigned int packet = state->max_packet;
    if (packet == 0) return 1;
    unsigned int length = state->transfer_length;
    return (((length + packet - 1U) / packet) & 65535U) == 1U;
}

void medius_vendor_initialize_hid_remainder(MediusHostHubPortPrefix *port,
    unsigned int interface_index, unsigned char *exclude_in, unsigned char *exclude_out);
void medius_vendor_reset_selection_state(void);
void medius_vendor_stop_mode_interfaces(void);

/* HID lifecycle storage. Count is native signed32; fixed-slot scans are separate. */
#define MEDIUS_HID_ENDPOINT_COUNT (*(volatile int *)0x3fcadaccU)
#define MEDIUS_HID_SHARED_BUSY_FLAGS ((volatile unsigned char *)0x3fca9735U)
#define MEDIUS_HID_POLL_OVERRIDE (*(volatile unsigned char *)0x3fca9737U)
#define MEDIUS_HID_SUSPEND_RESTORE_MASK (*(volatile unsigned int *)0x3fca974cU)
#define MEDIUS_HID_ALTERNATE_SELECTIONS ((volatile unsigned char *)0x3fcad9c8U)
#define MEDIUS_HID_REPORT_LENGTHS ((volatile unsigned short *)0x3fcad7c8U)
#define MEDIUS_HOST_RESET_PENDING (*(volatile unsigned char *)0x3fcadac8U)
#define MEDIUS_HOST_DESCRIPTORS_READY (*(volatile unsigned char *)0x3fcad635U)
void medius_host_pause_all_hid(void);
void medius_host_pause_hid_interface(MediusHostHidClass *interface);
void medius_host_restore_hid_interface(MediusHostHidClass *interface);
void medius_host_restore_suspended_hid(void);
void medius_hid_initialize_endpoint(MediusHidEndpointState *state, unsigned int report_length);
void medius_host_restore_hid_alternate(MediusHostHubPortPrefix *port,
    MediusHostHidClass *interface, unsigned int alternate, int allow_rearm);
void medius_vendor_pause_all(void);
void medius_vendor_resume_all(void);
void medius_vendor_set_paused_locked(int pause);
void medius_vendor_rebuild_hid_remainder(MediusHostHubPortPrefix *port,
    unsigned int interface_number, unsigned int alternate, unsigned char *exclude_in, unsigned char *exclude_out);
#define FUN_420307a0 medius_vendor_pause_all
#define FUN_420305f0 medius_vendor_resume_all
#define FUN_42030438 medius_vendor_rebuild_hid_remainder
#define FUN_4202f918 medius_vendor_set_paused_locked
void medius_out_pause_discard(void);
void medius_out_resume(void);
void medius_host_pick_interrupt_endpoints(MediusHostHubPortPrefix *port,
    unsigned int interface_number, unsigned int alternate, unsigned char **in, unsigned char **out);

/* HID class/descriptor storage; native addresses and read widths are retained. */
#define MEDIUS_HOST_HID_CLASS_MASK (*(volatile unsigned int *)0x3fca785cU)
#define MEDIUS_HOST_HID_CLASSES ((MediusHostHidClass *)0x3fca7860U)
#define MEDIUS_HID_DESCRIPTOR_SCRATCH ((unsigned char *)0x3fca1230U)
#define MEDIUS_HID_DESCRIPTOR_BLOB ((unsigned char *)0x3fcab608U)
#define MEDIUS_HID_DESCRIPTOR_BLOB_USED (*(volatile unsigned short *)0x3fcab604U)
#define MEDIUS_HOST_CLONE_ACTIVE (*(volatile unsigned char *)0x3fca9772U)
#define MEDIUS_HOST_SNAPSHOT_TIMER (*(EspTimer * volatile *)0x3fcad630U)
/* Native bounded formatter boundary at 4201654c; body review is separate. */
#define MEDIUS_HOST_SNPRINTF ((int (*)(char *,unsigned int,const char *,...))0x4201654cU)
int usbh_control_transfer(MediusHostHubPortPrefix *port,unsigned char *setup,unsigned char *buffer);
int usbh_hid_get_report_descriptor(MediusHostHidClass *hid,unsigned char *buffer,unsigned int length);
int usbh_hid_set_idle(MediusHostHidClass *hid,unsigned char report_id,unsigned char duration);
int medius_host_hid_class_connect(MediusHostHubPortPrefix *port,unsigned char interface_index);
int medius_host_hid_class_disconnect(MediusHostHubPortPrefix *port,unsigned char interface_index);
void medius_hid_attach_interface(MediusHostHidClass *hid);
void medius_hid_on_class_removed(MediusHostHidClass *ignored);
void medius_host_capture_descriptors_and_probe_controls(MediusHostHubPortPrefix *port);
void medius_host_teardown_interfaces(void);
int esp_timer_stop(EspTimer *timer);
void usb_osal_thread_schedule_other(void);

/* Host worker initialization and the UART TX admission callback. */
#define MEDIUS_HOST_CONTROL_WORK_QUEUE (*(RtosQueue * volatile *)0x3fcaa814U)
#define MEDIUS_HOST_CONFIGURATION_QUEUE (*(RtosQueue * volatile *)0x3fcaff10U)
#define MEDIUS_HOST_HALT_TIMER (*(EspTimer * volatile *)0x3fcad7c4U)
int medius_host_tx_admission(unsigned int encoded_length,unsigned int unused_context);
#define FUN_420264e0 medius_host_tx_admission
void medius_task_credit(void *unused);
void medius_task_ctrlwk(void);
void medius_task_cfgswitch(void);
void medius_snapshot_timer_cb(void);
void medius_halt_timer_cb(void);
int esp_timer_create(const EspTimerCreateArgs *args,EspTimer **result);
int esp_timer_start_periodic(EspTimer *timer,unsigned long long period_us);

/* Host recovery and frame-clock state: native-width independent samples. */
#define MEDIUS_HOST_CONTROL_BUSY (*(volatile unsigned char *)0x3fca97e8U)
#define MEDIUS_HOST_RECOVERY_ACTIVE (*(volatile unsigned char *)0x3fca976fU)
#define MEDIUS_HOST_RECOVERY_DEFERRED (*(volatile unsigned char *)0x3fca9773U)
#define MEDIUS_HOST_IDENTITY_REFRESH (*(volatile unsigned char *)0x3fca976eU)
#define MEDIUS_HOST_CURRENT_CONFIGURATION (*(volatile unsigned char *)0x3fcace0fU)
#define MEDIUS_HOST_REQUESTED_CONFIGURATION (*(volatile unsigned char *)0x3fcaff1dU)
#define MEDIUS_HOST_RESTART_REQUESTED_MS (*(volatile unsigned int *)0x3fcaff14U)
#define MEDIUS_HOST_CURRENT_VENDOR_ID (*(volatile unsigned short *)0x3fcaff0eU)
#define MEDIUS_HOST_CURRENT_PRODUCT_ID (*(volatile unsigned short *)0x3fcaff0cU)
#define MEDIUS_HOST_PREVIOUS_VENDOR_ID (*(volatile unsigned short *)0x3fcaff1aU)
#define MEDIUS_HOST_PREVIOUS_PRODUCT_ID (*(volatile unsigned short *)0x3fcaff18U)
#define MEDIUS_HOST_FRAME_CLOCK_MUTEX (*(RtosQueue * volatile *)0x3fcb98d0U)
#define MEDIUS_HOST_FRAME_CLOCK_BLOCKED (*(volatile unsigned char *)0x3fcb974cU)
#define MEDIUS_HOST_FRAME_CLOCK_REFERENCE_US ((volatile ClockWords *)0x3fcb9768U)
void medius_host_schedule_reenumeration(int force_identity_refresh);
void medius_host_block_frame_interval_updates(void);
void medius_host_resume_frame_interval_updates(void);
void medius_host_set_frame_clock_blocked(unsigned char blocked);
void medius_host_apply_frame_interval_adjustment(unsigned int nominal_ticks,int offset_ticks);
#define FUN_420265c4 medius_host_schedule_reenumeration
#define FUN_42025618 medius_host_block_frame_interval_updates
#define FUN_420255dc medius_host_resume_frame_interval_updates
#define FUN_42026320 medius_host_set_frame_clock_blocked
#define FUN_4202557c medius_host_apply_frame_interval_adjustment
int usbh_deinitialize(unsigned char bus_id);

/* Host control worker storage: distinct fields, not a coherent snapshot. */
#define MEDIUS_HOST_CURRENT_CONTROL_WORK ((volatile MediusControlWork *)0x3fca8dc4U)
#define MEDIUS_HOST_SHARED_SETUP ((volatile MediusUsbSetup *)0x3fca08e8U)
#define MEDIUS_HOST_CONTROL_DATA ((unsigned char *)0x3fca08f0U)
#define MEDIUS_HOST_CONTROL_RESPONSE ((volatile unsigned char *)0x3fca85c0U)
#define MEDIUS_HOST_CONTROL_PORT (*(MediusHostHubPortPrefix * volatile *)0x3fca97f0U)
#define MEDIUS_HOST_POWER ((volatile MediusHostPowerStateView *)0x3fca975cU)
#define MEDIUS_HOST_RESUME_PENDING (*(volatile unsigned char *)0x3fca9758U)
#define MEDIUS_HOST_RESUME_ARMED (*(volatile unsigned char *)0x3fca9759U)
#define MEDIUS_HOST_RESUME_EVENT_US ((volatile ClockWords *)0x3fca9750U)
#define MEDIUS_HOST_CONTROL_ACTIVITY (*(volatile unsigned char *)0x3fca9774U)
#define MEDIUS_HOST_ORDERED_LOCK (*(PortMuxWords *)0x3fc9ddd4U)
#define MEDIUS_HOST_PENDING_CONFIGURATION (*(volatile unsigned short *)0x3fca976cU)
#define MEDIUS_HOST_PENDING_CONFIGURATION_EPOCH (*(volatile unsigned int *)0x3fca9768U)
#define MEDIUS_HOST_ORDERED_EPOCH (*(volatile unsigned int *)0x3fca9764U)
#define MEDIUS_HOST_ORDERED_COUNT (*(volatile unsigned char *)0x3fca9784U)
#define MEDIUS_HOST_CAPTURE_PENDING (*(volatile unsigned char *)0x3fca9770U)
void control_fragment_emit(const unsigned char *data,unsigned short total,unsigned short chunk_limit,
    FragmentCallback callback,void *context);
void medius_ep0_send_response_fragment(const unsigned char *fragment,unsigned short length,void *context);
void medius_nonzero_send_response_fragment(const unsigned char *fragment,unsigned short length,void *context);
void medius_host_apply_generation(unsigned int generation);
void medius_host_apply_configuration(unsigned int selector,unsigned int generation,int deferred);
void medius_host_finish_resume(MediusHostHubPortPrefix *port,int restore_interfaces);
void medius_dwc2_host_gate_suspended_clock(unsigned int bus_index,unsigned char gated);
#define FUN_42020234 medius_dwc2_host_gate_suspended_clock
int usb_osal_mutex_take(void *mutex);
int usb_osal_mutex_give(void *mutex);
unsigned int ulTaskGenericNotifyTake(unsigned int index,int clear_count_on_exit,unsigned int ticks_to_wait);

/* Host control assembly buffers; payload begins at record offset0. */
#define MEDIUS_HOST_NONZERO_ASSEMBLY ((ControlAssembly *)0x3fca97f4U)
#define MEDIUS_HOST_EP0_ASSEMBLY ((ControlAssembly *)0x3fcaa004U)
int control_fragment_accept(ControlAssembly *assembly,
    const unsigned char *fragment,unsigned short length);
int medius_control_work_enqueue(MediusControlWork *work);
int medius_host_control_retry(MediusHostHubPortPrefix *port,long long started_us,
    unsigned int request_type,unsigned int request,unsigned short value,
    unsigned short index,unsigned short length);
void medius_usb_control_request_enqueue(unsigned char sequence,const unsigned char *payload,unsigned short length);
void medius_nonzero_request_enqueue(unsigned char sequence,const unsigned char *payload,unsigned short length);
void medius_nonzero_request_fragment(unsigned char sequence,const unsigned char *fragment,unsigned short length);
void medius_ep0_request_fragment(unsigned char sequence,const unsigned char *fragment,unsigned short length);

/* Ordered-change ring and signed16 endpoint acknowledgement tags. */
#define MEDIUS_HOST_ORDERED_HEAD (*(volatile unsigned char *)0x3fca9785U)
#define MEDIUS_HOST_ORDERED_CHANGES ((volatile MediusOrderedChange *)0x3fca9788U)
#define MEDIUS_HOST_ORDERED_LAST_RESULT (*(volatile unsigned char *)0x3fca9786U)
#define MEDIUS_HOST_ENDPOINT_HALT_ACTIVE_TAG (*(volatile short *)0x3fc9dddeU)
#define MEDIUS_HOST_ENDPOINT_HALT_COMPLETED_TAG (*(volatile short *)0x3fc9dddcU)
#define MEDIUS_HOST_ENUMERATION_DATA ((unsigned char *)0x3fc9ffe8U)
void medius_ordered_change_enqueue(unsigned int command,unsigned int arg1,unsigned int arg2,short ack_tag);
void medius_ordered_interface_request(const unsigned char *payload,unsigned short length);
void medius_ordered_configuration_request(const unsigned char *payload,unsigned short length);
void medius_ordered_generation_marker(void);
void medius_ordered_power_request(const unsigned char *payload,unsigned short length);
void medius_ordered_remote_wakeup_request(const unsigned char *payload,unsigned short length);
void medius_ordered_endpoint_halt_request(const unsigned char *payload,unsigned short length);
void medius_host_apply_remote_wakeup(MediusHostHubPortPrefix *port,long long started_us);
void medius_host_request_recovery(const char *reason,int force_identity_refresh);
unsigned int medius_host_control_no_data_retry(MediusHostHubPortPrefix *port,
    unsigned int request_type,unsigned int request,unsigned int value,unsigned int index,unsigned int force_recovery);
unsigned int medius_host_verify_device_identity(MediusHostHubPortPrefix *port);

/* Generation dispatcher dependencies and separately reviewed vendor controls. */
#define MEDIUS_HOST_CACHED_DEVICE_DESCRIPTOR_LENGTH (*(volatile unsigned short *)0x3fcad618U)
#define MEDIUS_HOST_CACHED_DEVICE_DESCRIPTOR ((const unsigned char *)0x3fcad61cU)
void medius_out_wake_worker(void);
unsigned char medius_out_has_queued_through(unsigned int generation);
void medius_out_drain_endpoint(unsigned char endpoint,unsigned int generation);
void medius_out_set_halted(unsigned char endpoint,unsigned char halted,unsigned char reset_toggle);
void medius_out_pause_preserve(void);
int medius_usbh_hub_set_port_feature(MediusHostHubState *hub,unsigned char port,unsigned char feature);
void medius_vendor_pause_interface(unsigned char index);
void medius_vendor_resume_interface(unsigned char index);
void medius_vendor_pause_streams(void);
void medius_vendor_prepare_clear_halt(unsigned char endpoint);
void medius_vendor_clear_stall_notifications(unsigned char endpoint);
void medius_vendor_set_endpoint_halt(unsigned int endpoint,unsigned int halted,unsigned int reset_toggle);

void medius_vendor_set_interface_paused_locked(unsigned int interface_number,int pause);
void medius_vendor_service_idle_streams(void);
unsigned char medius_vendor_first_active(void);
#define FUN_4202fa24 medius_vendor_set_interface_paused_locked
#define FUN_42030490 medius_vendor_service_idle_streams
#define FUN_42030584 medius_vendor_pause_interface
#define FUN_420305ac medius_vendor_resume_interface
#define FUN_420305d4 medius_vendor_pause_streams
#define FUN_42030610 medius_vendor_prepare_clear_halt
#define FUN_42030a60 medius_vendor_first_active
#define FUN_42030b00 medius_vendor_clear_stall_notifications
#define FUN_42030b5c medius_vendor_set_endpoint_halt

void medius_vendor_restore_configuration(MediusHostHubPortPrefix *port);
void medius_out_reset_toggles_resume(void);
#define FUN_42030860 medius_vendor_restore_configuration

/* Maintenance fields are independent native-width reads, not one snapshot. */
#define MEDIUS_HOST_CAPTURE_RUNNING (*(volatile unsigned char *)0x3fca9771U)
#define MEDIUS_HOST_CAPTURE_READY (*(volatile unsigned char *)0x3fcad634U)
#define MEDIUS_HOST_CLONE_PUBLICATION_PENDING (*(volatile unsigned char *)0x3fcaff24U)
#define MEDIUS_HOST_PRECAPTURE_COMPLETE (*(volatile unsigned char *)0x3fcafefdU)
#define MEDIUS_HOST_PRECAPTURE ((volatile MediusConfigurationCaptureState *)0x3fcaff00U)
#define MEDIUS_HOST_ENUMERATION_STARTED_MS (*(volatile unsigned int *)0x3fcadef4U)
#define MEDIUS_HOST_ENUMERATION_RESTART_COUNT (*(volatile unsigned int *)0x3fcadef0U)
void medius_host_set_forwarding_inhibit(unsigned char inhibit);
unsigned char medius_host_first_slow_hid_active(void);
void medius_clone_publish(void);
#define FUN_4202e370 medius_host_recovery_service
#define FUN_4202d74c medius_host_forwarding_indicator
#define FUN_4202d78c medius_host_set_forwarding_inhibit
#define FUN_4202d824 medius_host_report_drop_count
#define FUN_4202d834 medius_host_first_slow_hid_active

/* Native byte-oriented8-byte poll-phase wire record after a7-byte header. */
typedef struct {
    unsigned char endpoint,reserved;
    unsigned char remote_us_le[4];
    unsigned char sub_us_ns_le[2];
} MediusHidPollPhaseRecord;

/* View of the published link-clock estimate at3fccaf28. */
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
#define LINK_CLOCK_ESTIMATE ((volatile LinkClockEstimate *)0x3fccaf28U)
#define LINK_CLOCK_LOCK (*(PortMuxWords *)0x3fc9de28U)
#define MEDIUS_HID_POLL_POLICY_UPDATING (*(volatile unsigned char *)0x3fca9736U)
void medius_hid_set_poll_override(unsigned char override_ms);
void medius_hid_apply_poll_phases(const unsigned char *payload,unsigned int payload_length);
unsigned char medius_link_remote_to_local_us(unsigned int remote_us,long long *local_us);
int medius_host_get_frame_timing(long long *base_ns,long long *period_ns,unsigned short *frame);
long long medius_host_frame_phase_threshold_ns(void);
#define FUN_4202e07c medius_hid_set_poll_override
#define FUN_4202d86c medius_hid_apply_poll_phases
#define FUN_42021708 medius_link_remote_to_local_us

#define LINK_SYNC_PERIOD (*(volatile unsigned int *)0x3fc9de24U)
#define LINK_SYNC_FILTER_SCRATCH ((unsigned char *)0x3fccaf40U)
#define LINK_SYNC_QUEUE (*(RtosQueue * volatile *)0x3fccaf3cU)
#define FUN_4202161c medius_link_set_sync_period
#define FUN_42021674 link_read_sync_status

/* Native frame controller reset span:336 bytes, followed immediately by its
 * mutex. Split word fields document the individual native64 access order. */
typedef struct {
    ClockWords started_ns;
    ClockWords elapsed_sum_ns;
    ClockWords phase_sum_ns;
    unsigned int samples;                    /* Interpreted signed during fit. */
    unsigned int uninterpreted28;
} MediusFrameDriftBucket;
typedef struct {
    ClockWords integral_ppb;            /* 0x00 */
    ClockWords tick_remainder;          /* 0x08 */
    unsigned int adjustment_ticks;           /* 0x10, signed interpretation */
    unsigned int uninterpreted20;
    ClockWords last_sample_ns;          /* 0x18 */
    unsigned short stable_samples;           /* 0x20 */
    unsigned char locked;
    unsigned char reserved35[5];
    ClockWords model_origin_ns;         /* 0x28 */
    ClockWords integrated_tick_ns;      /* 0x30 */
    ClockWords modeled_phase_ns;        /* 0x38 */
    ClockWords drift_ppb;               /* 0x40 */
    unsigned char model_valid,bucket_count;   /* 0x48/0x49 */
    unsigned char reserved74[6];
    MediusFrameDriftBucket buckets[8];        /* 0x50,32-byte stride */
} MediusHostFrameController;
#define MEDIUS_HOST_FRAME_CONTROLLER ((volatile MediusHostFrameController *)0x3fcb9780U)
#define MEDIUS_HOST_FRAME_CACHED_NOMINAL (*(volatile unsigned int *)0x3fcb9750U)
#define MEDIUS_HOST_FRAME_LOW_RATE (*(volatile unsigned char *)0x3fcb974dU)
#define MEDIUS_HOST_FRAME_LAST_UPDATE_US ((volatile ClockWords *)0x3fcb9770U)
#define MEDIUS_HOST_FRAME_LAST_VALID_US ((volatile ClockWords *)0x3fcb9778U)
#define MEDIUS_HOST_PHASE_LOCK (*(PortMuxWords *)0x3fc9de00U)
/* Native producer publishes phase first, then its sample timestamp. */
#define MEDIUS_HOST_PHASE_ERROR_NS ((volatile ClockWords *)0x3fcb9760U)
#define MEDIUS_HOST_PHASE_SAMPLE_US ((volatile ClockWords *)0x3fcb9758U)
int medius_dwc2_host_frame_clock_snapshot(MediusHostFrameClockSnapshot *snapshot);
void medius_host_update_frame_controller(const unsigned char *payload,unsigned short length);
#define FUN_4202563c medius_host_update_frame_controller

/* Motion balances distinguish incoming input (class1) from command (class0)
 * contributions. Staged balances precede the current active balances in RAM;
 * both are signed native32 values stored as bits for defined wrapping sums. */
typedef struct {
    unsigned int input_x,command_x,input_y,command_y;
} MediusMotionBalances;
typedef struct {
    unsigned int generation;                 /* +0x00 */
    MediusMotionBalances staged;              /* +0x04 */
    MediusMotionBalances active;              /* +0x14 */
    unsigned int uninterpreted36;
    ClockWords timed_until_us;           /* +0x28 */
    ClockWords timed_started_us;         /* +0x30 */
    unsigned int timed_y,timed_x;              /* +0x38/+0x3c */
    unsigned int immediate_y,immediate_x;      /* +0x40/+0x44 */
    RtosQueue *wake_semaphore;           /* +0x48 */
    RtosTask *worker;                    /* +0x4c */
    ClockWords last_work_us;            /* +0x50, separate WORD accesses */
    unsigned char cancel_requested;           /* +0x58 */
    unsigned char reset_requested,busy;        /* +0x59/+0x5a */
    unsigned char active_program_mode;        /* +0x5b, snapshot when run starts */
    unsigned char program_mode,input_enabled,enabled; /* +0x5c/+0x5d/+0x5e */
    unsigned char uninterpreted95;
} MediusMotionEngineState;
typedef struct {
    ClockWords active_until_us;          /* +0x00 */
    ClockWords last_sent_us;             /* +0x08 */
    unsigned int counted_rx_drops;             /* +0x10 */
    unsigned int interval_metric;              /* +0x14 */
    unsigned char flags;                      /* +0x18 */
    unsigned char reserved25[3];
} MediusMotionStatusCache;
/* Seven actual native halfword stores: no inferred32-bit packet alignment. */
typedef struct {
    unsigned short flags_and_tag,metric_low,metric_high;
    unsigned short counted_drops_low,counted_drops_high;
    unsigned short other_drops_low,other_drops_high;
} MediusMotionStatusPacket;
#define MEDIUS_MOTION_ENGINE ((volatile MediusMotionEngineState *)0x3fcba128U)
#define MEDIUS_MOTION_ENGINE_LOCK (*(PortMuxWords *)0x3fc9de14U)
#define MEDIUS_MOTION_PENDING_LOCK (*(PortMuxWords *)0x3fc9ddf8U)
#define MEDIUS_MOTION_PENDING_AXES ((volatile unsigned int *)0x3fcb9630U)
#define MEDIUS_MOTION_INTERPOLATED_AXES ((volatile unsigned int *)0x3fcb9640U)
#define MEDIUS_MOTION_SEGMENT_COUNT (*(volatile unsigned char *)0x3fcb9610U)
#define MEDIUS_MOTION_STATUS_CACHE ((volatile MediusMotionStatusCache *)0x3fcb9388U)
#define MEDIUS_MOTION_OUTPUT_READ (*(volatile unsigned int *)0x3fcb98d8U)
#define MEDIUS_MOTION_OUTPUT_WRITE (*(volatile unsigned int *)0x3fcb98dcU)
#define MEDIUS_MOTION_PROGRAM_READY (*(volatile unsigned char *)0x3fcbb500U)
#define MEDIUS_MOTION_INTERVAL_SAMPLE_COUNT (*(volatile unsigned int *)0x3fcb9584U)
#define MEDIUS_MOTION_INTERVAL_MODAL_BIN (*(volatile unsigned short *)0x3fcb9588U)
#define MEDIUS_MOTION_INTERVAL_SCALE (*(volatile unsigned short *)0x3fcb9738U)
#define MEDIUS_MOTION_STATUS_TAG (*(volatile unsigned char *)0x3fcb9744U)
void medius_motion_cancel_requeue(const unsigned char *payload,unsigned short length);
void medius_motion_cancel_read(unsigned int *command_x,unsigned int *command_y,
    unsigned int *input_x,unsigned int *input_y);
unsigned char medius_motion_pending(void);
unsigned char medius_motion_command_pending(void);
unsigned char medius_motion_program_ready(void);
void medius_motion_publish_status(int force);
unsigned int medius_link_counted_rx_drop_count(void);
unsigned int medius_link_other_rx_drop_count(void);
/* Typed borrowed-payload boundary for the existing nonwaiting wrapper. */
void medius_link_send_borrowed_nowait(unsigned char type,unsigned char flags,
    const void *payload,unsigned short length) __asm__("medius_link_send_nowait");
#define FUN_42025450 medius_motion_cancel_requeue
#define FUN_42032384 medius_motion_cancel_read
#define FUN_403890c0 medius_motion_publish_status
#define FUN_4038b540 medius_motion_pending
#define FUN_4038ba4c medius_motion_command_pending
#define FUN_4038bb70 medius_motion_program_ready
#define FUN_4037f6cc medius_link_counted_rx_drop_count
#define FUN_4037f6e4 medius_link_other_rx_drop_count

typedef struct {unsigned short x,y;} MediusMotionAxisLimits;
typedef struct {unsigned int stamp,xy;} MediusMotionInputRecord;
#define MEDIUS_MOTION_AXIS_LIMITS ((volatile MediusMotionAxisLimits *)0x3fc9de1cU)
#define MEDIUS_MOTION_INPUT_READ (*(volatile unsigned int *)0x3fcb9920U)
#define MEDIUS_MOTION_INPUT_WRITE (*(volatile unsigned int *)0x3fcb9924U)
unsigned char medius_motion_set_policy(unsigned char enabled,unsigned char program_mode,
    unsigned char input_enabled);
void medius_motion_request_reset(void);
void medius_motion_set_axis_limits(int x_limit,int y_limit);
unsigned char medius_motion_input_program_ready(void);
void medius_motion_enqueue_input(unsigned int stamp,short x,short y);
void medius_motion_wake_worker(void);
#define FUN_42032488 medius_motion_set_policy
#define FUN_420324e8 medius_motion_request_reset
#define FUN_42032568 medius_motion_set_axis_limits
#define FUN_4038ba1c medius_motion_input_program_ready
#define FUN_4038bb18 medius_motion_enqueue_input
#define FUN_4038bb84 medius_motion_wake_worker

void medius_motion_accumulate(int x,int y,unsigned int source_class,
    unsigned int unused_slot,unsigned int now_low,unsigned int now_high,
    unsigned int duration_us);
unsigned char medius_motion_submit_input(short x,short y);
unsigned char medius_motion_submit_command(short x,short y,unsigned int now_low,
    unsigned int now_high,unsigned int duration_us);
#define FUN_4038b2a8 medius_motion_accumulate
#define FUN_4038ba90 medius_motion_submit_input
#define FUN_42032300 medius_motion_submit_command

#define MEDIUS_MOTION_INTERPOLATION_POLICY (*(volatile unsigned short *)0x3fcb9736U)
bool medius_motion_consume_output(unsigned int expected_generation,short x,short y);
void medius_motion_complete_output(short x,short y,unsigned int generation);
#define FUN_4038b594 medius_motion_consume_output
#define FUN_4038927c medius_motion_complete_output

typedef void (*MediusMotionOutputHandler)(short x,short y,unsigned int generation);
typedef struct {
    union {unsigned int xy;struct {short x,y;};};
    unsigned int generation;
} MediusMotionOutputRecord;
#define MEDIUS_MOTION_OUTPUT_HANDLER (*(MediusMotionOutputHandler volatile *)0x3fcba188U)
void medius_motion_drain_output(void);
#define FUN_4038b9c0 medius_motion_drain_output

typedef struct MediusMotionGruScales {
    int input[3];                                /* reset, update, candidate; Q31 multipliers */
    int recurrent[3];
} MediusMotionGruScales;

/* Complete cached multiplier/bias arrays shared by recurrent inference and
 * rendering. Gate order in each3x80 block is reset, update, candidate. */
typedef struct MediusMotionModelScales {
    MediusMotionGruScales gru;
    int gate;
    int grid[121];
} MediusMotionModelScales;
typedef struct MediusMotionModelBiases {
    int input[3][80],recurrent[3][80];
    int gate;
    int grid[121];
} MediusMotionModelBiases;

typedef struct MediusMotionGruWeights {
    signed char input[3][80][20];                 /* +0x0000, 4,800 bytes */
    signed char recurrent[3][80][80];             /* +0x12c0, 19,200 bytes */
} MediusMotionGruWeights;

/* Serialized signed-byte matrices following the 256-byte model header. */
typedef struct MediusMotionModelWeights {
    MediusMotionGruWeights gru;                 /* +0x0000 */
    signed char single_output[80];              /* +0x5dc0 */
    signed char projection[121][80];            /* +0x5e10 */
} MediusMotionModelWeights;

/* Native processing/configuration extents. Internal words remain opaque here;
 * their separate processing implementations own the detailed layouts. */
typedef union {
    unsigned int native_words[27];
    struct {
        const unsigned char *image;
        unsigned int length;
        union {
            const unsigned char *payload;
            const volatile MediusMotionGruWeights *gru_weights; /* +0x08 */
            const volatile MediusMotionModelWeights *model_weights;
        };
        const unsigned char *serialized_words_602,*serialized_words_128;
        const unsigned char *serialized_halfwords_a,*serialized_halfwords_b;
        const unsigned char *serialized_words_257,*serialized_halfwords_d;
        union {
            unsigned int parameters_88_to_9c[6]; /* serialized offsets0x88..0x9c */
            struct {
                int gate_offset_q14,gate_gain_q16;                 /* +0x24/+0x28 */
                int ring_center_gain_q16,ring_contrast_q16;        /* +0x2c/+0x30 */
                unsigned int reversal_dead_zone_q16;              /* +0x34 */
                unsigned int grid_force_threshold_q16;            /* +0x38 */
            };
        };
        union {unsigned int maximum_step;struct {unsigned short maximum_step_low,maximum_step_high;};}; /* +0x3c */
        union {
            unsigned int parameters_a4_to_b0[4];
            struct {
                unsigned int small_input_threshold_q16;           /* +0x40 */
                unsigned int minimum_residual_threshold_q16;      /* +0x44 */
                int perpendicular_penalty_q17,perpendicular_dead_zone_q15; /* +0x48/+0x4c */
            };
        };
        unsigned int payload_crc32; /* +0x50 */
        union {volatile unsigned int *cached_words_602;const volatile int *gru_bias_words;const volatile MediusMotionModelBiases *model_biases;}; /* +0x54 */
        union {volatile unsigned int *cached_words_128;const volatile MediusMotionGruScales *gru_scales;const volatile MediusMotionModelScales *model_scales;}; /* +0x58 */
        union {volatile unsigned short *cached_halfwords_a;const volatile unsigned short *sigmoid_q15;}; /* +0x5c */
        union {volatile unsigned short *cached_halfwords_b;const volatile short *tanh_q15;}; /* +0x60 */
        volatile unsigned int *cached_words_257;
        union {
            volatile unsigned short *cached_halfwords_d;
            const volatile short *log_mantissa_q14; /* +0x68, ln(1+i/256), i=0..256 */
        };
    };
} MediusMotionDecodedConfiguration;
typedef union {
    unsigned int native_words[38];
    struct {
        const unsigned char *image;
        unsigned int length;
        MediusMotionDecodedConfiguration decoded; /* +0x08 */
        const unsigned char *tail_header;          /* +0x74 */
        union {const unsigned char *table_145_a;const volatile unsigned char *dense_input_centers;}; /* +0x78, half floats */
        union {const unsigned char *table_145_b;const volatile unsigned char *dense_input_scales;};  /* +0x7c, half floats */
        union {const unsigned char *table_16_a;const volatile unsigned char *dense_hidden_scales;}; /* +0x80, float WORDs */
        union {const unsigned char *table_16_b;const volatile unsigned char *dense_hidden_biases;}; /* +0x84 */
        union {const unsigned char *matrix_145x16;const volatile signed char *dense_hidden_weights;}; /* +0x88, 16 rows */
        union {const unsigned char *table_80_a;const volatile unsigned char *dense_output_scales;}; /* +0x8c */
        union {const unsigned char *table_80_b;const volatile unsigned char *dense_output_biases;}; /* +0x90 */
        union {const unsigned char *matrix_80x16;const volatile signed char *dense_output_weights;}; /* +0x94, 80 rows */
    };
} MediusMotionConfiguration;
/* Motion filter: binary32 positions also copied as raw WORDs. Native64-bit
 * counters are separate LOW/HIGH WORD accesses, with no atomicity promise. */
typedef struct MediusMotionFilterVector {
    union {float x;unsigned int x_bits;};
    union {float y;unsigned int y_bits;};
} MediusMotionFilterVector;
typedef struct {unsigned int low,high;} MediusMotionFilterCounter;
typedef struct MediusMotionFilterState {
    MediusMotionFilterVector cumulative;             /* +0x00 */
    MediusMotionFilterVector cumulative_initial;     /* +0x08 */
    MediusMotionFilterVector cumulative_latest;      /* +0x10 */
    MediusMotionFilterVector cumulative_history[5];  /* +0x18, oldest first */
    unsigned int cumulative_history_count;           /* +0x40 */
    unsigned int uninterpreted68;
    MediusMotionFilterCounter cumulative_samples;    /* +0x48 */
    MediusMotionFilterVector averaged_initial;       /* +0x50 */
    MediusMotionFilterVector averaged_latest;        /* +0x58 */
    MediusMotionFilterVector averaged_history[5];    /* +0x60, oldest first */
    unsigned int averaged_history_count;             /* +0x88 */
    unsigned int uninterpreted140;
    MediusMotionFilterCounter averaged_samples;      /* +0x90 */
    MediusMotionFilterVector previous;               /* +0x98 */
    unsigned char has_previous;                      /* +0xa0 */
    unsigned char weighted_mode;                     /* +0xa1 */
    unsigned char sealed;                            /* +0xa2 */
    unsigned char uninterpreted163;
    MediusMotionFilterVector weighted_history[9];    /* +0xa4, newest first */
    unsigned int weighted_count;                     /* +0xec */
    MediusMotionFilterCounter input_samples;         /* +0xf0 */
    MediusMotionFilterCounter output_samples;        /* +0xf8 */
} MediusMotionFilterState;
typedef struct {short x,y;} MediusMotionDirectionQ15;
typedef struct {short x,y;} MediusMotionRawSample;
typedef struct MediusMotionLocalFeatures {
    short quarter_speed_q8,speed_change_q8,turn_q8;
    short direction_x_q8,direction_y_q8;
    short forward_deviation_q8,lateral_deviation_q8;
    short quarter_previous_forward_q8,quarter_previous_lateral_q8;
    short previous_activity_q8,activity_run_q8,inactive_fraction_q8;
    short log_speed_q8,quarter_nonzero_forward_q8,quarter_nonzero_lateral_q8;
} MediusMotionLocalFeatures;
typedef union {
    unsigned int words[10]; /* native paired-HALFWORD stores */
    short values[20];
    struct {
        MediusMotionLocalFeatures local;
        short nonzero_fraction_q8,log_mean_speed_q8,log_peak_speed_q8;
        short sign_change_fraction_q8,log_speed_variation_q8;
    };
} MediusMotionFeatureFrame;
typedef struct MediusMotionFeatureWindow {
    MediusMotionFilterVector sum;                    /* +0x00 */
    MediusMotionFilterVector baseline;               /* +0x08 */
    MediusMotionFilterVector previous_raw;           /* +0x10 */
    MediusMotionFilterVector previous_nonzero_raw;   /* +0x18 */
    MediusMotionRawSample last_nonzero_axis;         /* +0x20 */
    MediusMotionFilterVector last_direction_vector;  /* +0x24, not normalized in storage */
    MediusMotionFilterVector previous_filtered;      /* +0x2c */
    float previous_speed;                           /* +0x34 */
    unsigned short activity_run_length;             /* +0x38 */
    unsigned char previous_activity;                /* +0x3a */
    unsigned char activity_history[60];             /* +0x3b */
    unsigned char activity_cursor,activity_count;    /* +0x77/+0x78 */
    unsigned char uninterpreted121[3];
} MediusMotionFeatureWindow;
typedef struct MediusMotionSampleStatistics {
    unsigned int nonzero_count;                     /* +0x00 */
    float magnitude_sum;                            /* +0x04, max(abs(X),abs(Y)) */
    unsigned short peak_magnitude,previous_magnitude;
    unsigned int sign_changes,sign_comparisons;
    unsigned char previous_x_sign,previous_y_sign;  /* +0x14/+0x15: 0,1,255 */
    unsigned char uninterpreted22[2];
    float speed_delta_squares;                      /* +0x18 */
    unsigned short sorted_magnitudes[256];          /* +0x1c, ascending, nonzero only */
    float magnitude_squares;                        /* +0x21c */
    float spectrum_real[7],spectrum_imaginary[7];    /* +0x220/+0x23c */
} MediusMotionSampleStatistics;
/* Summary input accesses bytes0..96; the final byte of this aligned98-byte
 * type is padding. Parameters/vector are raw little-endian copied blocks. */
typedef struct MediusMotionCoreSummary {
    short statistics[5];                         /* +0x00 */
    union {
        unsigned char parameters_le[3][4];        /* +0x0a, copied WORD blocks */
        struct {
            MediusMotionRawSample previous_raw,previous_nonzero_raw,last_nonzero_axis;
        };
    };
    unsigned char uninterpreted22[2];
    unsigned char vector_q16_le[8];               /* +0x18 */
    unsigned short activity_weight;               /* +0x20 */
    unsigned char activity_mode;                  /* +0x22 */
    unsigned char activity_flags[60];             /* +0x23 */
    unsigned char activity_cursor,activity_count; /* +0x5f/+0x60 */
} MediusMotionCoreSummary;
typedef union {
    unsigned int native_words[512];
    struct {
        const MediusMotionDecodedConfiguration *configuration;
        unsigned int phase;
        short hidden_state[80];                   /* +0x08, previous recurrent Q15 state */
        unsigned int residual[2];                 /* +0xa8 */
        union {
            unsigned int summary_parameters[3];   /* +0xb0, copied raw WORD blocks */
            struct {
                MediusMotionRawSample previous_output;         /* +0xb0 */
                MediusMotionRawSample previous_nonzero_output; /* +0xb4 */
                MediusMotionRawSample previous_nonzero_axis;   /* +0xb8 */
            };
        };
        union {unsigned int limits_word;struct {unsigned short x_limit,y_limit;};}; /* +0xbc */
        union {unsigned char summary_activity_mode,previous_output_active;}; /* +0xc0 */
        unsigned char uninterpreted193;
        union {unsigned short summary_activity_weight,output_activity_run;}; /* +0xc2 */
        unsigned char summary_activity_flags[60]; /* +0xc4 */
        union {
            unsigned short summary_activity_indices;
            struct {unsigned char summary_activity_cursor,summary_activity_count;}; /* +0x100 */
        };
        MediusMotionRawSample raw_samples[256];    /* +0x102, HALFWORD aligned */
        unsigned short sample_cursor;             /* +0x502: masked only after writing */
        unsigned short samples;                   /* +0x504 */
        unsigned short uninterpreted1286;
        MediusMotionFilterCounter total_samples;   /* +0x508, LOW then HIGH */
        short summary_statistics[5];              /* +0x510 */
        union {
            struct {unsigned short initial_halfword,direction_y_bits;}; /* +0x51a: reset X32767 */
            MediusMotionDirectionQ15 direction;
        };
        unsigned char uninterpreted1310[2];
        int summary_vector_q16[2];                /* +0x520 */
        unsigned int summary_vector_magnitude;    /* +0x528 */
        unsigned char uninterpreted1324[4];
        union {
            struct {unsigned int seed_a,seed_b;};   /* +0x530/+0x534 */
            MediusMotionFilterCounter render_seed;
        };
        union {
            unsigned int seed_auxiliary[2];       /* +0x538/+0x53c */
            MediusMotionFilterCounter render_steps;
        };
        union {
            unsigned char uninterpreted1344[500]; /* retained extent view */
            struct {
                unsigned int last_gate_q15;       /* +0x540 */
                unsigned short last_grid_index;   /* +0x544; 120 also used on skipped sampling */
                unsigned char uninterpreted1350[2];
                unsigned int gate_random_u23,grid_random_u23; /* +0x548/+0x54c */
                union {
                    int grid_logits_q14[121];     /* +0x550; row-major11x11 offsets[-5,+5] */
                    unsigned int grid_weights_q20[121];
                };
            };
        };
        short next_hidden_state[80];              /* +0x734 */
        MediusMotionFeatureFrame latest_features; /* +0x7d4 */
        unsigned char uninterpreted2044[4];
    };
} MediusMotionCoreState;
typedef union {
    unsigned int native_words[1168];
    struct {
        const MediusMotionConfiguration *configuration;
        unsigned int uninterpreted4;
        MediusMotionCoreState core;               /* +0x08 */
        union {
            unsigned char filter_history[2][256]; /* +0x808/+0x908, legacy byte view */
            MediusMotionFilterState filters[2];
        };
        unsigned short collected_samples;         /* +0xa08, distinct from core.samples */
        unsigned short uninterpreted2570;
        union {
            struct {
                unsigned char uninterpreted2572[36];
                float unit_parameter_a30;          /* legacy name: first window direction X */
                unsigned char uninterpreted2612[120];
                float unit_parameter_aac;          /* legacy name: second window direction X */
                unsigned char uninterpreted2736[744];
            };
            struct {
                MediusMotionFeatureWindow feature_windows[2]; /* +0xa0c/+0xa88 */
                unsigned char late_activity[60];             /* +0xb04 */
                MediusMotionSampleStatistics statistics;     /* +0xb40 */
            };
        };
        float rotation_real[7];                   /* +0xd98: powers 1..7 */
        float rotation_imaginary[7];              /* +0xdb4 */
        union {
            float rotation_unit_parameters[7];    /* legacy reset view */
            float spectral_phase_real[7];         /* +0xdd0 */
        };
        float spectral_phase_imaginary[7];         /* +0xdec */
        float alternating_magnitude_sum;          /* +0xe08 */
        MediusMotionFeatureFrame features;        /* +0xe0c */
        union {
            unsigned char uninterpreted3636[1036]; /* retained extent view */
            struct {
                short final_statistics[5];             /* +0xe34 */
                MediusMotionLocalFeatures tail_features[4]; /* +0xe3e */
                unsigned char network_alignment[2];
                float network_inputs[145];             /* +0xeb8: 80+60+5 */
                float corrected_hidden[80];            /* +0x10fc */
                unsigned char uninterpreted4668[4];
            };
        };
    };
} MediusMotionProcessingState;
typedef void (*MediusMotionSampleHandler)(unsigned int context,short x,short y);
typedef union {
    unsigned int word;
    struct {
        union {unsigned short flags;struct {unsigned char present,capped;};};
        short x;
    };
} MediusMotionPendingHead;
typedef struct {
    MediusMotionSampleHandler callback;          /* +0x00 */
    unsigned int context;                       /* +0x04 */
    unsigned int deadline_us;                   /* +0x08 */
    unsigned int sum_x,sum_y;                   /* +0x0c/+0x10, signed interpretation */
    unsigned char started,uninterpreted21;
    unsigned short gap_samples;                 /* +0x16 */
    MediusMotionPendingHead pending;             /* +0x18, flags16/X16/word32 views */
    short pending_y;                            /* +0x1c */
    unsigned short uninterpreted30;
    unsigned int pending_stamp_us;              /* +0x20 */
} MediusMotionInputBatcher;
typedef struct {
    unsigned short samples;
    unsigned char late_nonzero,uninterpreted3;
} MediusMotionSampleWindow;
typedef struct {unsigned int stamp;short x,y;} MediusMotionInputSample;
#define MEDIUS_MOTION_BATCHER ((volatile MediusMotionInputBatcher *)0x3fcba290U)
#define MEDIUS_MOTION_WINDOW ((volatile MediusMotionSampleWindow *)0x3fcba2b4U)
#define MEDIUS_MOTION_CALLBACK_COUNT (*(volatile unsigned int *)0x3fcb98d4U)
#define MEDIUS_MOTION_DEFERRED_READY (*(volatile unsigned char *)0x3fcba2b8U)
#define MEDIUS_MOTION_DEFERRED_Y (*(volatile short *)0x3fcba2baU)
#define MEDIUS_MOTION_DEFERRED_X (*(volatile short *)0x3fcba2bcU)
#define MEDIUS_MOTION_DEFERRED_STATE ((MediusMotionProcessingState *)0x3fcba2c0U)
#define MEDIUS_MOTION_PUBLISHED_STATE ((MediusMotionProcessingState *)0x3fcbb508U)
#define MEDIUS_MOTION_BUILD_STATE ((MediusMotionProcessingState *)0x3fcbd988U)
#define MEDIUS_MOTION_CONFIG ((MediusMotionConfiguration *)0x3fcbebc8U)
#define MEDIUS_MOTION_RENDER_FILTER ((MediusMotionFilterState *)0x3fcba190U)
#define MEDIUS_MOTION_EMBEDDED_CONFIG ((const unsigned char *)0x3c045e28U)
bool medius_motion_start_renderer(MediusMotionOutputHandler output);
void medius_motion_collect_sample(unsigned int unused_context,short x,short y);
void medius_motion_process_input(void);
void medius_motion_filter_reset(void *state);
void medius_motion_filter_average_five(const volatile MediusMotionFilterVector history[5],
    unsigned int unused_word,unsigned int count_low,unsigned int count_high,
    volatile MediusMotionFilterVector *output);
int medius_motion_filter_difference(volatile MediusMotionFilterState *filter,
    const volatile MediusMotionFilterVector *input,volatile MediusMotionFilterVector *output);
int medius_motion_filter_step(volatile MediusMotionFilterState *filter,
    float x,float y,float output[2]);
int medius_motion_filter_finish(volatile MediusMotionFilterState *filter,float output[8]);
#define FUN_4037ad70 medius_motion_filter_step
#define FUN_4200e3f8 medius_motion_filter_finish
/* Typed native call boundaries; these callee bodies are reviewed separately. */
int medius_motion_config_load(MediusMotionConfiguration *configuration,
    const unsigned char *image,unsigned int length);
void medius_motion_config_prepare(const MediusMotionDecodedConfiguration *configuration);
#define FUN_4200e6c8 medius_motion_config_prepare
int medius_motion_processing_reset(MediusMotionProcessingState *state,
    MediusMotionConfiguration *configuration);
#define FUN_4200d330 medius_motion_processing_reset
int medius_motion_process_sample(MediusMotionProcessingState *state,short x,short y);
int medius_motion_core_append_sample(MediusMotionCoreState *core,short x,short y);
void medius_motion_extract_sample_features(volatile MediusMotionFeatureWindow *window,
    unsigned int sample_index,int raw_x,int raw_y,const volatile MediusMotionFilterVector *filtered,
    volatile MediusMotionLocalFeatures *output);
float medius_math_log1pf(float value);
#define FUN_4038703c medius_math_log1pf
/* Completed-window summary and dense residual correction. */
int medius_motion_finalize_processing(MediusMotionProcessingState *state);
#define FUN_4200c774 medius_motion_finalize_processing
/* Binary32 activation used by the dense motion layer. */
float medius_math_tanhf(float value) __asm__("FUN_4201579c");
#define FUN_403779a4 medius_motion_process_sample
#define FUN_4037d638 medius_motion_core_append_sample
#define FUN_4037737c medius_motion_extract_sample_features
RtosQueue *xQueueCreateCountingSemaphore(unsigned int capacity,
    unsigned int initial_count) __asm__("FUN_4038145c");
/* Same constructor previously identified through the motion worker caller. */
#define medius_motion_create_counting_semaphore xQueueCreateCountingSemaphore
#define FUN_4038145c xQueueCreateCountingSemaphore
RtosQueue *medius_rtos_create_queue_with_type(unsigned int capacity,
    unsigned int item_size,unsigned char queue_type) __asm__("xQueueGenericCreate");
void medius_motion_render_worker(void *argument) __asm__("medius_task_render");
#define FUN_420325a8 medius_motion_start_renderer
#define FUN_40376f10 medius_motion_collect_sample
#define FUN_40376ff4 medius_motion_process_input
#define FUN_4200e3e4 medius_motion_filter_reset

unsigned int medius_motion_config_crc32(const unsigned char *data,unsigned int length);
int medius_motion_seed_processing(MediusMotionProcessingState *state,
    unsigned int unused,unsigned int seed_a,unsigned int seed_b);
int medius_motion_processing_set_limits(MediusMotionProcessingState *state,int x_limit,int y_limit);
int medius_motion_core_initialize(MediusMotionCoreState *core,const MediusMotionDecodedConfiguration *configuration);
int medius_motion_core_seed(MediusMotionCoreState *core,unsigned int unused,unsigned int seed_a,unsigned int seed_b);
int medius_motion_core_set_limits(MediusMotionCoreState *core,int x_limit,int y_limit);
int medius_motion_core_submit_features(MediusMotionCoreState *core,const MediusMotionFeatureFrame *features);
int medius_motion_core_apply_summary(MediusMotionCoreState *core,const MediusMotionCoreSummary *summary);
float medius_motion_half_to_float(const void *little_endian_half);
void medius_motion_split_feature_bytes(const volatile unsigned short *input,int count,
    unsigned int clear_length,volatile unsigned char *high_bytes,volatile unsigned char *biased_low_bytes);
void medius_motion_normalize_vector_q15(int x,int y,volatile MediusMotionDirectionQ15 *direction,
    volatile unsigned int *magnitude);
int medius_motion_lookup_log_magnitude(const volatile MediusMotionDecodedConfiguration *configuration,
    unsigned int unused_word,unsigned int magnitude_low,unsigned int magnitude_high);
/* Borrowed feature-cache boundary; the inference/update body is reviewed
 * separately from the validation/copy wrapper. Its return register is ignored. */
void medius_motion_core_update_features(MediusMotionCoreState *core,const MediusMotionFeatureFrame *features);
#define FUN_4037840c medius_motion_core_update_features
#define FUN_403790dc medius_motion_core_submit_features
#define FUN_4200e2e0 medius_motion_core_apply_summary
#define FUN_4200c6fc medius_motion_half_to_float
#define FUN_4037b0ac medius_motion_split_feature_bytes
#define FUN_40377fd4 medius_motion_normalize_vector_q15
#define FUN_403782f8 medius_motion_lookup_log_magnitude
typedef struct __attribute__((aligned(16))) {signed char lanes[80];} MediusMotionS8Vector80;
typedef struct __attribute__((aligned(16))) {signed char lanes[32];} MediusMotionS8Vector32;
/* Shared aligned caches. Correction WORDs compensate the biased low-byte
 * inputs used by the accelerator: 128 times the signed-byte row sum. */
typedef struct MediusMotionModelCache {
    unsigned int single_correction;             /* 0x3fcc11d0 */
    unsigned int projection_corrections[121];   /* 0x3fcc11d4 */
    unsigned int recurrent_corrections[240];    /* 0x3fcc13b8 */
    unsigned int input_corrections[240];        /* 0x3fcc1778 */
    unsigned int reserved[2];
    MediusMotionS8Vector80 single_output;       /* 0x3fcc1b40 */
    MediusMotionS8Vector80 projection[121];     /* 0x3fcc1b90 */
    MediusMotionS8Vector80 recurrent[240];      /* 0x3fcc4160 */
    MediusMotionS8Vector32 input[240];          /* 0x3fcc8c60; 12 zero padding bytes per row */
} MediusMotionModelCache;

typedef struct MediusMotionMatrixTestState {
    MediusMotionS8Vector80 low;                 /* 0x3fcc0cd0 */
    MediusMotionS8Vector80 high;                /* 0x3fcc0d20 */
    union {
        short input[80];                       /* 0x3fcc0d70 */
        unsigned int input_words[40];
    };
    unsigned int results[240];                 /* 0x3fcc0e10 */
} MediusMotionMatrixTestState;
#define MEDIUS_MOTION_MODEL_CACHE ((volatile MediusMotionModelCache *)0x3fcc11d0U)
#define MEDIUS_MOTION_MATRIX_TEST ((volatile MediusMotionMatrixTestState *)0x3fcc0cd0U)

/* Shared rendering scratch; the recurrent workspace begins immediately after
 * it. Projection kernels reuse these high/low hidden bytes without resplitting. */
typedef struct MediusMotionRenderWorkspace {
    unsigned int projection_dot[121];           /* 0x3fcbec60 */
    unsigned int padding[3];
    MediusMotionS8Vector80 hidden_low;            /* 0x3fcbee50 */
    MediusMotionS8Vector80 hidden_high;           /* 0x3fcbeea0 */
} MediusMotionRenderWorkspace;
#define MEDIUS_MOTION_RENDER_WORKSPACE ((volatile MediusMotionRenderWorkspace *)0x3fcbec60U)

typedef struct MediusMotionGruWorkspace {
    unsigned int recurrent_dot[240];              /* +0x000 */
    unsigned int input_dot[240];                  /* +0x3c0 */
    MediusMotionS8Vector80 hidden_low;             /* +0x780, biased low bytes */
    MediusMotionS8Vector80 hidden_high;            /* +0x7d0 */
    MediusMotionS8Vector32 input_low;              /* +0x820, biased low bytes */
    MediusMotionS8Vector32 input_high;             /* +0x840 */
} MediusMotionGruWorkspace;
#define MEDIUS_MOTION_GRU_WORKSPACE ((volatile MediusMotionGruWorkspace *)0x3fcbeef0U)
#define MEDIUS_MOTION_GRU_ACCELERATED (*(volatile unsigned int *)0x3fc9de20U)
#define MEDIUS_MOTION_GRU_INPUT_WEIGHTS ((const volatile MediusMotionS8Vector32 *)0x3fcc8c60U)
#define MEDIUS_MOTION_GRU_RECURRENT_WEIGHTS ((const volatile MediusMotionS8Vector80 *)0x3fcc4160U)
#define MEDIUS_MOTION_GRU_INPUT_CORRECTIONS ((const volatile unsigned int *)0x3fcc1778U)
#define MEDIUS_MOTION_GRU_RECURRENT_CORRECTIONS ((const volatile unsigned int *)0x3fcc13b8U)
void medius_motion_dot_s8_80(const volatile MediusMotionS8Vector80 *weights,
    const volatile MediusMotionS8Vector80 *input,volatile unsigned int *output,unsigned int rows);
void medius_motion_dot_s8_32(const volatile MediusMotionS8Vector32 *weights,
    const volatile MediusMotionS8Vector32 *input,volatile unsigned int *output,unsigned int rows);
void medius_motion_accumulate_s8_80(const volatile MediusMotionS8Vector80 *weights,
    const volatile MediusMotionS8Vector80 *input,volatile unsigned int *output,unsigned int rows,
    const volatile unsigned int *bias);
void medius_motion_accumulate_s8_32(const volatile MediusMotionS8Vector32 *weights,
    const volatile MediusMotionS8Vector32 *input,volatile unsigned int *output,unsigned int rows,
    const volatile unsigned int *bias);
#define FUN_4037d694 medius_motion_dot_s8_80
#define FUN_4037d6d4 medius_motion_dot_s8_32
#define FUN_4037d700 medius_motion_accumulate_s8_80
#define FUN_4037d74c medius_motion_accumulate_s8_32
/* Fixed base-format validation and shared table-cache initialization. */
int medius_motion_decode_base(MediusMotionDecodedConfiguration *decoded,
    const unsigned char *image,unsigned int length);
#define FUN_4200d570 medius_motion_decode_base
#define FUN_4200d1d8 medius_motion_config_load
#define FUN_4200d4d0 medius_motion_config_crc32
#define FUN_4200d484 medius_motion_seed_processing
#define FUN_4200d4b4 medius_motion_processing_set_limits
#define FUN_4200e250 medius_motion_core_initialize
#define FUN_4200e28c medius_motion_core_seed
#define FUN_4201e878 medius_motion_core_set_limits

/* Binary32 arithmetic rounding in the current floating-point mode. */
float medius_math_rintf(float value);
float medius_math_rintf_core(float value);
#define FUN_42015b94 medius_math_rintf
#define FUN_42015c40 medius_math_rintf_core

/* Hardware square-root refinement and errno-setting wrapper. */
float medius_math_sqrtf(float value);
float medius_math_sqrtf_core(float value);
#define FUN_403872ac medius_math_sqrtf
#define FUN_4038407c medius_math_sqrtf_core

/* Binary32 math error paths. Sign selectors treat every nonzero word as true. */
float medius_math_with_errno(float result,int error);
float medius_math_range_product(unsigned int negative,float value);
float medius_math_overflow(unsigned int negative);
float medius_math_divide_by_zero(unsigned int negative);
float medius_math_invalid(float value);
#define FUN_42015ba4 medius_math_with_errno
#define FUN_42015bb4 medius_math_range_product
#define FUN_42015bd4 medius_math_overflow
#define FUN_42015be8 medius_math_divide_by_zero
#define FUN_42015c10 medius_math_invalid

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

/* ESP-IDF v5.4.4 terminal record: 28 bytes, four 16-bit flags, eleven
 * control characters, one alignment byte, then two 32-bit speed values. */
struct termios {
    unsigned short c_iflag;            /* +0x00: input conversion */
    unsigned short c_oflag;            /* +0x02: output modes */
    unsigned short c_cflag;            /* +0x04: UART line/speed controls */
    unsigned short c_lflag;            /* +0x06: local modes */
    unsigned char c_cc[11];            /* +0x08: EOF through VTIME */
    unsigned char padding_13;
    unsigned long c_ispeed;            /* +0x14: target uint32_t/speed_t */
    unsigned long c_ospeed;            /* +0x18 */
};
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
typedef struct {
    union {
        struct {bool is_sem_local;unsigned char padding[3];};
        unsigned int flags_word;
    };
    void *handle;
} VfsSelectSemaphore;
typedef int (*VfsStartSelectOperation)(int count,fd_set *read_set,
    fd_set *write_set,fd_set *error_set,VfsSelectSemaphore semaphore,void **end_arguments);
typedef int (*VfsEndSelectOperation)(void *arguments);
typedef void (*MediusVfsStopSelectOperation)(void *semaphore);
typedef void (*MediusVfsStopSelectIsrOperation)(void *semaphore,int *task_woken);
typedef struct VfsSelectOperations {
    VfsStartSelectOperation start;      /* +0x00 */
    int (*socket_select)(int count,fd_set *read_set,fd_set *write_set,
        fd_set *error_set,struct timeval *timeout);
    MediusVfsStopSelectOperation stop_socket; /* +0x08 */
    MediusVfsStopSelectIsrOperation stop_socket_isr; /* +0x0c */
    void *(*get_socket_select_semaphore)(void);
    VfsEndSelectOperation end;          /* +0x14 */
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
#define MEDIUS_VFS_DESCRIPTORS ((volatile MediusVfsDescriptor *)0x3fc9dce8U)
#define VFS_DRIVER_COUNT (*(volatile unsigned int *)0x3fca7830U)
#define VFS_DRIVERS ((const volatile VfsDriverEntry * volatile *)0x3fca7834U)
#define MEDIUS_VFS_DESCRIPTOR_LOCK (*(NewlibLock *)0x3fca782cU)
#define FUN_42032a14 medius_vfs_write
#define FUN_42032a80 medius_vfs_seek
#define FUN_42032aec medius_vfs_read
#define FUN_42032b58 medius_vfs_close
#define FUN_42032bf4 medius_vfs_status
#define FUN_42032c5c medius_vfs_control

int vfs_close_current(int descriptor);
int vfs_status_current(int descriptor,VfsStat *status);
int vfs_read_current(int descriptor,void *data,unsigned int length);
int vfs_write_current(int descriptor,const void *data,unsigned int length);
int medius_newlib_stream_close(NewlibReent *reent,void *cookie);
#define FUN_42016b6c vfs_close_current
#define FUN_42016b84 vfs_status_current
#define FUN_42016c00 vfs_read_current
#define FUN_42016c1c vfs_write_current
#define FUN_4201666c medius_newlib_stream_close

/* Newlib FILE callbacks: lengths and offsets retain the native 32-bit ABI. */
int medius_newlib_stream_read(NewlibReent *reent,void *cookie,char *buffer,int length);
int medius_newlib_stream_write(NewlibReent *reent,void *cookie,const char *buffer,int length);
long medius_newlib_stream_seek(NewlibReent *reent,void *cookie,long offset,int origin);
#define FUN_420165c0 medius_newlib_stream_read
#define FUN_420165f4 medius_newlib_stream_write
#define FUN_42016630 medius_newlib_stream_seek

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
#define MEDIUS_NEWLIB_STANDARD_FILES ((NewlibFile *)0x3fccbbf4U)
#define MEDIUS_NEWLIB_GLOBAL_CLEANUP (*(MediusNewlibGlobalCleanup volatile *)0x3fccbd2cU)
#define MEDIUS_NEWLIB_STDIO_GLUE ((NewlibGlue *)0x3fc9e378U)
#define MEDIUS_NEWLIB_STARTUP_REENT ((NewlibReent *)0x3fc9e388U)
#define FUN_42015f60 medius_newlib_initialize_file
#define FUN_42015fd0 medius_newlib_cleanup_global_streams
#define FUN_42015fe4 medius_newlib_cleanup_context
#define FUN_4201601c medius_newlib_initialize_standard_streams
#define FUN_42016050 medius_newlib_file_pool_lock
#define FUN_42016060 medius_newlib_file_pool_unlock
#define FUN_42016070 medius_newlib_allocate_file
#define FUN_42016124 medius_newlib_initialize_stdio_context
#define FUN_4201ec7c medius_newlib_walk_streams

/* Newlib FILE flushing and closure; callbacks use the complete FILE layout. */
int medius_newlib_close_file(NewlibReent *reent,NewlibFile *file);
int medius_newlib_flush_file_unlocked(NewlibReent *reent,NewlibFile *file);
int medius_newlib_flush_file(NewlibReent *reent,NewlibFile *file);
#define FUN_42015d0c medius_newlib_close_file
#define FUN_42015dd4 medius_newlib_flush_file_unlocked
#define FUN_42015f08 medius_newlib_flush_file

/* FILE opening, mode decoding and buffer/write preparation. */
NewlibFile *medius_newlib_open_file(NewlibReent *reent,const char *path,const char *mode);
NewlibFile *medius_newlib_open_file_current(const char *path,const char *mode);
int medius_newlib_prepare_write(NewlibReent *reent,NewlibFile *file);
unsigned int medius_newlib_parse_file_mode(NewlibReent *reent,const char *mode,unsigned int *open_flags);
unsigned int medius_newlib_select_buffer_size(NewlibReent *reent,NewlibFile *file,int *capacity,unsigned int *is_character);
void medius_newlib_make_file_buffer(NewlibReent *reent,NewlibFile *file);
int medius_newlib_isatty_unsupported(NewlibReent *reent,int descriptor);
#define FUN_42016150 medius_newlib_open_file
#define FUN_42016208 medius_newlib_open_file_current
#define FUN_42016728 medius_newlib_prepare_write
#define FUN_4201ecb4 medius_newlib_parse_file_mode
#define FUN_4201cf04 medius_newlib_select_buffer_size
#define FUN_4201cf70 medius_newlib_make_file_buffer
#define FUN_4201e7fc medius_newlib_isatty_unsupported

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
#define MEDIUS_VFS_ROOT_PATH ((const char *)0x3c04203cU)
#define FUN_42032714 medius_vfs_translate_path
#define FUN_420328b0 medius_vfs_find_path
#define FUN_4203292c medius_vfs_open
#define FUN_42016bb4 vfs_open_current
#define FUN_42032d38 medius_vfs_stat_path
#define FUN_42032d88 medius_vfs_link_path
#define FUN_42032e00 medius_vfs_unlink_path
#define FUN_42032e54 medius_vfs_rename_path
#define FUN_42032ed4 vfs_access_current

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
#define NULL_VFS_ACCESS_BITMAP (*(volatile unsigned int *)0x3fca7854U)
#define NULL_VFS_OPERATIONS ((const VfsOperations *)0x3c045b70U)
#define FUN_42008c9c null_vfs_open
#define FUN_42008d4c null_vfs_seek
#define FUN_42008d88 null_vfs_status
#define FUN_42008dc0 null_vfs_control
#define FUN_42008de4 null_vfs_write
#define FUN_42008e74 null_vfs_read
#define FUN_42008ec4 null_vfs_read_at
#define FUN_42008e98 null_vfs_write_at
#define FUN_42008e50 null_vfs_ioctl
#define FUN_42008ee8 null_vfs_close
#define FUN_42008f04 null_vfs_sync
#define FUN_42008e10 null_vfs_stat_path
#define FUN_42008f20 null_vfs_register
#define FUN_42016b9c gettimeofday

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
const VfsOperations *medius_uart_vfs_get_operations(void);
#define CONSOLE_GET_BACKEND medius_uart_vfs_get_operations
#define CONSOLE_BACKEND_OPERATIONS (*(const volatile VfsOperations * volatile *)0x3fca7828U)
#define CONSOLE_DESCRIPTOR (*(volatile int *)0x3fca7820U)
#define CONSOLE_REFERENCE_COUNT (*(volatile unsigned int *)0x3fca781cU)
#define CONSOLE_OPERATIONS ((const VfsOperations *)0x3c045ac4U)
#define CONSOLE_INITIAL_BACKEND ((const VfsOperations *)0x3c045904U)
#define CONSOLE_BACKING_PATH "/dev/uart/0"
#define FUN_42008b00 console_start_select
#define FUN_42008b30 console_end_select
#define FUN_42008b4c console_write
#define FUN_42008b64 console_status
#define FUN_42008b78 console_read
#define FUN_42008b90 console_control
#define FUN_42008ba8 console_sync
#define FUN_42008bbc console_access
#define FUN_42008bd0 console_set_attributes
#define FUN_42008be8 console_get_attributes
#define FUN_42008bfc console_drain
#define FUN_42008c10 console_flush
#define FUN_42008c24 console_open
#define FUN_42008c4c console_close
#define FUN_42008c7c console_register
#define FUN_4202271c medius_uart_vfs_get_operations
#define FUN_42032f7c vfs_get_attributes_current
#define FUN_42032ff4 vfs_set_attributes_current
#define FUN_42033070 vfs_drain_current
#define FUN_420330e4 vfs_flush_current
#define FUN_42032cc8 vfs_sync_current
#define FUN_420071b8 vfs_control_current
#define CONSOLE_ACCESS_PATH "/dev/uart/0"

/* UART VFS contexts, matched to native DROM pointers and 40-byte DRAM records.
 * Volatile fields retain deliberate native snapshots/reloads across callbacks;
 * they do not supply mutual exclusion. Locks are lazy Newlib lock SLOTS. */
typedef void (*MediusUartVfsWriteChar)(int port,int character);
typedef int (*MediusUartVfsReadChar)(int port);
typedef unsigned int (*MediusUartVfsAvailable)(int port);
typedef struct MediusUartVfsContext {
    UartRegisterView *uart;           /* +0x00 */
    volatile int lookahead;                /* +0x04: -1 means empty */
    NewlibLock read_lock;            /* +0x08 */
    NewlibLock write_lock;           /* +0x0c */
    volatile unsigned char nonblocking;    /* +0x10 */
    unsigned char padding_11[3];
    volatile int tx_mode;                  /* +0x14 */
    volatile int rx_mode;                  /* +0x18 */
    MediusUartVfsWriteChar volatile write_char; /* +0x1c */
    MediusUartVfsReadChar volatile read_char;   /* +0x20 */
    MediusUartVfsAvailable volatile available; /* +0x24 */
} MediusUartVfsContext;
#define MEDIUS_UART_VFS_CONTEXTS ((MediusUartVfsContext * const volatile *)0x3c0459b0U)
enum {
    MEDIUS_UART_LINE_ENDINGS_CRLF=0,
    MEDIUS_UART_LINE_ENDINGS_CR=1,
    MEDIUS_UART_LINE_ENDINGS_LF=2,
    MEDIUS_TERMIOS_ICRNL=0x02,
    MEDIUS_TERMIOS_IGNCR=0x08,
    MEDIUS_TERMIOS_CSTOPB=0x04,
    MEDIUS_TERMIOS_PARENB=0x10,
    MEDIUS_TERMIOS_PARODD=0x20,
    MEDIUS_TERMIOS_BAUD_FLAGS=0x300,
    MEDIUS_TERMIOS_BOTHER=0x400
};
unsigned int medius_uart_vfs_fifo_available(int port);
void medius_uart_vfs_fifo_write_char(int port,int character);
int medius_uart_vfs_fifo_read_char(int port);
int medius_uart_vfs_flush(int port,int queue_selector);
int medius_uart_vfs_drain(int port);
int medius_uart_vfs_get_attributes(int port,struct termios *attributes);
int medius_uart_vfs_set_attributes(int port,int action,const struct termios *attributes);
int medius_uart_vfs_access(const char *path,int access_mode);
int medius_uart_vfs_open(const char *path,int flags,int mode);
int medius_uart_vfs_control(int port,int command,int argument);
int medius_uart_vfs_close(int port);
int medius_uart_vfs_write(int port,const void *data,unsigned int length);
int medius_uart_vfs_register(void);
int medius_uart_vfs_status(int port,VfsStat *status);
int medius_uart_vfs_sync(int port);
int medius_uart_vfs_read(int port,void *data,unsigned int length);
#define FUN_42021acc medius_uart_vfs_fifo_available
#define FUN_42021ae4 medius_uart_vfs_fifo_write_char
#define FUN_42021b0c medius_uart_vfs_fifo_read_char
#define uart_tcflush medius_uart_vfs_flush
#define uart_tcdrain medius_uart_vfs_drain
#define uart_tcgetattr medius_uart_vfs_get_attributes
#define uart_tcsetattr medius_uart_vfs_set_attributes
#define FUN_42022374 medius_uart_vfs_access
#define FUN_420223e0 medius_uart_vfs_open
#define FUN_4202244c medius_uart_vfs_control
#define FUN_420224a0 medius_uart_vfs_close
#define FUN_420224b8 medius_uart_vfs_write
#define FUN_42022524 medius_uart_vfs_register
#define FUN_42022540 medius_uart_vfs_status
#define FUN_4202256c medius_uart_vfs_sync
#define FUN_420225a8 medius_uart_vfs_read

/* Selection arguments: three borrowed 64-bit fd_sets and their saved masks.
 * Volatile fields preserve native snapshots/reloads across wake callbacks. */
typedef struct MediusUartSelectArguments {
    volatile VfsSelectSemaphore semaphore; /* +0x00: full 8-byte value */
    fd_set * volatile read_set;             /* +0x08 */
    fd_set * volatile write_set;            /* +0x0c */
    fd_set * volatile error_set;            /* +0x10 */
    volatile fd_set original_read;          /* +0x14 */
    volatile fd_set original_write;         /* +0x1c */
    volatile fd_set original_error;         /* +0x24 */
} MediusUartSelectArguments;                 /* 44 bytes */
typedef void (*MediusUartSelectNotify)(int port,int notification,int *task_woken);
/* ESP-IDF ring-buffer control layout, 112 bytes. Typed callback boundaries
 * describe their ABI; each callback implementation retains its own review.
 * Volatile fields preserve observed native sampling/publication order. */
typedef struct MediusRingbuffer MediusRingbuffer;
typedef int (*MediusRingCheckFits)(MediusRingbuffer *,size_t);
typedef void (*MediusRingCopyItem)(MediusRingbuffer *,const unsigned char *,size_t);
typedef void *(*MediusRingGetItem)(MediusRingbuffer *,int *,size_t,size_t *);
typedef void (*MediusRingReturnItem)(MediusRingbuffer *,unsigned char *);
typedef size_t (*MediusRingGetMaxSize)(MediusRingbuffer *);
typedef struct MediusRingItemHeader {
    volatile size_t length;
    volatile unsigned int flags;
} MediusRingItemHeader;
struct MediusRingbuffer {
    size_t storage_size;                         /* +0x00 */
    volatile size_t max_item_size;              /* +0x04 */
    volatile unsigned int flags;                /* +0x08 */
    MediusRingCheckFits volatile check_fits;     /* +0x0c */
    MediusRingCopyItem volatile copy_item;       /* +0x10 */
    MediusRingGetItem volatile get_item;         /* +0x14 */
    MediusRingReturnItem volatile return_item;   /* +0x18 */
    MediusRingGetMaxSize get_max_size;           /* +0x1c */
    unsigned char * volatile acquire;           /* +0x20 */
    unsigned char * volatile write;             /* +0x24 */
    unsigned char * volatile read;              /* +0x28 */
    unsigned char * volatile free;              /* +0x2c */
    unsigned char * volatile head;              /* +0x30 */
    unsigned char * volatile tail;              /* +0x34 */
    volatile int items_waiting;                 /* +0x38 */
    RtosList waiting_to_send;              /* +0x3c */
    RtosList waiting_to_receive;           /* +0x50 */
    RtosQueue * volatile queue_set;        /* +0x64 */
    PortMuxWords lock;                    /* +0x68 */
};
/* Accessed UART-driver prefix only; allocation may include more fields.
 * Unknown regions retain their offsets. Byte stash/full fields are not words. */
typedef struct MediusUartDriverSelectPrefix {
    unsigned int unreviewed_00[3];
    volatile int mode;              /* +0x0c: 1=RS485 half duplex */
    unsigned int unreviewed_10;
    volatile int buffered_rx_length; /* +0x14 */
    volatile unsigned char rx_buffer_full; /* +0x18 */
    unsigned char padding_19[3];
    unsigned char * volatile rx_stash; /* +0x1c */
    volatile unsigned char rx_stash_length; /* +0x20 */
    unsigned char padding_21[3];
    volatile unsigned int rx_interrupt_user_mask; /* +0x24 */
    volatile int pattern_write;     /* +0x28 */
    volatile int pattern_read;      /* +0x2c */
    volatile int pattern_length;             /* +0x30 */
    volatile int * volatile pattern_positions; /* +0x34 */
    unsigned int unreviewed_38[7];
    MediusUartSelectNotify volatile select_notify; /* +0x54 */
    unsigned int unreviewed_58;
    MediusRingbuffer * volatile rx_ring;  /* +0x5c */
    unsigned int unreviewed_60;
    RtosQueue * volatile rx_mutex;  /* +0x64 */
    RtosQueue * volatile tx_mutex;  /* +0x68 */
    unsigned int unreviewed_6c;
    RtosQueue * volatile tx_done_sem; /* +0x70 */
} MediusUartDriverSelectPrefix;           /* 116-byte accessed prefix */
#define MEDIUS_UART_DRIVER_SELECT_OBJECTS ((MediusUartDriverSelectPrefix * volatile *)0x3fca7810U)
#define MEDIUS_UART_DRIVER_RX_LOCK(port) ((PortMuxWords *)(0x3fc9dc64U + 48U*(unsigned int)(port)))
#define MEDIUS_UART_DRIVER_SELECT_LOCK ((PortMuxWords *)0x3fc9dc50U)
#define MEDIUS_UART_DRIVER_LOG_TAG ((const char *)0x3c041d40U)
#define MEDIUS_UART_SELECT_REGISTRY_LOCK ((PortMuxWords *)0x3fc9dbd0U)
#define MEDIUS_UART_SELECT_REGISTRY_COUNT (*(volatile int *)0x3fca7808U)
#define MEDIUS_UART_SELECT_REGISTRY (*(MediusUartSelectArguments ** volatile *)0x3fca780cU)
#define MEDIUS_UART_SELECT_REFERENCE_COUNTS ((volatile unsigned int *)0x3fca77fcU)
void medius_uart_select_notify_isr(int port,int notification,int *task_woken);
int medius_uart_driver_get_buffered_length(unsigned int port,unsigned int *length);
int medius_uart_driver_is_installed(unsigned int port);
void medius_uart_driver_set_select_notify(unsigned int port,MediusUartSelectNotify callback);
PortMuxWords *medius_uart_driver_get_select_lock(void);
int medius_uart_vfs_end_select(void *arguments);
int medius_uart_vfs_start_select(int count,fd_set *read_set,fd_set *write_set,
    fd_set *error_set,VfsSelectSemaphore semaphore,void **end_arguments);
void medius_vfs_select_triggered(VfsSelectSemaphore semaphore);
void medius_vfs_select_triggered_isr(VfsSelectSemaphore semaphore,int *task_woken);
#define FUN_4037f8b4 medius_uart_select_notify_isr
#define FUN_42008878 medius_uart_driver_get_buffered_length
#define FUN_42008ac4 medius_uart_driver_is_installed
#define FUN_42008ae0 medius_uart_driver_set_select_notify
#define FUN_42008af8 medius_uart_driver_get_select_lock
#define FUN_42021b34 medius_uart_vfs_end_select
#define FUN_42021bf4 medius_uart_vfs_start_select
#define FUN_42032f30 medius_vfs_select_triggered
#define FUN_4038d550 medius_vfs_select_triggered_isr

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
#define UART_DRIVER_CONTEXTS ((UartDriverContext *)0x3fc9dc58U)
#define UART_LOG_TAG ((const char *)0x3c041d40U)
#define MEDIUS_UART_SYSTEM_RESET0 (*(volatile unsigned int *)0x600c0020U)
#define MEDIUS_UART_SYSTEM_CLOCK0 (*(volatile unsigned int *)0x600c0018U)
void uart_pattern_queue_update(int port,int consumed_bytes);
int uart_set_word_length(unsigned int port,unsigned int data_bits);
int uart_get_word_length(unsigned int port,unsigned int *data_bits);
int uart_set_stop_bits(unsigned int port,unsigned int stop_bits);
int uart_get_stop_bits(unsigned int port,unsigned int *stop_bits);
int uart_set_parity(unsigned int port,unsigned int parity_mode);
int uart_get_parity(unsigned int port,unsigned int *parity_mode);
int uart_get_baudrate(unsigned int port,unsigned int *baud);
void uart_hal_rxfifo_rst(UartHal *hal);
void uart_hal_get_baudrate(UartHal *hal,unsigned int *baud,unsigned int source_hz);
void uart_hal_get_stop_bits(UartHal *hal,unsigned int *stop_bits);
void uart_hal_get_data_bit_num(UartHal *hal,unsigned int *data_bits);
void uart_hal_get_parity(UartHal *hal,unsigned int *parity_mode);
void uart_hal_get_sclk(UartHal *hal,unsigned int *source_clock);
void uart_hal_set_stop_bits(UartHal *hal,unsigned int stop_bits);
void uart_hal_set_data_bit_num(UartHal *hal,unsigned int data_bits);
void uart_hal_set_parity(UartHal *hal,unsigned int parity_mode);
#define FUN_4201eabc uart_hal_get_sclk
#define FUN_4201eae0 uart_hal_get_baudrate

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
#define UART_SIGNAL_CONNECTIONS ((const volatile UartSignalConnection *)0x3c05129cU)
#define UART_CONSOLE_PORT 0

void uart_hal_txfifo_rst(UartHal *hal);
void uart_hal_set_hw_flow_ctrl(UartHal *hal,unsigned int mode,unsigned char threshold);
void uart_hal_set_tx_idle_num(UartHal *hal,unsigned int idle_count);
void uart_hal_init(UartHal *hal,unsigned int port);
bool periph_rtc_dig_clk8m_enable(void);
void rtc_dig_clk8m_enable(void);
void rtc_dig_clk8m_disable(void);
int esp_clk_tree_enable_src(unsigned int source_clock,bool enable);
#define RTC_DIGITAL_CLOCK_REGISTER (*(volatile unsigned int *)0x60008074U)
#define RTC_DIGITAL_RC_FAST_LOCK ((PortMuxWords *)0x3fc9e334U)
#define RTC_DIGITAL_RC_FAST_REFERENCE_COUNT (*(volatile unsigned char *)0x3fccbba4U)
#define RTC_DIGITAL_RC_FAST_FREQUENCY_HZ (*(volatile unsigned int *)0x3fccbba0U)
#define FUN_40385e44 uart_hal_txfifo_rst
#define FUN_4201386c uart_hal_set_hw_flow_ctrl
#define FUN_420138dc uart_hal_set_tx_idle_num
#define FUN_42013900 uart_hal_init
#define FUN_42013b64 periph_rtc_dig_clk8m_enable
#define FUN_4201ebd8 esp_clk_tree_enable_src
#define FUN_403805b4 rtc_dig_clk8m_enable
#define FUN_403805d4 rtc_dig_clk8m_disable

/* UART completion/flushing and ring-buffer borrow/copy interfaces. */
int uart_wait_tx_done(unsigned int port,unsigned int ticks_to_wait);
int uart_flush_input(unsigned int port);
void *prvAcquireItemNoSplit(MediusRingbuffer *ring,size_t item_bytes);
int prvSendAcquireGeneric(MediusRingbuffer *ring,const void *item,void **acquired,
                          size_t item_bytes,unsigned int ticks_to_wait);
int prvReceiveGeneric(MediusRingbuffer *ring,void **head_item,void **tail_item,
                       size_t *head_bytes,size_t *tail_bytes,size_t max_bytes,
                       unsigned int ticks_to_wait);
int xRingbufferSend(MediusRingbuffer *ring,const void *item,size_t item_bytes,
                    unsigned int ticks_to_wait);
void *xRingbufferReceive(MediusRingbuffer *ring,size_t *item_bytes,unsigned int ticks_to_wait);
void vRingbufferReturnItem(MediusRingbuffer *ring,void *item);

/* Scheduler delay-list globals, protected by kernel mux. */
#define RTOS_CURRENT_TASKS ((RtosTask * volatile *)0x3fca76c8U)
#define RTOS_TERMINATION_LIST ((RtosList *)0x3fca7468U)
#define RTOS_SUSPENDED_LIST ((RtosList *)0x3fca7450U)
#define RTOS_OVERFLOW_DELAYED_LIST (*(RtosList * volatile *)0x3fca74a4U)
#define RTOS_ACTIVE_DELAYED_LIST (*(RtosList * volatile *)0x3fca74a8U)
#define RTOS_NEXT_UNBLOCK_TICK (*(volatile unsigned int *)0x3fca7428U)
#define RTOS_KERNEL_LOCK ((PortMuxWords *)0x3fc9db00U)
void prvAddCurrentTaskToDelayedList(unsigned int ticks_to_wait,int can_block_indefinitely);
unsigned int xTaskGetTickCountFromISR(void);
void vListInsert(RtosList *list,RtosListItem *item);
unsigned int uxListRemove(RtosListItem *item);

/* Idle-task deferred deletion and IPC worker globals; native per-core slots. */
#define RTOS_PENDING_DELETIONS (*(volatile unsigned int *)0x3fca7464U)
#define RTOS_DELETION_TASK_COUNT (*(volatile unsigned int *)0x3fca744cU)
#define RTOS_TERMINATION_END ((RtosListItem *)0x3fca7470U)
#define IPC_DISPATCH_STATE ((IpcDispatchState *)0x3fca71d8U)
#define IPC_ISR_STALL_STATE (*(volatile unsigned int *)0x3fca71c8U)
void prvIdleTask(void *argument);
void prvDeleteTCB(RtosTask *task);
void newlib_reclaim_reent(NewlibReent *reent) __asm__("_reclaim_reent");
void ipc_task(void *argument);
void esp_ipc_isr_init(void);
void esp_ipc_isr_port_init(int core);
void esp_vApplicationIdleHook(void);
void esp_cpu_wait_for_intr(void);
#define FUN_42003294 esp_ipc_isr_init
#define FUN_420032b4 esp_ipc_isr_port_init
#define FUN_4200381c esp_vApplicationIdleHook
#define FUN_4037fa30 esp_cpu_wait_for_intr

/* Cache sync/freeze locks and S3 hardware/ROM interfaces. */
#define CACHE_SYNC_LOCK ((PortMuxWords *)0x3fc9e2acU)
#define CACHE_FREEZE_LOCK ((PortMuxWords *)0x3fc9e2b4U)
#define CACHE_LOG_TAG ((const char *)0x3fca6a54U)
#define EXTMEM_CACHE_STATE (*(volatile unsigned int *)0x600c4130U)
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
#define FUN_40380c04 esp_cache_sync_ops_enter_critical_section
#define FUN_40380c18 esp_cache_sync_ops_exit_critical_section
#define FUN_40380c28 esp_cache_get_alignment
#define FUN_40380c84 esp_cache_freeze_ext_mem_cache
#define FUN_40380c94 esp_cache_unfreeze_ext_mem_cache
#define FUN_40380ca4 esp_cache_freeze_caches_disable_interrupts
#define FUN_40380ce4 esp_cache_unfreeze_caches_enable_interrupts
#define FUN_403842d8 cache_hal_freeze
#define FUN_403842fc cache_hal_unfreeze
#define FUN_40384324 cache_hal_get_cache_line_size
#define FUN_403810a4 Cache_Freeze_ICache_Enable
#define FUN_403810c0 Cache_Freeze_DCache_Enable

/* Partial EXTMEM enable-control view, matching the device view. */
typedef struct ExtmemCacheControls {
    volatile unsigned int dcache_ctrl; /* +0x00 */
    unsigned char unknown4[92];
    volatile unsigned int icache_ctrl; /* +0x60 */
} ExtmemCacheControls;
#define EXTMEM_CACHE ((ExtmemCacheControls *)0x600c4000U)
bool cache_hal_is_cache_enabled(unsigned int level,CacheType type);

bool cache_hal_invalidate_addr(unsigned int start,unsigned int length);
int Cache_Invalidate_Addr(unsigned int start,unsigned int length); /* ROM400016b0 */
#define FUN_40384260 cache_hal_is_cache_enabled
#define FUN_40384298 cache_hal_invalidate_addr

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
#define FUN_40380ac4 rtc_time_us_to_slowclk
#define FUN_40380b40 rtc_time_get
#define FUN_40380b68 rtc_clk_freq_cal
#define FUN_40380b84 enable_timer_group0_for_calibration

/* Partial RTC clock register prefix and TIMG0 calibration window. */
typedef struct RtcCalibrationClockRegisters {
    unsigned int reserved_00[7];
    volatile unsigned int timer1;       /* +0x1c: RC_FAST wait count */
    unsigned int reserved_20[16];
    volatile unsigned int xtal_control; /* +0x60: crystal power/control */
    unsigned int reserved_64[4];
    volatile unsigned int clock_conf;   /* +0x74: source/enables */
    unsigned int reserved_78[18];
    volatile unsigned int xtal_store;   /* +0xc0: duplicate16-bit MHz */
    unsigned int reserved_c4[5];
    volatile unsigned int pad_hold;     /* +0xd8: RTC pad holds */
} RtcCalibrationClockRegisters;   /* 220-byte partial prefix */
typedef struct RtcCalibrationTimerRegisters {
    volatile unsigned int configuration; /* TIMG0+0x68 */
    volatile unsigned int value;         /* +0x6c */
    unsigned int reserved_70[4];
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
#define RTC_CLOCK_LOG_TAG ((const char *)0x3fca68dcU)
void rtc_clk_8m_enable(unsigned char fast_enabled,unsigned char divided_enabled);
unsigned int rtc_clk_slow_src_get(void);
unsigned int rtc_clk_xtal_freq_get(void);
unsigned int rtc_clk_cal_internal(unsigned int selection,unsigned int cycles);
unsigned int rtc_clk_cal(unsigned int selection,unsigned int cycles);
/* ROM40002544: two unsigned64 arguments and unsigned64 result, not four
 * invented scalar parameters. Named call retains native division boundaries. */
extern unsigned long long rom_unsigned_divide_u64(unsigned long long numerator,
    unsigned long long denominator) __asm__("__udivdi3");
#define FUN_4037fdcc rtc_clk_8m_enable
#define FUN_4037ff20 rtc_clk_slow_src_get
#define FUN_4037ffac rtc_clk_xtal_freq_get
#define FUN_40380774 rtc_clk_cal_internal
#define FUN_40380a24 rtc_clk_cal

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
#define FUN_4037fd7c rtc_clk_32k_disable_external
#define FUN_4037fe54 rtc_clk_8md256_enabled
#define FUN_4037ff40 rtc_clk_slow_freq_get_hz
#define FUN_4037ff68 rtc_clk_fast_src_set
#define FUN_4037ffec rtc_clk_cpu_freq_mhz_to_config

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
    ESP_SLEEP_LP_USE_XTAL_MODE = 6
};
typedef int SleepSubmodeCounts[7];
#define SLEEP_SUBMODE_COUNTS ((int *)0x500000a8U)
#define SLEEP_SUBMODE_NAMES ((const char * const volatile *)0x3c0458c8U)
#define SLEEP_CONFIGURATION_LOCK ((PortMuxWords *)0x3fc9dac0U)
int sleep_submode_adjust(unsigned int mode,unsigned int activate);
void sleep_submode_clear(unsigned int mode);
int esp_sleep_sub_mode_config(unsigned int mode,unsigned char activate);
int esp_sleep_sub_mode_force_disable(unsigned int mode);
int *esp_sleep_sub_mode_dump_config(NewlibFile *stream);
void rtc_clk_slow_src_set(unsigned int source);
#define FUN_4037fe6c rtc_clk_slow_src_set
#define FUN_42006ddc sleep_submode_adjust
#define FUN_42006e44 sleep_submode_clear
#define FUN_42006e78 esp_sleep_sub_mode_config
#define FUN_42006e90 esp_sleep_sub_mode_force_disable
#define FUN_42006ea4 esp_sleep_sub_mode_dump_config

/* Partial SYSTEM clock-control prefix, not the complete peripheral. */
typedef struct RtcCpuSystemRegisters {
    unsigned int reserved_00[4];
    volatile unsigned int cpu_period; /* +0x10: period/PLL-frequency bits */
    volatile unsigned int memory_power_mask; /* +0x14 */
    unsigned int reserved_18[18];
    volatile unsigned int system_clock; /* +0x60: divider/source */
} RtcCpuSystemRegisters;
/* Low-byte access view of four adjacent 32-bit trim globals, at 0/4/8/12. */
typedef struct RtcCpuBiasCalibrationBytes {
    volatile unsigned char rtc_non240;
    unsigned char reserved_01[3];
    volatile unsigned char digital_non240;
    unsigned char reserved_05[3];
    volatile unsigned char rtc_240;
    unsigned char reserved_09[3];
    volatile unsigned char digital_240;
    unsigned char reserved_0d[3];
} RtcCpuBiasCalibrationBytes;
#define RTC_CPU_SYSTEM_REGISTERS ((RtcCpuSystemRegisters *)0x600c0000U)
#define RTC_CPU_DATE_REGISTER (*(volatile unsigned int *)0x600081fcU)
#define RTC_CACHED_APB_HZ (*(volatile unsigned int *)0x3fca7404U)
#define RTC_CACHED_PLL_MHZ (*(volatile unsigned int *)0x3fca7408U)
#define RTC_CPU_BIAS_CALIBRATION ((RtcCpuBiasCalibrationBytes *)0x3fc9da64U)
void rtc_clk_cpu_freq_get_config(RtcCpuFrequencyConfig *configuration);
void rtc_clk_cpu_freq_to_xtal(unsigned int target_mhz,unsigned int divider);
void rtc_clk_cpu_set_to_default_config(void);
void rtc_clk_cpu_freq_set_xtal(void);
void esp_rom_set_cpu_ticks_per_us(unsigned int ticks); /* ROM40001a4c */
void regi2c_ctrl_write_reg_mask(unsigned char block,unsigned char host_id,
    unsigned char reg_address,unsigned char msb,unsigned char lsb,unsigned char value);
#define FUN_4038004c rtc_clk_cpu_freq_get_config
#define FUN_403802dc rtc_clk_cpu_freq_to_xtal
#define FUN_40380578 rtc_clk_cpu_set_to_default_config
#define FUN_40380588 rtc_clk_cpu_freq_set_xtal

/* RTC PLL configuration and its single-read consumer-count decision. */
#define RTC_PLL_CONSUMER_COUNT (*(volatile unsigned int *)0x3fca7400U)
#define RTC_PLL_ANALOG_CONFIGURATION (*(volatile unsigned int *)0x6000e040U)
void rtc_clk_cpu_freq_to_pll_mhz(unsigned int target_mhz);
void rtc_clk_cpu_freq_set_config(const RtcCpuFrequencyConfig *configuration);
void rtc_reconfigure_active_pll(void);
void regi2c_ctrl_write_reg(unsigned char block,unsigned char host_id,
    unsigned char reg_address,unsigned char value);
#define FUN_40380100 rtc_clk_cpu_freq_to_pll_mhz
#define FUN_4038038c rtc_clk_cpu_freq_set_config
#define FUN_403758e4 rtc_reconfigure_active_pll

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
#define FUN_403805f4 rtc_sleep_pu
#define FUN_4037fcb0 rtc_clk_32k_enable

/* MSPI register view; existing clock/pad offsets are retained. */
typedef struct MspiRegisters {
    volatile unsigned int cmd,addr,ctrl;
    volatile unsigned int ctrl1,ctrl2;
    volatile unsigned int flash_clock; /* +0x14 */
    volatile unsigned int user,user1,user2,mosi_dlen,miso_dlen;
    unsigned int reserved_2c[2];
    volatile unsigned int misc; /* +0x34 */
    unsigned int reserved_38;
    volatile unsigned int cache_fctrl; /* +0x3c */
    unsigned int reserved_40[4];
    volatile unsigned int psram_clock; /* +0x50 */
    unsigned int reserved_54;
    volatile unsigned int data[16]; /* +0x58..0x94 */
    volatile unsigned int wait_idle_ctrl; /* +0x98 */
    volatile unsigned int flash_suspend_command; /* +0x9c, FLASH_PER/PES */
    volatile unsigned int flash_suspend_control; /* +0xa0 */
    volatile unsigned int suspend_status; /* +0xa4 */
    volatile unsigned int timing_cali; /* +0xa8 */
    unsigned int reserved_ac[13];
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
void mspi_timing_change_speed_mode_cache_safe(unsigned char value);
#define MSPI_DRIVE_PAD_TABLE ((const void *)0x3fca68b8U)
#define FUN_4037fb40 mspi_timing_config_set_flash_clock
#define FUN_4037fbac mspi_timing_config_set_psram_clock
#define FUN_4037fc04 mspi_timing_change_speed_mode_cache_safe
#define FUN_4037fc40 mspi_set_all_pin_drive_3

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
void rtc_init(unsigned int configuration);
void sar_periph_ctrl_init(void);
unsigned char regi2c_ctrl_read_reg_mask(unsigned char block,unsigned char host_id,
    unsigned char reg_address,unsigned char msb,unsigned char lsb);
#define FUN_42023190 rtc_bias_from_efuse
#define FUN_42023240 rtc_init
#define FUN_42023948 sar_periph_ctrl_init

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
unsigned int gdma_ahb_hal_get_eof_desc_addr(GdmaHal *hal,int channel_id,int direction,unsigned char success);
unsigned int gdma_ahb_hal_read_intr_status(GdmaHal *hal,int channel_id,int direction,unsigned char raw);
void gdma_ahb_hal_reset(GdmaHal *hal,int channel_id,int direction);
void gdma_ahb_hal_start_with_desc(GdmaHal *hal,int channel_id,int direction,unsigned int descriptor_address);
void gdma_ahb_hal_stop(GdmaHal *hal,int channel_id,int direction);
void gdma_ahb_hal_set_strategy(GdmaHal *hal,int channel_id,int direction,unsigned char owner_check,unsigned char descriptor_writeback,unsigned char eof_till_popped);
void gdma_ahb_hal_set_burst_size(GdmaHal *hal,int channel_id,int direction,unsigned int burst_bytes);
void gdma_ahb_hal_init(GdmaHal *hal,const GdmaHalConfig *configuration);
void gdma_ahb_hal_set_priority(GdmaHal *hal,int channel_id,int direction,unsigned int priority);
void gdma_ahb_hal_disconnect_peri(GdmaHal *hal,int channel_id,int direction);
void gdma_ahb_hal_enable_burst(GdmaHal *hal,int channel_id,int direction,unsigned char data_burst,unsigned char descriptor_burst);
unsigned int gdma_ahb_hal_get_intr_status_reg(GdmaHal *hal,int channel_id,int direction);
void gdma_ahb_hal_enable_intr(GdmaHal *hal,int channel_id,int direction,unsigned int events,unsigned char enabled);
void gdma_ahb_hal_connect_peri(GdmaHal *hal,int channel_id,int direction,int peripheral_type,int peripheral_id);
#define GDMA_AHB_PRIVATE ((const GdmaPrivateData *)0x3fc9e370U)
#define FUN_40384358 gdma_ahb_hal_append
#define FUN_40384394 gdma_ahb_hal_clear_intr
#define FUN_403843b4 gdma_ahb_hal_get_eof_desc_addr
#define FUN_403843e8 gdma_ahb_hal_read_intr_status
#define FUN_40384420 gdma_ahb_hal_reset
#define FUN_40384474 gdma_ahb_hal_start_with_desc
#define FUN_403844e0 gdma_ahb_hal_stop
#define FUN_42023abc gdma_ahb_hal_set_strategy
#define FUN_42023b44 gdma_ahb_hal_set_burst_size
#define FUN_42023bb8 gdma_ahb_hal_init
#define FUN_42023c1c gdma_ahb_hal_set_priority
#define FUN_42023c60 gdma_ahb_hal_disconnect_peri
#define FUN_42023cac gdma_ahb_hal_enable_burst
#define FUN_42023d2c gdma_ahb_hal_get_intr_status_reg
#define FUN_42023d4c gdma_ahb_hal_enable_intr
#define FUN_42023da4 gdma_ahb_hal_connect_peri

/* GDMA dispatch layer: typed calls through the native HAL slots. */
void gdma_hal_clear_intr(GdmaHal *hal,int channel_id,int direction,unsigned int events);
void gdma_hal_start_with_desc(GdmaHal *hal,int channel_id,int direction,
    unsigned int descriptor_address);
void gdma_hal_deinit(GdmaHal *hal);
void gdma_hal_set_priority(GdmaHal *hal,int channel_id,int direction,unsigned int priority);
void gdma_hal_connect_peri(GdmaHal *hal,int channel_id,int direction,
    int peripheral_type,int peripheral_id);
void gdma_hal_disconnect_peri(GdmaHal *hal,int channel_id,int direction);
void gdma_hal_enable_burst(GdmaHal *hal,int channel_id,int direction,
    unsigned char data_burst,unsigned char descriptor_burst);
void gdma_hal_set_burst_size(GdmaHal *hal,int channel_id,int direction,unsigned int burst_bytes);
void gdma_hal_enable_intr(GdmaHal *hal,int channel_id,int direction,
    unsigned int events,unsigned char enabled);
#define FUN_4038451c gdma_hal_clear_intr
#define FUN_40384530 gdma_hal_start_with_desc
#define FUN_42023e48 gdma_hal_deinit
#define FUN_42023e54 gdma_hal_set_priority
#define FUN_42023e68 gdma_hal_connect_peri
#define FUN_42023e7c gdma_hal_disconnect_peri
#define FUN_42023e8c gdma_hal_enable_burst
#define FUN_42023ea4 gdma_hal_set_burst_size
#define FUN_42023eb8 gdma_hal_enable_intr

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
#define GDMA_PLATFORM ((GdmaPlatform *)0x3fc9e360U)
#define FUN_42022750 gdma_release_group_handle
#define FUN_420227c8 gdma_release_pair_handle
#define FUN_42022824 gdma_del_rx_channel
#define FUN_4202289c gdma_del_tx_channel
#define FUN_42022ec8(channel,type,id,bus) gdma_connect((GdmaChannel *)(uintptr_t)(channel),(GdmaTrigger){(type),(id),(bus)})

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
int do_allocate_gdma_channel(const GdmaAllocConfig *configuration,GdmaChannel **out);
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
void ledc_hal_set_fade_param(const LedcHal *hal,int channel_id,unsigned int range,
    unsigned int direction,unsigned int cycle,unsigned int scale,unsigned int step);
void ledc_hal_ls_channel_update(LedcHal *hal,int channel_id);
void ledc_hal_set_hpoint(LedcHal *hal,int channel_id,unsigned int hpoint);
#define FUN_40384544 ledc_hal_set_duty_start
#define FUN_4038456c ledc_hal_set_duty_int_part
#define FUN_403845a4 ledc_hal_set_fade_param
#define FUN_4038463c ledc_hal_ls_channel_update
#define FUN_40384664 ledc_hal_set_hpoint

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
#define LEDC_CONTEXT_SLOT ((LedcDriverContext *volatile *)0x3fccbbdcU)
#define LEDC_FADE_SLOTS ((LedcFadePrefix *volatile *)0x3fccbbbcU)
#define LEDC_ALLOCATION_MUTEX ((NewlibLock *)0x3fccbbb8U)
#define LEDC_SPINLOCK ((PortMuxWords *)0x3fc9e358U)
#define LEDC_SIGNAL_BASES ((const unsigned char *)0x3c0519bcU)
#define FUN_420155f0 ledc_hal_init
#define FUN_4201403c ledc_speed_mode_ctx_create
#define FUN_420140b8 ledc_fade_hw_acquire
#define FUN_42014110 ledc_timer_clk_src_set_xpd_in_sleep
#define FUN_420149b8 ledc_set_pin_internal

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
#define LEDC_RC_FAST_HZ (*(volatile unsigned int *)0x3fccbbb4U)
#define LEDC_CLOCK_CHOICES ((const int *)0x3c051958U)
/* Existing RC_FAST frequency getter; its body has a separate queued review. */
unsigned int periph_rtc_dig_clk8m_get_freq(void);
#define FUN_42013bc0 periph_rtc_dig_clk8m_get_freq
#define FUN_42014008 ledc_slow_clk_calibrate

#define ATOMIC_OPERATION_LOCK ((PortMuxWords *)0x3fc9e348U)
#define GPIO_RESERVED_MASK ((volatile unsigned long long *)0x3fc9e340U)
unsigned long long atomic_fetch_or_u64(volatile unsigned long long *address,unsigned long long mask,int memory_order);
#define GPIO_SLEEP_LOCK ((PortMuxWords *)0x3fc9e28cU)
#define GPIO_IOMUX_TABLE ((volatile unsigned int * const *)0x3c0511d8U)

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
#define GPIO_HAL_SLOT ((GpioHal *volatile *)0x3fc9e288U)

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
void led_timer_cb(void *argument);
void led_initialize(int gpio_pin,unsigned char active_high);
void led_set_status(unsigned int status);
extern long long signed_remainder_i64(long long numerator,long long denominator) __asm__("__moddi3");
#define LED_RUNTIME ((LedRuntime *)0x3fccbb0cU)
#define LED_OUTPUT ((LedOutputCache *)0x3fc9de4cU)
void medius_host_led_override_set(unsigned char mode,unsigned char brightness);
#define FUN_4200f588 led_initialize
#define FUN_4200f614 led_set_status

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
#define UPDATE_STORAGE_OPERATIONS ((const UpdateStorageOps *)0x3c050bfcU)
#define UPDATE_HASH_OPERATIONS ((const UpdateHashOps *)0x3c050bf0U)
#define UPDATE_SESSION ((UpdateSession *)0x3fcb912cU)
#define FUN_4200ef58 update_session_initialize
#define FUN_4200ef70 update_session_begin
#define FUN_4200f004 update_session_finish
#define FUN_4201e908 update_session_write
#define FUN_4201ea34 update_session_abort
#define FUN_4201ea50 update_session_is_staged
#define FUN_4201ea58 update_session_is_active
#define FUN_4200f31c update_storage_operations
#define FUN_4200f324 update_hash_operations
#define FUN_4201ea60 update_backend_context

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
    void *flash_chip;
    unsigned int type;
    unsigned int subtype;
    unsigned int address;
    unsigned int size;
    unsigned int erase_size;
    char label[17];
    unsigned char encrypted;
    unsigned char readonly;
    unsigned char reserved_2b;
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
#define UPDATE_BACKEND ((UpdateBackend *)0x3fccba84U)
#define UPDATE_LOG_TAG ((const char *)0x3c042e98U)
/* Existing SDK call boundaries; their implementations have separate reviews. */
const EspPartition * esp_ota_get_next_update_partition(const EspPartition *start);
int esp_ota_begin(const EspPartition *partition,unsigned int size,volatile unsigned int *handle);
int esp_ota_write(unsigned int handle,const void *payload,unsigned int length);
int esp_ota_end(unsigned int handle);
int esp_ota_abort(unsigned int handle);
extern int mbedtls_sha256_update(Sha256Context *context,const unsigned char *payload,size_t length);
extern int mbedtls_sha256_finish(Sha256Context *context,unsigned char output[32]);
#define FUN_4200f120 update_flash_begin
#define FUN_4200f0fc update_flash_write
#define FUN_4200f0a4 update_flash_finish
#define FUN_4200f208 update_flash_abort
#define FUN_4200f1dc update_hash_reset
#define FUN_4200f26c update_hash_update
#define FUN_4200f240 update_hash_digest
#define FUN_42014f70 mbedtls_sha256_init
#define FUN_42014f84 mbedtls_sha256_starts
#define FUN_4201ebe0 mbedtls_sha256_free
#define medius_ota_confirm_image confirm_running_image

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
#define OTA_PROBATION ((OtaProbation *)0x3fccba7cU)
#define OTA_PROBATION_LOCK ((PortMuxWords *)0x3fc9de44U)
#define OTA_LOG_HOOK medius_host_log_formatted
int esp_ota_set_boot_partition(const EspPartition *partition);
int esp_ota_get_state_partition(const EspPartition *partition,unsigned int *state);
const EspPartition *esp_ota_get_running_partition(void);
int esp_ota_current_ota_is_workable(unsigned int valid);
void medius_host_reboot_to_download(void);
void medius_host_reboot_to_run(void);
#define FUN_4200f2e4 update_activate_staged
#define FUN_4200f32c update_running_slot_info
#define FUN_4200f380 ota_start_grace
#define FUN_4200f414 confirm_running_image
#define FUN_42010fe0 esp_ota_mark_app_valid_cancel_rollback
#define FUN_42010fec esp_ota_mark_app_invalid_rollback_and_reboot

/* Native reply stack packing: only first5 bytes are transmitted. */
typedef struct MediusUpdateAnswerStorage {
    unsigned int first_four_bytes;
    unsigned char detail_most_significant_byte;
    unsigned char unused_padding[3];
} MediusUpdateAnswerStorage;
typedef struct MediusUpdateFirmwareInfo {
    unsigned char major,minor,patch,slot,state,staged;
} MediusUpdateFirmwareInfo;
#define MEDIUS_HOST_UPDATE_LAST_ACTIVITY_US (*(volatile unsigned int *)0x3fcb9128U)
unsigned int medius_link_send_now(unsigned char type,unsigned char flags,const void *payload,unsigned short length);
unsigned int medius_host_update_send_answer(unsigned int status,unsigned int detail);
void medius_host_update_session_init(void);
void medius_host_update_link_dispatch(unsigned char opcode,const unsigned char *payload,unsigned short length);
void medius_host_update_check_timeout(void);
#define FUN_4200c3e8 medius_host_update_send_answer
#define FUN_4200c464 medius_host_update_session_init
#define FUN_4037f714 medius_link_send_now
#define FUN_4200c68c medius_host_update_check_timeout

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
#define FUN_4038487c spi_flash_encryption_hal_enable
#define FUN_403848a0 spi_flash_encryption_hal_disable
#define FUN_403848b8 spi_flash_encryption_hal_prepare
#define FUN_403848f8 spi_flash_encryption_hal_done
#define FUN_4038491c spi_flash_encryption_hal_destroy
#define FUN_4038492c spi_flash_encryption_hal_check
/* Native MMU allocator block44, shared ESP-IDF TAILQ layout on this S3 build. */
struct MmuBlock {
    unsigned int linear_start,linear_end,virtual_start,virtual_end,size,caps;
    unsigned int physical_start,physical_end,target;
    MmuBlock *next;
    MmuBlock **previous_next;
};
#define MMU_CONTEXT ((volatile MmuContext *)0x3fccbb38U)
void mmu_freeze_cache(void);
void mmu_invalidate_cache_range(unsigned int virtual_address,unsigned int size);
void mmu_unfreeze_cache(void);
void mmu_map_region_with_cache(unsigned int target,unsigned int virtual_address,
    unsigned int physical_address,unsigned int size);
void mmu_unmap_region_with_cache(unsigned int virtual_address,unsigned int size);
void mmu_hal_map_region(unsigned int mmu,unsigned int target,unsigned int virtual_address,
    unsigned int physical_address,unsigned int length,unsigned int *mapped_length);
void mmu_hal_unmap_region(unsigned int mmu,unsigned int virtual_address,unsigned int length);
bool mmu_hal_vaddr_to_paddr(unsigned int mmu,unsigned int address,
    unsigned int *physical_address,unsigned int *target);
bool mmu_hal_check_valid_ext_vaddr_region(unsigned int mmu,unsigned int address,
    unsigned int length,unsigned int type_mask);
bool mmu_hal_paddr_to_vaddr(unsigned int mmu,unsigned int physical_address,
    unsigned int target,unsigned int type,unsigned int *virtual_address);
int esp_mmu_paddr_find_caps(unsigned int physical_address,unsigned int *caps);
void esp_cache_freeze_caches_disable_interrupts(void);
void esp_cache_unfreeze_caches_enable_interrupts(void);
void esp_cache_sync_ops_enter_critical_section(void);
void esp_cache_sync_ops_exit_critical_section(void);
bool cache_hal_invalidate_addr(unsigned int address,unsigned int size);
#define FUN_4037c290 mmu_freeze_cache
#define FUN_4037c298 mmu_invalidate_cache_range
#define FUN_4037c2ac mmu_unfreeze_cache
#define FUN_4037c2b4 mmu_map_region_with_cache
#define FUN_4037c364 mmu_unmap_region_with_cache
#define FUN_40384694 mmu_hal_map_region
#define FUN_4038471c mmu_hal_unmap_region
#define FUN_40384784 mmu_hal_vaddr_to_paddr
#define FUN_40384834 mmu_hal_check_valid_ext_vaddr_region
#define FUN_403847d4 mmu_hal_paddr_to_vaddr
#define FUN_4037c37c esp_mmu_paddr_find_caps
typedef struct FlashGuardFunctions {
    void (*start)(void);
    void (*end)(void);
} FlashGuardFunctions;
#define FLASH_GUARD (*(const FlashGuardFunctions *volatile *)0x3fccbb70U)
#define ROM_FLASH_LEGACY (*(RomFlashLegacy *volatile *)0x3fceffe4U)
bool bootloader_flash_is_octal_mode_enabled(void);
void spi_flash_restore_cache(void);
void spi_flash_enable_interrupts_caches_no_os(void);
bool flash_page_is_mapped(unsigned int physical_address,unsigned int *virtual_address);
bool spi_flash_check_and_flush_cache(size_t start_address,size_t length);
void spi_flash_guard_set(const FlashGuardFunctions *functions);
void esp_mspi_pin_init(void);
int spi_flash_init_chip_state(void);
int spi_flash_enable_high_performance_mode(void);
int esp_opiflash_init(unsigned int chip_id) __asm__("FUN_4038d4e8");
#define FUN_4038d4e8 esp_opiflash_init
void esp_rom_opiflash_pin_config(void); /* ROM0x40000894 */
void esp_cache_suspend_ext_mem_cache(void);
void esp_cache_resume_ext_mem_cache(void);
void flash_suspend_cache(void);
void flash_resume_cache(void);
#define FUN_4037c280 bootloader_flash_is_octal_mode_enabled
#define FUN_4037c5a8 spi_flash_enable_interrupts_caches_no_os
#define FUN_4037c5c4 flash_page_is_mapped
#define FUN_4037c60c spi_flash_check_and_flush_cache
#define FUN_4037c668 spi_flash_guard_set
#define FUN_4037c674 esp_mspi_pin_init
#define FUN_4037c68c spi_flash_init_chip_state
#define FUN_4038d33c spi_flash_enable_high_performance_mode
#define FUN_4037c454 flash_suspend_cache
#define FUN_4037c464 flash_resume_cache

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
#define OPI_FLASH_CHIP_REGISTRY ((OpiFlashChipSlot)0x3fc9e2f4U)
#define OPI_FLASH_SELECTED_SLOT (*(OpiFlashChipSlot volatile *)0x3fccbb78U)
#define OPI_FLASH_CHIP_ID (*(volatile unsigned int *)0x3fccbb7cU)
#define MXIC_STR_COMMANDS ((const volatile OpiFlashCommandSet *)0x3fca70fcU)
#define OPI_FLASH_LEGACY_FUNCTIONS ((const volatile RomFlashLegacyFunctions *)0x3fc9e2c0U)
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
#define FUN_403810e4 esp_rom_opiflash_cache_mode_config
#define FUN_4038d344 mxic_probe_octal_flash
#define FUN_4038d388 mxic_disable_dtr_byte_swaps
#define FUN_4038d3a8 mxic_initialize_str_flash
typedef struct MmuHardwareRegion {
    unsigned int start,end,size,bus_id,targets,caps;
} MmuHardwareRegion;
#define MMU_LOCK ((NewlibLock *)0x3fccbb64U)
#define MMU_LOG_TAG (*(const char *volatile *)0x3fca6634U)
void esp_mmu_map_init(void);
int esp_mmu_map_get_max_consecutive_free_block_size(unsigned int caps,unsigned int target,size_t *length);
int esp_mmu_map(unsigned int address,size_t size,unsigned int target,unsigned int caps,int flags,void **output);
int esp_mmu_unmap(void *address);
int esp_mmu_vaddr_to_paddr(void *address,unsigned int *physical_address,unsigned int *target);
#define FUN_420121cc esp_mmu_map_get_max_consecutive_free_block_size
#define MSPI_DEFAULT_PINS ((const volatile unsigned char *)0x3c050f1cU)
unsigned char esp_mspi_get_io(unsigned int signal_role);
void esp_mspi_pin_reserve(void);
unsigned int esp_rom_efuse_get_opiconfig(void);
unsigned int esp_rom_efuse_get_flash_wp_gpio(void); /* ROM0x40001fa4 */
unsigned int esp_rom_efuse_get_flash_gpio_info(void); /* ROM0x40001f74 */
#define FUN_42012988 esp_mspi_get_io
#define FUN_42012a00 esp_mspi_pin_reserve
#define FUN_42013508 esp_rom_efuse_get_opiconfig
typedef struct FlashMappingHandle {
    unsigned int *virtual_addresses;
    int count;
} FlashMappingHandle;
int spi_flash_mmap(size_t address,size_t size,unsigned int memory,
    const void **out_pointer,unsigned int *out_handle);
void spi_flash_munmap(unsigned int handle);
unsigned int spi_flash_mmap_get_free_pages(unsigned int memory);
size_t spi_flash_cache2phys(const void *cached);
bool spi_flash_cache_enabled(void);
#define FUN_42012834 spi_flash_mmap
#define FUN_42012900 spi_flash_munmap
#define FUN_42012944 spi_flash_mmap_get_free_pages
#define FUN_42012964 spi_flash_cache2phys
#define FUN_4037c5b0 spi_flash_cache_enabled

typedef struct EspFlash EspFlash;
typedef struct FlashHostView FlashHostView;
/* ID dispatch erases the first-argument class: either a chip or a host. */
typedef int (*FlashReadIdOperation)(void *,unsigned int *);
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
    int (*common_command)(FlashHostView *,FlashTransaction *);
    FlashReadIdOperation read_id;
    void (*erase_chip)(FlashHostView *);
    void (*erase_sector)(FlashHostView *,unsigned int);
    void (*erase_block)(FlashHostView *,unsigned int);
    int (*read_status)(FlashHostView *,unsigned char *);
    int (*set_write_protect)(FlashHostView *,unsigned char);
    void (*program_page)(FlashHostView *,const void *,unsigned int,unsigned int);
    bool (*supports_direct_write)(FlashHostView *,const void *);
    int (*write_data_slicer)(FlashHostView *,unsigned int,unsigned int,unsigned int *,unsigned int);
    int (*read)(FlashHostView *,void *,unsigned int,unsigned int);
    bool (*supports_direct_read)(FlashHostView *,const void *);
    int (*read_data_slicer)(FlashHostView *,unsigned int,unsigned int,unsigned int *,unsigned int);
    unsigned int (*host_status)(FlashHostView *);
    int (*configure_host_io_mode)(FlashHostView *,unsigned int command,
        unsigned int address_bits,int dummy_base,unsigned int io_mode);
    void (*poll_cmd_done)(FlashHostView *);
    int (*flush_cache)(FlashHostView *,unsigned int address,unsigned int length);
    unsigned int check_suspend_slot;
    void (*resume)(FlashHostView *);
    void (*suspend)(FlashHostView *);
    int (*sus_setup)(FlashHostView *,const struct FlashSuspendCommands *);
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
typedef int (*FlashEraseOperation)(EspFlash *,unsigned int address);
typedef int (*FlashWriteOperation)(EspFlash *,const void *,unsigned int address,unsigned int length);
typedef int (*FlashYieldOperation)(EspFlash *,unsigned int status);
typedef struct FlashTimeouts {
    unsigned int idle_timeout,chip_erase_timeout,block_erase_timeout;
    unsigned int sector_erase_timeout,page_program_timeout;
} FlashTimeouts; /* accessed prefix20, units supplied to wait_idle */
typedef struct FlashChipDriverView {
    const char *name;
    const volatile FlashTimeouts *timeout;
    int (*probe)(EspFlash *,unsigned int flash_id);
    int (*reset)(EspFlash *);
    int (*detect_size)(EspFlash *,unsigned int *size);
    int (*erase_chip)(EspFlash *);
    FlashEraseOperation erase_sector,erase_block;
    unsigned int sector_size,block_erase_size;
    int (*get_chip_write_protect)(EspFlash *,bool *);
    int (*set_chip_write_protect)(EspFlash *,unsigned char protect);
    unsigned char num_protectable_regions,reserved49[3];
    const FlashProtectedRegion *protectable_regions;
    int (*get_protected_regions)(EspFlash *,unsigned long long *);
    unsigned int set_protected_regions_slot;
    int (*read)(EspFlash *,void *,unsigned int address,unsigned int length);
    FlashWriteOperation write;
    FlashWriteOperation program_page;
    unsigned int page_size;
    FlashWriteOperation write_encrypted;
    int (*wait_idle)(EspFlash *,unsigned int timeout_us);
    int (*set_io_mode)(EspFlash *);
    int (*get_io_mode)(EspFlash *,unsigned int *);
    FlashReadIdOperation read_id;
    int (*read_reg)(EspFlash *,unsigned int,unsigned int *);
    FlashYieldOperation yield;
    int (*suspend_setup)(EspFlash *);
    int (*read_unique_id)(EspFlash *,unsigned long long *);
    unsigned int (*get_chip_caps)(EspFlash *);
    int (*config_host_io_mode)(EspFlash *,unsigned int flags);
} FlashChipDriverView; /* accessed prefix124, not the complete driver */
struct EspFlash {
    FlashHostView *host;
    const volatile FlashChipDriverView *chip_driver;
    const volatile MainFlashOsFunctions *os_functions;
    FlashOsContext *os_context;
    unsigned int read_mode,size,chip_id,flags;
};
typedef struct FlashApiFunctions {
    int (*start)(EspFlash *);
    int (*end)(EspFlash *,int status);
    int (*chip_check)(EspFlash **);
    int (*flash_end_flush_cache)(EspFlash *,int status,unsigned int bus_acquired,
        unsigned int address,unsigned int length);
} FlashApiFunctions;
/* Native initial table3fca671c: start4037d79c,end4037d7c8,
 * chip-check4037c6fc,flush/end4037c6ac. Reload slots at native boundaries. */
#define FLASH_API (*(const volatile FlashApiFunctions *volatile *)0x3fca6718U)
#define DEFAULT_FLASH_CHIP (*(EspFlash *volatile *)0x3fccbb74U)
#define REGISTERED_FLASH_DRIVERS (*(const volatile FlashChipDriverView *const *volatile *)0x3fc9e2fcU)
int flash_flush_cache_and_end(EspFlash *,int status,unsigned int bus_acquired,unsigned int address,unsigned int length);
int flash_check_chip_pointer(EspFlash **);
int flash_detect_chip_driver(EspFlash *);
int flash_read_id_core(EspFlash *,unsigned int *flash_id,unsigned int sanity_check);
int esp_flash_get_physical_size(void *chip,unsigned int *size);
int esp_flash_read_encrypted(void *chip,unsigned int address,void *output,unsigned int length);
int flash_start_default(EspFlash *);
int flash_end_default(EspFlash *,int status);
bool esp_flash_chip_driver_initialized(const EspFlash *);
#define FUN_4037c6ac flash_flush_cache_and_end
#define FUN_4037c6fc flash_check_chip_pointer
#define FUN_4037c720 flash_detect_chip_driver
#define FUN_4037c7b0 flash_read_id_core
#define FUN_4037c814 esp_flash_get_physical_size
#define FUN_4037ceb8 esp_flash_read_encrypted
#define FUN_4037d79c flash_start_default
#define FUN_4037d7c8 flash_end_default
#define FUN_4037d7e8 esp_flash_chip_driver_initialized
int esp_flash_erase_region(void *chip,unsigned int address,unsigned int length);
int esp_flash_read(void *chip,void *buffer,unsigned int address,unsigned int length);
int esp_flash_write(void *chip,const void *buffer,unsigned int address,unsigned int length);
int esp_flash_write_encrypted(void *chip,unsigned int address,const void *buffer,unsigned int length);
int esp_flash_init_main(void *chip);
int esp_flash_read_chip_id(EspFlash *,unsigned int *flash_id);
#define FUN_4037c9e0 esp_flash_erase_region
#define FUN_4037cbf8 esp_flash_read
#define FUN_4037cd3c esp_flash_write
#define FUN_4037cf24 esp_flash_write_encrypted
#define FUN_4037c87c esp_flash_init_main
#define FUN_42012a88 esp_flash_read_chip_id
typedef struct FlashEncryptionFunctions {
    void (*enable)(void);
    void (*disable)(void);
    void (*prepare)(unsigned int address,const unsigned int *buffer,unsigned int size);
    void (*done)(void);
    void (*destroy)(void);
    bool (*check)(unsigned int address,unsigned int length);
} FlashEncryptionFunctions;
#define FLASH_ENCRYPTION_FUNCTIONS ((const volatile FlashEncryptionFunctions *)0x3fca67fcU)
int spi_flash_chip_generic_write_encrypted(EspFlash *,const void *buffer,
    unsigned int address,unsigned int length);
int flash_no_os_delay_us(void *unused_context,unsigned int microseconds);
int flash_no_os_end(FlashOsContext *unused_context);
int flash_no_os_start(FlashOsContext *unused_context);
void cache_hal_suspend(unsigned int level,CacheType type);
void cache_hal_resume(unsigned int level,CacheType type);
#define FUN_4038c3a8 spi_flash_chip_generic_write_encrypted
#define FUN_4037d278 flash_no_os_delay_us
#define FUN_4037d288 flash_no_os_end
#define FUN_4037d29c flash_no_os_start

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
int memspi_host_init_pointers(FlashHostView *,const MemspiHostConfig *);
int esp_mspi_32bit_address_flash_feature_check(void);
#define DEFAULT_FLASH_OBJECT ((volatile EspFlash *)0x3fca6738U)
#define FLASH_DEFAULT_GUARD ((const FlashGuardFunctions *)0x3fca6638U)
#define MAIN_FLASH_OS_FUNCTIONS ((const volatile MainFlashOsFunctions *)0x3fca6788U)
#define MAIN_FLASH_OS_CONTEXT ((volatile FlashOsContext *)0x3fca67b0U)
#define MAIN_FLASH_DEVICE_LOCK (*(void *const volatile *)0x3c05187cU)
int __esp_system_init_fn_init_disable_rtc_wdt(void);
int __esp_system_init_fn_init_flash(void);
int esp_flash_app_init(void);
int esp_flash_app_enable_os_functions(EspFlash *chip);
void spi_flash_init_lock(void);
void spi_flash_needs_reset_check(void);
#define FUN_420022c4 __esp_system_init_fn_init_disable_rtc_wdt
#define FUN_420022ec __esp_system_init_fn_init_flash
#define FUN_42012c14 esp_flash_app_init
#define FUN_42012c30 esp_flash_app_enable_os_functions

#define DEFAULT_FLASH_HOST ((FlashHostView *)0x3fca6758U)
#define DEFAULT_MEMSPI_DRIVER ((const volatile FlashHostDriverView *)0x3fca682cU)
#define GPSPI_FLASH_DRIVER ((const volatile FlashHostDriverView *)0x3fca6c70U)
/* HAL initializer and divider retain independent native review entries. */
int spi_flash_hal_init(FlashHostView *,const MemspiHostConfig *);
#define FUN_42012a9c flash_choose_default_io_mode
#define FUN_4037fc38 spi_timing_get_flash_timing_param
#define FUN_4037fca8 spi_flash_timing_is_tuned
#define FUN_4038bd38 memspi_host_init_pointers
#define FUN_4037d794 esp_mspi_32bit_address_flash_feature_check

unsigned int flash_get_clock_divider(const MemspiHostConfig *);
#define FUN_42013540 flash_get_clock_divider
#define FUN_420135a0 spi_flash_hal_init

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
int spi_flash_hal_gpspi_device_config(FlashHostView *);
bool spi_flash_hal_gpspi_supports_direct_write(FlashHostView *,const void *);
bool spi_flash_hal_gpspi_supports_direct_read(FlashHostView *,const void *);
unsigned int spi_flash_hal_gpspi_check_status(FlashHostView *);
void spi_flash_hal_gpspi_poll_cmd_done(FlashHostView *);
bool spi_flash_hal_supports_direct_write(FlashHostView *,const void *);
bool spi_flash_hal_supports_direct_read(FlashHostView *,const void *);
#define FUN_4038493c spi_flash_hal_gpspi_device_config
#define FUN_4038500c spi_flash_hal_gpspi_supports_direct_write
#define FUN_40385014 spi_flash_hal_gpspi_supports_direct_read
#define FUN_4038501c spi_flash_hal_gpspi_check_status
#define FUN_40384ffc spi_flash_hal_gpspi_poll_cmd_done
#define FUN_4201370c spi_flash_hal_supports_direct_write
#define FUN_42013720 spi_flash_hal_supports_direct_read

unsigned int spi_flash_hal_check_status(FlashHostView *);
void spi_flash_hal_poll_cmd_done(FlashHostView *);
void spi_flash_hal_resume(FlashHostView *);
void spi_flash_hal_suspend(FlashHostView *);
int memspi_host_read_id_hs(FlashHostView *,unsigned int *);
void memspi_host_erase_chip(FlashHostView *);
void memspi_host_erase_sector(FlashHostView *,unsigned int);
void memspi_host_erase_block(FlashHostView *,unsigned int);
int memspi_host_read_status_hs(FlashHostView *,unsigned char *);
int memspi_host_set_write_protect(FlashHostView *,unsigned char);
void memspi_host_program_page(FlashHostView *,const void *,unsigned int,unsigned int);
int memspi_host_write_data_slicer(FlashHostView *,unsigned int,unsigned int,unsigned int *,unsigned int);
int memspi_host_read_data_slicer(FlashHostView *,unsigned int,unsigned int,unsigned int *,unsigned int);
#define FUN_40385b5c spi_flash_hal_check_status
#define FUN_40385b4c spi_flash_hal_poll_cmd_done
#define FUN_40385b7c spi_flash_hal_resume
#define FUN_40385ba0 spi_flash_hal_suspend
#define FUN_4038bbd4 memspi_host_read_id_hs
#define FUN_4038bdd8 memspi_host_erase_chip
#define FUN_4038bcbc memspi_host_erase_sector
#define FUN_4038bcf8 memspi_host_erase_block
#define FUN_4038bda0 memspi_host_read_status_hs
#define FUN_4038bdfc memspi_host_set_write_protect
#define FUN_4038bc74 memspi_host_program_page
#define FUN_4038be2c memspi_host_write_data_slicer
#define FUN_4038be64 memspi_host_read_data_slicer

void spi_flash_hal_erase_chip(FlashHostView *);
void spi_flash_hal_erase_sector(FlashHostView *,unsigned int);
void spi_flash_hal_erase_block(FlashHostView *,unsigned int);
int spi_flash_hal_set_write_protect(FlashHostView *,unsigned char);
void spi_flash_hal_program_page(FlashHostView *,const void *,unsigned int,unsigned int);
int spi_flash_hal_read(FlashHostView *,void *,unsigned int,unsigned int);
int memspi_host_flush_cache(FlashHostView *,unsigned int,unsigned int);
#define FUN_403855d4 spi_flash_hal_erase_chip
#define FUN_403855fc spi_flash_hal_erase_sector
#define FUN_4038566c spi_flash_hal_erase_block
#define FUN_40385784 spi_flash_hal_set_write_protect
#define FUN_403856d4 spi_flash_hal_program_page
#define FUN_40385518 spi_flash_hal_read
#define FUN_4038bc58 memspi_host_flush_cache

int spi_flash_hal_device_config(FlashHostView *);
int spi_flash_hal_setup_read_suspend(FlashHostView *,const FlashSuspendCommands *);
void spi_flash_hal_setup_auto_suspend_mode(FlashHostView *);
int spi_flash_hal_gpspi_read(FlashHostView *,void *,unsigned int,unsigned int);
#define FUN_403859c4 spi_flash_hal_device_config
#define FUN_403857bc spi_flash_hal_setup_read_suspend
#define FUN_40384f04 spi_flash_hal_gpspi_read
#define FUN_40385830 spi_flash_hal_setup_auto_suspend_mode

int spi_flash_hal_gpspi_configure_host_io_mode(FlashHostView *,unsigned int command,
    unsigned int address_bits,int dummy_base,unsigned int io_mode);
int spi_flash_hal_gpspi_common_command(FlashHostView *,FlashTransaction *);
#define FUN_40384a78 spi_flash_hal_gpspi_configure_host_io_mode
#define FUN_40384cdc spi_flash_hal_gpspi_common_command

int spi_flash_hal_configure_host_io_mode(FlashHostView *,unsigned int command,
    unsigned int address_bits,int dummy_base,unsigned int io_mode);
int spi_flash_hal_common_command(FlashHostView *,FlashTransaction *);
#define FUN_40385030 spi_flash_hal_configure_host_io_mode
#define FUN_40385368 spi_flash_hal_common_command

enum {
    FLASH_CAP_SUSPEND = 1U,
    FLASH_CAP_32MB_SUPPORT = 2U,
    FLASH_CAP_UNIQUE_ID = 4U
};
int spi_flash_chip_issi_probe(EspFlash *,unsigned int flash_id);
#define FUN_4038ca44 spi_flash_chip_issi_probe
int spi_flash_chip_generic_detect_size(EspFlash *,unsigned int *size);
#define FUN_4038bf9c spi_flash_chip_generic_detect_size
unsigned int spi_flash_chip_issi_get_caps(EspFlash *);
#define FUN_4038ca94 spi_flash_chip_issi_get_caps
int spi_flash_chip_gd_probe(EspFlash *,unsigned int flash_id);
#define FUN_4038bf2c spi_flash_chip_gd_probe
int spi_flash_chip_gd_detect_size(EspFlash *,unsigned int *size);
#define FUN_4038bebc spi_flash_chip_gd_detect_size
unsigned int spi_flash_chip_gd_get_caps(EspFlash *);
#define FUN_4038bf88 spi_flash_chip_gd_get_caps
int spi_flash_chip_mxic_probe(EspFlash *,unsigned int flash_id);
#define FUN_4038cadc spi_flash_chip_mxic_probe
int spi_flash_chip_mxic_detect_size(EspFlash *,unsigned int *size);
#define FUN_4038ca9c spi_flash_chip_mxic_detect_size
unsigned int spi_flash_chip_mxic_get_caps(EspFlash *);
#define FUN_4038cafc spi_flash_chip_mxic_get_caps
int spi_flash_chip_winbond_probe(EspFlash *,unsigned int flash_id);
#define FUN_4038d310 spi_flash_chip_winbond_probe
unsigned int spi_flash_chip_winbond_get_caps(EspFlash *);
#define FUN_4038d328 spi_flash_chip_winbond_get_caps
int spi_flash_chip_boya_probe(EspFlash *,unsigned int flash_id);
#define FUN_4038be94 spi_flash_chip_boya_probe
unsigned int spi_flash_chip_boya_get_caps(EspFlash *);
#define FUN_4038beb4 spi_flash_chip_boya_get_caps
int spi_flash_chip_th_probe(EspFlash *,unsigned int flash_id);
#define FUN_4038d0a0 spi_flash_chip_th_probe
unsigned int spi_flash_chip_th_get_caps(EspFlash *);
#define FUN_4038d0c0 spi_flash_chip_th_get_caps
int spi_flash_chip_mxic_opi_probe(EspFlash *,unsigned int flash_id);
#define FUN_4038d074 spi_flash_chip_mxic_opi_probe
int spi_flash_chip_mxic_opi_detect_size(EspFlash *,unsigned int *size);
#define FUN_4038cb04 spi_flash_chip_mxic_opi_detect_size
unsigned int spi_flash_chip_mxic_opi_get_caps(EspFlash *);
#define FUN_4038d090 spi_flash_chip_mxic_opi_get_caps
int spi_flash_chip_generic_probe(EspFlash *,unsigned int flash_id);
#define FUN_4038c4a8 spi_flash_chip_generic_probe
unsigned int spi_flash_chip_generic_get_caps(EspFlash *);
#define FUN_4038c120 spi_flash_chip_generic_get_caps

typedef int (*FlashReadStatusOperation)(EspFlash *,unsigned int *);
typedef int (*FlashWriteStatusOperation)(EspFlash *,unsigned int);
int spi_flash_chip_issi_set_io_mode(EspFlash *);
#define FUN_4038ca64 spi_flash_chip_issi_set_io_mode
int spi_flash_chip_issi_get_io_mode(EspFlash *,unsigned int *);
#define FUN_4038ca78 spi_flash_chip_issi_get_io_mode
int spi_flash_chip_generic_suspend_cmd_conf(EspFlash *);
#define FUN_4038c184 spi_flash_chip_generic_suspend_cmd_conf
int spi_flash_chip_gd_set_io_mode(EspFlash *);
#define FUN_4038bf4c spi_flash_chip_gd_set_io_mode
int spi_flash_chip_gd_get_io_mode(EspFlash *,unsigned int *);
#define FUN_4038bf10 spi_flash_chip_gd_get_io_mode
int spi_flash_chip_gd_suspend_cmd_conf(EspFlash *);
#define FUN_4038bef0 spi_flash_chip_gd_suspend_cmd_conf
int spi_flash_chip_generic_set_io_mode(EspFlash *);
#define FUN_4038c490 spi_flash_chip_generic_set_io_mode
int spi_flash_chip_generic_get_io_mode(EspFlash *,unsigned int *);
#define FUN_4038c83c spi_flash_chip_generic_get_io_mode
int spi_flash_chip_mxic_opi_set_io_mode(EspFlash *);
#define FUN_4038d098 spi_flash_chip_mxic_opi_set_io_mode
int spi_flash_chip_mxic_opi_get_io_mode(EspFlash *,unsigned int *);
#define FUN_4038cff8 spi_flash_chip_mxic_opi_get_io_mode
int spi_flash_common_read_status_8b_rdsr(EspFlash *,unsigned int *);
#define FUN_4038c924 spi_flash_common_read_status_8b_rdsr
int spi_flash_common_write_status_8b_wrsr(EspFlash *,unsigned int);
#define FUN_4038c958 spi_flash_common_write_status_8b_wrsr
int spi_flash_common_read_status_16b_rdsr_rdsr2(EspFlash *,unsigned int *);
#define FUN_4038c878 spi_flash_common_read_status_16b_rdsr_rdsr2
int spi_flash_common_write_status_16b_wrsr(EspFlash *,unsigned int);
#define FUN_4038c80c spi_flash_common_write_status_16b_wrsr
int spi_flash_common_read_status_8b_rdsr2(EspFlash *,unsigned int *);
#define FUN_4038c8f0 spi_flash_common_read_status_8b_rdsr2
int spi_flash_common_write_status_8b_wrsr2(EspFlash *,unsigned int);
#define FUN_4038c988 spi_flash_common_write_status_8b_wrsr2
int spi_flash_common_set_io_mode(EspFlash *,FlashWriteStatusOperation,FlashReadStatusOperation,unsigned int);
#define FUN_4038c9b8 spi_flash_common_set_io_mode
int spi_flash_chip_generic_read_reg(EspFlash *,unsigned int,unsigned int *);
#define FUN_4038c710 spi_flash_chip_generic_read_reg
int spi_flash_chip_mxic_read_unique_id(EspFlash *,unsigned long long *);
#define FUN_4038c8e8 spi_flash_chip_mxic_read_unique_id
int spi_flash_chip_generic_yield(EspFlash *,unsigned int);
#define FUN_4038c2d4 spi_flash_chip_generic_yield

void *memset(void *buffer,int byte_value,size_t length); /* ROM 0x400011e8 */
int spi_flash_chip_generic_reset(EspFlash *);
#define FUN_4038c4b0 spi_flash_chip_generic_reset
int spi_flash_chip_generic_erase_chip(EspFlash *);
#define FUN_4038c50c spi_flash_chip_generic_erase_chip
int spi_flash_chip_generic_erase_sector(EspFlash *,unsigned int);
#define FUN_4038c594 spi_flash_chip_generic_erase_sector
int spi_flash_chip_generic_erase_block(EspFlash *,unsigned int);
#define FUN_4038c628 spi_flash_chip_generic_erase_block
int spi_flash_chip_generic_get_write_protect(EspFlash *,bool *);
#define FUN_4038c45c spi_flash_chip_generic_get_write_protect
int spi_flash_chip_generic_set_write_protect(EspFlash *,unsigned char);
#define FUN_4038c6bc spi_flash_chip_generic_set_write_protect
int spi_flash_chip_generic_read(EspFlash *,void *,unsigned int,unsigned int);
#define FUN_4038c1a4 spi_flash_chip_generic_read
int spi_flash_chip_generic_write(EspFlash *,const void *,unsigned int,unsigned int);
#define FUN_4038c240 spi_flash_chip_generic_write
int spi_flash_chip_generic_page_program(EspFlash *,const void *,unsigned int,unsigned int);
#define FUN_4038c7a4 spi_flash_chip_generic_page_program
int spi_flash_chip_generic_wait_idle(EspFlash *,unsigned int);
#define FUN_4038c724 spi_flash_chip_generic_wait_idle
int spi_flash_chip_generic_read_unique_id(EspFlash *,unsigned long long *);
#define FUN_4038c314 spi_flash_chip_generic_read_unique_id

/* ROM flash dummy-cycle profile; six independent mode bytes. */
typedef struct FlashDummyCycles {
    unsigned char dual_io,quad_io,quad_output,dual_output,fast_read,slow_read;
} FlashDummyCycles;
#define FLASH_DUMMY_CYCLES_HIGH_PERFORMANCE (*(const volatile FlashDummyCycles *volatile *)0x3fca6814U)
#define FLASH_DUMMY_CYCLES_NORMAL (*(const volatile FlashDummyCycles *volatile *)0x3fca6818U)
int spi_flash_chip_generic_config_host_io_mode(EspFlash *,unsigned int flags);
#define FUN_4038bfdc spi_flash_chip_generic_config_host_io_mode

int spi_flash_chip_winbond_read(EspFlash *,void *buffer,unsigned int address,unsigned int length);
#define FUN_4038d0c8 spi_flash_chip_winbond_read
int spi_flash_chip_winbond_erase_sector(EspFlash *,unsigned int address);
#define FUN_4038d210 spi_flash_chip_winbond_erase_sector
int spi_flash_chip_winbond_erase_block(EspFlash *,unsigned int address);
#define FUN_4038d17c spi_flash_chip_winbond_erase_block
int spi_flash_chip_winbond_page_program(EspFlash *,const void *buffer,unsigned int address,unsigned int length);
#define FUN_4038d2a0 spi_flash_chip_winbond_page_program

int spi_flash_chip_mxic_opi_erase_chip(EspFlash *);
#define FUN_4038cba4 spi_flash_chip_mxic_opi_erase_chip
int spi_flash_chip_mxic_opi_erase_sector(EspFlash *,unsigned int);
#define FUN_4038cc2c spi_flash_chip_mxic_opi_erase_sector
int spi_flash_chip_mxic_opi_erase_block(EspFlash *,unsigned int);
#define FUN_4038ccb8 spi_flash_chip_mxic_opi_erase_block
int spi_flash_chip_mxic_opi_get_write_protect(EspFlash *,bool *);
#define FUN_4038cf64 spi_flash_chip_mxic_opi_get_write_protect
int spi_flash_chip_mxic_opi_set_write_protect(EspFlash *,unsigned char);
#define FUN_4038cb38 spi_flash_chip_mxic_opi_set_write_protect
int spi_flash_chip_mxic_opi_write(EspFlash *,const void *,unsigned int,unsigned int);
#define FUN_4038cd78 spi_flash_chip_mxic_opi_write
int spi_flash_chip_mxic_opi_page_program(EspFlash *,const void *,unsigned int,unsigned int);
#define FUN_4038ce0c spi_flash_chip_mxic_opi_page_program
int spi_flash_chip_mxic_opi_read_id(void *,unsigned int *);
#define FUN_4038ce90 spi_flash_chip_mxic_opi_read_id
int spi_flash_chip_mxic_opi_read_reg(EspFlash *,unsigned int,unsigned int *);
#define FUN_4038cf98 spi_flash_chip_mxic_opi_read_reg

int spi_flash_chip_mxic_opi_config_host_io_mode(EspFlash *,unsigned int flags);
#define FUN_4038cd44 spi_flash_chip_mxic_opi_config_host_io_mode

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
#define FUN_4201e634 medius_newlib_write_string_vectors

extern NewlibReent *medius_current_newlib_reent(void) __asm__("__getreent");
extern int medius_newlib_vformat_stream(NewlibReent *,NewlibFile *,
    const char *format,va_list arguments);
int vprintf(const char *format,va_list arguments);
int medius_single_byte_decode_u16(void *,volatile unsigned short *,
    const volatile unsigned char *,unsigned int available);
int medius_single_byte_encode_u16(NewlibReent *,volatile unsigned char *,
    unsigned short character);
#define FUN_4201ee30 medius_single_byte_decode_u16
#define FUN_4201ee50 medius_single_byte_encode_u16

/* Linker/ROM heap reservation records: unsigned address bits, eight-byte stride. */
typedef struct ReservedMemoryRegion {
    unsigned int start,end;
} ReservedMemoryRegion;
#define SOC_MEMORY_REGION_COUNT (*(const volatile unsigned int *)0x3c045574U)
#define RESERVED_MEMORY_START 0x3c0526ccU
#define RESERVED_MEMORY_END 0x3c0526f4U
unsigned int panic_get_address(const void *);
#define FUN_4201e768 panic_get_address
unsigned int panic_get_cause(const void *);
#define FUN_4201e770 panic_get_cause
void panic_set_address(void *,unsigned int);
#define FUN_4201e778 panic_set_address
bool heap_caps_match(const HeapRegion *,unsigned int);
#define FUN_4201e780 heap_caps_match
int heap_compare_reserved_regions(const void *,const void *);
#define FUN_4201e7a8 heap_compare_reserved_regions
unsigned int soc_get_available_memory_region_max_count(void);
#define FUN_42003f28 soc_get_available_memory_region_max_count

/* ACK queue copies exactly three bytes from this four-byte aligned stack view.
 * The final byte is unused and is never part of the queued record. */
typedef struct MediusOutAckStorage {
    unsigned short endpoint_sequence;
    unsigned char status,unused;
} MediusOutAckStorage;
#define MEDIUS_OUT_INFLIGHT (*(volatile unsigned char *)0x3fcb81c8U)
#define MEDIUS_OUT_PAUSE (*(volatile unsigned char *)0x3fcb81c9U)
#define MEDIUS_OUT_ACK_QUEUE (*(RtosQueue *volatile *)0x3fcb81ccU)
#define MEDIUS_OUT_WAKE (*(RtosQueue *volatile *)0x3fcb81d0U)
#define MEDIUS_OUT_MUTEX (*(RtosQueue *volatile *)0x3fcb81d4U)
#define MEDIUS_OUT_RELAYS ((MediusOutRelayState *)0x3fcb81d8U)
void medius_out_complete(MediusOutRelayState *,int result);
void medius_out_drop_stalled(MediusOutRelayState *);
void medius_out_discard_through(MediusOutRelayState *,unsigned int generation);
void medius_out_consume_completion(MediusOutRelayState *,long long now_us);
void medius_out_cancel(MediusOutRelayState *);
void medius_out_enqueue(unsigned int endpoint,unsigned int sequence,unsigned char *payload,unsigned int length);
void medius_out_pause_and_reconcile(unsigned int discard_queued);
void medius_out_handle_short(unsigned char *,unsigned int length);
void medius_out_handle_timed(unsigned char *,unsigned int length);
void medius_out_resume(void);

/* Outgoing native constructor/task ABI views. These aliases add no firmware
 * entry; queue type arguments and the task argument are explicit at call sites. */
extern RtosQueue *medius_out_create_mutex(unsigned char queue_type) __asm__("xQueueCreateMutex");
RtosQueue *rtos_create_mutex_type(unsigned char queue_type) __asm__("xQueueCreateMutex");
extern RtosQueue *medius_out_create_queue(unsigned int capacity,unsigned int item_size,
    unsigned char queue_type) __asm__("xQueueGenericCreate");
extern void medius_out_task_entry(void *argument) __asm__("medius_task_outrelay");
void medius_out_start_worker(void);
void medius_out_register(void *hubport,unsigned char *descriptor);
void medius_out_unregister(void *hubport,unsigned int endpoint);
void medius_out_handle_status_query(unsigned char *payload,unsigned short length);

#define MEDIUS_OUT_DMA_SLOTS ((unsigned char (*)[64])0x3fca3b84U)
void medius_task_outrelay(void *argument);
/* Typed URB callback view of the same medius_out_complete native entry. */
extern void medius_out_urb_completion(void *context,int result) __asm__("medius_out_complete");

/* Logger RAM recovered from native loads; cache is 31 eight-byte entries.
 * packed_level_generation uses level bits0..2 and generation bits3..31.
 */
typedef struct LogTagListNode {
    struct LogTagListNode *next;
    unsigned char level;
    char tag[];
} LogTagListNode;
typedef struct {
    const char *tag;
    unsigned int packed_level_generation;
} LogCacheEntry;
typedef struct {
    unsigned int early_base_ms;
    LogTagListNode *list;
    unsigned int cache_misses;
    unsigned int cache_count;
    unsigned int cache_generation;
    LogCacheEntry entries[31];
    RtosQueue *mutex;
} LogState;
typedef int (*LogVprintf)(const char *format,va_list arguments);
typedef struct {
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
int esp_clk_cpu_freq(void);
int esp_clk_apb_freq(void);
int esp_clk_xtal_freq(void);
#define FUN_40376568 esp_clk_cpu_freq
#define FUN_4037657c esp_clk_apb_freq
#define FUN_403765a0 esp_clk_xtal_freq
#define MEDIUS_WORKER_WDT_LOG_TAG ((const char *)0x3c042e6cU)
static __inline__ __attribute__((always_inline)) unsigned int esp_cpu_get_cycle_count(void)
{
    unsigned int cycles;
    __asm__ volatile ("rsr.ccount %0" : "=a"(cycles));
    return cycles;
}
#define LOG_STATE ((volatile LogState *)0x3fca72a0U)
#define LOG_OUTPUT ((volatile LogOutputConfig *)0x3fc9da34U)
#define FUN_42003a50 esp_log_linked_list_get_level
#define FUN_42003a7c esp_log_cache_heap_bubble_down
#define FUN_42003ad0 esp_log_cache_get_level
#define FUN_42003b88 esp_log_cache_add

/* Builtin-va_list callback ABI view of the reviewed raw12-byte hook entry. */
extern int medius_host_log_vprintf(const char *format,va_list arguments)
    __asm__("medius_host_log_hook");
void medius_host_log_init(void);

/* Accessed ESP32-S3 eFuse readback WORDs; gaps remain uninterpreted. */
typedef struct {
    unsigned char uninterpreted0[0x34];
    unsigned int repeat_data1;
    unsigned char uninterpreted38[8];
    unsigned int repeat_data4;
    unsigned char uninterpreted44[12];
    unsigned int mac_spi_sys3,mac_spi_sys4,mac_spi_sys5;
    unsigned char uninterpreted5c[16];
    unsigned int sys_part1_data4;
} EfuseReadRegisters;
#define EFUSE_READ_REGISTERS ((const volatile EfuseReadRegisters *)0x60007000U)
unsigned int efuse_hal_chip_revision(void);
unsigned int efuse_hal_blk_version(void);
bool efuse_hal_get_disable_wafer_version_major(void);
bool efuse_hal_get_disable_blk_version_major(void);
bool efuse_hal_flash_encryption_enabled(void);
unsigned int efuse_hal_get_major_chip_version(void);
unsigned int efuse_hal_get_minor_chip_version(void);
#define FUN_4037603c efuse_hal_chip_revision
#define FUN_40376054 efuse_hal_blk_version
#define FUN_40376078 efuse_hal_get_disable_wafer_version_major
#define FUN_4037608c efuse_hal_get_disable_blk_version_major
#define FUN_403760a0 efuse_hal_flash_encryption_enabled
#define FUN_403760c8 efuse_hal_get_major_chip_version
#define FUN_40376108 efuse_hal_get_minor_chip_version

/* Clock queries: register prefixes contain only the accessed named WORDs. */
typedef struct {
    unsigned char uninterpreted00[0x10];
    volatile unsigned int cpu_per_conf;       /* SYSTEM +0x10 */
    unsigned char uninterpreted14[0x4c];
    volatile unsigned int sysclk_conf;        /* SYSTEM +0x60 */
} ClockSystemRegisters;
typedef struct {
    unsigned int rc_fast_d256_hz;
    unsigned int xtal32k_hz;
} ClockFrequencyCache;
enum ClockPrecision {
    ESP_CLK_TREE_SRC_FREQ_PRECISION_CACHED = 0, ESP_CLK_TREE_SRC_FREQ_PRECISION_APPROX = 1, ESP_CLK_TREE_SRC_FREQ_PRECISION_EXACT = 2
};
enum ModuleClock {
    SOC_MOD_CLK_CPU = 1, SOC_MOD_CLK_RTC_FAST = 2,
    SOC_MOD_CLK_RTC_SLOW = 3, SOC_MOD_CLK_APB = 4,
    SOC_MOD_CLK_PLL_F80M = 5, SOC_MOD_CLK_PLL_F160M = 6,
    SOC_MOD_CLK_PLL_D2 = 7, SOC_MOD_CLK_XTAL32K = 8,
    SOC_MOD_CLK_RC_FAST = 9, SOC_MOD_CLK_RC_FAST_D256 = 10,
    SOC_MOD_CLK_XTAL = 11, SOC_MOD_CLK_TEMP_SENSOR = 12
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
#define CLOCK_FREQUENCY_CACHE ((ClockFrequencyCache *)0x3fca740cU)
#define PERIPHERAL_RCC_LOCK ((PortMuxWords *)0x3fc9da54U)
#define REGI2C_LOCK ((PortMuxWords *)0x3fc9da5cU)
#define PERIPHERAL_RCC_REFERENCE_COUNTS ((volatile unsigned char *)0x3fca73d0U)
/* External ROM boundaries: 0x40005d54, 0x40005d60, 0x40005d6c. */
unsigned char rom_i2c_readReg_Mask(unsigned char block, unsigned char host_id,
    unsigned char register_address, unsigned char most_significant_bit, unsigned char least_significant_bit);
void rom_i2c_writeReg(unsigned char block, unsigned char host_id,
    unsigned char register_address, unsigned char value);
void rom_i2c_writeReg_Mask(unsigned char block, unsigned char host_id,
    unsigned char register_address, unsigned char most_significant_bit, unsigned char least_significant_bit,
    unsigned char value);
unsigned char regi2c_ctrl_read_reg_mask(unsigned char block, unsigned char host_id,
    unsigned char register_address, unsigned char most_significant_bit, unsigned char least_significant_bit);
void regi2c_ctrl_write_reg(unsigned char block, unsigned char host_id,
    unsigned char register_address, unsigned char value);
void regi2c_ctrl_write_reg_mask(unsigned char block, unsigned char host_id,
    unsigned char register_address, unsigned char most_significant_bit, unsigned char least_significant_bit,
    unsigned char value);
/* RTC accounting returns 64 bits; the calibration setter discards them. */
#define FUN_42006ed8 esp_clk_tree_rc_fast_d256_get_freq_hz
#define FUN_42006f24 esp_clk_tree_xtal32k_get_freq_hz
#define FUN_42006f70 esp_clk_tree_lp_slow_get_freq_hz
#define FUN_42006fc0 esp_clk_tree_rc_fast_get_freq_hz
#define FUN_42007014 esp_clk_tree_lp_fast_get_freq_hz
#define FUN_42013760 clk_hal_xtal_get_freq_mhz
#define FUN_420137a0 clk_hal_cpu_get_freq_hz
#define FUN_4201384c clk_hal_apb_get_freq_hz
#define FUN_42013734 clk_hal_lp_slow_get_freq_hz
#define FUN_42004214 esp_clk_slowclk_cal_set

/* WORD view of the 24-byte RTC retained time block, including checksum. */
typedef struct {
    unsigned int time_us_low, time_us_high;
    unsigned int last_ticks_low, last_ticks_high;
    unsigned int reserved;
    unsigned int checksum;
} RtcRetainedTime;
#define RTC_RETAINED_TIME ((volatile RtcRetainedTime *)0x600fffe8U)
unsigned long long esp_rtc_get_time_us(void);
#define RTC_TIME_FIRST_CALL (*(volatile unsigned char *)0x3fc9da40U)
#define RTC_TIME_LOCK ((PortMuxWords *)0x3fc9da44U)
#define FUN_4200412c esp_rtc_get_time_us

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
#define TIME_STARTUP_WORDS ((const volatile ClockWords *)0x3fca71b8U)
#define SHUTDOWN_HANDLERS ((ShutdownHandler volatile *)0x3fca717cU)
#define TIME_TICK_CONVERSION_OPS ((const volatile SystimerTickOps *)0x3c0458fcU)
#define FUN_420072d0 medius_settimeofday_nonnull
#define FUN_42007334 settimeofday
#define FUN_42007344 esp_time_impl_init
#define FUN_420073b8 esp_sync_timekeeping_timers
#define FUN_4200744c esp_set_time_from_rtc
#define FUN_420074bc esp_timer_early_init
#define FUN_420074cc esp_timer_impl_init_system_time
#define FUN_42002200 esp_register_shutdown_handler

/* Named opaque ROM callback table: initialization publishes its address only. */
typedef struct MediusNewlibRomSyscalls MediusNewlibRomSyscalls;
typedef struct {
    char message[50];
    unsigned char padding32[2];
    const char *fragments[4];
    char address_text[9];
    char core_text[2];
} NewlibAbortFrame;
#define MEDIUS_NEWLIB_ROM_SYSCALL_POINTER (*(const MediusNewlibRomSyscalls *volatile *)0x3fceffd4U)
#define MEDIUS_NEWLIB_ROM_GLOBAL_REENT (*(NewlibReent *volatile *)0x3fceffd0U)
void esp_newlib_locks_init(void);
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
#define MEDIUS_NEWLIB_SYSCALL_TABLE ((const MediusNewlibRomSyscalls *)0x3fc9db10U)
#define MEDIUS_NEWLIB_ENVIRONMENT (*(char **volatile *)0x3fc9e374U)
#define NEWLIB_ABORT_PREFIX ((const char *)0x3fca6954U)
#define NEWLIB_ABORT_CORE_SEPARATOR ((const char *)0x3fca6970U)
#define FUN_42007054 esp_newlib_locks_init
#define FUN_4200709c esp_cleanup_r
#define FUN_420070d0 raise_r_stub
#define FUN_420070e0 esp_newlib_init
#define FUN_4200712c init_newlib
#define FUN_42007138 esp_newlib_init_global_stdio
#define FUN_4200719c init_newlib_stdio
#define FUN_420071ac _raise_r

void timer_alarm_handler(void *argument);
int esp_timer_impl_init(ClockAlarmHandler alarm_handler);
int esp_timer_init(void);
int esp_timer_init_os(void);
void esp_timer_task(void *argument);
void systimer_hal_enable_alarm_int(SystimerHal *hal,unsigned int alarm_id);
int esp_intr_enable(InterruptHandle *handle);
#define ESP_TIMER_TASK_SLOT ((RtosTask *volatile *)0x3fccbba8U)
#define ESP_TIMER_INTERRUPT_SLOT ((InterruptHandle *volatile *)0x3fca77f8U)
#define FUN_4037d3cc timer_alarm_handler
#define FUN_420075d0 esp_timer_impl_init
#define FUN_42013f48 esp_timer_init
#define FUN_42013fec esp_timer_init_os

typedef struct {
    WatchdogHalContext timer1,timer0,rtc;
} RestartWatchdogFrame;
typedef struct { volatile unsigned int select[6]; } RestartGpioDefaults;
typedef struct { unsigned int uninterpreted00; volatile unsigned int core1_entry; } RestartSystemPrefix;
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
#define RESTART_WATCHDOG0_TEMPLATE ((const volatile WatchdogHalContext *)0x3c0453a8U)
#define RESTART_WATCHDOG1_TEMPLATE ((const volatile WatchdogHalContext *)0x3c0453b0U)

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
#define LINK_TX_CHANNEL_ITEMS ((volatile LinkTxQueueItem *)0x3fccb1c0U)
#define LINK_APPLICATION_HANDLER (*(LinkApplicationFrameHandler volatile *)0x3fccba18U)
#define LINK_APPLICATION_CONTEXT (*(void *volatile *)0x3fccba14U)
void medius_link_send_nowait(unsigned char type,unsigned char flags,const void *payload,unsigned short length);

/* Typed receive boundaries for motion handlers awaiting their own body review.
 * The dispatcher supplies length in the second native argument register. */
void medius_motion_configuration_receive(const unsigned char *payload,unsigned short length);
void FUN_42024544(void *payload,unsigned short length) __asm__("medius_motion_configuration_receive");
void medius_motion_samples_receive(const unsigned char *payload,unsigned short length);
void FUN_42024a44(int payload,unsigned int length) __asm__("medius_motion_samples_receive");
void medius_clone_publish_request(void);
void medius_host_transfer_enqueue(unsigned int sequence,const unsigned char *payload,
    unsigned int length,unsigned int response_opcode);
void medius_host_transfer_ep0_enqueue(unsigned char sequence,const unsigned char *payload,
    unsigned short length);
void medius_host_transfer_nonzero_enqueue(unsigned char sequence,const unsigned char *payload,
    unsigned short length);
void medius_hid_get_report_enqueue(unsigned char sequence,unsigned char interface_number,
    unsigned char report_id,unsigned short requested_length);
void FUN_4202eb5c(unsigned char sequence,unsigned char interface_number,unsigned char report_id,
    unsigned int requested_length) __asm__("medius_hid_get_report_enqueue");

void medius_host_frame_clock_maintenance(void);
void FUN_42026220(void) __asm__("medius_host_frame_clock_maintenance");
void medius_task_link_hb(void *unused_argument);

/* Worker-private filter/history: exact624-byte reset span. Times are raw low32
 * microseconds; signed interpretation is chosen explicitly at each difference. */
typedef struct LinkSyncWindowSample {
    unsigned int time_us_low,round_trip_us,offset_us;
} LinkSyncWindowSample;
typedef struct LinkSyncFilterState {
    unsigned int offsets_us[16];             /* 0x000 */
    unsigned int round_trips_us[16];         /* 0x040 */
    unsigned int times_us_low[16];           /* 0x080 */
    unsigned char recent_count,recent_head; /* 0x0c0/0x0c1 */
    unsigned char reserved194[2];
    LinkSyncWindowSample history[32];  /* 0x0c4,12-byte stride */
    unsigned char history_count,history_head; /* 0x244/0x245 */
    unsigned char reserved582[2];
    unsigned int window_time_us_low;         /* 0x248 */
    unsigned int window_round_trip_us;       /* 0x24c */
    unsigned int window_offset_us;           /* 0x250 */
    unsigned int window_started_us_low;      /* 0x254 */
    unsigned char window_valid,reserved601[3]; /* 0x258 */
    unsigned int estimated_offset_us;        /* 0x25c */
    unsigned int reference_us_low;           /* 0x260 */
    unsigned int estimated_round_trip_us;    /* 0x264 */
    int estimated_drift_ppb;                 /* 0x268 */
    union {
        unsigned short flags;               /* published as one HALFWORD */
        struct { unsigned char ready,drift_valid; };
    };
    unsigned char reserved622[2];
} LinkSyncFilterState;
typedef struct LinkSyncExchange {
    unsigned int local_start_us,remote_start_us,remote_end_us,local_end_us;
} LinkSyncExchange;
void link_sync_task(void *startup_role);
/* Filter estimator is a separate body review; this is its zero-argument ABI. */
void link_sync_recompute_estimate(void);
void FUN_42020c60(void) __asm__("link_sync_recompute_estimate");
#define LINK_SYNC_FILTER ((volatile LinkSyncFilterState *)0x3fccaf40U)
#define LINK_SYNC_PROBE_SEQUENCE (*(volatile unsigned int *)0x3fccaf24U)

/* Explicit ROM division call preserves the native load ordering around it. */
long long link_sync_signed_divide(long long dividend,long long divisor) __asm__("__divdi3");

/* Exact101-byte motion configuration carried by link opcode38. Bounds and
 * coefficients are unaligned little-endian fields in the wire record. */
typedef struct __attribute__((packed)) MediusMotionWireConfiguration {
    unsigned char endpoint,report_id;
    unsigned short report_length;          /* +2, zero accepts any length */
    unsigned short bit_offsets[4];         /* +4, LSB-first X/Y/wheel/pan */
    unsigned char bit_widths[4];            /* +12 */
    union {
        unsigned char bounded_axes;        /* renderer/bounds interpretation */
        unsigned char signed_axes;         /* +16, signed-field admission bits */
    };
    int positive_bounds[4];                 /* +17 */
    int negative_bounds[4];                 /* +33 */
    short coefficients[4][4];               /* +49, four8-byte rows */
    unsigned char program_selector,input_enabled,mapping_mode; /* +81..83 */
    unsigned short filter_parameter,interpolation_policy;      /* +84/+86 */
    unsigned short duration_scale_percent;  /* +88 */
    unsigned int preferred_duration_us,fallback_duration_us; /* +90/+94 */
    unsigned char input_bypass,input_bypass_flags; /* +98/+99, low2 flags */
    unsigned char tag;                      /* +100 */
} MediusMotionWireConfiguration;
typedef struct MediusMotionAxisBounds {
    int positive,negative;
    unsigned char enabled,reserved9[3];
} MediusMotionAxisBounds;
typedef struct MediusMotionTransformState {
    union {                                /* +0x00, native WORD initialization */
        short coefficients[4][4];
        unsigned int coefficient_pairs[4][2];
    };
    unsigned int fractions[4][2];           /* +0x20 */
    unsigned int coupled_fractions[2];      /* +0x40 */
    union {
        unsigned char recent_state[16];
        int context_axes[4];                /* +0x48, last derived axis context */
    };
    unsigned char mapping_mode,reserved89[3]; /* +0x58 */
    MediusMotionAxisBounds bounds[4];       /* +0x5c,12-byte stride */
} MediusMotionTransformState;
#define MEDIUS_MOTION_WIRE_CONFIGURATION ((volatile MediusMotionWireConfiguration *)0x3fcb96e0U)
#define MEDIUS_MOTION_TRANSFORM ((volatile MediusMotionTransformState *)0x3fcb9654U)
#define MEDIUS_MOTION_CONFIGURATION_READY (*(volatile unsigned char *)0x3fcb9650U)
#define MEDIUS_MOTION_FILTER_PARAMETER (*(volatile unsigned short *)0x3fcb9734U)
#define MEDIUS_MOTION_MAPPING_MODE (*(volatile unsigned char *)0x3fcb9733U)
#define MEDIUS_MOTION_INTERPOLATION_CLOCK_WORDS ((volatile unsigned int *)0x3fcb9620U)
#define MEDIUS_MOTION_SEGMENT_STORAGE ((void *)0x3fcb9590U) /* 144-byte reset span */
#define MEDIUS_MOTION_RECENT_AXIS_STATE ((void *)0x3fcb93e0U) /* 16-byte reset span */
#define MEDIUS_MOTION_AXIS_LAST_INPUT_TIMES ((volatile ClockWords *)0x3fcb93c0U)
#define MEDIUS_MOTION_INTERVAL_STORAGE ((void *)0x3fcb9400U) /* 396-byte reset span */
#define MEDIUS_MOTION_REFERENCE_CLOCKS ((volatile ClockWords *)0x3fcb93f0U)
void medius_hid_set_activity_selector(unsigned char endpoint,unsigned char report_id);
void FUN_42027c88(unsigned short endpoint,short report_id) __asm__("medius_hid_set_activity_selector");

typedef struct __attribute__((packed)) MediusMotionWireSample {
    short x,y,wheel,pan;
    unsigned char flags;
    unsigned int source_us_low;
} MediusMotionWireSample;
typedef struct MediusMotionIntervalHistory {
    unsigned short bins[128];
    unsigned char recent_bins[128];
    unsigned short head,count;              /* +0x180/+0x182, not BYTEs */
    unsigned int total_samples;             /* +0x184, saturating */
    unsigned short modal_bin,reserved394;
} MediusMotionIntervalHistory;
typedef struct MediusMotionSegment {
    union { unsigned int xy; struct { short x,y; }; };
    unsigned int reserved4;
    ClockWords until_us;
} MediusMotionSegment;
typedef struct MediusMotionSegmentQueue {
    MediusMotionSegment entries[8];
    union {
        unsigned short count_and_multiple;
        struct { unsigned char count,multiple; };
    };
    unsigned char reserved130[2];
    unsigned int selected_duration_us;
    ClockWords last_consume_us;        /* +136, queue pacing reference */
} MediusMotionSegmentQueue;
typedef struct MediusMotionInterpolationTimes {
    ClockWords until_us,started_us;
} MediusMotionInterpolationTimes;
#define MEDIUS_MOTION_INTERVAL_HISTORY ((volatile MediusMotionIntervalHistory *)0x3fcb9400U)
#define MEDIUS_MOTION_SEGMENTS ((volatile MediusMotionSegmentQueue *)0x3fcb9590U)
#define MEDIUS_MOTION_INTERPOLATION_TIMES ((volatile MediusMotionInterpolationTimes *)0x3fcb9620U)
#define MEDIUS_MOTION_LAST_SOURCE_US ((volatile ClockWords *)0x3fcb93f8U)
#define MEDIUS_MOTION_INTERPOLATION_REFERENCE_US ((volatile ClockWords *)0x3fcb93f0U)
#define MEDIUS_MOTION_PREFERRED_DURATION_HALVES ((const volatile unsigned short *)0x3fcb973aU)
#define MEDIUS_MOTION_FALLBACK_DURATION_HALVES ((const volatile unsigned short *)0x3fcb973eU)
/* Native clock ABI is two separate WORDs, not an aligned64-bit argument. */
void medius_motion_flush_report(unsigned int now_low,unsigned int now_high);
void FUN_40388f68(unsigned int now_low,unsigned int now_high) __asm__("medius_motion_flush_report");
long long medius_motion_signed_divide(long long dividend,long long divisor) __asm__("__divdi3");

/* The builder writes axes only. The caller owns prefix/tag/trailing byte. */
typedef struct MediusMotionReport {
    unsigned char prefix[16];               /* four signed32 base axes, or zero */
    short axes[4];                          /* +16: additional x/y/wheel/pan */
    unsigned char tag,trailing;             /* +24/+25, trailing bit0: input accepted */
} MediusMotionReport;
unsigned char medius_motion_build_report(unsigned int now_low,unsigned int now_high,
    int advance_interpolation,MediusMotionReport *output);
unsigned char FUN_403878e4(unsigned int now_low,unsigned int now_high,
    int advance_interpolation,void *output) __asm__("medius_motion_build_report");
int medius_link_send_with_scratch(LinkTxQueueItem *scratch,unsigned char type,
    unsigned char flags,const void *payload,unsigned int length);
#define MEDIUS_MOTION_REPORT_LAST_EMITTED_US ((volatile ClockWords *)0x3fcb93a8U)
#define MEDIUS_MOTION_REPORT_TX_MUTEX (*(RtosQueue *volatile *)0x3fcb9748U)
#define MEDIUS_MOTION_REPORT_TX_SCRATCH ((LinkTxQueueItem *)0x3fcb916cU)

int medius_hid_extract_signed_field(const unsigned char *report,unsigned int length,
    unsigned int bit_offset,unsigned int bit_width,int signed_field);
#define FUN_40387510 medius_hid_extract_signed_field
void medius_motion_drain_output_guarded(void);
#define FUN_40387580 medius_motion_drain_output_guarded
unsigned int medius_hid_get_activity_time(void);
#define FUN_40389ea4 medius_hid_get_activity_time
#define MEDIUS_MOTION_DRAIN_ACTIVE (*(volatile unsigned char *)0x3fcb93b0U)

void medius_motion_grid_timer_cb(void);
/* Timer dispatch supplies an argument that this native callback ignores. */
void medius_motion_grid_timer_dispatch(void *argument) __asm__("medius_motion_grid_timer_cb");
#define MEDIUS_MOTION_GRID_NEXT_US ((volatile ClockWords *)0x3fcb93b8U)
#define MEDIUS_MOTION_GRID_LAST_ACTIVITY_US ((volatile ClockWords *)0x3fcb9378U)
#define MEDIUS_MOTION_GRID_TIMER (*(EspTimer *volatile *)0x3fcb9380U)
#define MEDIUS_MOTION_GRID_PHASE_NS ((volatile ClockWords *)0x3fc9ddf0U)
long long medius_motion_signed_remainder(long long dividend,long long divisor) __asm__("__moddi3");

typedef union MediusMotionDelta {
    unsigned int xy;
    struct {short x,y;};
} MediusMotionDelta;
#define MOTION_RENDER_STATE ((MediusMotionProcessingState *)0x3fcbc748U)
#define MEDIUS_MOTION_RENDER_FILTER_MODE_ONE (*(volatile unsigned char *)0x3fcba231U)
#define MEDIUS_MOTION_OUTPUT_RECORDS ((volatile MediusMotionOutputRecord *)0x3fcb98e0U)
void medius_task_render(void *unused_argument);
void medius_motion_process_input_limited(unsigned int callback_limit,unsigned int record_limit);
#define FUN_403771bc medius_motion_process_input_limited
int medius_motion_processing_render_step(MediusMotionProcessingState *state,
    int x_q16,int y_q16,const int lower[2],const int upper[2],MediusMotionDelta *output);
int medius_motion_core_render_step(MediusMotionCoreState *core,
    int x_q16,int y_q16,const int lower[2],const int upper[2],MediusMotionDelta *output);
/* Six-WORD fixed-point renderer ABI; output is borrowed during the call.
 * See app/motion_output.c for the native model/sampling and commit behavior. */
int medius_motion_core_render_impl(MediusMotionCoreState *core,
    int x_q16,int y_q16,const int lower[2],const int upper[2],MediusMotionDelta *output)
    __asm__("FUN_40379124");

/* Architectural exception entries use saved special registers, not C arguments. */
void _xt_debugexception(void) __asm__("FUN_4037b948");
void _xt_kernel_exc(void) __asm__("FUN_4037b960");
void _xt_highint5(void) __asm__("FUN_4037bf24");
void _xt_nmi(void) __asm__("FUN_4037bf2c");
bool esp_flash_encryption_enabled(void);
#define FUN_4037bf34 esp_flash_encryption_enabled
void _xt_panic(void) __asm__("FUN_4037d38c");

/* Saved-frame panic handoff; the downstream dispatcher is reviewed separately. */
void panic_dispatch_frame(XtensaExceptionFrame *frame,unsigned int exception_context) __asm__("FUN_420030e0");
void panic_from_exception(XtensaExceptionFrame *frame) __asm__("FUN_40375c24");
#define FUN_40375c24 panic_from_exception
#define FUN_40375c48 xt_unhandled_exception
void panic_clear_ipc_stall(void);
#define FUN_40375c6c panic_clear_ipc_stall

/* Backtrace cursor prefix; printer also carries an optional frame pointer.
 * pc/next_pc retain encoded Xtensa return addresses until local classification. */
typedef struct BacktraceFrame {
    unsigned int pc,sp,next_pc;
    XtensaExceptionFrame *exception_frame;
} BacktraceFrame;
bool esp_backtrace_get_next_frame(volatile BacktraceFrame *cursor);
void esp_backtrace_get_start(unsigned int *pc,unsigned int *sp,unsigned int *next_pc);
#define FUN_40375ce0 esp_backtrace_get_next_frame
#define FUN_40375f1c esp_backtrace_get_start

float medius_math_fabsf(float value);
/* Binary32 exponential-minus-one with native reduction/rounding. */
float medius_math_expm1f(float value) __asm__("FUN_420158dc");
#define FUN_4201579c medius_math_tanhf
#define FUN_4201ec70 medius_math_fabsf

#define FUN_420158dc medius_math_expm1f

/* Reviewed panic output and copied-cursor backtrace printing. */
int esp_backtrace_print_from_frame(int depth,const BacktraceFrame *frame,unsigned char panic);
void panic_print_str(const char *text);
void panic_print_hex(unsigned int value);
#define FUN_40375d38 esp_backtrace_print_from_frame
#define FUN_42002a4c panic_print_str
#define FUN_42002a8c panic_print_hex
#define MEDIUS_PANIC_UART_HAL ((UartHal *)0x3fc9da08U)
void uart_hal_write_txfifo(UartHal *hal,const unsigned char *data,unsigned int length,unsigned int *written);
#define FUN_40385e94 uart_hal_write_txfifo

/* Reviewed panic watchdog/re-entry helpers and diagnostic callbacks. */
#define PANIC_WDT0_TEMPLATE ((const volatile WatchdogHalContext *)0x3c0453b8U)
#define PANIC_WDT1_TEMPLATE ((const volatile WatchdogHalContext *)0x3c0453c0U)
#define PANIC_RTC_WDT ((WatchdogHalContext *)0x3fc9da0cU)
#define PANIC_ENTRY_COUNTS ((volatile unsigned int *)0x3fc9e4acU)
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
#define FUN_42002980 panic_feed_enabled_wdts
#define FUN_42002a08 panic_print_abort_details
#define FUN_42002ae4 panic_print_dec
#define FUN_42002b70 esp_panic_handler_disable_timg_wdts
#define FUN_42002bbc esp_panic_handler_enable_rtc_wdt
#define FUN_42002c14 esp_panic_handler_feed_wdts
#define FUN_42002c30 esp_panic_handler_increment_entry_count
#define FUN_42003288 panic_restart
#define PANIC_ABORT_DETAILS (*(const char * volatile *)0x3fca71acU)
void panic_abort(const char *details) __attribute__((noreturn));
void esp_system_abort(const char *details) __attribute__((noreturn));

/* Reviewed panic diagnostics, frame tables and classification layout. */
/* Panic information layout: offsets0..24 are used by these classifiers.
 * The frame/pseudo-cause tail agrees with the pinned ESP-IDF panic_info_t and
 * its caller's36-byte initialization; these helpers leave that tail untouched. */
typedef enum {
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
#define PANIC_FRAMES ((const XtensaExceptionFrame * volatile *)0x3fca71c0U)
#define PANIC_ABORT_IN_PROGRESS (*(volatile unsigned char *)0x3fca71b0U)
/*24 pointers: PC, PS, A0..A15, SAR, EXCCAUSE, EXCVADDR, LBEG, LEND, LCOUNT. */
#define PANIC_REGISTER_LABELS ((const char * const *)0x3c0453d0U)
#define PANIC_PSEUDO_REASONS ((const char * const volatile *)0x3c045430U)
#define PANIC_ARCH_REASONS ((const char * const volatile *)0x3c045450U)
#define FUN_4200286c esp_cache_err_get_cpuid
#define FUN_4200321c panic_dump_frames
#define FUN_420032d8 panic_debug_details
#define FUN_42003328 panic_illegal_instruction_details
#define FUN_4200337c panic_cache_details
#define FUN_42003458 panic_print_registers
#define FUN_42003548 panic_arch_fill_info
#define FUN_42003580 panic_soc_fill_info
#define FUN_420035e8 panic_print_frame_backtrace

/* Panic-entry local storage and the no-override SoC check hook. */
typedef union PanicInfoStorage {
    PanicInfo info;
    unsigned int words[9];
} PanicInfoStorage;
unsigned int panic_soc_check_pseudo_cause(const void *unused_frame,PanicInfo *unused_info);
#define FUN_4201e760 panic_soc_check_pseudo_cause
/* Retained crash-record capture followed by reviewed system panic handling. */
void panic_record_and_handle(PanicInfo *info) __asm__("FUN_42009154");

/* System panic handler, debugger semihosting payload and breakpoint API. */
typedef struct PanicSemihostArguments {
    const char *text;
    size_t length;
} PanicSemihostArguments;
void esp_panic_handler(PanicInfo *info);
int esp_cpu_set_breakpoint(unsigned int index,const void *address);
unsigned int esp_reset_reason_get_hint(void);
#define MEDIUS_PANIC_ELF_SHA256 ((const char *)0x3fca7170U)
/* Retain the native handler's ILL if its restart wrapper unexpectedly returns. */
void medius_panic_restart_returnable(void) __asm__("panic_restart");
#define FUN_42002c58 esp_panic_handler
#define FUN_4202272c esp_cpu_set_breakpoint

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
void panic_append_unfed_task(void *opaque,const char *fragment);
void panic_capture_watchdog_tasks(void);
RtosTask *xTaskGetCurrentTaskHandleForCore(int core_id);
const EspAppDescription *get_app_description(void);
#define PANIC_IMAGE_ID (*(volatile unsigned int *)0x3fca7858U)
/* Caller-only formatter ABI; its pending body is not counted here. */
#define FUN_42008f34 panic_record_checksum
#define FUN_42008fa0 panic_append_unfed_task
#define FUN_42009038 panic_capture_watchdog_tasks
#define FUN_42009154 panic_record_and_handle
#define FUN_42009318 boot_read_previous_panic

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
#define SOC_MEMORY_REGIONS ((const SocMemoryRegion *)0x3c045578U)
#define SOC_MEMORY_TYPES ((const SocMemoryType *)0x3c045640U)
#define HEAP_REGISTRATION_HEAD (*(HeapRegion *volatile *)0x3fca73b4U)
#define HEAP_LOG_LEVEL (*(const volatile unsigned int *)0x3fc9da38U)
#define HEAP_INIT_LOG_TAG ((const char *)0x3c040e44U)
#define MEMORY_LAYOUT_LOG_TAG ((const char *)0x3c040f90U)
void qsort(void *base, size_t count, size_t width, int (*compare)(const void *, const void *));
void *multi_heap_malloc(MultiHeap *heap, size_t bytes);
size_t soc_get_available_memory_regions(SocMemoryRegion *output);
void heap_caps_init(void);
int heap_startup_init(void);
#define FUN_42003cd0 heap_caps_init
#define FUN_42003f1c heap_startup_init
#define FUN_42003f44 soc_get_available_memory_regions

/* Reviewed per-core IPC static storage and startup constructor. */
typedef struct IpcTaskName {
    union { unsigned int word; unsigned char bytes[4]; } initial;
    unsigned char terminator;
    unsigned char padding_5[3];
} IpcTaskName; /* The native task name uses only the first five bytes. */
#define IPC_INITIAL_TASK_NAME ((const volatile IpcTaskName *)0x3c040e3cU)
#define IPC_MUTEX_STORAGE ((RtosQueue *)0x3fc9e55cU)
#define IPC_ACKNOWLEDGEMENT_STORAGE ((RtosQueue *)0x3fc9e4b4U)
void esp_ipc_init(void);
#define FUN_420036bc esp_ipc_init

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
#define RTC_DEFAULT_CONFIGURATION (*(const volatile unsigned int *)0x3c0453a4U)
void select_rtc_slow_clk(unsigned int requested_source);
/* Dependency's own implementation is reviewed separately. */
void periph_module_enable(unsigned int module);
static __inline__ __attribute__((always_inline)) void
esp_cpu_set_cycle_count(unsigned int cycles)
{
    __asm__ volatile ("wsr.ccount %0" : : "a"(cycles) : "memory");
}
#define FUN_42002370 select_rtc_slow_clk

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
#define PERIPHERAL_REFERENCES (*(volatile PeripheralReferenceCounts *)0x3fca73d0U)
unsigned int periph_ll_get_clk_en_mask(unsigned int module);
/* Raw native enable WORD: zero versus any nonzero value. */
unsigned int periph_ll_get_rst_en_mask(unsigned int module,unsigned int enable);
#define FUN_42004990 periph_ll_get_clk_en_mask
#define FUN_42004b24 periph_ll_get_rst_en_mask
#define FUN_42004cf0 periph_module_enable

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
    ESP_MSPI_IO_D6 = 9, ESP_MSPI_IO_D7 = 10, ESP_MSPI_IO_CS1 = 11
};
typedef struct RtcPadDescriptor {
    unsigned int uninterpreted0[10];
    unsigned int force_hold_mask; /* +0x28 in the56-byte SDK descriptor. */
    unsigned int uninterpreted44[3];
} RtcPadDescriptor;
typedef struct RtcSleepWakeRegisters {
    volatile unsigned int pad_hold;        /* RTC_CNTL+0xd8 */
    unsigned int uninterpreted_dc;
    volatile unsigned int ext1_selection;  /* RTC_CNTL+0xe0, pins0..21 */
} RtcSleepWakeRegisters;
#define RTC_SLEEP_WAKE_REGISTERS ((RtcSleepWakeRegisters *)0x600080d8U)
#define RTC_GPIO_CHANNEL_MAP ((const volatile signed char *)0x3c051814U)
#define RTC_PAD_DESCRIPTORS ((const volatile RtcPadDescriptor *)0x3c051344U)
void esp_sleep_config_gpio_isolate(void);
/* Native entry consumes the low BYTE; values beyond0/1 are not normalized. */
void esp_sleep_enable_gpio_switch(unsigned char enable);
int __esp_system_init_fn_esp_sleep_startup_init(void);
int gpio_sleep_set_pull_mode(unsigned int pin,unsigned int mode);
#define FUN_42004f0c esp_sleep_config_gpio_isolate
#define FUN_42004fe4 esp_sleep_enable_gpio_switch
#define FUN_42005084 __esp_system_init_fn_esp_sleep_startup_init
#define FUN_42005098 esp_deep_sleep_wakeup_io_reset
#define FUN_42010610 gpio_sleep_set_pull_mode

/* Native OTA selection records: CRC covers ONLY the4-byte sequence field. */
typedef struct OtaSelectEntry {
    volatile unsigned int sequence;
    unsigned char sequence_label[20];
    volatile unsigned int state;
    volatile unsigned int crc;
} OtaSelectEntry;
/* Byte views preserve native HIGH-before-LOW reads of unaligned LE16 fields.
 * This24-byte header view names only revision-admission fields used here.
 */
typedef struct RevisionPairBytes {
    volatile unsigned char low,high;
} RevisionPairBytes;
typedef struct ImageRevisionHeader {
    unsigned char uninterpreted0[12];
    RevisionPairBytes chip_id;          /* +12 */
    unsigned char legacy_minimum_revision;   /* +14: unused */
    RevisionPairBytes minimum_revision;/* +15 */
    RevisionPairBytes maximum_revision;/* +17 */
    unsigned char uninterpreted19[5];
} ImageRevisionHeader;
unsigned int bootloader_common_ota_select_crc(const OtaSelectEntry *entry);
bool bootloader_common_ota_select_valid(const OtaSelectEntry *entry);
int bootloader_common_check_efuse_blk_validity(unsigned int minimum_revision,unsigned int maximum_revision);
int bootloader_common_check_chip_validity(const ImageRevisionHeader *header,unsigned int image_type);
int bootloader_common_get_active_otadata(const OtaSelectEntry entries[2]);
int bootloader_common_select_otadata(const OtaSelectEntry entries[2],const unsigned char validity[2],unsigned char select_maximum);
unsigned int bootloader_mmap_get_free_pages(void);
const void *bootloader_mmap(unsigned int flash_address,unsigned int length);
void bootloader_munmap(const void *mapped_address);
unsigned int esp_rom_crc32_le(unsigned int initial_crc,const void *data,unsigned int size) __asm__("crc32_le");
#define BOOT_MMAP_HANDLE (*(volatile unsigned int *)0x3fccbb34U)
#define BOOT_EARLY_LOG_ENABLED (*(volatile unsigned int *)0x3fc9da38U)
#define FUN_420116b4 bootloader_common_ota_select_crc
#define FUN_420116c8 bootloader_common_ota_select_valid
#define FUN_420116f4 bootloader_common_check_efuse_blk_validity
#define FUN_420117b0 bootloader_common_check_chip_validity
#define FUN_420118d0 bootloader_common_get_active_otadata
#define FUN_4201ea68 bootloader_common_select_otadata
#define FUN_42011948 bootloader_mmap_get_free_pages
#define FUN_42011954 bootloader_mmap
#define FUN_420119c4 bootloader_munmap

/* OTA operation44 bytes. Link at+36 is a BSD LIST entry; previous_link
 * addresses the head slot or a preceding node's next field, not a node.
 * Bytes9..11 and17..19 are not interpreted by these reviewed entries.
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
} ImageHeader;
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
/* Native partition list node52 and iterator20; list owns descriptors. */
typedef struct PartitionListNode {
    EspPartition info;
    unsigned char user_registered,reserved45[3];
    struct PartitionListNode *next;
} PartitionListNode;
typedef struct PartitionIterator {
    unsigned int type,subtype;
    const char *label;
    PartitionListNode *next_item;
    const EspPartition *info;
} PartitionIterator;
/* Reviewed host partition API boundaries. */
const EspPartition *esp_partition_find_first(unsigned int type,unsigned int subtype,const char *label);
PartitionIterator *esp_partition_find(unsigned int type,unsigned int subtype,const char *label);
PartitionIterator *esp_partition_next(PartitionIterator *iterator);
const EspPartition *esp_partition_get(PartitionIterator *iterator);
void esp_partition_iterator_release(PartitionIterator *iterator);
int esp_partition_mmap(const EspPartition *partition,size_t offset,size_t size,unsigned int memory,const void **pointer,unsigned int *handle);
void esp_partition_munmap(unsigned int handle);
int esp_partition_erase_range(const EspPartition *partition,size_t offset,size_t length);
int esp_partition_write(const EspPartition *partition,size_t offset,const void *data,size_t size);
int esp_image_verify(unsigned int mode,const ImagePosition *position,ImageMetadataScratch *metadata);
#define OTA_OPERATIONS (*(OtaOperation *volatile *)0x3fccbb28U)
#define OTA_LAST_HANDLE (*(volatile unsigned int *)0x3fccbb24U)
#define OTA_RUNNING_PARTITION (*(const EspPartition *volatile *)0x3fccbb20U)
#define FUN_420108c4 esp_ota_init_entry
#define FUN_420108f8 ota_read_otadata
#define FUN_42010984 ota_rewrite_sequence
#define FUN_420109bc ota_cache_running_partition
#define FUN_42010a1c esp_ota_get_running_partition
#define FUN_42010a30 ota_validate_image_region
#define FUN_42010bd4 esp_ota_abort
#define FUN_42010c10 esp_ota_end
const EspPartition *esp_partition_verify(const EspPartition *partition);
#define FUN_42010a54 esp_ota_write
#define FUN_420110c8 esp_ota_begin
bool esp_ota_check_rollback_is_possible(void);
#define FUN_42010c98 esp_ota_set_boot_partition
#define FUN_42010d80 esp_ota_get_next_update_partition
#define FUN_42010de4 esp_ota_check_rollback_is_possible
#define FUN_42010ed4 esp_ota_current_ota_is_workable
#define FUN_42010ff8 esp_ota_get_state_partition

#define FUN_4201119c ensure_partitions_loaded
#define FUN_4201138c esp_partition_next
#define FUN_42011410 esp_partition_find
#define FUN_42011460 esp_partition_find_first
#define FUN_42011480 esp_partition_iterator_release
#define FUN_42011490 esp_partition_get
#define FUN_420114a8 esp_partition_verify
#define FUN_4201150c esp_partition_write
#define FUN_42011574 esp_partition_erase_range
#define FUN_420115c0 esp_partition_mmap
#define FUN_42011618 esp_partition_munmap
#define FUN_42011624 esp_partition_is_flash_region_writable
#define FUN_42011674 esp_partition_main_flash_region_safe
#define FUN_420116ac esp_partition_get_main_flash_sector_size
#define PARTITION_LIST (*(PartitionListNode *volatile *)0x3fccbb30U)
#define PARTITION_LIST_LOCK ((NewlibLock *)0x3fccbb2cU)
typedef struct PartitionTableEntry {
    unsigned short magic;
    unsigned char type,subtype;
    unsigned int address,size;
    char label[16];
    unsigned int flags;
} PartitionTableEntry;
/* ESP32-S3 ROM MD5 context88: state4, bit count2, input64 bytes. */
typedef struct RomMd5Context {
    unsigned int state[4],bit_count[2];
    unsigned char input[64];
} RomMd5Context;
int ensure_partitions_loaded(void);
bool esp_partition_is_flash_region_writable(size_t address,size_t size);
bool esp_partition_main_flash_region_safe(size_t address,size_t size);
unsigned int esp_partition_get_main_flash_sector_size(void);
void MD5Init(RomMd5Context *); /* ROM0x40001c5c */
void MD5Update(RomMd5Context *,const void *,unsigned int length); /* ROM0x40001c68 */
void MD5Final(unsigned char digest[16],RomMd5Context *); /* ROM0x40001c74 */
void *malloc(size_t bytes);
int strcmp(const char *left,const char *right);
int memcmp(const void *left,const void *right,size_t length);
char *strncpy(char *destination,const char *source,size_t length);

/* Application image parsing and corruption-hash verification boundaries. */
int bootloader_flash_read(unsigned int address,void *output,unsigned int size,unsigned char allow_decrypt);
int image_process_checksum(Sha256Context *,unsigned int checksum,ImageMetadataScratch *,unsigned int silent,unsigned int skip_checksum);
int image_process_header(ImageMetadataScratch *,unsigned int address,Sha256Context **,unsigned int verify,unsigned int silent);
int image_process_segments(ImageMetadataScratch *,unsigned int silent,Sha256Context *,unsigned int *checksum);
int image_process_appended_hash(ImageMetadataScratch *,unsigned int partition_size,unsigned int silent);
int image_load(unsigned int mode,const ImagePosition *,ImageMetadataScratch *);
Sha256Context *bootloader_sha256_start(void);
void bootloader_sha256_data(Sha256Context *,const void *data,unsigned int size);
void bootloader_sha256_finish(Sha256Context *,unsigned char *output);
void bootloader_debug_buffer(const void *data,unsigned int size,const char *label);
void bzero(void *storage,size_t length);
#define FUN_420119dc bootloader_flash_read
#define FUN_42011a28 image_process_checksum
#define FUN_42011ac8 image_process_header
#define FUN_42011b88 image_process_segments
#define FUN_42011e68 image_process_appended_hash
#define FUN_42011ec0 image_load
#define FUN_42011fd4 esp_image_verify
#define FUN_42011fe4 bootloader_sha256_start
#define FUN_4201200c bootloader_sha256_data
#define FUN_42012030 bootloader_sha256_finish
#define FUN_4201eab4 bootloader_debug_buffer

void esp_crosscore_int_send_print_backtrace(int core_id);
void esp_crosscore_int_send_twdt_abort(int core_id);
#define FUN_42013260 task_wdt_isr

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
#define SHA256_PADDING ((const unsigned char *)0x3c051964U)
#define CRYPTO_SHA_AES_LOCK ((NewlibLock *)0x3fccbb9cU)
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

/* ESP32-S3 DMA descriptor: two 12-bit lengths, success EOF at bit30,
 * DMA ownership at bit31. Keep raw control bits24..29 on field updates.
 * These are shared native storage, not per-call descriptor allocations.
 */
typedef struct CryptoDmaDescriptor {
    volatile unsigned int control;
    const void *volatile buffer;
    struct CryptoDmaDescriptor *volatile next;
} CryptoDmaDescriptor;
#define SHA_PREFIX_DESCRIPTOR ((CryptoDmaDescriptor *)0x3fca68a0U)
#define SHA_INPUT_DESCRIPTOR ((CryptoDmaDescriptor *)0x3fca68acU)
#define CRYPTO_TX_CHANNEL (*(GdmaChannel *volatile *)0x3fccbbe0U)
#define CRYPTO_RX_CHANNEL (*(GdmaChannel *volatile *)0x3fccbbe4U)
#define CRYPTO_AES_TRIGGER ((const volatile GdmaTrigger *)0x3c0519a4U)
#define CRYPTO_SHA_TRIGGER ((const volatile GdmaTrigger *)0x3c0519b0U)
int esp_sha_dma_start(const CryptoDmaDescriptor *input);
int crypto_shared_gdma_init(void);
int esp_crypto_shared_gdma_start(const CryptoDmaDescriptor *input,
    const CryptoDmaDescriptor *output,unsigned int peripheral);
#define FUN_42014fa4 mbedtls_sha256_update
#define FUN_42015090 mbedtls_sha256_finish
#define FUN_4201511c esp_sha_write_digest_state
#define FUN_4201512c esp_sha_read_digest_state
#define FUN_4201513c esp_sha_acquire_hardware
#define FUN_420151a0 esp_sha_release_hardware
#define FUN_420155fc sha_hal_hash_block
#define FUN_42015658 sha_hal_hash_dma
#define FUN_42015694 sha_hal_wait_idle
#define FUN_420156a4 sha_hal_read_digest
#define FUN_42015700 sha_hal_write_digest
#define FUN_42013b18 esp_crypto_sha_aes_lock_acquire
#define FUN_42013b28 esp_crypto_sha_aes_lock_release
#define FUN_4201ec44 esp_dport_access_read_buffer
#define FUN_420151cc esp_sha_dma
#define FUN_42015480 esp_sha_dma_start
#define FUN_42015490 crypto_shared_gdma_init
#define FUN_4201555c esp_crypto_shared_gdma_start

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
#define CXX_EH_KEY (*(volatile unsigned int *)0x3fccbbe8U)
#define CXX_EH_TLS_ENABLED (*(volatile unsigned char *)0x3fccbbecU)
void cxx_eh_globals_destroy(void *storage);
void cxx_eh_globals_initialize(void);
void cxx_unwind_delete_exception_abort(CxxUnwindException *) __attribute__((noreturn));
void medius_cxx_fatal_stub(void) __attribute__((noreturn));
#define FUN_42015740 cxx_eh_globals_destroy
#define FUN_42015764 cxx_eh_globals_initialize
#define FUN_42015784 cxx_unwind_delete_exception_abort
#define FUN_42015790 medius_cxx_fatal_stub
int pthread_key_create(unsigned int *key,PthreadDestructor destructor);

/* Newlib general FILE vector output and buffer refill. */
int medius_newlib_write_vectors(NewlibReent *,NewlibFile *,MediusNewlibStringWriteRequest *);
int medius_newlib_flush_vectors(NewlibReent *,NewlibFile *,MediusNewlibStringWriteRequest *);
int medius_newlib_flush_line_visitor(NewlibReent *,NewlibFile *);
int medius_newlib_refill_file(NewlibReent *,NewlibFile *);
void *memchr(const void *input,int byte_value,size_t length);
#define FUN_4201626c medius_newlib_write_vectors
#define FUN_4201cee0 medius_newlib_flush_vectors
#define FUN_4201cffc medius_newlib_flush_line_visitor
#define FUN_4201d01c medius_newlib_refill_file

int newlib_fprintf(NewlibFile *stream,const char *format,...);
int newlib_printf(const char *format,...);
int newlib_snprintf(char *output,size_t capacity,const char *format,...);
int medius_newlib_vformat_string(NewlibReent *,NewlibFile *,const char *,va_list);
#define FUN_42016220 newlib_fprintf
#define FUN_42016518 newlib_printf
#define FUN_4201654c newlib_snprintf

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
#define MEDIUS_NEWLIB_GLOBAL_LOCALE (*(const void *volatile *)0x3fc9e478U)
#define FUN_4201ce48 medius_newlib_format_temporary_stream
#define FUN_4201d110 medius_newlib_localeconv
#define FUN_4201d120 medius_newlib_frexp

/* Reviewed Newlib 32-bit file positioning. */
int medius_newlib_seek_file(NewlibReent *,NewlibFile *,long,int);
#define FUN_42016254 medius_newlib_seek_file
int medius_newlib_seek_file_offset(NewlibReent *,NewlibFile *,long,int);
#define FUN_420167cc medius_newlib_seek_file_offset

/* ESP32-S3 memory protection: saved 24-byte boot configuration and MMIO. */
enum {MEMPROT_IRAM=1,MEMPROT_DRAM=2,MEMPROT_RTCFAST=4};
typedef struct MemoryProtectionMonitor {
    volatile unsigned int lock;
    volatile unsigned int control; /* bit 0: interrupt clear; bit 1: enable */
} MemoryProtectionMonitor; /* register prefix, not the complete peripheral */
#define MEMPROT_CONFIGURATION (*(volatile BootMemoryProtectionConfiguration *)0x3fc9da74U)
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
int esp_mprot_set_pms_lock(unsigned int,int);
#define FUN_420055d8 esp_mprot_set_pms_lock
int esp_mprot_set_monitor_lock(unsigned int,int);
#define FUN_42005b80 esp_mprot_set_monitor_lock
int esp_mprot_get_monitor_lock(unsigned int,unsigned char *,int);
#define FUN_42005c28 esp_mprot_get_monitor_lock
int esp_mprot_set_monitor_en(unsigned int,unsigned char,int);
#define FUN_42005d10 esp_mprot_set_monitor_en
int esp_mprot_get_monitor_en(unsigned int,unsigned char *,int);
#define FUN_42005e20 esp_mprot_get_monitor_en
int esp_mprot_monitor_clear_intr(unsigned int,int);
#define FUN_42005eec esp_mprot_monitor_clear_intr
#define FUN_42005fd0 esp_mprot_is_conf_locked_any
int esp_mprot_ll_err_to_esp_err(int);
#define FUN_42006d5c esp_mprot_ll_err_to_esp_err

/* Exact, single memory-protection area IDs; combinations are not accepted. */
enum {
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
int esp_mprot_set_pms_area(unsigned int,unsigned int,int);
#define FUN_42005658 esp_mprot_set_pms_area
int esp_mprot_get_pms_area(unsigned int,unsigned int *,int);
#define FUN_4200594c esp_mprot_get_pms_area

/* SRAM split-line constraint words and native stack workspace. */
enum {MEMPROT_SPLIT_MAIN=1,MEMPROT_SPLIT_IRAM0=2,
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
int esp_mprot_set_split_addr(unsigned int,unsigned int,const void *,int);
#define FUN_4200513c esp_mprot_set_split_addr
#define MEMPROT_SPLIT_DEFAULTS ((const unsigned int *)0x3c045690U)
#define MEMPROT_SPLIT_HIGH_LIMITS ((const unsigned int *)0x3c0456acU)

#define FUN_42006244 esp_mprot_set_prot
#define MEMPROT_DEFAULT_SRAM_SPLIT 0x4038da00U
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
#define FUN_42016c38 medius_newlib_get_string_argument
MediusNewlibArgumentValue *medius_newlib_get_stream_argument(int,const unsigned char *,MediusXtensaVaListCursor *,unsigned int *,MediusNewlibArgumentValue *,int *,const unsigned char **);
#define FUN_42019ce0 medius_newlib_get_stream_argument

#define FUN_42017108 medius_newlib_vformat_string

#define FUN_4201a1b0 medius_newlib_vformat_stream



/* Native VFS registry; the exported table registration keeps its existing
 * address-symbol binding used by the console/UART driver declarations. */
int esp_vfs_register_fs_common(const char *,unsigned int,const volatile VfsOperations *,int,void *,int *);
int esp_vfs_register_fs(const char *,const volatile VfsOperations *,int,void *) __asm__("FUN_4203274c");
#define FUN_42032640 esp_vfs_register_fs_common
#define FUN_4203274c esp_vfs_register_fs

/* NVS Page::SEC_SIZE, initialized by the native global constructor. */
#define NVS_SECTOR_SIZE (*(volatile unsigned int *)0x3fccbbb0U)
void nvs_page_initialize_sector_size(void);
#define FUN_42013ff8 nvs_page_initialize_sector_size

/* Reviewed host USB shutdown and root-hub request boundaries. */
#define MEDIUS_HOST_HCD_CONTEXT(controller) ((volatile MediusDwc2HostContextPrefix *)(0x3fca7c24U+(unsigned int)(controller)*668U))
#define MEDIUS_HOST_HCD_CHANNEL(controller,channel) ((volatile MediusHostChannel *)(0x3fca7c80U+(unsigned int)(controller)*668U+(unsigned int)(channel)*36U))
#define MEDIUS_HOST_USB_INTERRUPT (*(InterruptHandle *volatile *)0x3fca7ec0U)
#define MEDIUS_HOST_USB_PHY (*(MediusUsbPhyContext *volatile *)0x3fca7ec4U)
#define MEDIUS_HOST_CAPTURED_PORT (*(MediusHostHubPortPrefix *volatile *)0x3fca97ecU)
int usbh_roothub_control(MediusHostBusPrefix *,unsigned char *,unsigned char *);
int usb_hc_deinit(MediusHostBusPrefix *);
void usb_hc_low_level_deinit(MediusHostBusPrefix *);
void usb_osal_sem_delete(void *);
MediusHostHubPortPrefix *usbh_find_hubport(unsigned char,unsigned char,unsigned char);
void medius_usb_host_event(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);
#define FUN_4201fef4 usb_hc_deinit
#define FUN_4201eea8 usb_hc_low_level_deinit

/* Empty native entry views; original prototypes are not implied. */
void return_without_work_4038b230(void);
#define FUN_4038b230 return_without_work_4038b230
void return_without_work_4201e748(void);
#define FUN_4201e748 return_without_work_4201e748
void return_without_work_4201e758(void);
#define FUN_4201e758 return_without_work_4201e758
void return_without_work_4201e7bc(void);
#define FUN_4201e7bc return_without_work_4201e7bc
void return_without_work_4201e7dc(void);
#define FUN_4201e7dc return_without_work_4201e7dc
void return_without_work_4201e7e4(void);
#define FUN_4201e7e4 return_without_work_4201e7e4
void return_without_work_4201e7ec(void);
#define FUN_4201e7ec return_without_work_4201e7ec
void return_without_work_4201e7f4(void);
#define FUN_4201e7f4 return_without_work_4201e7f4
void return_without_work_4201e808(void);
#define FUN_4201e808 return_without_work_4201e808
void return_without_work_4201e810(void);
#define FUN_4201e810 return_without_work_4201e810
void return_without_work_4201e818(void);
#define FUN_4201e818 return_without_work_4201e818
void return_without_work_4201e820(void);
#define FUN_4201e820 return_without_work_4201e820
void return_without_work_4201e828(void);
#define FUN_4201e828 return_without_work_4201e828
void return_without_work_4201e830(void);
#define FUN_4201e830 return_without_work_4201e830
void return_without_work_4201e838(void);
#define FUN_4201e838 return_without_work_4201e838
void return_without_work_4201e840(void);
#define FUN_4201e840 return_without_work_4201e840
void return_without_work_4201e848(void);
#define FUN_4201e848 return_without_work_4201e848
void return_without_work_4201e850(void);
#define FUN_4201e850 return_without_work_4201e850
void return_without_work_4201e858(void);
#define FUN_4201e858 return_without_work_4201e858
void return_without_work_4201e860(void);
#define FUN_4201e860 return_without_work_4201e860
void return_without_work_4201e868(void);
#define FUN_4201e868 return_without_work_4201e868
void return_without_work_42022724(void);
#define FUN_42022724 return_without_work_42022724
void return_without_work_4203315c(void);
#define FUN_4203315c return_without_work_4203315c

/* Mutable32-byte lazy version/hash cache, separate from the ELF SHA text cache. */
typedef char FirmwareLabelBuffer[32];
#define FIRMWARE_LABEL_BUFFER ((FirmwareLabelBuffer *)0x3fccba5cU)

#define HOST_LOG_RECURSION_GUARD (*(volatile unsigned char *)0x3fca96e0U)
int medius_format_bounded_current_context(char *output,unsigned int capacity,
    const char *format,MediusXtensaVaList argument_list);
int medius_host_log_hook(const char *format,MediusXtensaVaList argument_list);

int xPortStartScheduler(void) __attribute__((noreturn));

unsigned int bootloader_flash_execute_command_common(unsigned char command,unsigned int address_bits,unsigned int address,unsigned char dummy_bits,unsigned char mosi_bits,unsigned int mosi_data,unsigned char miso_bits);

unsigned int bootloader_read_flash_id(void);

int bootloader_flash_reset_chip(void);

/* Flash IPC handshake: raw bytes accept every nonzero native value. */
#define FLASH_OPERATION_COMPLETE (*(volatile unsigned char *)0x3fccbb6aU)
#define FLASH_OPERATION_PEER_READY (*(volatile unsigned char *)0x3fccbb6bU)
#define FLASH_OPERATION_OWNER (*(volatile int *)0x3fc9e2bcU)
void spi_flash_disable_cache(void);
void spi_flash_op_lock(void);
void spi_flash_op_unlock(void);
void spi_flash_op_block_func(void *unused_cpu_argument);
void spi_flash_disable_interrupts_caches_and_other_cpu(void);
void spi_flash_enable_interrupts_caches_and_other_cpu(void);
int esp_ipc_call_nonblocking(unsigned int cpu_id,IpcCallback callback,void *argument);
int spi_flash_os_yield(FlashOsContext *context,unsigned int *unused_status);
int spi_flash_os_check_yield(FlashOsContext *context,unsigned int chip_status,unsigned int *request);

int xTaskResumeAll(void);

#define FLASH_ERASE_IN_PROGRESS (*(volatile unsigned char *)0x3fccbb68U)
#define FLASH_BROWNOUT_RESET_NEEDED (*(volatile unsigned char *)0x3fccbb69U)
#define FLASH_OPERATION_MUTEX (*(RtosQueue *volatile *)0x3fccbb6cU)
int flash_os_delay_us(void *unused,unsigned int microseconds);
void main_flash_op_status(unsigned int flags);
int main_flash_region_protected(FlashOsContext *context,unsigned int address,unsigned int size);
void flash_os_cache_disable(void);
void flash_os_cache_enable(void);
int spi1_start(FlashOsContext *unused_context);
int spi1_end(FlashOsContext *context);
void spi_flash_needs_reset_check(void);
void spi_flash_set_erasing_flag(unsigned char erasing);
unsigned char spi_flash_brownout_need_reset(void);
void flash_update_rom_chip_id(void);
void spi_flash_init_lock(void);

/* IPC submission boundaries: full-width scheduler/priority and explicit wait mode. */
unsigned int uxTaskPriorityGet(RtosTask *task);
int esp_ipc_call_and_wait(unsigned int cpu_id,IpcCallback callback,
    void *argument,unsigned int wait_for);

void vListInsertEnd(RtosList *list,RtosListItem *item);

/* Native scheduler lists and counters; ready array contains25 lists. */
#define RTOS_READY_LISTS ((RtosList *)0x3fca74d4U)
#define RTOS_DELAYED_LIST1 ((RtosList *)0x3fca74c0U)
#define RTOS_DELAYED_LIST2 ((RtosList *)0x3fca74acU)
#define RTOS_PENDING_READY_LISTS ((RtosList *)0x3fca747cU)
#define RTOS_TASK_COUNT (*(volatile unsigned int *)0x3fca744cU)
#define RTOS_TASK_NUMBER (*(volatile unsigned int *)0x3fca742cU)
#define RTOS_TOP_READY_PRIORITY (*(volatile unsigned int *)0x3fca7444U)
int prvIsYieldRequiredSMP(RtosTask *task,unsigned int priority,int yield_equal_priority);
void prvAddNewTaskToReadyList(RtosTask *task);

/* Native scheduler overflow, pending-yield and deferred-tick WORDs. */
#define RTOS_TICK_OVERFLOWS (*(volatile unsigned int *)0x3fca7430U)
#define RTOS_YIELD_PENDING ((volatile unsigned int *)0x3fca7434U)
#define RTOS_PENDED_TICKS (*(volatile unsigned int *)0x3fca743cU)
void vTaskSwitchContext(void);

/* Native idle-task slots and the read-only OpenOCD priority-list bound. */
#define RTOS_IDLE_TASK_HANDLES ((RtosTask * volatile *)0x3fca7420U)
#define RTOS_DEBUGGER_TOP_USED_PRIORITY (*(const volatile unsigned int *)0x3c0458f0U)
void prvInitialiseNewTask(TaskEntry entry,char *name,unsigned int stack_bytes,void *argument,unsigned int priority,RtosTask **created_task,RtosTask *task,int core_id);
RtosTask *xTaskCreateStaticPinnedToCore(TaskEntry entry,char *name,unsigned int stack_bytes,void *argument,unsigned int priority,unsigned int *stack,RtosTask *task_buffer,int core_id);
void vTaskStartScheduler(void);
void vApplicationGetIdleTaskMemory(RtosTask **task_buffer,unsigned int **stack_buffer,unsigned int *stack_bytes);

/* Host capture storage: native access views, with shared borrowed lifetimes. */
#define medius_snapshot_section_packet (*(MediusSnapshotSectionPacket *)0x3fccaa60U)
#define medius_snapshot_sequence (*(volatile MediusHostControlByte *)0x3fcaff1eU)
#define medius_hid_descriptor_packet (*(MediusHidDescriptorPacket *)0x3fca95d8U)
#define medius_hid_descriptor_blob (*(MediusHidDescriptorBlob *)0x3fcab608U)
#define medius_string_descriptor_archive_used (*(volatile unsigned short *)0x3fcaae80U)
#define medius_string_descriptor_archive (*(MediusStringDescriptorArchive *)0x3fcaae84U)
#define medius_string_descriptor_scratch (*(MediusStringDescriptorScratch *)0x3fca07e8U)
/* Copied device descriptor's manufacturer/product/serial ID bytes14..16. */
#define CAPTURE_DEVICE_STRING_IDS ((const volatile unsigned char *)0x3fcad62aU)
void medius_snapshot_emit_section(unsigned int section,unsigned char *data,unsigned int length,
    unsigned int maximum_chunk,FragmentCallback callback,void *context);
void medius_snapshot_emit_commit_marker(FragmentCallback callback,void *context);
void medius_snapshot_send_section_frame(const unsigned char *packet,unsigned short length,void *ignored_context);
void medius_host_send_hid_descriptor_fragments(unsigned int configuration,unsigned int interface_index,const unsigned char *descriptor,unsigned int length);
void medius_host_publish_hid_descriptor_blob(unsigned int configuration,unsigned int available_bytes);
unsigned int medius_host_cached_string_ascii(unsigned int string_index,unsigned short language,char *output);
int medius_host_capture_string_descriptor(MediusHostHubPortPrefix *port,MediusStringCaptureBudget *budget,unsigned int string_index,unsigned int language_id,int requested_length);
unsigned int medius_host_collect_string_ids(const unsigned char *descriptors,unsigned int length,unsigned char *ids);

/* Host descriptor archive: data pointer, capacity HALFWORD, used HALFWORD. */
#define medius_hid_descriptor_archive (*(volatile MediusHidDescriptorArchive *)0x3fc9dde0U)
int medius_host_merge_hid_descriptor_blob(unsigned int configuration,unsigned int available_bytes,unsigned int protected_configuration);
unsigned int medius_host_classify_control_probe(MediusHostHubPortPrefix *port,unsigned int request_type,unsigned int request,unsigned int value,unsigned int index,unsigned int length,int *result,unsigned int timeout);
unsigned int medius_host_probe_response_padding(MediusHostHubPortPrefix *port,unsigned int request_type,unsigned int request,unsigned int index,unsigned int expected_length);

/* Native comparison access view of the first nine configuration bytes.
 * The final three C alignment bytes are padding and are never compared. */
typedef struct HostConfigurationHeaderView {
    unsigned int first_word;           /* Descriptor bytes0..3, one native load. */
    unsigned int second_word;          /* Descriptor bytes4..7, one native load. */
    unsigned char final_byte;          /* Descriptor byte8. */
} HostConfigurationHeaderView;
#define HOST_CONTROL_CONFIGURATION_HEADER ((const volatile HostConfigurationHeaderView *)MEDIUS_HOST_ENUMERATION_DATA)
#define HOST_CAPTURED_CONFIGURATION_HEADER ((const volatile HostConfigurationHeaderView *)0x3fcace18U)
#define HOST_CAPTURED_CONFIGURATION_LENGTH (*(volatile unsigned short *)0x3fcace14U)
#define HOST_CAPTURE_CONFIGURATION_RESULT (*(volatile int *)0x3fca9724U)
#define HOST_CAPTURE_CONFIGURATION_VALUE (*(volatile unsigned char *)0x3fca9720U)
unsigned char medius_host_select_enumeration_configuration(MediusHostHubPortPrefix *port);
unsigned int medius_host_fetch_configuration_descriptor(MediusHostHubPortPrefix *port,unsigned int configuration_index);

/* Capture scheduling reads these independent BYTE/HALFWORD globals in native order. */
#define HOST_CAPTURE_CONFIGURATION_COUNT (*(volatile unsigned char *)0x3fcace10U)
#define HOST_CAPTURE_ARCHIVE_VENDOR (*(volatile unsigned short *)0x3fcadefaU)
#define HOST_CAPTURE_ARCHIVE_PRODUCT (*(volatile unsigned short *)0x3fcadef8U)
#define HOST_OTHER_CONFIGURATION_LENGTH (*(volatile unsigned short *)0x3fcace12U)
/* Flat image-byte views retain unchecked advertised-span arithmetic. */
#define HOST_FIRST_CONFIGURATION_BYTES ((const volatile unsigned char *)0x3fcace18U)
#define HOST_OTHER_CONFIGURATION_BYTES ((const volatile unsigned char *)0x3fca1a30U)
#define medius_hid_descriptor_blob_used (*(volatile unsigned short *)0x3fcab604U)
int medius_host_prepare_configuration_capture(void);
void medius_snapshot_timer_cb(void);
long long __divdi3(long long numerator,long long denominator);

/* Host snapshot storage. Lengths are independent native observations; the
 * pointer views do not validate advertised spans or create a coherent snapshot. */
#define HOST_DEVICE_DESCRIPTOR_LENGTH (*(volatile unsigned short *)0x3fcad618U)
#define HOST_DEVICE_DESCRIPTOR_BYTES ((unsigned char *)0x3fcad61cU)
#define HOST_MANUFACTURER_ASCII_LENGTH (*(volatile unsigned short *)0x3fcaa820U)
#define HOST_PRODUCT_ASCII_LENGTH (*(volatile unsigned short *)0x3fcaa81eU)
#define HOST_SERIAL_ASCII_LENGTH (*(volatile unsigned short *)0x3fcaa81cU)
#define HOST_BOS_DESCRIPTOR_LENGTH (*(volatile unsigned short *)0x3fcaa81aU)
#define HOST_SPEED_DESCRIPTOR_RECORD_LENGTH (*(volatile unsigned short *)0x3fcaaa6cU)
#define HOST_CLONE_METADATA_IDENTITY (*(volatile unsigned int *)0x3fcaaa68U)
#define HOST_CLONE_METADATA_LENGTH (*(volatile unsigned short *)0x3fcaa822U)
#define HOST_CAPTURED_SPEED (*(volatile unsigned char *)0x3fcaa818U)
#define HOST_ENDPOINT_ANOMALY_AVAILABLE (*(volatile unsigned char *)0x3fcace08U)
#define HOST_MANUFACTURER_ASCII ((unsigned char *)0x3fcab584U)
#define HOST_PRODUCT_ASCII ((unsigned char *)0x3fcab504U)
#define HOST_SERIAL_ASCII ((unsigned char *)0x3fcab484U)
#define HOST_BOS_DESCRIPTOR_BYTES ((unsigned char *)0x3fca1130U)
#define HOST_SPEED_DESCRIPTOR_RECORD ((unsigned char *)0x3fcaaa70U)
/* Source67 bytes, output512 bytes, anomaly3 bytes; callers trust published lengths. */
#define medius_clone_metadata_source ((unsigned char *)0x3fcaaa24U)
#define medius_clone_metadata_buffer ((unsigned char *)0x3fcaa824U)
#define medius_clone_section15_data ((unsigned char *)0x3fcace0cU)
/* Eight native allocation/owner pairs; producer count and indices are trusted. */
#define medius_retired_descriptors (*(MediusRetiredDescriptors *)0x3fca7eccU)
#define medius_retired_descriptor_count (*(volatile MediusRetiredCount *)0x3fca7ec8U)

/* DWC2 interrupt notifications. SOF and resume helpers consume no bus argument. */
void medius_usbh_notify_hub(MediusHostHubState *hub);
void medius_host_publish_resume_event(void);

int medius_host_recent_phase_within_tolerance(void);

/* Host enumeration storage, separate from the control/capture scratch at
 * 0x3fc9ffe8. The setup pool ends at the enumeration scratch base. */
#define HOST_ENUMERATION_SETUP_POOL ((unsigned char *)0x3fc9f73cU)
#define HOST_ENUMERATION_SCRATCH ((unsigned char *)0x3fc9f77cU)
#define HOST_ENUMERATION_RETRY_DELAYS ((const volatile unsigned short *)0x3c045c34U)
#define HOST_BUS_LIST (*(MediusHostBusPrefix *volatile *)0x3fca8248U)
#define HOST_CLASS_MATCH_BEGIN (*(const MediusHostClassMatchEntry *volatile *)0x3fca8250U)
#define HOST_CLASS_MATCH_END (*(const MediusHostClassMatchEntry *volatile *)0x3fca824cU)
int usbh_hub_initialize(MediusHostBusPrefix *bus);
int medius_usbh_hub_shutdown(MediusHostBusPrefix *bus);
void medius_usbh_default_event_handler(unsigned int bus,unsigned int hub,
    unsigned int port,unsigned int interface_index,unsigned int event);
MediusHostHubPortPrefix *medius_usbh_find_port_in_hub(MediusHostHubState *hub,
    unsigned int hub_index,unsigned int port_number);
int usbh_enumerate(MediusHostHubPortPrefix *port);
int medius_host_parse_configuration(MediusHostHubPortPrefix *port,unsigned char *data,
    unsigned int length);
unsigned char medius_host_select_enumeration_configuration(MediusHostHubPortPrefix *port);
void medius_host_enumeration_timer_restart(MediusHostHubPortPrefix *port);
void medius_host_report_enumeration_limit(MediusHostHubPortPrefix *port,
    unsigned char reason,unsigned short detail);
void *usb_osal_malloc(unsigned int size);
void usb_osal_free(void *pointer);

/* One external hub slot and per-bus hub control/interrupt scratch storage. */
#define HOST_EXTERNAL_HUB_SLOTS (*(volatile unsigned int *)0x3fca8254U)
#define HOST_EXTERNAL_HUB ((MediusHostHubState *)0x3fca8258U)
#define HOST_HUB_STATUS_SCRATCH ((unsigned char *)0x3fc9ff84U)
#define HOST_HUB_INTERRUPT_BUFFERS ((unsigned char *)0x3fc9ff7cU)
void usbh_hubport_release(MediusHostHubPortPrefix *port);
void medius_usbh_hub_poll(MediusHostHubState *hub);
void medius_usbh_hub_interrupt_complete(void *context,int result);
int medius_usbh_hub_get_port_status(MediusHostHubState *hub,unsigned short port,
    unsigned char *status);
int medius_usbh_hub_clear_port_feature(MediusHostHubState *hub,unsigned char port,
    unsigned char feature);
void usbh_hub_thread(MediusHostBusPrefix *bus);
void *usb_osal_thread_create(char *name,unsigned int stack_bytes,unsigned int priority,
    TaskEntry task_entry,void *argument);
void usb_osal_thread_delete(void *thread);
void *usb_osal_mutex_create(void);
void usb_osal_mutex_delete(void *mutex);
void *usb_osal_mq_create(unsigned int length);
void usb_osal_mq_delete(void *queue);
int medius_usbh_queue_send_value(void *queue,unsigned int value);
int usb_osal_mq_recv(void *queue,unsigned int *value,unsigned int milliseconds);
MediusUsbOsalTimer *usb_osal_timer_create(char *name,unsigned int milliseconds,
    MediusUsbTimerCallback callback,void *argument,unsigned char periodic);
void usb_osal_timer_delete(MediusUsbOsalTimer *timer);
void usb_osal_timer_start(MediusUsbOsalTimer *timer);

/* SDK timer callback adapter owned by the USB OS abstraction wrapper. */
void medius_usb_osal_timer_dispatch(void *timer_argument);
