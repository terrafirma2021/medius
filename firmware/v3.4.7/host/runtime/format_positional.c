/* Medius v3.4.7 host: Newlib positional format-argument scanners. */
#include "../include/types.h"

/* Readable reconstruction utilities for the native inlined scanner/va_arg
 * operations. These helpers are not additional native function identities. */
enum MediusFormatCharacterClass {
    FORMAT_ZERO,FORMAT_DIGIT,FORMAT_DOLLAR,FORMAT_MODIFIER,FORMAT_SPECIFIER,
    FORMAT_DOT,FORMAT_STAR,FORMAT_FLAG,FORMAT_OTHER
};
enum MediusFormatParserState {
    FORMAT_START,FORMAT_FLAGS,FORMAT_WIDTH_DIGITS,FORMAT_WIDTH,FORMAT_MODIFIERS,
    FORMAT_PRECISION_DOT,FORMAT_VARIABLE_WIDTH,FORMAT_VARIABLE_PRECISION,
    FORMAT_PRECISION_DIGITS,FORMAT_WIDTH_POSITION,FORMAT_PRECISION_POSITION,
    FORMAT_DONE
};
enum MediusFormatParserAction {
    FORMAT_NO_ACTION,FORMAT_READ_NUMBER,FORMAT_SKIP_NUMBER,FORMAT_READ_MODIFIER,
    FORMAT_READ_ARGUMENT,FORMAT_READ_WIDTH,FORMAT_READ_WIDTH_PUSHBACK,
    FORMAT_ARGUMENT_POSITION,FORMAT_WIDTH_ARGUMENT_POSITION
};

/* Columns: zero, digit, $, modifier, specifier, dot, star, flag, other.
 * Recovered from both images' identical 99-byte native transition tables. */
static const unsigned char format_next_state[11][9]={
    {FORMAT_FLAGS,FORMAT_WIDTH_DIGITS,FORMAT_DONE,FORMAT_MODIFIERS,FORMAT_DONE,FORMAT_PRECISION_DOT,FORMAT_VARIABLE_WIDTH,FORMAT_FLAGS,FORMAT_DONE},
    {FORMAT_FLAGS,FORMAT_WIDTH_DIGITS,FORMAT_DONE,FORMAT_MODIFIERS,FORMAT_DONE,FORMAT_PRECISION_DOT,FORMAT_VARIABLE_WIDTH,FORMAT_FLAGS,FORMAT_DONE},
    {FORMAT_DONE,FORMAT_DONE,FORMAT_WIDTH,FORMAT_MODIFIERS,FORMAT_DONE,FORMAT_PRECISION_DOT,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE},
    {FORMAT_DONE,FORMAT_DONE,FORMAT_DONE,FORMAT_MODIFIERS,FORMAT_DONE,FORMAT_PRECISION_DOT,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE},
    {FORMAT_DONE,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE},
    {FORMAT_PRECISION_DOT,FORMAT_PRECISION_DIGITS,FORMAT_DONE,FORMAT_MODIFIERS,FORMAT_DONE,FORMAT_DONE,FORMAT_VARIABLE_PRECISION,FORMAT_DONE,FORMAT_DONE},
    {FORMAT_DONE,FORMAT_WIDTH_POSITION,FORMAT_DONE,FORMAT_MODIFIERS,FORMAT_DONE,FORMAT_PRECISION_DOT,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE},
    {FORMAT_DONE,FORMAT_PRECISION_POSITION,FORMAT_DONE,FORMAT_MODIFIERS,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE},
    {FORMAT_DONE,FORMAT_DONE,FORMAT_DONE,FORMAT_MODIFIERS,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE},
    {FORMAT_DONE,FORMAT_DONE,FORMAT_WIDTH,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE},
    {FORMAT_DONE,FORMAT_DONE,FORMAT_PRECISION_DIGITS,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE,FORMAT_DONE},
};
static const unsigned char format_action[11][9]={
    {FORMAT_NO_ACTION,FORMAT_READ_NUMBER,FORMAT_NO_ACTION,FORMAT_READ_MODIFIER,FORMAT_READ_ARGUMENT,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION},
    {FORMAT_NO_ACTION,FORMAT_READ_NUMBER,FORMAT_NO_ACTION,FORMAT_READ_MODIFIER,FORMAT_READ_ARGUMENT,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION},
    {FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_ARGUMENT_POSITION,FORMAT_READ_MODIFIER,FORMAT_READ_ARGUMENT,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION},
    {FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_READ_MODIFIER,FORMAT_READ_ARGUMENT,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION},
    {FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_READ_ARGUMENT,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION},
    {FORMAT_NO_ACTION,FORMAT_SKIP_NUMBER,FORMAT_NO_ACTION,FORMAT_READ_MODIFIER,FORMAT_READ_ARGUMENT,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION},
    {FORMAT_NO_ACTION,FORMAT_READ_NUMBER,FORMAT_NO_ACTION,FORMAT_READ_WIDTH,FORMAT_READ_WIDTH_PUSHBACK,FORMAT_READ_WIDTH,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION},
    {FORMAT_NO_ACTION,FORMAT_READ_NUMBER,FORMAT_NO_ACTION,FORMAT_READ_WIDTH,FORMAT_READ_WIDTH_PUSHBACK,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION},
    {FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_READ_MODIFIER,FORMAT_READ_ARGUMENT,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION},
    {FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_WIDTH_ARGUMENT_POSITION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION},
    {FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_WIDTH_ARGUMENT_POSITION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION,FORMAT_NO_ACTION},
};

static inline __attribute__((always_inline)) unsigned int format_character_class(
    unsigned char character)
{
    if (character>='1' && character<='9')
        return FORMAT_DIGIT;
    switch (character) {
    case '0': return FORMAT_ZERO;
    case '$': return FORMAT_DOLLAR;
    case 'h': case 'L': case 'l': case 'q': case 'j': case 'z': case 't':
        return FORMAT_MODIFIER;
    case 'A': case 'C': case 'D': case 'E': case 'F': case 'G':
    case 'O': case 'S': case 'U': case 'X': case 'a': case 'c':
    case 'd': case 'e': case 'f': case 'g': case 'i': case 'n':
    case 'o': case 'p': case 's': case 'u': case 'x':
        return FORMAT_SPECIFIER;
    case '.': return FORMAT_DOT;
    case '*': return FORMAT_STAR;
    case ' ': case '#': case '\'': case '+': case '-': return FORMAT_FLAG;
    default: return FORMAT_OTHER;
    }
}

/* Match native signed cursor comparisons and the 24-byte register-save limit.
 * Crossing from registers to stack restarts at biased offset 36/40, so an
 * argument never straddles the two areas. Offset arithmetic wraps at 32 bits. */
static inline __attribute__((always_inline)) volatile unsigned int *
format_argument_address(MediusXtensaVaListCursor *arguments,bool wide)
{
    volatile MediusXtensaVaListCursor *cursor=arguments;
    unsigned int previous=cursor->offset;
    unsigned int aligned=wide ? (previous+7U)&~7U : previous;
    unsigned int size=wide ? 8U : 4U;
    unsigned int next=aligned+size;
    cursor->offset=next;
    unsigned char *base;
    if ((int)next<=24)
        base=cursor->register_save;
    else {
        if ((int)aligned<=24)
            next=wide ? 40U : 36U;
        base=cursor->stack_base;
        cursor->offset=next;
    }
    return (volatile unsigned int *)((uintptr_t)base+next-size);
}

/* WORD arguments leave the slot's high WORD unchanged. Native pair reads
 * sample high then low; only an immediate DOUBLE stores low before high. */
static inline __attribute__((always_inline)) void format_fetch_argument(
    MediusXtensaVaListCursor *arguments,MediusNewlibArgumentValue *destination,
    int type,bool immediate)
{
    volatile MediusNewlibArgumentValue *slot=destination;
    bool wide=type==MEDIUS_NEWLIB_ARG_QUAD || type==MEDIUS_NEWLIB_ARG_DOUBLE ||
              type==MEDIUS_NEWLIB_ARG_LONG_DOUBLE;
    volatile unsigned int *source=format_argument_address(arguments,wide);
    if (!wide)
        slot->words[0]=source[0];
    else {
        unsigned int high=source[1];
        unsigned int low=source[0];
        if (immediate && type==MEDIUS_NEWLIB_ARG_DOUBLE) {
            slot->words[0]=low;
            slot->words[1]=high;
        } else {
            slot->words[1]=high;
            slot->words[0]=low;
        }
    }
}

/* Address arithmetic is explicit: positional numbers and width fetches are
 * not validated against the caller's actual 32-slot storage. */
static inline __attribute__((always_inline)) MediusNewlibArgumentValue *
format_argument_slot(MediusNewlibArgumentValue *cache,unsigned int index)
{
    return (MediusNewlibArgumentValue *)((uintptr_t)cache+index*8U);
}
static inline __attribute__((always_inline)) int *format_argument_type(
    int *types,unsigned int index)
{
    return (int *)((uintptr_t)types+index*4U);
}

/* Native entry: 0x42016c38. */
/* Original function-byte SHA-256:
 * c534eb42604b45d4b4d7d0492171ef00551baa31be53187bb3c0a10ea4817b46. */
/*
 * Newlib get_arg for string output: scan the format to identify/fetch zero-based
 * requested_index, starting at *resume when non-NULL, otherwise format. The
 * compiler removed the unused reent parameter: this entry has SEVEN arguments,
 * with resume on the caller stack. Cursor is the 12-byte Xtensa va_list shape;
 * cache slots are 8 bytes and type tags occupy 32 signed WORDs.
 *
 * A native state/action table recognizes numbers, modifiers, conversions and
 * positional width/precision. Positional conversions store tags for later;
 * sequential conversions consume the cursor immediately. Conversion handling
 * masks consumed count to 31; width/precision fetches and final catch-up do
 * NOT mask it. $ indexes are decremented without validation; -1 in types[0]
 * lazily clears all 128 type bytes. Decimal numbers wrap at 32 bits.
 *
 * h/t/z need no promoted-width flag; l sets LONG, ll/j/q QUAD, L a flag that
 * does not change the native DOUBLE fetch. D/O/U always LONG; C and lc are
 * WIDE_CHAR; S/s/p/n are pointers. 64-bit types align cursor to 8 and consume
 * two WORDs; others consume one, leaving cache high WORD unchanged. Preserve
 * high-before-low native pair reads and the different DOUBLE store order.
 * Register-save arguments stop at offset 24; stack transition uses biased
 * offsets 36/40. No argument is split across register/stack storage.
 *
 * Stop scanning when count exceeds requested_index or literal text ends; then
 * consume tagged/default-INT arguments through requested_index, or through the
 * largest observed positional index at string end. Save updated count/resume
 * and return cache+8*requested_index. No NULL, range, format validity, buffer
 * or argument availability checks, allocation, logging or errno changes.
 * Malformed formats can scan beyond NUL or address outside the nominal cache.
 * Caller supplies distinct initialized cursor/count/cache/type/resume storage.
 */
MediusNewlibArgumentValue *medius_newlib_get_string_argument(int requested_index,const unsigned char *format,
    MediusXtensaVaListCursor *arguments,unsigned int *consumed,
    MediusNewlibArgumentValue *cache,int *types,const unsigned char **resume)
{
    unsigned int count=*consumed;
    const unsigned char *scan=*resume;
    if (scan==NULL)
        scan=format;
    int largest_index=requested_index;
    while (*scan!=0 && requested_index>=(int)count) {
        while (*scan!=0 && *scan!='%')
            scan++;
        if (*scan==0)
            break;
        scan++;
        unsigned int state=FORMAT_START,flags=0,number=0;
        int position=-1,type=MEDIUS_NEWLIB_ARG_INT;
        while (state!=FORMAT_DONE) {
            unsigned char character=*scan++;
            unsigned int character_class=format_character_class(character);
            unsigned int action=format_action[state][character_class];
            state=format_next_state[state][character_class];
            switch (action) {
            case FORMAT_READ_NUMBER:
                number=(unsigned int)character-'0';
                while (*scan!=0 && (unsigned int)(*scan-'0')<10U) {
                    number=number*10U+(unsigned int)(*scan-'0');
                    scan++;
                }
                break;
            case FORMAT_SKIP_NUMBER:
                while ((unsigned char)(*scan-'0')<10U)
                    scan++;
                break;
            case FORMAT_READ_MODIFIER:
                switch (character) {
                case 'h': case 't': case 'z': break;
                case 'L': flags|=8U; break;
                case 'j': case 'q': flags|=32U; break;
                default:
                    if (*scan=='l') {
                        flags|=32U;
                        scan++;
                    } else
                        flags|=16U;
                    break;
                }
                break;
            case FORMAT_READ_ARGUMENT:
                count &= 31U;
                switch (character) {
                case 'd': case 'i': case 'o': case 'u': case 'x': case 'X':
                    type=(flags&16U)!=0 ? MEDIUS_NEWLIB_ARG_LONG :
                         (flags&32U)!=0 ? MEDIUS_NEWLIB_ARG_QUAD : MEDIUS_NEWLIB_ARG_INT;
                    break;
                case 'D': case 'O': case 'U': type=MEDIUS_NEWLIB_ARG_LONG; break;
                case 'a': case 'A': case 'e': case 'E': case 'f': case 'F':
                case 'g': case 'G': type=MEDIUS_NEWLIB_ARG_DOUBLE; break;
                case 'S': case 's': case 'p': case 'n': type=MEDIUS_NEWLIB_ARG_POINTER; break;
                case 'C': type=MEDIUS_NEWLIB_ARG_WIDE_CHAR; break;
                case 'c': type=(flags&16U)!=0 ? MEDIUS_NEWLIB_ARG_WIDE_CHAR : MEDIUS_NEWLIB_ARG_INT; break;
                }
                if (position!=-1)
                    *format_argument_type(types,(unsigned int)position)=type;
                else {
                    format_fetch_argument(arguments,format_argument_slot(cache,count),type,true);
                    count++;
                }
                break;
            case FORMAT_READ_WIDTH_PUSHBACK:
                scan--;
                /* fall through: interpret the character again as a conversion. */
            case FORMAT_READ_WIDTH:
                format_fetch_argument(arguments,format_argument_slot(cache,count),MEDIUS_NEWLIB_ARG_INT,true);
                count++;
                break;
            case FORMAT_ARGUMENT_POSITION:
                if (types[0]==-1)
                    memset(types,0,128);
                position=(int)(number-1U);
                if (largest_index<position)
                    largest_index=position;
                break;
            case FORMAT_WIDTH_ARGUMENT_POSITION:
                if (types[0]==-1)
                    memset(types,0,128);
                number--;
                *format_argument_type(types,number)=MEDIUS_NEWLIB_ARG_INT;
                if (largest_index<(int)number)
                    largest_index=(int)number;
                break;
            }
        }
    }
    int final_index=*scan==0 ? largest_index : requested_index;
    for (unsigned int index=count;(int)index<=final_index;index++) {
        int type=*format_argument_type(types,index);
        format_fetch_argument(arguments,format_argument_slot(cache,index),type,false);
    }
    unsigned int advance=0;
    if ((int)count<=(int)((unsigned int)final_index+1U))
        advance=(unsigned int)final_index-count+1U;
    *consumed=count+advance;
    *resume=scan;
    return format_argument_slot(cache,(unsigned int)requested_index);
}

/* Native entry: 0x42019ce0. */
/* Original function-byte SHA-256:
 * 35deb8f4eea84307b1b25e1b8db20ebd02a7b268523cd725d706e83408186c5e. */
/*
 * Newlib get_arg for FILE output: scan the format to identify/fetch zero-based
 * requested_index, starting at *resume when non-NULL, otherwise format. The
 * compiler removed the unused reent parameter: this entry has SEVEN arguments,
 * with resume on the caller stack. Cursor is the 12-byte Xtensa va_list shape;
 * cache slots are 8 bytes and type tags occupy 32 signed WORDs.
 *
 * A native state/action table recognizes numbers, modifiers, conversions and
 * positional width/precision. Positional conversions store tags for later;
 * sequential conversions consume the cursor immediately. Conversion handling
 * masks consumed count to 31; width/precision fetches and final catch-up do
 * NOT mask it. $ indexes are decremented without validation; -1 in types[0]
 * lazily clears all 128 type bytes. Decimal numbers wrap at 32 bits.
 *
 * h/t/z need no promoted-width flag; l sets LONG, ll/j/q QUAD, L a flag that
 * does not change the native DOUBLE fetch. D/O/U always LONG; C and lc are
 * WIDE_CHAR; S/s/p/n are pointers. 64-bit types align cursor to 8 and consume
 * two WORDs; others consume one, leaving cache high WORD unchanged. Preserve
 * high-before-low native pair reads and the different DOUBLE store order.
 * Register-save arguments stop at offset 24; stack transition uses biased
 * offsets 36/40. No argument is split across register/stack storage.
 *
 * Stop scanning when count exceeds requested_index or literal text ends; then
 * consume tagged/default-INT arguments through requested_index, or through the
 * largest observed positional index at string end. Save updated count/resume
 * and return cache+8*requested_index. No NULL, range, format validity, buffer
 * or argument availability checks, allocation, logging or errno changes.
 * Malformed formats can scan beyond NUL or address outside the nominal cache.
 * Caller supplies distinct initialized cursor/count/cache/type/resume storage.
 */
MediusNewlibArgumentValue *medius_newlib_get_stream_argument(int requested_index,const unsigned char *format,
    MediusXtensaVaListCursor *arguments,unsigned int *consumed,
    MediusNewlibArgumentValue *cache,int *types,const unsigned char **resume)
{
    unsigned int count=*consumed;
    const unsigned char *scan=*resume;
    if (scan==NULL)
        scan=format;
    int largest_index=requested_index;
    while (*scan!=0 && requested_index>=(int)count) {
        while (*scan!=0 && *scan!='%')
            scan++;
        if (*scan==0)
            break;
        scan++;
        unsigned int state=FORMAT_START,flags=0,number=0;
        int position=-1,type=MEDIUS_NEWLIB_ARG_INT;
        while (state!=FORMAT_DONE) {
            unsigned char character=*scan++;
            unsigned int character_class=format_character_class(character);
            unsigned int action=format_action[state][character_class];
            state=format_next_state[state][character_class];
            switch (action) {
            case FORMAT_READ_NUMBER:
                number=(unsigned int)character-'0';
                while (*scan!=0 && (unsigned int)(*scan-'0')<10U) {
                    number=number*10U+(unsigned int)(*scan-'0');
                    scan++;
                }
                break;
            case FORMAT_SKIP_NUMBER:
                while ((unsigned char)(*scan-'0')<10U)
                    scan++;
                break;
            case FORMAT_READ_MODIFIER:
                switch (character) {
                case 'h': case 't': case 'z': break;
                case 'L': flags|=8U; break;
                case 'j': case 'q': flags|=32U; break;
                default:
                    if (*scan=='l') {
                        flags|=32U;
                        scan++;
                    } else
                        flags|=16U;
                    break;
                }
                break;
            case FORMAT_READ_ARGUMENT:
                count &= 31U;
                switch (character) {
                case 'd': case 'i': case 'o': case 'u': case 'x': case 'X':
                    type=(flags&16U)!=0 ? MEDIUS_NEWLIB_ARG_LONG :
                         (flags&32U)!=0 ? MEDIUS_NEWLIB_ARG_QUAD : MEDIUS_NEWLIB_ARG_INT;
                    break;
                case 'D': case 'O': case 'U': type=MEDIUS_NEWLIB_ARG_LONG; break;
                case 'a': case 'A': case 'e': case 'E': case 'f': case 'F':
                case 'g': case 'G': type=MEDIUS_NEWLIB_ARG_DOUBLE; break;
                case 'S': case 's': case 'p': case 'n': type=MEDIUS_NEWLIB_ARG_POINTER; break;
                case 'C': type=MEDIUS_NEWLIB_ARG_WIDE_CHAR; break;
                case 'c': type=(flags&16U)!=0 ? MEDIUS_NEWLIB_ARG_WIDE_CHAR : MEDIUS_NEWLIB_ARG_INT; break;
                }
                if (position!=-1)
                    *format_argument_type(types,(unsigned int)position)=type;
                else {
                    format_fetch_argument(arguments,format_argument_slot(cache,count),type,true);
                    count++;
                }
                break;
            case FORMAT_READ_WIDTH_PUSHBACK:
                scan--;
                /* fall through: interpret the character again as a conversion. */
            case FORMAT_READ_WIDTH:
                format_fetch_argument(arguments,format_argument_slot(cache,count),MEDIUS_NEWLIB_ARG_INT,true);
                count++;
                break;
            case FORMAT_ARGUMENT_POSITION:
                if (types[0]==-1)
                    memset(types,0,128);
                position=(int)(number-1U);
                if (largest_index<position)
                    largest_index=position;
                break;
            case FORMAT_WIDTH_ARGUMENT_POSITION:
                if (types[0]==-1)
                    memset(types,0,128);
                number--;
                *format_argument_type(types,number)=MEDIUS_NEWLIB_ARG_INT;
                if (largest_index<(int)number)
                    largest_index=(int)number;
                break;
            }
        }
    }
    int final_index=*scan==0 ? largest_index : requested_index;
    for (unsigned int index=count;(int)index<=final_index;index++) {
        int type=*format_argument_type(types,index);
        format_fetch_argument(arguments,format_argument_slot(cache,index),type,false);
    }
    unsigned int advance=0;
    if ((int)count<=(int)((unsigned int)final_index+1U))
        advance=(unsigned int)final_index-count+1U;
    *consumed=count+advance;
    *resume=scan;
    return format_argument_slot(cache,(unsigned int)requested_index);
}
