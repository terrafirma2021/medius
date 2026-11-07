/* Medius v3.4.7 device — External TRANSFER command. */
#include "../include/types.h"

/* Native entry: 0x42033cc4. */
/* Original function-byte SHA-256:
 * 73d8676edac7ceaa4f3192df371507f4f02923932777a44f808bd46f12288b3e. */
/*
 * Submit an external TRANSFER command, using shared request/reply storage.
 * Snapshot signal before clearing *response_length. Missing signal or an OUT
 * payload's low16 length>504 returns0xfc. Copy endpoint and eight SETUP bytes;
 * append OUT data only for a nonempty OUT request. IN ignores OUT data/length.
 * Both length arguments use low16 bits; no pointer checks or local mutex.
 *
 * Sample current generation before forwarded generation; synchronize if the
 * latter is smaller. Allocate a seven-bit sequence, publish status0xffffffff
 * and waiting1, drain signal, send opcode0x31 for endpoint0 or0x33 otherwise,
 * and wait800 ticks. Ignore transport result. Clear waiting before checking
 * take result/sequence; timeout or mismatch returns0xfe with output length0.
 *
 * For a correlated reply, optionally take the live rewrite mutex indefinitely,
 * sample time and publish its actual low/high WORDs, then clear the input-change
 * committed BYTE and give a freshly sampled mutex. Return status's low BYTE.
 * Only status0 copies min(reply actual HALFWORD,capacity low16) and stores the
 * resulting output HALFWORD, including a zero-length memcpy. Reply capacity
 * and shared storage lifetime are caller/producer obligations; no post-wait
 * generation recheck or asynchronous cancellation is added.
 */
unsigned int control_transfer_request(unsigned char endpoint,
    const unsigned char *setup,const void *out_data,unsigned int out_length,
    void *response,unsigned int response_capacity,unsigned short *response_length)
{
    ExternalControlReply *reply = EXTERNAL_CONTROL_REPLY;
    RtosQueue *signal = reply->signal;
    *response_length = 0;
    out_length = (unsigned short)out_length;
    response_capacity = (unsigned short)response_capacity;
    if (signal == NULL)
        return 0xfcU;
    unsigned char request_type = *(const volatile unsigned char *)setup;
    if ((request_type & 0x80U) == 0 && out_length > 504U)
        return 0xfcU;
    MediusExternalControlRequest *request = MEDIUS_EXTERNAL_CONTROL_REQUEST;
    *(volatile unsigned char *)&request->endpoint = endpoint;
    memcpy(request->setup,setup,8);
    unsigned int packet_length = 9;
    if ((request_type & 0x80U) == 0 && out_length != 0) {
        packet_length = (unsigned short)(out_length + 9U);
        memcpy(request->out_payload,out_data,out_length);
    }
    memw();
    unsigned int generation = DEVICE_OUT_GENERATION;
    memw();
    unsigned int forwarded_generation = CONTROL_FORWARDED_GENERATION;
    if (forwarded_generation < generation)
        control_forward_generations(generation,0);
    memw();
    unsigned char sequence = (reply->sequence + 1U) & 0x7fU;
    memw();
    reply->sequence = sequence;
    signal = reply->signal;
    memw();
    reply->status = 0xffffffffU;
    memw();
    reply->waiting = 1;
    xQueueSemaphoreTake(signal,0);
    link_send_wait100(endpoint == 0 ? 0x31 : 0x33,sequence,
        request,(unsigned short)packet_length);
    int received = xQueueSemaphoreTake(reply->signal,800);
    memw();
    reply->waiting = 0;
    if (received != 1)
        return 0xfeU;
    memw();
    if (reply->completed_sequence != sequence)
        return 0xfeU;
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    memw();
    INPUT_CHANGE_TIME.low = (unsigned int)now;
    memw();
    INPUT_CHANGE_TIME.high = (unsigned int)(now >> 32);
    mutex = REWRITE_MUTEX;
    INPUT_CHANGE_COMMITTED = 0;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    memw();
    unsigned int status = reply->status & 255U;
    if (status == 0) {
        memw();
        unsigned int actual = reply->actual;
        unsigned int copied = actual < response_capacity ? actual : response_capacity;
        memcpy(response,reply->payload,copied);
        *response_length = (unsigned short)copied;
    }
    return status;
}
