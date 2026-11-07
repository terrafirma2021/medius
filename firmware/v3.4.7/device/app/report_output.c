/* Medius v3.4.7 device: output rules, control comparison and binding lookup. */

#include "../include/types.h"

/* Native entry: 0x40394300. */
/* Original function-byte SHA-256:
 * 7bc28c7c3714f245f46c45a2f3115ef4da4b73a35830c63685547aa52ba8b4d0. */
/* Apply class9 rules for LOW4(interface_index's mapped endpoint), direction1.
 * First publish input and LOW16(length) through the two output pointers. A
 * matching catch rule returns1 immediately. Otherwise cache the rule count
 * and endpoint, then choose the FIRST highest-scoring matching rewrite rule.
 * Exact class9/endpoint scores200000, class9/wildcard endpoint100000, wildcard
 * class0xff scores0 regardless of its endpoint. Add10 per set mask bit and
 * the configured direction byte (0 or1); direction>1 rejects. A nonempty prefix
 * requires non-NULL input, enough FULL32 length, and prefix==(input&mask).
 * Count/prefix length and payload offsets are not repaired or array-capped.
 *
 * Increment the chosen rule's cached hit count unless it is UINT32_MAX.
 * The native read/add/write is not atomic. Action0 returns untouched.
 * Every other action first copies min(length,
 * 64) bytes to scratch, INCLUDING action1 which then returns1 (drop). Actions2/7
 * patch only when the whole patch fits that copied span;3/4/8 replace with
 * min(payload_length,64) bytes, including a zero-length replacement. Other
 * action bytes retain the initial copy. Publish scratch/length only when the
 * resulting length or bytes differ; returning0 does NOT imply unchanged output.
 * A >64-byte input can thus be truncated by an otherwise ineffective action.
 * Caller supplies writable64-byte scratch/output slots and serialization.
 * No local lock, allocation, capture publication or report transmission. */
unsigned int report_apply_output_rules(unsigned int interface_index,
    const unsigned char *input,unsigned int length,unsigned char *scratch,
    const unsigned char **report_out,unsigned short *length_out)
{
    *report_out = input;
    unsigned int catch_enabled = PACKET_TRIGGER_COUNT;
    *length_out = (unsigned short)length;
    if (catch_enabled != 0) {
        unsigned int endpoint = CREDIT_INTERFACES.endpoint[interface_index] & 15U;
        if (clip_packet_rules_evaluate(9,endpoint,1,(unsigned char *)input,length) != 0)
            return 1;
    }
    unsigned int rule_count = REWRITE_COUNT;
    if (rule_count == 0)
        return 0;
    unsigned int endpoint = CREDIT_INTERFACES.endpoint[interface_index] & 15U;
    int best_score = -1;
    unsigned int selected_index = 0xffffffffU;
    for (unsigned int index = 0; index < rule_count; ++index) {
        const volatile RewriteRule *rule = REWRITE_RULES+index;
        unsigned int traffic_class = rule->traffic_class;
        unsigned int rule_endpoint = rule->endpoint;
        unsigned int direction = rule->direction;
        unsigned int prefix_length = rule->prefix_length;
        int rank;
        if (traffic_class == 9 && rule_endpoint == endpoint)
            rank = 2;
        else if (traffic_class == 9 && rule_endpoint == 65535U)
            rank = 1;
        else if (traffic_class == 255)
            rank = 0;
        else
            continue;
        if (direction > 1)
            continue;
        int mask_bits = 0;
        if (prefix_length != 0) {
            if (length < prefix_length || input == 0)
                continue;
            unsigned int index_in_prefix = 0;
            for (; index_in_prefix < prefix_length; ++index_in_prefix) {
                const volatile unsigned char *rule_bytes = (const volatile void *)rule;
                unsigned int mask = rule_bytes[21U+index_in_prefix];
                unsigned int byte = ((const volatile unsigned char *)input)[index_in_prefix];
                unsigned int prefix = rule_bytes[5U+index_in_prefix];
                if (prefix != (byte & mask))
                    break;
            }
            if (index_in_prefix != prefix_length)
                continue;
            for (unsigned int byte = 0; byte < prefix_length; ++byte) {
                const volatile unsigned char *rule_bytes = (const volatile void *)rule;
                mask_bits += __popcountsi2(rule_bytes[21U+byte]);
            }
        }
        int score = rank*100000 + mask_bits*10 + (int)direction;
        if (score > best_score) {
            best_score = score;
            selected_index = index;
        }
    }
    if (selected_index == 0xffffffffU)
        return 0;
    volatile RewriteRule *chosen = REWRITE_RULES+selected_index;
    unsigned int hits = chosen->hits;
    if (hits != 0xffffffffU)
        chosen->hits = hits+1U;
    if (chosen->action == 0)
        return 0;
    unsigned int size = length < 64 ? length : 64;
    chosen = REWRITE_RULES+(selected_index & 65535U);
    memcpy(scratch,input,size);
    unsigned int payload_offset = chosen->payload_offset;
    unsigned int action = chosen->action;
    unsigned int payload_length = chosen->payload_length;
    const unsigned char *payload = REWRITE_PAYLOAD_POOL+payload_offset;
    if (action == 1)
        return 1;
    if (action == 2 || action == 7) {
        unsigned int patch_offset = chosen->patch_offset;
        if (patch_offset+payload_length <= size)
            memcpy(scratch+patch_offset,payload,payload_length);
    } else if (action == 3 || action == 4 || action == 8) {
        size = payload_length < 64 ? payload_length : 64;
        if (size != 0)
            memcpy(scratch,payload,size);
        else if (length == 0)
            return 0;
    }
    if (length != size || memcmp(scratch,input,size) != 0) {
        *report_out = scratch;
        *length_out = (unsigned short)size;
    }
    return 0;
}

/* Native entry: 0x403950c4. */
/* Original function-byte SHA-256:
 * 8e49a72374d3bb116e458b6c98bed584e69d6d4e4a14069c44fe45f4418811f4. */
/* Compare up to64 bytes after masking the numeric fields and selected
 * normalization bytes in two LOCAL copies. Inputs and state are not written.
 * Copy current then previous; load the layout pointer after both copies.
 * With a layout, clear numeric fields in the same order through
 * report_clear_layout_bits.
 * Cache output_count; when nonzero, ignore byte_clamps[0].byte_offset if state
 * selector+c8 has its sign bit clear and the offset is in the copied span. If the cached
 * count is not1, similarly ignore record1 using selector+c9. Only these first
 * two byte records are considered. Both byte selectors use their sign bit,
 * not the chosen X/Y axis value. A NULL layout performs an ordinary comparison.
 * Returns1 for any remaining byte difference, else0; length0 compares equal.
 * No local lock/fence; caller supplies readable state and bounded input spans. */
unsigned int report_controls_differ(const InputStateView *input_state,
    const unsigned char *current,const unsigned char *previous,unsigned int length)
{
    unsigned int size = length < 64 ? length : 64;
    unsigned char current_copy[64],previous_copy[64];
    memcpy(current_copy,current,size);
    memcpy(previous_copy,previous,size);
    const volatile InputStateView *state_fields = input_state;
    const HidReportLayout *layout = state_fields->hid_layout;
    if (layout != 0) {
        report_clear_layout_bits((const BitClearLayout *)layout,current_copy,size);
        report_clear_layout_bits((const BitClearLayout *)layout,previous_copy,size);
        const volatile HidReportLayout *layout_fields = layout;
        unsigned int output_count = layout_fields->output_count;
        if (output_count != 0) {
            unsigned int selector = state_fields->primary_normalization_flags;
            unsigned int byte_offset = layout_fields->byte_clamps[0].byte_offset;
            if ((selector & 128U) == 0 && byte_offset < size) {
                previous_copy[byte_offset] = 0;
                current_copy[byte_offset] = 0;
            }
            if (output_count != 1) {
                selector = state_fields->secondary_normalization_flags;
                byte_offset = layout_fields->byte_clamps[1].byte_offset;
                if ((selector & 128U) == 0 && byte_offset < size) {
                    previous_copy[byte_offset] = 0;
                    current_copy[byte_offset] = 0;
                }
            }
        }
    }
    return memcmp(current_copy,previous_copy,size) != 0;
}

/* Native entry: 0x40395148. */
/* Original function-byte SHA-256:
 * ffa3c23a785b0eba0820d161a1cff20c8f96f6f74d127882605361a5f41711e2. */
/* Find the first904-byte binding whose signed interface word and unsigned16
 * expected length equal the supplied FULL32 values. A zero report-ID byte in
 * its layout matches immediately, including length0/NULL report. A nonzero ID
 * requires length!=0 and input byte0 equal to that ID. Neither layout nor input
 * is NULL-checked on the paths that dereference them. Cache signed table count
 * once; count<=0 returns NULL and positive count is not capped. Return a live
 * binding pointer or NULL; no mutation, fence, lock or report copy. */
ReportLayoutBinding *report_layout_find(int interface_index,
    const unsigned char *report,unsigned int length)
{
    int binding_count = REPORT_BINDING_COUNT;
    for (int index = 0; index < binding_count; ++index) {
        ReportLayoutBinding *binding = (ReportLayoutBinding *)
            ((unsigned char *)REPORT_BINDINGS+(unsigned int)index*904U);
        const volatile ReportLayoutBinding *binding_fields = binding;
        if (binding_fields->interface == interface_index && binding_fields->expected_length == length) {
            const volatile HidReportLayout *layout = binding_fields->state.hid_layout;
            unsigned int report_id = layout->report_id;
            if (report_id == 0 || (length != 0 && ((const volatile unsigned char *)report)[0] == report_id))
                return binding;
        }
    }
    return 0;
}
