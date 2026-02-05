#include "common.h"
#include "types.h"
#include "generic.h"
#include <stdlib.h>

const int GENERIC_PLUGIN_VERSION = GENERIC_PLUGIN_VERSION_REQ;
const int GENERIC_PLUGIN_OPTIONS = 0;

struct IdGenData {
    int progress;
};

static const int KEYSPACE_SIZE = 26 * 2 * 10000000;
static const int LETTER_CHECKSUMS[26] = {
    1, 0, 9, 8, 7, 6, 5, 4, 9, 3, 2, 2, 1,
    0, 8, 9, 8, 7, 6, 5, 4, 3, 1, 3, 2, 0,
};

bool global_init(generic_global_ctx_t *global_ctx,
                 generic_thread_ctx_t **thread_ctx,
                 hashcat_ctx_t *hashcat_ctx) {
    return true;
}

void global_term(generic_global_ctx_t *global_ctx,
                 generic_thread_ctx_t **thread_ctx,
                 hashcat_ctx_t *hashcat_ctx) {}

u64 global_keyspace(generic_global_ctx_t *global_ctx,
                    generic_thread_ctx_t **thread_ctx,
                    hashcat_ctx_t *hashcat_ctx) {
    return KEYSPACE_SIZE;
}

bool thread_init(generic_global_ctx_t *global_ctx,
                 generic_thread_ctx_t *thread_ctx) {
    struct IdGenData *data = malloc(sizeof(struct IdGenData));
    data->progress = 0;
    thread_ctx->thrdata = data;
    return true;
}

void thread_term(generic_global_ctx_t *global_ctx,
                 generic_thread_ctx_t *thread_ctx) {
    free(thread_ctx->thrdata);
}

int thread_next(generic_global_ctx_t *global_ctx,
                generic_thread_ctx_t *thread_ctx, u8 *out_buf) {
    int counter = ((struct IdGenData *)thread_ctx->thrdata)->progress++;
    if (counter == KEYSPACE_SIZE) {
        return -1;
    }
    int letter = counter % 26;
    counter /= 26;
    out_buf[0] = 'A' + letter;
    int checksum = LETTER_CHECKSUMS[letter];
    int sex = counter % 2 + 1;
    counter /= 2;
    out_buf[1] = '0' + sex;
    checksum += 8 * sex;
    for (int i = 2; i < 9; ++i) {
        int digit = counter % 10;
        counter /= 10;
        out_buf[i] = '0' + digit;
        checksum += digit * (9 - i);
    }
    out_buf[9] = '0' + (10 - checksum % 10) % 10;
    return 10;
}

bool thread_seek(generic_global_ctx_t *global_ctx,
                 generic_thread_ctx_t *thread_ctx, const u64 offset) {
    ((struct IdGenData *)thread_ctx->thrdata)->progress = offset;
    return true;
}
