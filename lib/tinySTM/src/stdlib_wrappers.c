/*
 * stdlib_wrappers.c
 *
 *  Created on: Jan 11, 2011
 *      Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#include "stm.h"
#include "wrappers.h"
#include "debug.h"

INLINE(extern) void stm_memmove(TXPARAMS uint8_t *dest, uint8_t *src, size_t len) {
    uint8_t *buf;
    if (len > 1024*1024)
        buf = malloc(len);
    else
        buf = alloca(len);
    stm_load_bytes(TXARGS src, buf, len);
    stm_store_bytes(TXARGS dest, buf, len);
    if (len > 1024*1024)
        free(buf);
}
