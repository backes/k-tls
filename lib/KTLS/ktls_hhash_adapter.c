/*
 * ktls_hhash_adapter.c
 *
 *  Created on: Apr 24, 2015
 *      Author: Daniel Birtel <daniel.birtel@stud.uni-saarland.de>
 */

#include "ktls_hhash_adapter.h"

#include <asm/page_types.h>

// adding PAGE_SIZE to addr -> workaround ensuring that addr != 0

char *ktls_ptr_hhash_get(struct ktls_hhash *S, unsigned long addr) {
    return (char *) ktls_hhash_get(S, (uint64_t) addr + PAGE_SIZE);
}

void ktls_ptr_hhash_add(struct ktls_hhash *S, unsigned long addr, char *ptr) {
    ktls_hhash_add(S, (uint64_t) addr + PAGE_SIZE, (uint64_t) ptr);
}

void ktls_ptr_hhash_add_or_update(struct ktls_hhash *S, unsigned long addr, char *ptr) {
    ktls_hhash_add_or_update(S, (uint64_t) addr + PAGE_SIZE, (uint64_t) ptr);
}
