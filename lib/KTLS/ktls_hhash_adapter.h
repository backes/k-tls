/*
 * ktls_hhash_adapter.h - Adapter functions for using hhash with char pointers
 * as values
 *
 *  Created on: Apr 24, 2015
 *      Author: Daniel Birtel <daniel.birtel@stud.uni-saarland.de>
 */

#include "ktls_hhash.h"

char *ktls_ptr_hhash_get(struct ktls_hhash *S, unsigned long addr);

void ktls_ptr_hhash_add(struct ktls_hhash *S, unsigned long addr, char *ptr);

void ktls_ptr_hhash_add_or_update(struct ktls_hhash *S, unsigned long addr, char *ptr);
