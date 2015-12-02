/*
 * ktls_hhash.h
 *
 *  Created on: Sep 23, 2013
 *      Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#ifndef KTLS_HHASH_H_
#define KTLS_HHASH_H_

#include <linux/init.h> /* for __init */
#include <linux/types.h> /* uint64_t, uint32_t, ... */

struct ktls_hhash {
    /**
     * Number of elements added to hashtable.
     */
    uint32_t m;

    /**
     * Allocated size.
     */
    uint32_t n;

    /**
     * Stored values:
     * Virtual page addresses written, lowest 8 bit used to store hop information.
     * At locations [n:2n], the version numbers of the corresponding pages are stored.
     */
    uint64_t *V;
};

/**
 * Initialize an empty set.
 */
void ktls_hhash_new(struct ktls_hhash *S);

/**
 * Free all allocated data of a set.
 */
void ktls_hhash_delete(struct ktls_hhash *S);

/**
 * Clear the set (removing all entries, but keeping allocated space).
 */
void ktls_hhash_clear(struct ktls_hhash *S);

/**
 * Get the version number of a page. 0 if not contained in this set.
 */
uint64_t ktls_hhash_get(struct ktls_hhash *S, uint64_t addr);

/**
 * Add an entry if none exists, or update the version number if an existing entry is found.
 */
void ktls_hhash_add_or_update(struct ktls_hhash *S, uint64_t addr, uint64_t version);

/**
 * Add entry to S.
 */
void ktls_hhash_add(struct ktls_hhash *S, uint64_t addr, uint64_t version);

#endif /* KTLS_HHASH_H_ */
