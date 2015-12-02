/** Implementation of hopscotch hashing (http://en.wikipedia.org/wiki/Hopscotch_hashing),
 * taken from the libhhash (http://code.google.com/p/libhhash/) (MIT-licensed).
 * Major modifications (specialization and performance improvements) by
 * Clemens Hammacher <hammacher@cs.uni-saarland.de>.
 */

#include "ktls_hhash.h"
#include "ktls_assert.h"

#include <asm/page.h> /* page and PFN stuff */

#include <linux/delay.h> /* msleep */
#include <linux/kallsyms.h> /* kallsyms_lookup_name */
#include <linux/vmalloc.h> /* vmalloc, vfree */

#define HASH_ADDR(addr, n) \
    ((((addr) >> 11) ^ ((addr) >> 18)) & (n-1))

// size of the neighborhood (number of elements).
#define NH_SIZE \
    8

#define ffs(x) \
    (uint32_t)(__builtin_ctz(x))

#define test(x,i) \
    ((x)&(1<<(i)))

#define set(x,i) \
    (x = (x)|(1<<(i)))

#define unset(x,i) \
    (x = (x)&~(1<<(i)))

#define wrap(x,n) \
    ((uint32_t)(x) & ((uint32_t)n-1))

#define hopinfo(x) \
    ((x) & (((uint64_t)1<<NH_SIZE)-1))

#define strip_hopinfo(x) \
    ((x) & ~(((uint64_t)1<<NH_SIZE)-1))

/**
 * Return index of an occupied entry in neighborhood of h greater than i.
 */
static int8_t next(uint32_t hops, uint8_t i) {
    uint32_t H = hops >> i;
    if (H == 0)
        return -1;
    return i + ffs(H);
}

/**
 * Return index of an occupied entry in neighborhood of h greater or equal to i.
 */
static int8_t succ(uint32_t hops, int8_t i) {
    if (test(hops, i))
        return i;
    return next(hops, i);
}

/*
 * In neighborhood h, move entry i to j.
 */
static void move(uint64_t *V, uint64_t n, uint32_t h, uint8_t i, uint8_t j) {
    ASSERT (test(V[h], i));
    ASSERT (!test(V[h], j));
    unset(V[h], i);
    set(V[h], j);
    uint32_t hi = wrap(h+i, n);
    uint32_t hj = wrap(h+j, n);
    ASSERT (strip_hopinfo(V[hi]) != 0);
    ASSERT (strip_hopinfo(V[hj]) == 0);
    V[hj] = strip_hopinfo(V[hi]) | hopinfo(V[hj]);
    V[hi] = hopinfo(V[hi]);
    uint64_t vi = V[n + hi];
    V[n + hi] = V[n + hj];
    V[n + hj] = vi;
}

/**
 * Return offset of next free slot from h (might be "behind the end", which means wrapped to the beginning).
 */
static uint32_t probe(uint64_t *V, uint32_t h, uint32_t n) {
    uint32_t i = 0;
    for (; h+i < n; ++i)
        if (strip_hopinfo(V[h+i]) == 0)
            return i;
    uint32_t j = 0;
    for (; strip_hopinfo(V[j]) != 0; ++j);
    return i+j;
}

/**
 * Search for a location which has an entry that can be moved to h, and return the offset from h to the left.
 * i==2 means an entry from (h-2) can be moved to h.
 */
static uint8_t seek(uint64_t *V, uint32_t h, uint32_t n) {
    for (uint8_t i = NH_SIZE - 1; i > 0; --i) {
        uint32_t hi = wrap(h-i, n);
        uint32_t hops = hopinfo(V[hi]);
        if (hops != 0 && ffs(hops) < i)
            return i;
    }
    return 0;
}


void ktls_hhash_new(struct ktls_hhash *S) {
    S->m = 0;
    S->n = 0;
    S->V = 0;
}

void ktls_hhash_delete(struct ktls_hhash *S) {
    if (!S->V)
        return;
    vfree(S->V);
    S->V = 0;
}

void ktls_hhash_clear(struct ktls_hhash *S) {
  if (S->m != 0) {
    S->m = 0;
    // zero the first half (storing the addresses and hop info)
    memset(S->V, 0, S->n * sizeof(uint64_t));
  }
}

uint64_t ktls_hhash_get(struct ktls_hhash *S, uint64_t addr) {
    ASSERT (addr != 0);
    ASSERT ((addr & ~PAGE_MASK) == 0);

    if (S->n == 0)
        return 0;

    uint32_t h = HASH_ADDR(addr, S->n);
    uint32_t hops = hopinfo(S->V[h]);
    while (hops != 0) {
        uint8_t i = ffs(hops);
        ASSERT (i >= 0 && (unsigned)i < NH_SIZE);
        h += i + 1;
        if (h > S->n)
            h -= S->n;
        hops >>= i+1;
        if (strip_hopinfo(S->V[h-1]) == addr)
            return S->V[S->n + h-1];
    }
    return 0;
}

static void resize(struct ktls_hhash *S, uint32_t min_size);

static void add0(struct ktls_hhash *S, uint64_t addr, uint64_t version) {
    ASSERT (addr != 0);
    ASSERT ((addr & ~PAGE_MASK) == 0);
    ASSERT (version != 0);
    ASSERT (ktls_hhash_get(S, addr) == 0);
    if (unlikely(S->m == S->n))
        resize(S, 0);
    uint32_t h;
retry:
    h = HASH_ADDR(addr, S->n);
    uint32_t d = probe(S->V, h, S->n); // offset of first free spot behind h
    // Move elements to get a free spot within the neighboorhood
    uint32_t hd = wrap(h+d, S->n);
    while (d >= NH_SIZE) {
        uint32_t z = seek(S->V, hd, S->n); // offset of a location containing an entry which can be moved to d
        if (unlikely(z == 0)) {
            resize(S, 0);
            goto retry;
        }
        uint32_t j = z;
        z = wrap(hd-z, S->n); // location containing an entry which can be moved to d
        uint32_t i = succ(hopinfo(S->V[z]), 0); // the entry of z which should be moved
        move(S->V, S->n, z, i, j);
        d -= j-i; // we moved the free spot (j-i) positions to the right (new d == z+i-h)
        hd = wrap(h+d, S->n); // == z+i
    }
    // Now d is within the neighborhood of h, and h+d is free.
    S->V[hd] = addr | hopinfo(S->V[hd]);
    S->V[S->n + hd] = version;
    set(S->V[h], d);
    ++S->m;
}

static void resize(struct ktls_hhash *S, uint32_t min_size) {
    uint64_t *old_V = S->V;
    uint32_t old_size = S->n;
    ASSERT ((old_size >> 30) == 0);
    uint32_t new_size = old_size * 2;
    if (min_size > new_size)
        new_size = min_size;
    if (new_size < NH_SIZE)
        new_size = NH_SIZE;
    S->m = 0;
    S->n = new_size;
    S->V = (uint64_t*) vmalloc(2 * new_size * sizeof(uint64_t));
    BUG_ON(S->V == 0);
    // zero the first half (storing the addresses and hop info)
    memset(S->V, 0, new_size * sizeof(uint64_t));
    if (old_V) {
        for (uint64_t *v = old_V, *end = old_V + old_size; v != end; ++v) {
            if (strip_hopinfo(*v))
                add0(S, strip_hopinfo(*v), *(v+old_size));
        }
        vfree(old_V);
    }
}

void ktls_hhash_add(struct ktls_hhash *S, uint64_t addr, uint64_t version) {
    ASSERT (addr != 0);
    ASSERT ((addr & PAGE_MASK) == addr);
    ASSERT (version > 0);

    add0(S, addr, version);
}

void ktls_hhash_add_or_update(struct ktls_hhash *S, uint64_t addr, uint64_t version) {
    ASSERT (addr != 0);
    ASSERT ((addr & PAGE_MASK) == addr);
    ASSERT (version > 0);

    /* Ensure this data structure is initialized */
    if (likely(S->m != 0)) {
        uint32_t h = HASH_ADDR(addr, S->n);

        /* First search for an existing entry and update it. */
        uint32_t hops = hopinfo(S->V[h]);
        while (hops != 0) {
            uint8_t i = ffs(hops);
            ASSERT (i >= 0 && i < NH_SIZE);
            h += i + 1;
            if (unlikely(h > S->n))
                h -= S->n;
            hops >>= i+1;
            if (strip_hopinfo(S->V[h-1]) == addr) {
                ASSERT(S->V[S->n + h-1] < version);
                S->V[S->n + h-1] = version;
                return;
            }
        }
    }

    /* Entry does not exist. Add it. */
    add0(S, addr, version);
}
