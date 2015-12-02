/** Implementation of hopscotch hashing (http://en.wikipedia.org/wiki/Hopscotch_hashing),
 * taken from the libhhash (http://code.google.com/p/libhhash/) (MIT-licensed).
 * Major modifications (specialization and performance improvements) by
 * Clemens Hammacher <hammacher@cs.uni-saarland.de>.
 */

#include "page_hhash.h"

#include <cassert>
#include <cstdio>
#include <cstdlib> /* abort */
#include <sys/mman.h>

using namespace TLS;


#define COMPILE_TIME_ASSERT(pred)       switch (0) { case 0: case pred: ; }

#define HASH_PAGEADDR(addr, n) \
    ((((addr) >> 11) ^ ((addr) >> 18)) & (n-1))

// size of the neighborhood (number of elements).
#define NH_SIZE \
    8

#define ENTRIES_PER_PAGE \
    (4096 / sizeof(uint64_t))

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

#define write_bit(x) \
    (((x) >> NH_SIZE) & 1)

#define set_write_bit(x) \
    ((x) | (1 << NH_SIZE))

#define strip_hopinfo(x) \
    ((x) & ~(((uint64_t)1<<NH_SIZE)-1))

#define strip_both(x) \
    ((x) & ~(((uint64_t)2<<NH_SIZE)-1))

namespace {

/**
 * Return index of an occupied entry in neighborhood of h greater than i.
 */
int8_t next(uint32_t hops, uint8_t i) {
    uint32_t H = hops >> i;
    if (H == 0)
        return -1;
    return i + ffs(H);
}

/**
 * Return index of an occupied entry in neighborhood of h greater or equal to i.
 */
int8_t succ(uint32_t hops, int8_t i) {
    if (test(hops, i))
        return i;
    return next(hops, i);
}

/*
 * In neighborhood h, move entry i to j.
 */
void move(uint64_t *V, uint32_t h, uint8_t i, uint8_t j, uint32_t n) {
    assert (test(V[h], i));
    assert (!test(V[h], j));
    unset(V[h], i);
    set(V[h], j);
    uint32_t hi = wrap(h+i, n);
    uint32_t hj = wrap(h+j, n);
    assert (strip_both(V[hi]) != 0);
    assert (strip_both(V[hj]) == 0);
    V[hj] = strip_hopinfo(V[hi]) | hopinfo(V[hj]);
    V[hi] = hopinfo(V[hi]);
}

/**
 * Return offset of next free slot from h (might be "behind the end", which means wrapped to the beginning).
 */
uint32_t probe(uint64_t *V, uint32_t h, uint32_t n) {
    uint32_t i = 0;
    for (; h+i < n; ++i)
        if (strip_both(V[h+i]) == 0)
            return i;
    uint32_t j = 0;
    for (; strip_both(V[j]) != 0; ++j);
    return i+j;
}

/**
 * Search for a location which has an entry that can be moved to h, and return the offset from h to the left.
 * i==2 means an entry from (h-2) can be moved to h.
 */
uint8_t seek(uint64_t *V, uint32_t h, uint32_t n) {
    for (uint8_t i = NH_SIZE - 1; i > 0; --i) {
        uint32_t hi = wrap(h-i, n);
        uint32_t hops = hopinfo(V[hi]);
        if (hops != 0 && ffs(hops) < i)
            return i;
    }
    return 0;
}

} // anonymous namespace

PageHashSet::~PageHashSet() {
    if (V && munmapPtr(V, n * sizeof(*V))) {
        perror("PageHashSet munmap");
        abort();
    }
}

uint8_t PageHashSet::get(uint64_t pageAddr) {
    assert (pageAddr);
    assert ((pageAddr & 4095) == 0);

    if (!V)
        return 0;

    uint32_t h = HASH_PAGEADDR(pageAddr, n);
    uint32_t hops = hopinfo(V[h]);
    while (hops != 0) {
        uint8_t i = ffs(hops);
        assert (i < NH_SIZE);
        h += i + 1;
        if (h > n)
            h -= n;
        hops >>= i+1;
        if (strip_both(V[h-1]) == pageAddr)
            return 1 + write_bit(V[h-1]);
    }
    return 0;
}

void PageHashSet::resize(uint32_t min_size) {
    uint64_t *old_V = V;
    uint32_t old_size = n;
    assert ((old_size >> 30) == 0);
    uint32_t new_size = old_size * 2;
    if (min_size > new_size)
        new_size = min_size;
    if (NH_SIZE > new_size)
        new_size = NH_SIZE;
    m = 0;
    n = new_size;
    // check if there is enough empty space within the same page
    uint64_t *old_page = (uint64_t*)((uint64_t) old_V & 4095);
    if (old_page && V + old_size + new_size <= old_page + 4096 / sizeof(*V)) {
        V += old_size;
        old_page = 0;
    } else {
        V = (uint64_t*) mmapPtr(0, new_size * sizeof(uint64_t), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (V == MAP_FAILED) {
            perror("resize page_hhash: mmap");
            abort();
        }
    }
    for (uint64_t *v = old_V, *end = old_V + old_size; v != end; ++v) {
        if (strip_hopinfo(*v))
            (this->*add0_ptr)(strip_hopinfo(*v));
    }
    if (old_page && munmapPtr(old_page, old_size * sizeof(uint64_t))) {
        perror("resize page_hhash: munmap");
        abort();
    }
}

void PageHashSet::add0(uint64_t page_and_write_bit) {
    assert (strip_both(page_and_write_bit) != 0);
    assert (hopinfo(page_and_write_bit) == 0);
    //assert (!get(strip_both(page_and_write_bit)));
    if (m == n)
        (this->*resize_ptr)(0);
    uint32_t h = HASH_PAGEADDR(strip_both(page_and_write_bit), n);
    uint32_t d = probe(V, h, n); // offset of first free spot behind h
    // Move elements to get a free spot within the neighboorhood
    uint32_t hd = wrap(h+d, n);
    while (d >= NH_SIZE) {
        uint32_t z = seek(V, hd, n); // offset of a location containing an entry which can be moved to d
        if (z == 0) {
            (this->*resize_ptr)(0);
            (this->*add0_ptr)(page_and_write_bit);
            return;
        }
        uint32_t j = z;
        z = wrap(hd-z, n); // location containing an entry which can be moved to d
        uint32_t i = succ(hopinfo(V[z]), 0); // the entry of z which should be moved
        move(V, z, i, j, n);
        d = wrap(z+i-h, n); // now entry i of z is free
        hd = wrap(h+d, n);
    }
    // Now d is within the neighborhood of h, and h+d is free.
    V[hd] = page_and_write_bit | hopinfo(V[hd]);
    set(V[h], d);
    ++m;
}

void PageHashSet::add(uint64_t page, uint8_t write_bit) {
    assert ((page & 4095) == 0);
    (this->*add0_ptr)(page | ((write_bit & 1) << NH_SIZE));
}

uint8_t PageHashSet::add_or_upgrade(uint64_t pageAddr) {
    assert (pageAddr);
    assert ((pageAddr & 4095) == 0);

    /* Ensure this data structure is initialized */
    if (!V)
        (this->*resize_ptr)(0);

    uint32_t h = HASH_PAGEADDR(pageAddr, n);

    /* First search for an existing entry. */
    uint32_t hops = hopinfo(V[h]);
    while (hops != 0) {
        uint8_t i = ffs(hops);
        assert (i < NH_SIZE);
        h += i + 1;
        if (h > n)
            h -= n;
        hops >>= i+1;
        if (strip_both(V[h-1]) != pageAddr)
            continue;
        if (write_bit(V[h-1]))
            return 0;
        V[h-1] = set_write_bit(V[h-1]);
        return 2;
    }

    /* Entry does not exist. Add it. */
    (this->*add0_ptr)(pageAddr);
    return 1;
}

void PageHashSet::reserve(uint32_t size)
{
    if (size <= n)
        return;
    --size;
    size |= size >> 1;
    size |= size >> 2;
    size |= size >> 4;
    size |= size >> 8;
    size |= size >> 16;
    resize(size+1);
}

int32_t PageHashSet::getAll(void**arr, int32_t capa) {
    int32_t num = 0;
    for (uint64_t *i = V, *e = V + n; i != e; ++i) {
        if (!strip_both(*i))
            continue;
        if (num == capa)
            return -1;
        arr[num] = (void*) (strip_both(*i) | (write_bit(*i) ? 0 : 1));
        ++num;
        assert ((uint32_t)num <= m);
    }
    assert ((uint32_t)num == m);
    return num;
}
