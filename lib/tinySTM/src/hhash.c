// THIS FILE SHOULD ONLY BE INCLUDED INTO stm.c AFTER
// DEFINING r_entry_t!!
/** Implementation of hopscotch hashing (http://en.wikipedia.org/wiki/Hopscotch_hashing),
 * taken from the libhhash (http://code.google.com/p/libhhash/) (MIT-licensed).
 * Major modifications (specialization and performance improvements) by
 * Clemens Hammacher <hammacher@cs.uni-saarland.de>.
 */

// size of a word stored in hhash::V, in bit
#define WORD \
  (sizeof(r_entry_t)*8)

// size of the neighborhood (number of elements).
// size of a cacheline is 64 bytes (512 bit)
#define NH_SIZE \
  (2*64*8 / WORD)

#define clz(x) \
  __builtin_clz(x)

#define fls(x) \
  (WORD-clz(x))

#define ffs(x) \
  (uint32_t)(__builtin_ctz(x))

#define get(x,i) \
  ((x)&(1<<(i)))

#define set(x,i) \
  (x = (x)|(1<<(i)))

#define unset(x,i) \
  (x = (x)&~(1<<(i)))

typedef struct hhash
{
  /**
   * Number of elements added to hashtable.
   */
  uint32_t m;

  /**
   * Allocated size.
   */
  uint32_t n;

  /**
   * Values plus hop info.
   */
  r_entry_t *V;
} hhash_t;

INLINE(static) uint32_t wrap(uint32_t x, uint32_t n) {
  assert (n > 0u && n < (1u<<31));
  assert (x < 2*n);
  return x < n ? x : x-n;
}

INLINE(static) uint32_t wrap_neg(uint32_t x, uint32_t n) {
  assert (n > 0u && n < (1u<<31));
  assert (x < n || (x+n) < n);
  return x < n ? x : x + n;
}

static void
hhashnew(hhash_t *T, uint32_t size)
{
  COMPILE_TIME_ASSERT(8 * sizeof(T->V[0].hopInfo) >= NH_SIZE);
  COMPILE_TIME_ASSERT(sizeof(*T->V) == 2 * sizeof(void*))
  T->m = 0;
  T->n = size;
  T->V = calloc(size, sizeof(*T->V));
}

static void
hhashfree(hhash_t *T)
{
  free(T->V);
}

/**
 * Return index of an occupied entry in neighborhood of h greater than i.
 */
static int8_t
next(hhash_t *T, uint32_t h, uint8_t i)
{
  uint32_t H = T->V[h].hopInfo >> i;
  if (H == 0)
    return -1;
  return i + ffs(H);
}

/**
 * Return index of an occupied entry in neighborhood of h greater or equal to i.
 */
static int8_t
succ(hhash_t *T, uint32_t h, int8_t i)
{
  // TODO if this special case really an optimization?
  if (get(T->V[h].hopInfo, i))
      return i;
  return next(T, h, i);
}

/*
 * In neighborhood h, move entry i to j.
 */
static void
move(hhash_t *T, uint32_t h, uint8_t i, uint8_t j)
{
  uint32_t hops = T->V[h].hopInfo;
  assert (get(hops, i));
  assert (!get(hops, j));
  unset(hops, i);
  set(hops, j);
  T->V[h].hopInfo = hops;
  uint32_t hi = wrap(h+i, T->n);
  uint32_t hj = wrap(h+j, T->n);
  assert (T->V[hj].lockIdx_sh == 0);
  assert (T->V[hi].lockIdx_sh & 1);
  T->V[hj].version = T->V[hi].version;
  T->V[hj].lockIdx_sh = T->V[hi].lockIdx_sh;
  T->V[hi].lockIdx_sh = 0;
}

/**
 * Return offset of next free slot from h (might be "behind the end", which means wrapped to the beginning).
 */
static uint32_t
probe(hhash_t *T, uint32_t h)
{
  uint32_t i = 0;
  for (; h+i < T->n; ++i)
    if (T->V[h+i].lockIdx_sh == 0)
      return i;
  uint32_t j = 0;
  for (; T->V[j].lockIdx_sh != 0; ++j);
  return i+j;
}

/**
 * Search for a location which has an entry that can be moved to h, and return the offset from h to the left.
 * i==2 means an entry from (h-2) can be moved to h.
 */
static uint8_t
seek(hhash_t *T, uint32_t h)
{
  for (uint8_t i = NH_SIZE - 1; i > 0; --i) {
    uint32_t hi = wrap_neg(h-i, T->n);
    uint32_t hops = T->V[hi].hopInfo;
    if (hops != 0 && ffs(hops) < i)
      return i;
  }
  return 0;
}

/**
 * Return 1 if entry for lock exists, 0 otherwise.
 */
static uint8_t
hhashcontains(hhash_t *T, uint32_t lockIdx)
{
  uint32_t lockIdx_sh = (lockIdx << 1) | 1;
  uint32_t h = HASH_LOCKIDX(lockIdx, T->n);
  uint32_t hops = T->V[h].hopInfo;
  while (hops != 0) {
    uint8_t i = ffs(hops);
    assert (i < NH_SIZE);
    h += i + 1;
    if (unlikely(h > T->n))
      h -= T->n;
    hops >>= i+1;
        if (T->V[h-1].lockIdx_sh == lockIdx_sh)
      return 1;
  }
  return 0;
}

// hhashput and resize are mutually recursive.
// forward declare hhashput:
static void hhashput(hhash_t* T, uint32_t lockIdx, stm_word_t version);

static void
resize(hhash_t *R)
{
  r_entry_t *old_V = R->V;
  uint32_t old_size = R->n;
  assert ((old_size >> 30) == 0);
  R->n = old_size * 2;
  R->V = calloc(R->n, sizeof(*R->V));
  R->m = 0;
  for (r_entry_t *v = old_V, *end = old_V + old_size; v != end; ++v) {
    if (v->lockIdx_sh)
      hhashput(R, v->lockIdx_sh >> 1, v->version);
  }
  free(old_V);
}

/**
 * Add entry e to T. This may also resize the table.
 */
static void
hhashput(hhash_t* T, uint32_t lockIdx, stm_word_t version)
{
  assert (lockIdx < (1u << 31));
  if (unlikely(T->m == T->n))
    resize(T);
  uint32_t h = HASH_LOCKIDX(lockIdx, T->n);
  assert (!hhashcontains(T, lockIdx));
  uint32_t d = probe(T, h); // offset of first free spot behind h
  // Move elements to get a free spot within the neighboorhood
  uint32_t hd = wrap(h+d, T->n);
  while (unlikely(d >= NH_SIZE)) {
    uint32_t z = seek(T, hd); // offset of a location containing an entry which can be moved to d
    if (unlikely(z == 0)) {
      resize(T);
      return hhashput(T, lockIdx, version);
    }
    uint32_t j = z;
    z = wrap_neg(hd-z, T->n); // location containing an entry which can be moved to d
    uint32_t i = succ(T, z, 0); // the entry of z which should be moved
    move(T, z, i, j);
    d = wrap_neg(z+i-h, T->n); // now entry i of z is free
    hd = wrap(h+d, T->n);
  }
  // Now d is within the neighborhood of h, and h+d is free.
  T->V[hd].version = version;
  T->V[hd].lockIdx_sh = (lockIdx << 1) | 1;
  set(T->V[h].hopInfo, d);
  ++T->m;
}

static stm_word_t
hhashget(hhash_t *T, uint32_t lockIdx)
{
  uint32_t lockIdx_sh = (lockIdx << 1) | 1;
  uint32_t h = HASH_LOCKIDX(lockIdx, T->n);
  uint32_t hops = T->V[h].hopInfo;
  while (hops != 0) {
    uint8_t i = ffs(hops);
    assert (i < NH_SIZE);
    h += i + 1;
    if (unlikely(h > T->n))
      h -= T->n;
    hops >>= i+1;
    if (T->V[h-1].lockIdx_sh == lockIdx_sh)
      return T->V[h-1].version;
  }
  return 0;
}

static void hhashclear(hhash_t *S)
{
  if (S->m == 0)
    return;
  S->m = 0;
  memset(S->V, 0, S->n * sizeof(*S->V));
}

