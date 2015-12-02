#ifndef __KTLS_BITARRAY_H_
#define __KTLS_BITARRAY_H_

#define BITARRAY_SIZE(n) ((n) / (8 * sizeof(long)) + ((n) % (8 * sizeof(long)) > 0 ? 1 : 0))
#define BITARRAY_BYTESIZE(n) (sizeof(long) * BITARRAY_SIZE(n))
#define BITARRAY_DECLARE(name, n) unsigned long name[BITARRAY_SIZE(n)];
#define BITARRAY_INDEX(i) ((i) / (sizeof(long) * 8))
#define BITARRAY_MASK(i) (1UL << ((i) % (sizeof(long) * 8)))
#define BITARRAY_GET(var, i) (var[BITARRAY_INDEX(i)] & BITARRAY_MASK(i))
#define BITARRAY_SET(var, i) var[BITARRAY_INDEX(i)] |= BITARRAY_MASK(i)
#define BITARRAY_CLEAR(var, i) var[BITARRAY_INDEX(i)] &= BITARRAY_MASK(i)

#endif /* __KTLS_BITARRAY_H_ */
