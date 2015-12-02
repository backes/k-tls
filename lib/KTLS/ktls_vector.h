/*
 * ktls_vector.h
 *
 * Created on: Sep 9, 2015
 *     Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#ifndef _INC_KTLS_VECTOR_H
#define _INC_KTLS_VECTOR_H

#include <linux/types.h>

struct ktls_vector {
  /**
   * This always points to kmalloc'ed memory.
   * It is either used directly to store data (if capacity*sizeof(uint64_t) <=
   * PAGE_SIZE), or used as an array of logical addresses of allocated pages (if
   * capacity*sizeof(uint64_t) > PAGE_SIZE).
   */
  union {
    uint64_t *data;
    uint64_t **pages;
  };

  /**
   * The capacity (in sizeof(uint64_t)) of the memory pointed to by data.
   * If value is greater than PAGE_SIZE/sizeof(uint64_t), then data points to
   * memory holding an array of logical addresses.
   */
  uint32_t capacity;

  /**
   * The number of elements in this vector.
   */
  uint32_t size;
};

/* initialize a new vector */
void ktls_vector_init(struct ktls_vector *vec);

/* free (deallocate) a vector */
void ktls_vector_free(struct ktls_vector *vec);

/* clear a vector, i.e. reset size to zero, but keep allocated space */
void ktls_vector_clear(struct ktls_vector *vec);

/* reserve (at least) this amount of space in the vector */
void ktls_vector_reserve(struct ktls_vector *vec, uint32_t size);

/* add an element to the vector */
void ktls_vector_add(struct ktls_vector *vec, uint64_t data);

/* retrieve an element from the vector */
uint64_t ktls_vector_get(struct ktls_vector *vec, uint64_t idx);

#endif /* !_INC_KTLS_VECTOR_H */
