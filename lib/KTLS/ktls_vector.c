/*
 * ktls_vector.c
 *
 * Created on: Sep 9, 2015
 *     Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#include "ktls_vector.h"

#include "ktls_assert.h"

#include <linux/slab.h> /* kmalloc, ... */

void ktls_vector_init(struct ktls_vector *vec) {
  vec->data = 0;
  vec->capacity = 0;
  vec->size = 0;
}

void ktls_vector_free(struct ktls_vector *vec) {
  if (unlikely(vec->capacity == 0))
    return;
  if (unlikely(vec->capacity > PAGE_SIZE / sizeof(uint64_t))) {
    ASSERT(vec->capacity % (PAGE_SIZE / sizeof(uint64_t)) == 0);
    for (uint64_t num_pages = vec->capacity / (PAGE_SIZE / sizeof(uint64_t));
         num_pages > 0; --num_pages)
      free_page(vec->data[num_pages - 1]);
  }
  kfree(vec->data);
  vec->data = 0;
  vec->capacity = 0;
  vec->size = 0;
}

void ktls_vector_clear(struct ktls_vector *vec) {
  vec->size = 0;
}


/**
 * Returns the next power of two, or 0 if x is 0.
 */
static uint64_t next_power_of_two(uint64_t x) {
  if ((x & (x - 1)) == 0)
    return x;
  x |= x >> 1;
  x |= x >> 2;
  x |= x >> 4;
  x |= x >> 8;
  x |= x >> 16;
  x |= x >> 32;
  return x + 1;
}

void ktls_vector_reserve(struct ktls_vector *vec, uint32_t size) {
  ASSERT(size <= (1u << 31) / sizeof(unsigned long));

  if (vec->capacity >= size)
    return;

  if (size <= PAGE_SIZE / sizeof(uint64_t)) {
    // make sure size is a power of two
    size = next_power_of_two(size);

    // old data was kmalloc'ed (or NULL), new data is kmalloc'ed
    uint64_t *new_data = kmalloc(size * sizeof(uint64_t), GFP_KERNEL);
    ASSERT (new_data != 0);
    if (vec->size != 0)
      memcpy(new_data, vec->data, vec->size * sizeof(uint64_t));
    if (vec->capacity != 0)
      kfree(vec->data);
    vec->data = new_data;
    vec->capacity = size;
  } else {
    // new data is paged
    uint64_t elems_per_page = PAGE_SIZE / sizeof(uint64_t);
    uint64_t num_pages = (size + (elems_per_page - 1)) / elems_per_page;
    uint64_t data_size = next_power_of_two(num_pages * sizeof(uint64_t));
    uint64_t old_num_pages = vec->capacity / (PAGE_SIZE / sizeof(uint64_t));
    if (unlikely(vec->capacity <= PAGE_SIZE / sizeof(uint64_t))) {
      // old data was kmalloc'ed (or NULL)
      uint64_t first_page = __get_free_page(GFP_KERNEL);
      ASSERT(first_page != 0);
      if (vec->size != 0)
        memcpy((char *)first_page, vec->data, vec->size * sizeof(uint64_t));
      if (data_size != vec->capacity) {
        if (vec->capacity != 0)
          kfree(vec->data);
        vec->data = kmalloc(data_size, GFP_KERNEL);
        ASSERT(vec->data != 0);
      }
      vec->data[0] = first_page;
    } else {
      // old data was paged (at least two pages)
      uint64_t old_data_size =
          next_power_of_two(old_num_pages * sizeof(uint64_t));
      if (unlikely(data_size != old_data_size)) {
        uint64_t *new_data = kmalloc(data_size, GFP_KERNEL);
        ASSERT(new_data != 0);
        memcpy(new_data, vec->data, old_num_pages * sizeof(uint64_t));
        kfree(vec->data);
        vec->data = new_data;
      }
    }
    for (uint64_t p = old_num_pages; p < num_pages; ++p) {
      vec->data[p] = __get_free_page(GFP_KERNEL);
      ASSERT(vec->data[p] != 0);
    }
    vec->capacity = num_pages * elems_per_page;
  }
}

void ktls_vector_add(struct ktls_vector *vec, uint64_t data) {
  if (vec->size == vec->capacity)
    ktls_vector_reserve(vec, vec->size == 0 ? 8 : 2 * vec->size);
  ASSERT(vec->capacity > vec->size);
  if (vec->capacity <= PAGE_SIZE / sizeof(uint64_t)) {
    vec->data[vec->size] = data;
  } else {
    uint64_t page_idx = vec->size / (PAGE_SIZE / sizeof(uint64_t));
    uint64_t data_idx = vec->size % (PAGE_SIZE / sizeof(uint64_t));
    vec->pages[page_idx][data_idx] = data;
  }
  ++vec->size;
}

uint64_t ktls_vector_get(struct ktls_vector *vec, uint64_t idx) {
  ASSERT(idx < vec->size);
  if (vec->capacity <= PAGE_SIZE / sizeof(uint64_t))
    return vec->data[idx];
  uint64_t page_idx = idx / (PAGE_SIZE / sizeof(uint64_t));
  uint64_t data_idx = idx % (PAGE_SIZE / sizeof(uint64_t));
  return vec->pages[page_idx][data_idx];
}
