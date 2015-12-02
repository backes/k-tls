/*
 * page_hhash.h
 *
 *  Created on: Apr 18, 2013
 *      Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#ifndef PAGE_HHASH_H_
#define PAGE_HHASH_H_

#include <cstdint>
#include <sys/types.h>
#include <sys/uio.h>

namespace TLS {

class PageHashSet
{
public:
  /**
   * Number of elements added to hashtable.
   */
  uint32_t m;

  /**
   * Allocated size.
   */
  uint32_t n;

  /**
   * Values plus write bit plus hop info.
   */
  uint64_t *V;

private:
  /**
   * These pointers are needed to circumvent the PLT which could lead to
   * SEGV inside the SEGV handler.
   */
  void* (*mmapPtr)(void*, size_t, int, int, int, off_t);
  int (*munmapPtr)(void*, size_t);

  void (PageHashSet::*add0_ptr)(uint64_t);
  void (PageHashSet::*resize_ptr)(uint32_t min_size);

  void resize(uint32_t min_size = 0);
  void add0(uint64_t page_and_write_bit);

public:
  PageHashSet(void* (*mmapPtr)(void*, size_t, int, int, int, off_t), int (*munmapPtr)(void*, size_t))
  : m(0), n(0), V(0), mmapPtr(mmapPtr), munmapPtr(munmapPtr), add0_ptr(&PageHashSet::add0),
    resize_ptr(&PageHashSet::resize),
    add_ptr(&PageHashSet::add), add_or_upgrade_ptr(&PageHashSet::add_or_upgrade),
    get_all_ptr(&PageHashSet::getAll) { /* nop */ };
  ~PageHashSet();

  /**
   * Return 1 if there is a read entry, 2 if there is a write entry, 0 otherwise.
   */
  uint8_t get(uint64_t pageAddr);

  /**
   * Add an entry without write bit if none exists, set write bit if there is already an entry.
   * Return 0 if there already existed an entry with write bit set, 1 if a new entry has been added,
   * and 2 if the write bit for an existing entry was set.
   */
  uint8_t add_or_upgrade(uint64_t pageAddr);

  /**
   * Add entry to T.
   */
  void add(uint64_t page, uint8_t write_bit);

  /**
   * Reserve a given space in T (resize underlying array).
   */
  void reserve(uint32_t size);

  /**
   * Get the capacity (size of underlying array) of this data structure.
   */
  uint32_t capacity() {
      return n;
  }

  /**
   * Get the size (number of contained elements) of this data structure.
   */
  uint32_t size() {
      return m;
  }

  /**
   * Retrieve all entries saved in this data structure.
   * The page addresses contain the write bit in the LSB.
   * Returns the number of pages, or -1 if more than "capa" pages are contained.
   */
  int32_t getAll(void **arr, int32_t capa);

  void (PageHashSet::*add_ptr)(uint64_t, uint8_t);
  uint8_t (PageHashSet::*add_or_upgrade_ptr)(uint64_t);
  int32_t (PageHashSet::*get_all_ptr)(void **arr, int32_t capa);
};

}

#endif /* PAGE_HHASH_H_ */
