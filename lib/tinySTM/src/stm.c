/*
 * File:
 *   stm.c
 * Author(s):
 *   Pascal Felber <pascal.felber@unine.ch>
 *   Patrick Marlier <patrick.marlier@unine.ch>
 * Description:
 *   STM functions.
 *
 * Copyright (c) 2007-2011.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <assert.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <pthread.h>
#include <sched.h>

#include "stm.h"

#include "debug.h"
#include "atomic.h"
#include "gc.h"

#ifdef COLLECT_TX_STATS
# include <sys/time.h>
#endif

#ifdef HYBRID_ASF
# include "asf/asf-highlevel.h"
/* Abort status */
# define ASF_RETRY                       (0)
# define ASF_FORCE_SOFTWARE              (1)
# define ASF_RETRY_IRREVOCABLE           (2)
/* Number of hybrid tx aborts before to switch to pure software transaction */
# define ASF_ABORT_THRESHOLD             (16)
/* Force lock shift to 0, otherwise a large area will be locked */
# ifdef LOCK_SHIFT_EXTRA 
#  warning LOCK_SHIFT_EXTRA is ignored with HYBRID_ASF
#  undef LOCK_SHIFT_EXTRA
# endif /* LOCK_SHIFT_EXTRA */
# define LOCK_SHIFT_EXTRA                (0)
#endif /* HYBRID_ASF */

/* ################################################################### *
 * DEFINES
 * ################################################################### */

#define COMPILE_TIME_ASSERT(pred)       switch (0) { case 0: case (pred?1:0): ; }
#if defined(__GNUC__) || defined(__INTEL_COMPILER)
# define likely(x)                      __builtin_expect(!!(x), 1)
# define unlikely(x)                    __builtin_expect(!!(x), 0)
#else /* ! (defined(__GNUC__) || defined(__INTEL_COMPILER)) */
# define likely(x)                      (x)
# define unlikely(x)                    (x)
#endif /* ! (defined(__GNUC__) || defined(__INTEL_COMPILER)) */

/* Designs */
#define WRITE_BACK_ETL                  0
#define WRITE_BACK_CTL                  1
#define WRITE_THROUGH                   2

static const char *design_names[] = {
  /* 0 */ "WRITE-BACK (ETL)",
  /* 1 */ "WRITE-BACK (CTL)",
  /* 2 */ "WRITE-THROUGH"
};

/* Nesting semantics */
#define NEST_FLATTENED                  0
#define NEST_CLOSED                     1

static const char *nest_names[] = {
  /* 0 */ "FLATTENED",
  /* 1 */ "CLOSED"
};

#ifndef NESTING
# define NESTING                        NEST_FLATTENED
#endif /* ! CM */

#ifndef DESIGN
# define DESIGN                         WRITE_BACK_ETL
#endif /* ! DESIGN */

/* Contention managers */
#define CM_SUICIDE                      0
#define CM_DELAY                        1
#define CM_BACKOFF                      2
#define CM_MODULAR                      3

static const char *cm_names[] = {
  /* 0 */ "SUICIDE",
  /* 1 */ "DELAY",
  /* 2 */ "BACKOFF",
  /* 3 */ "MODULAR"
};

#ifndef CM
# define CM                             CM_SUICIDE
#endif /* ! CM */

#if DESIGN != WRITE_BACK_ETL && CM == CM_MODULAR
# error "MODULAR contention manager can only be used with WB-ETL design"
#endif /* DESIGN != WRITE_BACK_ETL && CM == CM_MODULAR */

#if defined(CONFLICT_TRACKING) && ! defined(EPOCH_GC)
# error "CONFLICT_TRACKING requires EPOCH_GC"
#endif /* defined(CONFLICT_TRACKING) && ! defined(EPOCH_GC) */

#if CM == CM_MODULAR && ! defined(EPOCH_GC)
# error "MODULAR contention manager requires EPOCH_GC"
#endif /* CM == CM_MODULAR && ! defined(EPOCH_GC) */

#if defined(READ_LOCKED_DATA) && CM != CM_MODULAR
# error "READ_LOCKED_DATA can only be used with MODULAR contention manager"
#endif /* defined(READ_LOCKED_DATA) && CM != CM_MODULAR */

#if defined(EPOCH_GC) && defined(SIGNAL_HANDLER)
# error "SIGNAL_HANDLER can only be used without EPOCH_GC"
#endif /* defined(EPOCH_GC) && defined(SIGNAL_HANDLER) */

#if defined(HYBRID_ASF) && CM != CM_SUICIDE
# error "HYBRID_ASF can only be used with SUICIDE contention manager"
#endif /* defined(HYBRID_ASF) && CM != CM_SUICIDE */

#ifndef RW_SET_SIZE
// Clemens, 29.1.2013: This has been replaced by a dynamically tracked read/write set size
# define RW_SET_SIZE                    (1 << 10)           /* Initial size of read/write sets (must be power of two!) */
#endif /* ! RW_SET_SIZE */

#ifndef LOCK_ARRAY_LOG_SIZE
# define LOCK_ARRAY_LOG_SIZE            20                  /* Size of lock array: 2^20 = 1M */
#endif /* LOCK_ARRAY_LOG_SIZE */

#ifndef LOCK_SHIFT_EXTRA
# define LOCK_SHIFT_EXTRA               2                   /* 2 extra shift */
#endif /* LOCK_SHIFT_EXTRA */

#if CM == CM_BACKOFF
# ifndef MIN_BACKOFF
#  define MIN_BACKOFF                   (1UL << 2)
# endif /* MIN_BACKOFF */
# ifndef MAX_BACKOFF
#  define MAX_BACKOFF                   (1UL << 31)
# endif /* MAX_BACKOFF */
#endif /* CM == CM_BACKOFF */

#if CM == CM_MODULAR
# define VR_THRESHOLD                   "VR_THRESHOLD"
# ifndef VR_THRESHOLD_DEFAULT
#  define VR_THRESHOLD_DEFAULT          3
# endif /* VR_THRESHOLD_DEFAULT */
static int vr_threshold;
#endif /* CM == CM_MODULAR */

#define NO_SIGNAL_HANDLER               "NO_SIGNAL_HANDLER"

#define XSTR(s)                         STR(s)
#define STR(s)                          #s

/* ################################################################### *
 * TYPES
 * ################################################################### */

enum {                                  /* Transaction status */
  TX_IDLE = 0,
  TX_ACTIVE = 1,                        /* Lowest bit indicates activity */
  TX_COMMITTED = (1 << 1),
  TX_ABORTED = (2 << 1),
  TX_COMMITTING = (1 << 1) | TX_ACTIVE,
  TX_ABORTING = (2 << 1) | TX_ACTIVE,
  TX_KILLED = (3 << 1) | TX_ACTIVE,
  TX_IRREVOCABLE = 0x08 | TX_ACTIVE     /* Fourth bit indicates irrevocability */
};
#define STATUS_BITS                     4
#define STATUS_MASK                     ((1 << STATUS_BITS) - 1)

#if CM == CM_MODULAR
# define SET_STATUS(s, v)               ATOMIC_STORE_REL(&(s), ((s) & ~(stm_word_t)STATUS_MASK) | (v))
# define INC_STATUS_COUNTER(s)          ((((s) >> STATUS_BITS) + 1) << STATUS_BITS)
# define UPDATE_STATUS(s, v)            ATOMIC_STORE_REL(&(s), INC_STATUS_COUNTER(s) | (v))
# define GET_STATUS(s)                  ((s) & STATUS_MASK)
# define GET_STATUS_COUNTER(s)          ((s) >> STATUS_BITS)
#else /* CM != CM_MODULAR */
# define SET_STATUS(s, v)               ((s) = (v))
# define UPDATE_STATUS(s, v)            ((s) = (v))
# define GET_STATUS(s)                  ((s))
#endif /* CM != CM_MODULAR */
#define IS_ACTIVE(s)                    ((GET_STATUS(s) & 0x01) == TX_ACTIVE)

#ifndef MAX_SPECIFIC
# define MAX_SPECIFIC                   16
#endif /* MAX_SPECIFIC */

/* ################################################################### *
 * LOCKS
 * ################################################################### */

/*
 * A lock is a unsigned int of the size of a pointer.
 * The LSB is the lock bit. If it is set, this means:
 * - At least some covered memory addresses is being written.
 * - Write-back (ETL): all bits of the lock apart from the lock bit form
 *   a pointer that points to the write log entry holding the new
 *   value. Multiple values covered by the same log entry are organized
 *   in a linked list in the write log.
 * - Write-through and write-back (CTL): all bits of the lock apart from
 *   the lock bit form a pointer that points to the transaction
 *   descriptor containing the write-set.
 * If the lock bit is not set, then:
 * - All covered memory addresses contain consistent values.
 * - Write-back (ETL and CTL): all bits of the lock besides the lock bit
 *   contain a version number (timestamp).
 * - Write-through: all bits of the lock besides the lock bit contain a
 *   version number.
 *   - The high order bits contain the commit time.
 *   - The low order bits contain an incarnation number (incremented
 *     upon abort while writing the covered memory addresses).
 * When visible reads are enabled, two bits are used as read and write
 * locks. A read-locked address can be read by an invisible reader.
 */

#if CM == CM_MODULAR
# define OWNED_BITS                     2                   /* 2 bits */
# define WRITE_MASK                     0x01                /* 1 bit */
# define READ_MASK                      0x02                /* 1 bit */
# define OWNED_MASK                     (WRITE_MASK | READ_MASK)
#else /* CM != CM_MODULAR */
# define OWNED_BITS                     1                   /* 1 bit */
# define WRITE_MASK                     0x01                /* 1 bit */
# define OWNED_MASK                     (WRITE_MASK)
#endif /* CM != CM_MODULAR */
#if DESIGN == WRITE_THROUGH
# define INCARNATION_BITS               3                   /* 3 bits */
# define INCARNATION_MAX                ((1 << INCARNATION_BITS) - 1)
# define INCARNATION_MASK               (INCARNATION_MAX << 1)
# define LOCK_BITS                      (OWNED_BITS + INCARNATION_BITS)
#else /* DESIGN != WRITE_THROUGH */
# define LOCK_BITS                      (OWNED_BITS)
#endif /* DESIGN != WRITE_THROUGH */
#define MAX_THREADS                     8192                /* Upper bound (large enough) */
#define VERSION_MAX                     ((~(stm_word_t)0 >> LOCK_BITS) - MAX_THREADS)

#define LOCK_GET_OWNED(l)               (l & OWNED_MASK)
#define LOCK_GET_WRITE(l)               (l & WRITE_MASK)
#define LOCK_SET_ADDR_WRITE(a)          (a | WRITE_MASK)    /* WRITE bit set */
#define LOCK_GET_ADDR(l)                (l & ~(stm_word_t)OWNED_MASK)
#if CM == CM_MODULAR
# define LOCK_GET_READ(l)               (l & READ_MASK)
# define LOCK_SET_ADDR_READ(a)          (a | READ_MASK)     /* READ bit set */
# define LOCK_UPGRADE(l)                (l | WRITE_MASK)
#endif /* CM == CM_MODULAR */
#if DESIGN == WRITE_THROUGH
# define LOCK_GET_TIMESTAMP(l)          (l >> (1 + INCARNATION_BITS))
# define LOCK_SET_TIMESTAMP(t)          (t << (1 + INCARNATION_BITS))
# define LOCK_GET_INCARNATION(l)        ((l & INCARNATION_MASK) >> 1)
# define LOCK_SET_INCARNATION(i)        (i << 1)            /* OWNED bit not set */
# define LOCK_UPD_INCARNATION(l, i)     ((l & ~(stm_word_t)(INCARNATION_MASK | OWNED_MASK)) | LOCK_SET_INCARNATION(i))
#else /* DESIGN != WRITE_THROUGH */
# define LOCK_GET_TIMESTAMP(l)          (l >> OWNED_BITS)   /* Logical shift (unsigned) */
# define LOCK_SET_TIMESTAMP(t)          (t << OWNED_BITS)   /* OWNED bits not set */
#endif /* DESIGN != WRITE_THROUGH */
#define LOCK_UNIT                       (~(stm_word_t)0)

/*
 * We use the very same hash functions as TL2 for degenerate Bloom
 * filters on 32 bits.
 */
#ifdef USE_BLOOM_FILTER
# define FILTER_HASH(a)                 (((stm_word_t)a >> 2) ^ ((stm_word_t)a >> 5))
# define FILTER_BITS(a)                 (1 << (FILTER_HASH(a) & 0x1F))
#endif /* USE_BLOOM_FILTER */

/*
 * For WRITE_BACK_CTL, we organize the write set in a hash table.
 * This macro computes the hash of a memory address.
 */
#if DESIGN == WRITE_BACK_CTL
# define HASH_ADDR(a, size)             ((((stm_word_t)a >> ((sizeof(stm_word_t) == 4) ? 2 : 3)) ^ ((stm_word_t)a >> 8)) & (size - 1))
# define WRITE_FILL_THRESHOLD(size)     (size * 3 / 4)  /* max. fill ratio of the hash table. can also be greater than 1, recommended between 0.5 and 1. */
#endif

#if READ_SET == READ_SET_HASH_LINEAR
# define HASH_LOCK(lock, size)          ((((stm_word_t)lock) >> ((sizeof(stm_word_t) == 4) ? 2 : 3)) & ((size) - 1))
# define READ_FILL_THRESHOLD(size)      (size / 2)  /* for linear probing, there should be enough free space in the table! */
#endif
#if READ_SET == READ_SET_HASH_HOPSCOTCH
# define HASH_LOCKIDX(lockidx, size)    ((lockidx) & ((size) - 1))
#endif

/*
 * We use an array of locks and hash the address to find the location of the lock.
 * We try to avoid collisions as much as possible (two addresses covered by the same lock).
 */
#define LOCK_ARRAY_SIZE                 (1 << LOCK_ARRAY_LOG_SIZE)
#define LOCK_MASK                       (LOCK_ARRAY_SIZE - 1)
#define LOCK_SHIFT                      (((sizeof(stm_word_t) == 4) ? 2 : 3) + LOCK_SHIFT_EXTRA)
#define LOCK_IDX(a)                     (((stm_word_t)(a) >> LOCK_SHIFT) & LOCK_MASK)
#ifdef LOCK_IDX_SWAP
# if LOCK_ARRAY_LOG_SIZE < 16
#  error "LOCK_IDX_SWAP requires LOCK_ARRAY_LOG_SIZE to be at least 16"
# endif /* LOCK_ARRAY_LOG_SIZE < 16 */
# define GET_LOCK(a)                    (locks + lock_idx_swap(LOCK_IDX(a)))
#else /* ! LOCK_IDX_SWAP */
# define GET_LOCK(a)                    (locks + LOCK_IDX(a))
#endif /* ! LOCK_IDX_SWAP */

static volatile stm_word_t locks[LOCK_ARRAY_SIZE];

/* ################################################################### *
 * CLOCK
 * ################################################################### */

#ifdef CLOCK_IN_CACHE_LINE
/* At least twice a cache line (512 bytes to be on the safe side) */
static volatile stm_word_t gclock[1024 / sizeof(stm_word_t)];
# define CLOCK                          (gclock[512 / sizeof(stm_word_t)])
#else /* ! CLOCK_IN_CACHE_LINE */
static volatile stm_word_t gclock;
# define CLOCK                          (gclock)
#endif /* ! CLOCK_IN_CACHE_LINE */

#define GET_CLOCK                       (ATOMIC_LOAD_ACQ(&CLOCK))
#define FETCH_INC_CLOCK                 (ATOMIC_FETCH_INC_FULL(&CLOCK))

/* ################################################################### *
 * STATIC
 * ################################################################### */

/*
 * Just for debug: get a string representation of a rollback reason
 */
#ifdef DEBUG
char *decode_abort_reason(int reason) {
  switch (reason) {
    case STM_ABORT_EXPLICIT:    return (char*) "expl";
    case STM_ABORT_IMPLICIT:    return (char*) "impl";
    case STM_ABORT_RR_CONFLICT: return (char*) "rr";
    case STM_ABORT_RW_CONFLICT: return (char*) "rw";
    case STM_ABORT_WR_CONFLICT: return (char*) "wr";
    case STM_ABORT_WW_CONFLICT: return (char*) "ww";
    case STM_ABORT_VAL_READ:    return (char*) "rval";
    case STM_ABORT_VAL_WRITE:   return (char*) "wval";
    case STM_ABORT_VALIDATE:    return (char*) "val";
    case STM_ABORT_RO_WRITE:    return (char*) "ro";
    case STM_ABORT_IRREVOCABLE: return (char*) "irrev";
    case STM_ABORT_KILLED:      return (char*) "killed";
    case STM_ABORT_SIGNAL:      return (char*) "signal";
    case STM_ABORT_OTHER:       return (char*) "other";
    default:                    return (char*) "unknown";
  }
}
#endif


#if READ_SET == READ_SET_HASH_HOPSCOTCH
typedef struct r_entry {                /* Read set entry */
  stm_word_t version;                   /* Version read */
  uint32_t lockIdx_sh;                  /* Index of the associated lock, shifted by one bit to the left. LSB signal occupation of this slot. */
  uint8_t hopInfo;                      /* Bitset of occupied slots, used for hopscotch hashing */
} r_entry_t;
# define LOCK_FROM_RENTRY(r)            (locks + ((r)->lockIdx_sh >> 1))
typedef struct hhash r_set_t;
# include "hhash.c"
#else
typedef struct r_entry {                /* Read set entry */
  stm_word_t version;                   /* Version read */
  volatile stm_word_t *lock;            /* Pointer to lock (for fast access) */
} r_entry_t;
# define LOCK_FROM_RENTRY(r)            ((r)->lock)
typedef struct r_set {                  /* Read set */
  r_entry_t *entries;                   /* Array of entries */
  uint32_t nb_entries;                  /* Number of entries */
# if READ_SET == READ_SET_HASH_LINEAR
  /* If this ^ is enabled, then the entries array is organized
   * as hash table with linear probing. */
  uint32_t fill_threshold;              /* Resize the array when nb_entries==fill_threshold */
# endif
  uint32_t size;                        /* Size of array */
} r_set_t;
#endif

typedef struct w_entry {                /* Write set entry */
  union {                               /* For padding... */
    struct {
      volatile stm_word_t *addr;        /* Address written */
      stm_word_t value;                 /* New (write-back) or old (write-through) value */
      stm_word_t mask;                  /* Write mask */
      stm_word_t version;               /* Version overwritten */
      /* TODO check if it is faster to recompute the lock pointer from the address */
      //volatile stm_word_t *lock;        /* Pointer to lock (for fast access) */
#if CM == CM_MODULAR || (defined(CONFLICT_TRACKING) && DESIGN != WRITE_THROUGH)
      struct stm_tx *tx;                /* Transaction owning the write set */
#endif /* CM == CM_MODULAR || (defined(CONFLICT_TRACKING) && DESIGN != WRITE_THROUGH) */
#if DESIGN == WRITE_BACK_ETL || DESIGN == WRITE_BACK_CTL
      struct w_entry *next;             /* Next address covered by same lock, if any (for ETL); or
                                           pointer to next entry in the same hash table slot (for CTL). */
#endif /* DESIGN == WRITE_BACK_ETL || DESIGN == WRITE_BACK_CTL */
#if DESIGN != WRITE_BACK_ETL
      int no_drop;                      /* Should we drop lock upon abort? */
#endif /* DESIGN != WRITE_BACK_ETL */
    };
    stm_word_t padding[8];              /* Padding (multiple of a cache line) */
    /* TODO Check if padding is really usefull? */
  };
} w_entry_t;

typedef struct w_set {                  /* Write set */
  w_entry_t *entries;                   /* Array of entries. In WRITE_BACK_CTL, this is organized as a hash table. */
#if DESIGN == WRITE_BACK_CTL
  w_entry_t **hash_table;               /* Hash table over the entries, for faster lookup in stm_has_written. */
  uint32_t fill_threshold;              /* Resize the hash table when nb_entries==fill_threshold */
#endif
  uint32_t nb_entries;                  /* Number of entries */
  uint32_t size;                        /* Size of array(s) */
#if DESIGN == WRITE_BACK_ETL
  int has_writes;                       /* Has the write set any real write (vs. visible reads) */
#elif DESIGN == WRITE_BACK_CTL
  uint32_t nb_acquired;                 /* Number of locks acquired */
# ifdef USE_BLOOM_FILTER
  stm_word_t bloom;                     /* Same Bloom filter as in TL2 */
# endif /* USE_BLOOM_FILTER */
#endif /* DESIGN == WRITE_BACK_CTL */
} w_set_t;

typedef struct cb_entry {               /* Callback entry */
  void (*f)(TXPARAMS void *);           /* Function */
  void *arg;                            /* Argument to be passed to function */
} cb_entry_t;

#ifdef PRINT_TX_STATS_ON_EXIT
# ifndef COLLECT_TX_STATS
#  error PRINT_TX_STATS_ON_EXIT needs COLLECT_TX_STATS
# endif /* !COLLECT_TX_STATS */
typedef struct stm_stats_oldsigaction {
  int signal; /* 0 means free */
  struct sigaction old_handler;
} stm_stats_oldsigaction_t;
static stm_stats_oldsigaction_t stm_old_handlers[5];
#endif /* PRINT_TX_STATS_ON_EXIT */

#ifdef COLLECT_TX_STATS
# ifdef __APPLE__
#  define STATS_DEFINE_REALTIME(name) mach_timespec_t name;
#  define STATS_DEFINE_CPUTIME(name) clock_t name;
#  define STATS_GET_REALTIME(name) do { clock_get_time(cclock, &name); } while (0)
#  define STATS_GET_CPUTIME(name) do { (name) = clock(); } while (0)
#  define STATS_DIFF_CPUTIME_NANOS(time1, time2) \
  ((unsigned long long)((time2) - (time1)) * 1000000000 / CLOCKS_PER_SEC)
# else /* !__APPLE__ */
#  define STATS_DEFINE_REALTIME(name) struct timespec name;
#  define STATS_DEFINE_CPUTIME(name) struct timespec name;
#  define STATS_GET_REALTIME(name) do { clock_gettime(CLOCK_MONOTONIC, &name); } while (0)
#  define STATS_GET_CPUTIME(name) do { clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &name); } while (0)
#  define STATS_DIFF_CPUTIME_NANOS(time1, time2) \
  ((unsigned long long)((time2).tv_sec - (time1).tv_sec) * 1000000000 + (time2).tv_nsec - (time1).tv_nsec)
# endif /* !__APPLE__ */

# define START_COLLECT_STATS STATS_DEFINE_REALTIME(stat_start); STATS_GET_REALTIME(stat_start)
# define RESTART_COLLECT_STATS STATS_GET_REALTIME(stat_start)
# define STATS_DIFF_REALTIME_NANOS(time1, time2) \
  ((unsigned long long)((time2).tv_sec - (time1).tv_sec) * 1000000000 + (time2).tv_nsec - (time1).tv_nsec)
# define STAT_ADD_TIME(start, dst) do { \
        STATS_DEFINE_REALTIME(stat_end); \
        STATS_GET_REALTIME(stat_end); \
        __sync_fetch_and_add(&dst, STATS_DIFF_REALTIME_NANOS(start, stat_end)); \
    } while (0)

# define STOP_COLLECT_STATS(dst) STAT_ADD_TIME(stat_start, dst)

tx_stats_t global_tx_stats;
#ifdef __APPLE__
  clock_serv_t cclock;
  clock_t clock_on_init; // process CPU time on stm_init
#else /* !__APPLE__ */
  struct timespec clock_on_init; // process CPU time on stm_init
#endif


tx_stats_t stm_get_timings() {
    return global_tx_stats;
}
void stm_reset_timings() {
  memset(&global_tx_stats, 0, sizeof(global_tx_stats));
# ifdef __APPLE__
  host_get_clock_service(mach_host_self(), SYSTEM_CLOCK,
                         &cclock);
# endif /* __APPLE__ */
  STATS_GET_CPUTIME(clock_on_init);
}

// CASed to 1 on stm_print_stats with signal.
// this avoids double output if SEGV in several threads.
uint64_t dumped_stats_on_signal = 0;

struct stm_tx *running_txs[8];
void stm_add_running_tx(struct stm_tx *tx) {
  for (struct stm_tx **slot = running_txs,
                     **end = slot + sizeof(running_txs) / sizeof(*running_txs);
       slot != end; ++slot) {
    if (ATOMIC_LOAD((atomic_t *)slot) == 0 &&
        ATOMIC_CAS_FULL(slot, 0, (atomic_t)tx))
      return;
  }
  fprintf(stderr, "ERROR: no free slot in running_txs\n");
  abort();
}
void stm_remove_running_tx(struct stm_tx *tx) {
  for (struct stm_tx **slot = running_txs,
                     **end = slot + sizeof(running_txs) / sizeof(*running_txs);
       slot != end; ++slot) {
    if ((struct stm_tx *)ATOMIC_LOAD((atomic_t *)slot) == tx &&
        ATOMIC_CAS_FULL(slot, (atomic_t)tx, 0))
      return;
  }
  fprintf(stderr, "ERROR: tx not found in running_txs\n");
  abort();
}
#else /* !COLLECT_TX_STATS */
# define START_COLLECT_STATS do { } while (0)
# define RESTART_COLLECT_STATS do { } while (0)
# define STOP_COLLECT_STATS(dst) do { } while (0)
# define STAT_ADD_TIME(start, dst) do { } while (0)
tx_stats_t stm_get_timings() {
    tx_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    return stats;
}
void stm_reset_timings() { /* nop */ }
void stm_add_running_tx(struct stm_tx *tx) { /* nop */ }
void stm_remove_running_tx(struct stm_tx *tx) { /* nop */ }
#endif /* !COLLECT_TX_STATS */


typedef struct stm_tx {                 /* Transaction descriptor */
  sigjmp_buf env;                       /* Environment for setjmp/longjmp (must be first field!) */
  stm_tx_attr_t attr;                   /* Transaction attributes (user-specified) */
  volatile stm_word_t status;           /* Transaction status */
  stm_word_t start;                     /* Start timestamp */
  stm_word_t end;                       /* End timestamp (validity range) */
  r_set_t r_set;                        /* Read set */
  w_set_t w_set;                        /* Write set */
  unsigned int ro:1;                    /* Is this execution read-only? */
  unsigned int can_extend:1;            /* Can this transaction be extended? */
#if CM == CM_MODULAR
  unsigned int vr:1;                    /* Does this execution use visible reads? */
#endif /* CM == CM_MODULAR */
#ifdef IRREVOCABLE_ENABLED
  unsigned int irrevocable:4;           /* Is this execution irrevocable? */
#endif /* IRREVOCABLE_ENABLED */
#ifdef HYBRID_ASF
  unsigned int software:1;              /* Is the transaction mode pure software? */
#endif /* HYBRID_ASF */
#if NESTING == NEST_FLATTENED
  int nesting;                          /* Nesting level */
#elif NESTING == NEST_CLOSED
  struct stm_tx *parent;                /* The dynamic parent transaction */
#endif /* NESTING == FLATTENED */
#if CM == CM_MODULAR
  stm_word_t timestamp;                 /* Timestamp (not changed upon restart) */
#endif /* CM == CM_MODULAR */
  void *data[MAX_SPECIFIC];             /* Transaction-specific data (fixed-size array for better speed) */
  struct stm_tx *next;                  /* For keeping track of all transactional threads */
#ifdef CONFLICT_TRACKING
  pthread_t thread_id;                  /* Thread identifier (immutable) */
#endif /* CONFLICT_TRACKING */
#if CM == CM_DELAY || CM == CM_MODULAR
  volatile stm_word_t *c_lock;          /* Pointer to contented lock (cause of abort) */
#endif /* CM == CM_DELAY || CM == CM_MODULAR */
#if CM == CM_BACKOFF
  unsigned long backoff;                /* Maximum backoff duration */
  unsigned long seed;                   /* RNG seed */
#endif /* CM == CM_BACKOFF */
#if CM == CM_MODULAR
  int visible_reads;                    /* Should we use visible reads? */
#endif /* CM == CM_MODULAR */
#if CM == CM_MODULAR || defined(INTERNAL_STATS) || defined(HYBRID_ASF)
  unsigned long retries;                /* Number of consecutive aborts (retries) */
#endif /* CM == CM_MODULAR || defined(INTERNAL_STATS) || defined(HYBRID_ASF) */
#ifdef INTERNAL_STATS
  unsigned long aborts;                 /* Total number of aborts (cumulative) */
  unsigned long aborts_1;               /* Total number of transactions that abort once or more (cumulative) */
  unsigned long aborts_2;               /* Total number of transactions that abort twice or more (cumulative) */
  unsigned long aborts_ro;              /* Aborts due to wrong read-only specification (cumulative) */
  unsigned long aborts_locked_read;     /* Aborts due to trying to read when locked (cumulative) */
  unsigned long aborts_locked_write;    /* Aborts due to trying to write when locked (cumulative) */
  unsigned long aborts_validate_read;   /* Aborts due to failed validation upon read (cumulative) */
  unsigned long aborts_validate_write;  /* Aborts due to failed validation upon write (cumulative) */
  unsigned long aborts_validate_commit; /* Aborts due to failed validation upon commit (cumulative) */
  unsigned long aborts_invalid_memory;  /* Aborts due to invalid memory access (cumulative) */
# if CM == CM_MODULAR
  unsigned long aborts_killed;          /* Aborts due to being killed (cumulative) */
# endif /* CM == CM_MODULAR */
# ifdef READ_LOCKED_DATA
  unsigned long locked_reads_ok;        /* Successful reads of previous value */
  unsigned long locked_reads_failed;    /* Failed reads of previous value */
# endif /* READ_LOCKED_DATA */
  unsigned long max_retries;            /* Maximum number of consecutive aborts (retries) */
#endif /* INTERNAL_STATS */
#ifdef COLLECT_TX_STATS
  STATS_DEFINE_REALTIME(start_time)
  tx_stats_per_tx_t stats;
#endif
} stm_tx_t;

static int nb_specific = 0;             /* Number of specific slots used (<= MAX_SPECIFIC) */

static int initialized = 0;             /* Has the library been initialized? */

// quiescence support is currently broken, since each transaction is newly allocated on stm_start. */
//static pthread_mutex_t quiesce_mutex;   /* Mutex to support quiescence */
//static pthread_cond_t quiesce_cond;     /* Condition variable to support quiescence */
//static volatile stm_word_t quiesce;     /* Prevent threads from entering transactions upon quiescence */
//static volatile stm_word_t txs_nb;      /* Number of active transactions */
//static stm_tx_t *threads;               /* Head of linked list of threads */

#ifdef ADAPTIVE_READ_WRITE_SET_SIZE
static volatile size_t estimated_read_size = RW_SET_SIZE;   /* Exponentially floating average over last read sizes */
static volatile size_t estimated_write_size = RW_SET_SIZE;  /* Exponentially floating average over last write sizes */
#endif

static stm_tx_attr_t default_attributes = { 0, 0, 0, 0, 0 };

#ifdef IRREVOCABLE_ENABLED
// TODO put this value in a cacheline
static volatile stm_word_t irrevocable = 0;
#endif /* IRREVOCABLE_ENABLED */

/*
 * Transaction nesting is supported in a minimalist way (flat nesting):
 * - When a transaction is started in the context of another
 *   transaction, we simply increment a nesting counter but do not
 *   actually start a new transaction.
 * - The environment to be used for setjmp/longjmp is only returned when
 *   no transaction is active so that it is not overwritten by nested
 *   transactions. This allows for composability as the caller does not
 *   need to know whether it executes inside another transaction.
 * - The commit of a nested transaction simply decrements the nesting
 *   counter. Only the commit of the top-level transaction will actually
 *   carry through updates to shared memory.
 * - An abort of a nested transaction will rollback the top-level
 *   transaction and reset the nesting counter. The call to longjmp will
 *   restart execution before the top-level transaction.
 * Using nested transactions without setjmp/longjmp is not recommended
 * as one would need to explicitly jump back outside of the top-level
 * transaction upon abort of a nested transaction. This breaks
 * composability.
 */

/*
 * Reading from the previous version of locked addresses is implemented
 * by peeking into the write set of the transaction that owns the
 * lock. Each transaction has a unique identifier, updated even upon
 * retry. A special "commit" bit of this identifier is set upon commit,
 * right before writing the values from the redo log to shared memory. A
 * transaction can read a locked address if the identifier of the owner
 * does not change between before and after reading the value and
 * version, and it does not have the commit bit set.
 */

/* ################################################################### *
 * CALLBACKS
 * ################################################################### */

#define MAX_CB                          16

/* Declare as static arrays (vs. lists) to improve cache locality */
static cb_entry_t init_cb[MAX_CB];      /* Init thread callbacks */
static cb_entry_t exit_cb[MAX_CB];      /* Exit thread callbacks */
static cb_entry_t start_cb[MAX_CB];     /* Start callbacks */
static cb_entry_t precommit_cb[MAX_CB]; /* Commit callbacks */
static cb_entry_t commit_cb[MAX_CB];    /* Commit callbacks */
static cb_entry_t abort_cb[MAX_CB];     /* Abort callbacks */

static int nb_init_cb = 0;
static int nb_exit_cb = 0;
static int nb_start_cb = 0;
static int nb_precommit_cb = 0;
static int nb_commit_cb = 0;
static int nb_abort_cb = 0;

#ifdef CONFLICT_TRACKING
static void (*conflict_cb)(stm_tx_t *, stm_tx_t *) = NULL;
#endif /* CONFLICT_TRACKING */

/* ################################################################### *
 * THREAD-LOCAL
 * ################################################################### */

#ifdef TLS
static __thread stm_tx_t* thread_tx = NULL;
#else /* ! TLS */
static pthread_key_t thread_tx;
#endif /* ! TLS */


/*
 * Returns the transaction descriptor for the CURRENT thread.
 */
static inline stm_tx_t *stm_get_tx()
{
  stm_tx_t *tx;
#ifdef TLS
  tx = thread_tx;
#else
  tx = (stm_tx_t *)pthread_getspecific(thread_tx);
#endif
  PRINT_DEBUG("==> stm_get_tx(thread=%x) = %p\n", (unsigned int)pthread_self(),
              tx);
  return tx;
}

#if CM == CM_MODULAR
# define KILL_SELF                      0x00
# define KILL_OTHER                     0x01
# define DELAY_RESTART                  0x04

# define RR_CONFLICT                    0x00
# define RW_CONFLICT                    0x01
# define WR_CONFLICT                    0x02
# define WW_CONFLICT                    0x03

static int (*contention_manager)(stm_tx_t *, stm_tx_t *, int) = NULL;

/*
 * Kill other.
 */
int cm_aggressive(struct stm_tx *me, struct stm_tx *other, int conflict)
{
  return KILL_OTHER;
}

/*
 * Kill self.
 */
int cm_suicide(struct stm_tx *me, struct stm_tx *other, int conflict)
{
  return KILL_SELF;
}

/*
 * Kill self and wait before restart.
 */
int cm_delay(struct stm_tx *me, struct stm_tx *other, int conflict)
{
  return KILL_SELF | DELAY_RESTART;
}

/*
 * Oldest transaction has priority.
 */
int cm_timestamp(struct stm_tx *me, struct stm_tx *other, int conflict)
{
  if (me->timestamp < other->timestamp)
    return KILL_OTHER;
  if (me->timestamp == other->timestamp && (uintptr_t)me < (uintptr_t)other)
    return KILL_OTHER;
  return KILL_SELF | DELAY_RESTART;
}

/*
 * Transaction with more work done has priority.
 */
int cm_karma(struct stm_tx *me, struct stm_tx *other, int conflict)
{
  if ((me->w_set.nb_entries << 1) + me->r_set.nb_entries < (other->w_set.nb_entries << 1) + other->r_set.nb_entries)
    return KILL_OTHER;
  if (((me->w_set.nb_entries << 1) + me->r_set.nb_entries == (other->w_set.nb_entries << 1) + other->r_set.nb_entries) && (uintptr_t)me < (uintptr_t)other )
    return KILL_OTHER;
  return KILL_SELF;
}

struct {
  const char *name;
  int (*f)(stm_tx_t *, stm_tx_t *, int);
} cms[] = {
  { "aggressive", cm_aggressive },
  { "suicide", cm_suicide },
  { "delay", cm_delay },
  { "timestamp", cm_timestamp },
  { "karma", cm_karma },
  { NULL, NULL }
};
#endif /* CM == CM_MODULAR */

#ifdef LOCK_IDX_SWAP
/*
 * Compute index in lock table (swap bytes to avoid consecutive addresses to have neighboring locks).
 */
static inline unsigned int lock_idx_swap(unsigned int idx) {
  return (idx & ~(unsigned int)0xFFFF) | ((idx & 0x00FF) << 8) | ((idx & 0xFF00) >> 8);
}
#endif /* LOCK_IDX_SWAP */

/*
 * Initialize quiescence support.
 */
static inline void stm_quiesce_init()
{
}

/*
 * Clean up quiescence support.
 */
static inline void stm_quiesce_exit()
{
}

/*
 * Called by each thread upon initialization for quiescence support.
 */
static inline void stm_quiesce_enter_thread(stm_tx_t *tx)
{
}

/*
 * Called by each thread upon exit for quiescence support.
 */
static inline void stm_quiesce_exit_thread(stm_tx_t *tx)
{
}

/*
 * Wait for all transactions to be block on a barrier.
 */
static inline void stm_quiesce_barrier(stm_tx_t *tx, void (*f)(void *), void *arg)
{
  PRINT_DEBUG("==> stm_quiesce_barrier()\n");
  assert (0 && "quiescence support is currently broken");
  abort();
}

/*
 * Wait for all transactions to be be out of their current transaction.
 */
static inline int stm_quiesce(stm_tx_t *tx, int block)
{
  PRINT_DEBUG("==> stm_quiesce(%p)\n", tx);
  assert (0 && "quiescence support is currently broken");
  abort();
}

/*
 * Check if transaction must block.
 */
static inline int stm_check_quiesce(stm_tx_t *tx)
{
  return 0;
}

/*
 * Release threads blocked after quiescence.
 */
static inline void stm_quiesce_release(stm_tx_t *tx)
{
}

/*
 * Reset clock and timestamps
 */
static inline void rollover_clock(void *arg)
{
  PRINT_DEBUG("==> rollover_clock()\n");

  /* Reset clock */
  CLOCK = 0;
  /* Reset timestamps */
  memset((void *)locks, 0, LOCK_ARRAY_SIZE * sizeof(stm_word_t));
# ifdef EPOCH_GC
  /* Reset GC */
  gc_reset();
# endif /* EPOCH_GC */
}

/*
 * Check if stripe has been read previously.
 * Return <>0 if a read set entry is found, 0 otherwise;
 */
static inline uint8_t stm_has_read(stm_tx_t *tx, volatile stm_word_t *lock)
{
  PRINT_DEBUG2("==> stm_has_read(%p[%lu-%lu],%p)\n", tx, (unsigned long)tx->start, (unsigned long)tx->end, lock);

  /* Look for read */
#if READ_SET == READ_SET_HASH_HOPSCOTCH
  return hhashget(&tx->r_set, lock - locks);
#else
# if READ_SET == READ_SET_HASH_LINEAR
  for (r_entry_t *r = &tx->r_set.entries[HASH_LOCK(lock, tx->r_set.size)]; r->lock != NULL; ++r) {
# else /* READ_SET_DUPLICATES and READ_SET_LINEAR_SCAN */
  r_entry_t *r = tx->r_set.entries;
  for (int i = tx->r_set.nb_entries; i > 0; i--, r++) {
# endif
    if (r->lock == lock) {
      /* Return first match*/
      return 1;
    }
  }
  return 0;
#endif
}

#if DESIGN == WRITE_BACK_CTL || DESIGN == WRITE_THROUGH
/*
 * Check if address has been written previously.
 */
static inline w_entry_t *stm_has_written(stm_tx_t *tx, volatile stm_word_t *addr)
{
  PRINT_DEBUG2("==> stm_has_written(%p[%lu-%lu],addr=%p)\n", tx, (unsigned long)tx->start, (unsigned long)tx->end, addr);

# ifdef USE_BLOOM_FILTER
  stm_word_t mask = FILTER_BITS(addr);
  if ((tx->w_set.bloom & mask) != mask)
    return NULL;
# endif /* USE_BLOOM_FILTER */

  /* Look for write */
# if DESIGN == WRITE_BACK_CTL
  for (w_entry_t *w = tx->w_set.hash_table[HASH_ADDR(addr, tx->w_set.size)]; w; w = w->next) {
    assert (HASH_ADDR(w->addr, tx->w_set.size) == HASH_ADDR(addr, tx->w_set.size));
# else
  for (w_entry_t *w = tx->w_set.entries, *end = w + tx->w_set.nb_entries; w != end; ++w) {
# endif
    if (w->addr == addr) {
      return w;
    }
  }
  return NULL;
}
#endif /* DESIGN == WRITE_BACK_CTL */

  /* Hopscotch extends automatically when a neighboorhood is filled */
#if READ_SET != READ_SET_HASH_HOPSCOTCH
/*
 * (Re)allocate read set entries.
 */
static inline void stm_allocate_rs_entries(stm_tx_t *tx, int extend)
{
  PRINT_DEBUG("==> stm_allocate_rs_entries(%p[%lu-%lu],extend=%d,size=%d)\n", tx, (unsigned long)tx->start, (unsigned long)tx->end, extend, tx->r_set.size);

# if READ_SET == READ_SET_HASH_LINEAR
  if (extend) {
    /* Extend read set */
    int old_size = tx->r_set.size;
    int new_size = tx->r_set.size = 2 * old_size;
    r_entry_t *old_entries = tx->r_set.entries;
    r_entry_t *new_entries = tx->r_set.entries = (r_entry_t *)calloc(new_size, sizeof(r_entry_t));
    if (new_entries == NULL) {
      fprintf(stderr, "calloc table for hashed read set of size %d failed.\n",
              new_size);
      perror("calloc read set");
      abort();
    }
    tx->r_set.fill_threshold = READ_FILL_THRESHOLD(new_size);
    assert (tx->r_set.fill_threshold > tx->r_set.nb_entries);
    assert (tx->r_set.fill_threshold <= tx->r_set.size);
    uint32_t num_counted = 0;
    /* rehash: */
    for (r_entry_t *e = old_entries, *e_end = old_entries + old_size, *new_end = new_entries + new_size; e != e_end; ++e) {
      if (e->lock == NULL)
        continue;
      ++num_counted;
      r_entry_t *dst = &new_entries[HASH_LOCK(e->lock, new_size)];
      while (dst->lock != NULL)
        if (++dst == new_end)
          dst = new_entries;
      dst->lock = e->lock;
      dst->version = e->version;
    }
    free (old_entries);
    assert (num_counted == tx->r_set.nb_entries && "discrepancy in read set counter");
  } else {
    /* Allocate read set */
    if ((tx->r_set.entries = (r_entry_t *)calloc(tx->r_set.size, sizeof(r_entry_t))) == NULL) {
      fprintf(stderr, "calloc table for hashed read set of size %d failed.\n",
              tx->r_set.size);
      perror("calloc read set");
      abort();
    }
    tx->r_set.fill_threshold = READ_FILL_THRESHOLD(tx->r_set.size);
  }
# else /* READ_SET_DUPLICATES or READ_SET_LINEAR_SCAN */
  if (extend) {
    /* Extend read set */
    tx->r_set.size *= 2;
    if ((tx->r_set.entries = (r_entry_t *)realloc(tx->r_set.entries, tx->r_set.size * sizeof(r_entry_t))) == NULL) {
      fprintf(stderr, "realloc read set array of size %d failes.\n",
              tx->r_set.size);
      perror("realloc read set");
      abort();
    }
  } else {
    /* Allocate read set */
    if ((tx->r_set.entries = (r_entry_t *)malloc(tx->r_set.size * sizeof(r_entry_t))) == NULL) {
      fprintf(stderr, "malloc read set array of size %d failes.\n",
              tx->r_set.size);
      perror("malloc read set");
      abort();
    }
  }
# endif
}
#endif

/*
 * (Re)allocate write set entries.
 */
static inline void stm_allocate_ws_entries(stm_tx_t *tx, int extend)
{
#if CM == CM_MODULAR || (defined(CONFLICT_TRACKING) && DESIGN != WRITE_THROUGH)
  int i, first = (extend ? tx->w_set.size : 0);
#endif /* CM == CM_MODULAR || (defined(CONFLICT_TRACKING) && DESIGN != WRITE_THROUGH) */

  PRINT_DEBUG("==> stm_allocate_ws_entries(%p[%lu-%lu],extend=%d,size=%d)\n", tx, (unsigned long)tx->start, (unsigned long)tx->end, extend, tx->w_set.size);

  if (extend) {
    /* Extend write set */
#if DESIGN == WRITE_BACK_ETL
    w_entry_t *ows, *nws;
    /* Allocate new write set */
    ows = tx->w_set.entries;
    if ((nws = (w_entry_t *)malloc(tx->w_set.size * 2 * sizeof(w_entry_t))) == NULL) {
      perror("malloc write set");
      exit(1);
    }
    /* Copy write set */
    memcpy(nws, ows, tx->w_set.size * sizeof(w_entry_t));
    /* Update pointers and locks */
    for (uint32_t j = 0; j < tx->w_set.nb_entries; j++) {
      if (ows[j].next != NULL)
        nws[j].next = nws + (ows[j].next - ows);
    }
    for (uint32_t j = 0; j < tx->w_set.nb_entries; j++) {
      if (ows[j].lock == GET_LOCK(ows[j].addr))
        ATOMIC_STORE_REL(ows[j].lock, LOCK_SET_ADDR_WRITE((stm_word_t)&nws[j]));
    }
    tx->w_set.entries = nws;
    tx->w_set.size *= 2;
# ifdef EPOCH_GC
    gc_free(ows, tx->start);
# else /* ! EPOCH_GC */
    free(ows);
# endif /* ! EPOCH_GC */
#else /* DESIGN != WRITE_BACK_ETL */
    size_t old_size = tx->w_set.size;
    size_t new_size = tx->w_set.size = old_size * 2;
    size_t num_entries_to_alloc = new_size;
# if DESIGN == WRITE_BACK_CTL
    num_entries_to_alloc = WRITE_FILL_THRESHOLD(new_size);
# endif
    w_entry_t *old_entries = tx->w_set.entries; /* needed to rewrite the next pointers in case of CTL */
    w_entry_t *new_entries = (w_entry_t *)realloc(old_entries, num_entries_to_alloc * sizeof(w_entry_t));
    if ((tx->w_set.entries = new_entries) == NULL) {
      perror("realloc write set");
      exit(1);
    }
# if DESIGN == WRITE_BACK_CTL
    /*
    uint32_t numEmpty = 0;
    uint32_t longestChain = 0;
    for (w_entry_t **hash_ptr = tx->w_set.hash_table, **hash_end = tx->w_set.hash_table + old_size; hash_ptr != hash_end; ++hash_ptr) {
        uint32_t chain = 0;
        if (!*hash_ptr)
            ++numEmpty;
        for (w_entry_t *e = *hash_ptr; e; e = e->next)
            ++chain;
        if (chain > longestChain)
            longestChain = chain;
    }
    printf("oldSize: %lu;  empty: %d;  longestChain: %d\n", old_size, numEmpty, longestChain);
    */

    tx->w_set.fill_threshold = WRITE_FILL_THRESHOLD(new_size);
    w_entry_t **old_table = tx->w_set.hash_table;
    free(old_table);
    w_entry_t **new_table = (w_entry_t **)calloc(new_size, sizeof(w_entry_t*));
    if ((tx->w_set.hash_table = new_table) == NULL) {
      perror("calloc write hash table");
      exit(1);
    }

    for (w_entry_t *e = new_entries, *end = new_entries + tx->w_set.nb_entries; e != end; ++e) {
      w_entry_t **slot = new_table + HASH_ADDR(e->addr, new_size);
      e->next = *slot;
      *slot = e;
    }
# endif /* DESIGN == WRITE_BACK_CTL */
#endif /* DESIGN != WRITE_BACK_ETL */
  } else {
    int num_entries;
#if DESIGN == WRITE_BACK_CTL
    /* Allocate write hash table */
    tx->w_set.fill_threshold = num_entries = WRITE_FILL_THRESHOLD(tx->w_set.size);
    if ((tx->w_set.hash_table = (w_entry_t **)calloc(tx->w_set.size, sizeof(w_entry_t*))) == NULL) {
      perror("calloc write hash table");
      exit(1);
    }
#else
    num_entries = tx->w_set.size;
#endif
    /* Allocate write set */
    if ((tx->w_set.entries = (w_entry_t *)malloc(num_entries * sizeof(w_entry_t))) == NULL) {
      perror("malloc write set");
      exit(1);
    }
  }

#if CM == CM_MODULAR || (defined(CONFLICT_TRACKING) && DESIGN != WRITE_THROUGH)
  /* Initialize fields */
  for (i = first; i < tx->w_set.size; i++)
    tx->w_set.entries[i].tx = tx;
#endif /* CM == CM_MODULAR || (defined(CONFLICT_TRACKING) && DESIGN != WRITE_THROUGH) */
}

/*
 * Validate read set (check if all read addresses are still valid now).
 */
static inline int stm_validate(stm_tx_t *tx)
{
  START_COLLECT_STATS;
  PRINT_DEBUG("==> stm_validate(%p[%lu-%lu])\n", tx, (unsigned long)tx->start, (unsigned long)tx->end);

  /* Validate reads */
#if READ_SET == READ_SET_HASH_HOPSCOTCH
  for (r_entry_t *r = tx->r_set.V, *r_end = tx->r_set.V + tx->r_set.n; r != r_end; ++r) {
    if (r->lockIdx_sh == 0)
      continue;
#elif READ_SET == READ_SET_HASH_LINEAR
  r_entry_t *r_end = tx->r_set.entries + tx->r_set.size;
# ifdef DEBUG_PERFORMANCE_DATA
  int sum_probes = 0, max_probes = 0;
  for (r_entry_t *r = tx->r_set.entries; r != r_end; ++r)
    if (r->lock) {
      int probes = 1;
      for (r_entry_t *probe = &tx->r_set.entries[HASH_LOCK(r->lock, tx->r_set.size)]; probe != r; ++probe) {
        assert (probe->lock != NULL && probe->lock != r->lock);
        ++probes;
      }
      if (probes > max_probes)
          max_probes = probes;
      sum_probes += probes;
    }
  printf("at validate tx=%p: # read set entries = %d; max. probes = %d; avg. probes = %.2f\n",
    tx, tx->r_set.nb_entries, max_probes, (double)sum_probes / tx->r_set.nb_entries);
# endif
  for (r_entry_t *r = tx->r_set.entries; r != r_end; ++r) {
    if (r->lock == NULL)
      continue;
#else /* READ_SET_DUPLICATES or READ_SET_LINEAR_SCAN */
  r_entry_t *r = tx->r_set.entries;
  for (int i = tx->r_set.nb_entries; i > 0; i--, r++) {
    /* Read lock */
    assert (r->lock >= locks && r->lock < locks + LOCK_ARRAY_SIZE);
#endif
    volatile stm_word_t *lock = LOCK_FROM_RENTRY(r);
    stm_word_t l = ATOMIC_LOAD(lock);
    /* Unlocked and still the same version? */
    if (LOCK_GET_OWNED(l)) {
      /* Do we own the lock? */
#if DESIGN == WRITE_THROUGH
      if ((stm_tx_t *)LOCK_GET_ADDR(l) != tx)
#else /* DESIGN != WRITE_THROUGH */
      w_entry_t *w = (w_entry_t *)LOCK_GET_ADDR(l);
      /* Simply check if address falls inside our write set (avoids non-faulting load) */
      if (!(tx->w_set.entries <= w && w < tx->w_set.entries + tx->w_set.nb_entries))
#endif /* DESIGN != WRITE_THROUGH */
      {
        /* Locked by another transaction: cannot validate */
#ifdef CONFLICT_TRACKING
        if (conflict_cb != NULL && l != LOCK_UNIT) {
          /* Call conflict callback */
# if DESIGN == WRITE_THROUGH
          stm_tx_t *other = (stm_tx_t *)LOCK_GET_ADDR(l);
# else /* DESIGN != WRITE_THROUGH */
          stm_tx_t *other = w->tx;
# endif /* DESIGN != WRITE_THROUGH */
          conflict_cb(tx, other);
        }
#endif /* CONFLICT_TRACKING */
#if DESIGN == WRITE_THROUGH
        PRINT_DEBUG2("==>   read conflict detected in tx %p! lock %lx is owned by tx %p\n", tx, r->lock - locks, (void*)LOCK_GET_ADDR(l));
#else /* DESIGN != WRITE_THROUGH */
        PRINT_DEBUG2("==>   read conflict detected in tx %p! lock %lx is owned by another tx (write entry %p)\n", tx, LOCK_FROM_RENTRY(r) - locks, (void*)LOCK_GET_ADDR(l));
#endif /* DESIGN != WRITE_THROUGH */
        STOP_COLLECT_STATS(global_tx_stats.nanos_in_validate);
        return 0;
      }
      /* We own the lock: OK */
#if DESIGN == WRITE_BACK_CTL
      if (w->version != r->version) {
        /* Other version: cannot validate */
        PRINT_DEBUG2("==>   read conflict detected in tx %p for owned lock %lx! version number changed from %ld to %ld\n", tx, LOCK_FROM_RENTRY(r) - locks, r->version, w->version);
        STOP_COLLECT_STATS(global_tx_stats.nanos_in_validate);
        return 0;
      }
#endif /* DESIGN == WRITE_BACK_CTL */
    } else { /* not locked: */
      if (LOCK_GET_TIMESTAMP(l) != r->version) {
        /* Other version: cannot validate */
        PRINT_DEBUG2("==>   read conflict detected in tx %p for unlocked lock %lx! version number changed from %ld to %ld\n", tx, LOCK_FROM_RENTRY(r) - locks, r->version, LOCK_GET_TIMESTAMP(l));
        STOP_COLLECT_STATS(global_tx_stats.nanos_in_validate);
        return 0;
      }
      /* Same version: OK */
    }
  }
  STOP_COLLECT_STATS(global_tx_stats.nanos_in_validate);
  return 1;
}

/*
 * Extend snapshot range.
 */
static inline int stm_extend(stm_tx_t *tx)
{
  stm_word_t now;

  PRINT_DEBUG("==> stm_extend(%p[%lu-%lu])\n", tx, (unsigned long)tx->start, (unsigned long)tx->end);

  /* Get current time */
  now = GET_CLOCK;
  if (now >= VERSION_MAX) {
    /* Clock overflow */
    return 0;
  }
  /* Try to validate read set */
  if (stm_validate(tx)) {
    /* It works: we can extend until now */
    tx->end = now;
    return 1;
  }
  return 0;
}

#if CM == CM_MODULAR
/*
 * Kill other transaction.
 */
static inline int stm_kill(stm_tx_t *tx, stm_tx_t *other, stm_word_t status)
{
  stm_word_t c, t;

  PRINT_DEBUG("==> stm_kill(%p[%lu-%lu],%p,s=%ld)\n", tx, (unsigned long)tx->start, (unsigned long)tx->end, other, status);

# ifdef CONFLICT_TRACKING
  if (conflict_cb != NULL)
    conflict_cb(tx, other);
# endif /* CONFLICT_TRACKING */

# ifdef IRREVOCABLE_ENABLED
  if (GET_STATUS(status) == TX_IRREVOCABLE)
    return 0;
# endif /* IRREVOCABLE_ENABLED */
  if (GET_STATUS(status) == TX_ABORTED || GET_STATUS(status) == TX_COMMITTED || GET_STATUS(status) == TX_KILLED || GET_STATUS(status) == TX_IDLE)
    return 0;
  if (GET_STATUS(status) == TX_ABORTING || GET_STATUS(status) == TX_COMMITTING) {
    /* Transaction is already aborting or committing: wait */
    while (other->status == status)
      ;
    return 0;
  }
  assert(IS_ACTIVE(status));
  /* Set status to KILLED */
  if (ATOMIC_CAS_FULL(&other->status, status, status + (TX_KILLED - TX_ACTIVE)) == 0) {
    /* Transaction is committing/aborting (or has committed/aborted) */
    c = GET_STATUS_COUNTER(status);
    do {
      t = other->status;
# ifdef IRREVOCABLE_ENABLED
      if (GET_STATUS(t) == TX_IRREVOCABLE)
        return 0;
# endif /* IRREVOCABLE_ENABLED */
    } while (GET_STATUS(t) != TX_ABORTED && GET_STATUS(t) != TX_COMMITTED && GET_STATUS(t) != TX_KILLED && GET_STATUS(t) != TX_IDLE && GET_STATUS_COUNTER(t) == c);
    return 0;
  }
  /* We have killed the transaction: we can steal the lock */
  return 1;
}

/*
 * Drop locks after having been killed.
 */
static inline void stm_drop(stm_tx_t *tx)
{
  w_entry_t *w;
  stm_word_t l;
  int i;

  PRINT_DEBUG("==> stm_drop(%p[%lu-%lu])\n", tx, (unsigned long)tx->start, (unsigned long)tx->end);

  /* Drop locks */
  i = tx->w_set.nb_entries;
  if (i > 0) {
    w = tx->w_set.entries;
    for (; i > 0; i--, w++) {
      l = ATOMIC_LOAD_ACQ(w->lock);
      if (LOCK_GET_OWNED(l) && (w_entry_t *)LOCK_GET_ADDR(l) == w) {
        /* Drop using CAS */
        ATOMIC_CAS_FULL(w->lock, l, LOCK_SET_TIMESTAMP(w->version));
        /* If CAS fail, lock has been stolen or already released in case a lock covers multiple addresses */
      }
    }
    /* We need to reallocate the write set to avoid an ABA problem (the
     * transaction could reuse the same entry after having been killed
     * and restarted, and another slow transaction could steal the lock
     * using CAS without noticing the restart) */
    gc_free(tx->w_set.entries, tx->start);
    stm_allocate_ws_entries(tx, 0);
  }
}
#endif /* CM == CM_MODULAR */

/*
 * Initialize the transaction descriptor before start or restart.
 */
static inline void stm_prepare(stm_tx_t *tx)
{
  PRINT_DEBUG("==> stm_prepare(%p[%lu-%lu])\n", tx, (unsigned long)tx->start, (unsigned long)tx->end);

#if CM == CM_MODULAR
  if (!tx->vr && (tx->attr.visible_reads || (tx->visible_reads >= vr_threshold && vr_threshold >= 0))) {
    /* Use visible read */
    tx->vr = tx->attr.visible_reads = 1;
    tx->ro = tx->attr.read_only = 0;
  }
#endif /* CM == CM_MODULAR */
 start:
  /* Start timestamp */
  tx->start = tx->end = GET_CLOCK; /* OPT: Could be delayed until first read/write */

  /* Allow extensions */
  tx->can_extend = 1;
  if (tx->start >= VERSION_MAX) {
    /* Block all transactions and reset clock */
    stm_quiesce_barrier(tx, rollover_clock, NULL);
    goto start;
  }
#if CM == CM_MODULAR
  if (tx->retries == 0)
    tx->timestamp = tx->start;
#endif /* CM == CM_MODULAR */
  /* Read/write set */
#if DESIGN == WRITE_BACK_ETL
  tx->w_set.has_writes = 0;
#elif DESIGN == WRITE_BACK_CTL
  tx->w_set.nb_acquired = 0;
  for (w_entry_t **hash_ptr = tx->w_set.hash_table, **hash_end = tx->w_set.hash_table + tx->w_set.size; hash_ptr != hash_end; ++hash_ptr) {
    assert (*hash_ptr == NULL && "hash table should be empty");
  }
# ifdef USE_BLOOM_FILTER
  tx->w_set.bloom = 0;
# endif /* USE_BLOOM_FILTER */
#endif /* DESIGN == WRITE_BACK_CTL */
  tx->w_set.nb_entries = 0;
#if READ_SET == READ_SET_HASH_HOPSCOTCH
  assert (tx->r_set.m == 0);
#else
# if READ_SET == READ_SET_HASH_LINEAR
  for (r_entry_t *e = tx->r_set.entries, *e_end = tx->r_set.entries + tx->r_set.size; e != e_end; ++e) {
    assert (e->lock == NULL && "hash table should be empty");
  }
# endif /* READ_SET_HASH_LINEAR */
  tx->r_set.nb_entries = 0;
#endif

#ifdef EPOCH_GC
  gc_set_epoch(tx->start);
#endif /* EPOCH_GC */

#ifdef IRREVOCABLE_ENABLED
  if (tx->irrevocable != 0) {
    assert(!IS_ACTIVE(tx->status));
    stm_set_irrevocable(TXARGS -1);
    UPDATE_STATUS(tx->status, TX_IRREVOCABLE);
  } else
    UPDATE_STATUS(tx->status, TX_ACTIVE);
#else /* ! IRREVOCABLE_ENABLED */
  /* Set status */
  UPDATE_STATUS(tx->status, TX_ACTIVE);
#endif /* ! IRREVOCABLE_ENABLED */

#ifdef COLLECT_TX_STATS
  memset(&tx->stats, 0, sizeof(tx->stats));
  STATS_GET_REALTIME(tx->start_time);
#endif

  stm_check_quiesce(tx);
}

/*
 * Rollback transaction.
 */
NORETURN(static inline) void stm_rollback(stm_tx_t *tx, int reason)
{
#ifdef COLLECT_TX_STATS
  ATOMIC_FETCH_INC_FULL(&global_tx_stats.num_rollbacks);
#endif

  STAT_ADD_TIME(tx->start_time, global_tx_stats.nanos_in_rollbacked_code);

  START_COLLECT_STATS;

  w_entry_t *w;
#if DESIGN != WRITE_BACK_CTL
  int i;
#endif /* DESIGN != WRITE_BACK_CTL */
#if DESIGN == WRITE_THROUGH || CM == CM_MODULAR
  stm_word_t t;
#endif /* DESIGN == WRITE_THROUGH || CM == CM_MODULAR */
#if CM == CM_BACKOFF
  unsigned long wait;
  volatile int j;
#endif /* CM == CM_BACKOFF */

  PRINT_DEBUG("==> stm_rollback(%p[%lu-%lu],reason=%d(%s))\n", tx, (unsigned long)tx->start, (unsigned long)tx->end, reason, decode_abort_reason(reason));

  assert(IS_ACTIVE(tx->status));
#if CM == CM_MODULAR
  /* Set status to ABORTING */
  t = tx->status;
  if (GET_STATUS(t) == TX_KILLED || (GET_STATUS(t) == TX_ACTIVE && ATOMIC_CAS_FULL(&tx->status, t, t + (TX_ABORTING - TX_ACTIVE)) == 0)) {
    /* We have been killed */
    assert(GET_STATUS(tx->status) == TX_KILLED);
# ifdef INTERNAL_STATS
    tx->aborts_killed++;
# endif /* INTERNAL_STATS */
    /* Release locks */
    stm_drop(tx);
    goto dropped;
  }
#endif /* CM == CM_MODULAR */

#if DESIGN == WRITE_THROUGH
  t = 0;
  /* Undo writes and drop locks (traverse in reverse order) */
  w = tx->w_set.entries + tx->w_set.nb_entries;
  while (w != tx->w_set.entries) {
    w--;
    /* TODO stm_release */
    //if (w->addr == NULL)
      //continue;
    if (w->mask != 0)
      ATOMIC_STORE(w->addr, w->value);
    if (w->no_drop)
      continue;
    /* Incarnation numbers allow readers to detect dirty reads */
    i = LOCK_GET_INCARNATION(w->version) + 1;
    if (i > INCARNATION_MAX) {
      /* Simple approach: write new version (might trigger unnecessary aborts) */
      if (t == 0) {
        /* Get new version (may exceed VERSION_MAX by up to MAX_THREADS) */
        t = FETCH_INC_CLOCK + 1;
      }
      ATOMIC_STORE_REL(w->lock, LOCK_SET_TIMESTAMP(t));
    } else {
      /* Use new incarnation number */
      ATOMIC_STORE_REL(w->lock, LOCK_UPD_INCARNATION(w->version, i));
    }
  }
#elif DESIGN == WRITE_BACK_ETL
  /* Drop locks */
  i = tx->w_set.nb_entries;
  if (i > 0) {
    w = tx->w_set.entries;
    for (; i > 0; i--, w++) {
      /* TODO stm_release */
      //if (w->addr == NULL)
        //continue;
      if (w->next == NULL) {
        /* Only drop lock for last covered address in write set */
        ATOMIC_STORE(w->lock, LOCK_SET_TIMESTAMP(w->version));
      }
    }
    /* Make sure that all lock releases become visible */
    ATOMIC_MB_WRITE;
  }
#else /* DESIGN == WRITE_BACK_CTL */
  if (tx->w_set.nb_entries != 0) {
    memset(tx->w_set.hash_table, 0, tx->w_set.size * sizeof(*tx->w_set.hash_table));
  }
  if (tx->w_set.nb_acquired > 0) {
    w = tx->w_set.entries + tx->w_set.nb_entries;
    do {
      w--;
      if (!w->no_drop) {
        volatile stm_word_t *lock = GET_LOCK(w->addr);
        if (--tx->w_set.nb_acquired == 0) {
          /* Make sure that all lock releases become visible to other threads */
          ATOMIC_STORE_REL(lock, LOCK_SET_TIMESTAMP(w->version));
        } else {
          ATOMIC_STORE(lock, LOCK_SET_TIMESTAMP(w->version));
        }
      }
    } while (tx->w_set.nb_acquired > 0);
  }
#endif /* DESIGN == WRITE_BACK_CTL */

#if READ_SET == READ_SET_HASH_HOPSCOTCH
  hhashclear(&tx->r_set);
#elif READ_SET == READ_SET_HASH_LINEAR
  /* mark read set entries as free */
  if (tx->r_set.nb_entries != 0) {
    for (r_entry_t *e = tx->r_set.entries, *e_end = tx->r_set.entries + tx->r_set.size; e != e_end; ++e)
      if (e->lock != NULL)
        e->lock = NULL;
  }
#endif

#if CM == CM_MODULAR
 dropped:
#endif /* CM == CM_MODULAR */

#if CM == CM_MODULAR || defined(INTERNAL_STATS)
  tx->retries++;
#endif /* CM == CM_MODULAR || defined(INTERNAL_STATS) */
#ifdef INTERNAL_STATS
  tx->aborts++;
  if (tx->retries == 1)
    tx->aborts_1++;
  else if (tx->retries == 2)
    tx->aborts_2++;
  if (tx->max_retries < tx->retries)
    tx->max_retries = tx->retries;
#endif /* INTERNAL_STATS */

  /* Set status to ABORTED */
  SET_STATUS(tx->status, TX_ABORTED);

  /* Reset nesting level */
#if NESTING == NEST_FLATTENED
  tx->nesting = 1;
#endif /* NESTING == NEST_FLATTENED */

  /* Callbacks */
  if (nb_abort_cb != 0) {
    int cb;
    for (cb = 0; cb < nb_abort_cb; cb++)
      abort_cb[cb].f(TXARGS abort_cb[cb].arg);
  }

#if CM == CM_BACKOFF
  /* Simple RNG (good enough for backoff) */
  tx->seed ^= (tx->seed << 17);
  tx->seed ^= (tx->seed >> 13);
  tx->seed ^= (tx->seed << 5);
  wait = tx->seed % tx->backoff;
  for (j = 0; j < wait; j++) {
    /* Do nothing */
  }
  if (tx->backoff < MAX_BACKOFF)
    tx->backoff <<= 1;
#endif /* CM == CM_BACKOFF */

#if CM == CM_DELAY || CM == CM_MODULAR
  /* Wait until contented lock is free */
  if (tx->c_lock != NULL) {
    /* Busy waiting (yielding is expensive) */
    while (LOCK_GET_OWNED(ATOMIC_LOAD(tx->c_lock))) {
# ifdef WAIT_YIELD
      sched_yield();
# endif /* WAIT_YIELD */
    }
    tx->c_lock = NULL;
  }
#endif /* CM == CM_DELAY || CM == CM_MODULAR */

  /* TODO: what is the expected behavior of STM_ABORT_EXPLICIT? */
  /* Don't prepare a new transaction if no retry. */
  /* FIXME (by Clemens Hammacher, 10.7.2014): Just returning cannot be the solution here ;)
  if (tx->attr.no_retry || (reason & STM_ABORT_EXPLICIT) != 0) {
    tx->nesting = 0;
    return;
  }
  */

  /* Reset field to restart transaction */
  stm_prepare(tx);

  STOP_COLLECT_STATS(global_tx_stats.nanos_in_rollback);

  /* Jump back to transaction start */
  /* FIXME: not proper at all. it has to be changed. The value must be the one specified by the function. */
#if defined(TM_DTMC)
  /* Restore stack */
  tanger_stm_restore_stack();
  /* TODO if irrevocable + DTMC, can run uninstrumented */
#endif /* defined(TM_DTMC) */
#if defined(TM_DTMC) || defined(TM_GCC) || defined (TM_INTEL)
  siglongjmp(tx->env, 0x09); /* ABI 0x09 = runInstrumented + restoreLiveVariable */
#else /* !defined(TM_DTMC) && !defined(TM_GCC) && !defined (TM_INTEL) */
  siglongjmp(tx->env, reason);
#endif /* !defined(TM_DTMC) && !defined(TM_GCC) && !defined (TM_INTEL) */
}

/*
 * Load a word-sized value (invisible read).
 */
static inline stm_word_t stm_read_invisible(stm_tx_t *tx, volatile stm_word_t *addr)
{
  volatile stm_word_t *lock;
  stm_word_t l, l2, value, version;
#if DESIGN == WRITE_BACK_ETL
  w_entry_t *w;
#endif /* DESIGN == WRITE_BACK_ETL */
#if DESIGN == WRITE_BACK_CTL
  w_entry_t *written = NULL;
#endif /* DESIGN == WRITE_BACK_CTL */
#if CM == CM_MODULAR
  stm_word_t t;
  int decision;
#endif /* CM == CM_MODULAR */

  PRINT_DEBUG2("==> stm_read_invisible(%p[%lu-%lu],addr=%p,lock=%lx)\n", tx, (unsigned long)tx->start, (unsigned long)tx->end, addr, GET_LOCK(addr)-locks);

  assert (((uintptr_t)addr & (sizeof(stm_word_t) - 1)) == 0);

#if CM != CM_MODULAR
  assert(IS_ACTIVE(tx->status));
#endif /* CM != CM_MODULAR */

#if DESIGN == WRITE_BACK_CTL
  /* Did we previously write the same address? */
  written = stm_has_written(tx, addr);
  if (written != NULL) {
    /* Yes: get value from write set if possible */
    if (written->mask == ~(stm_word_t)0) {
      value = written->value;
      /* No need to add to read set */
      return value;
    }
  }
#endif /* DESIGN == WRITE_BACK_CTL */

  /* Get reference to lock */
  lock = GET_LOCK(addr);

  /* Note: we could check for duplicate reads and get value from read set */

  /* Read lock, value, lock */
 restart:
  l = ATOMIC_LOAD_ACQ(lock);
 restart_no_load:
  if (LOCK_GET_WRITE(l)) {
    /* Locked */
    if (l == LOCK_UNIT) {
      /* Data modified by a unit store: should not last long => retry */
      goto restart;
    }
    /* Do we own the lock? */
#if DESIGN == WRITE_THROUGH
    if (tx == (stm_tx_t *)LOCK_GET_ADDR(l)) {
      /* Yes: we have a version locked by us that was valid at write time */
      value = ATOMIC_LOAD(addr);
      /* No need to add to read set (will remain valid) */
      return value;
    }
#elif DESIGN == WRITE_BACK_ETL
    w = (w_entry_t *)LOCK_GET_ADDR(l);
    /* Simply check if address falls inside our write set (avoids non-faulting load) */
    if (tx->w_set.entries <= w && w < tx->w_set.entries + tx->w_set.nb_entries) {
      /* Yes: did we previously write the same address? */
      while (1) {
        if (addr == w->addr) {
          /* Yes: get value from write set (or from memory if mask was empty) */
          value = (w->mask == 0 ? ATOMIC_LOAD(addr) : w->value);
          break;
        }
        if (w->next == NULL) {
          /* No: get value from memory */
          value = ATOMIC_LOAD(addr);
# if CM == CM_MODULAR
          if (GET_STATUS(tx->status) == TX_KILLED) {
            stm_rollback(tx, STM_ABORT_KILLED);
            return 0;
          }
# endif
          break;
        }
        w = w->next;
      }
      /* No need to add to read set (will remain valid) */
      return value;
    }
#endif /* DESIGN == WRITE_BACK_ETL */
#if DESIGN == WRITE_BACK_CTL
    /* Spin while locked (should not last long) */
    goto restart;
#else /* DESIGN != WRITE_BACK_CTL */
    /* Conflict: CM kicks in (we could also check for duplicate reads and get value from read set) */
# if defined(IRREVOCABLE_ENABLED) && defined(IRREVOCABLE_IMPROVED)
    if (tx->irrevocable && ATOMIC_LOAD(&irrevocable) == 1)
      ATOMIC_STORE(&irrevocable, 2);
# endif /* defined(IRREVOCABLE_ENABLED) && defined(IRREVOCABLE_IMPROVED) */
# if CM != CM_MODULAR && defined(IRREVOCABLE_ENABLED)
    if(tx->irrevocable) {
      /* Spin while locked */
      goto restart;
    }
# endif /* CM != CM_MODULAR && defined(IRREVOCABLE_ENABLED) */
# if CM == CM_MODULAR
    t = w->tx->status;
    l2 = ATOMIC_LOAD_ACQ(lock);
    if (l != l2) {
      l = l2;
      goto restart_no_load;
    }
    if (t != w->tx->status) {
      /* Transaction status has changed: restart the whole procedure */
      goto restart;
    }
#  ifdef READ_LOCKED_DATA
#   ifdef IRREVOCABLE_ENABLED
    if (IS_ACTIVE(t) && !tx->irrevocable)
#   else /* ! IRREVOCABLE_ENABLED */
    if (GET_STATUS(t) == TX_ACTIVE)
#   endif /* ! IRREVOCABLE_ENABLED */
    {
      /* Read old version */
      version = ATOMIC_LOAD(&w->version);
      /* Read data */
      value = ATOMIC_LOAD(addr);
      /* Check that data has not been written */
      if (t != w->tx->status) {
        /* Data concurrently modified: a new version might be available => retry */
        goto restart;
      }
      if (version >= tx->start && (version <= tx->end || (!tx->ro && tx->can_extend && stm_extend(tx)))) {
      /* Success */
#  ifdef INTERNAL_STATS
        tx->locked_reads_ok++;
#  endif /* INTERNAL_STATS */
        goto add_to_read_set;
      }
      /* Invalid version: not much we can do => fail */
#  ifdef INTERNAL_STATS
      tx->locked_reads_failed++;
#  endif /* INTERNAL_STATS */
    }
#  endif /* READ_LOCKED_DATA */
    if (GET_STATUS(t) == TX_KILLED) {
      /* We can safely steal lock */
      decision = KILL_OTHER;
    } else {
      decision =
#  ifdef IRREVOCABLE_ENABLED
        GET_STATUS(tx->status) == TX_IRREVOCABLE ? KILL_OTHER :
        GET_STATUS(t) == TX_IRREVOCABLE ? KILL_SELF :
#  endif /* IRREVOCABLE_ENABLED */
        GET_STATUS(tx->status) == TX_KILLED ? KILL_SELF :
        (contention_manager != NULL ? contention_manager(tx, w->tx, WR_CONFLICT) : KILL_SELF);
      if (decision == KILL_OTHER) {
        /* Kill other */
        if (!stm_kill(tx, w->tx, t)) {
          /* Transaction may have committed or aborted: retry */
          goto restart;
        }
      }
    }
    if (decision == KILL_OTHER) {
      /* Steal lock */
      l2 = LOCK_SET_TIMESTAMP(w->version);
      if (ATOMIC_CAS_FULL(lock, l, l2) == 0)
        goto restart;
      l = l2;
      goto restart_no_load;
    }
    /* Kill self */
    if ((decision & DELAY_RESTART) != 0)
      tx->c_lock = lock;
# elif CM == CM_DELAY
    tx->c_lock = lock;
# endif /* CM == CM_DELAY */
    /* Abort */
# ifdef INTERNAL_STATS
    tx->aborts_locked_read++;
# endif /* INTERNAL_STATS */
# ifdef CONFLICT_TRACKING
    if (conflict_cb != NULL && l != LOCK_UNIT) {
      /* Call conflict callback */
#  if DESIGN == WRITE_THROUGH
      stm_tx_t *other = (stm_tx_t *)LOCK_GET_ADDR(l);
#  else /* DESIGN != WRITE_THROUGH */
      stm_tx_t *other = ((w_entry_t *)LOCK_GET_ADDR(l))->tx;
#  endif /* DESIGN != WRITE_THROUGH */
      conflict_cb(tx, other);
    }
# endif /* CONFLICT_TRACKING */
    stm_rollback(tx, STM_ABORT_RW_CONFLICT);
    return 0;
#endif /* DESIGN != WRITE_BACK_CTL */
  } else {
    /* Not locked */
    value = ATOMIC_LOAD_ACQ(addr);
    l2 = ATOMIC_LOAD_ACQ(lock);
    if (l != l2) {
      l = l2;
      goto restart_no_load;
    }
#ifdef IRREVOCABLE_ENABLED
    /* In irrevocable mode, no need check timestamp nor add entry to read set */
    if (tx->irrevocable)
      return value;
#endif /* IRREVOCABLE_ENABLED */
    /* Check timestamp */
#if CM == CM_MODULAR
    if (LOCK_GET_READ(l))
      version = ((w_entry_t *)LOCK_GET_ADDR(l))->version;
    else
      version = LOCK_GET_TIMESTAMP(l);
#else /* CM != CM_MODULAR */
    version = LOCK_GET_TIMESTAMP(l);
#endif /* CM != CM_MODULAR */
    /* Valid version? */
    if (version > tx->end) {
#ifdef IRREVOCABLE_ENABLED
      assert(!tx->irrevocable);
#endif /* IRREVOCABLE_ENABLED */
      /* No: try to extend first (except for read-only transactions: no read set) */
      if (tx->ro || !tx->can_extend || !stm_extend(tx)) {
        /* Not much we can do: abort */
#if CM == CM_MODULAR
        /* Abort caused by invisible reads */
        tx->visible_reads++;
#endif /* CM == CM_MODULAR */
#ifdef INTERNAL_STATS
        tx->aborts_validate_read++;
#endif /* INTERNAL_STATS */
        stm_rollback(tx, STM_ABORT_VAL_READ);
        return 0;
      }
      /* Verify that version has not been overwritten (read value has not
       * yet been added to read set and may have not been checked during
       * extend) */
      l = ATOMIC_LOAD_ACQ(lock);
      if (l != l2) {
        l = l2;
        goto restart_no_load;
      }
      /* Worked: we now have a good version (version <= tx->end) */
    }
#if CM == CM_MODULAR
    /* Check if killed (necessary to avoid possible race on read-after-write) */
    if (GET_STATUS(tx->status) == TX_KILLED) {
      stm_rollback(tx, STM_ABORT_KILLED);
      return 0;
    }
#endif /* CM == CM_MODULAR */
  }
  /* We have a good version: add to read set (update transactions) and return value */

#if DESIGN == WRITE_BACK_CTL
  /* Did we previously write the same address? */
  if (written != NULL) {
    value = (value & ~written->mask) | (written->value & written->mask);
    /* Must still add to read set */
  }
#endif /* DESIGN == WRITE_BACK_CTL */
#ifdef READ_LOCKED_DATA
 add_to_read_set:
#endif /* READ_LOCKED_DATA */
  if (!tx->ro) {
    /* Add address and version to read set */
#if READ_SET == READ_SET_HASH_HOPSCOTCH
    if (!hhashcontains(&tx->r_set, lock - locks))
      hhashput(&tx->r_set, lock - locks, version);
#else
# if READ_SET == READ_SET_HASH_LINEAR
    if (tx->r_set.nb_entries == tx->r_set.fill_threshold)
      stm_allocate_rs_entries(tx, 1);
    r_entry_t *r = &tx->r_set.entries[HASH_LOCK(lock, tx->r_set.size)];
    r_entry_t *end = tx->r_set.entries + tx->r_set.size;
    while (r->lock) {
      // already taken. linear probing to find next free entry.
      if (r->lock == lock)
        return value;
      if (++r == end)
        r = tx->r_set.entries;
    }
    ++tx->r_set.nb_entries;
# else /* READ_SET_DUPLICATES or READ_SET_LINEAR_SCAN */
    if (tx->r_set.nb_entries == tx->r_set.size)
      stm_allocate_rs_entries(tx, 1);
#  if READ_SET == READ_SET_LINEAR_SCAN
    for (r_entry_t *r = tx->r_set.entries, *end = tx->r_set.entries + tx->r_set.size; r != end; ++r)
      if (r->lock == lock)
        return value;
#  endif /* READ_SET_LINEAR_SCAN */
    r_entry_t *r = &tx->r_set.entries[tx->r_set.nb_entries++];
# endif /* READ_SET_DUPLICATES or READ_SET_LINEAR_SCAN */
    r->version = version;
    r->lock = lock;
#endif /* ! READ_SET_HASH_HOPSCOTCH */
  }
  return value;
}

#if CM == CM_MODULAR
/*
 * Load a word-sized value (visible read).
 */
static inline stm_word_t stm_read_visible(stm_tx_t *tx, volatile stm_word_t *addr)
{
  volatile stm_word_t *lock;
  stm_word_t l, l2, t, value, version;
  w_entry_t *w;
  int decision;

  PRINT_DEBUG2("==> stm_read_visible(%p[%lu-%lu],addr=%p)\n", tx, (unsigned long)tx->start, (unsigned long)tx->end, addr);

  if (GET_STATUS(tx->status) == TX_KILLED) {
    stm_rollback(tx, STM_ABORT_KILLED);
    return 0;
  }

  /* Get reference to lock */
  lock = GET_LOCK(addr);

  /* Try to acquire lock */
 restart:
  l = ATOMIC_LOAD_ACQ(lock);
 restart_no_load:
  if (LOCK_GET_OWNED(l)) {
    /* Locked */
    if (l == LOCK_UNIT) {
      /* Data modified by a unit store: should not last long => retry */
      goto restart;
    }
    /* Do we own the lock? */
    w = (w_entry_t *)LOCK_GET_ADDR(l);
    /* Simply check if address falls inside our write set (avoids non-faulting load) */
    if (tx->w_set.entries <= w && w < tx->w_set.entries + tx->w_set.nb_entries) {
      /* Yes: is it only read-locked? */
      if (!LOCK_GET_WRITE(l)) {
        /* Yes: get value from memory */
        value = ATOMIC_LOAD(addr);
      } else {
        /* No: did we previously write the same address? */
        while (1) {
          if (addr == w->addr) {
            /* Yes: get value from write set (or from memory if mask was empty) */
            value = (w->mask == 0 ? ATOMIC_LOAD(addr) : w->value);
            break;
          }
          if (w->next == NULL) {
            /* No: get value from memory */
            value = ATOMIC_LOAD(addr);
            break;
          }
          w = w->next;
        }
      }
      if (GET_STATUS(tx->status) == TX_KILLED) {
        stm_rollback(tx, STM_ABORT_KILLED);
        return 0;
      }
      /* No need to add to read set (will remain valid) */
      return value;
    }
    /* Conflict: CM kicks in */
# if defined(IRREVOCABLE_ENABLED) && defined(IRREVOCABLE_IMPROVED)
    if (tx->irrevocable && ATOMIC_LOAD(&irrevocable) == 1)
      ATOMIC_STORE(&irrevocable, 2);
# endif /* defined(IRREVOCABLE_ENABLED) && defined(IRREVOCABLE_IMPROVED) */
    t = w->tx->status;
    l2 = ATOMIC_LOAD_ACQ(lock);
    if (l != l2) {
      l = l2;
      goto restart_no_load;
    }
    if (t != w->tx->status) {
      /* Transaction status has changed: restart the whole procedure */
      goto restart;
    }
    if (GET_STATUS(t) == TX_KILLED) {
      /* We can safely steal lock */
      decision = KILL_OTHER;
    } else {
      decision =
# ifdef IRREVOCABLE_ENABLED
        GET_STATUS(tx->status) == TX_IRREVOCABLE ? KILL_OTHER :
        GET_STATUS(t) == TX_IRREVOCABLE ? KILL_SELF :
# endif /* IRREVOCABLE_ENABLED */
        GET_STATUS(tx->status) == TX_KILLED ? KILL_SELF :
        (contention_manager != NULL ? contention_manager(tx, w->tx, (LOCK_GET_WRITE(l) ? WR_CONFLICT : RR_CONFLICT)) : KILL_SELF);
      if (decision == KILL_OTHER) {
        /* Kill other */
        if (!stm_kill(tx, w->tx, t)) {
          /* Transaction may have committed or aborted: retry */
          goto restart;
        }
      }
    }
    if (decision == KILL_OTHER) {
      version = w->version;
      goto acquire;
    }
    /* Kill self */
    if ((decision & DELAY_RESTART) != 0)
      tx->c_lock = lock;
    /* Abort */
# ifdef INTERNAL_STATS
    tx->aborts_locked_read++;
# endif /* INTERNAL_STATS */
# ifdef CONFLICT_TRACKING
    if (conflict_cb != NULL && l != LOCK_UNIT) {
      /* Call conflict callback */
      stm_tx_t *other = ((w_entry_t *)LOCK_GET_ADDR(l))->tx;
      conflict_cb(tx, other);
    }
# endif /* CONFLICT_TRACKING */
    stm_rollback(tx, (LOCK_GET_WRITE(l) ? STM_ABORT_WR_CONFLICT : STM_ABORT_RR_CONFLICT));
    return 0;
  }
  /* Not locked */
  version = LOCK_GET_TIMESTAMP(l);
 acquire:
  /* Acquire lock (ETL) */
  if (tx->w_set.nb_entries == tx->w_set.size)
    stm_allocate_ws_entries(tx, 1);
  w = &tx->w_set.entries[tx->w_set.nb_entries];
  w->version = version;
  value = ATOMIC_LOAD(addr);
  if (ATOMIC_CAS_FULL(lock, l, LOCK_SET_ADDR_READ((stm_word_t)w)) == 0)
    goto restart;
  /* Add entry to write set */
  w->addr = addr;
  w->mask = 0;
  w->lock = lock;
  w->value = value;
  w->next = NULL;
  tx->w_set.nb_entries++;
  return value;
}
#endif /* CM == CM_MODULAR */

/*
 * Store a word-sized value (return write set entry or NULL).
 */
INLINE(static)
w_entry_t *stm_write(stm_tx_t *tx, volatile stm_word_t *addr, stm_word_t value, stm_word_t mask)
{
  volatile stm_word_t *lock;
  stm_word_t l, version;
  w_entry_t *w;
#if DESIGN == WRITE_BACK_ETL
  w_entry_t *prev = NULL;
#elif DESIGN == WRITE_THROUGH
  int duplicate = 0;
#endif /* DESIGN == WRITE_THROUGH */
#if CM == CM_MODULAR
  int decision;
  stm_word_t l2, t;
#endif /* CM == CM_MODULAR */

  PRINT_DEBUG2("==> stm_write(%p[%lu-%lu],addr=%p,lock=%lx,value=%p/%lu,mask=0x%lx)\n",
               tx, (unsigned long)tx->start, (unsigned long)tx->end, addr, GET_LOCK(addr)-locks, (void *)value, (unsigned long)value, (unsigned long)mask);

  assert (((uintptr_t)addr & (sizeof(stm_word_t) - 1)) == 0);

#if CM == CM_MODULAR
  if (GET_STATUS(tx->status) == TX_KILLED) {
    PRINT_DEBUG2("==>   status of tx %p is TX_KILLED\n", tx);
    stm_rollback(tx, STM_ABORT_KILLED);
    return NULL;
  }
#else /* CM != CM_MODULAR */
  assert(IS_ACTIVE(tx->status));
#endif /* CM != CM_MODULAR */

  if (tx->ro) {
    /* Disable read-only and abort */
    tx->attr.read_only = 0;
#ifdef INTERNAL_STATS
    tx->aborts_ro++;
#endif /* INTERNAL_STATS */
    stm_rollback(tx, STM_ABORT_RO_WRITE);
    return NULL;
    PRINT_DEBUG2("==>   tx %p has read-only set\n", tx);
  }

  /* Get reference to lock */
  lock = GET_LOCK(addr);

  /* Try to acquire lock */
 restart:
  l = ATOMIC_LOAD_ACQ(lock);
 restart_no_load:
  if (LOCK_GET_OWNED(l)) {
    /* Locked */
    if (l == LOCK_UNIT) {
      /* Data modified by a unit store: should not last long => retry */
      goto restart;
    }
    /* Do we own the lock? */
#if DESIGN == WRITE_THROUGH
    if (tx == (stm_tx_t *)LOCK_GET_ADDR(l)) {
      /* Yes */
# if WRITE_SET != WRITE_SET_DUPLICATES
      int i;
      /* Check if address is in write set (a lock may cover multiple addresses) */
      w = stm_has_written(tx, addr);
      if (w != NULL) {
        if (mask == 0)
          return w;
        if (w->mask == 0) {
          /* Remember old value */
          w->value = ATOMIC_LOAD(addr);
          w->mask = mask;
        } else {
          w->mask |= mask;
        }
        /* Yes: only write to memory */
        if (~mask != 0)
          value = (ATOMIC_LOAD(addr) & ~mask) | (value & mask);
        ATOMIC_STORE(addr, value);
        return w;
      }
# endif /* !WRITE_SET_DUPLICATES */
      /* Mark entry so that we do not drop the lock upon undo */
      duplicate = 1;
      /* Must add to write set (may add entry multiple times) */
      goto do_write;
    }
#elif DESIGN == WRITE_BACK_ETL
    w = (w_entry_t *)LOCK_GET_ADDR(l);
    /* Simply check if address falls inside our write set (avoids non-faulting load) */
    if (tx->w_set.entries <= w && w < tx->w_set.entries + tx->w_set.nb_entries) {
      /* Yes */
#if CM == CM_MODULAR
      /* If read-locked: upgrade lock */
      if (!LOCK_GET_WRITE(l)) {
        if (ATOMIC_CAS_FULL(lock, l, LOCK_UPGRADE(l)) == 0) {
          /* Lock must have been stolen: abort */
          PRINT_DEBUG2("==>   tx %p cannot upgrade lock %lx\n", tx, lock-locks);
          stm_rollback(tx, STM_ABORT_KILLED);
          return NULL;
        }
        ++tx->w_set.has_writes;
      }
#endif /* CM == CM_MODULAR */
      if (mask == 0) {
        /* No need to insert new entry or modify existing one */
        return w;
      }
      prev = w;
      /* Did we previously write the same address? */
      while (1) {
        if (addr == prev->addr) {
          /* No need to add to write set */
          if (~mask != 0) {
            if (prev->mask == 0)
              prev->value = ATOMIC_LOAD(addr);
            value = (prev->value & ~mask) | (value & mask);
          }
          prev->value = value;
          prev->mask |= mask;
          return prev;
        }
        if (prev->next == NULL) {
          /* Remember last entry in linked list (for adding new entry) */
          break;
        }
        prev = prev->next;
      }
      /* Get version from previous write set entry (all entries in linked list have same version) */
      version = prev->version;
      /* Must add to write set */
      if (tx->w_set.nb_entries == tx->w_set.size) {
        /* store a pointer to the old entry set, in order to recompute the prev pointer */
        w_entry_t *old_ws = tx->w_set.entries;
        stm_allocate_ws_entries(tx, 1);
        /* now recompute the prev pointer: */
        prev = tx->w_set.entries - old_ws + prev;
      }
      w = &tx->w_set.entries[tx->w_set.nb_entries];
# if CM == CM_MODULAR
      w->version = version;
# endif /* CM == CM_MODULAR */
      goto do_write;
    } /* end: we own the lock */
#endif /* DESIGN == WRITE_BACK_ETL */
#if DESIGN == WRITE_BACK_CTL
    /* Spin while locked (should not last long) */
    goto restart;
#else /* DESIGN != WRITE_BACK_CTL */
    /* Conflict: CM kicks in */
# if defined(IRREVOCABLE_ENABLED) && defined(IRREVOCABLE_IMPROVED)
    if (tx->irrevocable && ATOMIC_LOAD(&irrevocable) == 1)
      ATOMIC_STORE(&irrevocable, 2);
# endif /* defined(IRREVOCABLE_ENABLED) && defined(IRREVOCABLE_IMPROVED) */
# if CM != CM_MODULAR && defined(IRREVOCABLE_ENABLED)
    if (tx->irrevocable) {
      /* Spin while locked */
      goto restart;
    }
# endif /* CM != CM_MODULAR && defined(IRREVOCABLE_ENABLED) */
# if CM == CM_MODULAR
    t = w->tx->status;
    l2 = ATOMIC_LOAD_ACQ(lock);
    if (l != l2) {
      l = l2;
      goto restart_no_load;
    }
    if (t != w->tx->status) {
      /* Transaction status has changed: restart the whole procedure */
      goto restart;
    }
    if (GET_STATUS(t) == TX_KILLED) {
      /* We can safely steal lock */
      decision = KILL_OTHER;
    } else {
      decision =
# ifdef IRREVOCABLE_ENABLED
        GET_STATUS(tx->status) == TX_IRREVOCABLE ? KILL_OTHER :
        GET_STATUS(t) == TX_IRREVOCABLE ? KILL_SELF :
# endif /* IRREVOCABLE_ENABLED */
        GET_STATUS(tx->status) == TX_KILLED ? KILL_SELF :
        (contention_manager != NULL ? contention_manager(tx, w->tx, WW_CONFLICT) : KILL_SELF);
      if (decision == KILL_OTHER) {
        /* Kill other */
        if (!stm_kill(tx, w->tx, t)) {
          /* Transaction may have committed or aborted: retry */
          goto restart;
        }
      }
    }
    if (decision == KILL_OTHER) {
      /* Handle write after reads (before CAS) */
      version = w->version;
      goto acquire;
    }
    /* Kill self */
    if ((decision & DELAY_RESTART) != 0)
      tx->c_lock = lock;
# elif CM == CM_DELAY
    tx->c_lock = lock;
# endif /* CM == CM_DELAY */
    /* Abort */
# ifdef INTERNAL_STATS
    ++tx->aborts_locked_write;
# endif /* INTERNAL_STATS */
# ifdef CONFLICT_TRACKING
    if (conflict_cb != NULL && l != LOCK_UNIT) {
      /* Call conflict callback */
#  if DESIGN == WRITE_THROUGH
      stm_tx_t *other = (stm_tx_t *)LOCK_GET_ADDR(l);
#  else /* DESIGN != WRITE_THROUGH */
      stm_tx_t *other = ((w_entry_t *)LOCK_GET_ADDR(l))->tx;
#  endif /* DESIGN != WRITE_THROUGH */
      conflict_cb(tx, other);
    }
# endif /* CONFLICT_TRACKING */
# ifdef DEBUG2
#  if DESIGN == WRITE_THROUGH
    stm_tx_t *other = (stm_tx_t *)LOCK_GET_ADDR(l);
#  elif CM == CM_MODULAR || (defined(CONFLICT_TRACKING) && DESIGN != WRITE_THROUGH)
    stm_tx_t *other = ((w_entry_t *)LOCK_GET_ADDR(l))->tx;
#  else
    stm_tx_t *other = 0;
#  endif /* DESIGN != WRITE_THROUGH */
    PRINT_DEBUG2("==>   tx %p detected write conflict! lock %lx owned by tx %p\n", tx, lock-locks, other);
# endif /* DEBUG2 */
    stm_rollback(tx, STM_ABORT_WW_CONFLICT);
    return NULL;
#endif /* DESIGN != WRITE_BACK_CTL */
  }
  /* Not locked */
#if DESIGN == WRITE_BACK_CTL
  w = stm_has_written(tx, addr);
  if (w != NULL) {
    w->value = (w->value & ~mask) | (value & mask);
    w->mask |= mask;
    return w;
  }
#endif /* DESIGN == WRITE_BACK_CTL */
  /* Handle write after reads (before CAS) */
  version = LOCK_GET_TIMESTAMP(l);
#ifdef IRREVOCABLE_ENABLED
  /* In irrevocable mode, no need to revalidate */
  if (tx->irrevocable)
    goto acquire_no_check;
#endif /* IRREVOCABLE_ENABLED */
 acquire:
  if (version > tx->end) {
    /* We might have read an older version previously */
    if (!tx->can_extend || stm_has_read(tx, lock)) {
      /* Read version must be older (otherwise, tx->end >= version) */
      /* Not much we can do: abort */
#if CM == CM_MODULAR
      /* Abort caused by invisible reads */
      tx->visible_reads++;
#endif /* CM == CM_MODULAR */
#ifdef INTERNAL_STATS
      tx->aborts_validate_write++;
#endif /* INTERNAL_STATS */
      PRINT_DEBUG2("==>   tx %p detected write conflict! version number (%lu) is larger than tx end (%lu)\n", tx, version, tx->end);
      stm_rollback(tx, STM_ABORT_VAL_WRITE);
      return NULL;
    }
  }
  /* Acquire lock (ETL) */
#ifdef IRREVOCABLE_ENABLED
 acquire_no_check:
#endif /* IRREVOCABLE_ENABLED */
#if DESIGN == WRITE_THROUGH
  if (ATOMIC_CAS_FULL(lock, l, LOCK_SET_ADDR_WRITE((stm_word_t)tx)) == 0)
    goto restart;
#elif DESIGN == WRITE_BACK_ETL
  if (tx->w_set.nb_entries == tx->w_set.size)
    stm_allocate_ws_entries(tx, 1);
  w = &tx->w_set.entries[tx->w_set.nb_entries];
# if CM == CM_MODULAR
  w->version = version;
# endif /* if CM == CM_MODULAR */
  if (ATOMIC_CAS_FULL(lock, l, LOCK_SET_ADDR_WRITE((stm_word_t)w)) == 0)
    goto restart;
#endif /* DESIGN == WRITE_BACK_ETL */
  /* We own the lock here (ETL) */
do_write:
  /* Add address to write set */
#if DESIGN == WRITE_BACK_CTL
  assert (tx->w_set.nb_entries <= tx->w_set.fill_threshold);
  if (tx->w_set.nb_entries == tx->w_set.fill_threshold)
    stm_allocate_ws_entries(tx, 1);
  w = &tx->w_set.entries[tx->w_set.nb_entries++];
  w_entry_t **hash_table_entry = tx->w_set.hash_table + HASH_ADDR(addr, tx->w_set.size);
  w->next = *hash_table_entry;
  *hash_table_entry = w;
#elif DESIGN != WRITE_BACK_ETL
  if (tx->w_set.nb_entries == tx->w_set.size)
    stm_allocate_ws_entries(tx, 1);
  w = &tx->w_set.entries[tx->w_set.nb_entries++];
#endif /* DESIGN != WRITE_BACK_ETL */
  w->addr = addr;
  w->mask = mask;
  //w->lock = lock;
  if (mask == 0) {
    /* Do not write anything */
#ifndef NDEBUG
    w->value = 0;
#endif /* ! NDEBUG */
  } else
#if DESIGN == WRITE_THROUGH
  {
    /* Remember old value */
    w->value = ATOMIC_LOAD(addr);
  }
  /* We store the old value of the lock (timestamp and incarnation) */
  w->version = l;
  w->no_drop = duplicate;
  if (mask != 0) {
    if (mask != ~(stm_word_t)0)
      value = (w->value & ~mask) | (value & mask);
    ATOMIC_STORE(addr, value);
  }
#elif DESIGN == WRITE_BACK_ETL
  {
    /* Remember new value */
    if (~mask != 0)
      value = (ATOMIC_LOAD(addr) & ~mask) | (value & mask);
    w->value = value;
  }
# if CM != CM_MODULAR
  w->version = version;
# endif /* CM != CM_MODULAR */
  w->next = NULL;
  assert (!prev || (prev >= tx->w_set.entries && prev < tx->w_set.entries + tx->w_set.nb_entries));
  if (prev != NULL) {
    /* Link new entry in list */
    prev->next = w;
  }
  tx->w_set.nb_entries++;
  tx->w_set.has_writes++;
#else /* DESIGN == WRITE_BACK_CTL */
  {
    /* Remember new value */
    w->value = value;
  }
# ifndef NDEBUG
  w->version = version;
# endif
  w->no_drop = 1;
# ifdef USE_BLOOM_FILTER
  tx->w_set.bloom |= FILTER_BITS(addr) ;
# endif /* USE_BLOOM_FILTER */
#endif /* DESIGN == WRITE_BACK_CTL */

#ifdef IRREVOCABLE_ENABLED
  if (!tx->irrevocable && ATOMIC_LOAD_ACQ(&irrevocable)) {
    PRINT_DEBUG2("==>   tx %p is not irrevocable, but irrevocable is set!\n", tx);
    stm_rollback(tx, STM_ABORT_IRREVOCABLE);
    return NULL;
  }
#endif /* IRREVOCABLE_ENABLED */

  return w;
}

/*
 * Store a word-sized value in a unit transaction.
 */
static inline int stm_unit_write(volatile stm_word_t *addr, stm_word_t value, stm_word_t mask, stm_word_t *timestamp)
{
  volatile stm_word_t *lock;
  stm_word_t l;

  PRINT_DEBUG2("==> stm_unit_write(a=%p,d=%p-%lu,m=0x%lx)\n",
               addr, (void *)value, (unsigned long)value, (unsigned long)mask);

  /* Get reference to lock */
  lock = GET_LOCK(addr);

  /* Try to acquire lock */
 restart:
  l = ATOMIC_LOAD_ACQ(lock);
  if (LOCK_GET_OWNED(l)) {
    /* Locked: wait until lock is free */
#ifdef WAIT_YIELD
    sched_yield();
#endif /* WAIT_YIELD */
    goto restart;
  }
  /* Not locked */
  if (timestamp != NULL && LOCK_GET_TIMESTAMP(l) > *timestamp) {
    /* Return current timestamp */
    *timestamp = LOCK_GET_TIMESTAMP(l);
    return 0;
  }
  /* TODO: would need to store thread ID to be able to kill it (for wait freedom) */
  if (ATOMIC_CAS_FULL(lock, l, LOCK_UNIT) == 0)
    goto restart;
  ATOMIC_STORE(addr, value);
  /* Update timestamp with newer value (may exceed VERSION_MAX by up to MAX_THREADS) */
  l = FETCH_INC_CLOCK + 1;
  if (timestamp != NULL)
    *timestamp = l;
  /* Make sure that lock release becomes visible */
  ATOMIC_STORE_REL(lock, LOCK_SET_TIMESTAMP(l));
  if (l >= VERSION_MAX) {
    /* Block all transactions and reset clock (current thread is not in active transaction) */
    stm_quiesce_barrier(NULL, rollover_clock, NULL);
  }
  return 1;
}

#ifdef SIGNAL_HANDLER
/*
 * Catch signal (to emulate non-faulting load).
 */
static void signal_catcher(int sig)
{
  sigset_t block_signal;
  stm_tx_t *tx = stm_get_tx();

  /* A fault might only occur upon a load concurrent with a free (read-after-free) */
  PRINT_DEBUG("Caught signal: %d\n", sig);

  /* TODO: TX_KILLED should be also allowed */
  if (tx == NULL || tx->attr.no_retry || GET_STATUS(tx->status) != TX_ACTIVE) {
    /* There is not much we can do: execution will restart at faulty load */
    fprintf(stderr, "Error: invalid memory accessed and no longjmp destination\n");
    exit(1);
  }

# ifdef INTERNAL_STATS
  tx->aborts_invalid_memory++;
# endif /* INTERNAL_STATS */

  /* Unblock the signal since there is no return to signal handler */
  sigemptyset(&block_signal);
  sigaddset(&block_signal, sig);
  pthread_sigmask(SIG_UNBLOCK, &block_signal, NULL);

  /* Will cause a longjmp */
  stm_rollback(tx, STM_ABORT_SIGNAL);
}
#endif /* SIGNAL_HANDLER */

static void stm_stats_add_tx(struct stm_tx *tx, int success) {
#ifdef COLLECT_TX_STATS
  if (success) {
    ATOMIC_FETCH_INC_FULL(&global_tx_stats.num_commits);
    STAT_ADD_TIME(tx->start_time, global_tx_stats.nanos_in_committed_tx);
  } else {
    ATOMIC_FETCH_INC_FULL(&global_tx_stats.num_incomplete);
    STAT_ADD_TIME(tx->start_time, global_tx_stats.nanos_in_incomplete_tx);
  }

# if READ_SET == READ_SET_HASH_HOPSCOTCH
  uint64_t read_entries = tx->r_set.m;
# else
  uint64_t read_entries = tx->r_set.nb_entries;
# endif
  ATOMIC_FETCH_ADD_FULL(&global_tx_stats.sum_readset, read_entries);
  uint64_t write_entries = tx->w_set.nb_entries;
  ATOMIC_FETCH_ADD_FULL(&global_tx_stats.sum_writeset, write_entries);

  // and add the per-tx stats to the global stats
  for (uint64_t *src = (uint64_t *)&tx->stats,
                *end = (uint64_t *)((void *)&tx->stats + sizeof(tx->stats)),
                *dst = (uint64_t *)&global_tx_stats.per_tx;
       src != end; ++src, ++dst)
    ATOMIC_FETCH_ADD_FULL(dst, *src);
#endif /* COLLECT_TX_STATS */
}

#ifdef PRINT_TX_STATS_ON_EXIT
static void stm_print_stats(int sig) {
  if (sig != 0) {
    if (ATOMIC_CAS_FULL(dumped_stats_on_signal, 0, 1)) {
      printf("dumping STATS after receiving signal %d\n", sig);

      // add stats of incomplete txs
      for (struct stm_tx **
               slot = running_txs,
             **end = slot + sizeof(running_txs) / sizeof(*running_txs);
           slot != end; ++slot) {
        struct stm_tx *tx = (struct stm_tx *)ATOMIC_LOAD((atomic_t *)slot);
        if (tx)
          stm_stats_add_tx(tx, 0);
      }
    } else {
      printf("suppressed re-dumping STATS after receiving signal %d\n", sig);
    }
  }

  STATS_DEFINE_CPUTIME(end_clock);
  STATS_GET_CPUTIME(end_clock);
  uint64_t overall_cpu_nanos =
      STATS_DIFF_CPUTIME_NANOS(clock_on_init, end_clock);

  uint64_t stm_commits = global_tx_stats.num_commits;
  uint64_t stm_rollbacks = global_tx_stats.num_rollbacks;
  uint64_t stm_incomplete = global_tx_stats.num_incomplete;
  uint64_t stm_runs = stm_commits + stm_rollbacks + stm_incomplete;
#define sum_to_avg(sum)                                                        \
  (global_tx_stats.sum == 0 ? 0 : (global_tx_stats.sum / stm_runs))
  double stm_avg_readsize = sum_to_avg(sum_readset);
  double stm_avg_writesize = sum_to_avg(sum_writeset);
  double stm_micros_in_committed_tx =
      1e-3 * global_tx_stats.nanos_in_committed_tx;
  double stm_micros_in_incomplete_tx =
      1e-3 * global_tx_stats.nanos_in_incomplete_tx;
  double stm_micros_in_init = 1e-3 * global_tx_stats.nanos_in_init;
  double stm_micros_in_commit = 1e-3 * global_tx_stats.nanos_in_commit;
  double stm_micros_in_rollback = 1e-3 * global_tx_stats.nanos_in_rollback;
  double stm_micros_in_rollbacked_code =
      1e-3 * global_tx_stats.nanos_in_rollbacked_code;
  double stm_micros_in_read = 1e-3 * global_tx_stats.per_tx.nanos_in_read;
  double stm_micros_in_write = 1e-3 * global_tx_stats.per_tx.nanos_in_write;
  double overall_cpu_micros = 1e-3 * overall_cpu_nanos;
  printf("\n"
         "STM config: " XSTR(COMPILE_FLAGS) "\n"
         "STATS: commits: %" PRIu64 "\n"
         "STATS: rollbacks: %" PRIu64 "\n"
         "STATS: incomplete: %" PRIu64 "\n"
         "STATS: avg read set: %.1f\n"
         "STATS: avg write set: %.1f\n"
         "STATS: micros in committed tx: %.2f\n"
         "STATS: micros in incomplete tx: %.2f\n"
         "STATS: micros in init: %.2f\n"
         "STATS: micros in read: %.2f\n"
         "STATS: micros in write: %.2f\n"
         "STATS: micros in commit: %.2f\n"
         "STATS: micros in rollback: %.2f\n"
         "STATS: micros in rollbacked tx: %.2f\n"
         "STATS: overall cpu micros: %.2f\n",
         stm_commits, stm_rollbacks, stm_incomplete, stm_avg_readsize,
         stm_avg_writesize, stm_micros_in_committed_tx,
         stm_micros_in_incomplete_tx, stm_micros_in_init, stm_micros_in_read,
         stm_micros_in_write, stm_micros_in_commit, stm_micros_in_rollback,
         stm_micros_in_rollbacked_code, overall_cpu_micros);
  fflush(stdout);

  if (sig != 0) {
    // find previous signal handler
    stm_stats_oldsigaction_t *saved = stm_old_handlers;
    for (stm_stats_oldsigaction_t *end =
             stm_old_handlers +
             sizeof(stm_old_handlers) / sizeof(*stm_old_handlers);
         saved->signal == sig; ++saved) {
      if (saved == end) {
        fprintf(stderr, "missing old sigaction handler");
        abort();
      }
    }

    // restore this handler
    if (sigaction(sig, &saved->old_handler, NULL) < 0) {
      perror("sigaction");
      exit(1);
    }
    saved->signal = 0;

    // re-raise signal
    raise(sig);
  }
}
#endif /* PRINT_TX_STATS_ON_EXIT */

/* ################################################################### *
 * STM FUNCTIONS
 * ################################################################### */

/*
 * Called once (from main) to initialize STM infrastructure.
 */
void stm_init()
{
#if CM == CM_MODULAR
  char *s;
#endif /* CM == CM_MODULAR */
#ifdef SIGNAL_HANDLER
#endif /* SIGNAL_HANDLER */

  PRINT_DEBUG("==> stm_init()\n");

  if (initialized)
    return;

  PRINT_DEBUG("\tsizeof(word)=%d\n", (int)sizeof(stm_word_t));

  PRINT_DEBUG("\tVERSION_MAX=0x%lx\n", (unsigned long)VERSION_MAX);

  COMPILE_TIME_ASSERT(sizeof(stm_word_t) == sizeof(void *));
  COMPILE_TIME_ASSERT(sizeof(stm_word_t) == sizeof(atomic_t));

#ifdef EPOCH_GC
  gc_init(stm_get_clock);
#endif /* EPOCH_GC */

  memset((void *)locks, 0, LOCK_ARRAY_SIZE * sizeof(stm_word_t));

#if CM == CM_MODULAR
  s = getenv(VR_THRESHOLD);
  if (s != NULL)
    vr_threshold = (int)strtol(s, NULL, 10);
  else
    vr_threshold = VR_THRESHOLD_DEFAULT;
  PRINT_DEBUG("\tVR_THRESHOLD=%d\n", vr_threshold);
#endif /* CM == CM_MODULAR */

  CLOCK = 0;
  stm_quiesce_init();

#ifndef TLS
  if (pthread_key_create(&thread_tx, NULL) != 0) {
    fprintf(stderr, "Error creating thread local\n");
    exit(1);
  }
#endif /* ! TLS */

#ifdef SIGNAL_HANDLER
  if (getenv(NO_SIGNAL_HANDLER) == NULL) {
    /* Catch signals for non-faulting load */
    struct sigaction act;
    act.sa_handler = signal_catcher;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    if (sigaction(SIGBUS, &act, NULL) < 0 || sigaction(SIGSEGV, &act, NULL) < 0) {
      perror("sigaction");
      exit(1);
    }
  }
#endif /* SIGNAL_HANDLER */
  stm_reset_timings();
#ifdef PRINT_TX_STATS_ON_EXIT
  struct sigaction act;
  act.sa_handler = stm_print_stats;
  act.sa_flags = 0;
  sigemptyset(&act.sa_mask);
  int tx_dump_sigs[] = {SIGTERM, SIGABRT, SIGSEGV};
  for (int *i = tx_dump_sigs,
           *e = i + sizeof(tx_dump_sigs) / sizeof(*tx_dump_sigs);
       i != e; ++i) {
    stm_stats_oldsigaction_t *freeSlot = stm_old_handlers;
    for (stm_stats_oldsigaction_t *lastSlot =
             stm_old_handlers +
             sizeof(stm_old_handlers) / sizeof(*stm_old_handlers);
         freeSlot->signal != 0; ++freeSlot) {
      if (freeSlot == lastSlot) {
        fprintf(stderr, "no free sigaction slot\n");
        abort();
      }
    }

    if (sigaction(*i, &act, &freeSlot->old_handler) < 0) {
      perror("sigaction");
      exit(1);
    }
    freeSlot->signal = *i;
  }
#endif /* PRINT_TX_STATS_ON_EXIT */

#ifdef ADAPTIVE_READ_WRITE_SET_SIZE
  // this is REALLY quick and dirty, and just a proof of concept...
  extern const char *__progname;

  char filename[1024];
  strcpy(filename, getenv("HOME"));
  strcat(filename, "/.stm_estimated_set_");
  strcat(filename, __progname);
  FILE *fh = fopen(filename, "r");
  if (fh == NULL) {
    // fprintf(stderr, "cannot open file %s\n", filename);
  } else {
    int read =
        fscanf(fh, "%lu %lu", &estimated_read_size, &estimated_write_size);
    if (read == 2) {
      /* fprintf(stderr, "read estimated read/write set sizes: %lu, %lu\n",
              estimated_read_size, estimated_write_size); */
    } else {
      fprintf(stderr, "only read %d items from %s, expected 2.\n", read,
              filename);
    }
    fclose(fh);
  }
#endif /* ADAPTIVE_READ_WRITE_SET_SIZE */

  initialized = 1;
}

/*
 * Called once (from main) to clean up STM infrastructure.
 */
void stm_exit()
{
  PRINT_DEBUG("==> stm_exit()\n");

#ifdef COLLECT_TX_STATS
# ifdef PRINT_TX_STATS_ON_EXIT
  stm_print_stats(0);
# endif
# ifdef __APPLE__
  mach_port_deallocate(mach_task_self(), cclock);
# endif /* __APPLE__ */
#endif
  stm_reset_timings();

#ifndef TLS
  pthread_key_delete(thread_tx);
#endif /* ! TLS */
  stm_quiesce_exit();

#ifdef EPOCH_GC
  gc_exit();
#endif /* EPOCH_GC */

#ifdef ADAPTIVE_READ_WRITE_SET_SIZE
  // this is REALLY quick and dirty, and just a proof of concept...
  extern const char *__progname;

  char filename[1024];
  strcpy(filename, getenv("HOME"));
  strcat(filename, "/.stm_estimated_set_");
  strcat(filename, __progname);
  FILE *fh = fopen(filename, "w");
  if (fh == NULL) {
    fprintf(stderr, "cannot open file %s\n", filename);
  } else {
    fprintf(fh, "%lu %lu\n", estimated_read_size, estimated_write_size);
    /* fprintf(stderr, "wrote estimated read/write set sizes: %lu, %lu\n",
            estimated_read_size, estimated_write_size); */
    fclose(fh);
  }
#endif /* ADAPTIVE_READ_WRITE_SET_SIZE */
}

static size_t nextPowTwo(size_t val) {
  val -= 1;
  val |= val >> 1;
  val |= val >> 2;
  val |= val >> 4;
  val |= val >> 8;
  val |= val >> 16;
  COMPILE_TIME_ASSERT(sizeof(size_t) == 4 || sizeof(size_t) == 8);
  if (sizeof(size_t) == 8)
      val |= val >> 32;
  return val + 1;
}

/*
 * For internal use only!
 */
static stm_tx_t *init_tx(stm_tx_t *tx) {
  if (tx) {
    assert (!IS_ACTIVE(tx->status));
    // TODO try how the runtime is affected if we reuse the read/write set and hashtable
    memset(tx, 0, sizeof(stm_tx_t));
  } else {
    tx = (stm_tx_t *)calloc(1, sizeof(stm_tx_t));
    PRINT_DEBUG("==>  allocated new tx: %p\n", tx);
    if (!tx) {
        perror("calloc tx");
        exit(1);
    }
  }
  assert (TX_IDLE == 0); // zeroing out leads to TX_IDLE

#ifdef ADAPTIVE_READ_WRITE_SET_SIZE
  size_t est_read_size = ATOMIC_LOAD(&estimated_read_size) * 5 / 4;
  size_t est_write_size = ATOMIC_LOAD(&estimated_write_size) * 5 / 4;
  // find power of two (>= 4)
  size_t read_size = nextPowTwo(est_read_size | 4);
  size_t write_size = nextPowTwo(est_write_size | 4);
# if DESIGN == WRITE_BACK_CTL
  if (WRITE_FILL_THRESHOLD(write_size) < est_write_size)
    write_size *= 2;
  assert (WRITE_FILL_THRESHOLD(write_size) >= est_write_size);
# endif
# if READ_SET == READ_SET_HASH_LINEAR
  if (READ_FILL_THRESHOLD(read_size) < est_read_size)
    read_size *= 2;
  assert (READ_FILL_THRESHOLD(read_size) >= est_read_size);
# endif
#else
  size_t read_size = RW_SET_SIZE;
  size_t write_size = RW_SET_SIZE;
#endif

  /* Read set */
#if READ_SET == READ_SET_HASH_HOPSCOTCH
  hhashnew(&tx->r_set, read_size);
#else
  tx->r_set.size = read_size;
  stm_allocate_rs_entries(tx, 0);
#endif

  /* Write set */
  tx->w_set.size = write_size;
  stm_allocate_ws_entries(tx, 0);

#ifdef CONFLICT_TRACKING
  /* Thread identifier */
  tx->thread_id = pthread_self();
#endif /* CONFLICT_TRACKING */
#if CM == CM_BACKOFF
  /* Backoff */
  tx->backoff = MIN_BACKOFF;
  tx->seed = 123456789UL;
#endif /* CM == CM_BACKOFF */

  /* Store as thread-local data */
#ifdef TLS
  thread_tx = tx;
#else /* ! TLS */
  pthread_setspecific(thread_tx, tx);
#endif /* ! TLS */

  stm_quiesce_enter_thread(tx);

  stm_add_running_tx(tx);

  /* Callbacks */
  if (nb_init_cb != 0) {
    int cb;
    for (cb = 0; cb < nb_init_cb; cb++)
      init_cb[cb].f(TXARGS init_cb[cb].arg);
  }

  return tx;
}

/*
 * Called by the CURRENT thread to initialize thread-local STM data.
 */
void stm_init_thread()
{
  PRINT_DEBUG("==> stm_init_thread(thread=%ux)\n", (unsigned int)pthread_self());

#ifdef EPOCH_GC
  gc_init_thread();
#endif /* EPOCH_GC */
}

/*
 * Called by the CURRENT thread to cleanup thread-local STM data.
 */
void stm_exit_thread()
{
#ifdef EPOCH_GC
  stm_word_t t;
#endif /* EPOCH_GC */

  PRINT_DEBUG("==> stm_exit_thread(thread=%ux)\n", (unsigned int)pthread_self());

  /* Callbacks */
  struct stm_tx *tx = 0;
  if (nb_exit_cb != 0) {
    int cb;
    for (cb = 0; cb < nb_exit_cb; cb++)
      exit_cb[cb].f(TXARGS exit_cb[cb].arg);
  }

  stm_quiesce_exit_thread(tx);

#ifdef EPOCH_GC
  t = GET_CLOCK;
  //gc_free(tx, t);
  gc_exit_thread();
#else /* ! EPOCH_GC */
  //free(tx);
#endif /* ! EPOCH_GC */

#ifdef TLS
  thread_tx = NULL;
#else /* ! TLS */
  pthread_setspecific(thread_tx, NULL);
#endif /* ! TLS */
}

/*
 * Called by the CURRENT thread to start a transaction.
 */
TXTYPE stm_start(stm_tx_attr_t *attr) {
  START_COLLECT_STATS;

  /* Clemens, 29.1.2013: Do always allocate a new transaction. In tbb, the same thread
   * might execute another task while waiting for commit dependences, so in this case it
   * would be illegal to reuse the "thread tx".
   */
  struct stm_tx *tx = init_tx(NULL);

  PRINT_DEBUG("==> stm_start(%p)\n", tx);

#if NESTING == NEST_FLATTENED
  /* Increment nesting level */
  if (tx->nesting++ > 0) {
    TX_RETURN
  }
#elif NESTING == NEST_CLOSED
  if (IS_ACTIVE(tx->status)) {
    /* start a new transaction with the active one as parent */
# ifdef EXPLICIT_TX_PARAMETER
    // TODO this can't work at all. several places store pointers to the transaction.
    //      moving it to a different memory location is illegal.
    stm_tx_t *oldTx;
    if (!(oldTx = (stm_tx_t *)malloc(sizeof(stm_tx_t)))) {
      perror("malloc tx");
      exit(1);
    }
    memcpy(oldTx, tx, sizeof(stm_tx_t));
    init_tx(tx);
    tx->parent = oldTx;
# else /* ! EXPLICIT_TX_PARAMETER */
    stm_tx_t *newTx = init_tx(NULL);
    newTx->parent = tx;
    tx = newTx;
#  ifdef TLS
    thread_tx = tx;
#  else /* ! TLS */
    pthread_setspecific(thread_tx, tx);
#  endif /* ! TLS */
# endif /* ! EXPLICIT_TX_PARAMETER */
  }
#endif /* NESTING == NEST_CLOSED */

  /* Attributes */
  tx->attr = (attr == NULL ? default_attributes : *attr);
  tx->ro = tx->attr.read_only; /* TODO ro is a duplicate attribute */

  /* Initialize transaction descriptor */
  stm_prepare(tx);

  /* TODO: verify that mod_* deal with the new specification of stm_start (called only once per tx) */
  /* Callbacks */
  if (nb_start_cb != 0) {
    int cb;
    for (cb = 0; cb < nb_start_cb; cb++)
      start_cb[cb].f(TXARGS start_cb[cb].arg);
  }

  STOP_COLLECT_STATS(global_tx_stats.nanos_in_init);

  TX_RETURN
}

/* Helper function, used from stm_commit_tx to determine the end of it's stack frame.
   This is the same as the base of this (called) function. */
static char *get_frame_end_pointer() {
  return __builtin_frame_address(0);
}


int stm_commit_tx(struct stm_tx *tx) {
  w_entry_t *w;
  stm_word_t t;
  int i;
#if DESIGN == WRITE_BACK_CTL
  stm_word_t l, value;
#endif /* DESIGN == WRITE_BACK_CTL */

  START_COLLECT_STATS;

  PRINT_DEBUG("==> stm_commit(%p[%lu-%lu])\n", tx, (unsigned long)tx->start, (unsigned long)tx->end);

#if NESTING == NEST_FLATTENED
  /* Decrement nesting level */
  if (--tx->nesting > 0) {
    PRINT_DEBUG("==> stm_committed(%p[%lu-%lu],nesting=%d)\n", tx, (unsigned long)tx->start, (unsigned long)tx->end, tx->nesting+1);
    STOP_COLLECT_STATS(global_tx_stats.nanos_in_commit);
    return 1;
  }
#endif /* NESTING == FLATTENED */

  /* Callbacks */
  if (nb_precommit_cb != 0) {
    int cb;
    for (cb = 0; cb < nb_precommit_cb; cb++)
      precommit_cb[cb].f(TXARGS precommit_cb[cb].arg);
  }

  assert(IS_ACTIVE(tx->status));
#if CM == CM_MODULAR
  /* Set status to COMMITTING */
  t = tx->status;
  if (GET_STATUS(t) == TX_KILLED || ATOMIC_CAS_FULL(&tx->status, t, t + (TX_COMMITTING - GET_STATUS(t))) == 0) {
    /* We have been killed */
    assert(GET_STATUS(tx->status) == TX_KILLED);
    STOP_COLLECT_STATS(global_tx_stats.nanos_in_commit);
    stm_rollback(tx, STM_ABORT_KILLED);
    return 0;
  }
#endif /* CM == CM_MODULAR */

  /* A read-only transaction can commit immediately */
  if (tx->w_set.nb_entries == 0)
    goto end;

#if CM == CM_MODULAR
  /* A read-only transaction with visible reads must simply drop locks */
  /* FIXME: if killed? */
  if (tx->w_set.has_writes == 0) {
    w = tx->w_set.entries;
    for (i = tx->w_set.nb_entries; i > 0; i--, w++) {
      /* Only drop lock for last covered address in write set */
      if (w->next == NULL)
        ATOMIC_STORE_REL(w->lock, LOCK_SET_TIMESTAMP(w->version));
    }
    /* Update clock so that future transactions get higher timestamp (liveness of timestamp CM) */
    FETCH_INC_CLOCK;
    goto end;
  }
#endif /* CM == CM_MODULAR */

  /* Update transaction */
#if DESIGN == WRITE_BACK_CTL
# ifdef IRREVOCABLE_ENABLED
  /* Verify already if there is an irrevocable transaction before acquiring locks */
  if(!tx->irrevocable && ATOMIC_LOAD(&irrevocable)) {
    STOP_COLLECT_STATS(global_tx_stats.nanos_in_commit);
    stm_rollback(tx, STM_ABORT_IRREVOCABLE);
    return 0;
  }
# endif /* IRREVOCABLE_ENABLED */
  /* Acquire locks (in reverse order) */
  w = tx->w_set.entries + tx->w_set.nb_entries;
  do {
    w--;
    /* Try to acquire lock */
 restart:
    l = ATOMIC_LOAD(GET_LOCK(w->addr));
    if (LOCK_GET_OWNED(l)) {
      /* Do we already own the lock? */
      if (tx->w_set.entries <= (w_entry_t *)LOCK_GET_ADDR(l) && (w_entry_t *)LOCK_GET_ADDR(l) < tx->w_set.entries + tx->w_set.nb_entries) {
        /* Yes: ignore */
        continue;
      }
      /* Conflict: CM kicks in */
# if CM == CM_DELAY
      tx->c_lock = w->lock;
# endif /* CM == CM_DELAY */
      /* Abort self */
# ifdef INTERNAL_STATS
      tx->aborts_locked_write++;
# endif /* INTERNAL_STATS */
      stm_rollback(tx, STM_ABORT_WW_CONFLICT);
      return 0;
    }
    if (ATOMIC_CAS_FULL(GET_LOCK(w->addr), l, LOCK_SET_ADDR_WRITE((stm_word_t)w)) == 0)
      goto restart;
    /* We own the lock here */
    w->no_drop = 0;
    /* Store version for validation of read set */
    w->version = LOCK_GET_TIMESTAMP(l);
    tx->w_set.nb_acquired++;
  } while (w > tx->w_set.entries);
#endif /* DESIGN == WRITE_BACK_CTL */

#ifdef IRREVOCABLE_ENABLED
  /* Verify if there is an irrevocable transaction once all locks have been acquired */
# ifdef IRREVOCABLE_IMPROVED
  /* FIXME: it is bogus. the status should be changed to idle otherwise stm_quiesce will not progress */
  if (!tx->irrevocable) {
    do {
      t = ATOMIC_LOAD(&irrevocable);
      /* If the irrevocable transaction have encountered an acquired lock, abort */
      if (t == 2) {
        STOP_COLLECT_STATS(global_tx_stats.nanos_in_commit);
        stm_rollback(tx, STM_ABORT_IRREVOCABLE);
        return 0;
      }
    } while (t);
  }
# else /* ! IRREVOCABLE_IMPROVED */
  if (!tx->irrevocable && ATOMIC_LOAD(&irrevocable)) {
    STOP_COLLECT_STATS(global_tx_stats.nanos_in_commit);
    stm_rollback(tx, STM_ABORT_IRREVOCABLE);
    return 0;
  }
# endif /* ! IRREVOCABLE_IMPROVED */
#endif /* IRREVOCABLE_ENABLED */
  /* Get commit timestamp (may exceed VERSION_MAX by up to MAX_THREADS) */
  t = FETCH_INC_CLOCK + 1;
#ifdef IRREVOCABLE_ENABLED
  if (tx->irrevocable)
    goto release_locks;
#endif /* IRREVOCABLE_ENABLED */

  /* Try to validate (only if a concurrent transaction has committed since tx->start) */
  int revalidate = tx->start != t - 1;
  if (revalidate) {
    STOP_COLLECT_STATS(global_tx_stats.nanos_in_commit);
    if (!stm_validate(tx)) {
      /* Cannot commit */
#if CM == CM_MODULAR
      /* Abort caused by invisible reads */
      tx->visible_reads++;
#endif /* CM == CM_MODULAR */
#ifdef INTERNAL_STATS
      tx->aborts_validate_commit++;
#endif /* INTERNAL_STATS */
      stm_rollback(tx, STM_ABORT_VALIDATE);
      return 0;
    }
    RESTART_COLLECT_STATS;
  }

  /* determine the location of the current stack frame.
   * it is not so easy to determine the end (downwards) of the frame, so just
   * protect one memory page (4k). this should suffice for the execution of this
   * function.
   */
  stm_word_t *frame_base = (stm_word_t*) __builtin_frame_address(0) + 2;
  stm_word_t *frame_end = frame_base - 4096 / sizeof(*frame_base);

#ifdef IRREVOCABLE_ENABLED
  release_locks:
#endif /* IRREVOCABLE_ENABLED */
#if DESIGN == WRITE_THROUGH
  /* Make sure that the updates become visible before releasing locks */
  ATOMIC_MB_WRITE;
  /* Drop locks and set new timestamp (traverse in reverse order) */
  w = tx->w_set.entries + tx->w_set.nb_entries - 1;
  for (i = tx->w_set.nb_entries; i > 0; i--, w--) {
    /* TODO stm_release */
    //if (w->addr == NULL)
      //continue;
    if (w->no_drop)
      continue;
    /* No need for CAS (can only be modified by owner transaction) */
    ATOMIC_STORE(w->lock, LOCK_SET_TIMESTAMP(t));
  }
  /* Make sure that all lock releases become visible */
  ATOMIC_MB_WRITE;
#elif DESIGN == WRITE_BACK_ETL
  /* Install new versions, drop locks and set new timestamp */
  w = tx->w_set.entries;
  for (i = tx->w_set.nb_entries; i > 0; i--, w++) {
    /* TODO stm_release */
    //if (w->addr == NULL)
      //continue;
    if (w->mask != 0 && (w->addr > frame_base || w->addr < frame_end))
      ATOMIC_STORE(w->addr, w->value);
    /* Only drop lock for last covered address in write set */
    if (w->next == NULL) {
# if CM == CM_MODULAR
      /* In case of visible read, reset lock to its previous timestamp */
      if (w->mask == 0)
        ATOMIC_STORE_REL(w->lock, LOCK_SET_TIMESTAMP(w->version));
      else
# endif /* CM == CM_MODULAR */
        ATOMIC_STORE_REL(w->lock, LOCK_SET_TIMESTAMP(t));
    }
  }
#else /* DESIGN == WRITE_BACK_CTL */
  /* Install new versions, drop locks and set new timestamp */
  w = tx->w_set.entries;
  for (i = tx->w_set.nb_entries; i > 0; i--, w++) {
    /* TODO stm_release */
    //if (w->addr == NULL)
      //continue;
    if (w->addr > frame_base || w->addr < frame_end) {
      if (w->mask == ~(stm_word_t)0) {
        ATOMIC_STORE(w->addr, w->value);
      } else if (w->mask != 0) {
        value = (ATOMIC_LOAD(w->addr) & ~w->mask) | (w->value & w->mask);
        ATOMIC_STORE(w->addr, value);
      }
    }
    /* Only drop lock for last covered address in write set (cannot be "no drop") */
    if (!w->no_drop)
      ATOMIC_STORE_REL(GET_LOCK(w->addr), LOCK_SET_TIMESTAMP(t));
  }
#endif /* DESIGN == WRITE_BACK_CTL */

 end:
#if CM == CM_MODULAR || defined(INTERNAL_STATS)
  tx->retries = 0;
#endif /* CM == CM_MODULAR || defined(INTERNAL_STATS) */

#if CM == CM_BACKOFF
  /* Reset backoff */
  tx->backoff = MIN_BACKOFF;
#endif /* CM == CM_BACKOFF */

#if CM == CM_MODULAR
  tx->visible_reads = 0;
  tx->vr = 0;
#endif /* CM == CM_MODULAR */

#ifdef HYBRID_ASF
  /* Reset to Hybrid mode */
  tx->software = 0;
#endif /* HYBRID_ASF */

#ifdef IRREVOCABLE_ENABLED
  if (tx->irrevocable) {
    ATOMIC_STORE(&irrevocable, 0);
    if ((tx->irrevocable & 0x08) != 0)
      stm_quiesce_release(tx);
    tx->irrevocable = 0;
  }
#endif /* IRREVOCABLE_ENABLED */

  /* Set status to COMMITTED */
  SET_STATUS(tx->status, TX_COMMITTED);

  /* Callbacks */
  if (nb_commit_cb != 0) {
    int cb;
    for (cb = 0; cb < nb_commit_cb; cb++)
      commit_cb[cb].f(TXARGS commit_cb[cb].arg);
  }

  /* Free the read and write set */
#if READ_SET == READ_SET_HASH_HOPSCOTCH
  hhashfree(&tx->r_set);
#else
  free(tx->r_set.entries);
#endif
  free(tx->w_set.entries);

#if DESIGN == WRITE_BACK_CTL
  /* Free the write hash tables */
  free(tx->w_set.hash_table);
#endif

#ifdef ADAPTIVE_READ_WRITE_SET_SIZE
  /* Update the estimated read/write sizes */
  while (1) {
    size_t last_read_est = ATOMIC_LOAD(&estimated_read_size);
#if READ_SET == READ_SET_HASH_HOPSCOTCH
    size_t num_read = tx->r_set.m;
#else
    size_t num_read = tx->r_set.nb_entries;
#endif
    size_t new_read_est = num_read < last_read_est
            ? (last_read_est * 15 + num_read) / 16
            : (last_read_est * 3 + num_read) / 4;
    if (last_read_est == new_read_est
        || ATOMIC_CAS_FULL(&estimated_read_size, last_read_est, new_read_est))
      break;
  }
  while (1) {
    size_t last_write_est = ATOMIC_LOAD(&estimated_write_size);
    size_t new_write_est = tx->w_set.nb_entries < last_write_est
            ? (last_write_est * 15 + tx->w_set.nb_entries) / 16
            : (last_write_est * 3 + tx->w_set.nb_entries) / 4;
    if (last_write_est == new_write_est
        || ATOMIC_CAS_FULL(&estimated_write_size, last_write_est, new_write_est))
      break;
  }
#endif

  PRINT_DEBUG("==> stm_committed(%p[%lu-%lu])\n", tx, (unsigned long)tx->start, (unsigned long)tx->end);

  STOP_COLLECT_STATS(global_tx_stats.nanos_in_commit);

  stm_stats_add_tx(tx, 1);

  // only free the tx after collecting the per-tx stats.
  // transactions are not reused, stm_start always allocates a new one.
  stm_remove_running_tx(tx);
  free(tx);

  return 1;
}

/*
 * Called by the CURRENT thread to commit a transaction.
 */
int stm_commit(TXPARAM) {
  TX_GET;

  return stm_commit_tx(tx);
}

/*
 * Called by the CURRENT thread to abort a transaction.
 */
NORETURN(void) stm_abort(TXPARAMS int reason)
{
  TX_GET;
  stm_rollback(tx, reason | STM_ABORT_EXPLICIT);
}

/*
 * Called by the CURRENT thread to load a word-sized value.
 */
stm_word_t stm_load(TXPARAMS volatile stm_word_t *addr)
{
  TX_GET;

  START_COLLECT_STATS;

  stm_word_t val;

#ifdef IRREVOCABLE_ENABLED
  if (unlikely(((tx->irrevocable & 0x08) != 0))) {
    /* Serial irrevocable mode: direct access to memory */
    val = ATOMIC_LOAD(addr);
    goto out;
  }
#endif /* IRREVOCABLE_ENABLED */
#if CM == CM_MODULAR
  if (unlikely((tx->vr))) {
    /* Use visible read */
    val = stm_read_visible(tx, addr);
    goto out;
  }
#endif /* CM == CM_MODULAR */
  val = stm_read_invisible(tx, addr);

out:
  STOP_COLLECT_STATS(tx->stats.nanos_in_read);

  return val;
}

/*
 * Called by the CURRENT thread to store a word-sized value.
 */
void stm_store(TXPARAMS volatile stm_word_t *addr, stm_word_t value)
{
  TX_GET;

  START_COLLECT_STATS;

#ifdef IRREVOCABLE_ENABLED
  if (unlikely(((tx->irrevocable & 0x08) != 0))) {
    /* Serial irrevocable mode: direct access to memory */
    ATOMIC_STORE(addr, value);
    goto out;
  }
#endif /* IRREVOCABLE_ENABLED */
  stm_write(tx, addr, value, ~(stm_word_t)0);

out:
  STOP_COLLECT_STATS(tx->stats.nanos_in_write);
}

/*
 * Called by the CURRENT thread to store part of a word-sized value.
 */
void stm_store2(TXPARAMS volatile stm_word_t *addr, stm_word_t value, stm_word_t mask)
{
  TX_GET;

  START_COLLECT_STATS;

#ifdef IRREVOCABLE_ENABLED
  if (unlikely(((tx->irrevocable & 0x08) != 0))) {
    /* Serial irrevocable mode: direct access to memory */
    if (~mask == 0)
      ATOMIC_STORE(addr, value);
    else
      ATOMIC_STORE(addr, (ATOMIC_LOAD(addr) & ~mask) | (value & mask));
    goto out;
  }
#endif /* IRREVOCABLE_ENABLED */
  stm_write(tx, addr, value, mask);

out:
  STOP_COLLECT_STATS(tx->stats.nanos_in_write);
}

/*
 * Called by the CURRENT thread to inquire about the status of a transaction.
 */
int stm_active(TXPARAM)
{
  TX_GET;
  assert (tx != NULL);
  return IS_ACTIVE(tx->status);
}

/*
 * Called by the CURRENT thread to inquire about the status of a transaction.
 */
int stm_aborted(TXPARAM)
{
  TX_GET;
  assert (tx != NULL);
  return (GET_STATUS(tx->status) == TX_ABORTED);
}

# ifdef IRREVOCABLE_ENABLED
/*
 * Called by the CURRENT thread to inquire about the status of a transaction.
 */
int stm_irrevocable(TXPARAM)
{
  TX_GET;
  assert (tx != NULL);
  return ((tx->irrevocable & 0x07) == 3);
}
# endif /* IRREVOCABLE_ENABLED */

/*
 * Called by the CURRENT thread to obtain an environment for setjmp/longjmp.
 */
sigjmp_buf *stm_get_env(TXPARAM)
{
  TX_GET;
  assert (tx != NULL);
  /* Only return environment for top-level transaction */
  assert (tx->nesting > 0);
  return tx->nesting == 1 ? &tx->env : NULL;
}

/*
 * Get transaction attributes.
 */
stm_tx_attr_t *stm_get_attributes(TXPARAM)
{
  TX_GET;

  return &tx->attr;
}

/*
 * Get transaction attributes from a specifc transaction.
 */
stm_tx_attr_t *stm_get_attributes_tx(struct stm_tx *tx)
{ 
  return &tx->attr;
}

/*
 * Return statistics about a thread/transaction.
 */
int stm_get_stats(TXPARAMS const char *name, void *val)
{
  TX_GET;
  assert (tx != NULL);

  if (strcmp("read_set_size", name) == 0) {
#if READ_SET == READ_SET_HASH_HOPSCOTCH
    *(unsigned int *)val = tx->r_set.n;
#else
    *(unsigned int *)val = tx->r_set.size;
#endif
    return 1;
  }
  if (strcmp("write_set_size", name) == 0) {
    *(unsigned int *)val = tx->w_set.size;
    return 1;
  }
  if (strcmp("read_set_nb_entries", name) == 0) {
#if READ_SET == READ_SET_HASH_HOPSCOTCH
    *(unsigned int *)val = tx->r_set.m;
#else
    *(unsigned int *)val = tx->r_set.nb_entries;
#endif
    return 1;
  }
  if (strcmp("write_set_nb_entries", name) == 0) {
    *(unsigned int *)val = tx->w_set.nb_entries;
    return 1;
  }
  if (strcmp("read_only", name) == 0) {
    *(unsigned int *)val = tx->ro;
    return 1;
  }
#ifdef INTERNAL_STATS
  if (strcmp("nb_aborts", name) == 0) {
    *(unsigned long *)val = tx->aborts;
    return 1;
  }
  if (strcmp("nb_aborts_1", name) == 0) {
    *(unsigned long *)val = tx->aborts_1;
    return 1;
  }
  if (strcmp("nb_aborts_2", name) == 0) {
    *(unsigned long *)val = tx->aborts_2;
    return 1;
  }
  if (strcmp("nb_aborts_ro", name) == 0) {
    *(unsigned long *)val = tx->aborts_ro;
    return 1;
  }
  if (strcmp("nb_aborts_locked_read", name) == 0) {
    *(unsigned long *)val = tx->aborts_locked_read;
    return 1;
  }
  if (strcmp("nb_aborts_locked_write", name) == 0) {
    *(unsigned long *)val = tx->aborts_locked_write;
    return 1;
  }
  if (strcmp("nb_aborts_validate_read", name) == 0) {
    *(unsigned long *)val = tx->aborts_validate_read;
    return 1;
  }
  if (strcmp("nb_aborts_validate_write", name) == 0) {
    *(unsigned long *)val = tx->aborts_validate_write;
    return 1;
  }
  if (strcmp("nb_aborts_validate_commit", name) == 0) {
    *(unsigned long *)val = tx->aborts_validate_commit;
    return 1;
  }
  if (strcmp("nb_aborts_invalid_memory", name) == 0) {
    *(unsigned long *)val = tx->aborts_invalid_memory;
    return 1;
  }
# if CM == CM_MODULAR
  if (strcmp("nb_aborts_killed", name) == 0) {
    *(unsigned long *)val = tx->aborts_killed;
    return 1;
  }
# endif /* CM == CM_MODULAR */
# ifdef READ_LOCKED_DATA
  if (strcmp("locked_reads_ok", name) == 0) {
    *(unsigned long *)val = tx->locked_reads_ok;
    return 1;
  }
  if (strcmp("locked_reads_failed", name) == 0) {
    *(unsigned long *)val = tx->locked_reads_failed;
    return 1;
  }
# endif /* READ_LOCKED_DATA */
  if (strcmp("max_retries", name) == 0) {
    *(unsigned long *)val = tx->max_retries;
    return 1;
  }
#endif /* INTERNAL_STATS */
  return 0;
}

/*
 * Return STM parameters.
 */
int stm_get_parameter(const char *name, void *val)
{
  if (strcmp("nesting", name) == 0) {
    *(const char **)val = nest_names[NESTING];
    return 1;
  }
  if (strcmp("contention_manager", name) == 0) {
    *(const char **)val = cm_names[CM];
    return 1;
  }
  if (strcmp("design", name) == 0) {
    *(const char **)val = design_names[DESIGN];
    return 1;
  }
  if (strcmp("initial_rw_set_size", name) == 0) {
    *(int *)val = RW_SET_SIZE;
    return 1;
  }
#if CM == CM_BACKOFF
  if (strcmp("min_backoff", name) == 0) {
    *(unsigned long *)val = MIN_BACKOFF;
    return 1;
  }
  if (strcmp("max_backoff", name) == 0) {
    *(unsigned long *)val = MAX_BACKOFF;
    return 1;
  }
#endif /* CM == CM_BACKOFF */
#if CM == CM_MODULAR
  if (strcmp("vr_threshold", name) == 0) {
    *(int *)val = vr_threshold;
    return 1;
  }
#endif /* CM == CM_MODULAR */
#ifdef COMPILE_FLAGS
  if (strcmp("compile_flags", name) == 0) {
    *(const char **)val = XSTR(COMPILE_FLAGS);
    return 1;
  }
#endif /* COMPILE_FLAGS */
  return 0;
}

/*
 * Set STM parameters.
 */
int stm_set_parameter(const char *name, void *val)
{
#if CM == CM_MODULAR
  int i;

  if (strcmp("cm_policy", name) == 0) {
    for (i = 0; cms[i].name != NULL; i++) {
      if (strcasecmp(cms[i].name, (const char *)val) == 0) {
        contention_manager = cms[i].f;
        return 1;
      }
    }
    return 0;
  }
  if (strcmp("cm_function", name) == 0) {
    contention_manager = (int (*)(stm_tx_t *, stm_tx_t *, int))val;
    return 1;
  }
  if (strcmp("vr_threshold", name) == 0) {
    vr_threshold = *(int *)val;
    return 1;
  }
#endif /* CM == CM_MODULAR */
  return 0;
}

/*
 * Create transaction-specific data (return -1 on error).
 */
int stm_create_specific()
{
  if (nb_specific >= MAX_SPECIFIC) {
    fprintf(stderr, "Error: maximum number of specific slots reached\n");
    return -1;
  }
  return nb_specific++;
}

/*
 * Store transaction-specific data.
 */
void stm_set_specific(TXPARAMS int key, void *data)
{
  TX_GET;

  assert (key >= 0 && key < nb_specific);
  tx->data[key] = data;
}

/*
 * Fetch transaction-specific data.
 */
void *stm_get_specific(TXPARAMS int key)
{
  TX_GET;

  assert (key >= 0 && key < nb_specific);
  return tx->data[key];
}

/*
 * Register callbacks for an external module (must be called before creating transactions).
 */
int stm_register(void (*on_thread_init)(TXPARAMS void *arg),
                 void (*on_thread_exit)(TXPARAMS void *arg),
                 void (*on_start)(TXPARAMS void *arg),
                 void (*on_precommit)(TXPARAMS void *arg),
                 void (*on_commit)(TXPARAMS void *arg),
                 void (*on_abort)(TXPARAMS void *arg),
                 void *arg)
{
  if ((on_thread_init != NULL && nb_init_cb >= MAX_CB) ||
      (on_thread_exit != NULL && nb_exit_cb >= MAX_CB) ||
      (on_start != NULL && nb_start_cb >= MAX_CB) ||
      (on_precommit != NULL && nb_precommit_cb >= MAX_CB) ||
      (on_commit != NULL && nb_commit_cb >= MAX_CB) ||
      (on_abort != NULL && nb_abort_cb >= MAX_CB)) {
    fprintf(stderr, "Error: maximum number of modules reached\n");
    return 0;
  }
  /* New callback */
  if (on_thread_init != NULL) {
    init_cb[nb_init_cb].f = on_thread_init;
    init_cb[nb_init_cb++].arg = arg;
  }
  /* Delete callback */
  if (on_thread_exit != NULL) {
    exit_cb[nb_exit_cb].f = on_thread_exit;
    exit_cb[nb_exit_cb++].arg = arg;
  }
  /* Start callback */
  if (on_start != NULL) {
    start_cb[nb_start_cb].f = on_start;
    start_cb[nb_start_cb++].arg = arg;
  }
  /* Pre-commit callback */
  if (on_precommit != NULL) {
    precommit_cb[nb_precommit_cb].f = on_precommit;
    precommit_cb[nb_precommit_cb++].arg = arg;
  }
  /* Commit callback */
  if (on_commit != NULL) {
    commit_cb[nb_commit_cb].f = on_commit;
    commit_cb[nb_commit_cb++].arg = arg;
  }
  /* Abort callback */
  if (on_abort != NULL) {
    abort_cb[nb_abort_cb].f = on_abort;
    abort_cb[nb_abort_cb++].arg = arg;
  }

  return 1;
}

#if 0
void stm_release(TXPARAMS volatile stm_word_t *addr)
{
// TODO to test 
  w_entry_t *w;
  volatile stm_word_t *lock;
#if DESIGN == WRITE_THROUGH
  int must_release = 1;
  stm_word_t t, i;
#elif DESIGN == WRITE_BACK_ETL
  stm_word_t l;
#endif
  TX_GET;

#if CM == CM_MODULAR
  if (GET_STATUS(tx->status) == TX_KILLED) {
    stm_rollback(tx, STM_ABORT_KILLED);
    return;
  }
#else /* CM != CM_MODULAR */
  assert(GET_STATUS(tx->status) == TX_ACTIVE);
#endif /* CM != CM_MODULAR */

  /* Get reference to lock */
  lock = GET_LOCK(addr);

#if DESIGN == WRITE_THROUGH
  w = tx->w_set.entries;
  for (i = tx->w_set.nb_entries; i > 0; i--, w++) {
    /* If the lock covers this address */
    if (GET_LOCK(w->addr) == lock) {
      if (w->addr == addr) {
        /* Restore value */
        ATOMIC_STORE(w->addr, w->value);
        w->addr = NULL;
        if (w->no_drop)
          return;
    break;
      } else if (w->no_drop == 1) {
        w->no_drop = 0;
        must_release = 0;
    break;
      }
    }
  }
  if (must_release) {
    /* Release lock */
    /* Incarnation numbers allow readers to detect dirty reads */
    i = LOCK_GET_INCARNATION(w->version) + 1;
    if (i > INCARNATION_MAX) {
      /* Simple approach: write new version (might trigger unnecessary aborts) */
      if (t == 0) {
        t = FETCH_INC_CLOCK + 1;
        if (t >= VERSION_MAX) {
# ifdef ROLLOVER_CLOCK
          /* We can still use VERSION_MAX for protecting read-only trasanctions from dirty reads */
          t = VERSION_MAX;
# else /* ! ROLLOVER_CLOCK */
          fprintf(stderr, "Exceeded maximum version number: 0x%lx\n", (unsigned long)t);
          exit(1);
# endif /* ! ROLLOVER_CLOCK */
        }
      }
      ATOMIC_STORE_REL(w->lock, LOCK_SET_TIMESTAMP(t));
    } else {
      /* Use new incarnation number */
      ATOMIC_STORE_REL(w->lock, LOCK_UPD_INCARNATION(w->version, i));
    }
  }
#elif DESIGN == WRITE_BACK_ETL
  /* Read the lock */
  l = ATOMIC_LOAD_ACQ(lock);
  w = (w_entry_t *)LOCK_GET_ADDR(l);
  /* Reset the write set entry */
  if (tx->w_set.entries <= w && w < tx->w_set.entries + tx->w_set.nb_entries) {
    if (w->addr == addr) {
      if (w->next == NULL) {
        /* Release lock */
#if CM == CM_MODULAR
        ATOMIC_CAS_FULL(w->lock, l, LOCK_SET_TIMESTAMP(w->version));
#else
        ATOMIC_STORE(w->lock, LOCK_SET_TIMESTAMP(w->version));
#endif
      } else {
        /* Update lock */
#if CM == CM_MODULAR
        ATOMIC_CAS_FULL(w->lock, l, LOCK_SET_ADDR_WRITE((stm_word_t)w->next));
#else
        ATOMIC_STORE(w->lock, LOCK_SET_ADDR_WRITE((stm_word_t)w->next));
#endif
      }
      w->addr = NULL;
    } else {
      /* Lock was acquired first by another address */
      w->addr = NULL;
    }
  }
#else /* DESIGN == WRITE_BACK_CTL */
  /* Reset the write set entry */
  w = stm_has_written(tx, addr);
  if (w != NULL) {
    w->addr = NULL;
  }
#endif /* DESIGN == WRITE_BACK_CTL */

}
#endif

/*
 * Called by the CURRENT thread to load a word-sized value in a unit transaction.
 */
stm_word_t stm_unit_load(volatile stm_word_t *addr, stm_word_t *timestamp)
{
  volatile stm_word_t *lock;
  stm_word_t l, l2, value;

  PRINT_DEBUG2("==> stm_unit_load(a=%p)\n", addr);

  /* Get reference to lock */
  lock = GET_LOCK(addr);

  /* Read lock, value, lock */
 restart:
  l = ATOMIC_LOAD_ACQ(lock);
 restart_no_load:
  if (LOCK_GET_OWNED(l)) {
    /* Locked: wait until lock is free */
#ifdef WAIT_YIELD
    sched_yield();
#endif /* WAIT_YIELD */
    goto restart;
  }
  /* Not locked */
  value = ATOMIC_LOAD_ACQ(addr);
  l2 = ATOMIC_LOAD_ACQ(lock);
  if (l != l2) {
    l = l2;
    goto restart_no_load;
  }

  if (timestamp != NULL)
    *timestamp = LOCK_GET_TIMESTAMP(l);

  return value;
}

/*
 * Called by the CURRENT thread to store a word-sized value in a unit transaction.
 */
int stm_unit_store(volatile stm_word_t *addr, stm_word_t value, stm_word_t *timestamp)
{
  return stm_unit_write(addr, value, ~(stm_word_t)0, timestamp);
}

/*
 * Called by the CURRENT thread to store part of a word-sized value in a unit transaction.
 */
int stm_unit_store2(volatile stm_word_t *addr, stm_word_t value, stm_word_t mask, stm_word_t *timestamp)
{
  return stm_unit_write(addr, value, mask, timestamp);
}

/*
 * Enable or disable extensions and set upper bound on snapshot.
 */
void stm_set_extension(TXPARAMS int enable, stm_word_t *timestamp)
{
  TX_GET;

  tx->can_extend = enable;
  if (timestamp != NULL && *timestamp < tx->end)
    tx->end = *timestamp;
}

/*
 * Get current value of global clock.
 */
stm_word_t stm_get_clock()
{
  return GET_CLOCK;
}

/*
 * Get current transaction descriptor.
 */
stm_tx_t *stm_current_tx()
{
  return stm_get_tx();
}

/* ################################################################### *
 * UNDOCUMENTED STM FUNCTIONS (USE WITH CARE!)
 * ################################################################### */

#ifdef CONFLICT_TRACKING
/*
 * Get thread identifier of other transaction.
 */
int stm_get_thread_id(stm_tx_t *tx, pthread_t *id)
{
  *id = tx->thread_id;
  return 1;
}

/*
 * Set global conflict callback.
 */
int stm_set_conflict_cb(void (*on_conflict)(stm_tx_t *tx1, stm_tx_t *tx2))
{
  conflict_cb = on_conflict;
  return 1;
}
#endif /* CONFLICT_TRACKING */

#ifdef IRREVOCABLE_ENABLED
int stm_set_irrevocable(TXPARAMS int serial)
{
# if CM == CM_MODULAR
  stm_word_t t;
# endif /* CM == CM_MODULAR */
  TX_GET;

  if (!IS_ACTIVE(tx->status) && serial != -1) {
    /* Request irrevocability outside of a transaction or in abort handler (for next execution) */
    tx->irrevocable = 1 + (serial ? 0x08 : 0);
    return 0;
  }

  /* Are we already in irrevocable mode? */
  if ((tx->irrevocable & 0x07) == 3) {
    return 1;
  }

  if (tx->irrevocable == 0) {
    /* Acquire irrevocability for the first time */
    tx->irrevocable = 1 + (serial ? 0x08 : 0);
#ifdef HYBRID_ASF
    /* TODO: we shouldn't use pthread_mutex/cond since it could use syscall. */
    if (tx->software == 0) {
      asf_abort(ASF_RETRY_IRREVOCABLE);
      return 0;
    }
#endif /* HYBRID_ASF */
    /* Try acquiring global lock */
    if (irrevocable == 1 || ATOMIC_CAS_FULL(&irrevocable, 0, 1) == 0) {
      /* Transaction will acquire irrevocability after rollback */
      stm_rollback(tx, STM_ABORT_IRREVOCABLE);
      return 0;
    }
    /* Success: remember we have the lock */
    tx->irrevocable++;
    /* Try validating transaction */
    if (!stm_validate(tx)) {
      stm_rollback(tx, STM_ABORT_VALIDATE);
      return 0;
    }
# if CM == CM_MODULAR
   /* We might still abort if we cannot set status (e.g., we are being killed) */
    t = tx->status;
    if (GET_STATUS(t) != TX_ACTIVE || ATOMIC_CAS_FULL(&tx->status, t, t + (TX_IRREVOCABLE - TX_ACTIVE)) == 0) {
      stm_rollback(tx, STM_ABORT_KILLED);
      return 0;
    }
# endif /* CM == CM_MODULAR */
    if (serial && tx->w_set.nb_entries != 0) {
      /* TODO: or commit the transaction when we have the irrevocability. */
      /* Don't mix transactional and direct accesses => restart with direct accesses */
      stm_rollback(tx, STM_ABORT_IRREVOCABLE);
      return 0;
    }
  } else if ((tx->irrevocable & 0x07) == 1) {
    /* Acquire irrevocability after restart (no need to validate) */
    while (irrevocable == 1 || ATOMIC_CAS_FULL(&irrevocable, 0, 1) == 0)
      ;
    /* Success: remember we have the lock */
    tx->irrevocable++;
  }
  assert((tx->irrevocable & 0x07) == 2);

  /* Are we in serial irrevocable mode? */
  if ((tx->irrevocable & 0x08) != 0) {
    /* Stop all other threads */
    if (stm_quiesce(tx, 1) != 0) {
      /* Another thread is quiescing and we are active (trying to acquire irrevocability) */
      assert(serial != -1);
      stm_rollback(tx, STM_ABORT_IRREVOCABLE);
      return 0;
    }
  }

  /* We are in irrevocable mode */
  tx->irrevocable++;

  return 1;
}
#else /* ! IRREVOCABLE_ENABLED */
int stm_set_irrevocable(TXPARAMS int serial)
{
  fprintf(stderr, "Irrevocability is not supported in this configuration\n");
  exit(-1);
  return 1;
}
#endif /* ! IRREVOCABLE_ENABLED */


#ifdef HYBRID_ASF

/* Checking that the write-set can contains at least 256 */
/* XXX ASF can write many times at the same address, thus we can overflow */
#if RW_SET_SIZE <= 256
# error ASF (LLB_256) needs at least 256 entries for the write set.
#endif /* RW_SET_SIZE */

static inline uint64_t rdtsc()
{
    uint64_t hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return (uint64_t)hi << 32 | lo;
}

stm_word_t hytm_load(TXPARAMS volatile stm_word_t *addr)
{
  volatile stm_word_t *lock;
  stm_word_t l;
  lock = GET_LOCK(addr);
  /* Load descriptor using ASF */
  l = asf_lock_load64((long unsigned int *)lock);
  if (unlikely(LOCK_GET_WRITE(l))) {
    /* a software transaction is currently using this descriptor */
    asf_abort(ASF_RETRY);
    /* unreachable */
    return 0;
  }
  /* addr can return inconsistent value but will be abort after few cycles */
  return *addr;
  /* Load value using ASF.
   * (in previous version of PTLSIM/ASF, the ordering was not respected).
   * TODO: to be removed. */
  /*return asf_lock_load64((long unsigned int *)addr);*/
}

void hytm_store(TXPARAMS volatile stm_word_t *addr, stm_word_t value)
{
  TX_GET;
  volatile stm_word_t *lock;
  stm_word_t l;
  lock = GET_LOCK(addr);
  /* Load descriptor using ASF */
  l = asf_lock_load64((long unsigned int *)lock);
  if (unlikely(LOCK_GET_WRITE(l))) {
    /* a software transaction is currently using this descriptor, ASF tx has to give up */
    asf_abort(ASF_RETRY);
    /* XXX mark as unreachable */
    return;
  }
  /* Write the value using ASF */
  asf_lock_store64((long unsigned int *)addr, value);
  /* Add to write set to update the locks when we acquire TS */
  /* XXX This could overflow if many write to the same address. */
  tx->w_set.entries[tx->w_set.nb_entries++].lock = lock;
}

void hytm_store2(TXPARAMS volatile stm_word_t *addr, stm_word_t value, stm_word_t mask)
{
  hytm_store(TXARGS addr, (asf_lock_load64((long unsigned int *)addr) & ~mask) | (value & mask));
}

int hytm_commit(TXPARAM) 
{
  stm_word_t t;
  w_entry_t *w;
  int i;
  TX_GET;

  /* Release irrevocability */
#ifdef IRREVOCABLE_ENABLED
  if (tx->irrevocable) {
    ATOMIC_STORE(&irrevocable, 0);
    if ((tx->irrevocable & 0x08) != 0)
      stm_quiesce_release(tx);
    tx->irrevocable = 0;
    goto commit_end;
  }
#endif /* IRREVOCABLE_ENABLED */

  t = FETCH_INC_CLOCK + 1;
  
  /* Set new timestamp in locks */
  w = tx->w_set.entries;
  for (i = tx->w_set.nb_entries; i > 0; i--, w++) {
    /* XXX Maybe no duplicate entries can improve perf? */
    asf_lock_store64((long unsigned int *)w->lock, LOCK_SET_TIMESTAMP(t));
  }
  /* Commit the hytm transaction */
  asf_commit();

commit_end:
  tx->retries = 0;
  /* Set status to COMMITTED */
  SET_STATUS(tx->status, TX_COMMITTED);

  /* TODO statistics */
#ifdef INTERNAL_STATS
  
#endif
  return 1;
}

void hytm_abort(TXPARAMS int reason)
{
  asf_abort(ASF_RETRY);
}

sigjmp_buf *hytm_start(TXPARAMS stm_tx_attr_t *attr)
{
  TX_GET;
  unsigned long err;

  tx->retries = 0;
  /* Set status */
  UPDATE_STATUS(tx->status, TX_ACTIVE);
  stm_check_quiesce(tx);
  /* copy attributes if need to switch to software mode */
  tx->attr = (attr == NULL ? default_attributes : *attr);
  tx->start = rdtsc();

hytm_restart:
  /* All registers are lost when ASF aborts, thus we discard registers */
  asm volatile (ASF_SPECULATE 
                :"=a" (err)
                :
                :"memory","rbp","rbx","rcx","rdx","rsi","rdi",
                 "r8", "r9","r10","r11","r12","r13","r14","r15" );
 
  tx = stm_get_tx();
  if (unlikely(asf_status_code(err) != 0)) {
    /* Set status to ABORTED */
    SET_STATUS(tx->status, TX_ABORTED);
    tx->retries++;
    /* Error management */
    if (asf_status_code(err) == ASF_STATUS_CONTENTION) {
      if (tx->retries > ASF_ABORT_THRESHOLD) {
        /* There is too many conflicts, software will not help, start irrevocability. */
        stm_set_irrevocable(TXARGS 1);  /* Set irrevocable serial */
#if defined(TM_DTMC)
        stm_set_irrevocable(TXARGS -1); /* Acquire irrevocability */
        UPDATE_STATUS(tx->status, TX_IRREVOCABLE);
        siglongjmp(tx->env, 0x02); /* ABI 0x02 = runUninstrumented */
#else /* ! defined(TM_DTMC) */
        /* Non-tm compiler and GCC doesn't have path without instrumentation. */
        tx->software = 1;
#endif /* ! defined(TM_DTMC) */
      }
    } else if (asf_status_code(err) == ASF_STATUS_ABORT) {
      if (asf_abort_code(err) == ASF_FORCE_SOFTWARE) {
        tx->software = 1;
#ifdef IRREVOCABLE_ENABLED
      } else if(asf_abort_code(err) == ASF_RETRY_IRREVOCABLE) {
#if defined(TM_DTMC)
        if (tx->irrevocable != 0) {
          stm_set_irrevocable(TXARGS -1);
          UPDATE_STATUS(tx->status, TX_IRREVOCABLE);
          siglongjmp(tx->env, 0x02); /* ABI 0x02 = runUninstrumented */
        } 
#else /* ! defined(TM_DTMC) */
        /* Non-tm compiler and GCC doesn't have path without instrumentation. */
        tx->software = 1;
#endif /* ! defined(TM_DTMC) */
#endif /* IRREVOCABLE_ENABLED */
      } else {
        if (tx->retries > ASF_ABORT_THRESHOLD) { 
          tx->software = 1;
        }
      }
    } else {
      /* Other cases are critical and needs software mode */
      tx->software = 1;
    }
    if (tx->software) {
      /* Start a software transaction (it cannot use attr since the register/stack can be corrupted) */
      stm_start(TXARGS &tx->attr);
      /* Restoring the context */
#if defined(TM_DTMC)
      siglongjmp(tx->env, 0x01); /* ABI 0x01 = runInstrumented, DTMC explicitly needs 1 */
#else /* ! defined(TM_DTMC) */
      siglongjmp(tx->env, 0x09); /* ABI 0x09 = runInstrumented + restoreLiveVariable */
#endif /* ! defined(TM_DTMC) */
    } else {
      uint64_t wait = (uint64_t)rdtsc + (random() % (rdtsc() - tx->start)); /* XXX random but maybe not reliable */
      /* Waiting... */
      while (rdtsc() < wait);
      UPDATE_STATUS(tx->status, TX_ACTIVE);
      /* Check quiesce before to restart */
      stm_check_quiesce(tx);
      goto hytm_restart;
    }
  }
 
  /* Reset write set */
  tx->w_set.nb_entries = 0;

  if (tx->retries > 0) {
    /* Restoring registers for retry */
#if defined(TM_DTMC)
    siglongjmp(tx->env, 0x01); /* ABI 0x01 = runInstrumented, DTMC explicitly needs 1 */
#else /* ! defined(TM_DTMC) */
    siglongjmp(tx->env, 0x09); /* ABI 0x09 = runInstrumented + restoreLiveVariable */
#endif /* ! defined(TM_DTMC) */
  } 

  return &tx->env;
}

/* generic interface for HYTM and STM */

sigjmp_buf *tm_start(TXPARAMS stm_tx_attr_t *attr)
{
  TX_GET;

  if (!tx->software) {
    return hytm_start(TXARGS attr);
  } else {
    return stm_start(TXARGS attr);
  }
}

stm_word_t tm_load(TXPARAMS volatile stm_word_t *addr)
{
  TX_GET;
  if (!tx->software) {
    return hytm_load(TXARGS addr);
  } else {
    return stm_load(TXARGS addr);
  }
}

void tm_store(TXPARAMS volatile stm_word_t *addr, stm_word_t value)
{
  TX_GET;
  if (!tx->software) {
    hytm_store(TXARGS addr, value);
  } else {
    stm_store(TXARGS addr, value);
  }
}

void tm_store2(TXPARAMS volatile stm_word_t *addr, stm_word_t value, stm_word_t mask)
{
  TX_GET;
  if (!tx->software) {
    hytm_store2(TXARGS addr, value, mask);
  } else {
    stm_store2(TXARGS addr, value, mask);
  }
}

int tm_commit(TXPARAM)
{
  TX_GET;
  if (!tx->software) {
    return hytm_commit(TXARG);
  } else {
    return stm_commit(TXARG);
  }
}

void tm_abort(TXPARAMS int reason)
{
  TX_GET;
  if (!tx->software) {
    hytm_abort(TXARGS reason);
  } else {
    stm_abort(TXARGS reason);
  }
}

int tm_hybrid(TXPARAM)
{
  TX_GET;
  return !tx->software;
}

void tm_restart_software(TXPARAM)
{
  TX_GET;
  if (!tx->software) {
    asf_abort(ASF_FORCE_SOFTWARE);
  }
}
#else
/* Define tm_* functions */

void tm_start(stm_tx_attr_t *attr)
{
  stm_start(attr);
}

stm_word_t tm_load(TXPARAMS volatile stm_word_t *addr)
{
  return stm_load(TXARGS addr);
}

void tm_store(TXPARAMS volatile stm_word_t *addr, stm_word_t value)
{
  stm_store(TXARGS addr, value);
}

void tm_store2(TXPARAMS volatile stm_word_t *addr, stm_word_t value, stm_word_t mask)
{
  stm_store2(TXARGS addr, value, mask);
}

int tm_commit(TXPARAM)
{
  return stm_commit(TXARG);
}
void tm_abort(TXPARAMS int reason)
{
  stm_abort(TXARGS reason);
}

/* TODO what should be done for hybrid specific functions */
void tm_restart_software(TXPARAM) {
}
int tm_hybrid(TXPARAM) {
  return 0;
}


#endif /* HYBRID_ASF */
