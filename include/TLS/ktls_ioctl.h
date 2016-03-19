/* KTLS - Kernel Thread-Level Speculation
 *
 * ktls_ioctl.h - Shared definitions
 *
 * Can be included from the kernel module, c code, or c++ code.
 *
 * Authors: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 *          Janosch Graef <janosch.graef@gmx.net>
 */

#ifndef _KTLS_IOCTL_H_
#define _KTLS_IOCTL_H_

#ifdef __KERNEL__
# include <linux/types.h> /* uint16_t, uint32_t, ... */
#elif defined(__cplusplus)
# include <cstdint> /* uint16_t, uint32_t, ... */
#else
# include <stdint.h> /* uint16_t, uint32_t, ... */
#endif

/* check for architecture */
#if !defined(__x86_64__)
# error "KTLS is only supported on x86_64"
#endif


/* The name of the device used to communicate with KTLS */
#define KTLS_DEV_NAME "ktls"

/* IOCTLs */
#define KTLS_IOCTL_MAGIC 'K'
#define KTLS_IOCTL_SPAWN       _IOW(KTLS_IOCTL_MAGIC, 0, struct ktls_spawn_args)
#define KTLS_IOCTL_STATS       _IOR(KTLS_IOCTL_MAGIC, 1, struct ktls_stats)
#define KTLS_IOCTL_RESET_STATS _IO(KTLS_IOCTL_MAGIC, 2)


/* Arguments for the spawn IOCTL */
struct ktls_spawn_args {
  void *tasks;
  void *tasks_end;
  uint16_t num_tasks;
  void (*trampoline_function)(void *, void *, void (*)(void *, void *),
                              unsigned long);
};

/* struct to hold KTLS statistics */
struct ktls_stats {
  /* overall number of task lists spawned */
  unsigned num_task_lists;

  /* overall number of tasks in the task lists.
   * difference to num_tasks: num_tasks counts tasks twice if they get
   * respawned.
   */
  unsigned num_initial_tasks;

  /* overall number of tasks spawned */
  unsigned num_tasks;

  /* number of rollbacks occured */
  unsigned num_rollbacks;

  /* number of committed tasks */
  unsigned num_commits;

  /* total number of pages read by committed tasks */
  unsigned num_read_pages;

  /* total number of pages written by committed tasks */
  unsigned num_written_pages;

  /* total number of pages read or written by conflicting tasks */
  unsigned num_touched_pages_rollbacked;

  /* number of tasks made irrevocable */
  unsigned num_irrevocable_tasks;

  /* number of tasks rolled back because of a forbidden syscall */
  unsigned num_forbidden_syscalls;

  /* number of tasks on Nth position in the task list which succeeded on the first try */
  unsigned succeeding_tasks[8];

  /* total number of tasks on Nth position in the task list */
  unsigned num_tasks_on_position[8];

  /* total number of tasks which successfully returned from the user function */
  unsigned num_tasks_returned_from_user_function;

  /* total nanoseconds in failed conflict checking (= conflict found) */
  unsigned long nanos_conflict_checking_fail;

  /* total nanoseconds in successful conflict checking (= no conflict found) */
  unsigned long nanos_conflict_checking_success;

  /* total nanoseconds in commit */
  unsigned long nanos_commit;

  /* total nanoseconds of executing user code (only counted for tasks which
   * successfully return from the user function */
  unsigned long nanos_user_code;

  /* total nanoseconds for executing task lists (all time in the
   * KTLS_IOCTL_SPAWN ioctl) */
  unsigned long nanos_total_task_list;
};

#endif /* _KTLS_IOCTL_H_ */
