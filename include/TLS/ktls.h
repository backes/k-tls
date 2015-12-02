/* KTLS - Kernel Thread-Level Speculation
 * KTLS is a part of the sambamba framework
 *
 * test/ktls.h - User space interface to the KTLS kernel module
 * Authors: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 *          Janosch Graef <janosch.graef@gmx.net>
 */

#ifndef _KTLS_H_
#define _KTLS_H_

#include "ktls_ioctl.h"

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The all-in-one interface: take a TaskList and run all tasks contained in it.
 */
void ktls_run(void *taskList);

/**
 * Open a connection to the KTLS kernel module.
 * Return a file descriptor, or -1 if an error occured.
 * In this case, errno is set appropriately.
 */
int ktls_open(void);

/**
 * Close a KTLS connection which was previously opened by ktls_open.
 * Returns 0 on success, -1 on error (and sets errno).
 */
int ktls_close(int fd);

/**
 * The task-level-parallelism (a.k.a fork/join) interface.
 *
 * Spawn multiple threads with kernel transactional memory.
 * `fd` is the file descriptor returned by ktls_open.
 * `tasks` is a pointer to a TLS::TaskList.
 * `tasks_end` is a pointer past the end of the TaskList (as returned by
 *             TaskList::getEnd()).
 * `num_tasks` is the number of tasks in the list (as returned by
 *             TaskList::getNumTasks()).
 *
 * Returns 0 on success, 1 if an error occured (e.g. communication with kernel
 * module failed).
 * In case of error, errno is set accordingly.
 */
int ktls_spawn(int fd, void *tasks, void *tasks_end, uint32_t num_tasks);

/**
 * The loop interface.
 *
 * Start a loop execution with dynamic number of tasks.
 *
 * Aborts on error, otherwise returns a private pointer to be passed to the
 * other loop-related functions..
 */
void *ktls_start_loop();

/**
 * The loop interface.
 *
 * Spawn the next task.
 * `loopInfo` is the pointer returned by ktls_start_loop.
 * `fd` is the file descriptor returned by ktls_open.
 * `fun` is the function to execute with parameters (input_ptr, output_ptr).
 * `input` is a pointer to the space where the input is written.
 * `input_size` is the size in bytes of the input space.
 *
 * Aborts on error.
 */
void ktls_spawn_next(void *loopInfo, void (*fun)(void *, void *),
                     void *input, unsigned input_size);

/**
 * Sync on all the spawned threads.
 * This corresponds to the loop interface.
 * `loopInfo` is the pointer returned by ktls_start_loop.
 *
 * Aborts on error.
 */
void ktls_finish_loop(void *loopInfo);

/**
 * Reset KTLS statistics.
 * Returns 0 on success, -1 on error (and sets errno).
 */
int ktls_reset_stats(int fd);

/**
 * Retrieve KTLS statistics, and store them in `stats`.
 * Returns 0 on success, -1 on error (and sets errno).
 */
int ktls_get_stats(int fd, struct ktls_stats *stats);

/**
 * Reset the KTLS statistics for the global context used by previous ktls_run
 * calls.
 * Returns 0 on success, -1 on error (and sets errno).
 */
int ktls_reset_global_stats();

/**
 * Retrieve KTLS statistics for the global context used by previous ktls_run
 * calls, and store them in `stats`.
 * Returns 0 on success, -1 on error (and sets errno).
 */
int ktls_get_global_stats(struct ktls_stats *stats);

#ifdef __cplusplus
}
#endif

#endif /* _KTLS_H_ */
