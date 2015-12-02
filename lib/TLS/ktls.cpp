/*
 * ktls.cpp - User space interface to the KTLS kernel module
 *
 * KTLS - Kernel Thread-Level Speculation
 * KTLS is a part of the sambamba framework
 *
 * Authors: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 *          Janosch Graef <janosch.graef@gmx.net>
 */

#include "TLS/ktls_ioctl.h"
#include "TLS/ktls.h"
#include "TLS/tls.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <unistd.h>      /*  _SC_PAGESIZE */
#include <sys/ioctl.h>   /* ioctl */
#include <sys/syscall.h> /* syscall, SYS_gettid, SYS_exit */

#ifdef DEBUG_KTLS_INTERFACE
# define DEBUG(...) printf("[ktls] " __VA_ARGS__)
#else
# define DEBUG(...) do { } while (0)
#endif

namespace { // anonymous

int ktls_fd = -1;

int ktls_global_fd(void) {
  if (ktls_fd == -1)
    ktls_fd = ktls_open();
  return ktls_fd; // might still be -1 (on error)
}

} // anonymous namespace

extern "C" {

void ktls_run(void *list0) {
    const char *error = 0;
    TLS::TaskList *list = reinterpret_cast<TLS::TaskList*>(list0);
    void *tasks = list->getFirstTask();
    void *tasks_end = list->getEnd();
    uint32_t num_tasks = list->getNumTasks();

    DEBUG("ktls_run with %d tasks\n", num_tasks);

    int ret;

    int fd = ktls_global_fd();
    if (fd == -1) {
      error = "Error connecting to KTLS kernel module";
      goto _error;
    }

    ret = ktls_spawn(ktls_fd, tasks, tasks_end, num_tasks);
    DEBUG("ktls_run -> ktls_spawn ret %d\n", ret);
    if (ret < 0) {
        error = "Error spawning KTLS tasks";
        goto _error;
    }
    if (ret > 0) {
        // If ret > 0, then not all tasks were executed in the TLS.
        // Execute the rest here.

        unsigned reexec_task = ret - 1;
        assert (reexec_task < num_tasks);
        TLS::TLSTask *task = list->getFirstTask();
        for (unsigned t = 0; t < num_tasks; ++t, task = task->next()) {
          if (t >= reexec_task) {
            DEBUG("ktls_run -> run task %d\n", t);
            task->run();
          }
        }
    }

    DEBUG("ktls_run finished\n");

    return;

_error:
    perror(error);
    abort();
}

void ktls_task_trampoline(void *in, void *out, void (*func)(void*, void*), unsigned long reserved_stack_size) {
    __asm__ __volatile__ (
            "call *%1;\n"
            "add %0,%%rsp;\n" /* this will move the SP to the top stack frame, so
                                 that the succeeding retq will trigger a page fault */
            : /* output */
            : /* input */ "b" (reserved_stack_size), "r" (func)
            :
    );
}

int ktls_open(void) {
  return open("/dev/" KTLS_DEV_NAME, O_RDWR);
}

int ktls_close(int fd) {
    return close(fd);
}

int ktls_spawn(int fd, void *tasks, void *tasks_end, uint32_t num_tasks) {
    /*
    // debug
    printf("\nMy memory map:\n"); fflush(stdout);
    char buf[129];
    FILE *maps = fopen("/proc/self/maps", "r");
    int read;
    while ((read = fread(buf, 1, 128, maps))) {
        fwrite(buf, 1, read, stdout);
    }
    fclose(maps);
    printf("\n"); fflush(stdout);
    */

    struct ktls_spawn_args args;
    args.tasks = tasks;
    args.tasks_end = tasks_end;
    args.num_tasks = num_tasks;
    args.trampoline_function = ktls_task_trampoline;

    return ioctl(fd, KTLS_IOCTL_SPAWN, &args);
}

struct loop_info {
    int num_tasks_in_list;
    void *task_list;
};

void *ktls_start_loop() {
  struct loop_info *info = (struct loop_info *)malloc(sizeof(struct loop_info));
  if (info) {
    info->num_tasks_in_list = 0;
    info->task_list = 0;
  }
  DEBUG("ktls_start_loop\n");
  return info;
}

void ktls_spawn_next(void *loopInfo, void (*fun)(void *, void *),
                     void *input, unsigned input_size) {
    DEBUG("ktls_spawn_next\n");
    struct loop_info *info = (struct loop_info*) loopInfo;
    if (!info->task_list)
        info->task_list = tls_newList();
    char *in_dst = tls_addTask(info->task_list, input_size, 0, fun);
    if (input_size)
        memcpy(in_dst, (char*) input, input_size);
    ++info->num_tasks_in_list;
    if (info->num_tasks_in_list == 16) {
      ktls_run(info->task_list);
      tls_deleteList(info->task_list);
      info->num_tasks_in_list = 0;
      info->task_list = 0;
    }
}

void ktls_finish_loop(void *loopInfo) {
  DEBUG("ktls_finish_loop\n");
  struct loop_info *info = (struct loop_info *)loopInfo;
  if (info->task_list) {
    ktls_run(info->task_list);
    tls_deleteList(info->task_list);
  }
  free(info);
}

int ktls_get_stats(int fd, struct ktls_stats *stats) {
    return ioctl(fd, KTLS_IOCTL_STATS, stats);
}

int ktls_reset_stats(int fd) {
    return ioctl(fd, KTLS_IOCTL_RESET_STATS, 0);
}

int ktls_reset_global_stats() {
  if (ktls_fd == -1)
    return 0;
  return ktls_reset_stats(ktls_fd);
}

int ktls_get_global_stats(struct ktls_stats *stats) {
  if (ktls_fd == -1) {
    memset(stats, 0, sizeof(*stats));
    return 0;
  }
  return ktls_get_stats(ktls_fd, stats);
}

} /* extern "C" */
