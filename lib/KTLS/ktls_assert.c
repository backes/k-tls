/*
 * ktls_assert.c
 *
 * Created on: 2015-10-30
 *     Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#include "ktls_assert.h"

#include <linux/atomic.h> /* atomic_t */
#include <linux/sched.h> /* set_current_state, schedule */

static atomic_t ktls_num_bugs_happened = ATOMIC_INIT(0);
static volatile int foo = 0;

void ktls_bug_happened(void) {
  while (1) {
    unsigned long bug_nr = atomic_read(&ktls_num_bugs_happened);
    if (atomic_cmpxchg(&ktls_num_bugs_happened, bug_nr, bug_nr + 1) != bug_nr)
      continue;
    if (bug_nr == 0) {
      printk(KERN_ERR
             "This is the first ktls bug. Entering endless loop now...\n");
      while (1) {
        ++foo;
      }
    } else {
      printk(KERN_ERR
             "This is the ktls bug nr %ld. Sleeping endlessly now...\n",
             bug_nr + 1);
      set_current_state(TASK_UNINTERRUPTIBLE);
      schedule();
    }
  }
}
