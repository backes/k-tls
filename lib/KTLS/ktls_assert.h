/*
 * ktls_assert.h
 *
 *  Created on: Sep 25, 2013
 *      Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#ifndef KTLS_ASSERT_H_
#define KTLS_ASSERT_H_

#include <linux/sched.h> /* struct task_struct ... */
#include <asm/current.h> /* current, ... */
void ktls_bug_happened(void);

#ifndef NDEBUG
#define ASSERT(condition)                                                      \
  do {                                                                         \
    if (unlikely(!(condition))) {                                              \
      printk(KERN_ERR "[pid %d] ASSERTION FAILURE in %s, line %d: %s\n",       \
             current->pid, __FILE__, __LINE__, #condition);                    \
      ktls_bug_happened();                                                     \
    }                                                                          \
  } while (0)
#else
#define ASSERT(condition)                                                      \
  do {                                                                         \
  } while (0)
#endif


#endif /* KTLS_ASSERT_H_ */
