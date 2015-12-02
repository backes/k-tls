/*
 * syscalls.h
 *
 *  Created on: Jun 11, 2014
 *      Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#ifndef KTLS_SYSCALLS_H_
#define KTLS_SYSCALLS_H_

void ktls_redirect_system_calls(void (*sys_call_table[])(void),
                                int (*set_memory_rw)(unsigned long addr,
                                                     int numpages));
void ktls_restore_system_calls(void (*sys_call_table[])(void));

#endif /* KTLS_SYSCALLS_H_ */
