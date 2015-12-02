/*
 * utls.h
 *
 *  Created on: Jul 22, 2013
 *      Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#ifndef UTLS_UTLS_H_
#define UTLS_UTLS_H_

struct utls_stats {
  unsigned long micros_conflict_checking;
  unsigned long micros_commit;
  unsigned long num_tasks;
  unsigned long num_rollbacks;
};

extern "C" {

/**
 * Run task list in UTLS.
 */
void utls_run(void*);

/**
 * Reset the statistics gathered so far.
 */
void utls_reset_stats();

/**
 * Get a copy of the statistics over all UTLS tasks so far.
 */
struct utls_stats utls_get_stats();
}

#endif /* UTLS_UTLS_H_ */
