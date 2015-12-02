/*
 * debug.h
 *
 *  Created on: Dec 7, 2010
 *      Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#ifndef TINYSTM_DEBUG_H_
#define TINYSTM_DEBUG_H_

#ifdef DEBUG2
# ifndef DEBUG
#  define DEBUG
# endif /* ! DEBUG */
#endif /* DEBUG2 */

#ifdef DEBUG
/* Note: stdio is thread-safe */
# define IO_FLUSH                       fflush(NULL)
# define PRINT_DEBUG(...)               printf(__VA_ARGS__); fflush(NULL)
#else /* ! DEBUG */
# define IO_FLUSH
# define PRINT_DEBUG(...)
#endif /* ! DEBUG */

#ifdef DEBUG2
# define PRINT_DEBUG2(...)              PRINT_DEBUG(__VA_ARGS__)
#else /* ! DEBUG2 */
# define PRINT_DEBUG2(...)
#endif /* ! DEBUG2 */

#endif /* TINYSTM_DEBUG_H_ */
