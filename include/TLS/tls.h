/*
 * tls.h
 *
 *  Created on: Apr 7, 2013
 *      Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#ifndef TLS_TLS_H_
#define TLS_TLS_H_

#ifdef __cplusplus

# include <cstdint>
extern "C" {

#else /* __cplusplus */

# include <stdint.h> // uint16_t, uint32_t, ... */

#endif /* __cplusplus */

/**
 * Create a new task list.
 */
void* tls_newList(void);

/**
 * Add a task to tasklist, and return pointer to first input element.
 * Parameters:
 * task list, input size, output size, function to call
 */
char *tls_addTask(void *, uint16_t, uint16_t, void (*)(void *, void *));

/**
 * Free a list.
 */
void tls_deleteList(void*);

/**
 * Get the start pointer of a task list.
 */
void* tls_getTasks(void*);

/**
 * Get the end pointer of a task list.
 */
void* tls_getTasksEnd(void*);

#ifdef __cplusplus
} /* extern "C" */

namespace TLS {

/**
 * This struct represents a single task to be executed in TLS.
 * It contains the function to be called, the input size, output size, and
 * the actual input and output just behind the end of this struct.
 * The next TLSTask follows after all this data, padded to an 8 byte boundary.
 *
 * Caution: If the layout of this struct is changed, to also change
 * the code in KTLS which reads this struct from user space.
 */
struct TLSTask {
    uint16_t inputSize;
    uint16_t outputSize;
    void (*function)(void *, void *);

    TLSTask(uint16_t inputSize, uint16_t outputSize,
            void (*function)(void *, void *))
        : inputSize(inputSize), outputSize(outputSize), function(function) {
          /* nop */
    }

    /**
     * Return the next task in the list.
     * The caller ensures that he stops after numTasks tasks.
     */
    TLSTask *next() {
      return (TLSTask *)(((uint64_t) this + sizeof(*this) + inputSize +
                          outputSize + 7) &
                         ~7UL);
    }

    char *getInputData() {
        return (char*) this + sizeof(*this);
    }

    char *getOutputData() {
        return (char*) this + sizeof(*this) + inputSize;
    }

    void run() {
        function(getInputData(), getOutputData());
    }
};

class TaskList {

    uint32_t numTasks;

    TLSTask *firstTask;
    char *nextTask;
    char *endTasks;

public:

    TaskList(): numTasks(0), firstTask(0), nextTask(0), endTasks(0) { /* nop */ }

    ~TaskList();

    /**
     * Add a task to this list, and return a pointer to it.
     * function is a pointer to the non-instrumented version of task code,
     * Some execution models need both, i.e. if first transactified execution is
     * tried, and non-transactional code is executed sequentially as fallback.
     */
    TLSTask *addTask(uint16_t inputSize, uint16_t outputSize,
                     void (*function)(void *, void *));

    /**
     * Get a pointer to the first task. Use TLSTask::next to traverse the list.
     */
    TLSTask *getFirstTask() const {
        return firstTask;
    }

    /**
     * Get the number of tasks in this list.
     */
    uint32_t getNumTasks() const {
        return numTasks;
    }

    /**
     * Get a pointer past the end of the list.
     * This can be used if the whole list has to be copied.
     */
    TLSTask *getEnd() {
        return (TLSTask*) nextTask;
    }
};

} /* namespace TLS */

#endif /* __cplusplus */

#endif /* TLS_TLS_H_ */
