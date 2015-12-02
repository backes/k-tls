/*
 * tls.cpp
 *
 *  Created on: Apr 7, 2013
 *      Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#include "TLS/tls.h"

#include <sys/mman.h>

#include <cassert> /* assert */
#include <cstdio>  /* perror */
#include <cstdlib> /* abort */
#include <cstring> /* memcpy */
#include <new>     /* placement new */

using namespace TLS;

TaskList::~TaskList() {
  if (firstTask != 0) {
    size_t size = endTasks - (char *)firstTask;
    if (munmap(firstTask, size)) {
      perror("munmap task space");
      abort();
    }
  }
}

TLSTask *TaskList::addTask(uint16_t inputSize, uint16_t outputSize,
        void (*function)(void*,void*)) {
    char *next = (char*) ((uint64_t)(nextTask + sizeof(TLSTask) + inputSize + outputSize + 7) & ~7UL);
    if (next > endTasks) {
        size_t oldSize = endTasks - (char*) firstTask;
        size_t newSize = oldSize * 2;
        if (newSize < 4096)
            newSize = 4096;
        // TODO this is good for the UTLS, but KTLS does not need it. so it's additional overhead there.
        char *newTaskSpace = (char*) mmap(0, newSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
        if (newTaskSpace == MAP_FAILED) {
            perror("mmap task space");
            abort();
        }
        if (oldSize != 0) {
            memcpy(newTaskSpace, firstTask, oldSize);
            if (munmap(firstTask, oldSize)) {
                perror("munmap task space");
                abort();
            }
        }
        endTasks = newTaskSpace + newSize;
        nextTask = newTaskSpace + (nextTask - (char*) firstTask);
        firstTask = (TLSTask*) newTaskSpace;
        next = (char*) ((uint64_t)(nextTask + sizeof(TLSTask) + inputSize + outputSize + 7) & ~7UL);
    }
    assert (next <= endTasks);
    new (nextTask) TLSTask(inputSize, outputSize, function);
    TLSTask *newTask = (TLSTask*) nextTask;
    nextTask = next;
    ++numTasks;
    return newTask;
}

extern "C" {

    void* tls_newList() {
        return new TaskList();
    }

    char *tls_addTask(void *list0, uint16_t inputSize, uint16_t outputSize,
                      void (*fun)(void *, void *)) {
        TaskList *list = (TaskList*) list0;
        TLSTask *task = list->addTask(inputSize, outputSize, fun);
        return task->getInputData();
    }

    void tls_deleteList(void *list0) {
        TaskList *list = (TaskList*) list0;
        delete list;
    }

    void *tls_getTasks(void *list0) {
        TaskList *list = (TaskList*) list0;
        return list->getFirstTask();
    }

    void *tls_getTasksEnd(void *list0) {
        TaskList *list = (TaskList*) list0;
        return list->getEnd();
    }

}
