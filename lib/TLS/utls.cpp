/*
 * utls.cpp
 *
 *  Created on: Jul 22, 2013
 *      Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#include "TLS/tls.h"

#include "TLS/utls.h"

#include "page_hhash.h"

#include <cassert>  /* assert */
#include <cerrno>   /* ETIMEDOUT */
#include <cstdio>   /* perror */
#include <cstdlib>  /* abort */
#include <cstring>  /* memset */
#include <limits.h> /* IOV_MAX */
#include <new>      /* placement new */
#include <utility>  /* std::pair */
#include <sched.h>  /* clone */
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/wait.h> /* waitpid */

#ifdef __linux__
# include <fcntl.h> /* vmsplice */
#endif

#ifdef STANDALONE
# ifdef VERBOSE
#  define DEBUG(code) do { code; } while (0)
# else
#  define DEBUG(code) do { } while (0)
# endif
#else /* !STANDALONE */
# define DEBUG_TYPE "utls"
# include "llvm/Support/Debug.h"
#endif /* !STANDALONE */

using namespace TLS;

namespace {

struct utls_stats *get_stats() {
  static struct utls_stats *stats = nullptr;
  if (stats == nullptr) {
    stats = (struct utls_stats *)mmap(0, (sizeof(*stats) + 4095) & ~4095ULL,
                                      PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANON, -1, 0);
    if (stats == MAP_FAILED) {
      perror("mmap stats space");
      abort();
    }
  }
  return stats;
}

struct RangeToProtect {
    void *start;
    void *end;
    int wasReadable: 1;
    int wasWritable: 1;
    int wasExec: 1;
};

struct RunningTaskInformation {

    pid_t pid; // process id of the fork executing this task
    int pipe_read_end;
    int pipe_write_end;
    PageHashSet touchedPages;

    /* these values communicate to the parent how much to read from the pipe */
    uint32_t numReadRegions;
    uint32_t numWrittenRegions;

    pthread_mutex_t mutex;
    pthread_cond_t readyCond;
    unsigned ready:1;
    unsigned isReadSafe:1; // do not track read pages (because there is no speculative predecessor)

    RunningTaskInformation()
    : touchedPages(mmap, munmap), ready(0) {
        pthread_mutexattr_t mutexAttrs;
        pthread_mutexattr_init(&mutexAttrs);
        pthread_mutexattr_setpshared(&mutexAttrs, PTHREAD_PROCESS_SHARED);
        pthread_mutex_init(&mutex, &mutexAttrs);
        pthread_mutexattr_destroy(&mutexAttrs);

        pthread_condattr_t condAttrs;
        pthread_condattr_init(&condAttrs);
        pthread_condattr_setpshared(&condAttrs, PTHREAD_PROCESS_SHARED);
        pthread_cond_init(&readyCond, &condAttrs);
        pthread_condattr_destroy(&condAttrs);
    }
    ~RunningTaskInformation() {
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&readyCond);
    }

    void resetForRespawn() {
        // just reconstruct the hash set, the memory was only mapped into the child address space
        new (&touchedPages) PageHashSet(mmap, munmap);
        numReadRegions = 0;
        numWrittenRegions = 0;
        ready = 0;
    }
};

struct TlsChildInfo {
    TLSTask *task;
    int32_t numRangesToProtect;
    int (*mProtectFn)(void*, size_t, int);
    void *stack;
    uint32_t stackSize;
    RunningTaskInformation *runningTaskInformation;
    RangeToProtect rangesToProtect[1]; // grows beyond this object
};

struct MySmartMutex {
    pthread_mutex_t *mutex;
    MySmartMutex(pthread_mutex_t *mutex): mutex(mutex) {
        if (pthread_mutex_lock(mutex)) {
            perror("pthread_mutex_lock");
            abort();
        }
    }
    ~MySmartMutex() {
        if (pthread_mutex_unlock(mutex)) {
            perror("pthread_mutex_unlock");
            abort();
        }
    }
};

struct MySmartMutex2 {
    pthread_mutex_t *mutex;
    int (*pthread_mutex_lock_ptr)(pthread_mutex_t*);
    int (*pthread_mutex_unlock_ptr)(pthread_mutex_t*);

    MySmartMutex2(pthread_mutex_t *mutex, int (*lock_ptr)(pthread_mutex_t*), int (*unlock_ptr)(pthread_mutex_t*))
    : mutex(mutex), pthread_mutex_lock_ptr(lock_ptr), pthread_mutex_unlock_ptr(unlock_ptr) {
        if (pthread_mutex_lock_ptr(mutex)) {
            perror("pthread_mutex_lock");
            abort();
        }
    }
    ~MySmartMutex2() {
        if (pthread_mutex_unlock_ptr(mutex)) {
            perror("pthread_mutex_unlock");
            abort();
        }
    }
};

/* We need a global variable with all information which might be needed in the segfault handler.
 * This variable needs to be on it's own page, so that we avoid protecting this page but still
 * protect all other data.
 * The linker is not able to provide such a large alignment, so we manage this ourselves by
 * allocating a size of nearly two pages and just using the page-aligned part of it.
 */
char tlsChildInfoPage[2*4096-1];
#define GET_TLS_CHILDINFO() ((TlsChildInfo*) (((uint64_t) tlsChildInfoPage + 4095) & ~(uint64_t)4095))

/*
void flushTlb() {
    __asm__("movl %cr3, %0 \n"
         "movl %0, %cr3 \n");
}
*/

int32_t addRangeToProtect(uint64_t startAddr, uint64_t endAddr, char *access,
                          RangeToProtect *arr, int32_t capa, int32_t num,
                          const std::pair<void *, void *> *unprotectedRanges,
                          unsigned numUnprotectedRanges) {
  if (startAddr == endAddr)
    return num;

  for (auto *I = unprotectedRanges, *E = I + numUnprotectedRanges; I != E;
       ++I) {
    if (startAddr <= (uint64_t)I->first && endAddr >= (uint64_t)I->second) {
      num = addRangeToProtect(startAddr, (uint64_t)I->first, access, arr, capa,
                              num, unprotectedRanges, numUnprotectedRanges);
      if (num != -1)
        num = addRangeToProtect((uint64_t)I->second, endAddr, access, arr, capa,
                                num, unprotectedRanges, numUnprotectedRanges);
      return num;
    }
  }

  if (num == capa)
    return -1;

  arr[num].start = (void *)startAddr;
  arr[num].end = (void *)endAddr;
  arr[num].wasReadable = access[0] == 'r';
  arr[num].wasWritable = access[1] == 'w';
  arr[num].wasExec = access[2] == 'x';

  return num + 1;
}

int32_t
collectRangesToProtect(RangeToProtect *arr, int32_t capa,
                       const std::pair<void *, void *> *unprotectedRanges,
                       unsigned numUnprotectedRanges) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        perror("open /proc/self/maps");
        abort();
    }

    int32_t num = 0;
    char line[1024];
    while (!feof(maps)) {
        char *ret = fgets(line, sizeof(line), maps);
        if (ret != line) {
            if (feof(maps))
                break;
            perror("read /proc/self/maps");
            abort();
        }
        //printf("map line: %s", line);

        size_t startAddr, endAddr;
        char access[5];
        memset(access, 0, sizeof(access));
        int found = sscanf(line, "%zx-%zx %4s ", &startAddr, &endAddr, access);
        if (found != 3) {
            fprintf(stderr, "/proc/self/maps: line does not match expected format: %s\n", line);
            abort();
        }

        if (((unsigned)startAddr & 4095) || ((unsigned)endAddr & 4095)) {
            fprintf(stderr, "start/end not multiple of page size.\n");
            abort();
        }

        if (access[1] != 'w') {
            continue;
        }

        if (access[3] == 's') {
            continue;
        }

        num = addRangeToProtect(startAddr, endAddr, access, arr, capa, num,
                                unprotectedRanges, numUnprotectedRanges);
        if (num == -1)
            break;

    }
    // don't close this file handle right now. if we do, we lose a memory mapping ;)
    //fclose(maps);
    DEBUG(printf("Collected %d memory ranges to protect.\n", num); fflush(stdout));
    return num;
}

void protectMemory(const TlsChildInfo *info) {
    int (*mProtectFn)(void*, size_t, int) = info->mProtectFn;
    for (const RangeToProtect *r = info->rangesToProtect, *e = r + info->numRangesToProtect; r != e; ++r) {
        int newAccess = PROT_NONE;
        if (info->runningTaskInformation->isReadSafe)
            newAccess |= PROT_READ | PROT_EXEC;

        //printf("protecting writable range: %p - %p with access %x\n",
        //        r->start, r->end, newAccess);
        //fflush(stdout);
        int error = mProtectFn(r->start, (size_t)r->end - (size_t)r->start, newAccess);
        if (error) {
            // ignore this for now. somehow, some memory gets
            // unmapped between the fork and here...
            //perror("mprotect writable range");
        }
    }
}

struct sigaction oldSegvHandler;
void segvHandler(int sig, siginfo_t *info, void *) {

    // Take care not to touch any possibly protected memory before unprotecting
    // the requested page.

    size_t pageAddr = ((uint64_t) info->si_addr & ~4095);

    TlsChildInfo *tlsInfo = GET_TLS_CHILDINFO();
    RunningTaskInformation *runInfo = tlsInfo->runningTaskInformation;
    int newProtection;
    if (runInfo->isReadSafe) {
        (runInfo->touchedPages.*runInfo->touchedPages.add_ptr)(pageAddr, 1);
        //runInfo->touchedPages.add(pageAddr, 1);
        newProtection = PROT_EXEC | PROT_READ | PROT_WRITE;
    } else {
        uint8_t inserted = (runInfo->touchedPages.*runInfo->touchedPages.add_or_upgrade_ptr)(pageAddr);
        assert (inserted && "page was written before. why this segfault??\n");
        assert (inserted == 1 || inserted == 2);
        newProtection = inserted == 1 ? PROT_EXEC | PROT_READ
                                      : PROT_EXEC | PROT_READ | PROT_WRITE;
    }

    int error = tlsInfo->mProtectFn((void*) pageAddr, 4096, newProtection);
    if (error) {
        perror("mprotect unprotecting a page");
        abort();
    }

    assert (sig == SIGSEGV && "wrong signal");
    assert (info->si_code == SEGV_ACCERR && "wrong signal code");
}

void registerSegvHandler() {
    struct sigaction act;
    act.sa_sigaction = segvHandler;
    act.sa_flags = SA_SIGINFO | SA_RESTART;
    if (sigaction(SIGSEGV, &act, &oldSegvHandler) == -1) {
        perror("sigaction");
        abort();
    }
}

int pageLessOrEqual(void **a, void **b) {
  int read1 = (uint64_t) * a & 1;
  int read2 = (uint64_t) * b & 1;
  if (read1 != read2)
    return read1 > read2;
  return *a <= *b;
}

void swapPages(void **a, void **b) {
  void *ptr1 = *a;
  *a = *b;
  *b = ptr1;
}

void quicksort(void **left, void **right) {
  if (left + 1 >= right)
    return;

  void **leftPtr = left;
  void **rightPtr = right;
  while (1) {
    do {
      ++leftPtr;
    } while (leftPtr != rightPtr && pageLessOrEqual(leftPtr, left));
    do {
      --rightPtr;
    } while (!pageLessOrEqual(rightPtr, left));
    if (leftPtr >= rightPtr)
      break;
    swapPages(leftPtr, rightPtr);
  }

  swapPages(left, rightPtr);

  quicksort(left, rightPtr);
  quicksort(rightPtr + 1, right);
}

void collectReadAndWrittenRanges(void* *readPages, uint32_t numPages,
        uint32_t *numRegionsRead, uint32_t *numRegionsWritten, iovec *pageRanges, int32_t rangeCapa) {
    quicksort(readPages, readPages + numPages);

    int32_t numReadRanges = 0;
    int32_t numWrittenRanges = 0;

    for (uint32_t i = 0; i < numPages; ) {
        void *firstPage = readPages[i];
        uint32_t num = 1;
        while (i + num < numPages && readPages[i + num] == (char*)firstPage + num * 4096)
            ++num;
        if ((uint64_t) firstPage & 1)
            ++numReadRanges;
        else
            ++numWrittenRanges;
        assert (numReadRanges + numWrittenRanges <= rangeCapa);
        pageRanges->iov_base = (char*)((uint64_t)firstPage & ~((uint64_t)1));
        pageRanges->iov_len = 4096 * num;
        ++pageRanges;
        i += num;
    }

    *numRegionsRead = numReadRanges;
    *numRegionsWritten = numWrittenRanges;
}

int runTLSChild(void * /*unused*/) {
    TlsChildInfo *info = GET_TLS_CHILDINFO();


    //printf("In tls child.\n"); fflush(stdout);

    DEBUG(printf("child process id: %d (parent %d), read safe: %d\n", getpid(),
                 getppid(), info->runningTaskInformation->isReadSafe);
          fflush(stdout));

#ifndef NDEBUG
    char *secondsStr = getenv("TLS_SLEEP");
    int sleepSeconds = secondsStr ? atoi(secondsStr) : 0;
    if (sleepSeconds) {
      printf("Waiting for %d seconds...\n", sleepSeconds);
      fflush(stdout);
      sleep(sleepSeconds);
      printf("Continuing...\n");
      fflush(stdout);
    }
#endif

    //printf("Registering SEGV handler.\n"); fflush(stdout);

    registerSegvHandler();

    //printf("Protecting all memory.\n"); fflush(stdout);

    //printf("From this moment on, the child should be quiet ;)\n"); fflush(stdout);

    // Make the pointers volatile, so that the compiler is really forced to compute them here, before
    // protecting the memory. A compiler memory barrier did not do the job.
    volatile auto mmap_ptr = mmap;
    volatile auto pthread_cond_signal_ptr = pthread_cond_signal;
    volatile auto pthread_mutex_lock_ptr = pthread_mutex_lock;
    volatile auto pthread_mutex_unlock_ptr = pthread_mutex_unlock;
    volatile auto write_ptr = write;
#ifdef __linux__
    volatile auto vmsplice_ptr = vmsplice;
#endif

    asm volatile("": : :"memory");

    protectMemory(info);

    //printf("Running user function.\n"); fflush(stdout);

    info->task->function(info->task->getInputData(), info->task->getOutputData());

    //printf("User function finished. Communicating changed pages.\n"); fflush(stdout);

    // Reserve some scratch space for:
    // * read and written pages (touchedPages * sizeof(void*))
    // * read and written ranges (touchedPages * sizeof(iovec))
    //   -> typically not fully used
    size_t numTouchedPages = info->runningTaskInformation->touchedPages.m;
    size_t allocatedSize =
        (numTouchedPages * (sizeof(iovec) + sizeof(void *)) + 4095UL) & ~4095UL;
    void *scratch = allocatedSize == 0
                        ? 0
                        : mmap_ptr(0, allocatedSize, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANON, -1, 0);
    if (scratch == MAP_FAILED) {
        perror("mmap scratch space");
        abort();
    }
    void** touchedPages = (void**) scratch;
    int32_t numPages = (info->runningTaskInformation->touchedPages.*
                        info->runningTaskInformation->touchedPages.get_all_ptr)(
        touchedPages, numTouchedPages);
    assert(numPages >= 0 && (size_t)numPages == numTouchedPages &&
           "more pages appeared in touchedPages set during collection");
    iovec *touchedRanges = (iovec*)((void**)scratch + numTouchedPages);
    uint32_t numReadRanges = 0;
    uint32_t numWrittenRanges = 0;
    collectReadAndWrittenRanges(touchedPages, numPages, &numReadRanges,
                                &numWrittenRanges, touchedRanges,
                                numTouchedPages);
    info->runningTaskInformation->numReadRegions = numReadRanges;
    info->runningTaskInformation->numWrittenRegions = numWrittenRanges;

    {
        MySmartMutex2 lock(&info->runningTaskInformation->mutex,
                           pthread_mutex_lock_ptr, pthread_mutex_unlock_ptr);
        info->runningTaskInformation->ready = 1;
        if (pthread_cond_signal_ptr(&info->runningTaskInformation->readyCond)) {
            perror("pthread_cond_signal readyCond");
            abort();
        }
    }

    size_t bytesToWrite = (numReadRanges + numWrittenRanges) * sizeof(iovec);
    size_t written = 0;
    while (written < bytesToWrite) {
      ssize_t newWritten =
          write_ptr(info->runningTaskInformation->pipe_write_end,
                    ((char *)touchedRanges) + written, bytesToWrite - written);
      if (newWritten < 1) {
        perror(newWritten == 0 ? "no more bytes written"
                               : "error writing to pipe");
        abort();
      }
      written += newWritten;
      assert(written <= bytesToWrite);
    }

    // Now the actual memory pages.
#ifdef __linux__
    // Use vmsplice in linux

    iovec *nextRange = touchedRanges + numReadRanges;
    uint32_t rangesRemaining = info->runningTaskInformation->numWrittenRegions;

    while (rangesRemaining) {
        size_t nr_regs = rangesRemaining > IOV_MAX ? IOV_MAX : rangesRemaining;
        ssize_t bytesOrError =
            vmsplice_ptr(info->runningTaskInformation->pipe_write_end,
                         nextRange, nr_regs, SPLICE_F_GIFT);
        if (bytesOrError == -1) {
          fprintf(stderr, "vmsplice modified pages to pipe (fd %d): %s\n",
                  info->runningTaskInformation->pipe_write_end, strerror(errno));
          abort();
        }
        size_t numBytes = bytesOrError;
        assert ((numBytes & 4095) == 0 && "Should always splice whole pages");
        if (numBytes == 0) {
            perror("no more bytes to splice");
            abort();
        }
        while (numBytes) {
            if (numBytes >= nextRange->iov_len) {
                numBytes -= nextRange->iov_len;
                --rangesRemaining;
                ++nextRange;
                assert (numBytes == 0 || rangesRemaining);
            } else {
                nextRange->iov_base = (char*) nextRange->iov_base + numBytes;
                nextRange->iov_len -= numBytes;
                numBytes = 0;
            }
        }
    }
#else
    for (iovec *range = touchedRanges + numReadRanges,
            *rangeEnd = range + numWrittenRanges; range != rangeEnd; ++range) {
        char *ptr = static_cast<char*>(range->iov_base);
        size_t bytesRemaining = range->iov_len;
        while (bytesRemaining) {
            size_t bytesWritten = write_ptr(info->pipe_write_end, ptr, bytesRemaining);
            if (bytesWritten == 0) {
                perror("no more bytes written"); abort();
            }
            assert (bytesWritten <= bytesRemaining);
            bytesRemaining -= bytesWritten;
        }
    }
#endif

    //fflush(stdout);

    //printf("Exiting child.\n"); fflush(stdout);

    return 0;
}

void spawnTask() {
    TlsChildInfo *childInfo = GET_TLS_CHILDINFO();

    __sync_fetch_and_add(&get_stats()->num_tasks, 1);

    // Open a pipe for communication with this child (child writes, parent reads).
    int childPipe[2];
    if (pipe(childPipe)) {
        perror("pipe");
        abort();
    }
    DEBUG(printf("pipe: (%d, %d)\n", childPipe[0], childPipe[1]); fflush(stdout));

    childInfo->runningTaskInformation->pipe_read_end = childPipe[0];
    childInfo->runningTaskInformation->pipe_write_end = childPipe[1];

    char *topOfStack = (char *)childInfo->stack + childInfo->stackSize;

    pid_t pid = clone(runTLSChild, topOfStack,
                      CLONE_FILES | CLONE_FS | CLONE_IO | SIGCHLD, nullptr);
    if (pid < 0) {
        perror("fork UTLS child.");
        abort();
    }

    //printf("forked child %d: PID %d\n", childInfo->task->seqNr, pid); fflush(stdout);

    childInfo->runningTaskInformation->pid = pid;
}

void respawnTask() {
    TlsChildInfo *childInfo = GET_TLS_CHILDINFO();
    RunningTaskInformation *runInfo = childInfo->runningTaskInformation;
    // kill old process
    kill(runInfo->pid, SIGKILL);
    // wait for it to die
    int status;
    waitpid(runInfo->pid, &status, 0);

    // Close both ends of the old pipe
    if (close(runInfo->pipe_read_end)) {
        perror("close reading pipe end for respawn");
        abort();
    }
    if (close(runInfo->pipe_write_end)) {
        perror("close writing pipe end for respawn");
        abort();
    }

    runInfo->resetForRespawn();

    // now spawn a fresh task
    spawnTask();
}

void waitForChildren(const RunningTaskInformation *taskInfo, size_t from, size_t end) {
    for (; from < end; ++from) {
        pid_t pid = taskInfo[from].pid;
        int status;
        pid_t signalledPid = waitpid(pid, &status, 0);
        assert (pid == signalledPid || signalledPid == -1);
        if (signalledPid == -1) {
            // check if the child still exists:
            if (!kill(pid, 0)) {
                perror("can kill child, but not wait for it");
                abort();
            }
        } else if (WIFEXITED(status)) {
            /* OK */
        } else if (WIFSIGNALED(status)) {
            /* We use SIGKILL to terminate the tls children, as they should not run any
             * destructors or exit handlers.
             * So ignore SIGKILL. */
            if (WTERMSIG(status) != SIGKILL) {
                fprintf(stderr, "child %zu (pid %d) was killed by signal %d.\n", from, pid, WTERMSIG(status));
                abort();
            }
        } else {
            fprintf(stderr, "unknown status: %d\n", status);
            abort();
        }
    }
}

void runTasks(TaskList *list) {
    uint32_t numTasks = list->getNumTasks();
    // Store information about the spawned children in a shared page:
    uint32_t sizeForRunningTaskInformation =
        (numTasks * sizeof(RunningTaskInformation) + 4095) & ~4095;
    if (sizeForRunningTaskInformation == 0)
      sizeForRunningTaskInformation = 4096;
    void *runningTaskInformationPages =
        mmap(0, sizeForRunningTaskInformation, PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_ANON, -1, 0);
    if (runningTaskInformationPages == MAP_FAILED) {
        perror("mmap runningTaskInformation");
        abort();
    }
    RunningTaskInformation *runningTaskInformation = (RunningTaskInformation*) runningTaskInformationPages;
    for (uint32_t i = 0; i < numTasks; ++i)
        new (&runningTaskInformation[i]) RunningTaskInformation();

    // Compute the ranges to protect here in the parent task.
    // Put the child info into the private page.
    TlsChildInfo *childInfo = GET_TLS_CHILDINFO();

    // Get a direct pointer to the mprotect function.
    childInfo->mProtectFn = mprotect;

    // make sure that stats are allocated
    get_stats();

    fflush(stdout);
    fflush(stderr);

    // printf("Collecting memory mapping...\n"); fflush(stdout);

    char *alignedTaskInfo =
        (char *)((uint64_t)childInfo->runningTaskInformation & ~4095ULL);
    std::pair<void *, void *> unprotectedRanges[] = {
      std::make_pair(childInfo, (char *)childInfo + 4096),
      std::make_pair(alignedTaskInfo, alignedTaskInfo + 4096),
      std::make_pair(childInfo->stack,
                     (char *)childInfo->stack + childInfo->stackSize),
      std::make_pair(runningTaskInformationPages,
                     (char *)runningTaskInformationPages +
                         sizeForRunningTaskInformation),
    };
    unsigned numUnprotectedRanges =
        sizeof(unprotectedRanges) / sizeof(*unprotectedRanges);

    int32_t memoryRangeCapacity =
        ((uint64_t)childInfo + 4096 - (uint64_t)(childInfo->rangesToProtect)) /
        sizeof(RangeToProtect);
    // printf("capacity for memory ranges: %d\n", memoryRangeCapacity);
    childInfo->numRangesToProtect =
        collectRangesToProtect(childInfo->rangesToProtect, memoryRangeCapacity,
                               unprotectedRanges, numUnprotectedRanges);
    if (childInfo->numRangesToProtect == -1) {
      fprintf(stderr, "memory ranges to protect exceed capacity of %d\n",
              memoryRangeCapacity);
      abort();
    }

    // Now allocate a new stack, so that the different tasks don't collide on
    // that.
    size_t stackSize = 1 << 22;
    void *stack = mmap(0, stackSize, PROT_READ | PROT_WRITE,
                       MAP_ANON | MAP_PRIVATE, 0, 0);
    if (stack == MAP_FAILED) {
      perror("mmap task stack");
      abort();
    }
    // printf("new stack: %p\n", stack); fflush(stdout);

    childInfo->stack = stack;
    childInfo->stackSize = stackSize;

    {
        TLSTask *task = list->getFirstTask();
        for (uint32_t i = 0; i < numTasks; ++i, task = task->next()) {
            childInfo->task = task;
            childInfo->runningTaskInformation = &runningTaskInformation[i];
            childInfo->runningTaskInformation->isReadSafe = i == 0;
            spawnTask();
        }
    }

    // Track all modified pages in this structure:
    PageHashSet modifiedPages(mmap, munmap);

    DEBUG(printf("waiting for all children...\n"); fflush(stdout));
    TLSTask *task = list->getFirstTask();
    size_t touchedRegionsBytes = 0;
    iovec *touchedRegions = nullptr;
    for (uint32_t i = 0; i < numTasks; ) {
        DEBUG(printf("child %d...\n", i); fflush(stdout));
        RunningTaskInformation *thisTaskInfo = &runningTaskInformation[i];
        MySmartMutex lock(&thisTaskInfo->mutex);
        DEBUG(printf("isready? --> %d\n", thisTaskInfo->ready); fflush(stdout));
        int status;
        pid_t pid = 0;
        while (!thisTaskInfo->ready) {
            struct timespec timeToWait;
            struct timeval now;
            gettimeofday(&now, 0);

            timeToWait.tv_sec = now.tv_sec+1;
            timeToWait.tv_nsec = now.tv_usec * 1000ul;

            int ret = pthread_cond_timedwait(
                &thisTaskInfo->readyCond, &thisTaskInfo->mutex, &timeToWait);
            if (ret != 0 && ret != ETIMEDOUT) {
                perror("pthread_cond_wait");
                abort();
            }
            DEBUG(printf("isready? --> %d\n", thisTaskInfo->ready);
                  fflush(stdout));
            /*
            if (kill(thisTaskInfo->pid, 0)) {
                perror("kill child");
            }
            */
            if (pid != 0) {
                if (pid != thisTaskInfo->pid) {
                    fprintf(stderr, "waitpid (for child %d) returned %d.\n", thisTaskInfo->pid, pid);
                    abort();
                }
                if (WIFEXITED(status)) {
                    fprintf(stderr, "child %d exited normally.\n", pid);
                    abort();
                }
                if (WIFSIGNALED(status)) {
                    fprintf(stderr, "child %d was killed by signal %d.\n", pid, WTERMSIG(status));
                    abort();
                }
            }
            pid = waitpid(thisTaskInfo->pid, &status, WNOHANG);
        }
        DEBUG(printf("child %d is ready. checking for conflicts.\n", i);
              fflush(stdout));
        DEBUG(printf("child %d touched %d pages (hash array size %d). %d "
                     "regions read, %d regions read+written.\n",
                     i, thisTaskInfo->touchedPages.size(),
                     thisTaskInfo->touchedPages.capacity(),
                     thisTaskInfo->numReadRegions,
                     thisTaskInfo->numWrittenRegions);
              fflush(stdout));

        struct timeval time_before_conflict_checking;
        gettimeofday(&time_before_conflict_checking, nullptr);

        // Now first read the pages describing the changed memory, then the actual memory pages.
        size_t numTouchedRegions =
            thisTaskInfo->numReadRegions + thisTaskInfo->numWrittenRegions;
        size_t thisTouchedRegionsBytes = numTouchedRegions * sizeof(iovec);
        if (thisTouchedRegionsBytes > touchedRegionsBytes) {
          size_t newAllocate = thisTouchedRegionsBytes - touchedRegionsBytes;
          if (touchedRegionsBytes > newAllocate)
            newAllocate = touchedRegionsBytes;
          newAllocate = (newAllocate + 4095) & ~4095ULL;
          void *newMapping =
              mmap((char *)touchedRegions + touchedRegionsBytes, newAllocate,
                   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
          if (touchedRegions == MAP_FAILED) {
            perror("mmap touched regions");
            abort();
          }
          if (touchedRegionsBytes == 0)
            touchedRegions = (iovec*)newMapping;
          touchedRegionsBytes += newAllocate;
        }
        size_t bytesRead = 0;
        while (bytesRead < thisTouchedRegionsBytes) {
          ssize_t newBytesRead =
              read(thisTaskInfo->pipe_read_end,
                   ((char *)touchedRegions) + bytesRead,
                   thisTouchedRegionsBytes - bytesRead);
          if (newBytesRead <= 0) {
            fprintf(stderr,
                    "could not read more bytes from pipe. %ld out of %ld "
                    "bytes left.\n",
                    thisTouchedRegionsBytes - bytesRead, touchedRegionsBytes);
            fflush(stderr);
            abort();
          }
          bytesRead += newBytesRead;
        }

        // Verify read memory pages.
        int valid = 1;
        if (!thisTaskInfo->isReadSafe &&
            (thisTaskInfo->numReadRegions || thisTaskInfo->numWrittenRegions) &&
            modifiedPages.size()) {
          DEBUG(printf("Verifying read regions...\n"); fflush(stdout));
          // Note: also the modified pages might have been read...
          for (iovec *reg = touchedRegions, *end = reg + numTouchedRegions;
               reg != end && valid; ++reg) {
            uint64_t pageAddr = (uint64_t)reg->iov_base;
            DEBUG(printf("  - %p   (%lu bytes == %lu page%s)\n",
                         (void *)pageAddr, reg->iov_len, reg->iov_len / 4096,
                         reg->iov_len == 4096 ? "" : "s"));
            assert((reg->iov_len & 4095) == 0);
            for (size_t pagesRemaining = reg->iov_len >> 12; pagesRemaining;
                 --pagesRemaining, pageAddr += 4096) {
              if (modifiedPages.get(pageAddr)) {
                DEBUG(
                    printf("page %p was modified before.\n", (void *)pageAddr));
                valid = 0;
                break;
              }
            }
          }
        }

        struct timeval time_after_conflict_checking;
        gettimeofday(&time_after_conflict_checking, nullptr);
        DEBUG(printf("conflict checking took %.2f seconds\n",
                     (time_after_conflict_checking.tv_sec -
                      time_before_conflict_checking.tv_sec) +
                         1e-6 * (time_after_conflict_checking.tv_usec -
                                 time_before_conflict_checking.tv_usec)));

        if (!valid) {
            __sync_fetch_and_add(&get_stats()->num_rollbacks, 1);

            waitForChildren(runningTaskInformation, 0, i);
            fflush(stdout); fflush(stderr);
            childInfo->task = task;
            childInfo->runningTaskInformation = &runningTaskInformation[i];
            childInfo->runningTaskInformation->isReadSafe = 1;
            respawnTask();
            continue;
        }

        DEBUG(printf("Writing back modified regions...\n"); fflush(stdout));

        //char old[4096];
        // Now read the modified memory pages.
        for (iovec *reg = touchedRegions, *end = reg + numTouchedRegions;
             reg != end; ++reg) {
            // Add to modified set
            uint64_t pageAddr = (uint64_t) reg->iov_base;
            for (size_t pagesRemaining = reg->iov_len >> 12; pagesRemaining; --pagesRemaining, pageAddr += 4096)
                if (!modifiedPages.get(pageAddr))
                    modifiedPages.add(pageAddr, 0);

            char *memPtr = static_cast<char*>(reg->iov_base);
            size_t bytesRemaining = reg->iov_len;
            DEBUG(printf("  - %p   (%lu bytes == %lu page%s)\n", (void *)memPtr,
                         bytesRemaining, bytesRemaining / 4096,
                         bytesRemaining == 4096 ? "" : "s");
                  fflush(stdout));
            //memcpy(old, memPtr, 4096);
            while (bytesRemaining > 0) {
                size_t newBytes = read(thisTaskInfo->pipe_read_end, memPtr, bytesRemaining);
                if (newBytes == 0) {
                    fprintf(stderr, "child %d (pid %d) sent no more bytes. expecting %zd more.\n",
                            i, thisTaskInfo->pid, bytesRemaining);
                    abort();
                }
                memPtr += newBytes;
                bytesRemaining -= newBytes;
            }
            //char *newP = static_cast<char *>(reg->iov_base);
            //for (int i = 0; i < 4096; ++i) {
            //  if (old[i] != newP[i]) {
            //    printf("changed byte at %p: %02x -> %02x\n", (void *)(newP + i),
            //           (int)(old[i]), (int)(newP[i]));
            //  }
            //}
        }

        // Then close both ends of the pipe
        if (close(thisTaskInfo->pipe_read_end)) {
            perror("close read pipe after reading modified pages");
            abort();
        }
        if (close(thisTaskInfo->pipe_write_end)) {
            perror("close write pipe after reading modified pages");
            abort();
        }

        struct timeval time_after_commit;
        gettimeofday(&time_after_commit, nullptr);

        get_stats()->micros_conflict_checking +=
            1000000UL * (time_after_conflict_checking.tv_sec -
                         time_before_conflict_checking.tv_sec) +
            time_after_conflict_checking.tv_usec -
            time_before_conflict_checking.tv_usec;
        get_stats()->micros_commit +=
            1000000UL * (time_after_commit.tv_sec -
                         time_after_conflict_checking.tv_sec) +
            time_after_commit.tv_usec - time_after_conflict_checking.tv_usec;

        // continue with next child:
        ++i;
        task = task->next();
    }

    if (touchedRegionsBytes > 0) {
      if (munmap(touchedRegions, touchedRegionsBytes) != 0) {
        perror("munmap touched regions");
        abort();
      }
    }

    DEBUG(printf("validated all children. waiting for them to exit.\n"); fflush(stdout));
    waitForChildren(runningTaskInformation, 0, numTasks);
    DEBUG(printf("all children completed.\n"); fflush(stdout));

    for (uint32_t i = 0; i < numTasks; ++i) {
        runningTaskInformation[i].~RunningTaskInformation();
    }

    if (munmap(runningTaskInformationPages, sizeForRunningTaskInformation) != 0) {
        perror("munmap runningTaskInformation");
        abort();
    }

}

} // anonymous namespace

extern "C" {

    void utls_reset_stats() { memset(get_stats(), 0, sizeof(*get_stats())); }

    struct utls_stats utls_get_stats() { return *get_stats(); }

    void utls_run(void *list0) {
        TaskList *list = (TaskList*) list0;

        // Ensure that we move to a new page on the stack.
        // We do this in assembly and then call the runTasks function.
        // Note: the runTasks function gets a different name on Mac and Linux, so just
        // call it indirectly via the rax register.
        // Also note: we can only use %rsp, since -fomit-frame-pointer might be active.
        // Otherwise, it would be sufficient to move %rsp to a different page than %rbp.
        // On the other hand, it should not make any difference, since this function
        // does not use stack variables :)
        asm volatile (
                // Compute offset of the current stack page (in callee-saved register, needed later!)
                "mov $0x0fff, %%ebx;\n" // resets the upper 32 bit
                "and %%rsp, %%rbx;\n"
                // Reset these bits in %rsp
                "xor %%rbx, %%rsp;\n"
                "call *%0;\n"
                // Restore %rsp
                "or %%rbx, %%rsp;\n"
                : /* output */
                : /* input */ "r" (runTasks), "D" /* 1st param in rdi */ (list)
                : /* clobbered */ "rbx", "memory"
        );
    }

}
