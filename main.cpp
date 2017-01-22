/*
 * main.cpp
 *
 *  Created on: Jun 18, 2014
 *      Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#include "files.h"
#include "indexer.h"
#include "repo.h"
#include "timing.h"

#include "sambamba/Transactifier/CxxInterface.h"

#include "tbb/parallel_do.h"
#include "tbb/task_scheduler_init.h"

#include <cstring>
#include <iostream>

namespace { // anonymous

void indexFiles(Indexer &indexer, const std::vector<Mapping> &mappings, unsigned numThreads,
        MyVector<ParseError> &parseErrors) {
    if (numThreads == 0) {
        for (auto &mapping : mappings) {
            indexer.indexFile(mapping, parseErrors);
        }
        return;
    }

    tbb::task_scheduler_init sched(numThreads);

    auto parallel_index = [&](const Mapping &mapping) {
        TRANSACTION_ATOMIC(
            indexer.indexFile(mapping, parseErrors);
        );
    };
    tbb::parallel_do(mappings.begin(), mappings.end(), parallel_index);
}

void outputTiming(const char *msg, Timing &timing) {
    std::cout << msg << ": min " << timing.minMicros()
              << ", max " << timing.maxMicros()
              << ", avg " << timing.avgMicros()
              << ", median " << timing.medianMicros()
              << std::endl;
}

} // anonymous namespace

int main(int argc, const char **argv) {

    int argStart = 1;

    bool printIndex = false;
    bool printEachRun = false;
    bool useMmap = false;

    // 0 means sequential (untransactified), >0 means with stm support
    unsigned threads = 0;

    while (argStart < argc) {
        if (!strcmp(argv[argStart], "-m")) {
            useMmap = true;
        } else if (!strcmp(argv[argStart], "-p")) {
            printIndex = true;
        } else if (!strcmp(argv[argStart], "-t")) {
            threads = atoi(argv[++argStart]);
        } else if (!strcmp(argv[argStart], "-v")) {
            printEachRun = true;
        } else
            break;
        ++argStart;
    }

    std::cout << "Searching for *.c files in " << (argc - argStart)
              << " directories..." << std::endl;

    std::vector<std::string> files;

    for (int i = argStart; i < argc; ++i)
        searchFiles(argv[i], files);

    std::cout << "Opening " << files.size() << " files..." << std::endl;

    // memory map the files
    std::vector<Mapping> mappings;
    mappings.reserve(files.size());
    for (int i = 0, e = files.size(); i != e; ++i) {
        if (i && i % 10000 == 0)
          std::cout << i << "... " << std::endl;
        auto mapping = mapFile(files[i], useMmap);
        if (mapping.start == nullptr) {
          std::cerr << "Error: cannot open file '" << files[i] << "'."
                    << std::endl;
            exit(1);
        }
        mappings.push_back(std::move(mapping));
    }

    char *numRunsStr = getenv("NUM_RUNS");
    unsigned numRuns = numRunsStr ? std::stoul(numRunsStr) : 10;

    SymbolRepo repo;
    MyVector<ParseError> parseErrors;

    std::cout << "Running initial run..." << std::endl;

    // do one warmup run (warm up caches, read in the files)
    TimedRuns initialRun(1, [&] {
        Indexer indexer(repo);
        indexFiles(indexer, mappings, 0, parseErrors);
    });
    outputTiming("Initial run", initialRun);

    std::cout << "Running " << numRuns << " measured runs..." << std::endl;

    Timing readOverhead, writeOverhead, initOverhead, commitOverhead,
        rollbackOverhead, codeRollbackOverhead, overallCPUTime, numCommits,
        numRollbacks, numIncomplete, avgNanos, rollbackRatePerMille, avgReadset,
        avgWriteset;

    clock_t clockAtStart;
    TimedRuns runs(numRuns, [&] {
        repo.clear();
        //repo.~SymbolRepo();
        //new (&repo) SymbolRepo();
        parseErrors.clear();

        Indexer indexer(repo);

        // process the files (optionally in different threads)
        indexFiles(indexer, mappings, threads, parseErrors);
    }, [&] {
        clockAtStart = clock();
    }, [&](unsigned long micros) {
        clock_t clockCycles = clock() - clockAtStart;
        // after each execution, print the micros if requested
        if (printEachRun)
            std::cout << "Finished a run in " << micros << " microseconds." << std::endl;

        // and store the stm timings
        transaction_stats stats = TRANSACTION_GET_STATS();
        TRANSACTION_RESET_STATS();

        readOverhead.addTiming(stats.nanos_in_read);
        writeOverhead.addTiming(stats.nanos_in_write);
        initOverhead.addTiming(stats.nanos_in_init);
        commitOverhead.addTiming(stats.nanos_in_commit);
        rollbackOverhead.addTiming(stats.nanos_in_rollback);
        codeRollbackOverhead.addTiming(stats.nanos_in_rollbacked_code);
        overallCPUTime.addTiming((uint64_t)clockCycles * 1000000 / CLOCKS_PER_SEC);

        numCommits.addTiming(stats.num_commits);
        numRollbacks.addTiming(stats.num_rollbacks);
        numIncomplete.addTiming(stats.num_incomplete);
        uint64_t numTxs = stats.num_commits + stats.num_rollbacks + stats.num_incomplete;
        rollbackRatePerMille.addTiming(numTxs == 0 ? 0 : stats.num_rollbacks * 1000 / numTxs);
        avgReadset.addTiming(numTxs == 0 ? 0 : stats.sum_readset / numTxs);
        avgWriteset.addTiming(numTxs == 0 ? 0 : stats.sum_writeset / numTxs);
    });

    // close the memory mappings
    for (auto &mapping : mappings) {
        closeMapping(mapping, useMmap);
    }

    // output any discovered parse errors
    if (!parseErrors.empty()) {
        std::cout << "Parse errors:" << std::endl;
        for (ParseError &err : parseErrors)
            std::cout << "  - " << err.loc << ": " << err.message << std::endl;
    }

    std::cout << "Found an overall of " << repo.countDefinitions()
              << " symbol definitions and " << repo.countUses()
              << " usages." << std::endl;

    if (printIndex)
        repo.printAll(std::cout);

    outputTiming("Time per run (micros)", runs);
    outputTiming("In init", initOverhead);
    outputTiming("In commit", commitOverhead);
    outputTiming("In read", readOverhead);
    outputTiming("In write", writeOverhead);
    outputTiming("In rollback", rollbackOverhead);
    outputTiming("In rollbacked code", codeRollbackOverhead);
    outputTiming("Overall CPU time", overallCPUTime);

    outputTiming("Num commits", numCommits);
    outputTiming("Num rollbacks", numRollbacks);
    outputTiming("Num incomplete", numIncomplete);
    outputTiming("Rollback rate (per mille)", rollbackRatePerMille);
    outputTiming("Avg nanos per tx", avgNanos);
    outputTiming("Avg read set size", avgReadset);
    outputTiming("Avg write set size", avgWriteset);
}

