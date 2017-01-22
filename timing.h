/*
 * timing.h
 *
 *  Created on: Jun 22, 2014
 *      Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#ifndef TIMING_H_
#define TIMING_H_

#include <algorithm>
#include <functional>
#include <vector>
#include <sys/time.h>

class Timing {
    std::vector<long> microSeconds; // per run
    bool sorted = false;

    void sort() {
        if (sorted)
            return;
        sorted = true;
        std::sort(microSeconds.begin(), microSeconds.end());
    }

public:

    void addTiming(long microSecs) {
        microSeconds.push_back(microSecs);
        sorted = false;
    }

    const std::vector<long> &allMicros() {
        sort();
        return microSeconds;
    }

    long minMicros() {
        sort();
        return microSeconds.empty() ? -1 : microSeconds.front();
    }

    long maxMicros() {
        sort();
        return microSeconds.empty() ? -1 : microSeconds.back();
    }

    long medianMicros() {
        sort();
        return microSeconds.empty() ? -1 : microSeconds.at(microSeconds.size() / 2);
    }

    long avgMicros() {
        if (microSeconds.empty())
            return -1;
        long sum = 0;
        for (long l : microSeconds)
            sum += l;
        return sum / microSeconds.size();
    }
};

class TimedRuns : public Timing {
    struct NoCode {
        void operator()() const { }
    };

    template<typename T, typename V>
    static inline void runTeardownFunction(const T &func, unsigned long micros, void (T::*)(V) const) {
        func(micros);
    }
    template<typename T>
    static inline void runTeardownFunction(const T &func, unsigned long, void (T::*)() const) {
        func();
    }

public:
    // No setup, no teardown
    template<typename RunFunc>
    TimedRuns(unsigned numRuns, const RunFunc &runFunction)
    : TimedRuns(numRuns, runFunction, NoCode(), NoCode()) { }

    // Setup only
    template<typename RunFunc, typename SetupFunc>
    TimedRuns(unsigned numRuns, const RunFunc &runFunction, const SetupFunc &setupFunction)
    : TimedRuns(numRuns, runFunction, setupFunction, NoCode()) { }

    // Setup and Teardown
    template<typename RunFunc, typename SetupFunc, typename TeardownFunc>
    TimedRuns(unsigned numRuns, const RunFunc &runFunction,
            const SetupFunc &setupFunction = NoCode(),
            const TeardownFunc &teardownFunction = NoCode()) {
        for (unsigned run = 0; run < numRuns; ++run) {
            setupFunction();
            timeval start, end;
            gettimeofday(&start, nullptr);

            runFunction();

            gettimeofday(&end, nullptr);
            unsigned long micros = (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;

            // run teardown function with either 0 or 1 argument
            runTeardownFunction(teardownFunction, micros, &TeardownFunc::operator());

            addTiming(micros);
        }
    }

};


#endif /* TIMING_H_ */
