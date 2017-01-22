/*
 * files.h
 *
 *  Created on: Jun 18, 2014
 *      Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#ifndef FILES_H_
#define FILES_H_

#include <string>
#include <utility>
#include <vector>

#include "util.h"

struct Mapping {
    MyString filename;
    char *start;
    size_t len;
    Mapping(): filename(nullptr, 0), start(0), len(0) { }
    Mapping(const Mapping &other) // copy constructor (unfortunately) needed by tbb
    : filename(other.filename), start(other.start), len(other.len) { }
    Mapping(const MyString &filename, char *start, size_t len)
    : filename(filename), start(start), len(len) { }
    Mapping(Mapping &&other)
    : filename(std::move(other.filename)), start(other.start), len(other.len) { }
};

Mapping mapFile(const std::string &filename, bool useMmap);

void closeMapping(const Mapping &map, bool useMmap);

void searchFiles(const std::string &directory, std::vector<std::string> &files);

#endif /* FILES_H_ */
