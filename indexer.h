/*
 * indexer.h
 *
 *  Created on: Jun 18, 2014
 *      Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#ifndef INDEXER_H_
#define INDEXER_H_

#include "files.h"
#include "repo.h"
#include "util.h"

struct ParseError {
    Location loc;
    const char *message;
    ParseError(Location loc, const char *message)
    : loc(std::move(loc)), message(message) { }
};

class Indexer {
    SymbolRepo &repo;

public:
    Indexer(SymbolRepo &repo): repo(repo) { }

    TRANSACTION_SAFE
    void indexFile(const Mapping &mapping, MyVector<ParseError> &parseErrors);

};

#endif /* INDEXER_H_ */
