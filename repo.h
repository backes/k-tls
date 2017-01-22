/*
 * repo.h
 *
 *  Created on: Jun 18, 2014
 *      Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#ifndef REPO_H_
#define REPO_H_

#include <cstring> // for memcmp
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "hashmap.h"
#include "util.h"

enum Type {
    VARIABLE,
    FUNCTION,
};

class Symbol {
public:
    MyString name;
    Type type;

    Symbol(const char *_name, size_t _nameLen, Type _type)
    : name(_name, _nameLen), type(_type) { }

    Symbol(const Symbol &other)
    : name(other.name), type(other.type) { }

    Symbol(Symbol &&other)
    : name(std::move(other.name)), type(other.type) { }

    bool operator==(const Symbol &other) const {
        return type == other.type && name == other.name;
    }
};

struct SymbolHash {
    size_t operator() (const Symbol &sym) const {
        size_t hash = sym.name.hash();
        hash ^= (size_t)sym.type;
        return hash;
    }
};

inline std::ostream &operator<<(std::ostream &out, const Symbol &symbol) {
    return out << (symbol.type == VARIABLE ? "variable '" : "function '")
               << symbol.name << "'";
}

class Location {
public:
    MyString filename;
    unsigned lineNr;
    unsigned colNr;
    Location() { }
    Location(const char *filename, size_t filenameLen, unsigned lineNr, unsigned colNr)
    : filename(filename, filenameLen), lineNr(lineNr), colNr(colNr) { }
    Location(Location &&other)
    : Location() {
        swap(other);
    }
    Location(const Location &other)
    : filename(other.filename), lineNr(other.lineNr), colNr(other.colNr) { }

    Location &operator=(Location other) {
        swap(other);
        return *this;
    }
    void swap(Location &other) {
        filename.swap(other.filename);
        std::swap(lineNr, other.lineNr);
        std::swap(colNr, other.colNr);
    }
};

inline std::ostream &operator<<(std::ostream &out, const Location &loc) {
    return out << loc.filename << ":" << loc.lineNr
               << ":" << loc.colNr;
}

using Locations = MyVector<Location>;
using SymLocsMap = HashMap<Symbol, Locations, SymbolHash>;

class SymbolRepo {

    SymLocsMap definitions;

    SymLocsMap uses;

public:

    TRANSACTION_SAFE
    void addUse(Symbol sym, Location loc) {
        Locations *locs = uses.get(sym);
        if (!locs)
            locs = &uses.putIfAbsent(sym, Locations()).value;
        locs->push_back(std::move(loc));
    }

    TRANSACTION_SAFE
    void addDefinition(Symbol sym, Location loc) {
        Locations *locs = definitions.get(sym);
        if (!locs)
            locs = &definitions.putIfAbsent(sym, Locations()).value;
        locs->push_back(std::move(loc));
    }

    size_t countDefinitions() const {
        //return definitions.size();
        size_t size = 0;
        for (auto I = definitions.begin(), E = definitions.end(); I != E; ++I)
            ++size;
        return size;
    }

    size_t countUses() const {
        //return uses.size();
        size_t size = 0;
        for (auto I = uses.begin(), E = uses.end(); I != E; ++I)
            ++size;
        return size;
    }

    void clear() {
        definitions.clear();
        uses.clear();
    }

    void printAll(std::ostream &out) const {
        out << "Definitions:" << std::endl;
        for (auto &def : definitions) {
            out << "  - " << def.key << " in [";
            bool first = true;
            for (auto &loc : def.value) {
                out << (first ? "" : ", ") << loc;
                first = false;
            }
            out << "]" << std::endl;
        }

        out << "Uses:" << std::endl;
        for (auto &use : uses) {
            out << "  - " << use.key << " in [";
            bool first = true;
            for (auto &loc : use.value) {
                out << (first ? "" : ", ") << loc;
                first = false;
            }
            out << "]" << std::endl;
        }
    }
};

#endif /* REPO_H_ */
