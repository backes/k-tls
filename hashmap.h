#ifndef __INCLUDE_HASHMAP_H
#define __INCLUDE_HASHMAP_H

/**
 * A simple and efficient hashmap implementation.
 * It is optimized for small keys and values, since even nonused buckets have the size to hold a key, value and other information.
 *
 * Author: Clemens Hammacher
 */

#include <stdexcept>
#include <cassert>
#include <string>

#include "sambamba/Transactifier/CxxInterface.h"

// maximum number of nodes in a bucket before enlarging the hashset
#define MAX_CHAIN 3

template<typename K> struct DefaultEquals;

template<typename K, typename V, typename HashCode, typename Equals = DefaultEquals<K>, unsigned numPreallocated = 0>
class HashMap {

public:

	class Node : public TransactionSafeObject {
	public:
		K key;
		V value;

	private:
		friend class HashMap;
		Node* next;

	public:
		Node(const K &key, const V &value, Node* next = 0)
		: key(key), value(value), next(next) { };
		Node(Node &&other)
		: key(std::move(other.key)), value(std::move(other.value)), next(0) { };

        /*
		Node& operator=(const Node &other) {
			key = other.key;
			value = other.value;
			next = 0;
			return *this;
		}
        */
	};

private:
	template<typename ThisType, typename ValueType, typename HashMapType>
	class IteratorBase {

		friend class HashMap;

		HashMapType *map;
		Node *tableNode, *curNode;

		void moveOn() {
			if (curNode->next) {
				curNode = curNode->next;
			} else {
				Node* endNode = map->table + map->tableSize;
				while (++tableNode != endNode) {
					if (tableNode->next != tableNode) {
						break;
					}
				}
				curNode = tableNode;
			}
		}

	protected:
		IteratorBase(HashMapType* map)
		: map(map), tableNode(map->table) {
			Node* endNode = tableNode + map->tableSize;
			while ((tableNode != endNode) && (tableNode->next == tableNode))
				++tableNode;
			curNode = tableNode;
		}

		IteratorBase(HashMapType* map, Node *tableNode, Node *curNode)
		: map(map), tableNode(tableNode), curNode(curNode) {
		}

	public:

		ValueType& operator*() {
			return *curNode;
		}

		ValueType* operator->() {
			return curNode;
		}

		ThisType& operator++() { // Prefix
			moveOn();
			return *static_cast<ThisType*>(this);
		}
		ThisType operator++(int) { // Postfix
			ThisType old = *this;
			moveOn();
			return old;
		}

		bool operator==(const ThisType &it2) {
			return curNode == it2.curNode;
		}

		bool operator!=(const ThisType &it2) {
			return curNode != it2.curNode;
		}

		/**
		 * Removes the current element (returned by operator*) and returns an iterator to
		 * the next element (which is the same as the old iterator).
		 */
		ThisType& remove() {
			assert (!((curNode == tableNode) && (curNode->next == curNode)));
			if ((curNode == tableNode) && !curNode->next) {
				Node* old = curNode;
				moveOn();
				old->next = old;
				old->~Node();
			} else if (Node* next = curNode->next) {
				curNode->key = next->key;
				curNode->value = next->value;
				curNode->next = next->next;
				delete next;
			} else {
				// damn, then we have to search for the current node again, starting at the table node
				// (we are somewhere deeper in a bucket and have no successor)
				Node* lastNode = tableNode;
				while (lastNode->next != curNode)
					lastNode = lastNode->next;
				lastNode->next = 0;
				delete curNode;
				moveOn();
			}
			--map->_size;
			return *static_cast<ThisType*>(this);
		}

	};

public:
	class ConstIterator : public IteratorBase<ConstIterator, const Node, const HashMap> {

	public:
		ConstIterator(const HashMap* map)
		: IteratorBase<ConstIterator, const Node, const HashMap>(map) { }

		ConstIterator(const HashMap* map, Node *tableNode, Node *curNode)
		: IteratorBase<ConstIterator, const Node, const HashMap>(map, tableNode, curNode) { }

	};

	class Iterator : public IteratorBase<Iterator, Node, HashMap> {

	public:
		Iterator(HashMap* map)
		: IteratorBase<Iterator, Node, HashMap>(map) { }

		Iterator(HashMap* map, Node *tableNode, Node *curNode)
		: IteratorBase<Iterator, Node, HashMap>(map, tableNode, curNode) { }

		operator ConstIterator () {
			return ConstIterator(this->map, this->tableNode, this->curNode);
		}

	};

private:

	Node* table;
	size_t tableSize; // always a power of two

	// copied from SmallVectorImpl:
#ifdef __GNUC__
	typedef char U;
#else
	union U {
		double D;
		long double LD;
		long long L;
		void *P;
	};
#endif

	enum {
		tmp0 = numPreallocated,
        tmp1 = tmp0 | (tmp0 >>  1),
        tmp2 = tmp1 | (tmp1 >>  2),
        tmp3 = tmp2 | (tmp2 >>  4),
        tmp4 = tmp3 | (tmp3 >>  8),
        tmp5 = tmp4 | (tmp4 >> 16),
        tmp6 = (tmp5 - (tmp5 >> 1)) == numPreallocated ? numPreallocated : ((tmp5 << 1) - tmp5 + 1),
		numPreallocatedAsPowerOfTwo = (numPreallocated > 0 ? tmp6 : 0),
        /*
		defaultThreshold = numPreallocatedAsPowerOfTwo > 1 ? (numPreallocatedAsPowerOfTwo*3/4) :
				numPreallocatedAsPowerOfTwo == 1 ? 1 : 0,
        */

		// NumUs - The number of U's require to cover <numPreallocated> Nodes.
		NumUs = (static_cast<unsigned int>(sizeof(Node))*numPreallocatedAsPowerOfTwo +
				 static_cast<unsigned int>(sizeof(U)) - 1) /
				static_cast<unsigned int>(sizeof(U)),
		NumUsMinOne = NumUs > 1 ? NumUs : 1, // cannot allocate zero length array
	};
	U preallocated[NumUsMinOne];

	HashCode hasher;
	Equals equals;

    TRANSACTION_SAFE
	void enlargePenis() {
		if (tableSize == (1 << (8*sizeof(int)-2))) {
			exitFromTransaction("cannot enlarge hashmap further");
		}

        size_t newTableSize = tableSize < 8 ? 8 : tableSize * 2;

		Node* oldTable = table;
		size_t oldTableSize = tableSize;

		tableSize = newTableSize;
		table = (Node*)malloc(tableSize * sizeof(Node));
		if (!table) {
			exitFromTransaction("cannot enlarge hashmap (OOM)");
		}

		for (Node *newTableNode = table, *end=table+tableSize; newTableNode != end; ++newTableNode)
			newTableNode->next = newTableNode;
		for (Node* bucketPtr = oldTable, *end=oldTable+oldTableSize; bucketPtr != end; ++bucketPtr) {
			if (bucketPtr->next == bucketPtr)
				continue;
			transfer(bucketPtr, false);
			for (Node* node = bucketPtr->next; node; ) {
				Node* next = node->next; // node or next pointer may be destroyed during transfer
				transfer(node, true);
				node = next;
			}
		}
		if (reinterpret_cast<void*>(oldTable) != reinterpret_cast<void*>(&preallocated))
			free(oldTable);
	}

	void transfer(Node* oldNode, bool isInHeap) {
		int hash = hasher(oldNode->key);
		int offset = hash & (tableSize-1);
		Node* node = &table[offset];
		if (node->next == node) {
			// add there
			new (node) Node(std::move(*oldNode));
			if (isInHeap)
				delete oldNode;
			else
				oldNode->~Node();
		} else {
			// add node
            Node *newNode = oldNode;
            if (!isInHeap) {
                newNode = new Node(std::move(*oldNode));
                oldNode->~Node();
            }
            newNode->next = node->next;
            node->next = newNode;
		}
	}

    TRANSACTION_SAFE
	Node &put(const K &key, const V &value, bool overwrite) {
		if (!numPreallocatedAsPowerOfTwo && !tableSize) // note: if numPreallocatedAsPowerOfTwo > 0 then tableSize > 0
			enlargePenis();
		size_t hash = hasher(key);
		size_t offset = hash & (tableSize-1);
		Node *node = &table[offset];
		if (node->next == node) {
			new (node) Node(key, value, 0);
			return *node;
		} else {
            int length = 0;
			while (!equals(node->key, key)) {
                ++length;
				if (!node->next) {
				    if (length >= MAX_CHAIN) {
				        enlargePenis();
				        return put(key, value, overwrite);
				    }
					// add node
					Node* newNode = new Node(key, value);
					node->next = newNode;
					return *newNode;
				}
				node = node->next;
			}
			if (overwrite)
				node->value = value;
			return *node;
		}
	}

    TRANSACTION_SAFE
	Node* find(const K &key) const {
		if (!numPreallocatedAsPowerOfTwo && !tableSize) // note: if numPreallocatedAsPowerOfTwo > 0 then tableSize > 0
			return 0;
		int hash = hasher(key);
		int offset = hash & (tableSize-1);
		Node *node = &table[offset];
		if (node->next == node) {
			return 0;
		} else {
			while (!equals(node->key, key)) {
				if (!(node = node->next)) {
					return 0;
				}
			}
			return node;
		}
	}

public:

	HashMap()
	: table(reinterpret_cast<Node*>(&preallocated)), tableSize(numPreallocatedAsPowerOfTwo) {
		for (Node* node = table, *end = table+tableSize; node != end; ++node)
			node->next = node;
	}

	// copy constructor
	HashMap(const HashMap& other)
	: table(0), tableSize(0) {
		*this = other;
	}

	~HashMap() {
		for (Node* bucketPtr = table, *end = table+tableSize; bucketPtr != end; ++bucketPtr) {
			if (bucketPtr->next == bucketPtr)
				continue;
			for (Node* node = bucketPtr->next; node; ) {
				Node* next = node->next;
				delete node;
				node = next;
			}
			bucketPtr->~Node();
		}
		if (reinterpret_cast<void*>(table) != reinterpret_cast<void*>(&preallocated))
			free(table);
	}

	HashMap& operator=(const HashMap& other) {
		clear();
		for (ConstIterator it = other.begin(), end = other.end(); it != end; ++it)
			put(it->key, it->value);
		return *this;
	}

	void clear() {
		for (Node* bucketPtr = table, *end = table+tableSize; bucketPtr != end; ++bucketPtr) {
			if (bucketPtr->next == bucketPtr)
				continue;
			for (Node* node = bucketPtr->next; node; ) {
				Node* next = node->next;
				delete node;
				node = next;
			}
			bucketPtr->~Node();
			bucketPtr->next = bucketPtr;
		}
	}

	Node &put(const K &key, const V &value) {
		return put(key, value, true);
	}

    TRANSACTION_SAFE
	Node &putIfAbsent(const K &key, const V &value) {
		return put(key, value, false);
	}

	bool remove(const K &key) {
		if (!numPreallocatedAsPowerOfTwo && !tableSize) // note: if numPreallocatedAsPowerOfTwo > 0 then tableSize > 0
			return false;
		size_t hash = hasher(key);
		size_t offset = hash & (tableSize-1);
		Node *node = &table[offset];
		if (node->next == node) {
			return false;
		} else {
			Node* lastNode = node;
			while (!equals(node->key, key)) {
				lastNode = node;
				if (!(node = node->next)) {
					return false;
				}
			}
			if (node == lastNode) {
				// then this is a direct table node
				if (node->next) {
					Node* old = node->next;
					node->key = old->key;
					node->value = old->value;
					node->next = old->next;
					delete old;
				} else {
					node->next = node;
					node->~Node();
				}
			} else {
				lastNode->next = node->next;
				delete node;
			}
			return true;
		}
	}

	bool containsKey(const K &key) const {
		return find(key);
	}

	V* get(const K &key) const {
		Node* entry = find(key);
		return entry ? &entry->value : 0;
	}

	Iterator begin() {
		return Iterator(this);
	}

	Iterator end() {
		return Iterator(this, table, table + tableSize);
	}

	ConstIterator begin() const {
		return ConstIterator(this);
	}

	ConstIterator end() const {
		return ConstIterator(this, table, table + tableSize);
	}

};

template<typename IntType = size_t>
struct IntHasher {
	size_t operator() (IntType i) const {
		// this code is copied from the java hashmap
		size_t h = static_cast<size_t>(i);
		h ^= (h >> 20) ^ (h >> 12);
		h ^= (h >> 7) ^ (h >> 4);
		return h;
	}
};

template<typename K>
struct DefaultEquals {
    bool operator() (const K &k1, const K &k2) const {
        return k1 == k2;
    }
};

typedef IntHasher<const void*> IdentityPtrHasher;

struct StringHasher {
	size_t operator() (const std::string &s) const {
		// this code is copied from the java hashmap
		size_t h = s.length();
		for (std::string::const_iterator it = s.begin(), itEnd = s.end(); it != itEnd; ++it)
			h = 31*h + *it;
		return h;
	}
};

template<typename PtrType, typename ValueType, unsigned numPreallocated = 0>
struct PtrMap {
	typedef HashMap<PtrType*, ValueType, IdentityPtrHasher, DefaultEquals<PtrType*>, numPreallocated> T;
};
template<typename ValueType, typename IntType = int, unsigned numPreallocated = 0>
struct IntMap {
	typedef HashMap<IntType, ValueType, IntHasher<IntType>, DefaultEquals<IntType>, numPreallocated> T;
};
template<typename ValueType, unsigned numPreallocated = 0>
struct StringMap {
	typedef HashMap<std::string, ValueType, StringHasher, DefaultEquals<std::string>, numPreallocated> T;
};

#endif // __INCLUDE_HASHMAP_H
