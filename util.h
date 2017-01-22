/*
 * util.h
 *
 *  Created on: Jun 20, 2014
 *      Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#ifndef UTIL_H_
#define UTIL_H_

#include <iostream>

// memcmp and strcmp are not transaction-safe, so we just use this implementation
inline bool cmpStr(const char *str1, const char *str2, size_t len) {
    while (len--)
        if (*str1++ != *str2++)
            return false;
    return true;
}

inline size_t mystrlen(const char *str) {
    const char *p = str;
    while (*p++);
    return p - str;
}


// std::string is not transaction-safe, so we just implement our own
struct MyString {
    char *data;
    size_t len;

    using iterator = char*;
    using const_iterator = const char*;

    MyString(): data(0), len(0) { }

    MyString(const char *_str)
    : MyString(_str, mystrlen(_str)) { }

    MyString(const std::string &str)
    : MyString(str.data(), str.length()) { }

    MyString(const char *_data, size_t _len)
    : data(_len == 0 ? 0 : (char *)malloc(_len+1)), len(_len) {
        if (_len == 0)
            return;
        // memcpy is also not transaction-safe, so just copy manually ;)
        char *dst = data;
        for (const char *src = _data, *end = src + _len; src != end; ++src, ++dst)
            *dst = *src;
        *dst = 0;
    }

    MyString(const MyString &other)
    : MyString(other.data, other.len) { }

    MyString(MyString &&other)
    : MyString() {
        swap(other);
    }

    ~MyString() {
        if (data)
            free(data);
    }

    bool operator==(const MyString &other) const {
        return len == other.len && cmpStr(data, other.data, len);
    }

    MyString &operator=(MyString other) {
        swap(other);
        return *this;
    }

    void swap(MyString &other) {
        std::swap(data, other.data);
        std::swap(len, other.len);
    }

    iterator       begin()       { return data; }
    iterator       end()         { return data + len; }
    const_iterator begin() const { return data; }
    const_iterator end()   const { return data + len; }

    size_t hash() const {
        size_t hash = 0;
        for (char c : *this)
            hash = 31 * hash + (size_t)c;
        return hash;
    }
};

inline static std::ostream &operator<<(std::ostream &out, const MyString &str) {
    if (str.data)
        out << str.data;
    return out;
}

// transaction-safe variant of std::vector (with just the functionality we need right now)
template<typename T>
class MyVector {
    T *data;
    size_t size;
    size_t capacity;

    void ensureCapacity(size_t needed) {
        if (capacity >= needed)
            return;
        size_t newCapacity = std::max(capacity * 2, needed);
        T *newData = reinterpret_cast<T*>(malloc(sizeof(T) * newCapacity));
        if (data) {
            for (T *src = data, *end = data+size, *dst = newData; src != end; ++src, ++dst) {
                new (dst) T(std::move(*src));
                src->~T();
            }
            free(data);
        }
        data = newData;
        capacity = newCapacity;
    }

public:

    using iterator = T*;
    using const_iterator = const T*;

    MyVector(): data(0), size(0), capacity(0) { }
    MyVector(const MyVector<T> &other)
    : data (other.empty() ? 0 : reinterpret_cast<T*>(malloc(sizeof(T)*other.size))),
      size(other.size),
      capacity(size) {
        for (T *src = other.data, *end = src + other.size, *dst = data; src < end; ++src, ++dst)
            new (dst) T(*src);
    }
    MyVector(MyVector &&other)
    : MyVector() {
        swap(other);
    }

    ~MyVector() {
        if (!data)
            return;
        for (T &elem : *this)
            elem.~T();
        free(data);
    }

    MyVector &operator=(MyVector other) {
        swap(other);
        return *this;
    }

    void swap(MyVector &other) {
        std::swap(data, other.data);
        std::swap(size, other.size);
        std::swap(capacity, other.capacity);
    }

    void push_back(T val) {
        ensureCapacity(size + 1);
        new (data+size) T(std::move(val));
        ++size;
    }

    iterator begin() {
        return data;
    }
    iterator end() {
        return data+size;
    }
    const_iterator begin() const {
        return data;
    }
    const_iterator end() const {
        return data+size;
    }

    bool empty() const {
        return size == 0;
    }

    void clear() {
        *this = MyVector();
    }
};

#endif /* UTIL_H_ */
