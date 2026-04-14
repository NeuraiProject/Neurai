// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_SUPPORT_ALLOCATORS_SECURE_H
#define NEURAI_SUPPORT_ALLOCATORS_SECURE_H

#include "support/lockedpool.h"
#include "support/cleanse.h"

#include <string>
#include <vector>

//
// Allocator that locks its contents from being paged
// out of memory and clears its contents before deletion.
//
template <typename T>
struct secure_allocator : public std::allocator<T> {
    typedef std::allocator<T> base;
    typedef std::size_t size_type;
    typedef std::ptrdiff_t difference_type;
    typedef T value_type;
    secure_allocator() noexcept {}
    secure_allocator(const secure_allocator& a) noexcept : base(a) {}
    template <typename U>
    secure_allocator(const secure_allocator<U>& a) noexcept : base(a)
    {
    }
    ~secure_allocator() noexcept {}

    T* allocate(std::size_t n, const void* hint = 0)
    {
        return static_cast<T*>(LockedPoolManager::Instance().alloc(sizeof(T) * n));
    }

    void deallocate(T* p, std::size_t n)
    {
        if (p != nullptr) {
            memory_cleanse(p, sizeof(T) * n);
        }
        LockedPoolManager::Instance().free(p);
    }
};

// This is exactly like std::string, but with a custom allocator.
typedef std::basic_string<char, std::char_traits<char>, secure_allocator<char> > SecureString;
typedef std::vector<unsigned char, secure_allocator<unsigned char> >             SecureVector;

#endif // NEURAI_SUPPORT_ALLOCATORS_SECURE_H
