/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
 *
 * This file is part of gdnsd.
 *
 * gdnsd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * gdnsd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gdnsd.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef GDNSD_COMPILER_H
#define GDNSD_COMPILER_H

// With "zig cc" driving things, we can flat-out assume clang-19 here!

// Headers for compiler features we can take advantage of with C11 broadly:
#include <stdnoreturn.h>
#include <stdalign.h>
#include <assert.h>

#define F_PRINTF(X, Y)  __attribute__((__format__(__printf__, X, Y)))
#define F_NONNULLX(...) __attribute__((__nonnull__(__VA_ARGS__)))
#define F_NONNULL       __attribute__((__nonnull__))
#define HAVE_BUILTIN_CLZ 1
#define GDNSD_HAVE_UNREACH_BUILTIN 1
#define likely(_x)      __builtin_expect(!!(_x), 1)
#define unlikely(_x)    __builtin_expect(!!(_x), 0)
#define V_UNUSED        __attribute__((__unused__))
#define F_UNUSED        __attribute__((__unused__))
#define F_CONST         __attribute__((__const__))
#define F_PURE          __attribute__((__pure__))
#define F_MALLOC        __attribute__((__malloc__)) __attribute__((__warn_unused_result__))
#define F_NOINLINE      __attribute__((__noinline__))
#define F_WUNUSED       __attribute__((__warn_unused_result__))
#define F_DEPRECATED    __attribute__((__deprecated__))
#define F_ALLOCSZ(...)  __attribute__((__alloc_size__(__VA_ARGS__)))
#define F_HOT           __attribute__((__hot__))
#define F_COLD          __attribute__((__cold__))
#define F_RETNN         __attribute__((__returns_nonnull__))
#define F_ALLOCAL(_x)   __attribute__((__alloc_align__((_x))))

#define PRAG_(x) _Pragma(#x)
#define GDNSD_DIAG_PUSH_IGNORED(x) _Pragma("clang diagnostic push") \
                                   PRAG_(clang diagnostic ignored x)
#define GDNSD_DIAG_POP             _Pragma("clang diagnostic pop")
#define GDNSD_HAVE_ASSUME_BUILTIN 1

// Unaligned memory access stuff

#include <inttypes.h>
#include <string.h>

F_UNUSED F_NONNULL
static uint16_t gdnsd_get_una16(const uint8_t* p)
{
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

F_UNUSED F_NONNULL
static uint32_t gdnsd_get_una32(const uint8_t* p)
{
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

F_UNUSED F_NONNULL
static void gdnsd_put_una16(const uint16_t v, uint8_t* p)
{
    memcpy(p, &v, sizeof(v));
}

F_UNUSED F_NONNULL
static void gdnsd_put_una32(const uint32_t v, uint8_t* p)
{
    memcpy(p, &v, sizeof(v));
}

// Generic useful macros
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#endif // GDNSD_COMPILER_H
