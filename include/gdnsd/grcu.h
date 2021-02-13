/* Copyright © 2021 Brandon L Black <blblack@gmail.com>
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

/***************************************************************************
 * This provides an abstract interface "grcu_*" which, in normal builds, is
 * just a thin renaming of the userspace-rcu QSBR API calls we use.  It also
 * gives us some "GRCU_*" macros that wrap RCU-protected variables in hidden
 * structures to protect them from accidental non-API accesses.
 *
 * If the special define GDNSD_USE_GRCU_C11A is set for a build, it will switch
 * the code over from using userspace-rcu to using the alternate QSBR
 * implementation defined in this file.  This alternate implementation should
 * not be used for production builds, as it's generally inferior to the
 * userspace-rcu library in a number of important ways.  The primary reason for
 * its existence is that it [somewhat inefficiently] implements QSBR-style RCU
 * purely in terms of C11 atomics, and thus enables us to exercise the code for
 * QA purposes with thread data race checkers such as gcc's ThreadSanitizer,
 * which otherwise don't comprehend what's going on in the case of
 * userspace-rcu and thus would fail in ways that aren't meaningful.
 ****************************************************************************/

#ifndef GDNSD_GRCU_H
#define GDNSD_GRCU_H

#include <gdnsd/compiler.h>

#ifndef GDNSD_USE_GRCU_C11A

// Normal case: just pass through to the real urcu library:
#include <urcu-qsbr.h>

// All RCU-accessed variables must be created with these GRCU_* macros, and
// can only be accessed via grcu_* functions.  These use a hidden struct to
// ensure no accidental raw references to the underlying storage occur:
// _t is the type, _n is the name, and _i is the initial value

// For use as a field within a struct:
#define GRCU_FIELD(_t,_n) struct { _t val_; } _n
// For use as a static file-scope global:
#define GRCU_STATIC(_t,_n,_i) static struct { _t val_; } _n = { .val_ = _i }
// For split use as a global with an extern decl in a header
#define GRCU_PUB_DECL(_t,_n) extern struct _n##_s_ { _t val_; } _n;
#define GRCU_PUB_DEF(_n,_i) struct _n##_s_ _n = { .val_ = _i }

// This allows the owner (writer) thread, in the case of a single-writer-thread
// var (which is always the case in gdnsd), to read its own data without an
// explicit dereference and any pointless barriers that entails:
#define GRCU_OWN_READ(_n) ((_n).val_)

// .. And these are the usual userspace-rcu API:
#define grcu_register_thread() rcu_register_thread()
#define grcu_thread_online() rcu_thread_online()
#define grcu_quiescent_state() rcu_quiescent_state()
#define grcu_read_lock() rcu_read_lock()
#define grcu_dereference(s) rcu_dereference(((s).val_))
#define grcu_read_unlock() rcu_read_unlock()
#define grcu_thread_offline() rcu_thread_offline()
#define grcu_unregister_thread() rcu_unregister_thread()
#define grcu_assign_pointer(d, s) rcu_assign_pointer(((d).val_), (s))
#define grcu_synchronize_rcu() synchronize_rcu()

#else // GDNSD_USE_GRCU_C11A

// tsan case: use our toy substitute based on C11 Atomics!
// Known deficiencies vs better qsbr impls:
// 1. Reader thread registry is not a very efficient implementation, but it's
//    good enough for a smaller and fairly static list of threads.
// 2. No real debuggability or validation - it doesn't even track whether
//    threads are read-locking or registering properly.
// 2. Uses C11 "acquire" for rcu_deref.  This should in theory be "consume",
//    but "consume" has dependency-tracking issues that need standards-level
//    action AFAIK.  "acquire" is cheap on strongly-ordered systems like
//    x86_64, but costs more than it should need to on weak ones like ARM/PPC.
// 3. No grace batching is implemented; writer grace periods are
//    non-overlapping and serialized in whatever order they happen to grab a
//    mutex.  Kinda ok for our model of truly rare updates, but still...
// 4. The writer grace loop just uses nanosleep()s between scans of the
//    thread registry until it observes all readers have moved to the new
//    epoch, as opposed to some fancy wakeup scheme.  The nanosleep value
//    starts at 1ms and doubles until it flatlines at 16ms.  It does unlock the
//    thread registry while sleeping.
// 5. Writers can't be registered readers.
//
// XXX Writer-batching and writers-being-readers should be solveable without too much effort!

#define GRCU_FIELD(_t,_n) struct { _Atomic(_t) val_; } _n
#define GRCU_STATIC(_t,_n,_i) static struct { _Atomic(_t) val_; } _n = { .val_ = _i }
#define GRCU_PUB_DECL(_t,_n) extern struct _n##_s_ { _Atomic(_t) val_; } _n;
#define GRCU_PUB_DEF(_n,_i) struct _n##_s_ _n = { .val_ = _i }
#define GRCU_OWN_READ(_n) atomic_load_explicit(&((_n).val_), memory_order_relaxed)

#define grcu_register_thread() grcu_c11a_register_thread()
#define grcu_thread_online() grcu_c11a_thread_online()
#define grcu_quiescent_state() grcu_c11a_quiescent_state()
#define grcu_read_lock() ((void)(0))
#define grcu_dereference(s) atomic_load_explicit(&((s).val_), memory_order_acquire)
#define grcu_read_unlock() ((void)(0))
#define grcu_thread_offline() grcu_c11a_thread_offline()
#define grcu_unregister_thread() grcu_c11a_unregister_thread()
#define grcu_assign_pointer(d, s) atomic_store_explicit(&((d).val_), (s), memory_order_release)
#define grcu_synchronize_rcu() grcu_c11a_synchronize_rcu()

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdalign.h>
#include <pthread.h>
#include <time.h>

extern _Thread_local atomic_uintptr_t grcu_c11a_reader_epoch;

extern atomic_uintptr_t grcu_c11a_writer_epoch;
extern pthread_mutex_t grcu_c11a_writer_epoch_lock;

typedef struct {
    atomic_uintptr_t** readers;
    unsigned count;
} grcu_c11a_registry_t;
extern grcu_c11a_registry_t grcu_c11a_registry;
extern pthread_mutex_t grcu_c11a_reg_lock;

F_UNUSED
static void grcu_c11a_quiescent_state(void)
{
    const uintptr_t cur_epoch = atomic_load_explicit(&grcu_c11a_writer_epoch, memory_order_relaxed);
    const uintptr_t my_epoch = atomic_load_explicit(&grcu_c11a_reader_epoch, memory_order_relaxed);
    if (cur_epoch != my_epoch)
        atomic_store_explicit(&grcu_c11a_reader_epoch, cur_epoch, memory_order_release);
}

F_UNUSED
static void grcu_c11a_thread_online(void)
{
    atomic_store_explicit(&grcu_c11a_reader_epoch,
                          atomic_load_explicit(&grcu_c11a_writer_epoch, memory_order_relaxed),
                          memory_order_release);
}

F_UNUSED
static void grcu_c11a_thread_offline(void)
{
    atomic_store_explicit(&grcu_c11a_reader_epoch, 0, memory_order_release);
}

void grcu_c11a_register_thread(void);
void grcu_c11a_unregister_thread(void);
void grcu_c11a_synchronize_rcu(void);

#endif // GDNSD_USE_GRCU_C11A
#endif // GDNSD_GRCU_H
