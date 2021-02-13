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

#include <config.h>

#ifdef GDNSD_USE_GRCU_C11A

#include <gdnsd/grcu.h>

_Thread_local atomic_uintptr_t grcu_c11a_reader_epoch = 0U;
pthread_mutex_t grcu_c11a_writer_epoch_lock = PTHREAD_MUTEX_INITIALIZER;
atomic_uintptr_t grcu_c11a_writer_epoch = 1U;
pthread_mutex_t grcu_c11a_reg_lock = PTHREAD_MUTEX_INITIALIZER;
grcu_c11a_registry_t grcu_c11a_registry = { NULL, 0 };

void grcu_c11a_register_thread(void)
{
    pthread_mutex_lock(&grcu_c11a_reg_lock);
    unsigned i = 0;
    while (i < grcu_c11a_registry.count && grcu_c11a_registry.readers[i])
        i++;
    if (i == grcu_c11a_registry.count)
        grcu_c11a_registry.readers = xrealloc_n(grcu_c11a_registry.readers,
                                                ++grcu_c11a_registry.count, sizeof(*grcu_c11a_registry.readers));
    grcu_c11a_registry.readers[i] = &grcu_c11a_reader_epoch;
    pthread_mutex_unlock(&grcu_c11a_reg_lock);
    grcu_c11a_thread_online();
}

void grcu_c11a_unregister_thread(void)
{
    grcu_c11a_thread_offline();
    pthread_mutex_lock(&grcu_c11a_reg_lock);
    for (unsigned i = 0; i < grcu_c11a_registry.count; i++) {
        if (grcu_c11a_registry.readers[i] == &grcu_c11a_reader_epoch) {
            grcu_c11a_registry.readers[i] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&grcu_c11a_reg_lock);
}

void grcu_c11a_synchronize_rcu(void)
{
    pthread_mutex_lock(&grcu_c11a_writer_epoch_lock);

    uintptr_t new_epoch = atomic_load_explicit(&grcu_c11a_writer_epoch, memory_order_relaxed) + 1U;
    // Skip the zero (offline) value if we roll the epoch counter, which could
    // happen at least on 32-bit:
    if (unlikely(!new_epoch))
        new_epoch++;
    atomic_store_explicit(&grcu_c11a_writer_epoch, new_epoch, memory_order_relaxed);

    bool all_ok = true;
    struct timespec sleepfor = { 0, 1000000 }; // starts at 1ms

    pthread_mutex_lock(&grcu_c11a_reg_lock);

    do {
        all_ok = true;
        for (unsigned i = 0; i < grcu_c11a_registry.count; i++) {
            if (grcu_c11a_registry.readers[i]) {
                const uintptr_t their_epoch = atomic_load_explicit(grcu_c11a_registry.readers[i], memory_order_relaxed);
                if (their_epoch && their_epoch != new_epoch) {
                    // if this thread is online and using an old epoch, we have to wait
                    all_ok = false;
                    pthread_mutex_unlock(&grcu_c11a_reg_lock);
                    nanosleep(&sleepfor, NULL);
                    pthread_mutex_lock(&grcu_c11a_reg_lock);
                    // double the sleep time per iteration until we reach 32ms
                    if (sleepfor.tv_nsec < 32000000)
                        sleepfor.tv_nsec <<= 1U;
                    break; // registry could have changed, so we have to start over
                }
            }
        }
    } while (!all_ok);

    // I don't think this is actually necessary because of the surrounding
    // pthread lock(s), but technically we need an acquire barrier here after
    // loading the readers' epoch values before we return and let the writer
    // free old data to complete the happens-before causal chain with the
    // readers' claims of quiescence (which are written with release
    // semantics).  It doesn't hurt much anyways to be more formal here!
    // The other option would be to use acquire semantics in the actual loads
    // inside the loop, but that seems like a crazy expense vs a single fence
    // here.
    atomic_thread_fence(memory_order_acquire);

    pthread_mutex_unlock(&grcu_c11a_reg_lock);
    pthread_mutex_unlock(&grcu_c11a_writer_epoch_lock);
}

#endif // GDNSD_USE_GRCU_C11A
