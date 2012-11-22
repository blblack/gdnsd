/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
 *
 * This file is part of gdnsd-plugin-geoip.
 *
 * gdnsd-plugin-geoip is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * gdnsd-plugin-geoip is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gdnsd.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// gdmaps = GeoIP -> Datacenter Mapping library code

#include "config.h"
#include "gdmaps.h"
#include "fips104.h"
#include "dcinfo.h"
#include "dclists.h"
#include "dcmap.h"
#include "nlist.h"
#include "ntree.h"
#include "nets.h"
#include "gdgeoip.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pthread.h>

#include <gdnsd-dmn.h>
#include <gdnsd-log.h>
#include <gdnsd-vscf.h>
#include <gdnsd-ev.h>
#include <gdnsd-misc.h>

// When an input file change is detected, we wait this long
//  for a followup change notification before processing.  Every time we get
//  another notification within the window, we restart the timer again.  This
//  coalesces rapid-fire updates.
#define STAT_RELOAD_WAIT 5.0

// *after* reloading an individual input file, this timer is kicked similarly
//   to the above, to wait for all rapid-fire updates to all input files to
//   quiesce a while.  When it finally expires, the parsed new data from each
//   are merged into a single runtime lookup database, and we do a locked
//   swap of the data for the runtime lookup threads.
#define ALL_RELOAD_WAIT 7.0

typedef struct {
    pthread_rwlock_t tree_lock;
    char* name;
    char* geoip_path;
    char* geoip_v4o_path;
    const fips_t* fips;
    dcinfo_t* dcinfo; // basic datacenter list/info
    dcmap_t* dcmap; // map of locinfo -> dclist
    dclists_t* dclists; // corresponds to ->tree
    dclists_t* dclists_pend; // Pending modified dclist for latest update(s)
                             //   to ->foo_list, eventually promoted to
                             //   ->dclists when ->tree is updated, NULL
                             //   when no pending update(s) are outstanding
    nlist_t* geoip_list; // optional main geoip db
    nlist_t* geoip_v4o_list; // optional v4 overlay
    nlist_t* nets_list; // net overrides, optional
    ntree_t* tree; // merged->translated from the lists above
    ev_stat* geoip_stat_watcher;
    ev_stat* geoip_v4o_stat_watcher;
    ev_timer* geoip_reload_timer;
    ev_timer* geoip_v4o_reload_timer;
    ev_timer* tree_update_timer;
    bool city_no_region;
    bool city_auto_mode;
} gdmap_t;

F_NONNULL
static bool _gdmap_badkey(const char* key, unsigned klen V_UNUSED, const vscf_data_t* val V_UNUSED, void* data) {
    dmn_assert(key); dmn_assert(data);
    log_fatal("plugin_geoip: map '%s': invalid config key '%s'", (const char*)data, key);
    return false;
}

F_NONNULLX(1,2)
static gdmap_t* gdmap_new(const char* name, const vscf_data_t* map_cfg, const fips_t* fips) {
    dmn_assert(name); dmn_assert(map_cfg);

    // basics
    gdmap_t* gdmap = calloc(1, sizeof(gdmap_t));
    gdmap->name = strdup(name);
    gdmap->fips = fips;
    if(!vscf_is_hash(map_cfg))
        log_fatal("plugin_geoip: value for map '%s' must be a hash", name);

    // datacenters config
    const vscf_data_t* dc_cfg = vscf_hash_get_data_byconstkey(map_cfg, "datacenters", true);
    if(!dc_cfg)
        log_fatal("plugin_geoip: map '%s': missing required 'datacenters' array", name);
    const vscf_data_t* dc_auto_cfg = vscf_hash_get_data_byconstkey(map_cfg, "auto_dc_coords", true);
    const vscf_data_t* dc_auto_limit_cfg = vscf_hash_get_data_byconstkey(map_cfg, "auto_dc_limit", true);
    gdmap->city_auto_mode = dc_auto_cfg ? true : false;
    gdmap->dcinfo = dcinfo_new(dc_cfg, dc_auto_cfg, dc_auto_limit_cfg, name);
    gdmap->dclists_pend = dclists_new(gdmap->dcinfo);

    // geoip_db config
    const vscf_data_t* gdb_cfg = vscf_hash_get_data_byconstkey(map_cfg, "geoip_db", true);
    if(gdb_cfg) {
        if(!vscf_is_simple(gdb_cfg) || !vscf_simple_get_len(gdb_cfg))
            log_fatal("plugin_geoip: map '%s': 'geoip_db' must have a non-empty string value", name);
        gdmap->geoip_path = str_combine(GEOIP_DIR, vscf_simple_get_data(gdb_cfg), NULL);
    }

    // geoip_db_v4_overlay config
    const vscf_data_t* gdb_v4o_cfg = vscf_hash_get_data_byconstkey(map_cfg, "geoip_db_v4_overlay", true);
    if(gdb_v4o_cfg) {
        if(!gdb_cfg)
            log_fatal("plugin_geoip: map '%s': 'geoip_db_v4_overlay' requires an IPv6 'geoip_db'", name);
        if(!vscf_is_simple(gdb_v4o_cfg) || !vscf_simple_get_len(gdb_v4o_cfg))
            log_fatal("plugin_geoip: map '%s': 'geoip_db_v4_overlay' must have a non-empty string value", name);
        gdmap->geoip_v4o_path = str_combine(GEOIP_DIR, vscf_simple_get_data(gdb_v4o_cfg), NULL);
    }

    // map config
    const vscf_data_t* map_map = vscf_hash_get_data_byconstkey(map_cfg, "map", true);
    if(map_map) {
        if(!vscf_is_hash(map_map))
            log_fatal("plugin_geoip: map '%s': 'map' stanza must be a hash", name);
        if(!gdmap->geoip_path)
            log_fatal("plugin_geoip: map '%s': 'map' stanza requires 'geoip_db'", name);
        gdmap->dcmap = dcmap_new(map_map, gdmap->dclists_pend, 0, 0, name, gdmap->city_auto_mode);
    }

    // nets config
    const vscf_data_t* nets_cfg = vscf_hash_get_data_byconstkey(map_cfg, "nets", true);
    if(nets_cfg && !vscf_is_hash(nets_cfg))
        log_fatal("plugin_geoip: map '%s': 'nets' stanza must be a hash", name);
    gdmap->nets_list = nets_make_list(nets_cfg, gdmap->dclists_pend, name);

    // optional GeoIPCity behavior flags
    gdmap->city_no_region = false;
    const vscf_data_t* cnr_cfg = vscf_hash_get_data_byconstkey(map_cfg, "city_no_region", true);
    if(cnr_cfg) {
        if(!vscf_is_simple(cnr_cfg) || !vscf_simple_get_as_bool(cnr_cfg, &gdmap->city_no_region))
            log_fatal("plugin_geoip: map '%s': 'city_no_region' must be a boolean value ('true' or 'false')", name);
    }

    // check for invalid keys
    vscf_hash_iterate(map_cfg, true, _gdmap_badkey, (void*)name);

    // Set up tree lock for runtime reloads
    int pthread_err;
    pthread_rwlockattr_t lockatt;
    if((pthread_err = pthread_rwlockattr_init(&lockatt)))
        log_fatal("plugin_geoip: pthread_rwlockattr_init() failed: %s", logf_errnum(pthread_err));

    // Non-portable way to boost writer priority.  Our writelocks are held very briefly
    //  and very rarely, whereas the readlocks could be very spammy, and we don't want to
    //  block the write operation forever.  This works on Linux+glibc.
#   ifdef PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP
        if((pthread_err = pthread_rwlockattr_setkind_np(&lockatt, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)))
            log_fatal("plugin_geoip: pthread_rwlockattr_setkind_np(PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP) failed: %s", logf_errnum(pthread_err));
#   endif

    if((pthread_err = pthread_rwlock_init(&gdmap->tree_lock, &lockatt)))
        log_fatal("plugin_geoip: pthread_rwlock_init() failed: %s", logf_errnum(pthread_err));
    if((pthread_err = pthread_rwlockattr_destroy(&lockatt)))
        log_fatal("plugin_geoip: pthread_rwlockattr_destroy() failed: %s", logf_errnum(pthread_err));

    return gdmap;
}

F_NONNULL
static void gdmap_tree_update(gdmap_t* gdmap) {
    dmn_assert(gdmap);
    dmn_assert(gdmap->dclists_pend);

    ntree_t* merged;

    if(gdmap->geoip_list) {
        if(gdmap->geoip_v4o_list) {
            merged = nlist_merge3_tree(gdmap->geoip_list, gdmap->geoip_v4o_list, gdmap->nets_list);
        }
        else {
            merged = nlist_merge2_tree(gdmap->geoip_list, gdmap->nets_list);
        }
    }
    else {
        merged = nlist_xlate_tree(gdmap->nets_list);
    }

    ntree_t* old_tree = gdmap->tree;
    dclists_t* old_lists = gdmap->dclists;

    // This data swap is designed to be RCU-compatible for
    //   a future performance upgrade...
    pthread_rwlock_wrlock(&gdmap->tree_lock);
    gdmap->dclists = gdmap->dclists_pend;
    gdmap->tree = merged;
    pthread_rwlock_unlock(&gdmap->tree_lock);

    gdmap->dclists_pend = NULL;
    if(old_tree)
        ntree_destroy(old_tree);
    if(old_lists)
        dclists_destroy(old_lists, KILL_NO_LISTS);

    log_info("plugin_geoip: map '%s' runtime db updated. nets: %u dclists: %u", gdmap->name, gdmap->tree->count + 1, dclists_get_count(gdmap->dclists));
}

static bool gdmap_update_geoip(gdmap_t* gdmap, const char* path, nlist_t** out_list_ptr, gdgeoip_v4o_t v4o_flag) {
    dmn_assert(gdmap);

    dclists_t* update_dclists;

    if(!gdmap->dclists_pend) {
        dmn_assert(gdmap->dclists);
        update_dclists = dclists_clone(gdmap->dclists);
    }
    else {
        update_dclists = gdmap->dclists_pend;
    }

    nlist_t* new_list = gdgeoip_make_list(
        path,
        gdmap->name,
        update_dclists,
        gdmap->dcmap,
        gdmap->fips,
        v4o_flag,
        gdmap->city_auto_mode,
        gdmap->city_no_region
    );

    bool rv = false;

    if(!new_list) {
        log_err("plugin_geoip: map '%s': (Re-)loading geoip database '%s' failed!", gdmap->name, logf_pathname(path));
        if(!gdmap->dclists_pend)
            dclists_destroy(update_dclists, KILL_NEW_LISTS);
        rv = true;
    }
    else {
        if(!gdmap->dclists_pend)
            gdmap->dclists_pend = update_dclists;
        if(*out_list_ptr)
            nlist_destroy(*out_list_ptr);
        *out_list_ptr = new_list;
    }

    return rv;
}

F_NONNULL
static void gdmap_initial_load_all(gdmap_t* gdmap) {
    dmn_assert(gdmap);
    dmn_assert(gdmap->dclists_pend);
    dmn_assert(!gdmap->geoip_list);

    if(gdmap->geoip_path) {
        const bool v4o = !!gdmap->geoip_v4o_path;

        if(gdmap_update_geoip(gdmap, gdmap->geoip_path, &gdmap->geoip_list, v4o ? V4O_PRIMARY : V4O_NONE))
            log_fatal("plugin_geoip: map '%s': cannot continue initial load", gdmap->name);

        if(gdmap->geoip_v4o_path)
            if(gdmap_update_geoip(gdmap, gdmap->geoip_v4o_path, &gdmap->geoip_v4o_list, V4O_SECONDARY))
                log_fatal("plugin_geoip: map '%s': cannot continue initial load", gdmap->name);
    }

    gdmap_tree_update(gdmap);
}

F_NONNULL
static void gdmap_kick_tree_update(gdmap_t* gdmap, struct ev_loop* loop) {
    dmn_assert(gdmap); dmn_assert(loop);

    if(!ev_is_active(gdmap->tree_update_timer))
        log_info("plugin_geoip: map '%s': runtime data changes are pending, waiting for %gs of change quiescence...", gdmap->name, ALL_RELOAD_WAIT);
    else
        log_debug("plugin_geoip: map '%s': Timer for all runtime data re-kicked for %gs due to rapid change...", gdmap->name, ALL_RELOAD_WAIT);
    ev_timer_again(loop, gdmap->tree_update_timer);
}

F_NONNULL
static void gdmap_geoip_reload_timer_cb(struct ev_loop* loop, ev_timer* w V_UNUSED, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_TIMER);

    gdmap_t* gdmap = (gdmap_t*)w->data;
    dmn_assert(gdmap);
    dmn_assert(gdmap->geoip_path);
    const bool v4o = !!gdmap->geoip_v4o_path;

    ev_timer_stop(loop, gdmap->geoip_reload_timer);

    if(!gdmap_update_geoip(gdmap, gdmap->geoip_path, &gdmap->geoip_list, v4o ? V4O_PRIMARY : V4O_NONE)) {
        dmn_assert(gdmap->dclists_pend);
        gdmap_kick_tree_update(gdmap, loop);
    }
}

F_NONNULL
static void gdmap_geoip_v4o_reload_timer_cb(struct ev_loop* loop, ev_timer* w V_UNUSED, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_TIMER);

    gdmap_t* gdmap = (gdmap_t*)w->data;
    dmn_assert(gdmap);
    dmn_assert(gdmap->geoip_v4o_path);

    ev_timer_stop(loop, gdmap->geoip_reload_timer);

    if(!gdmap_update_geoip(gdmap, gdmap->geoip_v4o_path, &gdmap->geoip_v4o_list, V4O_SECONDARY)) {
        dmn_assert(gdmap->dclists_pend);
        gdmap_kick_tree_update(gdmap, loop);
    }
}

F_NONNULL
static void gdmap_geoip_reload_stat_cb(struct ev_loop* loop, ev_stat* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_STAT);

    gdmap_t* gdmap = (gdmap_t*)w->data;
    dmn_assert(gdmap);

    const bool v4o = gdmap->geoip_v4o_path == w->path;
    dmn_assert(v4o || gdmap->geoip_path == w->path);

    if(w->attr.st_nlink) { // file exists
        if(w->attr.st_mtime != w->prev.st_mtime || !w->prev.st_nlink) {
            // Start (or restart) a timer to geoip_reload_timer_cb, so that we
            //  wait for multiple changes to "settle" before re-reading the file
            ev_timer* which_timer = v4o ? gdmap->geoip_v4o_reload_timer : gdmap->geoip_reload_timer;
            if(!ev_is_active(which_timer))
                log_info("plugin_geoip: map '%s': Change detected in GeoIP database '%s', waiting for %gs of change quiescence...", gdmap->name, logf_pathname(w->path), STAT_RELOAD_WAIT);
            else
                log_debug("plugin_geoip: map '%s': Timer for GeoIP database '%s' re-kicked for %gs due to rapid change...", gdmap->name, logf_pathname(w->path), STAT_RELOAD_WAIT);
            ev_timer_again(loop, which_timer);
        }
    }
    else {
        log_warn("plugin_geoip: map '%s': GeoIP database '%s' dissappeared! Internal DB remains unchanged, waiting for it to re-appear...", gdmap->name, logf_pathname(w->path));
    }
}

F_NONNULL
static void gdmap_tree_update_cb(struct ev_loop* loop, ev_timer* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_TIMER);

    gdmap_t* gdmap = (gdmap_t*)w->data;
    dmn_assert(gdmap);
    ev_timer_stop(loop, gdmap->tree_update_timer);
    gdmap_tree_update(gdmap);
}

F_NONNULL
static void gdmap_setup_geoip_watcher(gdmap_t* gdmap, struct ev_loop* loop) {
    dmn_assert(gdmap); dmn_assert(loop);
    dmn_assert(gdmap->geoip_path);

    const bool v4o = !!gdmap->geoip_v4o_path;

    // the reload stat-quiesce timers
    gdmap->geoip_reload_timer = malloc(sizeof(ev_timer));
    ev_init(gdmap->geoip_reload_timer, gdmap_geoip_reload_timer_cb);
    ev_set_priority(gdmap->geoip_reload_timer, -1);
    gdmap->geoip_reload_timer->repeat = STAT_RELOAD_WAIT;
    gdmap->geoip_reload_timer->data = gdmap;

    if(v4o) {
        gdmap->geoip_v4o_reload_timer = malloc(sizeof(ev_timer));
        ev_init(gdmap->geoip_v4o_reload_timer, gdmap_geoip_v4o_reload_timer_cb);
        ev_set_priority(gdmap->geoip_v4o_reload_timer, -1);
        gdmap->geoip_v4o_reload_timer->repeat = STAT_RELOAD_WAIT;
        gdmap->geoip_v4o_reload_timer->data = gdmap;
    }

    // the reload stat() watchers (they share a callback differentiated on w->path)
    gdmap->geoip_stat_watcher = malloc(sizeof(ev_stat));
    ev_stat_init(gdmap->geoip_stat_watcher, gdmap_geoip_reload_stat_cb, gdmap->geoip_path, 0);
    ev_set_priority(gdmap->geoip_stat_watcher, 0);
    gdmap->geoip_stat_watcher->data = gdmap;
    ev_stat_start(loop, gdmap->geoip_stat_watcher);

    if(v4o) {
        gdmap->geoip_v4o_stat_watcher = malloc(sizeof(ev_stat));
        ev_stat_init(gdmap->geoip_v4o_stat_watcher, gdmap_geoip_reload_stat_cb, gdmap->geoip_v4o_path, 0);
        ev_set_priority(gdmap->geoip_v4o_stat_watcher, 0);
        gdmap->geoip_v4o_stat_watcher->data = gdmap;
        ev_stat_start(loop, gdmap->geoip_v4o_stat_watcher);
    }
}

F_NONNULL
static void gdmap_setup_watchers(gdmap_t* gdmap, struct ev_loop* loop) {
    dmn_assert(gdmap); dmn_assert(loop);
    if(gdmap->geoip_path)
        gdmap_setup_geoip_watcher(gdmap, loop);

    gdmap->tree_update_timer = malloc(sizeof(ev_timer));
    ev_init(gdmap->tree_update_timer, gdmap_tree_update_cb);
    ev_set_priority(gdmap->tree_update_timer, -2);
    gdmap->tree_update_timer->repeat = ALL_RELOAD_WAIT;
    gdmap->tree_update_timer->data = gdmap;
}

F_NONNULL
static const char* gdmap_get_name(const gdmap_t* gdmap) {
    dmn_assert(gdmap);
    return gdmap->name;
}

F_NONNULL
static const uint8_t* gdmap_lookup(gdmap_t* gdmap, const client_info_t* client, unsigned* scope_mask) {
    dmn_assert(gdmap); dmn_assert(client);

    pthread_rwlock_rdlock(&gdmap->tree_lock);
    const unsigned dclist_u = ntree_lookup(gdmap->tree, client, scope_mask);
    const uint8_t* dclist_u8 = dclists_get_list(gdmap->dclists, dclist_u);
    pthread_rwlock_unlock(&gdmap->tree_lock);

    dmn_assert(dclist_u8);
    return dclist_u8;
}

// In practice, the real plugin running in a daemon doesn't bother destroying
//  gdmap_t's, so there is no race here on pthread_cancel() of i/o
//  thread doing rdlock lookups and lock destruction here.
F_NONNULL
static void gdmap_destroy(gdmap_t* gdmap) {
    dmn_assert(gdmap);

    int pthread_err;
    if((pthread_err = pthread_rwlock_destroy(&gdmap->tree_lock)))
        log_fatal("plugin_geoip: pthread_rwlock_destroy() failed: %s", logf_errnum(pthread_err));
    if(gdmap->tree)
        ntree_destroy(gdmap->tree);
    if(gdmap->nets_list)
        nlist_destroy(gdmap->nets_list);
    if(gdmap->geoip_list)
        nlist_destroy(gdmap->geoip_list);
    if(gdmap->geoip_v4o_list)
        nlist_destroy(gdmap->geoip_v4o_list);
    if(gdmap->geoip_v4o_path)
        free(gdmap->geoip_v4o_path);
    if(gdmap->geoip_path)
        free(gdmap->geoip_path);
    if(gdmap->geoip_v4o_stat_watcher)
        free(gdmap->geoip_v4o_stat_watcher);
    if(gdmap->geoip_stat_watcher)
        free(gdmap->geoip_stat_watcher);
    if(gdmap->geoip_v4o_reload_timer)
        free(gdmap->geoip_v4o_reload_timer);
    if(gdmap->geoip_reload_timer)
        free(gdmap->geoip_reload_timer);
    if(gdmap->tree_update_timer)
        free(gdmap->tree_update_timer);
    if(gdmap->dclists)
        dclists_destroy(gdmap->dclists, KILL_ALL_LISTS);
    dcinfo_destroy(gdmap->dcinfo);
    if(gdmap->dcmap)
        dcmap_destroy(gdmap->dcmap);
    free(gdmap->name);
    free(gdmap);
}

/***************************************
 * gdmaps_t and related methods
 **************************************/

struct _gdmaps_t {
    pthread_t reload_tid;
    bool reload_thread_spawned;
    unsigned count;
    struct ev_loop* reload_loop;
    fips_t* fips;
    gdmap_t** maps;
};

F_NONNULL
static bool _gdmaps_new_iter(const char* key, unsigned klen V_UNUSED, const vscf_data_t* val, void* data) {
    dmn_assert(key); dmn_assert(val); dmn_assert(data);
    gdmaps_t* gdmaps = data;
    gdmaps->maps = realloc(gdmaps->maps, sizeof(gdmap_t*) * (gdmaps->count + 1));
    gdmaps->maps[gdmaps->count++] = gdmap_new(key, val, gdmaps->fips);
    return true;
}

gdmaps_t* gdmaps_new(const vscf_data_t* maps_cfg) {
    dmn_assert(maps_cfg);
    dmn_assert(vscf_is_hash(maps_cfg));

    gdmaps_t* gdmaps = calloc(1, sizeof(gdmaps_t));

    const vscf_data_t* crn_cfg = vscf_hash_get_data_byconstkey(maps_cfg, "city_region_names", true);
    if(crn_cfg) {
        if(!vscf_is_simple(crn_cfg))
            log_fatal("plugin_geoip: 'city_region_names' must be a filename as a simple string value");
        gdmaps->fips = fips_init(vscf_simple_get_data(crn_cfg));
    }

    vscf_hash_iterate(maps_cfg, true, _gdmaps_new_iter, gdmaps);
    return gdmaps;
}

int gdmaps_name2idx(const gdmaps_t* gdmaps, const char* map_name) {
    dmn_assert(gdmaps); dmn_assert(map_name);
    for(unsigned i = 0; i < gdmaps->count; i++)
        if(!strcmp(map_name, gdmap_get_name(gdmaps->maps[i])))
            return (int)i;
    return -1;
}

const char* gdmaps_idx2name(const gdmaps_t* gdmaps, const unsigned gdmap_idx) {
    dmn_assert(gdmaps);
    if(gdmap_idx >= gdmaps->count)
        return NULL;
    return gdmap_get_name(gdmaps->maps[gdmap_idx]);
}

unsigned gdmaps_get_dc_count(const gdmaps_t* gdmaps, const unsigned gdmap_idx) {
    dmn_assert(gdmaps);
    dmn_assert(gdmap_idx < gdmaps->count);
    return dcinfo_get_count(gdmaps->maps[gdmap_idx]->dcinfo);
}

unsigned gdmaps_dcname2num(const gdmaps_t* gdmaps, const unsigned gdmap_idx, const char* dcname) {
    dmn_assert(gdmaps); dmn_assert(dcname);
    dmn_assert(gdmap_idx < gdmaps->count);
    return dcinfo_name2num(gdmaps->maps[gdmap_idx]->dcinfo, dcname);
}

const char* gdmaps_dcnum2name(const gdmaps_t* gdmaps, const unsigned gdmap_idx, const unsigned dcnum) {
    dmn_assert(gdmaps);
    dmn_assert(gdmap_idx < gdmaps->count);
    return dcinfo_num2name(gdmaps->maps[gdmap_idx]->dcinfo, dcnum);
}

// mostly for debugging / error output
#define DCLIST_LOGF_MAX 512
static const char dclist_len_err[] = "<dclist too large to format for printing>";
static const char dclist_nodc[] = "<INVALID>";
const char* gdmaps_logf_dclist(const gdmaps_t* gdmaps, const unsigned gdmap_idx, const uint8_t* dclist) {
    dmn_assert(gdmaps); dmn_assert(dclist);
    dmn_assert(gdmap_idx < gdmaps->count);

    char tbuf[DCLIST_LOGF_MAX];
    tbuf[0] = '\0';
    unsigned tbuf_remain = DCLIST_LOGF_MAX - 1;

    unsigned dcnum;
    bool first = true;
    while((dcnum = *dclist++)) {
        const char* dcname = gdmaps_dcnum2name(gdmaps, gdmap_idx, dcnum);
        if(!dcname)
            dcname = dclist_nodc;
        unsigned addlen = strlen(dcname);
        if(!first) addlen += 2;
        if(addlen > tbuf_remain)
            return dclist_len_err;
        if(!first)
            strcat(tbuf, ", ");
        strcat(tbuf, dcname);
        tbuf_remain -= addlen;
        first = false;
    }

    char* buf = dmn_fmtbuf_alloc(strlen(tbuf) + 1);
    strcpy(buf, tbuf);
    return buf;
}

const uint8_t* gdmaps_lookup(const gdmaps_t* gdmaps, const unsigned gdmap_idx, const client_info_t* client, unsigned* scope_mask) {
    dmn_assert(gdmaps); dmn_assert(client);
    dmn_assert(gdmap_idx < gdmaps->count);
    return gdmap_lookup(gdmaps->maps[gdmap_idx], client, scope_mask);
}

void gdmaps_load_databases(gdmaps_t* gdmaps) {
    dmn_assert(gdmaps);
    for(unsigned i = 0; i < gdmaps->count; i++)
        gdmap_initial_load_all(gdmaps->maps[i]);
}

static void* gdmaps_reload_thread(void* arg) {
    gdmaps_t* gdmaps = (gdmaps_t*)arg;

    gdmaps->reload_loop = ev_loop_new(EVFLAG_AUTO);
    ev_set_timeout_collect_interval(gdmaps->reload_loop, 0.5);
    ev_set_io_collect_interval(gdmaps->reload_loop, 0.5);

    for(unsigned i = 0; i < gdmaps->count; i++)
        gdmap_setup_watchers(gdmaps->maps[i], gdmaps->reload_loop);

    ev_run(gdmaps->reload_loop, 0);

    return NULL;
}

void gdmaps_setup_watchers(gdmaps_t* gdmaps) {
    dmn_assert(gdmaps);

    pthread_attr_t attribs;
    pthread_attr_init(&attribs);
    pthread_attr_setdetachstate(&attribs, PTHREAD_CREATE_JOINABLE);

    sigset_t sigmask_all, sigmask_prev;
    sigfillset(&sigmask_all);
    pthread_sigmask(SIG_SETMASK, &sigmask_all, &sigmask_prev);

    int pthread_err;
    if((pthread_err = pthread_create(&gdmaps->reload_tid, &attribs, gdmaps_reload_thread, gdmaps)))
        log_fatal("plugin_geoip: failed to create GeoIP reload thread: %s", logf_errnum(pthread_err));

    gdmaps->reload_thread_spawned = true;

    pthread_sigmask(SIG_SETMASK, &sigmask_prev, NULL);
    pthread_attr_destroy(&attribs);
}

void gdmaps_destroy(gdmaps_t* gdmaps) {
    dmn_assert(gdmaps);
    if(gdmaps->reload_thread_spawned) {
        pthread_cancel(gdmaps->reload_tid);
        pthread_join(gdmaps->reload_tid, NULL);
    }
    if(gdmaps->reload_loop)
        ev_loop_destroy(gdmaps->reload_loop);
    for(unsigned i = 0; i < gdmaps->count; i++)
        gdmap_destroy(gdmaps->maps[i]);
    free(gdmaps->maps);
    if(gdmaps->fips)
        fips_destroy(gdmaps->fips);
    free(gdmaps);
}
