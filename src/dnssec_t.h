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

#ifndef GDNSD_DNSSEC_T_H
#define GDNSD_DNSSEC_T_H

// This file's only purpose is to resolve the dependency loop between
// structures in ltree.h and dnssec.h

struct dnssec_t;
typedef struct dnssec_t dnssec_t;

#endif // GDNSD_DNSSEC_T_H
