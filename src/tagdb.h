/*
 * Copyright (C) 2019  Red Hat, Inc.
 * Author(s):  David Shea <dshea@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _TAGDB_H
#define _TAGDB_H

#include <stdint.h>

#include "rpmtypes.h"

/* Opaque structure for managing the tag store */
typedef struct tag_db tag_db;

tag_db * init_tag_db(void);
void free_tag_db(tag_db *);

/* Map a tag value to a type */
rpmTagType rpmTagGetType(rpmTag);
rpmTagType rpmSigTagGetType(rpmSigTag);

/* Add a tag to the db */
int add_tag(tag_db *, rpmTag, const void *, size_t);

#endif
