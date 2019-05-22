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

#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include "rpmtypes.h"

struct tag_entry {
    uint32_t count;
    size_t data_used;
    size_t data_total;
    void *data;
};

/* linked list of tags actually used, since there's only 30-some that will
 * actually be populated in tagDb.entries. Tags that are populated in entries
 * will also be stored in tagDb.tagList, so that this list can iterated over
 * to output the final tag store, instead of iterating over all 1000-some
 * possible values in entries.
 */
typedef struct _tag_list_entry {
    int tag;
    SLIST_ENTRY(_tag_list_entry) items;
} tag_list_entry;

typedef SLIST_HEAD(_tag_list, _tag_list_entry) tag_list;

typedef struct _tag_db {
    /* An array of the individual tags, indexed by the tag value.
     * The tag values only go up to 5096, and the biggest we care about is
     * 1126, so this isn't that huge.
     */
    struct tag_entry *entries[RPMTAG_MAX];

    /* List of tags that appear in entries */
    tag_list tags_used;
} tag_db;

tag_db * init_tag_db(void);
void free_tag_db(tag_db *);

/* Map a tag value to a type */
rpmTagType rpm_tag_get_type(int);
rpmTagType rpm_sig_tag_get_type(int);

/* Add a tag to the db */
int add_tag(tag_db *, rpmTag, const void *, size_t);

/* Add all of the tags for the given file */
int add_file_tags(tag_db *, const char *, const struct stat *, const char *);

#endif
