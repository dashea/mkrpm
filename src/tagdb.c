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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/queue.h>

#include "tagdb.h"

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
    rpmTag tag;
    SLIST_ENTRY(_tag_list_entry) items;
} tag_list_entry;

typedef SLIST_HEAD(_tag_list, _tag_list_entry) tag_list;

struct tag_db {
    /* An array of the individual tags, indexed by the tag value.
     * The tag values only go up to 5096, and the biggest we care about is
     * 1126, so this isn't that huge.
     */
    struct tag_entry *entries[RPMTAG_MAX];

    /* List of tags that appear in entries */
    tag_list tags_used;
};

tag_db * init_tag_db(void) {
    tag_db *ret;

    ret = calloc(1, sizeof(*ret));
    if (ret == NULL) {
        return NULL;
    }

    SLIST_INIT(&ret->tags_used);
    return ret;
}

void free_tag_db(tag_db *db) {
    tag_list_entry *iter;

    if (db == NULL) {
        return;
    }

    while (!SLIST_EMPTY(&db->tags_used)) {
        iter = SLIST_FIRST(&db->tags_used);
        SLIST_REMOVE_HEAD(&db->tags_used, items);

        free(db->entries[iter->tag]->data);
        free(db->entries[iter->tag]);
        free(iter);
    }

    free(db);
}

rpmTagType rpmTagGetType(rpmTag tag) {
    switch (tag) {
        case RPMTAG_NAME:
        case RPMTAG_VERSION:
        case RPMTAG_RELEASE:
        case RPMTAG_LICENSE:
        case RPMTAG_GROUP:
        case RPMTAG_OS:
        case RPMTAG_ARCH:
        case RPMTAG_PAYLOADFORMAT:
        case RPMTAG_PAYLOADCOMPRESSOR:
        case RPMTAG_PAYLOADFLAGS:
            return RPM_STRING_TYPE;

        case RPMTAG_SUMMARY:
        case RPMTAG_DESCRIPTION:
            return RPM_I18NSTRING_TYPE;

        case RPMTAG_SIZE:
        case RPMTAG_FILESIZES:
        case RPMTAG_FILEMTIMES:
        case RPMTAG_FILEMD5S:
        case RPMTAG_FILEFLAGS:
        case RPMTAG_FILEDEVICES:
        case RPMTAG_FILEINODES:
        case RPMTAG_FILELANGS:
        case RPMTAG_PROVIDEFLAGS:
        case RPMTAG_REQUIREFLAGS:
        case RPMTAG_DIRINDEXES:
            return RPM_INT32_TYPE;

        case RPMTAG_FILEMODES:
        case RPMTAG_FILERDEVS:
            return RPM_INT16_TYPE;

        case RPMTAG_FILELINKTOS:
        case RPMTAG_FILEUSERNAME:
        case RPMTAG_FILEGROUPNAME:
        case RPMTAG_PROVIDENAME:
        case RPMTAG_REQUIRENAME:
        case RPMTAG_REQUIREVERSION:
        case RPMTAG_PROVIDEVERSION:
        case RPMTAG_BASENAMES:
        case RPMTAG_DIRNAMES:
            return RPM_STRING_ARRAY_TYPE;

        default:
            fprintf(stderr, "Unimplemented tag %d: add the type to %s\n", tag, __func__);
            abort();
    }
}

rpmTagType rpmSigTagGetType(rpmSigTag tag) {
    switch (tag) {
        case RPMSIGTAG_SIZE:
            return RPM_INT32_TYPE;

        case RPMSIGTAG_MD5:
            return RPM_BIN_TYPE;

        default:
            fprintf(stderr, "Unimplemented signature tag %d: add the type to %s\n", tag, __func__);
            abort();
    }
}

int add_tag(tag_db *db, rpmTag tag, const void *data, size_t data_size) {

    struct tag_entry *entry;
    tag_list_entry *list_entry;

    size_t data_avail;
    size_t space_to_add;
    void *tmp;

    /* Is this a new tag? If so, allocate an entry and add the value to tags_used */
    if (db->entries[tag] == NULL) {
        db->entries[tag] = calloc(1, sizeof(*(db->entries[tag])));

        if (db->entries[tag] == NULL) {
            return -1;
        }

        list_entry = calloc(1, sizeof(*list_entry));

        if (list_entry == NULL) {
            return -1;
        }

        list_entry->tag = tag;
        SLIST_INSERT_HEAD(&db->tags_used, list_entry, items);
    }

    entry = db->entries[tag];

    /* Is there space for the data? If not, allocate more */
    data_avail = entry->data_total - entry->data_used;

    if (data_avail < data_size) {
        /* Round up the amount of space allocated to the next multiple of BUFSIZ */
        space_to_add = data_size - data_avail;
        space_to_add += BUFSIZ - (space_to_add % BUFSIZ);

        tmp = realloc(entry->data, entry->data_total + space_to_add);
        if (tmp == NULL) {
            return -1;
        }

        entry->data = tmp;
        entry->data_total += space_to_add;
    }

    (void) memcpy(entry->data + entry->data_used, data, data_size);
    entry->data_used += data_size;
    entry->count++;

    return 0;
}
