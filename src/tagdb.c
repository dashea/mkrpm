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

#include <endian.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <sys/queue.h>

#include "tagdb.h"

tag_db * init_tag_db(void) {
    tag_db *ret;

    ret = calloc(1, sizeof(*ret));
    if (ret == NULL) {
        fprintf(stderr, "Unable to allocate tag database: %s\n", strerror(errno));
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

rpmTagType rpm_tag_get_type(int tag) {
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
        case RPMTAG_FILEFLAGS:
        case RPMTAG_FILEDEVICES:
        case RPMTAG_FILEINODES:
        case RPMTAG_PROVIDEFLAGS:
        case RPMTAG_REQUIREFLAGS:
        case RPMTAG_DIRINDEXES:
            return RPM_INT32_TYPE;

        case RPMTAG_FILEMODES:
        case RPMTAG_FILERDEVS:
            return RPM_INT16_TYPE;

        case RPMTAG_HEADERI18NTABLE:
        case RPMTAG_FILELINKTOS:
        case RPMTAG_FILEUSERNAME:
        case RPMTAG_FILEGROUPNAME:
        case RPMTAG_FILELANGS:
        case RPMTAG_FILEMD5S:
        case RPMTAG_PROVIDENAME:
        case RPMTAG_REQUIRENAME:
        case RPMTAG_REQUIREVERSION:
        case RPMTAG_PROVIDEVERSION:
        case RPMTAG_OLDFILENAMES:
        case RPMTAG_BASENAMES:
        case RPMTAG_DIRNAMES:
            return RPM_STRING_ARRAY_TYPE;

        default:
            fprintf(stderr, "Unimplemented tag %d: add the type to %s\n", tag, __func__);
            abort();
    }
}

rpmTagType rpm_sig_tag_get_type(int tag) {
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
            fprintf(stderr, "Unable to allocate memory: %s\n", strerror(errno));
            return -1;
        }

        list_entry = calloc(1, sizeof(*list_entry));

        if (list_entry == NULL) {
            fprintf(stderr, "Unable to allocate memory: %s\n", strerror(errno));
            free(db->entries[tag]);
            db->entries[tag] = NULL;
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

        if (space_to_add % BUFSIZ) {
            space_to_add += BUFSIZ - (space_to_add % BUFSIZ);
        }

        tmp = realloc(entry->data, entry->data_total + space_to_add);
        if (tmp == NULL) {
            fprintf(stderr, "Unable to allocate memory: %s\n", strerror(errno));

            /* If this was a new entry, clean up the empty entry */
            if (entry->data_total == 0) {
                free(entry);
                db->entries[tag] = NULL;

                list_entry = SLIST_FIRST(&db->tags_used);
                SLIST_REMOVE_HEAD(&db->tags_used, items);
                free(list_entry);
            }

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

int add_file_tags(tag_db *db, const char *path, const struct stat *sbuf, const char *link_target, const char *checksum) {
    struct passwd *pwd;
    char uid_buf[12] = { 0 };

    struct group *grp;
    char gid_buf[12] = { 0 };

    uint32_t u32_buf;
    uint16_t u16_buf;

    if (sbuf->st_size > UINT32_MAX) {
        fprintf(stderr, "File %s is too large to be stored\n", path);
        return -1;
    }

    u32_buf = htobe32((uint32_t) sbuf->st_size);
    if (add_tag(db, RPMTAG_FILESIZES, &u32_buf, sizeof(u32_buf)) != 0) {
        return -1;
    }

    u16_buf = htobe16((uint16_t) sbuf->st_mode);
    if (add_tag(db, RPMTAG_FILEMODES, &u16_buf, sizeof(u16_buf)) != 0) {
        return -1;
    }

    u16_buf = htobe16((uint16_t) sbuf->st_rdev);
    if (add_tag(db, RPMTAG_FILERDEVS, &u16_buf, sizeof(u16_buf)) != 0) {
        return -1;
    }

    if (sbuf->st_mtime > UINT32_MAX) {
        fprintf(stderr, "%s: RPM is not Y2K38 compliant\n", path);
        return -1;
    }

    u32_buf = htobe32((uint32_t) sbuf->st_mtime);
    if (add_tag(db, RPMTAG_FILEMTIMES, &u32_buf, sizeof(u32_buf)) != 0) {
        return -1;
    }

    if (add_tag(db, RPMTAG_FILEMD5S, checksum, strlen(checksum) + 1) != 0) {
        return -1;
    }

    if (add_tag(db, RPMTAG_FILELINKTOS, link_target, strlen(link_target) + 1) != 0) {
        return -1;
    }

    /* XXX maybe make file flags configurable by config at some point */
    u32_buf = 0;
    if (add_tag(db, RPMTAG_FILEFLAGS, &u32_buf, sizeof(u32_buf)) != 0) {
        return -1;
    }

    /* If the uid/gid are not resolvable to names, convert the ID to a string */
    if ((pwd = getpwuid(sbuf->st_uid)) == NULL) {
        (void) snprintf(uid_buf, sizeof(uid_buf), "%u", (unsigned int) sbuf->st_uid);

        if (add_tag(db, RPMTAG_FILEUSERNAME, uid_buf, strlen(uid_buf) + 1) != 0) {
            return -1;
        }
    } else {
        if (add_tag(db, RPMTAG_FILEUSERNAME, pwd->pw_name, strlen(pwd->pw_name) + 1) != 0) {
            return -1;
        }
    }

    if ((grp = getgrgid(sbuf->st_gid)) == NULL) {
        (void) snprintf(gid_buf, sizeof(gid_buf), "%u", (unsigned int) sbuf->st_gid);

        if (add_tag(db, RPMTAG_FILEGROUPNAME, gid_buf, strlen(gid_buf) + 1) != 0) {
            return -1;
        }
    } else {
        if (add_tag(db, RPMTAG_FILEGROUPNAME, grp->gr_name, strlen(grp->gr_name) + 1) != 0) {
            return -1;
        }
    }

    u32_buf = htobe32((uint32_t) sbuf->st_dev);
    if (add_tag(db, RPMTAG_FILEDEVICES, &u32_buf, sizeof(u32_buf)) != 0) {
        return -1;
    }

    u32_buf = htobe32((uint32_t) sbuf->st_ino);
    if (add_tag(db, RPMTAG_FILEINODES, &u32_buf, sizeof(u32_buf)) != 0) {
        return -1;
    }

    if (add_tag(db, RPMTAG_FILELANGS, "", 1) != 0) {
        return -1;
    }

    if (add_tag(db, RPMTAG_OLDFILENAMES, path, strlen(path) + 1) != 0) {
        return -1;
    }

    return 0;
}
