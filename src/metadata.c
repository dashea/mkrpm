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
#include <grp.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "rpmtypes.h"
#include "tagdb.h"

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

    if (sbuf->st_mtime > UINT32_MAX) {
        fprintf(stderr, "%s: RPM is not Y2K38 compliant\n", path);
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
