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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <archive.h>
#include <archive_entry.h>

#include <openssl/md5.h>

#include "metadata.h"
#include "payload_cpio.h"
#include "tagdb.h"

struct archive * init_archive(FILE *output, struct archive_entry_linkresolver **resolver_out) {
    struct archive *archive;

    assert(output != NULL);
    assert(resolver_out != NULL);

    archive = archive_write_new();
    if (archive == NULL) {
        return NULL;
    }

    if (archive_write_add_filter_gzip(archive) != ARCHIVE_OK) {
        fprintf(stderr, "Unable to add gzip filter to archive: %s\n", archive_error_string(archive));
        (void) archive_write_free(archive);
        return NULL;
    }

    if (archive_write_set_format_cpio_newc(archive) != ARCHIVE_OK) {
        fprintf(stderr, "Unable to set format to cpio: %s\n", archive_error_string(archive));
        (void) archive_write_free(archive);
        return NULL;
    }

    if (archive_write_set_filter_option(archive, NULL, "compression-level", "9") != ARCHIVE_OK) {
        fprintf(stderr, "Unable to set compression level: %s\n", archive_error_string(archive));
        (void) archive_write_free(archive);
        return NULL;
    }

    if (archive_write_open_FILE(archive, output) != ARCHIVE_OK) {
        fprintf(stderr, "Unable to open archive: %s\n", archive_error_string(archive));
        (void) archive_write_free(archive);
        return NULL;
    }

    if ((*resolver_out = archive_entry_linkresolver_new()) == NULL) {
        fprintf(stderr, "Unable to allocate new entry link resolver\n");
        (void) archive_write_free(archive);
        return NULL;
    }

    archive_entry_linkresolver_set_strategy(*resolver_out, ARCHIVE_FORMAT_CPIO_SVR4_NOCRC);

    return archive;
}

static int add_payload_entry(struct archive *archive, struct archive_entry *entry, tag_db *tags) {
    const char *sourcepath;
    const struct stat *sbuf;
    struct stat restat;
    const char *link_target;
    int fd;
    char buffer[BUFSIZ];
    ssize_t bytes_read;
    bool write_payload = true;

    MD5_CTX md5_ctx;
    unsigned char md5sum[MD5_DIGEST_LENGTH];
    char md5_ascii[(MD5_DIGEST_LENGTH * 2) + 1];
    int i;

    assert(archive != NULL);
    assert(entry != NULL);

    if (archive_write_header(archive, entry) != ARCHIVE_OK) {
        fprintf(stderr, "Unable to write archive entry: %s\n", archive_error_string(archive));
        return -1;
    }

    sourcepath = archive_entry_sourcepath(entry);

    if (archive_entry_filetype(entry) == AE_IFREG) {
        /* If the entry's size is 0, do not write a cpio payload; this may be a placeholder entry
         * from the hardlink resolver. However, we still need the md5sum for the file, so read the
         * data anyway.
         */
        if (archive_entry_size(entry) == 0) {
            write_payload = false;
        }

        if (!MD5_Init(&md5_ctx)) {
            fprintf(stderr, "Unable to initialize MD5 context\n");
            return -1;
        }

        fd = open(sourcepath, O_RDONLY);

        if (fd == -1) {
            fprintf(stderr, "Unable to open %s: %s\n", sourcepath, strerror(errno));
            return -1;
        }

        while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
            if (write_payload && (archive_write_data(archive, buffer, (size_t) bytes_read) < 0)) {
                fprintf(stderr, "Unable to write data for %s to archive: %s\n", sourcepath, archive_error_string(archive));
                close(fd);
                return -1;
            }

            if (!MD5_Update(&md5_ctx, buffer, (unsigned long) bytes_read)) {
                fprintf(stderr, "Error updating checksum for %s\n", sourcepath);
                close(fd);
                return -1;
            }
        }

        if (bytes_read < 0) {
            fprintf(stderr, "Error reading from %s: %s\n", sourcepath, strerror(errno));
            close(fd);
            return -1;
        }

        close(fd);

        if (!MD5_Final(md5sum, &md5_ctx)) {
            fprintf(stderr, "Error finalizing checksum for %s\n", sourcepath);
            return -1;
        }

        for (i = 0; i < sizeof(md5sum); i++) {
            snprintf(md5_ascii + (i * 2), 3, "%02x", md5sum[i]);
        }
    } else {
        md5_ascii[0] = '\0';
    }

    /*
     * Add the metadata to the RPM header.
     * If this is a hardlink with a size of 0, re-stat the file. The linkresolver
     * may have unset the size in order to write a hardlink entry, and we need the actual
     * stat size for RPM's metadata.
     */
    sbuf = archive_entry_stat(entry);
    if (S_ISREG(sbuf->st_mode) && (sbuf->st_nlink > 1) && (sbuf->st_size == 0)) {
        if (lstat(sourcepath, &restat) != 0) {
            fprintf(stderr, "Unable to stat %s: %s\n", sourcepath, strerror(errno));
            return -1;
        }

        sbuf = &restat;
    }

    if (S_ISLNK(sbuf->st_mode)) {
        link_target = archive_entry_symlink(entry);
    } else {
        link_target = "";
    }

    if (add_file_tags(tags, sourcepath, sbuf, link_target, md5_ascii) != 0) {
        return -1;
    }


    return 0;
}

/* Add the given file to the CPIO payload, using write_func + output_handle to write the data
 * Return 0 on success, and write the stat info for the file to sbuf.
 * Return -1 on failure.
 */
int add_file_to_payload(struct archive *archive, struct archive_entry_linkresolver *resolver, tag_db *tags, const char *pathname, struct stat *sbuf) {
    char link_target[PATH_MAX + 1];
    struct archive_entry *entry = NULL;
    struct archive_entry *sparse = NULL;

    int returncode = -1;

    assert(archive != NULL);
    assert(resolver != NULL);
    assert(tags != NULL);
    assert(pathname != NULL);

    /* Stat the file */
    if (lstat(pathname, sbuf) != 0) {
        fprintf(stderr, "Unable to stat %s: %s\n", pathname, strerror(errno));
        goto cleanup;
    }

    /* Create a new archive entry */
    entry = archive_entry_new();
    if (entry == NULL) {
        fprintf(stderr, "Unable to allocate new archive entry\n");
        goto cleanup;
    }

    /* Set the pathname */
    archive_entry_set_pathname(entry, pathname);

    /* Set the sourcename to the same thing, for use by add_payload_entry */
    archive_entry_copy_sourcepath(entry, pathname);

    /* Set the rest of the metadata from the stat values */
    archive_entry_copy_stat(entry, sbuf);

    /* If this is a symlink, set the symlink destination */
    if (S_ISLNK(sbuf->st_mode)) {
        memset(link_target, 0, sizeof(link_target));

        if (readlink(pathname, link_target, PATH_MAX) < 0) {
            fprintf(stderr, "Unable to readlink at %s: %s\n", pathname, strerror(errno));
            goto cleanup;
        }

        archive_entry_set_symlink(entry, link_target);
    }

    /* Run everything through the hardlink resolver */
    archive_entry_linkify(resolver, &entry, &sparse);

    /* Add any entries that came back from the resolver */
    if (entry != NULL) {
        if (add_payload_entry(archive, entry, tags) != 0) {
            goto cleanup;
        }
    }

    if (sparse != NULL) {
        if (add_payload_entry(archive, sparse, tags) != 0) {
            goto cleanup;
        }
    }

    returncode = 0;

cleanup:
    if (entry != NULL) {
        archive_entry_free(entry);
    }

    if (sparse != NULL) {
        archive_entry_free(entry);
    }

    return returncode;
}

int finish_archive(struct archive *archive, struct archive_entry_linkresolver *resolver, tag_db *tags) {
    struct archive_entry *entry;

    /* Unused, but the argument to archive_entry_linkify must be non-NULL */
    struct archive_entry *sparse;

    assert(archive != NULL);
    assert(resolver != NULL);

    /* Flush any queued entries */
    do {
        entry = NULL;
        archive_entry_linkify(resolver, &entry, &sparse);

        if (entry != NULL) {
            if (add_payload_entry(archive, entry, tags) != 0) {
                return -1;
            }

            archive_entry_free(entry);
        }
    } while (entry != NULL);

    /* Close the archive */
    if (archive_write_close(archive) != ARCHIVE_OK) {
        fprintf(stderr, "Unable to close archive: %s\n", archive_error_string(archive));
        return -1;
    }

    /* Free the resources */
    archive_entry_linkresolver_free(resolver);
    (void) archive_write_free(archive);

    return 0;
}
