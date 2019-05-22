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
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <archive.h>
#include <archive_entry.h>

#include "payload_cpio.h"

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

int add_payload_entry(struct archive *archive, struct archive_entry *entry) {
    const char *sourcepath;
    int fd;
    char buffer[BUFSIZ];
    ssize_t bytes_read;

    assert(archive != NULL);
    assert(entry != NULL);

    if (archive_write_header(archive, entry) != ARCHIVE_OK) {
        fprintf(stderr, "Unable to write archive entry: %s\n", archive_error_string(archive));
        return -1;
    }

    if ((archive_entry_filetype(entry) == AE_IFREG) && (archive_entry_size(entry) > 0)) {
        sourcepath = archive_entry_sourcepath(entry);
        fd = open(sourcepath, O_RDONLY);

        if (fd == -1) {
            fprintf(stderr, "Unable to open %s: %s\n", sourcepath, strerror(errno));
            return -1;
        }

        while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
            if (archive_write_data(archive, buffer, (size_t) bytes_read) < 0) {
                fprintf(stderr, "Unable to write data for %s to archive: %s\n", sourcepath, archive_error_string(archive));
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
    }

    return 0;
}

/* Add the given file to the CPIO payload, using write_func + output_handle to write the data
 * link_target must be a buffer of size PATH_MAX
 * Return 0 on success, and write the stat info for the file to sbuf.
 * Return -1 on failure.
 */
int add_file_to_payload(struct archive *archive, struct archive_entry_linkresolver *resolver, const char *pathname, struct stat *sbuf, char *link_target) {
    struct archive_entry *entry = NULL;
    struct archive_entry *sparse = NULL;

    int returncode = -1;

    assert(archive != NULL);
    assert(resolver != NULL);
    assert(pathname != NULL);
    assert(sbuf != NULL);
    assert(link_target != NULL);

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
        if (readlink(pathname, link_target, PATH_MAX) < 0) {
            fprintf(stderr, "Unable to readlink at %s: %s\n", pathname, strerror(errno));
            goto cleanup;
        }

        archive_entry_set_symlink(entry, link_target);
    } else {
        *link_target = '\0';
    }

    /* Run everything through the hardlink resolver */
    archive_entry_linkify(resolver, &entry, &sparse);

    /* Add any entries that came back from the resolver */
    if (entry != NULL) {
        if (add_payload_entry(archive, entry) != 0) {
            goto cleanup;
        }
    }

    if (sparse != NULL) {
        if (add_payload_entry(archive, sparse) != 0) {
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

int finish_archive(struct archive *archive, struct archive_entry_linkresolver *resolver) {
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
            if (add_payload_entry(archive, entry) != 0) {
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
