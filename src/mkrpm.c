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
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <archive.h>
#include <archive_entry.h>

#include "output.h"
#include "payload_cpio.h"
#include "rpmtypes.h"
#include "tagdb.h"

static int add_file(tag_db *, struct archive *, struct archive_entry_linkresolver *, const char *);
static int add_dir(tag_db *, struct archive *, struct archive_entry_linkresolver *, const char *);

static void usage(const char *argv0) {
    assert(argv0 != NULL);

    printf("Create an rpm from the given inputs.\n");
    printf("Usage: %s <input path> [<input path> ...]\n", argv0);
}

static int add_dir(tag_db *tags, struct archive *archive, struct archive_entry_linkresolver *resolver, const char *path) {
    DIR *dir;
    struct dirent *dirent;
    char *entry_path;

    if ((dir = opendir(path)) == NULL) {
        fprintf(stderr, "Unable to open directory %s: %s\n", path, strerror(errno));
        return -1;
    }

    while ((dirent = readdir(dir)) != NULL) {
        if ((strcmp(dirent->d_name, ".") == 0) || (strcmp(dirent->d_name, "..") == 0)) {
            continue;
        }

        if (asprintf(&entry_path, "%s/%s", path, dirent->d_name) < 0) {
            fprintf(stderr, "Unable to construct path for %s/%s: %s\n", path, dirent->d_name, strerror(errno));
            closedir(dir);
            return -1;
        }

        if (add_file(tags, archive, resolver, entry_path) != 0) {
            closedir(dir);
            free(entry_path);
            return -1;
        }

        free(entry_path);
    }

    if (errno != 0) {
        fprintf(stderr, "Error reading directory %s: %s\n", path, strerror(errno));
        closedir(dir);
        return -1;
    }

    closedir(dir);
    return 0;
}

static int add_file(tag_db *tags, struct archive *archive, struct archive_entry_linkresolver *resolver, const char *path) {
    struct stat sbuf;

    /* Add the file to the payload, and in doing so get the stat info */
    if (add_file_to_payload(archive, resolver, tags, path, &sbuf) != 0) {
        return -1;
    }

    /* if this is a directory, recurse */
    if (S_ISDIR(sbuf.st_mode)) {
        if (add_dir(tags, archive, resolver, path) != 0) {
            return -1;
        }
    }

    return 0;
}

int main(int argc, char **argv) {
    tag_db *tags;
    struct archive *archive;
    struct archive_entry_linkresolver *resolver;

    FILE *payload_output;
    char *payload_buffer = NULL;
    size_t payload_buffer_size;

    char *name = "mkrpm-payload";
    char *version = "1.0";
    char *release = "1";
    char *summary = "Package generated by mkrpm";
    char *description = "Package generated by mkrpm";
    char *license = "None";
    char *group = "Unspecified";
    char *os = "linux";
    char *arch = "noarch";
    char *payload_format = "cpio";
    char *compression = "gzip";
    char *payload_flags = "9";

    int i;

    if (argc < 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Use a open_memstream buffer to allocate memory for and store the payload */
    payload_output = open_memstream(&payload_buffer, &payload_buffer_size);
    if (payload_output == NULL) {
        fprintf(stderr, "Unable to allocate memory for payload buffer: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Initialize the payload and header data */
    tags = init_tag_db();
    if (tags == NULL) {
        fprintf(stderr, "Unable to allocate memory for tag database: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    archive = init_archive(payload_output, &resolver);
    if (archive == NULL) {
        fprintf(stderr, "Unable to initialize archive structures\n");
        exit(EXIT_FAILURE);
    }

    /* Add the required metadata */
    /* TODO: provide a way to set this information on the command-line */
    if ((add_tag(tags, RPMTAG_NAME, name, strlen(name) + 1) != 0) ||
            (add_tag(tags, RPMTAG_VERSION, version, strlen(version) + 1) != 0) ||
            (add_tag(tags, RPMTAG_RELEASE, release, strlen(release) + 1) != 0) ||
            (add_tag(tags, RPMTAG_SUMMARY, summary, strlen(summary) + 1) != 0) ||
            (add_tag(tags, RPMTAG_DESCRIPTION, description, strlen(description) + 1) != 0) ||
            (add_tag(tags, RPMTAG_LICENSE, license, strlen(license) + 1) != 0) ||
            (add_tag(tags, RPMTAG_GROUP, group, strlen(group) + 1) != 0) ||
            (add_tag(tags, RPMTAG_OS, os, strlen(os) + 1) != 0) ||
            (add_tag(tags, RPMTAG_ARCH, arch, strlen(arch) + 1) != 0) ||
            (add_tag(tags, RPMTAG_PAYLOADFORMAT, payload_format, strlen(payload_format) + 1) != 0) ||
            (add_tag(tags, RPMTAG_PAYLOADCOMPRESSOR, compression, strlen(compression) + 1) != 0) ||
            (add_tag(tags, RPMTAG_PAYLOADFLAGS, payload_flags, strlen(payload_flags) + 1) != 0) ||
            (add_tag(tags, RPMTAG_HEADERI18NTABLE, "C", 2) != 0)) {
        exit(EXIT_FAILURE);
    }

    /* Add the files specified on the command-line. */
    for (i = 1; i < argc; i++) {
        /* TODO normalize filenames */
        if (add_file(tags, archive, resolver, argv[i]) != 0) {
            exit(EXIT_FAILURE);
        }
    }

    /* Finalize the payload */
    if (finish_archive(archive, resolver, tags) != 0) {
        exit(EXIT_FAILURE);
    }

    if (fclose(payload_output) != 0) {
        fprintf(stderr, "Unable to finalize payload: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Output the RPM */
    /* XXX add an option for an output file that's not stdout */
    if (output_rpm(tags, payload_buffer, payload_buffer_size, stdout) != 0) {
        exit(EXIT_FAILURE);
    }

    free_tag_db(tags);
    free(payload_buffer);
    return EXIT_SUCCESS;
}
