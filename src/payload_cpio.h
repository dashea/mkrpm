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

#ifndef _PAYLOAD_CPIO_H
#define _PAYLOAD_CPIO_H

#include <stdio.h>
#include <sys/stat.h>

#include <archive.h>
#include <archive_entry.h>

#include "tagdb.h"

struct archive * init_archive(FILE *, struct archive_entry_linkresolver **);
int add_file_to_payload(struct archive *, struct archive_entry_linkresolver *, tag_db *, const char *, struct stat *);
int finish_archive(struct archive *, struct archive_entry_linkresolver *, tag_db *);

#endif
