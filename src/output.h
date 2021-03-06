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

#ifndef _OUTPUT_H_
#define _OUTPUT_H_

#include <stdio.h>
#include <sys/types.h>
#include "tagdb.h"

int output_lead(FILE *, const char *);

typedef rpmTagType (*tag_type_func)(int);

off_t align_tag(rpmTagType, off_t);
void construct_tag_header(int, rpmTagType, uint32_t, uint32_t, char *);
int construct_header(tag_db *, char **, size_t *, tag_type_func);

int output_rpm(tag_db *, const void *, size_t, FILE *);

#endif
