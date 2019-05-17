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

#include "rpmtypes.h"
#include "tagdb.h"

#include <stdio.h>
#include <sys/queue.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

static void test_init_tag_db(void **state) {
    tag_db *db;

    db = init_tag_db();
    assert_non_null(db);
    free_tag_db(db);
}

static void test_free_tag_db(void **state) {
    /* Ensure freeing NULL doesn't bomb out */
    free_tag_db(NULL);
}

static void test_rpm_tag_get_type(void **state) {
    assert_int_equal(rpm_tag_get_type(RPMTAG_NAME),          RPM_STRING_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_VERSION),       RPM_STRING_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_RELEASE),       RPM_STRING_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_SUMMARY),       RPM_I18NSTRING_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_DESCRIPTION),   RPM_I18NSTRING_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_SIZE),          RPM_INT32_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_LICENSE),       RPM_STRING_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_GROUP),         RPM_STRING_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_OS),            RPM_STRING_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_ARCH),          RPM_STRING_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_FILESIZES),     RPM_INT32_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_FILEMODES),     RPM_INT16_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_FILERDEVS),     RPM_INT16_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_FILEMTIMES),    RPM_INT32_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_FILEMD5S),      RPM_STRING_ARRAY_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_FILELINKTOS),   RPM_STRING_ARRAY_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_FILEFLAGS),     RPM_INT32_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_FILEUSERNAME),  RPM_STRING_ARRAY_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_FILEGROUPNAME), RPM_STRING_ARRAY_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_PROVIDENAME),   RPM_STRING_ARRAY_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_REQUIREFLAGS),  RPM_INT32_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_REQUIRENAME),   RPM_STRING_ARRAY_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_REQUIREVERSION),RPM_STRING_ARRAY_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_FILEDEVICES),   RPM_INT32_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_FILEINODES),    RPM_INT32_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_FILELANGS),     RPM_STRING_ARRAY_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_PROVIDEFLAGS),  RPM_INT32_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_PROVIDEVERSION),RPM_STRING_ARRAY_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_DIRINDEXES),    RPM_INT32_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_BASENAMES),     RPM_STRING_ARRAY_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_DIRNAMES),      RPM_STRING_ARRAY_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_PAYLOADFORMAT), RPM_STRING_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_PAYLOADCOMPRESSOR), RPM_STRING_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_PAYLOADFLAGS),  RPM_STRING_TYPE);
}

static void test_rpm_sig_tag_get_type(void **state) {
    assert_int_equal(rpm_sig_tag_get_type(RPMSIGTAG_SIZE), RPM_INT32_TYPE);
    assert_int_equal(rpm_sig_tag_get_type(RPMSIGTAG_MD5),  RPM_BIN_TYPE);
}

static void test_add_tag_simple(void **state) {
    tag_db *db;
    uint32_t val = 47;
    tag_list_entry *list_entry;
    struct tag_entry *entry;
    int retval;

    /* Create a new tag db */
    db = init_tag_db();
    assert_non_null(db);

    /* Add a tag to an empty db */
    assert_int_equal(add_tag(db, RPMTAG_FILESIZES, &val, sizeof(val)), 0);

    /* Check that the tag is in the entries array */
    assert_non_null(db->entries[RPMTAG_FILESIZES]);

    /* Check that the tag is in the tags_used list */
    assert_false(SLIST_EMPTY(&db->tags_used));

    list_entry = SLIST_FIRST(&db->tags_used);
    assert_int_equal(list_entry->tag, RPMTAG_FILESIZES);

    /* Check that the actual entry struct looks correct */
    entry = db->entries[RPMTAG_FILESIZES];
    assert_int_equal(entry->count, 1);
    assert_int_equal(entry->data_used, 4);
    assert_int_equal(entry->data_total, BUFSIZ);
    assert_non_null(entry->data);
    assert_int_equal(*((uint32_t *) entry->data), 47);

    free_tag_db(db);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_init_tag_db),
        cmocka_unit_test(test_free_tag_db),
        cmocka_unit_test(test_rpm_tag_get_type),
        cmocka_unit_test(test_rpm_sig_tag_get_type),
        cmocka_unit_test(test_add_tag_simple),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
