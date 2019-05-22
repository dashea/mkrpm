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
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

/* Provide a wrapper for abort
 * Do a longjmp to a point saved by the caller, so that this
 * function, like abort, does not exit.
 */
void __wrap_abort(void) {
    jmp_buf *env = mock_ptr_type(jmp_buf *);
    longjmp(*env, 1);
}

/* Provide a wrapper for calloc
 * If the mock input is 0, return NULL, otherwise just do a normal calloc.
 */
extern void * __real_calloc(size_t nmemb, size_t size);
void * __wrap_calloc(size_t nmemb, size_t size) {
    int do_calloc = mock_type(int);

    if (do_calloc) {
        return __real_calloc(nmemb, size);
    }

    return NULL;
}

/* Provide a wrapper for realloc
 * If the mock input is 0, return NULL, otherwise just do a normal realloc.
 */
extern void * __real_realloc(void *ptr, size_t size);
void * __wrap_realloc(void *ptr, size_t size) {
    int do_realloc = mock_type(int);

    if (do_realloc) {
        return __real_realloc(ptr, size);
    }

    return NULL;
}

static void test_init_tag_db(void **state) {
    tag_db *db;

    will_return(__wrap_calloc, 1);
    db = init_tag_db();
    assert_non_null(db);
    free_tag_db(db);

    will_return(__wrap_calloc, 0);
    db = init_tag_db();
    assert_null(db);
}

static void test_free_tag_db(void **state) {
    /* Ensure freeing NULL doesn't bomb out */
    free_tag_db(NULL);
}

static void test_rpm_tag_get_type(void **state) {
    jmp_buf env;

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
    assert_int_equal(rpm_tag_get_type(RPMTAG_OLDFILENAMES),  RPM_STRING_ARRAY_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_DIRINDEXES),    RPM_INT32_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_BASENAMES),     RPM_STRING_ARRAY_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_DIRNAMES),      RPM_STRING_ARRAY_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_PAYLOADFORMAT), RPM_STRING_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_PAYLOADCOMPRESSOR), RPM_STRING_TYPE);
    assert_int_equal(rpm_tag_get_type(RPMTAG_PAYLOADFLAGS),  RPM_STRING_TYPE);

    /* Check that calling with an invalid tag calls abort() */
    if (setjmp(env) == 0) {
        will_return(__wrap_abort, &env);
        rpm_tag_get_type(RPMTAG_MAX);
    }
}

static void test_rpm_sig_tag_get_type(void **state) {
    jmp_buf env;

    assert_int_equal(rpm_sig_tag_get_type(RPMSIGTAG_SIZE), RPM_INT32_TYPE);
    assert_int_equal(rpm_sig_tag_get_type(RPMSIGTAG_MD5),  RPM_BIN_TYPE);

    /* Check that calling with an invalid tag calls abort() */
    if (setjmp(env) == 0) {
        will_return(__wrap_abort, &env);
        rpm_sig_tag_get_type(RPMSIGTAG_MAX);
    }
}

static void test_add_tag_simple(void **state) {
    tag_db *db;
    uint32_t val = 47;
    tag_list_entry *list_entry;
    struct tag_entry *entry;

    /* Create a new tag db */
    will_return(__wrap_calloc, 1);
    db = init_tag_db();
    assert_non_null(db);

    /* Add a tag to an empty db */
    will_return(__wrap_calloc, 1);
    will_return(__wrap_calloc, 1);
    will_return(__wrap_realloc, 1);
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

static void test_add_tag_array(void **state) {
    tag_db *db;
    uint32_t val1 = 47;
    uint32_t val2 = 48;
    tag_list_entry *list_entry;
    struct tag_entry *entry;

    /* Create a new tag db */
    will_return(__wrap_calloc, 1);
    db = init_tag_db();
    assert_non_null(db);

    /* Add a tag to an empty db */
    will_return(__wrap_calloc, 1);
    will_return(__wrap_calloc, 1);
    will_return(__wrap_realloc, 1);
    assert_int_equal(add_tag(db, RPMTAG_FILESIZES, &val1, sizeof(val1)), 0);

    /* Add another tag of the same type, ensure the tag is added to the array */
    assert_int_equal(add_tag(db, RPMTAG_FILESIZES, &val2, sizeof(val2)), 0);

    assert_non_null(db->entries[RPMTAG_FILESIZES]);

    assert_false(SLIST_EMPTY(&db->tags_used));
    list_entry = SLIST_FIRST(&db->tags_used);
    assert_int_equal(list_entry->tag, RPMTAG_FILESIZES);

    /* Check that both array values are present */
    entry = db->entries[RPMTAG_FILESIZES];
    assert_int_equal(entry->count, 2);
    assert_int_equal(entry->data_used, 8);
    assert_int_equal(entry->data_total, BUFSIZ);

    assert_non_null(entry->data);
    assert_int_equal(*((uint32_t *) entry->data), 47);
    assert_int_equal(*(((uint32_t *) entry->data) + 1), 48);

    free_tag_db(db);
}

static void test_add_tag_multiple(void **state) {
    tag_db *db;
    uint32_t val1 = 47;
    uint32_t val2 = 48;
    tag_list_entry *list_entry;
    struct tag_entry *entry;

    /* Create a new tag db */
    will_return(__wrap_calloc, 1);
    db = init_tag_db();
    assert_non_null(db);

    /* Add a tag to an empty db */
    will_return(__wrap_calloc, 1);
    will_return(__wrap_calloc, 1);
    will_return(__wrap_realloc, 1);
    assert_int_equal(add_tag(db, RPMTAG_FILESIZES, &val1, sizeof(val1)), 0);

    /* Add another tag of a different type */
    will_return(__wrap_calloc, 1);
    will_return(__wrap_calloc, 1);
    will_return(__wrap_realloc, 1);
    assert_int_equal(add_tag(db, RPMTAG_FILEFLAGS, &val2, sizeof(val2)), 0);

    assert_non_null(db->entries[RPMTAG_FILESIZES]);
    assert_non_null(db->entries[RPMTAG_FILEFLAGS]);

    assert_false(SLIST_EMPTY(&db->tags_used));

    list_entry = SLIST_FIRST(&db->tags_used);
    assert_int_equal(list_entry->tag, RPMTAG_FILEFLAGS);

    list_entry = SLIST_NEXT(list_entry, items);
    assert_non_null(list_entry);
    assert_int_equal(list_entry->tag, RPMTAG_FILESIZES);

    entry = db->entries[RPMTAG_FILESIZES];
    assert_int_equal(entry->count, 1);
    assert_int_equal(entry->data_used, 4);
    assert_int_equal(entry->data_total, BUFSIZ);

    assert_non_null(entry->data);
    assert_int_equal(*((uint32_t *) entry->data), 47);

    entry = db->entries[RPMTAG_FILEFLAGS];
    assert_int_equal(entry->count, 1);
    assert_int_equal(entry->data_used, 4);
    assert_int_equal(entry->data_total, BUFSIZ);

    assert_non_null(entry->data);
    assert_int_equal(*((uint32_t *) entry->data), 48);

    free_tag_db(db);
}

static void test_add_tag_malloc_errors(void **state) {
    tag_db *db;
    uint32_t val = 47;

    uint8_t input_buffer[BUFSIZ];
    uint8_t test_buffer[BUFSIZ];
    void *input_save;

    /* Create a new tag db */
    will_return(__wrap_calloc, 1);
    db = init_tag_db();
    assert_non_null(db);

    /* Add a tag, fail to allocate the tag entry */
    will_return(__wrap_calloc, 0);
    assert_int_equal(add_tag(db, RPMTAG_FILESIZES, &val, sizeof(val)), -1);
    assert_null(db->entries[RPMTAG_FILESIZES]);
    assert_true(SLIST_EMPTY(&db->tags_used));

    /* Add a tag, fail when allocating the linked list entry */
    will_return(__wrap_calloc, 1);
    will_return(__wrap_calloc, 0);
    assert_int_equal(add_tag(db, RPMTAG_FILESIZES, &val, sizeof(val)), -1);
    assert_null(db->entries[RPMTAG_FILESIZES]);
    assert_true(SLIST_EMPTY(&db->tags_used));

    /* Add a tag, fail when allocating the tag entry buffer */
    will_return(__wrap_calloc, 1);
    will_return(__wrap_calloc, 1);
    will_return(__wrap_realloc, 0);
    assert_int_equal(add_tag(db, RPMTAG_FILESIZES, &val, sizeof(val)), -1);
    assert_null(db->entries[RPMTAG_FILESIZES]);
    assert_true(SLIST_EMPTY(&db->tags_used));

    /* Add a tag successfully, fail when extending the tag entry's array */
    will_return(__wrap_calloc, 1);
    will_return(__wrap_calloc, 1);
    will_return(__wrap_realloc, 1);

    memset(input_buffer, 47, sizeof(input_buffer));
    assert_int_equal(add_tag(db, 0, input_buffer, sizeof(input_buffer)), 0);
    assert_non_null(db->entries[0]);
    assert_int_equal(db->entries[0]->count, 1);
    assert_int_equal(db->entries[0]->data_used, BUFSIZ);
    assert_int_equal(db->entries[0]->data_total, BUFSIZ);
    assert_non_null(db->entries[0]->data);
    input_save = db->entries[0]->data;

    will_return(__wrap_realloc, 0);
    assert_int_equal(add_tag(db, 0, input_buffer, sizeof(input_buffer)), -1);
    assert_non_null(db->entries[0]);
    assert_int_equal(db->entries[0]->count, 1);
    assert_int_equal(db->entries[0]->data_used, BUFSIZ);
    assert_int_equal(db->entries[0]->data_total, BUFSIZ);
    assert_non_null(db->entries[0]->data);
    assert_ptr_equal(db->entries[0]->data, input_save);

    memset(test_buffer, 47, sizeof(test_buffer));
    assert_int_equal(memcmp(input_save, test_buffer, BUFSIZ), 0);

    free_tag_db(db);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_init_tag_db),
        cmocka_unit_test(test_free_tag_db),
        cmocka_unit_test(test_rpm_tag_get_type),
        cmocka_unit_test(test_rpm_sig_tag_get_type),
        cmocka_unit_test(test_add_tag_simple),
        cmocka_unit_test(test_add_tag_multiple),
        cmocka_unit_test(test_add_tag_array),
        cmocka_unit_test(test_add_tag_malloc_errors),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
