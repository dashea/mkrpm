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

#include "metadata.h"
#include "rpmtypes.h"
#include "tagdb.h"

#include <assert.h>
#include <endian.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#define EMPTY_MD5SUM    "d41d8cd98f00b204e9800998ecf8427e"

/* Wrappers for getpwuid and getgrgid, so we can fake user/group names predictably */
struct passwd * __wrap_getpwuid(uid_t uid) {
    static struct passwd pwd;
    char *user_name;

    check_expected(uid);
    user_name = mock_ptr_type(char *);

    if (user_name == NULL) {
        return NULL;
    }

    pwd.pw_name = user_name;
    pwd.pw_uid = uid;

    return &pwd;
}

struct group * __wrap_getgrgid(gid_t gid) {
    static struct group grp;
    char *group_name;

    check_expected(gid);
    group_name = mock_ptr_type(char *);

    if (group_name == NULL) {
        return NULL;
    }

    grp.gr_name = group_name;
    grp.gr_gid = gid;

    return &grp;
}

/* Override add_tag. This just ensures that add_tag was called with the expected arguments */
extern int __real_add_tag(tag_db *, rpmTag, const void *, size_t);
int __wrap_add_tag(tag_db *db, rpmTag tag, const void *data, size_t data_size) {
    int retval;
    check_expected(tag);
    check_expected(data);
    check_expected(data_size);

    retval = mock_type(int);
    return retval;
}

static void test_add_file_tags_simple(void **state) {
    struct stat sbuf;
    tag_db *tags;

    /* Keep a second copy of the stat data, so there's correctly sized and ordered memory to check
     * add_tag calls against.
     */
    uint32_t dev;
    uint32_t ino;
    uint16_t mode;
    uint16_t rdev;
    uint32_t size;
    uint32_t mtime;

    uint32_t zero = 0;

    tags = init_tag_db();
    assert_non_null(tags);

    /* host byte order */
    sbuf.st_dev = 0xFD04;
    sbuf.st_ino = 0x00C0FFEE;
    sbuf.st_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH;
    sbuf.st_uid = 1000;
    sbuf.st_gid = 1000;
    sbuf.st_rdev = 0;
    sbuf.st_size = 47;
    sbuf.st_mtime = 0xDEADBEEF;

    /* network byte order */
    dev = htobe32(sbuf.st_dev);
    ino = htobe32(sbuf.st_ino);
    mode = htobe16(sbuf.st_mode);
    rdev = htobe16(sbuf.st_rdev);
    size = htobe32(sbuf.st_size);
    mtime = htobe32(sbuf.st_mtime);

    /* Expect the uid/gid translation function calls */
    expect_value(__wrap_getpwuid, uid, sbuf.st_uid);
    will_return(__wrap_getpwuid, "test-user");

    expect_value(__wrap_getgrgid, gid, sbuf.st_gid);
    will_return(__wrap_getgrgid, "test-group");

    /* Queue up the value for the expected calls to add_tag */
    expect_value(__wrap_add_tag, tag, RPMTAG_SIZE);
    expect_memory(__wrap_add_tag, data, &size, 4);
    expect_value(__wrap_add_tag, data_size, 4);
    will_return(__wrap_add_tag, 0);

    expect_value(__wrap_add_tag, tag, RPMTAG_FILESIZES);
    expect_memory(__wrap_add_tag, data, &size, 4);
    expect_value(__wrap_add_tag, data_size, 4);
    will_return(__wrap_add_tag, 0);

    expect_value(__wrap_add_tag, tag, RPMTAG_FILEMODES);
    expect_memory(__wrap_add_tag, data, &mode, 2);
    expect_value(__wrap_add_tag, data_size, 2);
    will_return(__wrap_add_tag, 0);

    expect_value(__wrap_add_tag, tag, RPMTAG_FILERDEVS);
    expect_memory(__wrap_add_tag, data, &rdev, 2);
    expect_value(__wrap_add_tag, data_size, 2);
    will_return(__wrap_add_tag, 0);

    expect_value(__wrap_add_tag, tag, RPMTAG_FILEMTIMES);
    expect_memory(__wrap_add_tag, data, &mtime, 4);
    expect_value(__wrap_add_tag, data_size, 4);
    will_return(__wrap_add_tag, 0);

    expect_value(__wrap_add_tag, tag, RPMTAG_FILEMD5S);
    expect_string(__wrap_add_tag, data, EMPTY_MD5SUM);
    expect_value(__wrap_add_tag, data_size, strlen(EMPTY_MD5SUM) + 1);
    will_return(__wrap_add_tag, 0);

    expect_value(__wrap_add_tag, tag, RPMTAG_FILELINKTOS);
    expect_string(__wrap_add_tag, data, "");
    expect_value(__wrap_add_tag, data_size, 1);
    will_return(__wrap_add_tag, 0);

    expect_value(__wrap_add_tag, tag, RPMTAG_FILEFLAGS);
    expect_memory(__wrap_add_tag, data, &zero, 4);
    expect_value(__wrap_add_tag, data_size, 4);
    will_return(__wrap_add_tag, 0);

    expect_value(__wrap_add_tag, tag, RPMTAG_FILEUSERNAME);
    expect_string(__wrap_add_tag, data, "test-user");
    expect_value(__wrap_add_tag, data_size, 10);
    will_return(__wrap_add_tag, 0);

    expect_value(__wrap_add_tag, tag, RPMTAG_FILEGROUPNAME);
    expect_string(__wrap_add_tag, data, "test-group");
    expect_value(__wrap_add_tag, data_size, 11);
    will_return(__wrap_add_tag, 0);

    expect_value(__wrap_add_tag, tag, RPMTAG_FILEDEVICES);
    expect_memory(__wrap_add_tag, data, &dev, 4);
    expect_value(__wrap_add_tag, data_size, 4);
    will_return(__wrap_add_tag, 0);

    expect_value(__wrap_add_tag, tag, RPMTAG_FILEINODES);
    expect_memory(__wrap_add_tag, data, &ino, 4);
    expect_value(__wrap_add_tag, data_size, 4);
    will_return(__wrap_add_tag, 0);

    expect_value(__wrap_add_tag, tag, RPMTAG_FILELANGS);
    expect_string(__wrap_add_tag, data, "");
    expect_value(__wrap_add_tag, data_size, 1);
    will_return(__wrap_add_tag, 0);

    expect_value(__wrap_add_tag, tag, RPMTAG_OLDFILENAMES);
    expect_string(__wrap_add_tag, data, "/whatever");
    expect_value(__wrap_add_tag, data_size, 10);
    will_return(__wrap_add_tag, 0);

    assert_int_equal(add_file_tags(tags, "/whatever", &sbuf, "", EMPTY_MD5SUM), 0);

    free_tag_db(tags);
}

static void test_add_file_tags_big_values(void **state) {
    struct stat sbuf;
    tag_db *tags;
    uint32_t u32_buf;

    tags = init_tag_db();
    assert_non_null(tags);

    /* size > UINT32_MAX */
    memset(&sbuf, 0, sizeof(sbuf));
    sbuf.st_size = 0x100000000LL;
    assert_int_equal(add_file_tags(tags, "/whatever", &sbuf, "", ""), -1);

    /* mtime > UINT32_MAX */
    memset(&sbuf, 0, sizeof(sbuf));
    sbuf.st_mtime = 0x100000000LL;
    assert_int_equal(add_file_tags(tags, "/whatever", &sbuf, "", ""), -1);

    /* combined size (RPMTAG_SIZE) > UINT32_MAX */
    /* Start with UINT32_MAX already in RPMTAG_SIZE */
    u32_buf = 0xFFFFFFFF;
    assert_int_equal(__real_add_tag(tags, RPMTAG_SIZE, &u32_buf, 4), 0);

    memset(&sbuf, 0, sizeof(sbuf));
    sbuf.st_size = 1;
    assert_int_equal(add_file_tags(tags, "/whoever", &sbuf, "", ""), -1);

    free_tag_db(tags);
}

static void test_add_file_tags_combined_size(void **state) {
    struct stat sbuf;
    tag_db *tags;
    uint32_t u32_buf;

    tags = init_tag_db();
    assert_non_null(tags);

    /* Start with an initial size */
    u32_buf = htobe32(420);
    assert_int_equal(__real_add_tag(tags, RPMTAG_SIZE, &u32_buf, 4), 0);

    /* Add a new size */
    memset(&sbuf, 0, sizeof(sbuf));
    sbuf.st_size = 69;

    expect_any_always(__wrap_add_tag, tag);
    expect_any_always(__wrap_add_tag, data);
    expect_any_always(__wrap_add_tag, data_size);
    will_return_always(__wrap_add_tag, 0);

    expect_any_always(__wrap_getpwuid, uid);
    will_return_always(__wrap_getpwuid, NULL);

    expect_any_always(__wrap_getgrgid, gid);
    will_return_always(__wrap_getgrgid, NULL);

    assert_int_equal(add_file_tags(tags, "/whatever", &sbuf, "", ""), 0);

    assert_non_null(tags->entries[RPMTAG_SIZE]);
    assert_non_null(tags->entries[RPMTAG_SIZE]->data);
    assert_int_equal(*((uint32_t *) tags->entries[RPMTAG_SIZE]->data), htobe32(420 + 69));

    free_tag_db(tags);
}

static void test_add_file_tags_no_user_group(void **state) {
    struct stat sbuf;
    tag_db *tags;

    tags = init_tag_db();
    assert_non_null(tags);

    memset(&sbuf, 0, sizeof(sbuf));
    sbuf.st_mode = S_IFREG;
    sbuf.st_uid = 1000;
    sbuf.st_gid = 2000;

    /* Return NULL for the UID and GID lookups */
    expect_value(__wrap_getpwuid, uid, sbuf.st_uid);
    will_return(__wrap_getpwuid, NULL);

    expect_value(__wrap_getgrgid, gid, sbuf.st_gid);
    will_return(__wrap_getgrgid, NULL);

    /* Add the expected calls to add_tag */
    /* SIZE, FILESIZES, FILEMODES, FILERDEVS, FILEMTIMES, FILEMD5S, FILELINKTOS, FILEFLAGS */
    expect_any_count(__wrap_add_tag, tag, 8);
    expect_any_count(__wrap_add_tag, data, 8);
    expect_any_count(__wrap_add_tag, data_size, 8);
    will_return_count(__wrap_add_tag, 0, 8);

    expect_value(__wrap_add_tag, tag, RPMTAG_FILEUSERNAME);
    expect_string(__wrap_add_tag, data, "1000");
    expect_value(__wrap_add_tag, data_size, 5);
    will_return(__wrap_add_tag, 0);

    expect_value(__wrap_add_tag, tag, RPMTAG_FILEGROUPNAME);
    expect_string(__wrap_add_tag, data, "2000");
    expect_value(__wrap_add_tag, data_size, 5);
    will_return(__wrap_add_tag, 0);

    /* FILEDEVICES, FILEINODES, FILELANGS, OLDFILENAMES */
    expect_any_count(__wrap_add_tag, tag, 4);
    expect_any_count(__wrap_add_tag, data, 4);
    expect_any_count(__wrap_add_tag, data_size, 4);
    will_return_count(__wrap_add_tag, 0, 4);

    assert_int_equal(add_file_tags(tags, "/whatever", &sbuf, "", ""), 0);

    free_tag_db(tags);
}

static void test_add_file_tags_add_tag_failures(void **state) {
    struct stat sbuf;
    tag_db *tags;
    int i;

    tags = init_tag_db();
    assert_non_null(tags);

    memset(&sbuf, 0, sizeof(sbuf));

    /* Ignore inputs, always return NULL for the uid/gid lookups. */
    expect_any_always(__wrap_getpwuid, uid);
    expect_any_always(__wrap_getgrgid, gid);
    will_return_always(__wrap_getpwuid, NULL);
    will_return_always(__wrap_getgrgid, NULL);

    expect_any_always(__wrap_add_tag, tag);
    expect_any_always(__wrap_add_tag, data);
    expect_any_always(__wrap_add_tag, data_size);

    /* check each of the 14 add_tag calls, make sure failure on any of them causes add_file_tags to fail and stop calling add_tag */
    for (i = 0; i < 14; i++) {
        if (i > 0) {
            will_return_count(__wrap_add_tag, 0, i);
        }

        will_return(__wrap_add_tag, -1);

        assert_int_equal(add_file_tags(tags, "/whatever", &sbuf, "", ""), -1);
    }

    free_tag_db(tags);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_add_file_tags_simple),
        cmocka_unit_test(test_add_file_tags_big_values),
        cmocka_unit_test(test_add_file_tags_no_user_group),
        cmocka_unit_test(test_add_file_tags_add_tag_failures),
        cmocka_unit_test(test_add_file_tags_combined_size),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
