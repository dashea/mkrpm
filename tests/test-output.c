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

#include "output.h"
#include "rpmtypes.h"
#include "tagdb.h"

#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

/* wrapper for fwrite
 * any output from the unit tests themselves is going to go through fwrite, so
 * we can't unconditionally wrap it. Use a marker value for the FILE argument to
 * determine whether or not this is a wrapped call.
 */
#define WRAP_OUTPUT ((FILE *) 0x00000001)

extern size_t __real_fwrite(const void *, size_t, size_t, FILE *);
size_t __wrap_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (stream != WRAP_OUTPUT) {
        return __real_fwrite(ptr, size, nmemb, stream);
    }

    check_expected(ptr);
    check_expected(size);
    check_expected(nmemb);

    return mock_type(size_t);
}

static void test_output_lead(__attribute__((unused)) void **state) {
    char rpmlead_buf[96];
    const char *nevra = "testy-1.0-1.x86_64";

    /* magic */
    rpmlead_buf[0] = 0xED;
    rpmlead_buf[1] = 0xAB;
    rpmlead_buf[2] = 0xEE;
    rpmlead_buf[3] = 0xDB;

    /* major */
    rpmlead_buf[4] = 0x03;
    /* minor */
    rpmlead_buf[5] = 0x00;

    /* type */
    rpmlead_buf[6] = 0x00;
    rpmlead_buf[7] = 0x00;

    /* archnum */
    rpmlead_buf[8] = 0x00;
    rpmlead_buf[9] = 0x01;

    /* name */
    rpmlead_buf[10] = 't';
    rpmlead_buf[11] = 'e';
    rpmlead_buf[12] = 's';
    rpmlead_buf[13] = 't';
    rpmlead_buf[14] = 'y';
    rpmlead_buf[15] = '-';
    rpmlead_buf[16] = '1';
    rpmlead_buf[17] = '.';
    rpmlead_buf[18] = '0';
    rpmlead_buf[19] = '-';
    rpmlead_buf[20] = '1';
    rpmlead_buf[21] = '.';
    rpmlead_buf[22] = 'x';
    rpmlead_buf[23] = '8';
    rpmlead_buf[24] = '6';
    rpmlead_buf[25] = '_';
    rpmlead_buf[26] = '6';
    rpmlead_buf[27] = '4';
    rpmlead_buf[28] = 0;
    rpmlead_buf[29] = 0;
    rpmlead_buf[30] = 0;
    rpmlead_buf[31] = 0;
    rpmlead_buf[32] = 0;
    rpmlead_buf[33] = 0;
    rpmlead_buf[34] = 0;
    rpmlead_buf[35] = 0;
    rpmlead_buf[36] = 0;
    rpmlead_buf[37] = 0;
    rpmlead_buf[38] = 0;
    rpmlead_buf[39] = 0;
    rpmlead_buf[40] = 0;
    rpmlead_buf[41] = 0;
    rpmlead_buf[42] = 0;
    rpmlead_buf[43] = 0;
    rpmlead_buf[44] = 0;
    rpmlead_buf[45] = 0;
    rpmlead_buf[46] = 0;
    rpmlead_buf[47] = 0;
    rpmlead_buf[48] = 0;
    rpmlead_buf[49] = 0;
    rpmlead_buf[50] = 0;
    rpmlead_buf[51] = 0;
    rpmlead_buf[52] = 0;
    rpmlead_buf[53] = 0;
    rpmlead_buf[54] = 0;
    rpmlead_buf[55] = 0;
    rpmlead_buf[56] = 0;
    rpmlead_buf[57] = 0;
    rpmlead_buf[58] = 0;
    rpmlead_buf[59] = 0;
    rpmlead_buf[60] = 0;
    rpmlead_buf[61] = 0;
    rpmlead_buf[62] = 0;
    rpmlead_buf[63] = 0;
    rpmlead_buf[64] = 0;
    rpmlead_buf[65] = 0;
    rpmlead_buf[66] = 0;
    rpmlead_buf[67] = 0;
    rpmlead_buf[68] = 0;
    rpmlead_buf[69] = 0;
    rpmlead_buf[70] = 0;
    rpmlead_buf[71] = 0;
    rpmlead_buf[72] = 0;
    rpmlead_buf[73] = 0;
    rpmlead_buf[74] = 0;
    rpmlead_buf[75] = 0;

    /* osnum */
    rpmlead_buf[76] = 0x00;
    rpmlead_buf[77] = 0x01;

    /* signature type */
    rpmlead_buf[78] = 0x00;
    rpmlead_buf[79] = 0x05;

    /* "reserved" */
    rpmlead_buf[80] = 0;
    rpmlead_buf[81] = 0;
    rpmlead_buf[82] = 0;
    rpmlead_buf[83] = 0;
    rpmlead_buf[84] = 0;
    rpmlead_buf[85] = 0;
    rpmlead_buf[86] = 0;
    rpmlead_buf[87] = 0;
    rpmlead_buf[88] = 0;
    rpmlead_buf[89] = 0;
    rpmlead_buf[90] = 0;
    rpmlead_buf[91] = 0;
    rpmlead_buf[92] = 0;
    rpmlead_buf[93] = 0;
    rpmlead_buf[94] = 0;
    rpmlead_buf[95] = 0;

    expect_memory(__wrap_fwrite, ptr, rpmlead_buf, 96);
    expect_value(__wrap_fwrite, size, 1);
    expect_value(__wrap_fwrite, nmemb, 96);
    will_return(__wrap_fwrite, 96);

    assert_int_equal(output_lead(WRAP_OUTPUT, nevra), 0);

    /* Check that fwrite failure is returned as failure */
    expect_any(__wrap_fwrite, ptr);
    expect_any(__wrap_fwrite, size);
    expect_any(__wrap_fwrite, nmemb);
    will_return(__wrap_fwrite, 0);

    assert_int_equal(output_lead(WRAP_OUTPUT, nevra), -1);
}

static void test_align_tag(__attribute__((unused)) void **state) {
    assert_int_equal(align_tag(RPM_INT16_TYPE, 45), 46);
    assert_int_equal(align_tag(RPM_INT16_TYPE, 46), 46);
    assert_int_equal(align_tag(RPM_INT32_TYPE, 46), 48);
    assert_int_equal(align_tag(RPM_INT32_TYPE, 48), 48);
    assert_int_equal(align_tag(RPM_INT64_TYPE, 45), 48);
    assert_int_equal(align_tag(RPM_INT64_TYPE, 48), 48);
    assert_int_equal(align_tag(RPM_STRING_ARRAY_TYPE, 45), 45);
}

static void test_construct_tag_header(__attribute__((unused)) void **state) {
    uint32_t u32_buf;
    uint32_t offset = 48;
    uint32_t count = 1;

    char expected_buffer[16] = { 0 };
    char output_buffer[16] = { 0 };

    /* Build a tag for RPMTAG_SIZE */
    /* tag */
    u32_buf = htobe32(RPMTAG_SIZE);
    memcpy(expected_buffer, &u32_buf, 4);

    /* type */
    u32_buf = htobe32(RPM_INT32_TYPE);
    memcpy(expected_buffer + 4, &u32_buf, 4);

    /* offset */
    u32_buf = htobe32(offset);
    memcpy(expected_buffer + 8, &u32_buf, 4);

    /* count */
    u32_buf = htobe32(count);
    memcpy(expected_buffer + 12, &u32_buf, 4);

    construct_tag_header(RPMTAG_SIZE, RPM_INT32_TYPE, offset, count, output_buffer);
    assert_memory_equal(output_buffer, expected_buffer, sizeof(expected_buffer));
}

static void test_construct_header(__attribute__((unused)) void **state) {
    tag_db *tags;
    char *output_buffer;
    size_t output_size;
    uint32_t u32_buf;

    uint32_t size_value = 47;
    uint32_t filesize_1 = 48;
    uint32_t filesize_2 = 48;

    /* 16-byte header, 2 16-byte index records, 12 bytes of data */
    size_t expected_size = 60;
    char expected_buffer[60] = { 0 };

    tags = init_tag_db();
    assert_non_null(tags);

    /* Add a couple of tags */
    u32_buf = htobe32(49);
    assert_int_equal(add_tag(tags, RPMTAG_FILESIZES, &filesize_1, sizeof(filesize_1)), 0);
    u32_buf = htobe32(48);
    assert_int_equal(add_tag(tags, RPMTAG_FILESIZES, &filesize_2, sizeof(filesize_2)), 0);

    assert_int_equal(add_tag(tags, RPMTAG_SIZE, &size_value, sizeof(size_value)), 0);

    /* construct what we expect to come back */
    /* header magic */
    u32_buf = htobe32(RPMHEADER_MAGIC);
    memcpy(expected_buffer, &u32_buf, 4);

    /* four bytes "reserved", leave as 0's */
    /* nindex, four bytes, should be 2 for the 2 tags */
    u32_buf = htobe32(2);
    memcpy(expected_buffer + 8, &u32_buf, 4);

    /* hsize, four bytes, should be 12 */
    u32_buf = htobe32(12);
    memcpy(expected_buffer + 12, &u32_buf, 4);

    /* index records. The tags_used list is built by prepending to head, so it's
     * in reverse order with respect to the add_tag calls.
     */
    construct_tag_header(RPMTAG_SIZE, RPM_INT32_TYPE, 0, 1, expected_buffer + 16);
    construct_tag_header(RPMTAG_FILESIZES, RPM_INT32_TYPE, 4, 2, expected_buffer + 32);

    /* data blob */
    /* RPMTAG_SIZE value */
    memcpy(expected_buffer + 48, &size_value, 4);

    /* RPMTAG_FILESIZE array */
    memcpy(expected_buffer + 52, &filesize_1, 4);
    memcpy(expected_buffer + 56, &filesize_2, 4);

    assert_int_equal(construct_header(tags, &output_buffer, &output_size, rpm_tag_get_type), 0);

    assert_int_equal(output_size, expected_size);
    assert_non_null(output_buffer);
    assert_memory_equal(output_buffer, expected_buffer, expected_size);

    free(output_buffer);
    free_tag_db(tags);
}

static void test_construct_header_bin(__attribute__((unused)) void **state) {
    /* Ensure the count is correctly adjusted for RPM_BIN_TYPE */

    tag_db *tags;
    char *output_buffer;
    size_t output_size;
    uint32_t u32_buf;

    char md5sum[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x16,
                        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    size_t expected_size = 64;
    char expected_buffer[64] = { 0 };

    tags = init_tag_db();
    assert_non_null(tags);

    assert_int_equal(add_tag(tags, RPMSIGTAG_MD5, md5sum, sizeof(md5sum)), 0);

    /* header magic */
    u32_buf = htobe32(RPMHEADER_MAGIC);
    memcpy(expected_buffer, &u32_buf, 4);

    /* four bytes "reserved", leave as 0's */
    /* nindex, four bytes */
    u32_buf = htobe32(1);
    memcpy(expected_buffer + 8, &u32_buf, 4);

    /* hsize, four bytes */
    u32_buf = htobe32(sizeof(md5sum));
    memcpy(expected_buffer + 12, &u32_buf, 4);

    /* index record */
    construct_tag_header(RPMSIGTAG_MD5, RPM_BIN_TYPE, 0, 32, expected_buffer + 16);

    /* data */
    memcpy(expected_buffer + 32, md5sum, sizeof(md5sum));

    assert_int_equal(construct_header(tags, &output_buffer, &output_size, rpm_sig_tag_get_type), 0);

    assert_int_equal(output_size, expected_size);
    assert_non_null(output_buffer);
    assert_memory_equal(output_buffer, expected_buffer, expected_size);

    free(output_buffer);
    free_tag_db(tags);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_output_lead),
        cmocka_unit_test(test_align_tag),
        cmocka_unit_test(test_construct_tag_header),
        cmocka_unit_test(test_construct_header_bin),
        cmocka_unit_test(test_construct_header),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
