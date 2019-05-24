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

/* Same thing for fseeko */
extern int __real_fseeko(FILE *, off_t, int);
int __wrap_fseeko(FILE *stream, off_t offset, int whence) {
    if (stream != WRAP_OUTPUT) {
        return __real_fseeko(stream, offset, whence);
    }

    check_expected(offset);
    check_expected(whence);

    return mock_type(int);
}

/* Fake rpmTagType functions */
rpmTagType bin_type(int i) { return RPM_BIN_TYPE; }
rpmTagType int32_type(int i) { return RPM_INT32_TYPE; }

static void test_output_lead(void **state) {
    unsigned char rpmlead_buf[96];
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

static void test_align_tag(void **state) {
    assert_int_equal(align_tag(RPM_INT16_TYPE, 45), 46);
    assert_int_equal(align_tag(RPM_INT16_TYPE, 46), 46);
    assert_int_equal(align_tag(RPM_INT32_TYPE, 46), 48);
    assert_int_equal(align_tag(RPM_INT32_TYPE, 48), 48);
    assert_int_equal(align_tag(RPM_INT64_TYPE, 45), 48);
    assert_int_equal(align_tag(RPM_INT64_TYPE, 48), 48);
    assert_int_equal(align_tag(RPM_STRING_ARRAY_TYPE, 45), 45);
}

static void test_construct_tag(void **state) {
    struct tag_entry entry;
    uint32_t tag_entry_data;

    uint32_t u32_buf;
    off_t next_index;
    off_t data_start;
    off_t data_used;

    /* Build a tag for RPMTAG_SIZE */
    tag_entry_data = htobe32(420);
    entry.count = 1;
    entry.data_used = 4;
    entry.data_total = 4;
    entry.data = &tag_entry_data;

    /* Describe a header buffer with no tags written, no data written, and space for two tag index records.
     * i.e., next_index is the end of the rpmheader struct (32), data_start is (next_index + (2 * sizeof(struct rpmhdrindex))) == 96,
     * and data_used is 0.
     *
     * We expect a seek to where the index will be written (32), one fwrite for each rpmhdrindex member, a seek to the start of the data,
     * and a fwrite for the data.
     */
    next_index = 32;
    data_start = 96;
    data_used = 0;

    expect_value(__wrap_fseeko, offset, next_index);
    expect_value(__wrap_fseeko, whence, SEEK_SET);
    will_return(__wrap_fseeko, 0);

    u32_buf = htobe32(RPMTAG_SIZE);
    expect_memory(__wrap_fwrite, ptr, &u32_buf, 4);
    expect_value(__wrap_fwrite, size, 4);
    expect_value(__wrap_fwrite, nmemb, 1);
    will_return(__wrap_fwrite, 1);

    u32_buf = htobe32(RPM_INT32_TYPE);
    expect_memory(__wrap_fwrite, ptr, &u32_buf, 4);
    expect_value(__wrap_fwrite, size, 4);
    expect_value(__wrap_fwrite, nmemb, 1);
    will_return(__wrap_fwrite, 1);

    u32_buf = 0;
    expect_memory(__wrap_fwrite, ptr, &u32_buf, 4);
    expect_value(__wrap_fwrite, size, 4);
    expect_value(__wrap_fwrite, nmemb, 1);
    will_return(__wrap_fwrite, 1);

    u32_buf = htobe32(entry.count);
    expect_memory(__wrap_fwrite, ptr, &u32_buf, 4);
    expect_value(__wrap_fwrite, size, 4);
    expect_value(__wrap_fwrite, nmemb, 1);
    will_return(__wrap_fwrite, 1);

    expect_value(__wrap_fseeko, offset, data_start);
    expect_value(__wrap_fseeko, whence, SEEK_SET);
    will_return(__wrap_fseeko, 0);

    expect_memory(__wrap_fwrite, ptr, entry.data, entry.data_used);
    expect_value(__wrap_fwrite, size, 1);
    expect_value(__wrap_fwrite, nmemb, entry.data_used);
    will_return(__wrap_fwrite, entry.data_used);

    assert_int_equal(construct_tag(RPMTAG_SIZE, &entry, next_index, data_start, &data_used, int32_type, WRAP_OUTPUT), 0);
    assert_int_equal(data_used, 4);
}

static void test_construct_tag_bin(void **state) {
    /* Check that the count for RPM_BIN_TYPE is correctly adjusted. */
    struct tag_entry entry;
    unsigned char tag_entry_data[32] = { 0 };
    uint32_t u32_buf;

    off_t next_index;
    off_t data_start;
    off_t data_used;

    entry.count = 1;
    entry.data_used = sizeof(tag_entry_data);
    entry.data_total = sizeof(tag_entry_data);
    entry.data = tag_entry_data;

    next_index = 32;
    data_start = 96;
    data_used = 0;

    expect_any_always(__wrap_fseeko, offset);
    expect_any_always(__wrap_fseeko, whence);
    will_return_always(__wrap_fseeko, 0);

    u32_buf = htobe32(RPMTAG_SIZE);
    expect_memory(__wrap_fwrite, ptr, &u32_buf, 4);
    expect_value(__wrap_fwrite, size, 4);
    expect_value(__wrap_fwrite, nmemb, 1);
    will_return(__wrap_fwrite, 1);

    u32_buf = htobe32(RPM_BIN_TYPE);
    expect_memory(__wrap_fwrite, ptr, &u32_buf, 4);
    expect_value(__wrap_fwrite, size, 4);
    expect_value(__wrap_fwrite, nmemb, 1);
    will_return(__wrap_fwrite, 1);

    u32_buf = 0;
    expect_memory(__wrap_fwrite, ptr, &u32_buf, 4);
    expect_value(__wrap_fwrite, size, 4);
    expect_value(__wrap_fwrite, nmemb, 1);
    will_return(__wrap_fwrite, 1);

    u32_buf = htobe32(sizeof(tag_entry_data));
    expect_memory(__wrap_fwrite, ptr, &u32_buf, 4);
    expect_value(__wrap_fwrite, size, 4);
    expect_value(__wrap_fwrite, nmemb, 1);
    will_return(__wrap_fwrite, 1);

    expect_memory(__wrap_fwrite, ptr, entry.data, entry.data_used);
    expect_value(__wrap_fwrite, size, 1);
    expect_value(__wrap_fwrite, nmemb, entry.data_used);
    will_return(__wrap_fwrite, entry.data_used);

    assert_int_equal(construct_tag(RPMTAG_SIZE, &entry, next_index, data_start, &data_used, bin_type, WRAP_OUTPUT), 0);
}

static void test_construct_tag_write_errors(void **state) {
    struct tag_entry entry;
    uint32_t tag_entry_data;

    off_t next_index;
    off_t data_start;
    off_t data_used;

    tag_entry_data = 0;
    entry.count = 1;
    entry.data_used = 4;
    entry.data_total = 4;
    entry.data = &tag_entry_data;

    next_index = 32;
    data_start = 96;
    data_used = 0;

    /* Ignore all input, just set an error in the output at each point */
    expect_any_always(__wrap_fseeko, offset);
    expect_any_always(__wrap_fseeko, whence);

    expect_any_always(__wrap_fwrite, ptr);
    expect_any_always(__wrap_fwrite, size);
    expect_any_always(__wrap_fwrite, nmemb);

    will_return(__wrap_fseeko, -1);
    assert_int_equal(construct_tag(RPMTAG_SIZE, &entry, next_index, data_start, &data_used, int32_type, WRAP_OUTPUT), -1);

    will_return(__wrap_fseeko, 0);
    will_return(__wrap_fwrite, 0);
    assert_int_equal(construct_tag(RPMTAG_SIZE, &entry, next_index, data_start, &data_used, int32_type, WRAP_OUTPUT), -1);

    will_return(__wrap_fseeko, 0);
    will_return(__wrap_fwrite, 1);
    will_return(__wrap_fwrite, 0);
    assert_int_equal(construct_tag(RPMTAG_SIZE, &entry, next_index, data_start, &data_used, int32_type, WRAP_OUTPUT), -1);

    will_return(__wrap_fseeko, 0);
    will_return_count(__wrap_fwrite, 1, 2);
    will_return(__wrap_fwrite, 0);
    assert_int_equal(construct_tag(RPMTAG_SIZE, &entry, next_index, data_start, &data_used, int32_type, WRAP_OUTPUT), -1);

    will_return(__wrap_fseeko, 0);
    will_return_count(__wrap_fwrite, 1, 3);
    will_return(__wrap_fwrite, 0);
    assert_int_equal(construct_tag(RPMTAG_SIZE, &entry, next_index, data_start, &data_used, int32_type, WRAP_OUTPUT), -1);

    will_return(__wrap_fseeko, 0);
    will_return_count(__wrap_fwrite, 1, 4);
    will_return(__wrap_fseeko, -1);
    assert_int_equal(construct_tag(RPMTAG_SIZE, &entry, next_index, data_start, &data_used, int32_type, WRAP_OUTPUT), -1);

    will_return_count(__wrap_fseeko, 0, 2);
    will_return_count(__wrap_fwrite, 1, 4);
    will_return(__wrap_fwrite, 0);
    assert_int_equal(construct_tag(RPMTAG_SIZE, &entry, next_index, data_start, &data_used, int32_type, WRAP_OUTPUT), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_output_lead),
        cmocka_unit_test(test_align_tag),
        cmocka_unit_test(test_construct_tag),
        cmocka_unit_test(test_construct_tag_bin),
        cmocka_unit_test(test_construct_tag_write_errors),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
