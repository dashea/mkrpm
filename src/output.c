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
#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>

#include <openssl/md5.h>

#include "output.h"
#include "rpmtypes.h"
#include "tagdb.h"

int output_lead(FILE *output, const char *nevra) {
    /* Construct the lead structure */
    char rpmlead_buf[RPMLEAD_SIZE] = { 0 };

    /* magic, 4 bytes */
    rpmlead_buf[0] = ((RPMLEAD_MAGIC & 0xFF000000) >> 24);
    rpmlead_buf[1] = ((RPMLEAD_MAGIC & 0x00FF0000) >> 16);
    rpmlead_buf[2] = ((RPMLEAD_MAGIC & 0x0000FF00) >> 8);
    rpmlead_buf[3] = (RPMLEAD_MAGIC & 0x000000FF);

    /* major, 1 byte */
    rpmlead_buf[4] = 3;

    /* minor, 1 byte, leave as 0 */
    /* rpmlead_buf[5] = 0; */

    /* type, 2 bytes, leave as 0 for "binary" package */
    /* rpmlead_buf[6] = 0; */
    /* rpmlead_buf[7] = 0; */

    /* arch, 2 bytes */
    /* XXX maybe make this configurable or something but also nothing uses it who cares */
    /* XXX 0x0001 is intel, both 32 and 64 bit */
    rpmlead_buf[8] = 0;
    rpmlead_buf[9] = 1;

    /* name, truncate the NEVRA to 65-bytes + \0 */
    (void) strncpy(rpmlead_buf + 10, nevra, 65);

    /* osnum, 2 bytes, 1 for "linux" */
    rpmlead_buf[76] = 0;
    rpmlead_buf[77] = 1;

    /* signature_type, has to be 5 */
    rpmlead_buf[78] = 0;
    rpmlead_buf[79] = 5;

    /* remainder is "reserved", leave as 0 */

    if (fwrite(rpmlead_buf, 1, RPMLEAD_SIZE, output) != RPMLEAD_SIZE) {
        fprintf(stderr, "Error writing rpm lead: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

off_t align_tag(rpmTagType type, off_t offset) {
    int align;

    switch (type) {
        case RPM_INT16_TYPE:
            align = 2;
            break;
        case RPM_INT32_TYPE:
            align = 4;
            break;
        case RPM_INT64_TYPE:
            align = 8;
            break;
        default:
            align = 1;
    }

    if ((offset % align) != 0) {
        offset += align - (offset % align);
    }

    return offset;
}

void construct_tag_header(int tag, rpmTagType type, uint32_t data_offset, uint32_t count, char *output) {
    uint32_t u32_buf;

    /* Tag ID */
    u32_buf = htobe32(tag);
    memcpy(output, &u32_buf, sizeof(u32_buf));

    /* Tag type */
    u32_buf = htobe32(type);
    memcpy(output + 4, &u32_buf, sizeof(u32_buf));

    /* Offset into the data blob */
    u32_buf = htobe32(data_offset);
    memcpy(output + 8, &u32_buf, sizeof(u32_buf));

    /* Number of items */
    u32_buf = htobe32(count);
    memcpy(output + 12, &u32_buf, sizeof(u32_buf));
}

int construct_header(tag_db *tags, char **output_buffer, size_t *output_size, tag_type_func f_tag_type) {
    tag_list_entry *tag_entry;
    uint32_t tag_count;

    char *buffer = NULL;
    size_t buffer_size;

    uint32_t u32_buf;

    struct tag_entry *entry;
    rpmTagType type;

    size_t next_index;
    size_t data_start;

    uint32_t data_offset;
    uint32_t count;

    assert(tags != NULL);
    assert(output_buffer != NULL);
    assert(*output_buffer != NULL);
    assert(output_size != NULL);
    assert(f_tag_type != NULL);

    /* Count the tags and add up the sizes */
    /* Start with a buffer size of 16 for the rpmheader struct */
    tag_count = 0;
    buffer_size = 16;
    SLIST_FOREACH(tag_entry, &tags->tags_used, items) {
        tag_count++;
        buffer_size += 16 + tags->entries[tag_entry->tag]->data_used;
        buffer_size = align_tag(tag_entry->tag, buffer_size);
    }

    /* Allocate the buffer */
    if ((buffer = calloc(buffer_size, 1)) == NULL) {
        fprintf(stderr, "Unable to allocate memory for header: %s\n", strerror(errno));
        return -1;
    }

    *output_buffer = buffer;
    *output_size = buffer_size;

    /* Output the header's header */
    /* Magic, 4 bytes */
    u32_buf = htobe32(RPMHEADER_MAGIC);
    memcpy(buffer, &u32_buf, sizeof(u32_buf));

    /* Reserved, 4 bytes, must 0's which calloc already took care of */

    /* number of header tags */
    u32_buf = htobe32(tag_count);
    memcpy(buffer + 8, &u32_buf, sizeof(u32_buf));

    /* size of the data blob, which is the buffer size minus the rpmheader minus the index records
     * both the rpmheader and index structs are 16 bytes each
     */
    data_start = 16 * (tag_count + 1);
    u32_buf = htobe32(buffer_size - data_start);
    memcpy(buffer + 12, &u32_buf, sizeof(u32_buf));

    /* Output the tags and tag data. The index data starts after the 16 byte rpmheader */
    next_index = 16;
    data_offset = 0;

    SLIST_FOREACH(tag_entry, &tags->tags_used, items) {
        entry = tags->entries[tag_entry->tag];
        type = f_tag_type(tag_entry->tag);

        /* Align the start of the data */
        data_offset = align_tag(type, data_offset);

        /* For RPM_BIN_TYPE, count is the number of bytes, otherwise count is provided by the entry */
        if (type == RPM_BIN_TYPE) {
            count = entry->data_used;
        } else {
            count = entry->count;
        }

        /* Write the index data */
        construct_tag_header(tag_entry->tag, type, data_offset, count, buffer + next_index);
        next_index += 16;

        /* Write the data blog */
        memcpy(buffer + data_start + data_offset, entry->data, entry->data_used);
        data_offset += entry->data_used;
    }

    return 0;
}

int output_rpm(tag_db *tags, const void *payload, size_t payload_size, FILE *output) {
    char *nevra = NULL;

    char *header_buffer = NULL;
    size_t header_size;

    char *signature_header_buffer = NULL;
    size_t signature_header_size;

    uint32_t u32_buf;

    tag_db *signature_tag_db = NULL;
    off_t pad;

    MD5_CTX md5_ctx;
    unsigned char md5sum[MD5_DIGEST_LENGTH];

    int retval = -1;

    /* Construct a NEVRA for the rpmlead */
    /* TODO if epoch support gets added anywhere, it needs to get added here */
    if (asprintf(&nevra, "%s-%s-%s.%s",
                (char *) tags->entries[RPMTAG_NAME]->data,
                (char *) tags->entries[RPMTAG_VERSION]->data,
                (char *) tags->entries[RPMTAG_RELEASE]->data,
                (char *) tags->entries[RPMTAG_ARCH]->data) < 0) {
        fprintf(stderr, "Unable to construct NEVRA: %s\n", strerror(errno));
        goto cleanup;
    }

    if (output_lead(output, nevra) != 0) {
        goto cleanup;
    }

    /* Construct the header (the second one, not the signature one), since its data is needed for the signature header */
    if (construct_header(tags, &header_buffer, &header_size, rpm_tag_get_type) != 0) {
        goto cleanup;
    }

    /* Create a new tagdb for the signature header, add the appropriate data to it */
    signature_tag_db = init_tag_db();
    if (signature_tag_db == NULL) {
        goto cleanup;
    }

    /* RPMSIGTAG_SIZE is the size of the header plus the *compressed* payload */
    if ((header_size > UINT32_MAX) || (payload_size > UINT32_MAX) || ((header_size + payload_size) > UINT32_MAX)) {
        fprintf(stderr, "Data too large for RPM: header length: %zu, payload length: %zu\n", header_size, payload_size);
        goto cleanup;
    }

    u32_buf = (uint32_t) header_size + (uint32_t) payload_size;
    if (add_tag(signature_tag_db, RPMSIGTAG_SIZE, &u32_buf, sizeof(u32_buf)) != 0) {
        goto cleanup;
    }

    /* Generate the checksum for RPMSIGTAG_MD5 */
    if (!MD5_Init(&md5_ctx)) {
        fprintf(stderr, "Unable to initialize MD5 context\n");
        goto cleanup;
    }

    if (!MD5_Update(&md5_ctx, header_buffer, header_size) || !MD5_Update(&md5_ctx, payload, payload_size)) {
        fprintf(stderr, "Error updating header checksum\n");
        goto cleanup;
    }

    if (!MD5_Final(md5sum, &md5_ctx)) {
        fprintf(stderr, "Error finalizing header checksum\n");
        goto cleanup;
    }

    if (add_tag(signature_tag_db, RPMSIGTAG_MD5, md5sum, MD5_DIGEST_LENGTH) != 0) {
        goto cleanup;
    }

    /* Construct the signature header and output it */
    if (construct_header(signature_tag_db, &signature_header_buffer, &signature_header_size, rpm_sig_tag_get_type) != 0) {
        goto cleanup;
    }

    /* Since only the lead has been output so far, the start of the signature header is automatically 8-byte aligned */
    if (fwrite(signature_header_buffer, 1, signature_header_size, output) != signature_header_size) {
        fprintf(stderr, "Error writing signature header: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Add whatever padding is necesarry to get the next header aligned to an 8-byte boundary */
    if ((signature_header_size % 8) != 0) {
        pad = 8 - (signature_header_size % 8);
        if (fseeko(output, pad, SEEK_CUR) != 0) {
            fprintf(stderr, "Error writing header padding: %s\n", strerror(errno));
            goto cleanup;
        }
    }
    /* Output the other header and the payload */
    if (fwrite(header_buffer, 1, header_size, output) != header_size) {
        fprintf(stderr, "Error writing metadata header: %s\n", strerror(errno));
        goto cleanup;
    }

    if (fwrite(payload, 1, payload_size, output) != payload_size) {
        fprintf(stderr, "Error writing payload: %s\n", strerror(errno));
        goto cleanup;
    }

    if (fflush(output) != 0) {
        fprintf(stderr, "Error flushing output: %s\n", strerror(errno));
        goto cleanup;
    }

    retval = 0;

cleanup:
    free(nevra);
    free(header_buffer);
    free(signature_header_buffer);
    free_tag_db(signature_tag_db);

    return retval;
}
