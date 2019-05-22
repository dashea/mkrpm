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

typedef rpmTagType (*tag_type_func)(int);

int construct_tag(int tag, struct tag_entry *entry, off_t next_index, off_t data_start, off_t *data_used, tag_type_func f_tag_type, FILE *output) {
    rpmTagType type = f_tag_type(tag);
    uint32_t count;
    uint32_t u32_buf;
    off_t data_offset = *data_used;

    /* In the case of RPM_BIN_TYPE, the count member of the tag entry is not the count we need to output.
     * The count to output in this case is the number of bytes in the entry.
     */
    if (type == RPM_BIN_TYPE) {
        count = (uint32_t) entry->data_used;
    } else {
        count = entry->count;
    }

    /* Seek to the position of the next index header slot */
    if (fseeko(output, next_index, SEEK_SET) != 0) {
        fprintf(stderr, "Unable to seek to tag index position: %s\n", strerror(errno));
        return -1;
    }

    /* Tag ID */
    u32_buf = htobe32(tag);
    if (fwrite(&u32_buf, sizeof(u32_buf), 1, output) != 1) {
        fprintf(stderr, "Unable to write tag ID: %s\n", strerror(errno));
        return -1;
    }

    /* Tag type */
    u32_buf = htobe32(type);
    if (fwrite(&u32_buf, sizeof(u32_buf), 1, output) != 1) {
        fprintf(stderr, "Unable to write tag type: %s\n", strerror(errno));
        return -1;
    }

    /* Offset into the data blob. Just start at the end of what's written, plus any padding needed for alignment */
    if ((type == RPM_INT16_TYPE) && ((data_offset % 2) != 0)) {
        data_offset++;
    }

    if ((type == RPM_INT32_TYPE) && ((data_offset % 4) != 0)) {
        data_offset += 4 - (data_offset % 4);
    }

    if ((type == RPM_INT64_TYPE) && ((data_offset % 8) != 0)) {
        data_offset += 8 - (data_offset % 8);
    }

    u32_buf = htobe32((uint32_t) data_offset);
    if (fwrite(&u32_buf, sizeof(u32_buf), 1, output) != 1) {
        fprintf(stderr, "Unable to write tag offset: %s\n", strerror(errno));
        return -1;
    }

    /* Number of items */
    u32_buf = htobe32(count);
    if (fwrite(&u32_buf, sizeof(u32_buf), 1, output) != 1) {
        fprintf(stderr, "Unable to write tag count: %s\n", strerror(errno));
        return -1;
    }

    /* Seek to the data offset */
    if (fseeko(output, data_start + data_offset, SEEK_SET) != 0) {
        fprintf(stderr, "Unable to seek to data offset: %s\n", strerror(errno));
        return -1;
    }

    /* Write the data */
    if (fwrite(entry->data, 1, entry->data_used, output) != entry->data_used) {
        fprintf(stderr, "Unable to write tag data: %s\n", strerror(errno));
        return -1;
    }

    /* Update the data_used */
    *data_used = data_offset + entry->data_used;

    return 0;
}

int construct_header(tag_db *tags, char **output_buffer, size_t *output_size, tag_type_func f_tag_type) {
    tag_list_entry *tag_entry;
    uint32_t tag_count;
    FILE *output = NULL;

    uint32_t u32_buf;

    off_t next_index;
    off_t data_start;
    off_t data_used;

    int retval = -1;

    /* Use open_memstream to allocate the buffer */
    if ((output = open_memstream(output_buffer, output_size)) == NULL) {
        fprintf(stderr, "Unable to allocate output buffer: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Count the tags */
    tag_count = 0;
    SLIST_FOREACH(tag_entry, &tags->tags_used, items) {
        tag_count++;
    }

    /* Output the header's header */
    /* Magic, 4 bytes */
    u32_buf = htobe32(RPMHEADER_MAGIC);
    if (fwrite(&u32_buf, sizeof(u32_buf), 1, output) != 1) {
        fprintf(stderr, "Unable to output header magic: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Reserved, 4 bytes, must 0's */
    u32_buf = 0;
    if (fwrite(&u32_buf, sizeof(u32_buf), 1, output) != 1) {
        fprintf(stderr, "Unable to output header reserved area: %s\n", strerror(errno));
        goto cleanup;
    }

    /* number of header tags */
    u32_buf = htobe32(tag_count);
    if (fwrite(&u32_buf, sizeof(u32_buf), 1, output) != 1) {
        fprintf(stderr, "Unable to output header nindex: %s\n", strerror(errno));
        goto cleanup;
    }

    /* size of the data blob. Fill in with 0's for now, we'll come back to it once we know the actual size */
    u32_buf = 0;
    if (fwrite(&u32_buf, sizeof(u32_buf), 1, output) != 1) {
        fprintf(stderr, "Unable to reserve space for hsize: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Allocate space for the index records. Each one is 32 bytes.
     * Add another 32 bytes for the rpmheader data, so we have a value that can be used
     * with SEEK_SET in construct_tag().
     */
    data_start = 32 * (tag_count + 1);
    if (fseeko(output, data_start, SEEK_SET) != 0) {
        fprintf(stderr, "Unable to reserve space for tag index records: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Output the tags and tag data. The index data starts after the header header, which is also 32 bytes. */
    next_index = 32;
    data_used = 0;
    SLIST_FOREACH(tag_entry, &tags->tags_used, items) {
        if (construct_tag(tag_entry->tag, tags->entries[tag_entry->tag], next_index, data_start, &data_used, f_tag_type, output) != 0) {
            goto cleanup;
        }

        next_index += 32;
    }

    /* Back up and write the data blob size */
    if (fseeko(output, 12, SEEK_SET) != 0) {
        fprintf(stderr, "Unable to seek to hblob position: %s\n", strerror(errno));
        goto cleanup;
    }

    u32_buf = htobe32(data_used);
    if (fwrite(&u32_buf, sizeof(u32_buf), 1, output) != 1) {
        fprintf(stderr, "Unable to write header data size: %s\n", strerror(errno));
        goto cleanup;
    }

    retval = 0;

cleanup:
    if (output != NULL) {
        if ((fclose(output) != 0) && (retval == 0)) {
            fprintf(stderr, "Unable to flush output while writing header: %s\n", strerror(errno));
            retval = 1;
        }
    }

    return retval;
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
