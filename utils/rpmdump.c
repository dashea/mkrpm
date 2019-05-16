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

#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void readError(const char *filename, FILE *input) {
    if (ferror(input)) {
        fprintf(stderr, "Unable to read %s: %s\n", filename, strerror(errno));
    } else {
        fprintf(stderr, "Unable to read %s: Unexpected EOF\n", filename);
    }
}

int realign(const char *filename, FILE *input, long alignment) {
    long cur;

    if ((cur = ftell(input)) == -1) {
        fprintf(stderr, "Unable to get position of %s: %s\n", filename, strerror(errno));
        return EXIT_FAILURE;
    }

    if (cur % alignment) {
        printf("REALIGN: %ld\n", alignment - (cur % alignment));
        if (fseek(input, alignment - (cur % alignment), SEEK_CUR) == -1) {
            fprintf(stderr, "Unable to seek %s: %s\n", filename, strerror(errno));
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int dumpRpmLead(const char *filename, FILE *input) {
    unsigned char buffer[96];
    short val;

    if (fread(buffer, 96, 1, input) != 1) {
        readError(filename, input);
        return EXIT_FAILURE;
    }

    printf("  Lead:\n");

    /* Check the magic */
    if ((buffer[0] != 0xED) || (buffer[1] != 0xAB) || (buffer[2] != 0xEE) || (buffer[3] != 0xDB)) {
        fprintf(stderr, "Invalid lead magic for %s: 0x%X%X%X%X\n", filename,
                 buffer[0], buffer[1], buffer[2], buffer[3]);
        return EXIT_FAILURE;
    }

    /* major and minor, unsigned chars */
    printf("    Major: %u\n", (int)buffer[4]);
    printf("    Minor: %u\n", (int)buffer[5]);

    /* Type, short */
    val = (buffer[6] << 8) | buffer[7];
    printf("    Type: %hd\n", val);

    /* arch, short */
    val = (buffer[8] << 8) | buffer[9];
    printf("    Arch: %hd\n", val);

    /* name, 66 chars */
    printf("    Name: %.66s\n", buffer + 10);

    /* osnum, short */
    val = (buffer[76] << 8) | buffer[77];
    printf("    OSNum: %hd\n", val);

    /* signature_type, short */
    val = (buffer[78] << 8) | buffer[79];
    printf("    signature_type: %hd\n", val);

    /* remaining 16 characters are reserved */
    return EXIT_SUCCESS;
}

struct rpmtag {
    int tag;
    int type;
    int offset;
    int count;
};

int dumpRpmTag(const char *filename, struct rpmtag *tag, uint8_t *data, int data_size) {
    char *tmp;
    int buf_idx;
    int arr_count;

    if (tag->offset > data_size) {
        fprintf(stderr, "Invalid tag %d in %s: offset %d > hsize %d\n", tag->tag, filename, tag->offset, data_size);
        return EXIT_FAILURE;
    }

    printf("      Tag:    %d\n", tag->tag);
    printf("      Type:   %d\n", tag->type);
    printf("      Offset: %d\n", tag->offset);
    printf("      Count:  %d\n", tag->count);

    switch (tag->type) {
        case 0: /* RPM_NULL_TYPE */
            printf("        NULL\n");
            break;
        case 1: /* RPM_CHAR_TYPE */
        case 2: /* RPM_INT8_TYPE */
            if ((tag->offset + tag->count) > data_size) {
                fprintf(stderr, "Invalid tag %d in %s: offset %d + count %d > hsize %d\n",
                        tag->tag, filename, tag->offset, tag->count, data_size);
                return EXIT_FAILURE;
            }

            fputs("        ", stdout);
            for (arr_count = 0; arr_count < (tag->count - 1); arr_count++) {
                printf("%" PRIu8 ",", *(((uint8_t *) (data + tag->offset)) + arr_count));
            }
            printf("%" PRIu8 "\n", *(((uint8_t *) (data + tag->offset)) + arr_count));
            break;

        case 3: /* RPM_INT16_TYPE */
            if ((tag->offset + (tag->count * 2)) > data_size) {
                fprintf(stderr, "Invalid tag %d in %s: offset %d + (count %d * 2) > hsize %d\n",
                        tag->tag, filename, tag->offset, tag->count, data_size);
                return EXIT_FAILURE;
            }

            fputs("        ", stdout);
            for (arr_count = 0; arr_count < (tag->count - 1); arr_count++) {
                printf("%" PRIu16 ",", be16toh(*(((uint16_t *) (data + tag->offset)) + arr_count)));
            }
            printf("%" PRIu16 "\n", be16toh(*(((uint16_t *) (data + tag->offset)) + arr_count)));

            break;

        case 4: /* RPM_INT32_TYPE */
            if ((tag->offset + (tag->count * 4)) > data_size) {
                fprintf(stderr, "Invalid tag %d in %s: offset %d + (count %d * 4) > hsize %d\n",
                        tag->tag, filename, tag->offset, tag->count, data_size);
                return EXIT_FAILURE;
            }

            fputs("        ", stdout);
            for (arr_count = 0; arr_count < (tag->count - 1); arr_count++) {
                printf("%" PRIu32 ",", be32toh(*(((uint32_t *) (data + tag->offset)) + arr_count)));
            }
            printf("%" PRIu32 "\n", be32toh(*(((uint32_t *) (data + tag->offset)) + arr_count)));

            break;

        case 5: /* RPM_INT64_TYPE */
            if ((tag->offset + (tag->count * 8)) > data_size) {
                fprintf(stderr, "Invalid tag %d in %s: offset %d + (count %d * 8) > hsize %d\n",
                        tag->tag, filename, tag->offset, tag->count, data_size);
                return EXIT_FAILURE;
            }

            fputs("        ", stdout);
            for (arr_count = 0; arr_count < (tag->count - 1); arr_count++) {
                printf("%" PRIu64 ",", be64toh(*(((uint64_t *) (data + tag->offset)) + arr_count)));
            }
            printf("%" PRIu64 "\n", be64toh(*(((uint64_t *) (data + tag->offset)) + arr_count)));
            break;

        case 6: /* RPM_STRING_TYPE */
            if (tag->count != 1) {
                fprintf(stderr, "Invalid tag %d in %s: count %d > 1\n", tag->tag, filename, tag->count);
                return EXIT_FAILURE;
            }

        /* fall through, since string and string arrays are effectively the same thing */
        case 8: /* RPM_STRING_ARRAY_TYPE */
        case 9: /* RPM_I18NSTRING_TYPE */
            if (tag->offset > data_size) {
                fprintf(stderr, "Invalid tag %d in %s: offset %d > hsize %d\n",
                        tag->tag, filename, tag->offset, data_size);
                return EXIT_FAILURE;
            }

            buf_idx = 0;
            arr_count = 0;
            tmp = (char *) (data + tag->offset);

            fputs("        ", stdout);
            while (arr_count < tag->count) {
                if (buf_idx == data_size) {
                    fprintf(stderr, "Invalid tag %d in %s: reached end of data without finding end of string\n", tag->tag, filename);
                }

                if (*tmp == '\0') {
                    arr_count++;
                    fputs("\n        ", stdout);
                } else {
                    fputc(*tmp, stdout);
                }

                buf_idx++;
                tmp++;
            }
            fputc('\n', stdout);

            break;

        case 7: /* RPM_BIN_TYPE */
            if ((tag->offset + tag->count) > data_size) {
                fprintf(stderr, "Invalid tag %d in %s: offset %d + count %d > hsize %d\n",
                        tag->tag, filename, tag->offset, tag->count, data_size);
                return EXIT_FAILURE;
            }

            fputs("        ", stdout);
            for (arr_count = 0; arr_count < (tag->count - 1); arr_count++) {
                printf("%02X,", *(((uint8_t *) (data + tag->offset)) + arr_count));
            }
            printf("%02X\n", *(((uint8_t *) (data + tag->offset)) + arr_count));
            break;

        default:
            fprintf(stderr, "Invalid tag type in %s: %d\n", filename, tag->type);
            return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int dumpRpmHeader(const char *filename, const char *header_type, FILE *input) {
    unsigned char header_buffer[16];
    unsigned int nindex;
    unsigned int hsize;
    int i;

    unsigned char index_buffer[16];

    struct rpmtag *tagIdxs = NULL;
    uint8_t *data = NULL;

    long pos;

    int result;

    if ((result = realign(filename, input, 8)) != EXIT_SUCCESS) {
        return result;
    }

    if ((pos = ftell(input)) == -1) {
        fprintf(stderr, "Unable to get position of %s: %s\n", filename, strerror(errno));
        return EXIT_FAILURE;
    }

    if (fread(header_buffer, 16, 1, input) != 1) {
        readError(filename, input);
        return EXIT_FAILURE;
    }

    printf("  %s: (%ld)\n", header_type, pos);

    /* Check the magic */
    /* The 4 bytes after magic are "reserved" and must be 0 */
    if ((header_buffer[0] != 0x8E) || (header_buffer[1] != 0xAD) || (header_buffer[2] != 0xE8) || (header_buffer[3] != 0x01) ||
            (header_buffer[4] != 0) || (header_buffer[5] != 0) || (header_buffer[6] != 0 || (header_buffer[7] != 0))) {
        fprintf(stderr, "Invalid header magic for %s: 0x%.2X%.2X%.2X%.2X 0x%.2X%.2X%.2X%.2X\n", filename,
                header_buffer[0], header_buffer[1], header_buffer[2], header_buffer[3],
                header_buffer[4], header_buffer[5], header_buffer[6], header_buffer[7]);
        return EXIT_FAILURE;
    }

    /* Read the index records */
    nindex = (header_buffer[8] << 24) | (header_buffer[9] << 16) | (header_buffer[10] << 8) | header_buffer[11];
    if (nindex == 0) {
        fprintf(stderr, "Invalid %s in for %s: nindex == 0\n", header_type, filename);
        return EXIT_FAILURE;
    }
    hsize = (header_buffer[12] << 24) | (header_buffer[13] << 16) | (header_buffer[14] << 8) | header_buffer[15];

    printf("    nindex: %d\n", nindex);
    printf("    hsize:  %d\n", hsize);

    tagIdxs = calloc(nindex, sizeof(struct rpmtag));
    if (tagIdxs == NULL) {
        perror("calloc");
        return EXIT_FAILURE;
    }

    for (i = 0; i < nindex; i++) {
        if (fread(index_buffer, 16, 1, input) != 1) {
            readError(filename, input);
            result = EXIT_FAILURE;
            goto cleanup;
        }

        tagIdxs[i].tag    = (index_buffer[0] << 24) | (index_buffer[1] << 16) | (index_buffer[2] << 8) | index_buffer[3];
        tagIdxs[i].type   = (index_buffer[4] << 24) | (index_buffer[5] << 16) | (index_buffer[6] << 8) | index_buffer[7];
        tagIdxs[i].offset = (index_buffer[8] << 24) | (index_buffer[9] << 16) | (index_buffer[10] << 8) | index_buffer[11];
        tagIdxs[i].count  = (index_buffer[12] << 24) | (index_buffer[13] << 16) | (index_buffer[14] << 8) | index_buffer[15];
    }

    /* Read the data storage */
    if (hsize != 0) {
        data = calloc(hsize, sizeof(uint8_t));
        if (data == NULL) {
            perror("calloc");
            result = EXIT_FAILURE;
            goto cleanup;
        }

        if (fread(data, 1, hsize, input) != hsize) {
            readError(filename, input);
            result = EXIT_FAILURE;
            goto cleanup;
        }
    }

    /* Print the tags */
    for (i = 0; i < nindex; i++) {
        result = dumpRpmTag(filename, tagIdxs + i, data, hsize);

        if (result != EXIT_SUCCESS) {
            goto cleanup;
        }
    }

cleanup:
    free(tagIdxs);
    free(data);

    return result;
}

int dumpRpm(const char *filename, FILE *input) {
    int result;
    long startpos;
    long endpos;

    printf("%s:\n", filename);

    if ((result = dumpRpmLead(filename, input)) != 0) {
        return result;
    }

    if ((result = dumpRpmHeader(filename, "Signature Header", input)) != 0) {
        return result;
    }

    if ((result = dumpRpmHeader(filename, "Everything Else Header", input)) != 0) {
        return result;
    }

    if ((startpos = ftell(input)) == -1) {
        fprintf(stderr, "Unable to get current file position for %s: %s\n", filename, strerror(errno));
        return EXIT_FAILURE;
    }

    if (fseek(input, 0L, SEEK_END) == -1) {
        fprintf(stderr, "Unable to seek to end of %s: %s\n", filename, strerror(errno));
        return EXIT_FAILURE;
    }

    if ((endpos = ftell(input)) == -1) {
        fprintf(stderr, "Unable to get current file position for %s: %s\n", filename, strerror(errno));
        return EXIT_FAILURE;
    }

    printf("Payload start: %ld\n", startpos);
    printf("Payload length: %ld\n", endpos - startpos);

    return EXIT_SUCCESS;
}

void usage(const char *argv0) {
    printf("Usage: %s INPUT [INPUT ...]\n", argv0);
}

int main(int argc, char **argv) {
    FILE *input;
    int result;
    int i;

    if (argc < 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    for (i = 1; i < argc; i++) {
        if ((input = fopen(argv[i], "r")) == NULL) {
            fprintf(stderr, "Unable to open %s: %s\n", argv[i], strerror(errno));
            return EXIT_FAILURE;
        }

        result = dumpRpm(argv[i], input);
        fclose(input);

        if (result != EXIT_SUCCESS) {
            break;
        }
    }

    return result;
}
