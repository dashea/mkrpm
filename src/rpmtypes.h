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

#include <stdint.h>

#ifndef _RPMTYPES_H_
#define _RPMTYPES_H_

/*
 * Structs and constants used in RPM
 * struct definitions taken from LSB-5.0.0 and RPM code, and modified
 * to use fixed-width integer types because honestly it's kind of wild
 * that the supposed spec just says, like, "int" all over the place.
 */

/* Lead section, mostly unused */
#define RPMLEAD_MAGIC   (0xEDABEEDB)
#define RPMLEAD_SIZE    (96)

/*
 * Values used with "archnum" in rpmlead
 * In rpm, the values are defined in the rpmrc config file, and they don't
 * really matter since nothing ever reads them. RPMTAG_ARCH contains the
 * actual architecture information.
 *
 * LSB-5.0.0 defines values for IA32, IA64, PPC32, PPC64, S390, S390X, and
 * AMD64, and it gets S390X wrong (should be 0x000F). Using the values from LSB
 * anyway for the sake of standards compliance, such as it is, and everything
 * not in the LSB gets a 0. Again, nothing actually uses this data.
 */
#define RPMARCH_INTEL   (0x0001)    /* used for both 32-bit intel and x86_64 */
#define RPMARCH_PPC32   (0x0005)
#define RPMARCH_IA64    (0x0009)
#define RPMARCH_S390    (0x000E)
#define RPMARCH_S390X   (0x000E)
#define RPMARCH_PPC64   (0x0010)    /* big and little endian */

struct rpmlead {
    uint32_t magic;         /* RPMLEAD_MAGIC */
    uint8_t major;          /* 3 */
    uint8_t minor;          /* 0 */
    int16_t type;           /* 0 for binary packages, which is all we care about */
    int16_t archnum;        /* See above */
    char name[66];          /* NEVRA, truncated to 65 chars */
    int16_t osnum;          /* 1. RPM has other values but nothing reads this data anyway */
    int16_t signature_type; /* 5. RPM specifies that this is the only non-deprecated field
                               in rpmlead, and 5 (RPMSIGTYPE_HEADERSIG) is currently the only
                               valid value. */
    int8_t reserved[16];
};

/* Header, used by both signature and header sections */

/*
 * The rpmheader struct must be aligned to an 8-byte boundary, which
 * essentially means that the rpmheader for signatures needs to be padded
 * out to an 8-byte boundary
 */

#define RPMHEADER_MAGIC (0x8EADE801)

struct rpmheader {
    uint32_t magic;
    uint32_t reserved;
    uint32_t nindex;    /* Number of index records following the header record */
    uint32_t hsize;     /* Size of the data blob following the index records */
};

/* Header index. Describes a tag in the data blob following the index records */

/* Values for "type" */
typedef enum rpmTagType {
    RPM_NULL_TYPE         = 0,
    RPM_CHAR_TYPE         = 1,
    RPM_INT8_TYPE         = 2,
    RPM_INT16_TYPE        = 3,
    RPM_INT32_TYPE        = 4,
    RPM_INT64_TYPE        = 5,
    RPM_STRING_TYPE       = 6,
    RPM_BIN_TYPE          = 7,
    RPM_STRING_ARRAY_TYPE = 8,
    RPM_I18NSTRING_TYPE   = 9,
} rpmTagType;

struct rpmhdrindex {
    uint32_t tag;
    uint32_t type;
    uint32_t offset;
    uint32_t count;
};

/*
 * Tag values
 * Only doing the ones that are "required" in LSB for now
 */

/* Signature header */
typedef enum rpmSigTag {
    RPMSIGTAG_SIZE = 1000,  /* int32 */
    RPMSIGTAG_MD5  = 1004,  /* bin */
} rpmSigTag;

typedef enum rpmTag {
    RPMTAG_NAME              = 1000,    /* string */
    RPMTAG_VERSION           = 1001,    /* string */
    RPMTAG_RELEASE           = 1002,    /* string */
    RPMTAG_SUMMARY           = 1004,    /* i18n string */
    RPMTAG_DESCRIPTION       = 1005,    /* i18n string */
    RPMTAG_SIZE              = 1009,    /* int32 */
    RPMTAG_LICENSE           = 1014,    /* string */
    RPMTAG_GROUP             = 1016,    /* string */
    RPMTAG_OS                = 1021,    /* string */
    RPMTAG_ARCH              = 1022,    /* string */
    RPMTAG_FILESIZES         = 1028,    /* int32 array */
    RPMTAG_FILEMODES         = 1030,    /* int16 array */
    RPMTAG_FILERDEVS         = 1033,    /* int16 array */
    RPMTAG_FILEMTIMES        = 1034,    /* int32 array */
    RPMTAG_FILEMD5S          = 1035,    /* string array */
    RPMTAG_FILELINKTOS       = 1036,    /* string array */
    RPMTAG_FILEFLAGS         = 1037,    /* int32 array */
    RPMTAG_FILEUSERNAME      = 1039,    /* string array */
    RPMTAG_FILEGROUPNAME     = 1040,    /* string array */
    RPMTAG_PROVIDENAME       = 1047,    /* string array */
    RPMTAG_REQUIREFLAGS      = 1048,    /* int32 array */
    RPMTAG_REQUIRENAME       = 1049,    /* string array */
    RPMTAG_REQUIREVERSION    = 1050,    /* string array */
    RPMTAG_FILEDEVICES       = 1095,    /* int32 array */
    RPMTAG_FILEINODES        = 1096,    /* int32 array */
    RPMTAG_FILELANGS         = 1097,    /* string array */
    RPMTAG_PROVIDEFLAGS      = 1112,    /* int32 array */
    RPMTAG_PROVIDEVERSION    = 1113,    /* string array */
    RPMTAG_DIRINDEXES        = 1116,    /* int32 array */
    RPMTAG_BASENAMES         = 1117,    /* string array */
    RPMTAG_DIRNAMES          = 1118,    /* string array */
    RPMTAG_PAYLOADFORMAT     = 1124,    /* string */
    RPMTAG_PAYLOADCOMPRESSOR = 1125,    /* string */
    RPMTAG_PAYLOADFLAGS      = 1126,    /* string */
    RPMTAG_MAX
} rpmTag;

/* Type values */

/* bit values for RPMTAG_FILEFLAGS */
#define RPMFILE_CONFIG              (1 << 0)
#define RPMFILE_DOC                 (1 << 1)
#define RPMFILE_DONOTUSE            (1 << 2)
#define RPMFILE_MISSINGOK           (1 << 3)
#define RPMFILE_NOREPLACE           (1 << 4)
#define RPMFILE_SPECFILE            (1 << 5)
#define RPMFILE_GHOST               (1 << 6)
#define RPMFILE_LICENSE             (1 << 7)
#define RPMFILE_README              (1 << 8)
#define RPMFILE_EXCLUDE             (1 << 9)

/* bit values for require/provide/etc flags */
/* rpm defines a lot more of these */
#define RPMSENSE_LESS           (1 << 1)
#define RPMSENSE_GREATER        (1 << 2)
#define RPMSENSE_EQUAL          (1 << 3)
#define RPMSENSE_PREREQ         (1 << 6)
#define RPMSENSE_INTERP         (1 << 8)
#define RPMSENSE_SCRIPT_PRE     (1 << 9)
#define RPMSENSE_SCRIPT_POST    (1 << 10)
#define RPMSENSE_SCRIPT_PREUN   (1 << 11)
#define RPMSENSE_SCRIPT_POSTUN  (1 << 12)
#define RPMSENSE_RPMLIB         (1 << 24)

#endif
