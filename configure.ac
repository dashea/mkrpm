# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([mkrpm], [0.1], [dshea@redhat.com])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([src/mkrpm.c])
AC_CONFIG_HEADERS([config.h])

# Enable -D_GNU_SOURCE
AC_USE_SYSTEM_EXTENSIONS

LT_INIT
AC_CONFIG_MACRO_DIRS([m4])

# Generate code coverage targets
AX_CODE_COVERAGE

# Generate valgrind check targets
AX_VALGRIND_DFLT([sgcheck], [off])
AX_VALGRIND_CHECK

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdint.h sys/queue.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT8_T
AC_TYPE_UINT8_T
AC_TYPE_INT16_T
AC_TYPE_UINT32_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_REALLOC

# Checks for pkg-config modules
PKG_CHECK_MODULES([CMOCKA], [cmocka])
PKG_CHECK_MODULES([LIBARCHIVE], [libarchive])
PKG_CHECK_MODULES([LIBCRYPTO], [libcrypto])

AC_SUBST([CMOCKA_CFLAGS])
AC_SUBST([CMOCKA_LIBS])
AC_SUBST([LIBARCHIVE_CFLAGS])
AC_SUBST([LIBARCHIVE_LIBS])
AC_SUBST([LIBCRYPTO_CFLAGS])
AC_SUBST([LIBCRYPTO_LIBS])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 tests/Makefile
                 utils/Makefile])
AC_OUTPUT
