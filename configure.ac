# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([mkrpm], [0.1], [dshea@redhat.com])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([src/mkrpm.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT8_T
AC_TYPE_UINT8_T
AC_TYPE_INT16_T
AC_TYPE_UINT32_T

# Checks for library functions.

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 utils/Makefile])
AC_OUTPUT
