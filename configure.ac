AC_PREREQ([2.69])
AC_INIT([libvdestack], [0.1], [info@v2.cs.unibo.it])
AM_INIT_AUTOMAKE([foreign dist-bzip2])
AC_CONFIG_SRCDIR([vdestack.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_LIBTOOL
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([vdeplug], [vde_open_real])
AC_CHECK_LIB([cap], [cap_get_proc])
AC_CHECK_LIB([execs], [s2multiargv])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h sys/ioctl.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset socket])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
