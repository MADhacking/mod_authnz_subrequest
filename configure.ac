dnl Process this file with autoconf to produce a configure script.

dnl Ensure a recent version of Autoconf.
AC_PREREQ([2.68])

dnl Initialise the Autoconf system.
AC_INIT(mod_authnz_subrequest, 0.1)

dnl Configure m4 macro directory.
AC_CONFIG_MACRO_DIR([m4])

dnl Configure auxillary directory.
AC_CONFIG_AUX_DIR([aux_dir])

dnl Determine system type.
AC_CANONICAL_TARGET

dnl Initialize automake.
AM_INIT_AUTOMAKE([])

dnl Locate suitable tools.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AM_PROG_CC_C_O 

dnl Initialize Libtool.
LT_INIT

dnl Check if Libtool is present.
AC_PROG_LIBTOOL

dnl Check for correct source directory.
AC_CONFIG_SRCDIR([src/mod_authnz_subrequest.c])

dnl Check that we have version 2.0.40+ of Apache and get useful vars.
AP_VERSION=2.0.40
CHECK_APACHE( , $AP_VERSION, :, :, [AC_MSG_ERROR([*** Apache version $AP_VERSION not found!])])
LIBTOOL="`${APR_CONFIG} --apr-libtool`"
AC_SUBST(LIBTOOL)

dnl Check that we have libapreq2 available and get config info.
AC_MSG_CHECKING([for libapreq2])
if which apreq2-config &>/dev/null; then
	APREQ2_VERSION=`apreq2-config --library-version`
	APREQ2_CFLAGS=`apreq2-config --includes`
	APREQ2_LIBS=`apreq2-config --link-libtool --ldflags --libs`

	AC_MSG_RESULT([yes (version $APREQ2_VERSION)])

	AC_SUBST(APREQ2_VERSION)
	AC_SUBST(APREQ2_CFLAGS)
	AC_SUBST(APREQ2_LIBS)
else
	AC_MSG_RESULT([no])
	AC_MSG_ERROR([*** libapreq2 is required for mod_subreqonly to compile.])
	AC_MSG_ERROR([*** Please download it from: http://httpd.apache.org/apreq/])
fi


MODULE_CFLAGS="${APXS_CFLAGS} ${AP_INCLUDES} ${APR_INCLUDES} ${APU_INCLUDES}"

AC_SUBST(MODULE_CFLAGS)

dnl Set the location of the autoconf generated config.h.
AM_CONFIG_HEADER(include/config.h:aux_dir/config.in)

dnl Set the location of the makefiles.
AC_CONFIG_FILES([Makefile])

dnl Generate config.status and launch it.
AC_OUTPUT
