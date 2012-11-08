AUTOMAKE_OPTIONS = foreign dist-bzip2
ACLOCAL_AMFLAGS= -I m4

moddir=${AP_LIBEXECDIR}
mod_LTLIBRARIES = mod_authnz_subrequest.la 

mod_authnz_subrequest_la_SOURCES = src/mod_authnz_subrequest.c
mod_authnz_subrequest_la_CFLAGS = -Wall -I${top_srcdir}/include ${XSLT_CFLAGS} ${MODULE_CFLAGS}
mod_authnz_subrequest_LDFLAGS = -rpath ${AP_LIBEXECDIR} -module -avoid-version ${XSLT_LIBS} -lexslt
