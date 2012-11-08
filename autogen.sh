#!/bin/sh
# autogen.sh - generates configure using the autotools
# $Id$
export WANT_AUTOCONF=2.5

libtoolize --force --copy
aclocal -I m4
autoheader
automake --add-missing --copy --foreign
autoconf
rm -rf autom4te.cache
