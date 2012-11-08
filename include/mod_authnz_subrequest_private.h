/**
 *    Copyright (c) 2012, Hacking Networked Solutions
 *
 *    Authors:    Max Hacking <max@hacking.co.uk>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef _MOD_SUBREQONLY_PRIVATE_H
#define _MOD_SUBREQONLY_PRIVATE_H

#define SUBREQONLY_FILTER_NAME "SubReqOnly"

#define APACHEFS_FILTER_NAME "transform_store_brigade"
#define MOD_INCLUDE_NAME	 "INCLUDES"

#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <http_core.h>
#include <http_log.h>
#include <http_request.h>
#include <apr_buckets.h>
#include <apr_strings.h>
#include <apr_uri.h>
#include <apr_tables.h>
#include <apr_dso.h>

/* Unfortunately these have leaked in here from the Apache headers */
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include "config.h"

extern module AP_MODULE_DECLARE_DATA subreqonly_module;

/* SubReqOnlyOptions */
#define NO_OPTIONS          (1 <<  0)
#define ALLOW_APACHE_FS     (1 <<  1)
#define ALLOW_ALL           (1 <<  2)

typedef struct svr_cfg
{
    int announce;
}
svr_cfg;

typedef struct dir_cfg
{
	int authoritative;
    apr_int32_t opts;
    apr_int32_t incremented_opts;
    apr_int32_t decremented_opts;
}
dir_cfg;

#endif /* _MOD_SUBREQONLY_PRIVATE_H */
