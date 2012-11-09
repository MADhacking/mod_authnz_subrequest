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

#ifndef _MOD_AUTHNZ_SUBREQEST_PRIVATE_H
#define _MOD_AUTHNZ_SUBREQEST_PRIVATE_H

#define SUBREQEST_AUTH_TYPE	"SubRequest"
#define SUBREQEST_REQUIRE	"sub-request"

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

/* Module data structure */
extern module AP_MODULE_DECLARE_DATA authnz_subrequest_module;

/* Server level configuration structure */
typedef struct svr_cfg
{
    int 			announce;
    apr_table_t*	sub_req_table;
} svr_cfg;

/* Directory level configuration structure */
typedef struct dir_cfg
{
	int authn_authoritative;
	int authz_authoritative;
	int reject_method;
} dir_cfg;

#endif /* _MOD_AUTHNZ_SUBREQEST_PRIVATE_H */
