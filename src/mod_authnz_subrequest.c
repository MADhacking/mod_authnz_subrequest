/**
 * 	  Copyright (c) 2012 Max Hacking
 *
 *    Authors:  Max Hacking 		<max@hacking.co.uk>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
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

#include "mod_subreqonly_private.h"
#include <mod_auth.h>
#include <ap_provider.h>
#include <apr_dso.h>
#include <ctype.h>

/* Function to determine if this is an ApacheFS sub-request */
static unsigned char is_apachefs_request(ap_filter_t *filter)
{
	// Loop through the previous requests in the chain.  If one of them is
	// an ApacheFS filter then return true.
	ap_filter_t *temp_filter = filter;
	while (temp_filter)
	{
		if (strcasecmp(temp_filter->frec->name, APACHEFS_FILTER_NAME) == 0)
			return TRUE;

		temp_filter = temp_filter->next;
	};

	// We got to the end of the filter chain without finding an ApacheFS filter
	// so return false.
    return FALSE;
}

static int subreqcheck(request_rec *r)
{
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, "subreqcheck");
	// Get information regarding the Requires directives for this request.
    const apr_array_header_t *reqs_arr = ap_requires(r);

	// If there are no Requires directives we are done already so decline to process.
    if (!reqs_arr)
    {
    	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, "subreqcheck : !reqs_arr");
        return DECLINED;
    }

    // Get the (directory level) configuration information for this module.
	dir_cfg *dconf = ap_get_module_config(r->per_dir_config, &subreqonly_module);

	int m = r->method_number;
    register int x;
    const char *req_text, *req_word;
    require_line *reqs;
    char *reason = NULL;

    // Loop through the Require lines...
    reqs = (require_line *)reqs_arr->elts;
    for (x = 0; x < reqs_arr->nelts; x++)
    {
        // If we have already failed for some reason and we are authoritative then
    	// further processing would be pointless.
        if (reason && dconf->authoritative)
            break;

        // Check that this Require line applies to the request method.
        if (!(reqs[x].method_mask & (AP_METHOD_BIT << m)))
            continue;

        // Get the textual representation of this Require directive and split off
        // the first word.
        req_text = reqs[x].requirement;
        req_word = ap_getword_white(r->pool, &req_text);

        // If it indicates a sub-request authorisation type then this is for us...
        if (!strcmp(req_word, "sub-request"))
        {
        	// If ALLOW_ALL is set and this is a sub-request of any kind then allow it.
        	if ((dconf->opts & ALLOW_ALL) && !ap_is_initial_req(r))
        		return OK;

        	// If ALLOW_APACHE_FS is set and this is an ApacheFS sub-request then allow it.
        	if ((dconf->opts & ALLOW_APACHE_FS) && is_apachefs_request(r->output_filters))
        		return OK;
        }
    } // End of Require lines loop.

    /*/ If we are non-authoritative then we should decline to process.
    if (!dconf->authoritative)
    {
    	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, "subreqcheck : !dconf->authoritative");
    	return DECLINED;
    }*/

    // If we got this far then the request in unauthorised.
    return HTTP_UNAUTHORIZED;
}

/**
 * This hook is used to analyse the request headers, authenticate the user,
 * and set the user information in the request record (r->user and
 * r->ap_auth_type). This hook is only run when Apache determines that
 * authentication/authorisation is required for this resource (as determined
 * by the 'Require' directive). It runs after the access_checker hook, and
 * before the auth_checker hook.
 *
 * @param r The current request
 * @return OK, DECLINED, or HTTP_...
 */
static int check_user_id_hook(request_rec *r)
{
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, "check_user_id_hook");

    /* Are we configured to be SubRequest auth? */
	const char *current_auth = ap_auth_type(r);
    if (!current_auth || strcasecmp(current_auth, "SubRequest"))
    {
    	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, "check_user_id_hook : DECLINED");
        return DECLINED;
    }

    int ret = subreqcheck(r);

	r->ap_auth_type = "SubRequest";

	return ret;
}

/**
 * This hook is used to check to see if the resource being requested
 * is available for the authenticated user (r->user and r->ap_auth_type).
 * It runs after the access_checker and check_user_id hooks. Note that
 * it will *only* be called if Apache determines that access control has
 * been applied to this resource (through a 'Require' directive).
 *
 * @param r the current request
 * @return OK, DECLINED, or HTTP_...
 */
static int auth_checker_hook(request_rec *r)
{
    // Get the current request auth type.
	const char *current_auth = ap_auth_type(r);

	// If we don't have a request type or the request auth type is NOT
	// SubRequest then we should decline to process.
    if (!current_auth || strcasecmp(current_auth, "SubRequest"))
    {
    	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, "auth_checker_hook : DECLINED");
        return DECLINED;
    }

    // Presumably, if we got this far, the request auth type IS SubRequest so
    // we can allow it.  If it did not meet the SubRequest criteria then it will
    // have been denied already.
    return OK;
}

/* Function to merge a directory configuration */
static void *merge_dir_config(apr_pool_t * p, void *basev, void *addv)
{
    dir_cfg *from = basev;
    dir_cfg *merge = addv;
    dir_cfg *to = apr_palloc(p, sizeof(dir_cfg));

    /* This code comes from mod_autoindex's IndexOptions */
    if (merge->opts & NO_OPTIONS)
    {
        /*
         * If the current directory says 'no options' then we also
         * clear any incremental mods from being inheritable further down.
         */
        to->opts = NO_OPTIONS;
        to->incremented_opts = 0;
        to->decremented_opts = 0;
    }
    else
    {
        /*
         * If there were any nonincremental options selected for
         * this directory, they dominate and we don't inherit *anything.*
         * Contrariwise, we *do* inherit if the only settings here are
         * incremental ones.
         */
        if (merge->opts == 0)
        {
            to->incremented_opts = (from->incremented_opts | merge->incremented_opts) & ~merge->decremented_opts;
            to->decremented_opts = (from->decremented_opts | merge->decremented_opts);
            /*
             * We may have incremental settings, so make sure we don't
             * inadvertently inherit an IndexOptions None from above.
             */
            to->opts = (from->opts & ~NO_OPTIONS);
        }
        else
        {
            /*
             * There are local nonincremental settings, which clear
             * all inheritance from above.  They *are* the new base settings.
             */
            to->opts = merge->opts;;
        }
        /*
         * We're guaranteed that there'll be no overlap between
         * the add-options and the remove-options.
         */
        to->opts |= to->incremented_opts;
        to->opts &= ~to->decremented_opts;
    }

    return to;
}

static void *create_server_cfg(apr_pool_t * p, server_rec * x)
{
    svr_cfg *cfg = apr_pcalloc(p, sizeof(svr_cfg));

    cfg->announce = 1;

    return cfg;
}

static void *create_dir_config(apr_pool_t * p, char *x)
{
    dir_cfg *conf = apr_pcalloc(p, sizeof(dir_cfg));

    conf->authoritative = 1;
    conf->opts = 0;
    conf->incremented_opts = 0;
    conf->decremented_opts = 0;

    return conf;
}

static const char *add_opts(cmd_parms * cmd, void *d, const char *optstr)
{
    char *w;
    apr_int32_t opts;
    apr_int32_t opts_add;
    apr_int32_t opts_remove;
    char action;
    dir_cfg *d_cfg = (dir_cfg *) d;

    opts = d_cfg->opts;
    opts_add = d_cfg->incremented_opts;
    opts_remove = d_cfg->decremented_opts;
    while (optstr[0])
    {
        int option = 0;

        w = ap_getword_conf(cmd->pool, &optstr);

        if ((*w == '+') || (*w == '-'))
        {
            action = *(w++);
        }
        else
        {
            action = '\0';
        }


        if (!strcasecmp(w, "AllowApacheFS"))
        {
            option = ALLOW_APACHE_FS;
        }
        else if (!strcasecmp(w, "AllowAll"))
        {
            option = ALLOW_ALL;
        }
        else if (!strcasecmp(w, "None"))
        {
            if (action != '\0')
            {
                return "Cannot combine '+' or '-' with 'None' keyword";
            }
            opts = NO_OPTIONS;
            opts_add = 0;
            opts_remove = 0;
        }
        else
        {
            return "Invalid SubReqOnlyOption";
        }

        if (action == '\0')
        {
            opts |= option;
            opts_add = 0;
            opts_remove = 0;
        }
        else if (action == '+')
        {
            opts_add |= option;
            opts_remove &= ~option;
        }
        else
        {
            opts_remove |= option;
            opts_add &= ~option;
        }
    }
    if ((opts & NO_OPTIONS) && (opts & ~NO_OPTIONS))
    {
        return "Cannot combine other TransformOptions keywords with 'None'";
    }
    d_cfg->incremented_opts = opts_add;
    d_cfg->decremented_opts = opts_remove;
    d_cfg->opts = opts;
    return NULL;
}

/* This function is registered as a command hook for the SubReqOnlyAnnounce command */
static const char *set_announce(cmd_parms *cmd, void *struct_ptr, int arg)
{
    svr_cfg *cfg = ap_get_module_config(cmd->server->module_config,	&subreqonly_module);

    // SubReqOnlyAnnounce is a server wide option, check it has been used as such.
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
    if (err)
        return err;

    cfg->announce = arg ? 1 : 0;

    return NULL;
}

/* Once the module is loaded, initialised, the hooks registered and the server wide
 * configuration loaded this function is executed.  Server wide configuration options
 * should be acted upon here if required.
 */
static int post_config_hook(apr_pool_t *p, apr_pool_t *log, apr_pool_t *ptemp, server_rec *s)
{
    svr_cfg *cfg = ap_get_module_config(s->module_config, &subreqonly_module);

    /* Add version string to Apache headers */
    if (cfg->announce)
    {
        char *compinfo = PACKAGE_NAME "/" PACKAGE_VERSION;

        ap_add_version_component(p, compinfo);
    }

    return OK;
}

/* The register_hooks function will be called once when the module is loaded
 * and should only contain calls to hook and filter registration functions.
 */
static void register_hooks(apr_pool_t * p)
{
    ap_hook_post_config(post_config_hook, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_check_user_id(check_user_id_hook, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_auth_checker(auth_checker_hook, NULL, NULL, APR_HOOK_MIDDLE);

    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "subreqonly", "0", &subreqonly_module);
};

/* The command array.  This contains entries for the commands
 * which appear in configuration files.
 */
static const command_rec command_array[] =
{
    AP_INIT_RAW_ARGS("SubReqOnlyOptions", add_opts, NULL, OR_INDEXES, "One or more index options [+|-][]"),

    AP_INIT_FLAG("SubReqOnlyAnnounce", set_announce, NULL, RSRC_CONF, "Whether to announce this module in the server header. Default: On"),

    {NULL}
};

/* The declaration of the Apache module.  This structure contains function pointers to
 * connect the module to the daemon.
 */
module AP_MODULE_DECLARE_DATA subreqonly_module =
{
    STANDARD20_MODULE_STUFF,
    create_dir_config,
    merge_dir_config,
    create_server_cfg,
    NULL,
    command_array,
    register_hooks
};
