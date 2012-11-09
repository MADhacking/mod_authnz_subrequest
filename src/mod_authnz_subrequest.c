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

#include "mod_authnz_subrequest_private.h"
#include <mod_auth.h>
#include <ap_provider.h>
#include <apr_dso.h>
#include <ctype.h>

//#define _DEBUG_MAIN APLOG_WARNING
//#define _DEBUG_CONFIG APLOG_WARNING

/* Function to determine if this is an ApacheFS sub-request */
static unsigned char is_sub_request_of_type(request_rec *r, const char* sub_text)
{
	// If this is NOT a sub-request of some kind then we should just return false
	// already, isn't it!
    if (ap_is_initial_req(r))
    	return FALSE;

	// Loop through the filter chain in the previous request.  If one of them is
	// specified in sub_text then return true.
	ap_filter_t *temp_filter = r->main->output_filters;
	while (temp_filter)
	{
		#ifdef _DEBUG_MAIN
			ap_log_rerror(APLOG_MARK, _DEBUG_MAIN, APR_SUCCESS, r, "is_sub_request_of_type : frec->name = %s", temp_filter->frec->name);
		#endif

		if (strcasecmp(temp_filter->frec->name, sub_text) == 0)
			return TRUE;

		temp_filter = temp_filter->next;
	};

	// We got to the end of the filter chain without finding a filter with a name
	// like that in sub_text so return false.
    return FALSE;
}

static int sub_request_check(request_rec *r, dir_cfg *dconf)
{
	#ifdef _DEBUG_MAIN
		ap_log_rerror(APLOG_MARK, _DEBUG_MAIN, APR_SUCCESS, r, "sub_request_check");
	#endif

	// Get information regarding the Requires directives for this request.
    const apr_array_header_t *reqs_arr = ap_requires(r);

	// If there are no Requires directives we are done already so decline to process.
    if (!reqs_arr)
    {
		#ifdef _DEBUG_MAIN
			ap_log_rerror(APLOG_MARK, _DEBUG_MAIN, APR_SUCCESS, r, "sub_request_check : !reqs_arr");
		#endif
    	return DECLINED;
    }

	int m = r->method_number;
    register int x;
    const char *req_text, *req_word;
    require_line *reqs;

    // Loop through the Require lines...
    reqs = (require_line *)reqs_arr->elts;
    for (x = 0; x < reqs_arr->nelts; x++)
    {
        // Check that this Require line applies to the request method.
        if (!(reqs[x].method_mask & (AP_METHOD_BIT << m)))
            continue;

        // Get the textual representation of this Require directive and split off
        // the first word.
        req_text = reqs[x].requirement;
        req_word = ap_getword_white(r->pool, &req_text);
		#ifdef _DEBUG_MAIN
			ap_log_rerror(APLOG_MARK, _DEBUG_MAIN, APR_SUCCESS, r, "sub_request_check : req_word = %s", req_word);
		#endif

        // If it indicates a sub-request authorisation type then this is for us...
        if (!strcmp(req_word, SUBREQEST_REQUIRE))
        {
            // Get the (server level) configuration information for this module.
        	svr_cfg *sconf = ap_get_module_config(r->server->module_config, &authnz_subrequest_module);

        	// Loop through the remaining words...
        	char* sub_word;
        	while(*req_text && (sub_word = ap_getword_white(r->pool, &req_text)))
        	{
				#ifdef _DEBUG_MAIN
					ap_log_rerror(APLOG_MARK, _DEBUG_MAIN, APR_SUCCESS, r, "sub_request_check : sub_word = %s", sub_word);
				#endif

        		// Is the word the special word "any"?
        		if (!strcasecmp(sub_word, "any"))
        		{
        			// As "any" was specified any old sub-request will do.
                	if (!ap_is_initial_req(r))
                		return OK;
        		}

        		// Look for the word in the table of allowed sub-requests.
        		const char* sub_text = apr_table_get(sconf->sub_req_table, sub_word);

				#ifdef _DEBUG_MAIN
					ap_log_rerror(APLOG_MARK, _DEBUG_MAIN, APR_SUCCESS, r, "sub_request_check : sub_text = %s", sub_text);
				#endif

        		// If we didn't find this sub_text in the table log a warning and continue.
        		if (!sub_text)
        		{
        			ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, PACKAGE_NAME ": Unknown filter: %s", sub_word);
        			return HTTP_INTERNAL_SERVER_ERROR;
        		}

        		// If we found a sub_text then see if this is that kind of sub-request.
            	if (is_sub_request_of_type(r, sub_text))
            		return OK;
        	}
        }
    } // End of Require lines loop.

    // If we got this far then the request is unauthorised.
    return dconf->reject_method;
}

/**
 * Authentication
 *
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
	#ifdef _DEBUG_MAIN
		ap_log_rerror(APLOG_MARK, _DEBUG_MAIN, APR_SUCCESS, r, "check_user_id_hook");
	#endif

    // If this request is NOT using SUBREQEST_AUTH_TYPE as the authentication type
	// specified in the configuration then decline to process it.
	const char *current_auth = ap_auth_type(r);
    if (!current_auth || strcasecmp(current_auth, SUBREQEST_AUTH_TYPE))
    {
		#ifdef _DEBUG_MAIN
			ap_log_rerror(APLOG_MARK, _DEBUG_MAIN, APR_SUCCESS, r, "check_user_id_hook : DECLINED, not for us!");
		#endif
        return DECLINED;
    }

    // Get the (directory level) configuration information for this module.
	dir_cfg *dconf = ap_get_module_config(r->per_dir_config, &authnz_subrequest_module);

	#ifdef _DEBUG_CONFIG
		ap_log_rerror(APLOG_MARK, _DEBUG_CONFIG, APR_SUCCESS, r, "check_user_id_hook : dconf->authn_authoritative = %i", dconf->authn_authoritative);
	#endif


	// This request IS using SUBREQEST_AUTH_TYPE as the authentication type so we
	// need to see if it is a sub-request, there is no point proceeding if it isn't.
    if (ap_is_initial_req(r))
    	return dconf->reject_method;

    // This request IS using SUBREQEST_AUTH_TYPE as the authentication type so we
    // need to see if it is a sub-request of the correct type.
    int auth_result = sub_request_check(r, dconf);

	#ifdef _DEBUG_MAIN
		ap_log_rerror(APLOG_MARK, _DEBUG_MAIN, APR_SUCCESS, r, "check_user_id_hook : sub_request_check = %i", auth_result);
	#endif

    // If the sub-request checks returned anything other than OK and we ARE authoritative
    // then we should return whatever result we got above.
    if ((auth_result != OK) && dconf->authn_authoritative)
    	return auth_result;

    // If the sub-request checks returned anything other than OK and we are NOT authoritative
    // then we should decline processing.
    if (auth_result != OK)
    	return DECLINED;

    // Assuming we got this far then we have authenticated the user.  Set the authentication
    // type for this request and indicate that all is OK.
    r->ap_auth_type = SUBREQEST_AUTH_TYPE;
	return OK;
}

/**
 * Authorisation
 *
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
	#ifdef _DEBUG_MAIN
		ap_log_rerror(APLOG_MARK, _DEBUG_MAIN, APR_SUCCESS, r, "auth_checker_hook");
	#endif

    // Get the current request authentication type.
	const char *current_auth = ap_auth_type(r);

	// If we don't have an authentication type or the request authentication type is NOT
	// our authentication type...
    if (!current_auth || strcasecmp(current_auth, SUBREQEST_AUTH_TYPE))
    {
		#ifdef _DEBUG_MAIN
			ap_log_rerror(APLOG_MARK, _DEBUG_MAIN, APR_SUCCESS, r, "auth_checker_hook : DECLINED");
		#endif
        return DECLINED;
    }

    // Presumably, if we got this far, the request authentication type IS our authentication
    // type so we can allow it.  If it did not meet the SubRequest criteria then it will
    // have been denied already.
    return OK;
}

/* Function to merge a directory configuration */
static void *merge_dir_config(apr_pool_t * p, void *basev, void *addv)
{
	#ifdef _DEBUG_CONFIG
		ap_log_perror(APLOG_MARK, _DEBUG_CONFIG, APR_SUCCESS, p, "merge_dir_config");
	#endif

    // dir_cfg *from = basev;
    dir_cfg *merge = addv;
    dir_cfg *to = apr_palloc(p, sizeof(dir_cfg));

    // Merge the new options with those from the directory above.
    to->authn_authoritative = merge->authn_authoritative;
    to->authz_authoritative = merge->authz_authoritative;
    to->reject_method		= merge->reject_method;

    return to;
}
/* Function to create a new server level configuration object */
static void *create_server_cfg(apr_pool_t * p, server_rec * x)
{
	#ifdef _DEBUG_CONFIG
		ap_log_perror(APLOG_MARK, _DEBUG_CONFIG, APR_SUCCESS, p, "create_server_cfg : %s", 	x->server_hostname);
	#endif

	// Allocate some memory for our svr_cfg structure from the provided pool.
    svr_cfg *cfg = apr_pcalloc(p, sizeof(svr_cfg));

    // Create a new table for our sub-request types and strings and populate it with
    // the default values.
    cfg->sub_req_table = apr_table_make(p, 5);
    apr_table_add(cfg->sub_req_table, "mod_transform", 	"XSLT");
    apr_table_add(cfg->sub_req_table, "mod_include", 	"INCLUDES");

    // By default we shall announce our presence in the headers.
    cfg->announce = 1;

    return cfg;
}

/* Function to create a new directory level configuration object */
static void *create_dir_config(apr_pool_t * p, char *x)
{
	#ifdef _DEBUG_CONFIG
		ap_log_perror(APLOG_MARK, _DEBUG_CONFIG, APR_SUCCESS, p, "create_dir_cfg : %s", x);
	#endif

	// Allocate some memory for our dir_cfg structure from the provided pool.
    dir_cfg *conf = apr_pcalloc(p, sizeof(dir_cfg));

    // By default we should be authoritative for authentication and authorisation.
    conf->authn_authoritative = 1;
    conf->authz_authoritative = 1;

    // We will give a real error message by default.
    conf->reject_method = HTTP_UNAUTHORIZED;

    return conf;
}

/* This function is registered as a command hook for the SubReqOnlyAnnounce command */
static const char *set_announce(cmd_parms *cmd, void *struct_ptr, int arg)
{
	#ifdef _DEBUG_CONFIG
		ap_log_perror(APLOG_MARK, _DEBUG_CONFIG, APR_SUCCESS, cmd->pool, "set_announce");
	#endif

    svr_cfg *cfg = ap_get_module_config(cmd->server->module_config,	&authnz_subrequest_module);

    // SubReqOnlyAnnounce is a server wide option, check it has been used as such.
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
    if (err)
        return err;

    cfg->announce = arg ? 1 : 0;

    return NULL;
}

static const char *add_subreq_type(cmd_parms *cmd, void *struct_ptr, const char *key, const char *value)
{
	#ifdef _DEBUG_CONFIG
		ap_log_perror(APLOG_MARK, _DEBUG_CONFIG, APR_SUCCESS, cmd->pool, "add_subreq_type: key = %s, value = %s", key, value);
	#endif

    svr_cfg *cfg = ap_get_module_config(cmd->server->module_config,	&authnz_subrequest_module);

    apr_table_add(cfg->sub_req_table, key, value);

    return NULL;
}

/* Once the module is loaded, initialised, the hooks registered and the server wide
 * configuration loaded this function is executed.  Server wide configuration options
 * should be acted upon here if required.
 */
static int post_config_hook(apr_pool_t *p, apr_pool_t *log, apr_pool_t *ptemp, server_rec *s)
{
    svr_cfg *cfg = ap_get_module_config(s->module_config, &authnz_subrequest_module);

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

    ap_register_provider(p, AUTHN_PROVIDER_GROUP, PACKAGE_NAME, PACKAGE_VERSION, &authnz_subrequest_module);
};

/* The command array.  This contains entries for the commands
 * which appear in configuration files.
 */
static const command_rec command_array[] =
{
	AP_INIT_FLAG("Auth" SUBREQEST_AUTH_TYPE "Authoritative", ap_set_flag_slot, (void *)APR_OFFSETOF(dir_cfg, authn_authoritative),
		OR_AUTHCFG, "Set to 'Off' to allow access control to be passed along to lower modules (default is On)."),

	AP_INIT_FLAG("Authz" SUBREQEST_AUTH_TYPE "Authoritative", ap_set_flag_slot, (void *)APR_OFFSETOF(dir_cfg, authz_authoritative),
		OR_AUTHCFG, "Set to 'Off' to allow access control to be passed along to lower modules (default is On)."),

    AP_INIT_FLAG(SUBREQEST_AUTH_TYPE "Announce", set_announce, NULL, RSRC_CONF, "Whether to announce this module in the server header. Default: On"),

    AP_INIT_TAKE1(SUBREQEST_AUTH_TYPE "RejectMethod", ap_set_int_slot, (void *)APR_OFFSETOF(dir_cfg, reject_method),
    	OR_AUTHCFG, "The HTTP response method code to use for rejecting access.  Default: 401"),

    AP_INIT_TAKE2(SUBREQEST_AUTH_TYPE "DeclareType", add_subreq_type, NULL,
    	RSRC_CONF, "Declare a new sub-request type using the form " SUBREQEST_AUTH_TYPE " DeclareType KEY VALUE"),

    {NULL}
};

/* The declaration of the Apache module.  This structure contains function pointers to
 * connect the module to the daemon.
 */
module AP_MODULE_DECLARE_DATA authnz_subrequest_module =
{
    STANDARD20_MODULE_STUFF,
    create_dir_config,
    merge_dir_config,
    create_server_cfg,
    NULL,
    command_array,
    register_hooks
};
