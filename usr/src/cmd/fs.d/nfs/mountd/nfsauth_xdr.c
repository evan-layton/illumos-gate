/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2020 Nexenta by DDN, Inc. All rights reserved.
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <nfs/auth.h>
#include <rpc/auth_sys.h>

bool_t
xdr_varg(XDR *xdrs, varg_t *vap)
{
	if (!xdr_u_int(xdrs, &vap->vers))
		return (FALSE);

	switch (vap->vers) {
	case V_PROTO:
	case V_AUDIT:
		if (!xdr_nfsauth_arg(xdrs, &vap->arg_u.arg, vap->vers))
			return (FALSE);
		break;

	/* Additional versions of the args go here */

	default:
		vap->vers = V_ERROR;
		return (FALSE);
		/* NOTREACHED */
	}
	return (TRUE);
}

bool_t
xdr_nfsauth_auditinfo_arg(XDR *xdrs, audit_req *req)
{
	if (!xdr_uid_t(xdrs, &req->req_uid))
		return (FALSE);
	if (!xdr_gid_t(xdrs, &req->req_gid))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfsauth_access_arg(XDR *xdrs, auth_req *req)
{
	if (!xdr_netobj(xdrs, &req->req_client))
		return (FALSE);
	if (!xdr_string(xdrs, &req->req_netid, ~0))
		return (FALSE);
	if (!xdr_string(xdrs, &req->req_path, A_MAXPATH))
		return (FALSE);
	if (!xdr_int(xdrs, &req->req_flavor))
		return (FALSE);
	if (!xdr_uid_t(xdrs, &req->req_clnt_uid))
		return (FALSE);
	if (!xdr_gid_t(xdrs, &req->req_clnt_gid))
		return (FALSE);
	if (!xdr_array(xdrs, (caddr_t *)&req->req_clnt_gids.val,
	    &req->req_clnt_gids.len, NGROUPS_UMAX,
	    (uint_t)sizeof (gid_t), xdr_gid_t))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfsauth_arg(XDR *xdrs, nfsauth_arg_t *argp, vtypes type)
{
	if (!xdr_u_int(xdrs, &argp->cmd))
		return (FALSE);

	switch (argp->cmd) {
	case NFSAUTH_ACCESS:
		if (!xdr_nfsauth_access_arg(xdrs, &argp->areq))
			return (FALSE);
		break;

	case NFSAUTH_AUDITINFO:
		if (type < V_AUDIT ||
		    !xdr_nfsauth_auditinfo_arg(xdrs, &argp->ureq))
			return (FALSE);
		break;

	default:
		argp->cmd = 0;
		return (FALSE);
		/* NOTREACHED */
	}
	return (TRUE);
}

bool_t
xdr_nfsauth_auditinfo_res(XDR *xdrs, audit_res *res)
{
	if (!xdr_u_int(xdrs, &res->res_auid))
		return (FALSE);
	if (!xdr_u_int(xdrs, &res->res_amask.as_success))
		return (FALSE);
	if (!xdr_u_int(xdrs, &res->res_amask.as_failure))
		return (FALSE);
	if (!xdr_u_int(xdrs, &res->res_asid))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfsauth_access_res(XDR *xdrs, auth_res *res)
{
	if (!xdr_int(xdrs, &res->auth_perm))
		return (FALSE);
	if (!xdr_uid_t(xdrs, &res->auth_srv_uid))
		return (FALSE);
	if (!xdr_gid_t(xdrs, &res->auth_srv_gid))
		return (FALSE);
	if (!xdr_array(xdrs, (caddr_t *)&res->auth_srv_gids.val,
	    &res->auth_srv_gids.len, NGROUPS_UMAX,
	    (uint_t)sizeof (gid_t), xdr_gid_t))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_nfsauth_res(XDR *xdrs, nfsauth_res_t *argp, uint_t cmd)
{
	if (!xdr_u_int(xdrs, &argp->stat))
		return (FALSE);

	switch (cmd) {
	case NFSAUTH_ACCESS:
		if (!xdr_nfsauth_access_res(xdrs, &argp->ares))
			return (FALSE);
		break;

	case NFSAUTH_AUDITINFO:
		if (!xdr_nfsauth_auditinfo_res(xdrs, &argp->ures))
			return (FALSE);
		break;

	default:
		return (FALSE);
		/* NOTREACHED */
	}
	return (TRUE);
}
