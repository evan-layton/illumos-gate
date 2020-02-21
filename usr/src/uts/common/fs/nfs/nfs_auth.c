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
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015 by Delphix. All rights reserved.
 * Copyright (c) 2015 Joyent, Inc.  All rights reserved.
 * Copyright 2020 Nexenta by DDN, Inc. All rights reserved.
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/cred.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/pathname.h>
#include <sys/utsname.h>
#include <sys/debug.h>
#include <sys/door.h>
#include <sys/sdt.h>
#include <sys/thread.h>
#include <sys/avl.h>

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>

#include <nfs/nfs.h>
#include <nfs/nfsauth_cache.h>
#include <nfs/nfs_clnt.h>
#include <nfs/auth.h>

#include <c2/audit.h>
#include <c2/audit_kernel.h>
#include <sys/idmap.h>

static struct kmem_cache *nfsauth_cache_handle;
static void nfsauth_cache_reclaim(void *);
static void nfsauth_cache_reclaim_zone(nfs_globals_t *);
static void nfsauth_cache_trim(avl_tree_t **cache, krwlock_t *rwlock);

extern pri_t minclsyspri;

/* NFS auth cache statistics */
volatile uint_t nfsauth_cache_hit;
volatile uint_t nfsauth_cache_miss;
volatile uint_t nfsauth_cache_refresh;
volatile uint_t nfsauth_cache_reclaims;
volatile uint_t exi_cache_auth_reclaim_failed;
volatile uint_t exi_cache_clnt_reclaim_failed;

/*
 * Used to manipulate things on the refreshq_queue.  Note that the refresh
 * thread will effectively pop a node off of the queue, at which point it
 * will no longer need to hold the mutex.
 */
static kmutex_t refreshq_lock;
static list_t refreshq_queue;
static kcondvar_t refreshq_cv;

static void nfsauth_free_node(struct auth_cache *);
static void nfsauth_refresh_thread(nfsauth_globals_t *);

static bool_t nfsauth_cache_setinfo(nfsauth_cache_t *, nfsauth_cache_t *, int);
static bool_t nfsauth_cache_getinfo(nfsauth_cache_t *, nfsauth_globals_t *,
    struct exportinfo *, char *, int, struct netbuf *, cred_t *);

static bool_t nfsauth_cache_getauditinfo(struct svc_req *, cred_t *,
    au_id_t *, au_mask_t *, au_asid_t *);
static bool_t nfsauth_getauditinfo(nfsauth_globals_t *, cred_t *,
    nfsauth_cache_t *);

static int nfsauth_cache_compar(const void *, const void *);

static nfsauth_globals_t *
nfsauth_get_zg(void)
{
	nfs_globals_t *ng = nfs_srv_getzg();
	nfsauth_globals_t *nag = ng->nfs_auth;
	ASSERT(nag != NULL);
	return (nag);
}

void
mountd_args(uint_t did)
{
	nfsauth_globals_t *nag;

	nag = nfsauth_get_zg();
	mutex_enter(&nag->mountd_lock);
	if (nag->mountd_dh != NULL)
		door_ki_rele(nag->mountd_dh);
	nag->mountd_dh = door_ki_lookup(did);
	mutex_exit(&nag->mountd_lock);
}

void
nfsauth_init(void)
{
	nfsauth_cache_handle = kmem_cache_create("nfsauth_cache_handle",
	    sizeof (struct auth_cache), 0, NULL, NULL,
	    nfsauth_cache_reclaim, NULL, NULL, 0);
}

void
nfsauth_fini(void)
{
	kmem_cache_destroy(nfsauth_cache_handle);
}

void
nfsauth_zone_init(nfs_globals_t *ng)
{
	nfsauth_globals_t *nag;
	int i;

	nag = kmem_zalloc(sizeof (*nag), KM_SLEEP);

	/*
	 * mountd can be restarted by smf(5).  We need to make sure
	 * the updated door handle will safely make it to mountd_dh.
	 */
	mutex_init(&nag->mountd_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&nag->refreshq_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&nag->refreshq_queue, sizeof (refreshq_exi_node_t),
	    offsetof(refreshq_exi_node_t, ren_node));
	cv_init(&nag->refreshq_cv, NULL, CV_DEFAULT, NULL);
	nag->refreshq_thread_state = REFRESHQ_THREAD_NEED_CREATE;

	for (i = 0; i < AUTH_TABLESIZE; i++) {
		nag->audit_cache[i] = kmem_alloc(sizeof (avl_tree_t), KM_SLEEP);
		avl_create(nag->audit_cache[i], nfsauth_cache_clnt_compar,
		    sizeof (struct auth_cache_clnt),
		    offsetof(struct auth_cache_clnt, authc_link));
	}
	rw_init(&nag->audit_lock, NULL, RW_DEFAULT, NULL);

	ng->nfs_auth = nag;
}

void
nfsauth_zone_shutdown(nfs_globals_t *ng)
{
	refreshq_exi_node_t	*ren;
	nfsauth_globals_t	*nag = ng->nfs_auth;

	/* Prevent the nfsauth_refresh_thread from getting new work */
	mutex_enter(&nag->refreshq_lock);
	if (nag->refreshq_thread_state == REFRESHQ_THREAD_RUNNING) {
		nag->refreshq_thread_state = REFRESHQ_THREAD_FINI_REQ;
		cv_broadcast(&nag->refreshq_cv);

		/* Wait for nfsauth_refresh_thread() to exit */
		while (nag->refreshq_thread_state != REFRESHQ_THREAD_HALTED)
			cv_wait(&nag->refreshq_cv, &nag->refreshq_lock);
	}
	mutex_exit(&nag->refreshq_lock);

	/*
	 * Walk the exi_list and in turn, walk the auth_lists and free all
	 * lists.  In addition, free INVALID auth_cache entries.
	 */
	while ((ren = list_remove_head(&nag->refreshq_queue))) {
		refreshq_auth_node_t *ran;

		while ((ran = list_remove_head(&ren->ren_authlist)) != NULL) {
			struct auth_cache *p = ran->ran_auth;
			if (p->auth_state == NFS_AUTH_INVALID)
				nfsauth_free_node(p);
			strfree(ran->ran_netid);
			kmem_free(ran, sizeof (*ran));
		}

		list_destroy(&ren->ren_authlist);
		if (ren->ren_exi != NULL)
			exi_rele(ren->ren_exi);
		kmem_free(ren, sizeof (*ren));
	}
}

void
nfsauth_zone_fini(nfs_globals_t *ng)
{
	nfsauth_globals_t *nag = ng->nfs_auth;
	int i;

	ng->nfs_auth = NULL;

	nfsauth_cache_free(nag->audit_cache);
	rw_destroy(&nag->audit_lock);
	for (i = 0; i < AUTH_TABLESIZE; i++) {
		avl_destroy(nag->audit_cache[i]);
		kmem_free(nag->audit_cache[i], sizeof (avl_tree_t));
	}

	list_destroy(&nag->refreshq_queue);
	cv_destroy(&nag->refreshq_cv);
	mutex_destroy(&nag->refreshq_lock);
	mutex_destroy(&nag->mountd_lock);
	/* Extra cleanup. */
	if (nag->mountd_dh != NULL)
		door_ki_rele(nag->mountd_dh);
	kmem_free(nag, sizeof (*nag));
}

/*
 * Convert the address in a netbuf to
 * a hash index for the auth_cache table.
 */
static int
hash(struct netbuf *a)
{
	int i, h = 0;

	for (i = 0; i < a->len; i++)
		h ^= a->buf[i];

	return (h & (AUTH_TABLESIZE - 1));
}

/*
 * Mask out the components of an
 * address that do not identify
 * a host. For socket addresses the
 * masking gets rid of the port number.
 */
static void
addrmask(struct netbuf *addr, struct netbuf *mask)
{
	int i;

	for (i = 0; i < addr->len; i++)
		addr->buf[i] &= mask->buf[i];
}

/*
 * nfsauth4_access is used for NFS V4 auth checking. Besides doing
 * the common nfsauth_access(), it will check if the client can
 * have a limited access to this vnode even if the security flavor
 * used does not meet the policy.
 */
int
nfsauth4_access(struct exportinfo *exi, vnode_t *vp, struct svc_req *req,
    cred_t *cr, uid_t *uid, gid_t *gid, uint_t *ngids, gid_t **gids)
{
	int access;

	access = nfsauth_access(exi, req, cr, uid, gid, ngids, gids);

	/*
	 * There are cases that the server needs to allow the client
	 * to have a limited view.
	 *
	 * e.g.
	 * /export is shared as "sec=sys,rw=dfs-test-4,sec=krb5,rw"
	 * /export/home is shared as "sec=sys,rw"
	 *
	 * When the client mounts /export with sec=sys, the client
	 * would get a limited view with RO access on /export to see
	 * "home" only because the client is allowed to access
	 * /export/home with auth_sys.
	 */
	if (access & NFSAUTH_DENIED || access & NFSAUTH_WRONGSEC) {
		/*
		 * Allow ro permission with LIMITED view if there is a
		 * sub-dir exported under vp.
		 */
		if (has_visible(exi, vp))
			return (NFSAUTH_LIMITED);
	}

	return (access);
}

int
nfs4auth_getauditinfo(struct svc_req *req, cred_t *cr)
{
	auditinfo_addr_t *au;

	if (!AU_ZONE_AUDITING(NULL))
		return (1);

	au = crgetauinfo_modifiable(cr);
	if (au == NULL)
		return (0);

	if (!nfsauth_cache_getauditinfo(req, cr, &au->ai_auid,
	    &au->ai_mask, &au->ai_asid))
		return (0);

	struct sockaddr *sa;
	sa = (struct sockaddr *)svc_getrpccaller(req->rq_xprt)->buf;

	if (sa == NULL)
		return (0);

	if (sa->sa_family == AF_INET) {
		au->ai_termid.at_addr[0] =
		    ((struct sockaddr_in *)sa)->sin_addr.s_addr;
		au->ai_termid.at_port =
		    ntohs(((struct sockaddr_in *)sa)->sin_port);
		au->ai_termid.at_type = AU_IPv4;
	} else {
		bcopy(&((struct sockaddr_in6 *)sa)->sin6_addr,
		    au->ai_termid.at_addr, sizeof (in6_addr_t));
		au->ai_termid.at_port =
		    ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
		au->ai_termid.at_type = AU_IPv6;
	}

	return (1);
}

static void
sys_log(const char *msg)
{
	static time_t	tstamp = 0;
	time_t		now;

	/*
	 * msg is shown (at most) once per minute
	 */
	now = gethrestime_sec();
	if ((tstamp + 60) < now) {
		tstamp = now;
		cmn_err(CE_WARN, msg);
	}
}

static void
nfsauth_auth_res_setinfo(nfsauth_cache_t *p, nfsauth_res_t *res)
{
	p->auth_access = res->ares.auth_perm;
	p->auth_srv_uid = res->ares.auth_srv_uid;
	p->auth_srv_gid = res->ares.auth_srv_gid;

	if ((p->auth_srv_ngids = res->ares.auth_srv_gids.len) != 0) {
		p->auth_srv_gids = kmem_alloc(
		    p->auth_srv_ngids * sizeof (gid_t), KM_SLEEP);
		bcopy(res->ares.auth_srv_gids.val, p->auth_srv_gids,
		    p->auth_srv_ngids * sizeof (gid_t));
	} else {
		p->auth_srv_gids = NULL;
	}
}

static void
nfsauth_audit_res_setinfo(nfsauth_cache_t *p, nfsauth_res_t *res)
{
	p->audit_auid = res->ures.res_auid;
	p->audit_amask = res->ures.res_amask;
	p->audit_asid = res->ures.res_asid;
}

static void
nfsauth_res_setinfo(nfsauth_cache_t *p, nfsauth_res_t *res)
{
	if (p->auth_type == NFSAUTH_ACCESS)
		nfsauth_auth_res_setinfo(p, res);
	else
		nfsauth_audit_res_setinfo(p, res);
}

static int
nfsauth_doorcall(nfsauth_globals_t *nag, varg_t *varg, nfsauth_cache_t *p)
{
	nfsauth_res_t		  res = {0};
	XDR			  xdrs;
	size_t			  absz;
	caddr_t			  abuf;
	int			  last = 0;
	door_arg_t		  da;
	door_info_t		  di;
	door_handle_t		  dh;
	uint_t			  ntries = 0;

	DTRACE_PROBE1(nfsserv__func__nfsauth__varg, varg_t *, varg);

	/*
	 * Setup the XDR stream for encoding the arguments. Notice that
	 * in addition to the args having variable fields (req_netid and
	 * req_path), the argument data structure is itself versioned,
	 * so we need to make sure we can size the arguments buffer
	 * appropriately to encode all the args. If we can't get sizing
	 * info _or_ properly encode the arguments, there's really no
	 * point in continuting, so we fail the request.
	 */
	if ((absz = xdr_sizeof(xdr_varg, varg)) == 0) {
		return (NFSAUTH_DENIED);
	}

	abuf = (caddr_t)kmem_alloc(absz, KM_SLEEP);
	xdrmem_create(&xdrs, abuf, absz, XDR_ENCODE);
	if (!xdr_varg(&xdrs, varg)) {
		XDR_DESTROY(&xdrs);
		goto fail;
	}
	XDR_DESTROY(&xdrs);

	/*
	 * Prepare the door arguments
	 *
	 * We don't know the size of the message the daemon
	 * will pass back to us.  By setting rbuf to NULL,
	 * we force the door code to allocate a buf of the
	 * appropriate size.  We must set rsize > 0, however,
	 * else the door code acts as if no response was
	 * expected and doesn't pass the data to us.
	 */
	da.data_ptr = (char *)abuf;
	da.data_size = absz;
	da.desc_ptr = NULL;
	da.desc_num = 0;
	da.rbuf = NULL;
	da.rsize = 1;

retry:
	mutex_enter(&nag->mountd_lock);
	dh = nag->mountd_dh;
	if (dh != NULL)
		door_ki_hold(dh);
	mutex_exit(&nag->mountd_lock);

	if (dh == NULL) {
		/*
		 * The rendezvous point has not been established yet!
		 * This could mean that either mountd(1m) has not yet
		 * been started or that _this_ routine nuked the door
		 * handle after receiving an EINTR for a REVOKED door.
		 *
		 * Returning NFSAUTH_DROP will cause the NFS client
		 * to retransmit the request, so let's try to be more
		 * rescillient and attempt for ntries before we bail.
		 */
		if (++ntries % NFSAUTH_DR_TRYCNT) {
			delay(hz);
			goto retry;
		}

		kmem_free(abuf, absz);

		sys_log("nfsauth: mountd has not established door");
		return (NFSAUTH_DROP);
	}

	ntries = 0;

	/*
	 * Now that we've got what we need, place the call.
	 */
	switch (door_ki_upcall_limited(dh, &da, NULL, SIZE_MAX, 0)) {
	case 0:				/* Success */
		door_ki_rele(dh);

		if (da.data_ptr == NULL && da.data_size == 0) {
			/*
			 * The door_return that contained the data
			 * failed! We're here because of the 2nd
			 * door_return (w/o data) such that we can
			 * get control of the thread (and exit
			 * gracefully).
			 */
			DTRACE_PROBE1(nfsserv__func__nfsauth__door__nil,
			    door_arg_t *, &da);
			goto fail;
		}

		break;

	case EAGAIN:
		/*
		 * Server out of resources; back off for a bit
		 */
		door_ki_rele(dh);
		delay(hz);
		goto retry;
		/* NOTREACHED */

	case EINTR:
		if (!door_ki_info(dh, &di)) {
			door_ki_rele(dh);

			if (di.di_attributes & DOOR_REVOKED) {
				/*
				 * The server barfed and revoked
				 * the (existing) door on us; we
				 * want to wait to give smf(5) a
				 * chance to restart mountd(1m)
				 * and establish a new door handle.
				 */
				mutex_enter(&nag->mountd_lock);
				if (dh == nag->mountd_dh) {
					door_ki_rele(nag->mountd_dh);
					nag->mountd_dh = NULL;
				}
				mutex_exit(&nag->mountd_lock);
				delay(hz);
				goto retry;
			}
			/*
			 * If the door was _not_ revoked on us,
			 * then more than likely we took an INTR,
			 * so we need to fail the operation.
			 */
			goto fail;
		}
		/*
		 * The only failure that can occur from getting
		 * the door info is EINVAL, so we let the code
		 * below handle it.
		 */
		/* FALLTHROUGH */

	case EBADF:
	case EINVAL:
	default:
		/*
		 * If we have a stale door handle, give smf a last
		 * chance to start it by sleeping for a little bit.
		 * If we're still hosed, we'll fail the call.
		 *
		 * Since we're going to reacquire the door handle
		 * upon the retry, we opt to sleep for a bit and
		 * _not_ to clear mountd_dh. If mountd restarted
		 * and was able to set mountd_dh, we should see
		 * the new instance; if not, we won't get caught
		 * up in the retry/DELAY loop.
		 */
		door_ki_rele(dh);
		if (!last) {
			delay(hz);
			last++;
			goto retry;
		}
		sys_log("nfsauth: stale mountd door handle");
		goto fail;
	}

	ASSERT(da.rbuf != NULL);

	/*
	 * No door errors encountered; setup the XDR stream for decoding
	 * the results. If we fail to decode the results, we've got no
	 * other recourse than to fail the request.
	 */
	xdrmem_create(&xdrs, da.rbuf, da.rsize, XDR_DECODE);
	if (!xdr_nfsauth_res(&xdrs, &res, varg->arg_u.arg.cmd)) {
		xdr_free(xdr_nfsauth_res, (char *)&res);
		XDR_DESTROY(&xdrs);
		kmem_free(da.rbuf, da.rsize);
		goto fail;
	}
	XDR_DESTROY(&xdrs);
	kmem_free(da.rbuf, da.rsize);

	DTRACE_PROBE1(nfsserv__func__nfsauth__results, nfsauth_res_t *, &res);
	switch (res.stat) {
		case NFSAUTH_DR_OKAY:
			nfsauth_res_setinfo(p, &res);
			break;

		case NFSAUTH_DR_EFAIL:
		case NFSAUTH_DR_DECERR:
		case NFSAUTH_DR_BADCMD:
		case NFSAUTH_DR_NOAUDIT:
		default:
			xdr_free(xdr_nfsauth_res, (char *)&res);
fail:
			kmem_free(abuf, absz);
			return (NFSAUTH_DENIED);
			/* NOTREACHED */
	}

	xdr_free(xdr_nfsauth_res, (char *)&res);
	kmem_free(abuf, absz);

	return (0);
}

/*
 * Callup to the mountd to get access information in the kernel.
 * Use V_PROTO, so that down-rev mountd's (in NGZ) will understand it.
 */
static bool_t
nfsauth_retrieve(nfsauth_globals_t *nag, struct exportinfo *exi,
    char *req_netid, int flavor, struct netbuf *addr, cred_t *clnt_cred,
    nfsauth_cache_t *p)
{
	varg_t varg = {
		.vers = V_PROTO,
		.arg_u.arg = { .cmd = NFSAUTH_ACCESS, { .areq = {
			.req_client.n_len = addr->len,
			.req_client.n_bytes = addr->buf,
			.req_netid = req_netid,
			.req_path = exi->exi_export.ex_path,
			.req_flavor = flavor,
			.req_clnt_uid = crgetuid(clnt_cred),
			.req_clnt_gid = crgetgid(clnt_cred),
			.req_clnt_gids.len = crgetngroups(clnt_cred),
			.req_clnt_gids.val = (gid_t *)crgetgroups(clnt_cred)
		}}}
	};
	int err;

	/*
	 * No entry in the cache for this client/flavor
	 * so we need to call the nfsauth service in the
	 * mount daemon.
	 */
	err = nfsauth_doorcall(nag, &varg, p);
	if (err != 0) {
		p->auth_access = err;
		return (FALSE);
	}

	return (TRUE);
}

/*
 * Callup to the mountd to get audit information in the kernel.
 */
static bool_t
nfsauth_getauditinfo(nfsauth_globals_t *nag, cred_t *clnt_cred,
    nfsauth_cache_t *p)
{
	varg_t varg = {
		.vers = V_AUDIT,
		.arg_u.arg = { .cmd = NFSAUTH_AUDITINFO, { .ureq = {
			.req_uid = crgetuid(clnt_cred),
			.req_gid = crgetgid(clnt_cred)
		}}}
	};

	/*
	 * No entry in the cache for this client
	 * so we need to call the nfsauth service in the
	 * mount daemon.
	 */
	if (nfsauth_doorcall(nag, &varg, p) == 0)
		return (TRUE);

	if (varg.vers != V_ERROR)
		return (FALSE);

	/*
	 * mountd didn't understand V_AUDIT, which means it's a
	 * down-rev mountd (in a NGZ). Do our best to fill in
	 * the audit information.
	 */
	if (AU_ZONE_AUDITING(NULL)) {
		p->audit_auid = crgetuid(clnt_cred);
		p->audit_amask = (IDMAP_ID_IS_EPHEMERAL(p->audit_auid)) ?
		    (GET_KCTX_PZ)->auk_info.ai_namask :
		    (GET_KCTX_PZ)->auk_info.ai_amask;
		p->audit_asid = 0; // 0 is the only 'invalid' ASID
		cmn_err(CE_WARN, "zone %s did not provide audit info, "
		    "but auditing is configured; consider upgrading",
		    curzone->zone_name);
	} else {
		p->audit_auid = AU_NOAUDITID;
		p->audit_amask.am_success = p->audit_amask.am_failure = 0;
		p->audit_asid = 0;
	}
	return (TRUE);
}

static void
nfsauth_refresh_thread(nfsauth_globals_t *nag)
{
	refreshq_exi_node_t	*ren;
	refreshq_auth_node_t	*ran;

	struct exportinfo	*exi;

	bool_t			retrieval;

	callb_cpr_t		cprinfo;

	CALLB_CPR_INIT(&cprinfo, &nag->refreshq_lock, callb_generic_cpr,
	    "nfsauth_refresh");

	for (;;) {
		mutex_enter(&nag->refreshq_lock);
		if (nag->refreshq_thread_state != REFRESHQ_THREAD_RUNNING) {
			/* Keep the hold on the lock! */
			break;
		}

		ren = list_remove_head(&nag->refreshq_queue);
		if (ren == NULL) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&nag->refreshq_cv, &nag->refreshq_lock);
			CALLB_CPR_SAFE_END(&cprinfo, &nag->refreshq_lock);
			mutex_exit(&nag->refreshq_lock);
			continue;
		}
		mutex_exit(&nag->refreshq_lock);

		exi = ren->ren_exi;

		/*
		 * Since the ren was removed from the refreshq_queue above,
		 * this is the only thread aware about the ren existence, so we
		 * have the exclusive ownership of it and we do not need to
		 * protect it by any lock.
		 */
		while ((ran = list_remove_head(&ren->ren_authlist))) {
			struct auth_cache *p = ran->ran_auth;
			char *netid = ran->ran_netid;
			nfsauth_cache_t tmpauth;

			ASSERT(p != NULL);
			ASSERT(netid != NULL);

			kmem_free(ran, sizeof (refreshq_auth_node_t));

			mutex_enter(&p->auth_lock);

			/*
			 * Once the entry goes INVALID, it can not change
			 * state.
			 *
			 * No need to refresh entries also in a case we are
			 * just shutting down.
			 *
			 * In general, there is no need to hold the
			 * refreshq_lock to test the refreshq_thread_state.  We
			 * do hold it at other places because there is some
			 * related thread synchronization (or some other tasks)
			 * close to the refreshq_thread_state check.
			 *
			 * The check for the refreshq_thread_state value here
			 * is purely advisory to allow the faster
			 * nfsauth_refresh_thread() shutdown.  In a case we
			 * will miss such advisory, nothing catastrophic
			 * happens: we will just spin longer here before the
			 * shutdown.
			 */
			if (p->auth_state == NFS_AUTH_INVALID ||
			    nag->refreshq_thread_state !=
			    REFRESHQ_THREAD_RUNNING) {
				mutex_exit(&p->auth_lock);

				if (p->auth_state == NFS_AUTH_INVALID)
					nfsauth_free_node(p);

				strfree(netid);

				continue;
			}

			/*
			 * Make sure the state is valid.  Note that once we
			 * change the state to NFS_AUTH_REFRESHING, no other
			 * thread will be able to work on this entry.
			 */
			ASSERT(p->auth_state == NFS_AUTH_STALE);

			p->auth_state = NFS_AUTH_REFRESHING;
			mutex_exit(&p->auth_lock);

			DTRACE_PROBE2(nfsauth__debug__cache__refresh,
			    struct exportinfo *, exi,
			    struct auth_cache *, p);

			/*
			 * The first caching of the access rights
			 * is done with the netid pulled out of the
			 * request from the client. All subsequent
			 * users of the cache may or may not have
			 * the same netid. It doesn't matter. So
			 * when we refresh, we simply use the netid
			 * of the request which triggered the
			 * refresh attempt.
			 */

			tmpauth.auth_type = p->authi_type;

			retrieval = nfsauth_cache_getinfo(&tmpauth, nag, exi,
			    netid, p->auth_flavor, &p->auth_clnt->authc_addr,
			    p->auth_clnt_cred);

			/*
			 * This can only be set in one other place
			 * and the state has to be NFS_AUTH_FRESH.
			 */
			strfree(netid);

			mutex_enter(&p->auth_lock);
			if (p->auth_state == NFS_AUTH_INVALID) {
				mutex_exit(&p->auth_lock);
				nfsauth_free_node(p);
				if (tmpauth.auth_type == NFSAUTH_ACCESS &&
				    retrieval == TRUE)
					kmem_free(tmpauth.auth_srv_gids,
					    tmpauth.auth_srv_ngids *
					    sizeof (gid_t));
			} else {
				/*
				 * If we got an error, do not reset the
				 * time. This will cause the next access
				 * check for the client to reschedule this
				 * node.
				 */
				if (retrieval == TRUE) {
					(void) nfsauth_cache_setinfo(&tmpauth,
					    &p->auth_info, 0);
					p->auth_freshness = gethrestime_sec();
				}
				p->auth_state = NFS_AUTH_FRESH;

				cv_broadcast(&p->auth_cv);
				mutex_exit(&p->auth_lock);
			}
		}

		list_destroy(&ren->ren_authlist);
		if (exi != NULL)
			exi_rele(ren->ren_exi);
		kmem_free(ren, sizeof (refreshq_exi_node_t));
	}

	nag->refreshq_thread_state = REFRESHQ_THREAD_HALTED;
	cv_broadcast(&nag->refreshq_cv);
	CALLB_CPR_EXIT(&cprinfo);
	DTRACE_PROBE(nfsauth__nfsauth__refresh__thread__exit);
	zthread_exit();
}

int
nfsauth_cache_clnt_compar(const void *v1, const void *v2)
{
	int c;

	const struct auth_cache_clnt *a1 = (const struct auth_cache_clnt *)v1;
	const struct auth_cache_clnt *a2 = (const struct auth_cache_clnt *)v2;

	if (a1->authc_addr.len < a2->authc_addr.len)
		return (-1);
	if (a1->authc_addr.len > a2->authc_addr.len)
		return (1);

	c = memcmp(a1->authc_addr.buf, a2->authc_addr.buf, a1->authc_addr.len);
	if (c < 0)
		return (-1);
	if (c > 0)
		return (1);

	return (0);
}

static int
nfsauth_cache_compar(const void *v1, const void *v2)
{
	int c;

	const struct auth_cache *a1 = (const struct auth_cache *)v1;
	const struct auth_cache *a2 = (const struct auth_cache *)v2;

	if (a1->authi_type == NFSAUTH_ACCESS) {
		if (a1->auth_flavor < a2->auth_flavor)
			return (-1);
		if (a1->auth_flavor > a2->auth_flavor)
			return (1);
	}

	if (crgetuid(a1->auth_clnt_cred) < crgetuid(a2->auth_clnt_cred))
		return (-1);
	if (crgetuid(a1->auth_clnt_cred) > crgetuid(a2->auth_clnt_cred))
		return (1);

	if (crgetgid(a1->auth_clnt_cred) < crgetgid(a2->auth_clnt_cred))
		return (-1);
	if (crgetgid(a1->auth_clnt_cred) > crgetgid(a2->auth_clnt_cred))
		return (1);

	if (crgetngroups(a1->auth_clnt_cred) < crgetngroups(a2->auth_clnt_cred))
		return (-1);
	if (crgetngroups(a1->auth_clnt_cred) > crgetngroups(a2->auth_clnt_cred))
		return (1);

	c = memcmp(crgetgroups(a1->auth_clnt_cred),
	    crgetgroups(a2->auth_clnt_cred), crgetngroups(a1->auth_clnt_cred));
	if (c < 0)
		return (-1);
	if (c > 0)
		return (1);

	return (0);
}

static void
nfsauth_auth_cache_init(nfsauth_cache_t *p)
{
	p->auth_srv_ngids = 0;
	p->auth_srv_gids = NULL;
}

static void
nfsauth_audit_cache_init(nfsauth_cache_t *p)
{
	p->audit_auid = AU_NOAUDITID;
	p->audit_asid = AU_NOAUDITID;
	p->audit_amask.as_success = 0;
	p->audit_amask.as_failure = 0;
}

static void
nfsauth_cache_init(nfsauth_cache_t *p, int type)
{
	p->auth_type = type;
	if (type == NFSAUTH_ACCESS)
		nfsauth_auth_cache_init(p);
	else
		nfsauth_audit_cache_init(p);
}

static bool_t
nfsauth_cache_getinfo(nfsauth_cache_t *p, nfsauth_globals_t *nag,
    struct exportinfo *exi, char *netid, int flavor, struct netbuf *addr,
    cred_t *cr)
{
	if (p->auth_type == NFSAUTH_ACCESS)
		return (nfsauth_retrieve(nag, exi, netid, flavor, addr, cr, p));

	return (nfsauth_getauditinfo(nag, cr, p));
}

static bool_t
nfsauth_auth_cache_setinfo(nfsauth_cache_t *src, nfsauth_cache_t *dest,
    int kmflags)
{
	uint_t ngids = src->auth_srv_ngids;
	size_t sz = ngids * sizeof (gid_t);
	gid_t *gids;

	dest->auth_access = src->auth_access;

	if (kmflags != 0 && ngids != 0) {
		gid_t *gids = kmem_alloc(sz, kmflags);
		if (gids == NULL)
			return (FALSE);

		bcopy(src->auth_srv_gids, gids, sz);
	} else if (ngids != 0) {
		gids = src->auth_srv_gids;
	} else {
		gids = NULL;
	}

	dest->auth_srv_uid = src->auth_srv_uid;
	dest->auth_srv_gid = src->auth_srv_gid;
	dest->auth_srv_ngids = ngids;

	if (dest->auth_srv_gids != NULL)
		kmem_free(dest->auth_srv_gids,
		    dest->auth_srv_ngids * sizeof (gid_t));

	dest->auth_srv_gids = gids;
	return (TRUE);
}

static void
nfsauth_audit_cache_setinfo(nfsauth_cache_t *src, nfsauth_cache_t *dest)
{
	dest->audit_auid = src->audit_auid;
	dest->audit_amask = src->audit_amask;
	dest->audit_asid = src->audit_asid;
}

static bool_t
nfsauth_cache_setinfo(nfsauth_cache_t *src, nfsauth_cache_t *dest, int kmflags)
{
	if (src->auth_type == NFSAUTH_ACCESS)
		return (nfsauth_auth_cache_setinfo(src, dest, kmflags));
	nfsauth_audit_cache_setinfo(src, dest);
	return (TRUE);
}

static bool_t
nfsauth_cache_common_get(struct exportinfo *exi, struct svc_req *req,
    cred_t *cr, nfsauth_cache_t *authp, int flavor, int type)
{
	nfsauth_globals_t	*nag;
	struct netbuf		*taddrmask;
	struct netbuf		addr;	/* temporary copy of client's address */
	const struct netbuf	*claddr;
	avl_tree_t		*tree;
	struct auth_cache	ac;	/* used as a template for avl_find() */
	struct auth_cache_clnt	*c;
	struct auth_cache_clnt	acc;	/* used as a template for avl_find() */
	struct auth_cache	*p = NULL;
	krwlock_t		*cache_lock;
	avl_index_t		where;	/* used for avl_find()/avl_insert() */
	bool_t			res;

	ASSERT(cr != NULL);

	/*
	 * Now check whether this client already
	 * has an entry for this flavor in the cache
	 * for this export.
	 * Get the caller's address, mask off the
	 * parts of the address that do not identify
	 * the host (port number, etc), and then hash
	 * it to find the chain of cache entries.
	 */

	claddr = svc_getrpccaller(req->rq_xprt);
	addr = *claddr;
	if (claddr->len != 0) {
		addr.buf = kmem_alloc(addr.maxlen, KM_SLEEP);
		bcopy(claddr->buf, addr.buf, claddr->len);
	} else {
		addr.buf = NULL;
	}

	SVC_GETADDRMASK(req->rq_xprt, SVC_TATTR_ADDRMASK, (void **)&taddrmask);
	ASSERT(taddrmask != NULL);
	addrmask(&addr, taddrmask);

	acc.authc_addr = addr;
	ac.authi_type = type;
	if (type == NFSAUTH_ACCESS) {
		VERIFY3P(exi, !=, NULL);
		ASSERT3P(curzone->zone_id, ==, exi->exi_zoneid);
		cache_lock = &exi->exi_cache_lock;
		tree = exi->exi_cache[hash(&addr)];
		nag = nfsauth_get_zg();
	} else {
		VERIFY3P(exi, ==, NULL);
		nag = nfsauth_get_zg();
		cache_lock = &nag->audit_lock;
		tree = nag->audit_cache[hash(&addr)];
	}

	rw_enter(cache_lock, RW_READER);
	c = (struct auth_cache_clnt *)avl_find(tree, &acc, NULL);

	if (c == NULL) {
		struct auth_cache_clnt *nc;

		rw_exit(cache_lock);

		nc = kmem_alloc(sizeof (*nc), KM_NOSLEEP | KM_NORMALPRI);
		if (nc == NULL)
			goto retrieve;

		/*
		 * Initialize the new auth_cache_clnt
		 */
		nc->authc_addr = addr;
		nc->authc_addr.buf = kmem_alloc(addr.maxlen,
		    KM_NOSLEEP | KM_NORMALPRI);
		if (addr.maxlen != 0 && nc->authc_addr.buf == NULL) {
			kmem_free(nc, sizeof (*nc));
			goto retrieve;
		}
		bcopy(addr.buf, nc->authc_addr.buf, addr.len);
		rw_init(&nc->authc_lock, NULL, RW_DEFAULT, NULL);
		avl_create(&nc->authc_tree, nfsauth_cache_compar,
		    sizeof (struct auth_cache),
		    offsetof(struct auth_cache, auth_link));

		rw_enter(cache_lock, RW_WRITER);
		c = (struct auth_cache_clnt *)avl_find(tree, &acc, &where);
		if (c == NULL) {
			avl_insert(tree, nc, where);
			rw_downgrade(cache_lock);
			c = nc;
		} else {
			rw_downgrade(cache_lock);

			avl_destroy(&nc->authc_tree);
			rw_destroy(&nc->authc_lock);
			kmem_free(nc->authc_addr.buf, nc->authc_addr.maxlen);
			kmem_free(nc, sizeof (*nc));
		}
	}

	ASSERT(c != NULL);

	ac.auth_flavor = flavor;
	ac.auth_clnt_cred = crdup(cr);

	rw_enter(&c->authc_lock, RW_READER);
	p = (struct auth_cache *)avl_find(&c->authc_tree, &ac, NULL);

	if (p == NULL) {
		struct auth_cache *np;

		rw_exit(&c->authc_lock);

		np = kmem_cache_alloc(nfsauth_cache_handle,
		    KM_NOSLEEP | KM_NORMALPRI);
		if (np == NULL) {
			rw_exit(cache_lock);
			goto retrieve;
		}

		/*
		 * Initialize the new auth_cache
		 */
		np->auth_clnt = c;
		np->auth_flavor = flavor;
		np->auth_clnt_cred = ac.auth_clnt_cred;
		np->auth_time = np->auth_freshness = gethrestime_sec();
		np->auth_state = NFS_AUTH_NEW;
		mutex_init(&np->auth_lock, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&np->auth_cv, NULL, CV_DEFAULT, NULL);

		nfsauth_cache_init(&np->auth_info, type);

		rw_enter(&c->authc_lock, RW_WRITER);
		rw_exit(cache_lock);

		p = (struct auth_cache *)avl_find(&c->authc_tree, &ac, &where);
		if (p == NULL) {
			avl_insert(&c->authc_tree, np, where);
			rw_downgrade(&c->authc_lock);
			p = np;
		} else {
			rw_downgrade(&c->authc_lock);

			cv_destroy(&np->auth_cv);
			mutex_destroy(&np->auth_lock);
			crfree(ac.auth_clnt_cred);
			kmem_cache_free(nfsauth_cache_handle, np);
		}
	} else {
		rw_exit(cache_lock);
		crfree(ac.auth_clnt_cred);
	}

	mutex_enter(&p->auth_lock);
	rw_exit(&c->authc_lock);

	/*
	 * If the entry is in the WAITING state then some other thread is just
	 * retrieving the required info.  The entry was either NEW, or the list
	 * of client's supplemental groups is going to be changed (either by
	 * this thread, or by some other thread).  We need to wait until the
	 * nfsauth_retrieve() is done.
	 */
	while (p->auth_state == NFS_AUTH_WAITING)
		cv_wait(&p->auth_cv, &p->auth_lock);

	/*
	 * Here the entry cannot be in WAITING or INVALID state.
	 */
	ASSERT(p->auth_state != NFS_AUTH_WAITING);
	ASSERT(p->auth_state != NFS_AUTH_INVALID);

	/*
	 * If the cache entry is not valid yet, we need to retrieve the
	 * info ourselves.
	 */
	if (p->auth_state == NFS_AUTH_NEW) {
		/*
		 * NFS_AUTH_NEW is the default output auth_state value in a
		 * case we failed somewhere below.
		 */
		auth_state_t state = NFS_AUTH_NEW;

		p->auth_state = NFS_AUTH_WAITING;
		mutex_exit(&p->auth_lock);
		kmem_free(addr.buf, addr.maxlen);
		addr = p->auth_clnt->authc_addr;

		atomic_inc_uint(&nfsauth_cache_miss);

		res = nfsauth_cache_getinfo(&ac.auth_info, nag, exi,
		    svc_getnetid(req->rq_xprt), flavor, &addr, cr);

		p->auth_time = p->auth_freshness = gethrestime_sec();

		if (type == NFSAUTH_ACCESS)
			p->authi_access = authp->auth_access = ac.authi_access;

		if (res) {
			(void) nfsauth_cache_setinfo(&ac.auth_info, authp, 0);
			if (type != NFSAUTH_ACCESS || ac.authi_srv_ngids == 0 ||
			    ac.authi_srv_gids != NULL)
				if (nfsauth_cache_setinfo(&ac.auth_info,
				    &p->auth_info, KM_NOSLEEP|KM_NORMALPRI))
					state = NFS_AUTH_FRESH;
		}

		/*
		 * Set the auth_state and notify waiters.
		 */
		mutex_enter(&p->auth_lock);
		p->auth_state = state;
		cv_broadcast(&p->auth_cv);
		mutex_exit(&p->auth_lock);
	} else {
		uint_t nach;
		time_t refresh;

		res = TRUE;

		refresh = gethrestime_sec() - p->auth_freshness;

		p->auth_time = gethrestime_sec();
		(void) nfsauth_cache_setinfo(&p->auth_info, authp, KM_SLEEP);

		if ((refresh > NFSAUTH_CACHE_REFRESH) &&
		    p->auth_state == NFS_AUTH_FRESH) {
			refreshq_auth_node_t *ran;
			uint_t nacr;

			p->auth_state = NFS_AUTH_STALE;
			mutex_exit(&p->auth_lock);

			nacr = atomic_inc_uint_nv(&nfsauth_cache_refresh);
			DTRACE_PROBE3(nfsauth__debug__cache__stale,
			    struct exportinfo *, exi,
			    struct auth_cache *, p,
			    uint_t, nacr);

			ran = kmem_alloc(sizeof (refreshq_auth_node_t),
			    KM_SLEEP);
			ran->ran_auth = p;
			ran->ran_netid = strdup(svc_getnetid(req->rq_xprt));

			mutex_enter(&nag->refreshq_lock);

			if (nag->refreshq_thread_state ==
			    REFRESHQ_THREAD_NEED_CREATE) {
				/* Launch nfsauth refresh thread */
				nag->refreshq_thread_state =
				    REFRESHQ_THREAD_RUNNING;
				(void) zthread_create(NULL, 0,
				    nfsauth_refresh_thread, nag, 0,
				    minclsyspri);
			}

			/*
			 * We should not add a work queue item if the thread
			 * is not accepting them.
			 */
			if (nag->refreshq_thread_state ==
			    REFRESHQ_THREAD_RUNNING) {
				refreshq_exi_node_t *ren;

				/*
				 * Is there an existing exi_list?
				 */
				for (ren = list_head(&nag->refreshq_queue);
				    ren != NULL;
				    ren = list_next(&nag->refreshq_queue,
				    ren)) {
					if (ren->ren_exi == exi) {
						list_insert_tail(
						    &ren->ren_authlist, ran);
						break;
					}
				}

				if (ren == NULL) {
					ren = kmem_alloc(
					    sizeof (refreshq_exi_node_t),
					    KM_SLEEP);

					if (exi != NULL)
						exi_hold(exi);
					ren->ren_exi = exi;

					list_create(&ren->ren_authlist,
					    sizeof (refreshq_auth_node_t),
					    offsetof(refreshq_auth_node_t,
					    ran_node));

					list_insert_tail(&ren->ren_authlist,
					    ran);
					list_insert_tail(&nag->refreshq_queue,
					    ren);
				}

				cv_broadcast(&nag->refreshq_cv);
			} else {
				strfree(ran->ran_netid);
				kmem_free(ran, sizeof (refreshq_auth_node_t));
			}

			mutex_exit(&nag->refreshq_lock);
		} else {
			mutex_exit(&p->auth_lock);
		}

		nach = atomic_inc_uint_nv(&nfsauth_cache_hit);
		DTRACE_PROBE2(nfsauth__debug__cache__hit,
		    uint_t, nach,
		    time_t, refresh);

		kmem_free(addr.buf, addr.maxlen);
	}

	return (res);

retrieve:
	crfree(ac.auth_clnt_cred);

	/*
	 * Retrieve the required data without caching.
	 */

	ASSERT(p == NULL);

	atomic_inc_uint(&nfsauth_cache_miss);

	res = nfsauth_cache_getinfo(&ac.auth_info, nag, exi,
	    svc_getnetid(req->rq_xprt), flavor, &addr, cr);

	if (res)
		(void) nfsauth_cache_setinfo(&ac.auth_info, authp, 0);
	else if (type == NFSAUTH_ACCESS)
		authp->auth_access = ac.authi_access;

	kmem_free(addr.buf, addr.maxlen);

	return (res);
}

/*
 * Get the access information from the cache or callup to the mountd
 * to get and cache the access information in the kernel.
 */
static int
nfsauth_cache_get(struct exportinfo *exi, struct svc_req *req, int flavor,
    cred_t *cr, uid_t *uid, gid_t *gid, uint_t *ngids, gid_t **gids)
{
	nfsauth_cache_t tmpauth;
	bool_t res;
	gid_t *newgids;

	tmpauth.auth_srv_gids = NULL;
	res = nfsauth_cache_common_get(exi, req, cr, &tmpauth, flavor,
	    NFSAUTH_ACCESS);

	newgids = tmpauth.auth_srv_gids;

	if (res) {
		if (uid != NULL)
			*uid = tmpauth.auth_srv_uid;
		if (gid != NULL)
			*gid = tmpauth.auth_srv_gid;
		if (ngids != NULL)
			*ngids = tmpauth.auth_srv_ngids;
		if (gids != NULL)
			*gids = newgids;
		else if (newgids != NULL)
			kmem_free(newgids,
			    tmpauth.auth_srv_ngids * sizeof (gid_t));
	} else if (newgids != NULL) {
		kmem_free(newgids, tmpauth.auth_srv_ngids * sizeof (gid_t));
	}

	return (tmpauth.auth_access);
}

/*
 * Get the audit information from the cache or callup to the mountd
 * to get and cache the audit information in the kernel.
 */
static bool_t
nfsauth_cache_getauditinfo(struct svc_req *req,
    cred_t *cr, au_id_t *auid, au_mask_t *amask, au_asid_t *asid)
{
	nfsauth_cache_t tmpauth;
	bool_t res;

	res = nfsauth_cache_common_get(NULL, req, cr, &tmpauth, 0,
	    NFSAUTH_AUDITINFO);
	*auid = tmpauth.audit_auid;
	*amask = tmpauth.audit_amask;
	*asid = tmpauth.audit_asid;

	return (res);
}

/*
 * Check if the requesting client has access to the filesystem with
 * a given nfs flavor number which is an explicitly shared flavor.
 */
int
nfsauth4_secinfo_access(struct exportinfo *exi, struct svc_req *req,
    int flavor, int perm, cred_t *cr)
{
	int access;

	if (! (perm & M_4SEC_EXPORTED)) {
		return (NFSAUTH_DENIED);
	}

	/*
	 * Optimize if there are no lists
	 */
	if ((perm & (M_ROOT | M_NONE | M_MAP)) == 0) {
		perm &= ~M_4SEC_EXPORTED;
		if (perm == M_RO)
			return (NFSAUTH_RO);
		if (perm == M_RW)
			return (NFSAUTH_RW);
	}

	access = nfsauth_cache_get(exi, req, flavor, cr, NULL, NULL, NULL,
	    NULL);

	return (access);
}

int
nfsauth_access(struct exportinfo *exi, struct svc_req *req, cred_t *cr,
    uid_t *uid, gid_t *gid, uint_t *ngids, gid_t **gids)
{
	int access, mapaccess;
	struct secinfo *sp;
	int i, flavor, perm;
	int authnone_entry = -1;

	/*
	 * By default root is mapped to anonymous user.
	 * This might get overriden later in nfsauth_cache_get().
	 */
	if (crgetuid(cr) == 0) {
		if (uid != NULL)
			*uid = exi->exi_export.ex_anon;
		if (gid != NULL)
			*gid = exi->exi_export.ex_anon;
	} else {
		if (uid != NULL)
			*uid = crgetuid(cr);
		if (gid != NULL)
			*gid = crgetgid(cr);
	}

	if (ngids != NULL)
		*ngids = 0;
	if (gids != NULL)
		*gids = NULL;

	/*
	 *  Get the nfs flavor number from xprt.
	 */
	flavor = (int)(uintptr_t)req->rq_xprt->xp_cookie;

	/*
	 * First check the access restrictions on the filesystem.  If
	 * there are no lists associated with this flavor then there's no
	 * need to make an expensive call to the nfsauth service or to
	 * cache anything.
	 */

	sp = exi->exi_export.ex_secinfo;
	for (i = 0; i < exi->exi_export.ex_seccnt; i++) {
		if (flavor != sp[i].s_secinfo.sc_nfsnum) {
			if (sp[i].s_secinfo.sc_nfsnum == AUTH_NONE)
				authnone_entry = i;
			continue;
		}
		break;
	}

	mapaccess = 0;

	if (i >= exi->exi_export.ex_seccnt) {
		/*
		 * Flavor not found, but use AUTH_NONE if it exists
		 */
		if (authnone_entry == -1)
			return (NFSAUTH_DENIED);
		flavor = AUTH_NONE;
		mapaccess = NFSAUTH_MAPNONE;
		i = authnone_entry;
	}

	/*
	 * If the flavor is in the ex_secinfo list, but not an explicitly
	 * shared flavor by the user, it is a result of the nfsv4 server
	 * namespace setup. We will grant an RO permission similar for
	 * a pseudo node except that this node is a shared one.
	 *
	 * e.g. flavor in (flavor) indicates that it is not explictly
	 *	shared by the user:
	 *
	 *		/	(sys, krb5)
	 *		|
	 *		export  #share -o sec=sys (krb5)
	 *		|
	 *		secure  #share -o sec=krb5
	 *
	 *	In this case, when a krb5 request coming in to access
	 *	/export, RO permission is granted.
	 */
	if (!(sp[i].s_flags & M_4SEC_EXPORTED))
		return (mapaccess | NFSAUTH_RO);

	/*
	 * Optimize if there are no lists.
	 * We cannot optimize for AUTH_SYS with NGRPS (16) supplemental groups.
	 */
	perm = sp[i].s_flags;
	if ((perm & (M_ROOT | M_NONE | M_MAP)) == 0 && (ngroups_max <= NGRPS ||
	    flavor != AUTH_SYS || crgetngroups(cr) < NGRPS)) {
		perm &= ~M_4SEC_EXPORTED;
		if (perm == M_RO)
			return (mapaccess | NFSAUTH_RO);
		if (perm == M_RW)
			return (mapaccess | NFSAUTH_RW);
	}

	access = nfsauth_cache_get(exi, req, flavor, cr, uid, gid, ngids, gids);

	/*
	 * For both NFSAUTH_DENIED and NFSAUTH_WRONGSEC we do not care about
	 * the supplemental groups.
	 */
	if (access & NFSAUTH_DENIED || access & NFSAUTH_WRONGSEC) {
		if (ngids != NULL && gids != NULL) {
			kmem_free(*gids, *ngids * sizeof (gid_t));
			*ngids = 0;
			*gids = NULL;
		}
	}

	/*
	 * Client's security flavor doesn't match with "ro" or
	 * "rw" list. Try again using AUTH_NONE if present.
	 */
	if ((access & NFSAUTH_WRONGSEC) && (flavor != AUTH_NONE)) {
		/*
		 * Have we already encountered AUTH_NONE ?
		 */
		if (authnone_entry != -1) {
			mapaccess = NFSAUTH_MAPNONE;
			access = nfsauth_cache_get(exi, req, AUTH_NONE, cr,
			    NULL, NULL, NULL, NULL);
		} else {
			/*
			 * Check for AUTH_NONE presence.
			 */
			for (; i < exi->exi_export.ex_seccnt; i++) {
				if (sp[i].s_secinfo.sc_nfsnum == AUTH_NONE) {
					mapaccess = NFSAUTH_MAPNONE;
					access = nfsauth_cache_get(exi, req,
					    AUTH_NONE, cr, NULL, NULL, NULL,
					    NULL);
					break;
				}
			}
		}
	}

	if (access & NFSAUTH_DENIED)
		access = NFSAUTH_DENIED;

	return (access | mapaccess);
}

static void
nfsauth_free_clnt_node(struct auth_cache_clnt *p)
{
	void *cookie = NULL;
	struct auth_cache *node;

	while ((node = avl_destroy_nodes(&p->authc_tree, &cookie)) != NULL)
		nfsauth_free_node(node);
	avl_destroy(&p->authc_tree);

	kmem_free(p->authc_addr.buf, p->authc_addr.maxlen);
	rw_destroy(&p->authc_lock);

	kmem_free(p, sizeof (*p));
}

static void
nfsauth_free_node(struct auth_cache *p)
{
	crfree(p->auth_clnt_cred);
	if (p->authi_type == NFSAUTH_ACCESS)
		kmem_free(p->authi_srv_gids,
		    p->authi_srv_ngids * sizeof (gid_t));
	mutex_destroy(&p->auth_lock);
	cv_destroy(&p->auth_cv);
	kmem_cache_free(nfsauth_cache_handle, p);
}

/*
 * Free the nfsauth cache for a given export
 */
void
nfsauth_cache_free(avl_tree_t **cache)
{
	int i;

	/*
	 * The only way we got here was with an exi_rele, which means that no
	 * auth cache entry is being refreshed.
	 */

	for (i = 0; i < AUTH_TABLESIZE; i++) {
		avl_tree_t *tree = cache[i];
		void *cookie = NULL;
		struct auth_cache_clnt *node;

		while ((node = avl_destroy_nodes(tree, &cookie)) != NULL)
			nfsauth_free_clnt_node(node);
	}
}

/*
 * Called by the kernel memory allocator when memory is low.
 * Free unused cache entries. If that's not enough, the VM system
 * will call again for some more.
 *
 * This needs to operate on all zones, so we take a reader lock
 * on the list of zones and walk the list.  This is OK here
 * because nfsauth_cache_trim doesn't block or cause new objects
 * to be allocated (basically just frees lots of stuff).
 * Use care if nfssrv_globals_rwl is taken as reader in any
 * other cases because it will block nfs_server_zone_init
 * and nfs_server_zone_fini, which enter as writer.
 */
/*ARGSUSED*/
void
nfsauth_cache_reclaim(void *cdrarg)
{
	nfs_globals_t *ng;

	rw_enter(&nfssrv_globals_rwl, RW_READER);

	ng = list_head(&nfssrv_globals_list);
	while (ng != NULL) {
		nfsauth_cache_reclaim_zone(ng);
		ng = list_next(&nfssrv_globals_list, ng);
	}

	rw_exit(&nfssrv_globals_rwl);
}

static void
nfsauth_cache_reclaim_zone(nfs_globals_t *ng)
{
	int i;
	struct exportinfo *exi;
	nfs_export_t *ne = ng->nfs_export;

	rw_enter(&ne->exported_lock, RW_READER);

	for (i = 0; i < EXPTABLESIZE; i++) {
		for (exi = ne->exptable[i]; exi; exi = exi->fid_hash.next)
			nfsauth_cache_trim(exi->exi_cache,
			    &exi->exi_cache_lock);
	}

	rw_exit(&ne->exported_lock);

	nfsauth_cache_trim(ng->nfs_auth->audit_cache,
	    &ng->nfs_auth->audit_lock);
	atomic_inc_uint(&nfsauth_cache_reclaims);
}

static void
nfsauth_cache_trim(avl_tree_t **cache, krwlock_t *rwlock)
{
	struct auth_cache_clnt *c;
	struct auth_cache_clnt *nextc;
	struct auth_cache *p;
	struct auth_cache *next;
	int i;
	time_t stale_time;
	avl_tree_t *tree;

	for (i = 0; i < AUTH_TABLESIZE; i++) {
		tree = cache[i];
		stale_time = gethrestime_sec() - NFSAUTH_CACHE_TRIM;
		rw_enter(rwlock, RW_READER);

		/*
		 * Free entries that have not been
		 * used for NFSAUTH_CACHE_TRIM seconds.
		 */
		for (c = avl_first(tree); c != NULL; c = AVL_NEXT(tree, c)) {
			/*
			 * We are being called by the kmem subsystem to reclaim
			 * memory so don't block if we can't get the lock.
			 */
			if (rw_tryenter(&c->authc_lock, RW_WRITER) == 0) {
				exi_cache_auth_reclaim_failed++;
				rw_exit(rwlock);
				return;
			}

			for (p = avl_first(&c->authc_tree); p != NULL;
			    p = next) {
				next = AVL_NEXT(&c->authc_tree, p);

				ASSERT(p->auth_state != NFS_AUTH_INVALID);

				mutex_enter(&p->auth_lock);

				/*
				 * We won't trim recently used and/or WAITING
				 * entries.
				 */
				if (p->auth_time > stale_time ||
				    p->auth_state == NFS_AUTH_WAITING) {
					mutex_exit(&p->auth_lock);
					continue;
				}

				DTRACE_PROBE1(nfsauth__debug__trim__state,
				    auth_state_t, p->auth_state);

				/*
				 * STALE and REFRESHING entries needs to be
				 * marked INVALID only because they are
				 * referenced by some other structures or
				 * threads.  They will be freed later.
				 */
				if (p->auth_state == NFS_AUTH_STALE ||
				    p->auth_state == NFS_AUTH_REFRESHING) {
					p->auth_state = NFS_AUTH_INVALID;
					mutex_exit(&p->auth_lock);

					avl_remove(&c->authc_tree, p);
				} else {
					mutex_exit(&p->auth_lock);

					avl_remove(&c->authc_tree, p);
					nfsauth_free_node(p);
				}
			}
			rw_exit(&c->authc_lock);
		}

		if (rw_tryupgrade(rwlock) == 0) {
			rw_exit(rwlock);
			exi_cache_clnt_reclaim_failed++;
			continue;
		}

		for (c = avl_first(tree); c != NULL; c = nextc) {
			nextc = AVL_NEXT(tree, c);

			if (avl_is_empty(&c->authc_tree) == B_FALSE)
				continue;

			avl_remove(tree, c);

			nfsauth_free_clnt_node(c);
		}

		rw_exit(rwlock);
	}
}
