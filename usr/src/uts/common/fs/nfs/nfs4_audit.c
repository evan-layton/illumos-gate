/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020 Nexenta by DDN, Inc. All rights reserved.
 */

#include <c2/audit.h>
#include <c2/audit_kernel.h>
#include <nfs/nfs4.h>

/*
 * NFS auditing primitives.
 */
#define	NFS_AUDIT_PATHLEN (2 * MAXPATHLEN)

volatile uint_t nfs_audit_notset = 0;

/* vnodetopath() uses the zone root when the given vp is NULL */
static vnode_t *
nfs_audit_rootvp()
{
	return (AU_AUDIT_PERZONE() ?
	    NULL : rootdir);
}

static int
nfs_audit_vnodetopath(vnode_t *vp, vnode_t *rootvp, char *buf, size_t buflen)
{
	int rc;
	cred_t *kcr = (AU_AUDIT_PERZONE()) ? zone_kcred() : kcred;

	VN_HOLD(vp);
	if (rootvp != NULL) {
		VN_HOLD(rootvp);
		rc = vnodetopath(rootvp, vp, buf, buflen, kcr);
		VN_RELE(rootvp);
	} else {
		rc = vnodetopath(NULL, vp, buf, buflen, kcr);
	}
	VN_RELE(vp);

#if DEBUG
	if (rc != 0) {
		/*
		 * We can't fallback here the way we do in SMB,
		 * so just return an error.
		 */

		cmn_err(CE_NOTE,
		    "nfs_audit_vnodetopath: vnodetopath failed! %d", rc);
	}
#endif
	return (rc);
}

/*
 * This should take an access mask & file handle
 * if we implement "first-use" auditing
 */
boolean_t
nfs_audit_init(struct svc_req *req, char **path, vnode_t *vp)
{
	t_audit_data_t *tad;
	int rc;

	*path = NULL;

	if (!AU_ZONE_AUDITING(NULL) || req->rq_vers < NFS_V4)
		return (B_FALSE);

	*path = kmem_alloc(NFS_AUDIT_PATHLEN, KM_SLEEP);
	/* We don't keep the resolved pathname around, so get it from here */
	*path[0] = '\0';
	rc = nfs_audit_vnodetopath(vp, nfs_audit_rootvp(), *path,
	    NFS_AUDIT_PATHLEN);

	if (rc != 0) {
		kmem_free(*path, NFS_AUDIT_PATHLEN);
		*path = NULL;
	} else {
		tad = T2A(curthread);
		tad->tad_sacl_ctrl = SACL_AUDIT_ON;
		tad->tad_sacl_mask.tas_smask = AU_SACL_NOTSET;
		tad->tad_sacl_mask.tas_fmask = AU_SACL_NOTSET;
	}
	return (B_TRUE);
}

void
nfs_audit_fini(cred_t *cr, uint32_t desired, vnode_t *vp,
    boolean_t success, caller_context_t *ct, char *path)
{
	t_audit_data_t *tad;

	if (!AU_ZONE_AUDITING(NULL)) {
		kmem_free(path, NFS_AUDIT_PATHLEN);
		return;
	}
	tad = T2A(curthread);

	if (AU_SACL_MASK_NOTSET(tad->tad_sacl_mask)) {
		/*
		 * ACLs were never checked; try again using VREAD to bypass
		 * edge cases where access checks aren't done
		 */
		uint_t num_notset = atomic_inc_uint_nv(&nfs_audit_notset);

		DTRACE_PROBE2(nfsaudit__mask__notset,
		    uint32_t, desired,
		    uint_t, num_notset);

		tad->tad_sacl_ctrl = SACL_AUDIT_ON;
		(void) VOP_ACCESS(vp, VREAD, 0, cr, ct);

		/* If it's STILL not set, assume it was meant to be audited. */
		if (AU_SACL_MASK_NOTSET(tad->tad_sacl_mask)) {
#if DEBUG
			cmn_err(CE_NOTE,
			    "nfs_audit_fini: tad_sacl_mask still not set? "
			    "0x%x %d",
			    desired,
			    num_notset);
#endif
			tad->tad_sacl_mask.tas_smask = 0xffffffff;
			tad->tad_sacl_mask.tas_fmask = 0xffffffff;
		}
	}

	audit_sacl(path, cr, desired, success,
	    &tad->tad_sacl_mask);
	tad->tad_sacl_ctrl = SACL_AUDIT_NONE;
	kmem_free(path, NFS_AUDIT_PATHLEN);
}

void
nfs_audit_delete_fini(cred_t *cr, uint32_t desired, vnode_t *vp,
    char *name, boolean_t success, caller_context_t *ct, char *path)
{
	t_audit_data_t *tad;
	size_t len;

	if (!AU_ZONE_AUDITING(NULL)) {
		kmem_free(path, NFS_AUDIT_PATHLEN);
		return;
	}
	tad = T2A(curthread);

	/*
	 * If desired == ACE_DELETE_CHILD, vp is a directory, and we haven't
	 * retrieved the audit mask yet.
	 */
	if (desired == ACE_DELETE_CHILD ||
	    AU_SACL_MASK_NOTSET(tad->tad_sacl_mask)) {
		/*
		 * ACLs were never checked; try again using VREAD to bypass
		 * edge cases where access checks aren't done
		 */
		uint_t num_notset = atomic_inc_uint_nv(&nfs_audit_notset);

		DTRACE_PROBE2(nfsaudit__mask__notset_delete,
		    uint32_t, desired,
		    uint_t, num_notset);

		tad->tad_sacl_ctrl = SACL_AUDIT_ON;
		tad->tad_sacl_mask.tas_smask = AU_SACL_NOTSET;
		tad->tad_sacl_mask.tas_fmask = AU_SACL_NOTSET;
		(void) VOP_ACCESS(vp, VREAD, 0, cr, ct);

		/* If it's STILL not set, assume it was meant to be audited. */
		if (AU_SACL_MASK_NOTSET(tad->tad_sacl_mask)) {
#if DEBUG
			cmn_err(CE_NOTE,
			    "nfs_audit_delete_fini: "
			    "tad_sacl_mask still not set? 0x%x %d",
			    desired,
			    num_notset);
#endif
			tad->tad_sacl_mask.tas_smask = 0xffffffff;
			tad->tad_sacl_mask.tas_fmask = 0xffffffff;
		}
	}

	/*
	 * Symlinks don't have their own ACEs, but we'd still like to be able to
	 * audit their removal; use the directory's DELETE_CHILD audit entry as
	 * a stand-in.
	 */
	if (desired == ACE_DELETE_CHILD) {
		if ((tad->tad_sacl_mask.tas_smask & ACE_DELETE_CHILD) != 0)
			tad->tad_sacl_mask.tas_smask |= ACE_DELETE;
		if ((tad->tad_sacl_mask.tas_fmask & ACE_DELETE_CHILD) != 0)
			tad->tad_sacl_mask.tas_fmask |= ACE_DELETE;
		desired = ACE_DELETE;
	}

	len = strlen(path);
	if ((len + 2) < NFS_AUDIT_PATHLEN && path[len - 1] != '/') {
		path[len] = '/';
		path[len + 1] = '\0';
	}
	if (strlcat(path, name, NFS_AUDIT_PATHLEN) >= NFS_AUDIT_PATHLEN) {
		cmn_err(CE_WARN,
		    "nfs_audit_delete_fini: path truncated: path: %s name: %s",
		    path, name);
		path[0] = '*';
	}
	audit_sacl(path, cr, desired, success,
	    &tad->tad_sacl_mask);
	tad->tad_sacl_ctrl = SACL_AUDIT_NONE;
	kmem_free(path, NFS_AUDIT_PATHLEN);
}

boolean_t
nfs_audit_rename_init(struct svc_req *req, char **src, vnode_t *vp, char **dst,
    vnode_t *tvp, char **dpath, vnode_t *dvp)
{
	t_audit_data_t *tad;
	int rc;

	if (!AU_ZONE_AUDITING(NULL) || req->rq_vers < NFS_V4)
		return (B_FALSE);

	*src = NULL;
	*dst = NULL;
	*dpath = NULL;

	*src = kmem_alloc(NFS_AUDIT_PATHLEN, KM_SLEEP);
	*src[0] = '\0';
	rc = nfs_audit_vnodetopath(vp, nfs_audit_rootvp(), *src,
	    NFS_AUDIT_PATHLEN);

	if (rc == 0) {
		*dpath = kmem_alloc(NFS_AUDIT_PATHLEN, KM_SLEEP);
		*dpath[0] = '\0';
		rc = nfs_audit_vnodetopath(dvp, nfs_audit_rootvp(), *dpath,
		    NFS_AUDIT_PATHLEN);
	}

	if (rc == 0 && tvp != NULL) {
		*dst = kmem_alloc(NFS_AUDIT_PATHLEN, KM_SLEEP);
		*dst[0] = '\0';
		rc = nfs_audit_vnodetopath(tvp, nfs_audit_rootvp(), *dst,
		    NFS_AUDIT_PATHLEN);
	}

	if (rc != 0) {
		kmem_free(*src, NFS_AUDIT_PATHLEN);
		*src = NULL;
		if (*dpath != NULL)
			kmem_free(*dpath, NFS_AUDIT_PATHLEN);
		if (*dst != NULL)
			kmem_free(*dst, NFS_AUDIT_PATHLEN);
	} else {
		tad = T2A(curthread);
		tad->tad_sacl_ctrl = SACL_AUDIT_ALL;
		tad->tad_sacl_mask.tas_smask = AU_SACL_NOTSET;
		tad->tad_sacl_mask.tas_fmask = AU_SACL_NOTSET;
		tad->tad_sacl_mask_src.tas_smask = AU_SACL_NOTSET;
		tad->tad_sacl_mask_src.tas_fmask = AU_SACL_NOTSET;
		tad->tad_sacl_mask_dest.tas_smask = AU_SACL_NOTSET;
		tad->tad_sacl_mask_dest.tas_fmask = AU_SACL_NOTSET;
	}
	return (B_TRUE);
}

void
nfs_audit_rename_fini(cred_t *cr, char *src, char *dest, char *dpath,
    boolean_t success, boolean_t isdir)
{
	t_audit_data_t *tad;
	boolean_t notset = B_FALSE;
	uint_t num_notset;
	uint32_t desired = 0;

	if (!AU_ZONE_AUDITING(NULL)) {
		if (src != NULL)
			kmem_free(src, NFS_AUDIT_PATHLEN);
		if (dest != NULL)
			kmem_free(dest, NFS_AUDIT_PATHLEN);
		if (dpath != NULL)
			kmem_free(dpath, NFS_AUDIT_PATHLEN);
		return;
	}

	tad = T2A(curthread);

	/*
	 * We don't really have a good way to 'recheck' here,
	 * so just assume they're meant to be audited.
	 */
	if (dpath != NULL && AU_SACL_MASK_NOTSET(tad->tad_sacl_mask)) {
		tad->tad_sacl_mask.tas_smask = 0xffffffff;
		tad->tad_sacl_mask.tas_fmask = 0xffffffff;
#if DEBUG
		cmn_err(CE_NOTE,
		    "nfs_audit_rename_fini: tad_sacl_mask not set? %d",
		    num_notset);
#endif
		num_notset = atomic_inc_uint_nv(&nfs_audit_notset);
		desired |= isdir ? ACE_ADD_SUBDIRECTORY : ACE_ADD_FILE;
	}
	if (src != NULL && AU_SACL_MASK_NOTSET(tad->tad_sacl_mask_src)) {
		tad->tad_sacl_mask_src.tas_smask = 0xffffffff;
		tad->tad_sacl_mask_src.tas_fmask = 0xffffffff;
#if DEBUG
		cmn_err(CE_NOTE,
		    "nfs_audit_rename_fini: tad_sacl_mask_src not set? %d",
		    num_notset);
#endif
		num_notset = atomic_inc_uint_nv(&nfs_audit_notset);
		desired |= ACE_DELETE;
	}
	if (dest != NULL && AU_SACL_MASK_NOTSET(tad->tad_sacl_mask_dest)) {
		tad->tad_sacl_mask_dest.tas_smask = 0xffffffff;
		tad->tad_sacl_mask_dest.tas_fmask = 0xffffffff;
#if DEBUG
		cmn_err(CE_NOTE,
		    "nfs_audit_rename_fini: tad_sacl_mask_dest not set? %d",
		    num_notset);
#endif
		num_notset = atomic_inc_uint_nv(&nfs_audit_notset);
		desired |= ACE_DELETE;
	}

	if (notset)
		DTRACE_PROBE2(nfsaudit__mask__notset_rename,
		    uint32_t, desired,
		    uint_t, num_notset);

	if (src != NULL) {
		audit_sacl(src, cr, ACE_DELETE, success,
		    &tad->tad_sacl_mask_src);
		kmem_free(src, NFS_AUDIT_PATHLEN);
	}
	if (dest != NULL) {
		audit_sacl(dest, cr, ACE_DELETE, success,
		    &tad->tad_sacl_mask_dest);
		kmem_free(dest, NFS_AUDIT_PATHLEN);
	}

	audit_sacl(dpath, cr,
	    isdir ? ACE_ADD_SUBDIRECTORY : ACE_ADD_FILE,
	    success, &tad->tad_sacl_mask);
	tad->tad_sacl_ctrl = SACL_AUDIT_NONE;
	kmem_free(dpath, NFS_AUDIT_PATHLEN);
}

void
nfs_audit_save()
{
	t_audit_data_t *tad;
	if (AU_ZONE_AUDITING(NULL)) {
		tad = T2A(curthread);
		tad->tad_sacl_backup = tad->tad_sacl_ctrl;
		tad->tad_sacl_ctrl = SACL_AUDIT_BACKUP;
	}
}

void
nfs_audit_load()
{
	t_audit_data_t *tad = T2A(curthread);
	if (AU_ZONE_AUDITING(NULL) && tad->tad_sacl_backup != SACL_AUDIT_NONE) {
		tad->tad_sacl_ctrl = tad->tad_sacl_backup;
		tad->tad_sacl_backup = SACL_AUDIT_NONE;
	}
}

void
nfs_audit_freepath(char *path)
{
	kmem_free(path, NFS_AUDIT_PATHLEN);
}
