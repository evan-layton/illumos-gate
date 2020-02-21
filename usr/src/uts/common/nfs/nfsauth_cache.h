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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2020 Nexenta by DDN, Inc. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef	_NFSAUTH_CACHE_H
#define	_NFSAUTH_CACHE_H

#include <nfs/export.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * An auth cache entry can exist in 6 states.
 *
 * A NEW entry was recently allocated and added to the cache.  It does not
 * contain the valid auth state yet.
 *
 * A WAITING entry is one which is actively engaging the user land mountd code
 * to authenticate or re-authenticate it.  The auth state might not be valid
 * yet.  The other threads should wait on auth_cv until the retrieving thread
 * finishes the retrieval and changes the auth cache entry to FRESH, or NEW (in
 * a case this entry had no valid auth state yet).
 *
 * A REFRESHING entry is one which is actively engaging the user land mountd
 * code to re-authenticate the cache entry.  There is currently no other thread
 * waiting for the results of the refresh.
 *
 * A FRESH entry is one which is valid (it is either newly retrieved or has
 * been refreshed at least once).
 *
 * A STALE entry is one which has been detected to be too old.  The transition
 * from FRESH to STALE prevents multiple threads from submitting refresh
 * requests.
 *
 * An INVALID entry is one which was either STALE or REFRESHING and was deleted
 * out of the encapsulating exi.  Since we can't delete it yet, we mark it as
 * INVALID, which lets the refresh thread know not to work on it and free it
 * instead.
 *
 * Note that the auth state of the entry is valid, even if the entry is STALE.
 * Just as you can eat stale bread, you can consume a stale cache entry. The
 * only time the contents change could be during the transition from REFRESHING
 * or WAITING to FRESH.
 *
 * Valid state transitions:
 *
 *          alloc
 *            |
 *            v
 *         +-----+
 *    +--->| NEW |------>free
 *    |    +-----+
 *    |       |
 *    |       v
 *    |  +---------+
 *    +<-| WAITING |
 *    ^  +---------+
 *    |       |
 *    |       v
 *    |       +<--------------------------+<---------------+
 *    |       |                           ^                |
 *    |       v                           |                |
 *    |   +-------+    +-------+    +------------+    +---------+
 *    +---| FRESH |--->| STALE |--->| REFRESHING |--->| WAITING |
 *        +-------+    +-------+    +------------+    +---------+
 *            |            |              |
 *            |            v              |
 *            v       +---------+         |
 *          free<-----| INVALID |<--------+
 *                    +---------+
 */
typedef enum auth_state {
	NFS_AUTH_FRESH,
	NFS_AUTH_STALE,
	NFS_AUTH_REFRESHING,
	NFS_AUTH_INVALID,
	NFS_AUTH_NEW,
	NFS_AUTH_WAITING
} auth_state_t;

/*
 * NFSAUTH_ACCESS cache entries contain identity mapping and access information
 * for a given client on a particular export. They are read/created when a
 * client accesses an export for the first time in a request.
 *
 * NFSAUTH_AUDITINFO cache entries contain audit information for a given client
 * in a zone, not attached to any particular export. They are read/created when
 * the credential is initialized at the beginning of an NFSv4 Compound.
 *
 * These are managed by different collections of auth_cache_clnt's, but
 * use the same machinery for expiration and refreshing.
 */

/*
 * An authorization cache entry
 *
 * Either the state in auth_state will protect the
 * contents or auth_lock must be held.
 */
typedef struct nfsauth_cache {
	int			auth_type;
	union {
		struct {	/* NFSAUTH_ACCESS */
			uid_t	auth_srv_uid;
			gid_t	auth_srv_gid;
			uint_t	auth_srv_ngids;
			gid_t	*auth_srv_gids;
			int	auth_access;
		};
		struct {	/* NFSAUTH_AUDITINFO */
			au_id_t		audit_auid;
			au_mask_t	audit_amask;
			au_asid_t	audit_asid;
		};
	};
} nfsauth_cache_t;

struct auth_cache {
	avl_node_t		auth_link;
	struct auth_cache_clnt	*auth_clnt;
	int			auth_flavor;
	cred_t			*auth_clnt_cred;
	time_t			auth_time;
	time_t			auth_freshness;
	auth_state_t		auth_state;
	kmutex_t		auth_lock;
	kcondvar_t		auth_cv;
	nfsauth_cache_t		auth_info;
};

#define	authi_type	auth_info.auth_type
#define	authi_access	auth_info.auth_access
#define	authi_srv_ngids	auth_info.auth_srv_ngids
#define	authi_srv_gids	auth_info.auth_srv_gids

/*
 * The lifetime of an auth cache entry:
 * ------------------------------------
 *
 * An auth cache entry is created with both the auth_time
 * and auth_freshness times set to the current time.
 *
 * Upon every client access which results in a hit, the
 * auth_time will be updated.
 *
 * If a client access determines that the auth_freshness
 * indicates that the entry is STALE, then it will be
 * refreshed. Note that this will explicitly reset
 * auth_time.
 *
 * When the REFRESH successfully occurs, then the
 * auth_freshness is updated.
 *
 * There are two ways for an entry to leave the cache:
 *
 * 1) Purged by an action on the export (remove or changed)
 * 2) Memory backpressure from the kernel (check against NFSAUTH_CACHE_TRIM)
 *
 * For 2) we check the timeout value against auth_time.
 */

/*
 * Number of seconds until we mark for refresh an auth cache entry.
 */
#define	NFSAUTH_CACHE_REFRESH 600

/*
 * Number of idle seconds until we yield to backpressure
 * to trim a cache entry.
 */
#define	NFSAUTH_CACHE_TRIM 3600

/*
 * While we could encapuslate the exi_list inside the
 * exi structure, we can't do that for the auth_list.
 * So, to keep things looking clean, we keep them both
 * in these external lists.
 */
typedef struct refreshq_exi_node {
	struct exportinfo	*ren_exi;
	list_t			ren_authlist;
	list_node_t		ren_node;
} refreshq_exi_node_t;

typedef struct refreshq_auth_node {
	struct auth_cache	*ran_auth;
	char			*ran_netid;
	list_node_t		ran_node;
} refreshq_auth_node_t;

/*
 * If there is ever a problem with loading the module, then nfsauth_fini()
 * needs to be called to remove state.  In that event, since the refreshq
 * thread has been started, they need to work together to get rid of state.
 */
typedef enum nfsauth_refreshq_thread_state {
	REFRESHQ_THREAD_RUNNING,
	REFRESHQ_THREAD_FINI_REQ,
	REFRESHQ_THREAD_HALTED,
	REFRESHQ_THREAD_NEED_CREATE
} nfsauth_refreshq_thread_state_t;

typedef struct nfsauth_globals {
	kmutex_t	mountd_lock;
	door_handle_t   mountd_dh;

	/*
	 * Used to manipulate things on the refreshq_queue.  Note that the
	 * refresh thread will effectively pop a node off of the queue,
	 * at which point it will no longer need to hold the mutex.
	 */
	kmutex_t	refreshq_lock;
	list_t		refreshq_queue;
	kcondvar_t	refreshq_cv;

	/*
	 * A list_t would be overkill.  These are auth_cache entries which are
	 * no longer linked to an exi.  It should be the case that all of their
	 * states are NFS_AUTH_INVALID, i.e., the only way to be put on this
	 * list is iff their state indicated that they had been placed on the
	 * refreshq_queue.
	 *
	 * Note that while there is no link from the exi or back to the exi,
	 * the exi can not go away until these entries are harvested.
	 */
	struct auth_cache		*refreshq_dead_entries;
	nfsauth_refreshq_thread_state_t	refreshq_thread_state;

	krwlock_t	audit_lock;
	avl_tree_t	*audit_cache[AUTH_TABLESIZE];
} nfsauth_globals_t;

#ifdef	__cplusplus
}
#endif

#endif /* _NFSAUTH_CACHE_H */
