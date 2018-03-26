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
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _IDMAP_H
#define	_IDMAP_H

#include <sys/mdb_modapi.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern int nfs4_idmap_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int nfs4_idmap_info_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void nfs4_idmap_info_help(void);

extern int nfs4_idmap_walk_init(mdb_walk_state_t *);
extern void nfs4_idmap_walk_fini(mdb_walk_state_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _IDMAP_H_ */
