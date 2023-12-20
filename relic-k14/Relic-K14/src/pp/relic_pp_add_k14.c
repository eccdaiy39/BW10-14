/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2019 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * RELIC is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of Miller doubling for curves of embedding degree 12.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/
void pp_add_k14(fp14_t l1,fp14_t l2, ep7_t r, const ep7_t q, const ep_t p1, const ep_t p2) {
	fp7_t t0, t1, t2, t3, t4;
	dv7_t u0, u1;
	int i;
	fp7_null(t0);
	fp7_null(t1);
	fp7_null(t2);
	fp7_null(t3);
	fp7_null(t4);
	dv7_null(u0);
	dv7_null(u1);

	RLC_TRY {
		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);
		fp2_new(t3);
		fp2_new(t4);
		dv2_new(u0);
		dv2_new(u1);

		fp7_sqr(t0,r->z);
		fp7_mul(t1, q->y, t0);
        fp7_mul(t1, t1, r->z);
		fp7_sub(t1, t1, r->y);
		fp7_mul(t2, t0, q->x);
		fp7_sub(t2, t2, r->x);
		fp7_sqr(t0, t2);
		fp7_mul(t3, t2, t0);
		fp7_mul(t4, r->x, t0);
		fp7_sqr(r->x, t1);
		fp7_dbl(t0, t4);
		fp7_sub(r->x, r->x, t0);
		fp7_sub(r->x, r->x, t3);

		fp7_sub(t0, t4, r->x);
		fp7_muln_low(u0, t0, t1);
		fp7_muln_low(u1, r->y, t3);
		fp7_subc_low(u0, u0, u1);
		fp7_rdc(r->y, u0);
		fp7_mul(r->z, r->z, t2);
		for(i=0;i<7;i++)fp_mul(l1[0][i], r->z[i],p1->y);
		for(i=0;i<7;i++)fp_mul(t2[i], t1[i],p1->x);
		for(i=0;i<7;i++)fp_mul(t3[i], t1[i],p2->x);
		fp7_copy(l2[0], l1[0]);
		fp7_muln_low(u0, t1, q->x);
		fp7_muln_low(u1, r->z, q->y);
		fp7_subc_low(u0, u0, u1);
		fp7_rdc(t4, u0);
		fp7_mul_art(t4, t4);
		fp7_sub(l1[1], t4, t2);
		fp7_sub(l2[1], t4, t3);

		r->coord = PROJC;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp7_free(t0);
		fp7_free(t1);
		fp7_free(t2);
		fp7_free(t3);
		fp7_free(t4);
		dv7_free(u0);
		dv7_free(u1);
	}
}


