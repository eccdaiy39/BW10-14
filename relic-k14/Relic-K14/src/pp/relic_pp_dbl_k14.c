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
void pp_dbl_k14(fp14_t l1, fp14_t l2, ep7_t r, const ep_t p1,const ep_t p2) {
	fp7_t t0, t1, t2, t3, t4, t5, t6;
	dv7_t u0, u1;
	int i;

	fp7_null(t0);
	fp7_null(t1);
	fp7_null(t2);
	fp7_null(t3);
	fp7_null(t4);
	fp7_null(t5);
	fp7_null(t6);
	dv7_null(u0);
	dv7_null(u1);

	RLC_TRY {
		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);
		fp2_new(t3);
		fp2_new(t4);
		fp2_new(t5);
		fp2_new(t6);
		dv2_new(u0);
		dv2_new(u1);

		fp7_sqr(t0,r->x);
		fp7_dbl(t1, t0);
		fp7_addn_low(t0, t0, t1);
		fp7_mul(t1, t0, r->x);
		fp7_hlv(t2,t1);
		fp7_hlv(t3,t2);
		fp7_addn_low(t3, t2, t3);
		fp7_sqr(t4, r->y);
		fp7_dbl(t5, t4);
		fp7_sub(t6, t5, t2);
		fp7_muln_low(u0, t3, t6);
		fp7_sqrn_low(u1, t4);
		fp7_sqr(t2, r->z);
		fp7_mul(r->z, r->z, r->y);
		fp7_subc_low(u0, u0, u1);
		fp7_rdc(r->y, u0);
		fp7_sub(t6, t3, t5);
		fp7_mul(r->x, r->x, t6);
		fp_dbln_low(t6[0], p1->y);
		for(int i=0; i<7; i++)fp_mul(t3[i], r->z[i], t6[0]);
		fp7_mul(l1[0], t3, t2);
		fp7_copy(l2[0], l1[0]);
		fp7_sub(t4, t1, t5);
		fp7_mul(t5, t0, t2);
		for(i=0; i<7; i++)fp_mul(t0[i], t5[i], p1->x);
		for(i=0; i<7; i++)fp_mul(t1[i], t5[i], p2->x);
        fp7_mul_art(t4, t4);
		fp7_sub(l1[1], t4, t0);   
		fp7_sub(l2[1], t4, t1);   	
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
		fp7_free(t5);
		fp7_free(t6);
		dv7_free(u0);
		dv7_free(u1);
	}
}


void pp_dbl_k14_first(fp14_t l1, fp14_t l2, ep7_t r, const ep_t p1,const ep_t p2) {
	fp7_t t0, t1, t2, t3, t4, t5, t6;
	dv7_t u0, u1;
	int i;

	fp7_null(t0);
	fp7_null(t1);
	fp7_null(t2);
	fp7_null(t3);
	fp7_null(t4);
	fp7_null(t5);
	fp7_null(t6);
	dv7_null(u0);
	dv7_null(u1);

	RLC_TRY {
		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);
		fp2_new(t3);
		fp2_new(t4);
		fp2_new(t5);
		fp2_new(t6);
		dv2_new(u0);
		dv2_new(u1);

		fp7_sqr(t0,r->x);
		fp7_dbl(t1, t0);
		//fp7_addn_low(t0, t0, t1);
		fp7_add(t0, t0, t1);
		fp7_mul(t1, t0, r->x);
		fp7_hlv(t2,t1);
		fp7_hlv(t3,t2);
		fp7_add(t3, t2, t3);
		//fp7_addn_low(t3, t2, t3);
		fp7_sqr(t4, r->y);
		fp7_dbl(t5, t4);
		fp7_sub(t6, t5, t2);
		fp7_muln_low(u0, t3, t6);
		fp7_sqrn_low(u1, t4);

		
		fp7_copy(r->z, r->y);
		fp7_subc_low(u0, u0, u1);
		fp7_rdc(r->y, u0);
		fp7_sub(t6, t3, t5);
		fp7_mul(r->x, r->x, t6);
		//fp_dbln_low(t6[0], p1->y);
		fp_dbl(t6[0], p1->y);
		for(int i=0; i<7; i++)fp_mul(l1[0][i], r->z[i], t6[0]);
		fp7_copy(l2[0], l1[0]);
		fp7_sub(t4, t1, t5);
		for(i=0; i<7; i++)fp_mul(t1[i], t0[i], p2->x);
		for(i=0; i<7; i++)fp_mul(t0[i], t0[i], p1->x);
        	fp7_mul_art(t4, t4);
		fp7_sub(l1[1], t4, t0);   
		fp7_sub(l2[1], t4, t1);   	
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
		fp7_free(t5);
		fp7_free(t6);
		dv7_free(u0);
		dv7_free(u1);
	}
}


void pp_dbl_k14_last(fp14_t l1, fp14_t l2, ep7_t r, const ep_t p1,const ep_t p2) {
	fp7_t t0, t1, t2, t3;
	int i;

	fp7_null(t0);
	fp7_null(t1);
	fp7_null(t2);
	fp7_null(t3);
	RLC_TRY {
		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);
		fp2_new(t3);

		fp7_sqr(t0,r->x);
		fp7_dbl(t1, t0);
		fp7_add(t0, t0, t1);
		//fp7_addn_low(t0, t0, t1);

		fp7_mul(t1, t0, r->x);
		fp7_sqr(t2, r->y);
		fp7_dbl(t2, t2);
		fp7_sub(t1, t1, t2);//3x^3-2y^2
		fp7_mul_art(t1, t1);
		fp7_sqr(t2, r->z);
		fp7_mul(t0, t0, t2);//3x^2z^2
		fp7_mul(t3, r->y, r->z);//z3
		fp7_mul(t3, t2, t3);//z^2z3
		//fp_dbln_low(t2[0], p1->y);
		fp_dbl(t2[0], p1->y);
		for(int i=0; i<7; i++)fp_mul(l1[0][i], t3[i], t2[0]);
		fp7_copy(l2[0], l1[0]);

		for(i=0; i<7; i++)fp_mul(l1[1][i], t0[i] , p1->x);
		for(i=0; i<7; i++)fp_mul(l2[1][i], t0[i], p2->x);
		fp7_sub(l1[1], t1, l1[1]);   
		fp7_sub(l2[1], t1, l2[1]);   	
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
	}
}


