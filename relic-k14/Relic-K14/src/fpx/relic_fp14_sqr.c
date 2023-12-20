/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
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
 * Implementation of multiplication in a dodecic extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"


/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/
// void fp14_sqrn_low(dv14_t c, const fp14_t a) {
// 	dv14_t t;
//         fp7_t d;
// 	dv14_null(t);
// 	fp7_null(d);
// 	RLC_TRY {
// 		dv14_new(t);
// 		fp7_new(d);
// 		fp7_sqrn_low(t[0], a[0]);
// 		fp7_sqrn_low(t[1], a[1]);	
		
// 		fp7_addn_low(d, a[0], a[1]);	
// 		fp7_sqrn_low(c[1], d);
// 		fp7_subc_low(c[1], c[1], t[0]);
// 		fp7_subc_low(c[1], c[1], t[1]);	
// 		fp7_mul_nor_low(c[0], t[1]);
// 		fp_subc_low(c[0][0], t[0][0], c[0][0]);	
// 		for(int i=1; i<7;i++)fp_addd_low(c[0][i], t[0][i], c[0][i]);	
		
// 	} RLC_CATCH_ANY {
// 		RLC_THROW(ERR_CAUGHT);
// 	} RLC_FINALLY {
// 		dv14_free(t);
// 		fp7_free(d);
// 	}
// }



void fp14_sqr_basic(fp14_t c, const fp14_t a) {
	fp7_t t0, t1;

	fp7_null(t0);
	fp7_null(t1);

	RLC_TRY {
		fp7_new(t0);
		fp7_new(t1);

		fp7_add(t0, a[0], a[1]);
		fp7_mul_art(t1, a[1]);
		fp7_add(t1, a[0], t1);
		fp7_mul(t0, t0, t1);
		fp7_mul(c[1], a[0], a[1]);
		fp7_sub(c[0], t0, c[1]);
		fp7_mul_art(t1, c[1]);
		fp7_sub(c[0], c[0], t1);
		fp7_dbl(c[1], c[1]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp7_free(t0);
		fp7_free(t1);
	}
}

void fp14_sqrn_low(dv14_t c, const fp14_t a) {
	fp7_t t0, t1;
    dv_t u;
	fp7_null(t0);
	fp7_null(t1);
	dv7_null(u);

	RLC_TRY {
		fp7_new(t0);
		fp7_new(t1);
		dv7_new(u);

		fp7_addn_low(t0, a[0], a[1]);
		fp7_mul_art(t1, a[1]);
		fp7_addn_low(t1, a[0], t1);
		fp7_muln_low(c[0], t0, t1);
		fp7_muln_low(c[1], a[0], a[1]);
		fp7_subc_low(c[0], t0, c[1]);
		fp7_mul_nor_low(u, c[1]);
		fp7_subc_low(c[0], c[0], t1);
		fp7_addd_low(c[1], c[1],  c[1]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp7_free(t0);
		fp7_free(t1);
		dv7_free(u);
	}
}

// void fp14_sqr_lazyr(fp14_t c, const fp14_t a){
//      dv14_t u;
//      dv14_null(u);
//      dv14_new(u);
//      fp14_sqrn_low(u,a);
//      fp14_rdc(d,u;  
//      dv14_free(u);
// }

void fp14_sqr_lazyr(fp14_t c, const fp14_t a){
	fp7_t t0, t1;

	fp7_null(t0);
	fp7_null(t1);

	RLC_TRY {
		fp7_new(t0);
		fp7_new(t1);

		fp7_addn_low(t0, a[0], a[1]);
		fp7_mul_art(t1, a[1]);
		fp7_addn_low(t1, a[0], t1);
		fp7_mul(t0, t0, t1);
		fp7_mul(c[1], a[0], a[1]);
		fp7_sub(c[0], t0, c[1]);
		fp7_mul_art(t1, c[1]);
		fp7_sub(c[0], c[0], t1);
		fp7_dbl(c[1], c[1]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp7_free(t0);
		fp7_free(t1);
	}
}

void fp14_sqr_cyc(fp14_t c, const fp14_t a){
		fp7_mul(c[1], a[0], a[1]);
		fp7_dbl(c[1],c[1]);
		fp7_sqr(c[0], a[0]);
		fp7_dbl(c[0], c[0]);
		fp_sub_dig(c[0], c[0], 1);
}