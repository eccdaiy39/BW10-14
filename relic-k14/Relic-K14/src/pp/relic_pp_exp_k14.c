/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2019 RELIC Authors
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
 * Implementation of the final exponentiation for pairings over prime curves.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_util.h"


void pp_exp_bwk14(fp14_t c, fp14_t a) {
 	fp14_t t0, t1, t2, t3, t4, d;
    dv14_t u;
	fp14_null(t0);
	fp14_null(t1);
	fp14_null(t2);
	fp14_null(t3);
	fp14_null(t4);
	fp14_null(d);
	dv14_null(u);
	RLC_TRY {
		fp14_new(t0);
		fp14_new(t1);
		fp14_new(t2);
		fp14_new(t3);
		fp14_new(t4);
		fp14_new(d);
		dv14_new(u);

		/*easy part: d=a^{(p^7-1)(p+1)}*/
		fp14_frb(d, a, 7);
		fp14_inv(t0, a);
		fp14_mul(d, d, t0);
		fp14_frb(t0, d, 1);
		fp14_mul(d, d, t0);
        
		/* hard part*/
		fp14_exp_dig(t1, d, 3);
		fp14_exp_cyc_x(t2, d);
		fp14_exp_cyc_x(t3, t2);
		fp14_mul(t3, t3, t2);
		fp14_mul(t3, t3, d);
		fp14_frb(t0, t3, 3);//3
		
		fp14_exp_cyc_x(t2, t3);
		fp14_exp_cyc_x(t3, t2);
		fp14_exp_cyc_x(t3, t3);
		fp14_mul(t0, t0, t3);//0
		
		fp14_exp_cyc_x(t3, t3);
		fp14_exp_cyc_x(t4, t3);
		fp14_exp_cyc_x(t4, t4);
		fp14_mul(t1, t1, t4);
		fp14_inv_cyc(t1, t1);
		fp14_frb(t4, t1, 4);
		fp14_mul(t0, t0, t4);//4
		
		fp14_exp_cyc_x(t4, t1);
		fp14_exp_cyc_x(t1, t4);
		//fp14_sqr(t2, t2);
		fp14_mul(t2, t2, t1);
		fp14_inv_cyc(t2, t2);	
		fp14_frb(t4, t2, 2);
		fp14_mul(t0, t0, t4);//2
		
		fp14_exp_cyc_x(t1, t1);
		fp14_frb(t4, t1, 1);
		fp14_mul(t0, t0, t4);//1

			
		fp14_exp_cyc_x(t1, t1);
		fp14_exp_cyc_x(t1, t1);
		fp14_mul(t2, t1, t3);	
		fp14_exp_cyc_x(t1, t1);
		fp14_inv_cyc(t1, t1);
		fp14_frb(t4, t1, 5);
		fp14_mul(t0, t0, t4);	//5
		
		fp14_frb(t4, t2, 6);//6
		fp14_muln_low(u, t0, t4);	
		fp14_rdc(c, u);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp14_free(t0);
		fp14_free(t1);
		fp14_free(t2);
		fp14_free(t3);	
		fp14_free(t4);	
		fp14_free(d);	
		dv14_free(u);		
	
	
	}

}



