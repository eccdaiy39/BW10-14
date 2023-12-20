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
void fp14_muln_low(dv14_t c, const fp14_t a, const fp14_t b) {
	dv14_t t;
    fp14_t d;
	dv14_null(t);
	fp14_null(d);
	RLC_TRY {
		dv14_new(t);
		fp14_new(d);
		fp7_muln_low(t[0], a[0], b[0]);
		fp7_muln_low(t[1], a[1], b[1]);	
		fp7_addn_low(d[0], a[0], a[1]);	
		fp7_addn_low(d[1], b[0], b[1]);	
		fp7_muln_low(c[1], d[0], d[1]);
		fp7_subc_low(c[1], c[1], t[0]);
		fp7_subc_low(c[1], c[1], t[1]);	
		
		fp7_mul_nor_low(c[0], t[1]);

		#if FP_PRIME ==340 
	      	fp_subc_low(c[0][0], t[0][0], c[0][0]);	
        #elif FP_PRIME ==351 
	      	fp_addc_low(c[0][0], t[0][0], c[0][0]);	
     	 #endif

		for(int i=1; i<7;i++)fp_addc_low(c[0][i], t[0][i], c[0][i]);	
		
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv14_free(t);
		fp14_free(d);
	}
}

void fp14_mul_lazyr(fp14_t d, const fp14_t a, const fp14_t b){
     dv14_t c;
     dv14_null(c);
     dv14_new(c);
     fp14_muln_low(c,a, b);
     fp14_rdc(d,c);  
     dv14_free(c);
}
