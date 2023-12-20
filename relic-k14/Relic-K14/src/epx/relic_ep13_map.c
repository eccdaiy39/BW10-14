#include <stdio.h>
#include "relic.h"
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
 * Implementation of hashing to a prime elliptic curve over a 13-th
 * extension.
 *
 * @ingroup epx
 */
/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/
static void ep13_sw_bw(ep13_t p, const fp_t t) {
	fp_t r[3], j, srm3;
        fp13_t t0, x[3], y[3],  w;
	int i, a[3];
       
	
  
     RLC_TRY {
 		 /*compute j and w*/
		fp_null(j);
		fp_new(j);
		fp_null(srm3);
		fp_new(srm3);
		fp13_null(t0);
		fp13_new(t0);
		fp13_null(w);
		fp13_new(w);
	         for(i=0; i<3; i++){
			fp_null(r[i]);
			fp_new(r[i]);
			fp13_null(x[i]);
			fp13_new(x[i]);
			fp13_null(y[i]);
			fp13_new(y[i]);
			
		}
		 fp_copy(srm3, core_get()->sr3);
         	fp_sub_dig(j, srm3, 1);
         	fp_hlv(j, j);//j

		 fp13_zero(t0);
		 fp_copy(t0[1], t);
         	 fp13_sqr(y[0], t0);
         	 fp_add(y[0][0], y[0][0], ep_curve_get_b());
         	 fp_add_dig(y[0][0], y[0][0], 1);
		 fp13_inv(y[0], y[0]);
		 fp13_mul(y[0], y[0], t0);
        	 for(i=0; i<13; i++)fp_mul(w[i], y[0][i], srm3);//w

		/*compute x[0], x[1] and x[2]*/
		 fp13_mul(x[0], t0, w);
		 fp13_neg(x[0], x[0]);
		 fp_add(x[0][0], x[0][0], j);

		 fp13_neg(x[1], x[0]);
		 fp_sub_dig(x[1][0], x[1][0], 1);

		 fp13_sqr(x[2], w);
		 fp13_inv(x[2], x[2]);
		 fp_add_dig(x[2][0], x[2][0], 1);


		for(i = 0; i < 3; i++){
			fp_rand(r[i]);
			fp_sqr(r[i], r[i]);
			fp13_sqr(y[i], x[i]);
			fp13_mul(y[i], y[i],  x[i]);
			fp_add(y[i][0], y[i][0], ep_curve_get_b());

		}
        	 for(i=0; i<13; i++)fp_mul(y[0][i], y[0][i], r[0]);
        	 for(i=0; i<13; i++)fp_mul(y[1][i], y[1][i], r[1]);
		a[0]=fp13_is_square(y[0]);
		a[1]=fp13_is_square(y[1]);
		a[2]=(a[0]-1)*a[1];
		if(a[2] < 0)a[2] = a[2] + 3;
		a[2]= a[2] % 3;
		fp13_copy(p->x, x[a[2]]);
		fp13_sqr(p->y, p->x);
		fp13_mul(p->y, p->y, p->x);
         	fp_add(p->y[0], p->y[0], ep_curve_get_b());
		fp13_srt(p->y, p->y);
	        fp_mul(r[2], r[2], t);
		if(!fp_srt(r[2], r[2]))fp13_neg(p->y, p->y);
		fp13_zero(p->z);
          	fp_set_dig(p->z[0], 1);
		
		
     }
     RLC_CATCH_ANY {
         RLC_THROW(ERR_CAUGHT);
     }
     RLC_FINALLY {

		fp_free(j);
		fp_free(srm3);
		fp13_free(t0);
		fp13_free(w);
	         for(i=0; i<3; i++){
			fp_free(r[i]);
			fp13_free(x[i]);
			fp13_free(y[i]);
		 }

     }
 }
  
/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/
 void ep13_map(ep13_t p, const uint8_t *msg, int len) {
     bn_t k, pm1o2;
     fp_t t;
     uint8_t digest[RLC_MD_LEN];
     bn_null(k);
     bn_null(pm1o2);
     fp_null(t);
  
     RLC_TRY {
         bn_new(k);
         bn_new(pm1o2);
         fp_new(t);
         pm1o2->sign = RLC_POS;
         pm1o2->used = RLC_FP_DIGS;
         dv_copy(pm1o2->dp, fp_prime_get(), RLC_FP_DIGS);
         bn_hlv(pm1o2, pm1o2);
         md_map(digest, msg, len);
         bn_read_bin(k, digest, RLC_MIN(RLC_FP_BYTES, RLC_MD_LEN));
         fp_prime_conv(t, k);
         ep13_sw_bw(p, t);
         ep13_cof(p, p);
     }
     RLC_CATCH_ANY {
         RLC_THROW(ERR_CAUGHT);
     }
     RLC_FINALLY {
         bn_free(k);
         bn_free(pm1o2);
         fp_free(t);
     }
 }
