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

void pp_exp_bwk13(fp13_t c, fp13_t l1, fp13_t l2) {
 	fp13_t t[6], h[5], f, f1, f2, f3, f4;
	bn_t x;
	bn_null(x);
	for(int i=0;i<6; i++)fp13_null(t[i]);
	for(int i=0;i<5; i++)fp13_null(h[i]);
	fp13_null(f);
	fp13_null(f1);
	fp13_null(f2);
	fp13_null(f3);
	fp13_null(f4);
	RLC_TRY {
	       	bn_new(x);
		for(int i=0; i<6; i++)fp13_new(t[i]);
		for(int i=0; i<5; i++)fp13_new(h[i]);
		fp13_new(f);
		fp13_new(f1);
		fp13_new(f2);
		fp13_new(f3);
		fp13_new(f4);

		fp_prime_get_par(x);
                bn_neg(x,x);

		/*a1 = a^(p-1)*/
		/*easy part: f = (l1^p*l2)/(l1*l2^p)*/

		fp13_frb(t[0], l1, 1);
		fp13_frb(t[1], l2, 1);
		fp13_mul(t[0], t[0], l2);
		fp13_mul(t[1], t[1], l1);
		fp13_inv(t[1], t[1]);
		fp13_mul(f, t[0], t[1]);
		
	       /*exponentiation f by 3 and exponents with low degrees: 
		s00=2x+2,  s10=2x^4+2x^3, s21=x^2, s31=4x^2+x+1*/
		
		fp13_sqr(t[1], f);
		fp13_mul(t[0], t[1], f);//t[0]=f^3
		fp13_sqr(t[1], t[1]);
		fp13_sqr(t[1], t[1]);
		fp13_sqr(t[1], t[1]);
		fp13_mul(t[1], t[1], f);
		fp13_sqr(t[1], t[1]);
		fp13_sqr(t[1], t[1]);
		fp13_mul(t[1], t[1], f);
		fp13_sqr(t[1], t[1]);
	       	fp13_mul(t[1], t[1], f);
		fp13_sqr(t[1], t[1]);
		fp13_sqr(t[1], t[1]);
		fp13_sqr(t[1], t[1]);
		fp13_sqr(t[1], t[1]);//t[1]=f^x
		for(int i =2; i<6; i++)fp13_exp(t[i], t[i-1], x);

		fp13_mul(f1, t[1], f);
		fp13_sqr(f2, f1);//f2=f^(s00)
		fp13_sqr(f3, t[2]);
		fp13_sqr(f3, f3);
		fp13_mul(f1, f3, f1);//f1=f^(s31)
		fp13_mul(f3, t[3], t[4]);//f3=f^(x^3+x^4)
		fp13_sqr(f4, f3);// f4= f^(s10)
		//t[2]=f^(s21)


		/*exponentiation f by exponents with large degrees: 
		s01=x^15+2x^14+2x^13+x^12+x^2,  
		s11=x^18+2x^17+2x^16+x^15+x^5, 
		s20=x^16+x^15+x^14+x^4+2x^3+x, 
		s30=x^16+x^15+x^14*/

		fp13_mul(h[0], t[5], f3);
		for(int i =1; i<10; i++)fp13_exp(h[0], h[0], x);
		for(int i =1; i<5; i++)fp13_exp(h[i], h[i-1], x);

		fp13_mul(h[0], h[0], h[1]);
		fp13_mul(h[0], h[0], t[2]);//h[0]=f^(s01)

		fp13_mul(h[1], h[2], f3);
		fp13_mul(h[1], h[1], t[1]);
		fp13_mul(h[1], h[1], t[3]);//h[1]=f^(s20)
	
		fp13_mul(h[4], h[4], h[3]);
		fp13_mul(h[4], h[4], t[5]);//h[4]=f^(s11)
		//h[2]=f^(s30)

		/* f1=f^(s11+s21*p+s31*p^2)*f^(s01)*/
		
		fp13_frb(t[2], t[2], 1);
		fp13_frb(f1, f1, 2);
		fp13_mul(f1, f1, t[2]);
		fp13_mul(f1, f1, h[4]);

		/* f3=1/(f^(s11+s21*p+s31*p^2)*f^(s01))*/
		fp13_mul(f3, f1, h[0]);
		fp13_inv_uni(f3, f3);

		/* f4=f^(s10+s20*p+s30*p^2)*/

		fp13_frb(h[1], h[1], 1);
		fp13_frb(h[2], h[2], 2);
		fp13_mul(f4, f4, h[1]);
		fp13_mul(f4, f4, h[2]);

		/*f2=f^(s00)/f^(s01), f4= f^(s10+s20*p+s^(30*p^2))/f^(s11+s21*p+s^(31*p^2))*/

		fp13_mul(f2, f2, f1);
		fp13_mul(f2, f2, f3);

		fp13_mul(h[0], h[0], f3);
		fp13_mul(f4, h[0], f4);

               /*the last step*/
		fp13_exp(t[1], f4, x);
		fp13_exp(t[1], t[1], x);
		fp13_exp(t[1], t[1], x);

		fp13_exp(t[2], t[1], x);
		fp13_exp(t[2], t[2], x);
		fp13_exp(t[2], t[2], x);
	
		fp13_exp(t[3], t[2], x);
		fp13_exp(t[3], t[3], x);
		fp13_exp(t[3], t[3], x);
		

		fp13_frb(t[1], t[1], 7);
		fp13_frb(t[2], t[2], 4);
		fp13_frb(t[4], f4, 10);

		fp13_mul(t[0], t[0], t[3]);	
		fp13_frb(t[0], t[0], 1);
		fp13_mul(t[0], t[0], f2);
		fp13_mul(t[0], t[0], t[1]);
		fp13_mul(t[0], t[0], t[2]);	
		fp13_mul(c, t[0], t[4]);	
			
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(x);
		for(int i=0;i<6; i++)fp13_free(t[i]);
		for(int i=0;i<5; i++)fp13_free(h[i]);
		fp13_free(f);
		fp13_free(f1);
		fp13_free(f2);
		fp13_free(f3);
		fp13_free(f4);
		
	}

}



