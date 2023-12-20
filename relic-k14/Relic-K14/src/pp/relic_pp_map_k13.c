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
 * Implementation of the pairings over prime curves.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_util.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Compute the modified Miller loop  for super-optimal ate pairings of type G_2 x G_1 with k=13.
 *
 * @param[out] t			- the resulting point.
 * @param[in] q				- the vector of first arguments in affine coordinates.
 * @param[in] p				- the vector of second arguments in affine coordinates.
 * @param[in] p2			- the image of p under the glv endomorphism.
 * @param[in] a				- the loop parameter.
 * @param[out] l1			- numerator of f_{a,q}(p).
 * @param[out] l2			- denominator of f_{a,q}(p).
 * @param[out] s1			- numerator of f_{a,q}(p2).
 * @param[out] s2			- denominator of f_{a,q}(p2).
 */
static void pp_mil_k13_sim(fp13_t l1,  fp13_t l2, fp13_t l3, fp13_t l4, ep13_t *t, ep13_t *q, ep_t *p, ep_t *p2, int m,  bn_t a) {
	fp13_t f1, f2, f3, f4;
	int j;
	fp13_null(f1);
	fp13_null(f2);
	fp13_null(f3);
	fp13_null(f4);
	RLC_TRY {
		fp13_new(f1);
		fp13_new(f2);
		fp13_new(f3);
		fp13_new(f4);	
		for (j= 0; j < m; j++)ep13_copy(t[j], q[j]);

         /*initializing l1, l2, l3 and l4*/
	    fp13_neg(l1, q[0]->x);
	    fp13_neg(l3, q[0]->x);
	    fp_add(l1[0], l1[0], p[0]->x);

	    fp_add(l3[0],l3[0], p2[0]->x);
		if(m>1){
			for (j = 1;  j < m;  j++) {
				fp13_neg(f1, q[j]->x);
	    		fp13_neg(f3, q[j]->x);
				fp_add(f1[0], f1[0], p[j]->x);
	   			fp_add(f3[0], f3[0], p2[j]->x);
				fp13_mul(l1,  l1,  f1);
				fp13_mul(l3,  l3,  f3);
			}
		}
		fp13_set_dig(l2,  1);
		fp13_set_dig(l4,  1);

		/*the fist qpl*/
		fp13_sqr(l1, l1);
		fp13_sqr(l1, l1);
		fp13_sqr(l3,  l3);
		fp13_sqr(l3,  l3);
       	for(j=0; j<m; j++){
			pp_qpl_k13_projc_lazyr(f1, f2, f3, f4, t[j],  p[j],  p2[j]);
				fp13_mul(l1, l1, f1);
				fp13_mul(l2, l2, f2);
				fp13_mul(l3, l3, f3);
				fp13_mul(l4, l4, f4);
	   }
	    
		fp13_sqr(l2, l2);
		fp13_sqr(l4, l4);
	
	 /*the main miller loop*/
		for (int i = bn_bits(a) - 4; i >= 0;) {
			if (bn_get_bit(a, i)) {
					fp13_sqr(l1, l1);
					fp13_sqr(l2, l2);
					fp13_sqr(l3, l3);
					fp13_sqr(l4, l4);
      			    for(j=0; j<m; j++){
					    pp_dba_k13_projc_lazyr(f1, f2, f3, f4, t[j], q[j], p[j], p2[j]);
						fp13_mul(l1, l1, f1);
						fp13_mul(l2, l2, f2);
						fp13_mul(l3, l3, f3);
						fp13_mul(l4, l4, f4);
	   			}
					i--;
			}
			else{
				fp13_sqr(l1, l1);
				fp13_sqr(l1, l1);
				fp13_sqr(l2, l2);
				fp13_sqr(l3,  l3);
				fp13_sqr(l3,  l3);
				fp13_sqr(l4, l4);
       			for(j=0; j<m; j++){
					pp_qpl_k13_projc_lazyr(f1, f2, f3, f4, t[j],  p[j],  p2[j]);
					fp13_mul(l1, l1, f1);
					fp13_mul(l2, l2, f2);
					fp13_mul(l3, l3, f3);
					fp13_mul(l4, l4, f4);
	   			}
	    		fp13_sqr(l2, l2);
				fp13_sqr(l4, l4);
				i--;
				if (bn_get_bit(a, i)) {
				  for(j=0; j<m; j++){
				        pp_add_k13_projc_lazyr(f1, f2, f3, f4, t[j], q[j], p[j], p2[j]);
						fp13_mul(l1, l1, f1);
						fp13_mul(l2, l2, f2);
						fp13_mul(l3, l3, f3);
						fp13_mul(l4, l4, f4);
	   				}
				}
				i--;			
			}
		}

	}
	 
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp13_free(f1);
		fp13_free(f2);
		fp13_free(f3);
		fp13_free(f4);		
	}

}
/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/
void pp_map_sup_oatep_k13(fp13_t r, ep_t p, ep13_t q) {

	ep_t _p[1], p2[1];
	ep13_t t[1], _q[1];
	bn_t a;
	fp13_t l1,l2, l3, l4, f1,f2,f3,f4;

	ep_null(_p[0]);
	ep_null(p2[0]);
	ep13_null(_q[0]);
	ep13_null(t[0]);
	bn_null(a);
    fp13_null(l1);
    fp13_null(l2);
	fp13_null(l3);
	fp13_null(l4);
	fp13_null(f1);
    fp13_null(f2);
	fp13_null(f3);
	fp13_null(f4);

	RLC_TRY {
		ep_new(_p[0]);
		ep_new(p2[0]);
		ep13_new(_q[0]);
		ep13_new(t[0]);
		bn_new(a);
    	fp13_new(l1);
    	fp13_new(l2);
		fp13_new(l3);
		fp13_new(l4);
		fp13_new(f1);
    	fp13_new(f2);
		fp13_new(f3);
		fp13_new(f4);

		fp_prime_get_par(a);
		fp13_set_dig(r, 1);
		dig_t* w;
		w = ep_curve_get_beta();
       	ep_copy(p2[0], p);
		ep_copy(_p[0], p);

		ep13_copy(t[0], q);
		ep13_copy(_q[0], q);

		fp_mul(p2[0]->x, _p[0]->x, w);

		if (!ep_is_infty(_p[0]) && !ep13_is_infty(_q[0])) {
			bn_neg(a, a);
			pp_mil_k13_sim(l1, l2, l3, l4,  t, _q,_p, p2,1, a);

			/* computing L_1  and  L_2}, 
	    	where L_1=l1 and L_2=l4 */

    		//l2=l2*(x_p-x_q)^p
 			fp_sqr(f1[0], ep_curve_get_beta());
			for(int i = 0; i<13; i++)fp_mul(f2[i], _q[0]->x[i], f1[0]);
			fp13_neg(f2, f2);
			fp13_copy(f4, f2);
			fp_add(f2[0], _p[0]->x, f2[0]);
			fp13_frb(f2, f2, 1);
			fp13_mul(l2,l2, f2);

    		//l4=l4*(x_{p2}-w*x_q)^p
    		// l4=l4^p	
			fp_add(f4[0], p2[0]->x, f4[0]);
			fp13_frb(f4, f4, 1);
			fp13_mul(l4, l4, f4);   
			fp13_frb(l4, l4, 1);

  			//l3=l3^p*(y_p-y_q)^(p^2)
 			fp13_frb(l3, l3, 1);
			fp13_neg(f3,   _q[0]->y);
			fp_add(f3[0],  f3[0],  _p[0]->y);
			fp13_frb(f3, f3, 2);
			fp13_mul(l3,  l3,  f3);

			//the final step for computing L_1 

			fp13_inv(l2, l2);
			fp13_mul(l1, l1, l2);
			fp13_frb(l2, l1, 1);
			fp13_exp(l1, l1, a);
			fp13_mul(l1, l1, l2);
			fp13_mul(l1, l1, l3);

			/*the final exponentiation*/
			pp_exp_bwk13(r, l1, l4);
		}
	}


	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(_p[0]);
		ep_free(p2[0]);
		ep13_free(_q[0]);
		ep13_free(t[0]);
		bn_free(a);
    	fp13_free(l1);
    	fp13_free(l2);
		fp13_free(l3);
		fp13_free(l4);
		fp13_free(f1);
    	fp13_free(f2);
		fp13_free(f3);
		fp13_free(f4);
	}
}

void pp_map_sim_sup_oatep_k13(fp13_t r,  ep_t *p,   ep13_t *q, int m) {
	ep_t *p2= RLC_ALLOCA(ep_t, m);
	ep13_t *t= RLC_ALLOCA(ep13_t, m);
	bn_t a;
	int i, j;
	dig_t* w;
	fp13_t  l1, l2, l3, l4, f1, f2, f3, f4;
	w = ep_curve_get_beta();
	RLC_TRY {
		bn_null(a);
		bn_new(a);
		for (j= 0; j < m; j++) {
			ep_null(p2[j]);
			ep13_null(t[j]);
			ep_new(p2[j]);
			ep13_new(t[j]);
		}
		for (j= 0; j < m; j++) {
			ep_norm(p2[j], p[j]);
			fp_mul(p2[j]->x, p2[j]->x, w);
		}
		fp_prime_get_par(a);
		fp13_set_dig(r, 1);
		bn_neg(a, a);
		pp_mil_k13_sim(l1, l2, l3, l4, t, q, p,  p2, m,  a);

    	/* computing L_{n,1}  and  L_{n,2}}, 
	   		where L_{n,1}=l1 and L_{n,2}=l4 */

    	//l2=l2*(\prod{1}^{n}{x_{p_i}-x_{q^i}})^p
 		fp_sqr(f1[0], ep_curve_get_beta());
		for(int i = 0; i<13; i++)fp_mul(f2[i], q[0]->x[i], f1[0]);
		fp13_neg(f2, f2);
		fp13_copy(f4, f2);
		fp_add(f2[0], p[0]->x, f2[0]);
		if(m>1){
			for(j=1; j<m; j++){
				for(int i = 0; i<13; i++)fp_mul(f3[i], q[j]->x[i], f1[0]);
				fp13_neg(f3, f3);
				fp_add(f3[0], p[j]->x, f3[0]);
				fp13_mul(f2, f2, f3);
			}
		}
		fp13_frb(f2, f2, 1);
		fp13_mul(l2,l2, f2);

    	//l4=l4*(\prod{1}^{n}{x_{p2_i}-w*x_{Q^i}})^p
    	// l4=l4^p
		fp_add(f4[0], p2[0]->x, f4[0]);
		if(m>1){
			for(j=1; j<m; j++){
				for(int i = 0; i<13; i++)fp_mul(f3[i], q[j]->x[i], f1[0]);
				fp13_neg(f3, f3);
				fp_add(f3[0], p2[j]->x, f3[0]);
				fp13_mul(f4, f4, f3);
			}
		}
		fp13_frb(f4, f4, 1);
		fp13_mul(l4, l4, f4);   
		fp13_frb(l4, l4, 1);

  		//l3=l3^p*(\prod{1}^{n}{y_{p_i}-y_{q_i}})^(p^2)
 		fp13_frb(l3, l3, 1);
		fp13_neg(f3,   q[0]->y);
		fp_add(f3[0],  f3[0],  p[0]->y);
		for (j= 1; j < m; j++) {
			fp13_neg(f1,   q[j]->y);
			fp_add(f1[0],  f1[0],  p[j]->y);
			fp13_mul(f3,  f3,  f1);
		}
		fp13_frb(f3, f3, 2);
		fp13_mul(l3,  l3,  f3);

		//the final step for computing L_{n,1} }
		fp13_inv(l2, l2);
		fp13_mul(l1, l1, l2);
		fp13_frb(l2, l1, 1);
		fp13_exp(l1, l1, a);
		fp13_mul(l1, l1, l2);
		fp13_mul(l1, l1, l3);

		/*the final exponentiation*/
		pp_exp_bwk13(r,  l1,  l4);
		
	}


	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(a);
		fp13_free(l1);
		fp13_free(l2);
		fp13_free(l3);
		fp13_free(l4);
		fp13_free(f1);
		fp13_free(f2);
		fp13_free(f3);
		fp13_free(f4);
		for (j = 0; j < m; j++) {
			ep_free(p2[j]);
			ep13_free(t[j]);
		}
	}

 }

