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
 * Compute the  Miller loop  for super-optimal ate pairings of type G_2 x G_1 with k=14.
 *
 * @param[out] t			- the resulting point.
 * @param[in] q				- the vector of first arguments in affine coordinates.
 * @param[in] p				- the vector of second arguments in affine coordinates.
 * @param[in] p2			- the image of p under the glv endomorphism.
 * @param[in] a				- the loop parameter.
 * @param[out] l1			- numerator of f_{a,q}(p).
 * @param[out] s2			- denominator of f_{a,q}(p2).
 */
static void pp_mil_k14_sim_basic(fp14_t f1,  fp14_t f2,  ep7_t *t, ep7_t *q, ep_t *p, ep_t *p2, int m,  bn_t a) {

	fp14_t l1, l2;
	//ep_t *_p = RLC_ALLOCA(ep_t, m);
	//ep_t *_p2 = RLC_ALLOCA(ep_t, m);
	ep7_t *_q = RLC_ALLOCA(ep7_t, m);
	size_t len = bn_bits(a) + 1;
	int i, j;
	int8_t s[RLC_FP_BITS + 1];

	if (m == 0) {
		return;
	}

	fp14_null(l1);
	fp14_null(l2);

	RLC_TRY {
		fp14_new(l1);
		fp14_new(l2);

		if (_q == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (j = 0; j < m; j++) {
			//ep_null(_p[j]);
			//ep_null(_p2[j]);
			//ep_new(_p[j]);

			ep7_null(_q[j]);
			ep7_new(_q[j]);
			ep7_copy(t[j], q[j]);
			ep7_neg(_q[j], q[j]);
		}

		fp14_zero(l1);
		fp14_zero(l2);

		bn_rec_naf(s, &len, a, 2);
		pp_dbl_k14_first(f1, f2, t[0], p[0], p2[0]);
		for (j = 1; j < m; j++) {
			pp_dbl_k14_first(l1,l2, t[j], p[j], p2[j]);
			fp14_mul(f1, f1, l1);
			fp14_mul(f2, f2, l2);

		}
		if (s[len - 2] > 0) {
			for (j = 0; j < m; j++) {
				pp_add_k14(l1,l2, t[j], q[j], p[j],p2[j]);
				fp14_mul(f1, f1, l1);
				fp14_mul(f2, f2, l2);
			}
		}
		if (s[len - 2] < 0) {
			for (j = 0; j < m; j++) {
				pp_add_k14(l1, l2, t[j], _q[j], p[j],p2[j]);
				fp14_mul(f1, f1, l1);
				fp14_mul(f2, f2, l2);		
			}
		}

		for (i = len - 3; i >= 1; i--) {
			fp14_sqr(f1, f1);
			fp14_sqr(f2, f2);
			for (j = 0; j < m; j++) {
				pp_dbl_k14(l1, l2, t[j],p[j], p2[j]);
				fp14_mul(f1, f1, l1);
				fp14_mul(f2, f2, l2);
				if (s[i] > 0) {
					pp_add_k14(l1, l2, t[j], q[j], p[j], p2[j]);
					fp14_mul(f1, f1, l1);
					fp14_mul(f2, f2, l2);
				}
				if (s[i] < 0) {
					pp_add_k14(l1, l2, t[j], _q[j], p[j], p2[j]);
					fp14_mul(f1, f1, l1);
					fp14_mul(f2, f2, l2);
				}
			}
		}
		fp14_sqr(f1, f1);
		fp14_sqr(f2, f2);
		for (j = 0; j < m; j++) {
		pp_dbl_k14_last(l1, l2, t[j],p[j], p2[j]);
		fp14_mul(f1, f1, l1);
		fp14_mul(f2, f2, l2);
		}
		
		
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp14_free(l1);
		fp14_free(l2);
		for (j = 0; j < m; j++) {
			ep7_free(_q[j]);
		}
	}
}

static void pp_mil_k14_sim(fp14_t f1,  fp14_t *tab,  ep7_t *t, ep7_t *q, ep_t *p, ep_t *p2, int m,  bn_t a) {

	fp14_t l1, l2; 
	ep7_t *_q = RLC_ALLOCA(ep7_t, m);
	size_t len = bn_bits(a) + 1;
	int i, j;int k =1; 
	int8_t s[RLC_FP_BITS + 1];

	if (m == 0) {
		return;
	}

	fp14_null(l1);
	fp14_null(l2);

	RLC_TRY {
		fp14_new(l1);
		fp14_new(l2);

		if (_q == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (j = 0; j < m; j++) {
	
			ep7_null(_q[j]);
			ep7_new(_q[j]);
			ep7_copy(t[j], q[j]);
			ep7_neg(_q[j], q[j]);
		}

		fp14_zero(l1);
		fp14_zero(l2);

		bn_rec_naf(s, &len, a, 2);
		pp_dbl_k14_first(f1, tab[0], t[0], p[0], p2[0]);
		for (j = 1; j < m; j++) {
			pp_dbl_k14_first(l1,l2, t[j], p[j], p2[j]);
			fp14_mul(f1, f1, l1);
			fp14_mul(tab[0], tab[0], l2);
		}

		for (i = len - 3; i >= 1; i--) {
			fp14_sqr(f1, f1);
			pp_dbl_k14(l1, tab[k], t[0],p[0], p2[0]);
			fp14_mul(f1, f1, l1);
			for (j = 1; j < m; j++) {
				pp_dbl_k14(l1, l2, t[j],p[j], p2[j]);
				fp14_mul(f1, f1, l1);
				fp14_mul(tab[k],  tab[k], l2);
			}
			k++;

			if (s[i] > 0) {
				pp_add_k14(l1, tab[k], t[0], q[0], p[0], p2[0]);
				fp14_mul(f1, f1, l1);
				for (j = 1; j < m; j++) {
					pp_add_k14(l1, l2, t[j], q[j], p[j], p2[j]);
					fp14_mul(f1, f1, l1);
					fp14_mul(tab[k], tab[k], l2);
				}
				k++;

			}
			if (s[i] < 0) {
				pp_add_k14(l1, tab[k], t[0], _q[0], p[0], p2[0]);
				fp14_mul(f1, f1, l1);
				for (j = 1; j < m; j++) {
					pp_add_k14(l1, l2, t[j], _q[j], p[j], p2[j]);
					fp14_mul(f1, f1, l1);
					fp14_mul(tab[k], tab[k], l2);
				}
				k++;
			}
		}
		fp14_sqr(f1, f1);
		pp_dbl_k14_last(l1, tab[k], t[0],p[0], p2[0]);
		fp14_mul(f1, f1, l1);
		for (j = 1; j < m; j++) {
			pp_dbl_k14_last(l1, l2, t[j],p[j], p2[j]);
			fp14_mul(f1, f1, l1);
			fp14_mul(tab[k], tab[k], l2);
		}

		
		
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp14_free(l1);
		fp14_free(l2);
		for (j = 0; j < m; j++) {
			ep7_free(_q[j]);
		}
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/
void pp_map_sup_oatep_k14_basic(fp14_t r,  ep_t p,   ep7_t q) {
	ep_t _p[1], p2[1];
	ep7_t t[1],_q[1];
	bn_t a;
	int j;
	dig_t* w;
	fp14_t f1, f2;
	w = ep_curve_get_beta();
	RLC_TRY {
		bn_null(a);
		bn_new(a);
		ep_null(_p[0]);
		ep_null(p2[0]);
		ep7_null(t[0]);
		ep_new(_p[0]);
		ep_new(p2[0]);
		ep7_new(t[0]);
		ep_norm(p2[0], p);
		ep_copy(_p[0], p2[0]);
		ep7_norm(_q[0], q);
		fp_mul(p2[0]->x, p2[0]->x, w);
		fp_mul(p2[0]->x, p2[0]->x, w);
		fp_prime_get_par(a);

		#if FP_PRIME == 351
			bn_neg(a, a);
		#endif

		fp14_set_dig(f1, 1);
		fp14_set_dig(f2, 1);
		fp14_zero(r);
		pp_mil_k14_sim_basic(f1, f2, t, _q, _p, p2, 1, a);

		fp14_mul(f2, f1, f2);
		fp14_frb(f2, f2, 1);
		fp14_exp_x(f1, f1);
		
		fp14_mul(f1, f1, f2);

		#if FP_PRIME == 351
			fp14_inv_cyc(f1, f1);
		#endif

        fp14_zero(f2);
		fp7_neg(f2[1], _q[0]->y);
		fp7_mul_art(f2[1], f2[1]);
		fp_copy(f2[0][0], _p[0]->y);

		fp14_frb(f2, f2, 2);
		fp14_mul(f1, f1, f2);
		/*the final exponentiation*/
		pp_exp_bwk14(r,  f1);
		
	}


	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(a);
		fp14_free(l1);
		fp14_free(l2);
		fp14_free(l3);
		fp14_free(l4);
		fp14_free(f1);
		fp14_free(f2);
		fp14_free(f3);
		fp14_free(f4);
		ep_free(p2);
		ep7_free(t);
	}
}

 void pp_map_sim_sup_oatep_k14_basic(fp14_t r,  ep_t *p,   ep7_t *q, int m) {
	ep_t *p2= RLC_ALLOCA(ep_t, m);
	ep7_t *t= RLC_ALLOCA(ep7_t, m);
	bn_t a;
	int j;
	dig_t* w;
	fp14_t f1, f2;
	w = ep_curve_get_beta();
	RLC_TRY {
		bn_null(a);
		bn_new(a);
		for (j= 0; j < m; j++) {
			ep_null(p2[j]);
			ep7_null(t[j]);
			ep_new(p2[j]);
			ep7_new(t[j]);
		}
		for (j= 0; j < m; j++) {
			ep_norm(p2[j], p[j]);
			fp_mul(p2[j]->x, p2[j]->x, w);
			fp_mul(p2[j]->x, p2[j]->x, w);
		}
		fp_prime_get_par(a);

		#if FP_PRIME == 351
			bn_neg(a, a);
		#endif

		fp14_set_dig(f1, 1);
		fp14_set_dig(f2, 1);
		fp14_zero(r);
		pp_mil_k14_sim_basic(f1, f2, t, q, p, p2, m,  a);
        fp14_mul(f2, f1, f2);
		fp14_frb(f2, f2, 1);
		fp14_exp_x(f1, f1);
		fp14_mul(f1, f1, f2);

		#if FP_PRIME == 351
			fp14_inv_cyc(f1, f1);
		#endif

		fp14_zero(f2);
		fp7_neg(f2[1], q[0]->y);
		fp7_mul_art(f2[1], f2[1]);
		fp_copy(f2[0][0], p[0]->y);
		if (m>1){
			for(j=1; j<m; j++) {
				fp7_neg(r[1], q[j]->y);
				fp7_mul_art(r[1], r[1]);
		    	fp_copy(r[0][0], p[j]->y);
				fp14_mul(f2, f2, r);
			}
		}
		fp14_frb(f2, f2, 2);
		fp14_mul(f1, f1, f2);
		/*the final exponentiation*/
		pp_exp_bwk14(r,  f1);
		
	}


	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(a);
		fp14_free(l1);
		fp14_free(l2);
		fp14_free(l3);
		fp14_free(l4);
		fp14_free(f1);
		fp14_free(f2);
		fp14_free(f3);
		fp14_free(f4);
		for (j = 0; j < m; j++) {
			ep_free(p2[j]);
			ep7_free(t[j]);
		}
	}

 }

void pp_map_sup_oatep_k14(fp14_t r,  ep_t p,   ep7_t q) {
	ep_t _p[1], p2[1];
	ep7_t t[1],_q[1];
	bn_t a;
	int i;
	int j = 0;
	dig_t* w;
	fp14_t f1, f2, f3, f4; fp14_t tab[26];
	w = ep_curve_get_beta();
	RLC_TRY {
		bn_null(a);
		bn_new(a);
		ep_null(_p[0]);
		ep_null(p2[0]);
		ep7_null(t[0]);
		ep_new(_p[0]);
		ep_new(p2[0]);
		ep7_new(t[0]);
		ep_norm(p2[0], p);
		ep_copy(_p[0], p2[0]);
		ep7_norm(_q[0], q);
		fp_mul(p2[0]->x, p2[0]->x, w);
		fp_mul(p2[0]->x, p2[0]->x, w);
		fp_prime_get_par(a); 

		#if FP_PRIME == 351
			bn_neg(a, a);
		#endif

		int8_t s[RLC_FP_BITS + 1];
		size_t len = bn_bits(a)+1;
		bn_rec_naf(s, &len, a, 2);


		fp14_set_dig(f1, 1);
		fp14_set_dig(f2, 1);
		fp14_zero(r);
		pp_mil_k14_sim(f1, tab, t, _q, _p, p2, 1, a);	  
			
  		fp14_frb(f2, f1, 13);
		
		#if FP_PRIME == 351
			fp14_inv_cyc(f2, f2);
		#endif

		fp14_inv_cyc(f4, f2);
	
		fp14_sqr(f3, f2);
		fp14_mul(f3, f3, tab[j]);
		j++;
		for (i = len - 3; i >= 0; i--) {
			fp14_sqr(f3, f3);
			fp14_mul(f3, f3, tab[j]);
			j++;

			if (s[i]>0) {
				fp14_mul(f3, f3, f2);
				fp14_mul(f3, f3, tab[j]);
        	j++;
			}	
		   	if (s[i]<0) {
				fp14_mul(f3, f3, f4);
				fp14_mul(f3, f3, tab[j]);
      		  j++;
			}	
		}


		fp14_mul(f1, f1, f3);
		#if FP_PRIME == 351
			fp14_inv_cyc(f1, f1);
		#endif        
		fp14_zero(f2);
		fp7_neg(f2[1], _q[0]->y);
		fp7_mul_art(f2[1], f2[1]);
		fp_copy(f2[0][0], _p[0]->y);

		fp14_frb(f2, f2, 1);
		fp14_mul(f1, f1, f2);
		/*the final exponentiation*/
		pp_exp_bwk14(r,  f1);
		
	}


	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(a);
		fp14_free(l1);
		fp14_free(l2);
		fp14_free(l3);
		fp14_free(l4);
		fp14_free(f1);
		fp14_free(f2);
		fp14_free(f3);
		fp14_free(f4);
		ep_free(p2);
		ep7_free(t);
	}

 }


 void pp_map_sim_sup_oatep_k14(fp14_t r,  ep_t *p,   ep7_t *q, int m) {
	ep_t *p2= RLC_ALLOCA(ep_t, m);
	ep7_t *t= RLC_ALLOCA(ep7_t, m);
	bn_t a;
	int i;
	int j = 0;
	dig_t* w;
	fp14_t f1, f2, f3, f4;fp14_t tab[26];
	w = ep_curve_get_beta();
	RLC_TRY {
		bn_null(a);
		bn_new(a);
		for (j= 0; j < m; j++) {
			ep_null(p2[j]);
			ep7_null(t[j]);
			ep_new(p2[j]);
			ep7_new(t[j]);
		}
		for (j= 0; j < m; j++) {
			ep_norm(p2[j], p[j]);
			fp_mul(p2[j]->x, p2[j]->x, w);
			fp_mul(p2[j]->x, p2[j]->x, w);
		}
		fp_prime_get_par(a);

		#if FP_PRIME == 351
			bn_neg(a, a);
		#endif
		
		int8_t s[RLC_FP_BITS + 1];
		size_t len = bn_bits(a)+1;
		bn_rec_naf(s, &len, a, 2);

		fp14_set_dig(f1, 1);
		fp14_set_dig(f2, 1);
		fp14_zero(r);
		pp_mil_k14_sim(f1, tab, t, q, p, p2, m,  a);

		fp14_frb(f2, f1, 13);

		#if FP_PRIME == 351
			fp14_inv_cyc(f2, f2);
		#endif

		fp14_inv_cyc(f4, f2);
		fp14_sqr(f3, f2);

	    j =0;
		fp14_mul(f3, f3, tab[j]);
		j++;
		for (i = len - 3; i >= 0; i--) {
			fp14_sqr(f3, f3);
			fp14_mul(f3, f3, tab[j]);
			j++;

			if (s[i]>0) {
				fp14_mul(f3, f3, f2);
				fp14_mul(f3, f3, tab[j]);
        	j++;
			}	
		   	if (s[i]<0) {
				fp14_mul(f3, f3, f4);
				fp14_mul(f3, f3, tab[j]);
      		  j++;
			}	
		}

		fp14_mul(f1, f1, f3);

		#if FP_PRIME == 351
			fp14_inv_cyc(f1, f1);
		#endif   


        fp14_zero(f2);
		fp7_neg(f2[1], q[0]->y);
		fp7_mul_art(f2[1], f2[1]);
		fp_copy(f2[0][0], p[0]->y);
		if (m>1){
			for(j=1; j<m; j++) {
				fp7_neg(r[1], q[j]->y);
				fp7_mul_art(r[1], r[1]);
		    	fp_copy(r[0][0], p[j]->y);
				fp14_mul(f2, f2, r);
			}
		}

		fp14_frb(f2, f2, 1);
		fp14_mul(f1, f1, f2);

		/*the final exponentiation*/
		pp_exp_bwk14(r,  f1);
		
	}


	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(a);
		fp14_free(l1);
		fp14_free(l2);
		fp14_free(l3);
		fp14_free(l4);
		fp14_free(f1);
		fp14_free(f2);
		fp14_free(f3);
		fp14_free(f4);
		for (j = 0; j < m; j++) {
			ep_free(p2[j]);
			ep7_free(t[j]);
		}
	}

 }






