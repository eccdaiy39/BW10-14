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
 * Implementation of point multiplication on prime elliptic curves over
 * quadratic extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_MUL == LWNAF || !defined(STRIP)

#if defined(EP_ENDOM)

static void ep7_mul_glv_imp(ep7_t r, const ep7_t p, const bn_t k) {
	int i, j;
	size_t l, _l[12];
	bn_t n, _k[12], u;
	int8_t naf[12][RLC_FP_BITS + 1];
	ep7_t q[12];

	bn_null(n);
	bn_null(u);

	RLC_TRY {
		bn_new(n);
		bn_new(u);
		for (i = 0; i < 12; i++) {
			bn_null(_k[i]);
			ep7_null(q[i]);
			bn_new(_k[i]);
			ep7_new(q[i]);
		}

		ep_curve_get_ord(n);
		fp_prime_get_par(u);
		bn_neg(u,u);
		bn_mod(_k[0], k, n);
		bn_rec_frb(_k, 12, _k[0], u, n, 0);

		ep7_norm(q[0], p);
		for (i = 1; i < 12; i++)ep7_psi(q[i], q[i-1], 1);
		for (i = 0; i < 6; i++)ep7_neg(q[2*i+1], q[2*i+1]);
		l = 0;
		for (i = 0; i < 12; i++) {
			if (bn_sign(_k[i]) == RLC_NEG) {
				ep7_neg(q[i], q[i]);
			}
			_l[i] = RLC_FP_BITS + 1;
			bn_rec_naf(naf[i], &_l[i], _k[i], 2);
			l = RLC_MAX(l, _l[i]);
		}

		ep7_set_infty(r);
		for (j = l - 1; j >= 0; j--) {
			ep7_dbl(r, r);

			for (i = 0; i < 12; i++) {
				if (naf[i][j] > 0) {
					ep7_add(r, r, q[i]);
				}
				if (naf[i][j] < 0) {
					ep7_sub(r, r, q[i]);
				}
			}
		}

		/* Convert r to affine coordinates. */
		ep7_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(u);
		for (i = 0; i < 12; i++) {
			bn_free(_k[i]);
			ep7_free(q[i]);
		}

	}
}

#endif /* EP_ENDOM */

static void ep7_mul_naf_imp(ep7_t r, const ep7_t p, const bn_t k) {
	int  i;
	size_t l, n;
	int8_t naf[RLC_FP_BITS + 1];
	ep7_t t[1 << (RLC_WIDTH - 2)];

	RLC_TRY {
		/* Prepare the precomputation table. */
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ep7_null(t[i]);
			ep7_new(t[i]);
		}
		/* Compute the precomputation table. */
		ep7_tab(t, p, RLC_WIDTH);

		/* Compute the w-NAF representation of k. */
		l = sizeof(naf);
		bn_rec_naf(naf, &l, k, RLC_WIDTH);

		ep7_set_infty(r);
		for (i = l - 1; i >= 0; i--) {
			ep7_dbl(r, r);

			n = naf[i];
			if (n > 0) {
				ep7_add(r, r, t[n / 2]);
			}
			if (n < 0) {
				ep7_sub(r, r, t[-n / 2]);
			}
		}
		/* Convert r to affine coordinates. */
		ep7_norm(r, r);
		if (bn_sign(k) == RLC_NEG) {
			ep7_neg(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		/* Free the precomputation table. */
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ep7_free(t[i]);
		}
	}
}

#endif /* EP_MUL == LWNAF */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep7_mul_basic(ep7_t r, const ep7_t p, const bn_t k) {
	int i, l;
	ep7_t t;

	ep7_null(t);

	if (bn_is_zero(k) || ep7_is_infty(p)) {
		ep7_set_infty(r);
		return;
	}

	RLC_TRY {
		ep7_new(t);
		l = bn_bits(k);

		if (bn_get_bit(k, l - 1)) {
			ep7_copy(t, p);
		} else {
			ep7_set_infty(t);
		}

		for (i = l - 2; i >= 0; i--) {
			ep7_dbl(t, t);
			if (bn_get_bit(k, i)) {
				ep7_add(t, t, p);
			}
		}

		ep7_copy(r, t);
		ep7_norm(r, r);
		if (bn_sign(k) == RLC_NEG) {
			ep7_neg(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep7_free(t);
	}
}

#if EP_MUL == SLIDE || !defined(STRIP)

void ep7_mul_slide(ep7_t r, const ep7_t p, const bn_t k) {
	ep7_t t[1 << (RLC_WIDTH - 1)], q;
	int i, j, l;
	uint8_t win[RLC_FP_BITS + 1];

	ep7_null(q);

	if (bn_is_zero(k) || ep7_is_infty(p)) {
		ep7_set_infty(r);
		return;
	}

	RLC_TRY {
		for (i = 0; i < (1 << (RLC_WIDTH - 1)); i ++) {
			ep7_null(t[i]);
			ep7_new(t[i]);
		}

		ep7_new(q);

		ep7_copy(t[0], p);
		ep7_dbl(q, p);

#if defined(EP_MIXED)
		ep7_norm(q, q);
#endif

		/* Create table. */
		for (i = 1; i < (1 << (RLC_WIDTH - 1)); i++) {
			ep7_add(t[i], t[i - 1], q);
		}

#if defined(EP_MIXED)
		ep7_norm_sim(t + 1, t + 1, (1 << (RLC_WIDTH - 1)) - 1);
#endif

		ep7_set_infty(q);
		l = RLC_FP_BITS + 1;
		bn_rec_slw(win, &l, k, RLC_WIDTH);
		for (i = 0; i < l; i++) {
			if (win[i] == 0) {
				ep7_dbl(q, q);
			} else {
				for (j = 0; j < util_bits_dig(win[i]); j++) {
					ep7_dbl(q, q);
				}
				ep7_add(q, q, t[win[i] >> 1]);
			}
		}

		ep7_norm(r, q);
		if (bn_sign(k) == RLC_NEG) {
			ep7_neg(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < (1 << (RLC_WIDTH - 1)); i++) {
			ep7_free(t[i]);
		}
		ep7_free(q);
	}
}

#endif

#if EP_MUL == LWNAF || !defined(STRIP)

void ep7_mul_lwnaf(ep7_t r, const ep7_t p, const bn_t k) {
	if (bn_is_zero(k) || ep7_is_infty(p)) {
		ep7_set_infty(r);
		return;
	}

#if defined(EP_ENDOM)
	if (ep_curve_is_endom()) {
		if (ep_curve_opt_a() == RLC_ZERO) {
			ep7_mul_glv_imp(r, p, k);
		} else {
			ep7_mul_naf_imp(r, p, k);
		}
		return;
	}
#endif

#if defined(EP_PLAIN) || defined(EP_SUPER)
	ep7_mul_naf_imp(r, p, k);
#endif
}

#endif

void ep7_mul_dig(ep7_t r, const ep7_t p, const dig_t k) {
	int i, l;
	ep7_t t;

	ep7_null(t);

	if (k == 0 || ep7_is_infty(p)) {
		ep7_set_infty(r);
		return;
	}

	RLC_TRY {
		ep7_new(t);

		l = util_bits_dig(k);

		ep7_copy(t, p);

		for (i = l - 2; i >= 0; i--) {
			ep7_dbl(t, t);
			if (k & ((dig_t)1 << i)) {
				ep7_add(t, t, p);
			}
		}

		ep7_norm(r, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep7_free(t);
	}
}



void ep7_rand_mul_u(ep7_t c, const ep7_t a) {
	ep7_t t, v;
	ep7_null(t);
	ep7_null(v);

	RLC_TRY {
		ep7_new(t);
		ep7_new(v);
		ep7_neg(v, a);	

		#if FP_PRIME == 340
		//x:=2^2+2^7+2^9-2^13+2^19+2^21;
			ep7_dbl(t,a);
			ep7_dbl(t,t);
			ep7_add(t,t,a);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_add(t,t,v);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_add(t,t,a);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_add(t,t,a);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_add(t,t,a);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
		#elif FP_PRIME == 351
		//x = -(-2^6 + 2^12 + 2^14 + 2^22)
			ep7_dbl(t,a);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_add(t,t,a);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_add(t,t,a);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_add(t,t,v);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_dbl(t,t);
			ep7_neg(t,t);
        #endif
		ep7_copy(c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep7_free(t);
		ep7_free(v);
	}
}

/*cofactor multiplication for G2*/
 void  ep7_cof(ep7_t r, const ep7_t p) {
	  ep7_t R[9]; 
	  ep7_t u0, u1;
	  for(int i=0; i<9;i++)ep7_null(R[i]);
	  ep7_null(u0);
	  ep7_null(u1);



		RLC_TRY {
		ep7_frb(u0, p, 1);
		ep7_add(u0, u0, p);
		ep7_rand_mul_u(u1, u0);
		ep7_add(R[6], u1, u0);
		
		ep7_rand_mul_u(R[6], R[6]);		
		ep7_add(R[6], R[6], u0);
		ep7_dbl(R[8], u0);
		
		for(int i=5; i>1; i--)ep7_rand_mul_u(R[i], R[i+1]);
	     	ep7_rand_mul_u(R[1], R[2]);		
		ep7_sub(R[1], R[1], u0);
		
		ep7_add(R[0], u1, R[8]);
		ep7_add(u1, R[1], R[4]);
		ep7_add(R[0], R[0], u1);
		ep7_sub(R[0], R[0], R[3]);
		ep7_sub(R[0], R[0], R[6]);

		ep7_add(R[7], R[2], R[5]);	
		ep7_sub(R[7], R[7], u1);	
		ep7_add(R[7], R[7], u0);					
		for(int i=1; i<9; i++){
			ep7_psi(R[i], R[i], i);
			ep7_add(R[0], R[0], R[i]);
		}
		ep7_copy(r, R[0]);
		ep7_norm(r, r);
} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		 for(int i=0; i<9;i++)ep7_free(R[i]);
	 	 ep7_free(u0);
	 	 ep7_free(u1);
	}
}

