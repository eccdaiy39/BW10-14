/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2022 RELIC Authors
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
 * Implementation of comparison for points on prime elliptic curves over
 * quartic extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int ep7_is_infty(const ep7_t p) {
	return (fp7_is_zero(p->z) == 1);
}

void ep7_set_infty(ep7_t p) {
	fp7_zero(p->x);
	fp7_zero(p->y);
	fp7_zero(p->z);
	p->coord = BASIC;
}

void ep7_copy(ep7_t r, const ep7_t p) {
	fp7_copy(r->x, p->x);
	fp7_copy(r->y, p->y);
	fp7_copy(r->z, p->z);
	r->coord = p->coord;
}

void ep7_rand(ep7_t p) {
	bn_t n, k;

	bn_null(k);
	bn_null(n);

	RLC_TRY {
		bn_new(k);
		bn_new(n);

		//ep7_curve_get_ord(n);
		//bn_rand_mod(k, n);
		ep7_curve_get_gen(p);
		//ep7_mul_gen(p, k);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(k);
		bn_free(n);
	}
}

void ep7_blind(ep7_t r, const ep7_t p) {
	fp7_t rand;

	fp7_null(rand);

	RLC_TRY {
		fp7_new(rand);
		fp7_rand(rand);
#if EP_ADD == BASIC
		(void)rand;
		ep7_copy(r, p);
#else
		fp7_mul(r->z, p->z, rand);
		fp7_mul(r->y, p->y, rand);
		fp7_sqr(rand, rand);
		fp7_mul(r->x, r->x, rand);
		fp7_mul(r->y, r->y, rand);
		r->coord = EP_ADD;
#endif
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp7_free(rand);
	}
}

void ep7_rhs(fp7_t rhs, const ep7_t p) {
	fp7_t t0, t1;

	fp7_null(t0);
	fp7_null(t1);

	RLC_TRY {
		fp7_new(t0);
		fp7_new(t1);
		fp7_sqr(t0, p->x);                
		fp7_mul(t0, t0, p->x);				
		ep7_curve_get_b(t1);
		fp7_add(t0, t0, t1);
		fp7_copy(rhs, t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp7_free(t0);
		fp7_free(t1);
	}
}


int ep7_on_curve(const ep7_t p) {
	ep7_t t;
	int r = 0;

	ep7_null(t);

	RLC_TRY {
		ep7_new(t);

		ep7_norm(t, p);

		ep7_rhs(t->x, t);
		fp7_sqr(t->y, t->y);

		r = (fp7_cmp(t->x, t->y) == RLC_EQ) || ep7_is_infty(p);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep7_free(t);
	}
	return r;
}
void ep7_print(const ep7_t p) {
	fp7_print(p->x);
	fp7_print(p->y);
	fp7_print(p->z);
}

void ep7_neg(ep7_t r, const ep7_t p) {
	if (ep7_is_infty(p)) {
		ep7_set_infty(r);
		return;
	}

	if (r != p) {
		fp7_copy(r->x, p->x);
		fp7_copy(r->z, p->z);
	}

	fp7_neg(r->y, p->y);

	r->coord = p->coord;
}

void ep7_tab(ep7_t *t, const ep7_t p, int w) {
	if (w > 2) {
		ep7_dbl(t[0], p);
#if defined(EP_MIXED)
		ep7_norm(t[0], t[0]);
#endif
		ep7_add(t[1], t[0], p);
		for (int i = 2; i < (1 << (w - 2)); i++) {
			ep7_add(t[i], t[i - 1], t[0]);
		}
#if defined(EP_MIXED)
		ep7_norm_sim(t + 1, t + 1, (1 << (w - 2)) - 1);
#endif
	}
	ep7_copy(t[0], p);
}

