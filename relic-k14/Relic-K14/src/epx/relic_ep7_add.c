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
 * Implementation of addition on prime elliptic curves over quadratic
 * extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

static void ep7_add_basic_imp(ep7_t r, fp7_t s, const ep7_t p, const ep7_t q) {
	fp7_t t0, t1, t2;

	fp7_null(t0);
	fp7_null(t1);
	fp7_null(t2);

	RLC_TRY {
		fp7_new(t0);
		fp7_new(t1);
		fp7_new(t2);

		/* t0 = x2 - x1. */
		fp7_sub(t0, q->x, p->x);
		/* t1 = y2 - y1. */
		fp7_sub(t1, q->y, p->y);

		/* If t0 is zero. */
		if (fp7_is_zero(t0)) {
			if (fp7_is_zero(t1)) {
				/* If t1 is zero, q = p, should have doubled. */
				ep7_dbl_slp_basic(r, s, p);
			} else {
				/* If t1 is not zero and t0 is zero, q = -p and r = infty. */
				ep7_set_infty(r);
			}
		} else {
			/* t2 = 1/(x2 - x1). */
			fp7_inv(t2, t0);
			/* t2 = lambda = (y2 - y1)/(x2 - x1). */
			fp7_mul(t2, t1, t2);

			/* x3 = lambda^2 - x2 - x1. */
			fp7_sqr(t1, t2);
			fp7_sub(t0, t1, p->x);
			fp7_sub(t0, t0, q->x);

			/* y3 = lambda * (x1 - x3) - y1. */
			fp7_sub(t1, p->x, t0);
			fp7_mul(t1, t2, t1);
			fp7_sub(r->y, t1, p->y);

			fp7_copy(r->x, t0);
			fp7_copy(r->z, p->z);

			if (s != NULL) {
				fp7_copy(s, t2);
			}

			r->coord = BASIC;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp7_free(t0);
		fp7_free(t1);
		fp7_free(t2);
	}
}

#endif /* EP_ADD == BASIC */

#if EP_ADD == PROJC || !defined(STRIP)

#if defined(EP_MIXED) || !defined(STRIP)

/**
 * Adds a point represented in affine coordinates to a point represented in
 * projective coordinates.
 *
 * @param r					- the result.
 * @param s					- the slope.
 * @param p					- the affine point.
 * @param q					- the projective point.
 */
static void ep7_add_projc_mix(ep7_t r, const ep7_t p, const ep7_t q) {
	fp7_t t0, t1, t2, t3, t4, t5, t6;

	fp7_null(t0);
	fp7_null(t1);
	fp7_null(t2);
	fp7_null(t3);
	fp7_null(t4);
	fp7_null(t5);
	fp7_null(t6);

	RLC_TRY {
		fp7_new(t0);
		fp7_new(t1);
		fp7_new(t2);
		fp7_new(t3);
		fp7_new(t4);
		fp7_new(t5);
		fp7_new(t6);

		if (p->coord != BASIC) {
			/* t0 = z1^2. */
			fp7_sqr(t0, p->z);

			/* t3 = U2 = x2 * z1^2. */
			fp7_mul(t3, q->x, t0);

			/* t1 = S2 = y2 * z1^3. */
			fp7_mul(t1, t0, p->z);
			fp7_mul(t1, t1, q->y);

			/* t3 = H = U2 - x1. */
			fp7_sub(t3, t3, p->x);

			/* t1 = R = 2 * (S2 - y1). */
			fp7_sub(t1, t1, p->y);
		} else {
			/* H = x2 - x1. */
			fp7_sub(t3, q->x, p->x);

			/* t1 = R = 2 * (y2 - y1). */
			fp7_sub(t1, q->y, p->y);
		}

		/* t2 = HH = H^2. */
		fp7_sqr(t2, t3);

		/* If E is zero. */
		if (fp7_is_zero(t3)) {
			if (fp7_is_zero(t1)) {
				/* If I is zero, p = q, should have doubled. */
				ep7_dbl(r, p);
			} else {
				/* If I is not zero, q = -p, r = infinity. */
				ep7_set_infty(r);
			}
		} else {
			/* t5 = J = H * HH. */
			fp7_mul(t5, t3, t2);

			/* t4 = V = x1 * HH. */
			fp7_mul(t4, p->x, t2);

			/* x3 = R^2 - J - 2 * V. */
			fp7_sqr(r->x, t1);
			fp7_sub(r->x, r->x, t5);
			fp7_dbl(t6, t4);
			fp7_sub(r->x, r->x, t6);

			/* y3 = R * (V - x3) - Y1 * J. */
			fp7_sub(t4, t4, r->x);
			fp7_mul(t4, t4, t1);
			fp7_mul(t1, p->y, t5);
			fp7_sub(r->y, t4, t1);

			if (p->coord != BASIC) {
				/* z3 = z1 * H. */
				fp7_mul(r->z, p->z, t3);
			} else {
				/* z3 = H. */
				fp7_copy(r->z, t3);
			}
		}
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
	}
}

#endif

/**
 * Adds two points represented in projective coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param r					- the result.
 * @param p					- the first point to add.
 * @param q					- the second point to add.
 */
static void ep7_add_projc_imp(ep7_t r, const ep7_t p, const ep7_t q) {
#if defined(EP_MIXED) && defined(STRIP)
	ep7_add_projc_mix(r, p, q);
#else /* General addition. */
	fp7_t t0, t1, t2, t3, t4, t5, t6;

	fp7_null(t0);
	fp7_null(t1);
	fp7_null(t2);
	fp7_null(t3);
	fp7_null(t4);
	fp7_null(t5);
	fp7_null(t6);

	RLC_TRY {
		fp7_new(t0);
		fp7_new(t1);
		fp7_new(t2);
		fp7_new(t3);
		fp7_new(t4);
		fp7_new(t5);
		fp7_new(t6);

		if (q->coord == BASIC) {
			ep7_add_projc_mix(r, p, q);
		} else {
			/* t0 = z1^2. */
			fp7_sqr(t0, p->z);

			/* t1 = z2^2. */
			fp7_sqr(t1, q->z);

			/* t2 = U1 = x1 * z2^2. */
			fp7_mul(t2, p->x, t1);

			/* t3 = U2 = x2 * z1^2. */
			fp7_mul(t3, q->x, t0);

			/* t6 = z1^2 + z2^2. */
			fp7_add(t6, t0, t1);

			/* t0 = S2 = y2 * z1^3. */
			fp7_mul(t0, t0, p->z);
			fp7_mul(t0, t0, q->y);

			/* t1 = S1 = y1 * z2^3. */
			fp7_mul(t1, t1, q->z);
			fp7_mul(t1, t1, p->y);

			/* t3 = H = U2 - U1. */
			fp7_sub(t3, t3, t2);

			/* t0 = R = 2 * (S2 - S1). */
			fp7_sub(t0, t0, t1);

			fp7_dbl(t0, t0);

			/* If E is zero. */
			if (fp7_is_zero(t3)) {
				if (fp7_is_zero(t0)) {
					/* If I is zero, p = q, should have doubled. */
					ep7_dbl(r, p);
				} else {
					/* If I is not zero, q = -p, r = infinity. */
					ep7_set_infty(r);
				}
			} else {
				/* t4 = I = (2*H)^2. */
				fp7_dbl(t4, t3);
				fp7_sqr(t4, t4);

				/* t5 = J = H * I. */
				fp7_mul(t5, t3, t4);

				/* t4 = V = U1 * I. */
				fp7_mul(t4, t2, t4);

				/* x3 = R^2 - J - 2 * V. */
				fp7_sqr(r->x, t0);
				fp7_sub(r->x, r->x, t5);
				fp7_dbl(t2, t4);
				fp7_sub(r->x, r->x, t2);

				/* y3 = R * (V - x3) - 2 * S1 * J. */
				fp7_sub(t4, t4, r->x);
				fp7_mul(t4, t4, t0);
				fp7_mul(t1, t1, t5);
				fp7_dbl(t1, t1);
				fp7_sub(r->y, t4, t1);

				/* z3 = ((z1 + z2)^2 - z1^2 - z2^2) * H. */
				fp7_add(r->z, p->z, q->z);
				fp7_sqr(r->z, r->z);
				fp7_sub(r->z, r->z, t6);
				fp7_mul(r->z, r->z, t3);
			}
		}
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
	}
#endif
}

#endif /* EP_ADD == PROJC */

/*============================================================================*/
	/* Public definitions                                                         */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

void ep7_add_basic(ep7_t r, const ep7_t p, const ep7_t q) {
	if (ep7_is_infty(p)) {
		ep7_copy(r, q);
		return;
	}

	if (ep7_is_infty(q)) {
		ep7_copy(r, p);
		return;
	}

	ep7_add_basic_imp(r, NULL, p, q);
}

void ep7_add_slp_basic(ep7_t r, fp7_t s, const ep7_t p, const ep7_t q) {
	if (ep7_is_infty(p)) {
		ep7_copy(r, q);
		return;
	}

	if (ep7_is_infty(q)) {
		ep7_copy(r, p);
		return;
	}

	ep7_add_basic_imp(r, s, p, q);
}

#endif

#if EP_ADD == PROJC || !defined(STRIP)

void ep7_add_projc(ep7_t r, const ep7_t p, const ep7_t q) {
	if (ep7_is_infty(p)) {
		ep7_copy(r, q);
		return;
	}

	if (ep7_is_infty(q)) {
		ep7_copy(r, p);
		return;
	}

	if (p == q) {
		/* TODO: This is a quick hack. Should we fix this? */
		ep7_dbl(r, p);
		return;
	}

	ep7_add_projc_imp(r, p, q);
}


void ep7_sub_projc(ep7_t r, const ep7_t p, const ep7_t q) {
	ep7_t t;

	ep7_null(t);

	if (p == q) {
		ep7_set_infty(r);
		return;
	}

	RLC_TRY {
		ep7_new(t);

		ep7_neg(t, q);
		ep7_add(r, p, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep7_free(t);
	}
}

#endif
