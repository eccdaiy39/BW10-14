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
 * Implementation of point normalization on prime elliptic curves over 13th
 * extensions.
 *
 * @ingroup epx
 */




#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_ADD == PROJC || !defined(STRIP)

/**
 * Normalizes a point represented in projective coordinates.
 *
 * @param r			- the result.
 * @param p			- the point to normalize.
 */
static void ep7_norm_imp(ep7_t r, const ep7_t p, int inverted) {
	if (p->coord != BASIC) {
		fp7_t t0, t1;

		fp7_null(t0);
		fp7_null(t1);

		RLC_TRY {

			fp7_new(t0);
			fp7_new(t1);

			if (inverted) {
				fp7_copy(t1, p->z);
			} else {
				fp7_inv(t1, p->z);
			}
			fp7_sqr(t0, t1);
			fp7_mul(r->x, p->x, t0);
			fp7_mul(t0, t0, t1);
			fp7_mul(r->y, p->y, t0);
			fp7_set_dig(r->z, 1);
		}
		RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		}
		RLC_FINALLY {
			fp7_free(t0);
			fp7_free(t1);
		}
	}

	r->coord = BASIC;
}

#endif /* EP_ADD == PROJC */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep7_norm(ep7_t r, const ep7_t p) {
	if (ep7_is_infty(p)) {
		ep7_set_infty(r);
		return;
	}

	if (p->coord == BASIC) {
		/* If the point is represented in affine coordinates, we just copy it. */
		ep7_copy(r, p);
	}
#if EP_ADD == PROJC || !defined(STRIP)
	ep7_norm_imp(r, p, 0);
#endif
}

void ep7_norm_sim(ep7_t *r, const ep7_t *t, int n) {
	int i;
	fp7_t *a = RLC_ALLOCA(fp7_t, n);

	RLC_TRY {
		if (a == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i < n; i++) {
			fp7_null(a[i]);
			fp7_new(a[i]);
			fp7_copy(a[i], t[i]->z);
		}

		fp7_inv_sim(a, a, n);

		for (i = 0; i < n; i++) {
			fp7_copy(r[i]->x, t[i]->x);
			fp7_copy(r[i]->y, t[i]->y);
			fp7_copy(r[i]->z, a[i]);
		}

		for (i = 0; i < n; i++) {
			ep7_norm_imp(r[i], r[i], 1);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < n; i++) {
			fp7_free(a[i]);
		}
		RLC_FREE(a);
	}
}
