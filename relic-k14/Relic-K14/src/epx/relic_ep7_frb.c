/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 7017 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 7.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 7.0 of the Apache
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
 * Implementation of frobenius action on prime elliptic curves over
 * quadratic extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep7_psi(ep7_t r, const ep7_t p, int i) {
	ctx_t *ctx = core_get();
	ep7_copy(r, p);
	for (; i > 0; i--) {
		fp7_frb(r->x, r->x, 1);
		fp7_frb(r->y, r->y, 1);
		fp7_frb(r->z, r->z, 1);
		for(int j= 0; j<7; j++)fp_mul(r->x[j],r->x[j], ctx->frb7_1[1]);
		for(int j= 0; j<7; j++)fp_mul(r->y[j],r->y[j], ctx->frb7_1b[1]);		
		for(int j= 0; j<7; j++)fp_mul(r->x[j],r->x[j], ep_curve_get_beta());
	}
}



void ep7_frb(ep7_t r, const ep7_t p, int i) {
	ctx_t *ctx = core_get();
	ep7_copy(r, p);
	for (; i > 0; i--) {
		fp7_frb(r->x, r->x, 1);
		fp7_frb(r->y, r->y, 1);
		fp7_frb(r->z, r->z, 1);
		for(int j= 0; j<7; j++)fp_mul(r->x[j],r->x[j], ctx->frb7_1[1]);
		for(int j= 0; j<7; j++)fp_mul(r->y[j],r->y[j], ctx->frb7_1b[1]);		
	}
}

