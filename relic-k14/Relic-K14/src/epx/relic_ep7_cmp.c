/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
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
 * Implementation of utilities for prime elliptic curves over quadratic
 * extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int ep7_cmp( const ep7_t p, const ep7_t q) {
    fp7_t u0, u1, u2, u3;
    int result = RLC_NE;
	if (ep7_is_infty(p) || ep7_is_infty(q)) {

	   if (ep7_is_infty(p) && ep7_is_infty(q)) return RLC_EQ;
	   else return RLC_NE;

	}
    fp7_null(u0);
    fp7_null(u1);


    RLC_TRY {
        fp7_new(u0);
        fp7_new(u1);
	fp7_new(u2);
        fp7_new(u3);

       	fp7_sqr(u2, p->z);
       	fp7_sqr(u3, q->z);
	fp7_mul(u0, p->x, u3);
	fp7_mul(u1, q->x, u2);
	
	fp7_mul(u2, u2, p->z);
	fp7_mul(u3, u3, q->z);
	fp7_mul(u2, u2, q->y);
	fp7_mul(u3, u3, p->y);
	if((fp7_cmp(u0, u1) == RLC_EQ) && (fp7_cmp(u2, u3) == RLC_EQ)){
            result = RLC_EQ;
        }
	
    } RLC_CATCH_ANY {
        RLC_THROW(ERR_CAUGHT);
    } RLC_FINALLY {
        fp7_free(u0);
        fp7_free(u1);
	fp7_free(u2);
        fp7_free(u3);
    }

    return result;
}

