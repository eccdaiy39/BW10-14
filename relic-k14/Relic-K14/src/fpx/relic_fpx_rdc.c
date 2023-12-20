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
 * Implementation of modular reduction in extensions defined over prime fields.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if PP_QDR == BASIC || !defined(STRIP)

void fp2_rdc_basic(fp2_t c, dv2_t a) {
	fp_rdc(c[0], a[0]);
	fp_rdc(c[1], a[1]);
}

#endif

#if PP_QDR == INTEG || !defined(STRIP)

void fp2_rdc_integ(fp2_t c, dv2_t a) {
	fp2_rdcn_low(c, a);
}

#endif

#if PP_CBC == BASIC || !defined(STRIP)

void fp3_rdc_basic(fp3_t c, dv3_t a) {
	fp_rdc(c[0], a[0]);
	fp_rdc(c[1], a[1]);
	fp_rdc(c[2], a[2]);
}

#endif

#if PP_CBC == INTEG || !defined(STRIP)

void fp3_rdc_integ(fp3_t c, dv3_t a) {
	fp3_rdcn_low(c, a);
}

void fp7_rdc(fp7_t c, dv7_t a){
	fp_rdc(c[0],a[0]);
	fp_rdc(c[1],a[1]);
	fp_rdc(c[2],a[2]);
	fp_rdc(c[3],a[3]);
	fp_rdc(c[4],a[4]);
	fp_rdc(c[5],a[5]);
	fp_rdc(c[6],a[6]);
}
void fp13_rdc(fp13_t c, dv13_t a){
	fp13_do_2(fp_rdc, c, a);


}
void fp14_rdc(fp14_t c, dv14_t a){
	fp7_rdc(c[0], a[0]);
	fp7_rdc(c[1], a[1]);
}


#endif
