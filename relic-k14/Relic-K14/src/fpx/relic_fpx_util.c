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
 * Implementation of utilities in extensions defined over prime fields.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_copy(fp2_t c, const fp2_t a) {
	fp_copy(c[0], a[0]);
	fp_copy(c[1], a[1]);
}

void fp2_zero(fp2_t a) {
	fp_zero(a[0]);
	fp_zero(a[1]);
}

int fp2_is_zero(const fp2_t a) {
	return fp_is_zero(a[0]) && fp_is_zero(a[1]);
}

void fp2_rand(fp2_t a) {
	fp_rand(a[0]);
	fp_rand(a[1]);
}

void fp2_print(const fp2_t a) {
	fp_print(a[0]);
	fp_print(a[1]);
}

int fp2_size_bin(fp2_t a, int pack) {
	if (pack) {
		if (fp2_test_cyc(a)) {
			return RLC_FP_BYTES + 1;
		} else {
			return 2 * RLC_FP_BYTES;
		}
	} else {
		return 2 * RLC_FP_BYTES;
	}
}

void fp2_read_bin(fp2_t a, const uint8_t *bin, size_t len) {
	if (len != RLC_FP_BYTES + 1 && len != 2 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	if (len == RLC_FP_BYTES + 1) {
		fp_read_bin(a[0], bin, RLC_FP_BYTES);
		fp_zero(a[1]);
		fp_set_bit(a[1], 0, bin[RLC_FP_BYTES]);
		fp2_upk(a, a);
	}
	if (len == 2 * RLC_FP_BYTES) {
		fp_read_bin(a[0], bin, RLC_FP_BYTES);
		fp_read_bin(a[1], bin + RLC_FP_BYTES, RLC_FP_BYTES);
	}
}

void fp2_write_bin(uint8_t *bin, size_t len, const fp2_t a, int pack) {
	fp2_t t;

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);

		if (pack && fp2_test_cyc(a)) {
			if (len < RLC_FP_BYTES + 1) {
				RLC_THROW(ERR_NO_BUFFER);
				return;
			} else {
				fp2_pck(t, a);
				fp_write_bin(bin, RLC_FP_BYTES, t[0]);
				bin[RLC_FP_BYTES] = fp_get_bit(t[1], 0);
			}
		} else {
			if (len < 2 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
				return;
			} else {
				fp_write_bin(bin, RLC_FP_BYTES, a[0]);
				fp_write_bin(bin + RLC_FP_BYTES, RLC_FP_BYTES, a[1]);
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t);
	}
}

void fp2_set_dig(fp2_t a, const dig_t b) {
	fp_set_dig(a[0], b);
	fp_zero(a[1]);
}

void fp3_copy(fp3_t c, const fp3_t a) {
	fp_copy(c[0], a[0]);
	fp_copy(c[1], a[1]);
	fp_copy(c[2], a[2]);
}

void fp3_zero(fp3_t a) {
	fp_zero(a[0]);
	fp_zero(a[1]);
	fp_zero(a[2]);
}

int fp3_is_zero(const fp3_t a) {
	return fp_is_zero(a[0]) && fp_is_zero(a[1]) && fp_is_zero(a[2]);
}

void fp3_rand(fp3_t a) {
	fp_rand(a[0]);
	fp_rand(a[1]);
	fp_rand(a[2]);
}

void fp3_print(const fp3_t a) {
	fp_print(a[0]);
	fp_print(a[1]);
	fp_print(a[2]);
}

int fp3_size_bin(fp3_t a) {
	return 3 * RLC_FP_BYTES;
}

void fp3_read_bin(fp3_t a, const uint8_t *bin, size_t len) {
	if (len != 3 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp_read_bin(a[0], bin, RLC_FP_BYTES);
	fp_read_bin(a[1], bin + RLC_FP_BYTES, RLC_FP_BYTES);
	fp_read_bin(a[2], bin + 2 * RLC_FP_BYTES, RLC_FP_BYTES);
}

void fp3_write_bin(uint8_t *bin, size_t len, const fp3_t a) {
	if (len != 3 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp_write_bin(bin, RLC_FP_BYTES, a[0]);
	fp_write_bin(bin + RLC_FP_BYTES, RLC_FP_BYTES, a[1]);
	fp_write_bin(bin + 2 * RLC_FP_BYTES, RLC_FP_BYTES, a[2]);
}

void fp3_set_dig(fp3_t a, const dig_t b) {
	fp_set_dig(a[0], b);
	fp_zero(a[1]);
	fp_zero(a[2]);
}

void fp4_copy(fp4_t c, const fp4_t a) {
	fp2_copy(c[0], a[0]);
	fp2_copy(c[1], a[1]);
}

void fp4_zero(fp4_t a) {
	fp2_zero(a[0]);
	fp2_zero(a[1]);
}

int fp4_is_zero(const fp4_t a) {
	return fp2_is_zero(a[0]) && fp2_is_zero(a[1]);
}

void fp4_rand(fp4_t a) {
	fp2_rand(a[0]);
	fp2_rand(a[1]);
}

void fp4_print(const fp4_t a) {
	fp2_print(a[0]);
	fp2_print(a[1]);
}

int fp4_size_bin(fp4_t a) {
	return 4 * RLC_FP_BYTES;
}

void fp4_read_bin(fp4_t a, const uint8_t *bin, size_t len) {
	if (len != 4 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp2_read_bin(a[0], bin, 2 * RLC_FP_BYTES);
	fp2_read_bin(a[1], bin + 2 * RLC_FP_BYTES, 2 * RLC_FP_BYTES);
}

void fp4_write_bin(uint8_t *bin, size_t len, const fp4_t a) {
	if (len != 4 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp2_write_bin(bin, 2 * RLC_FP_BYTES, a[0], 0);
	fp2_write_bin(bin + 2 * RLC_FP_BYTES, 2 * RLC_FP_BYTES, a[1], 0);
}

void fp4_set_dig(fp4_t a, const dig_t b) {
	fp2_set_dig(a[0], b);
	fp2_zero(a[1]);
}

void fp6_copy(fp6_t c, const fp6_t a) {
	fp2_copy(c[0], a[0]);
	fp2_copy(c[1], a[1]);
	fp2_copy(c[2], a[2]);
}

void fp6_zero(fp6_t a) {
	fp2_zero(a[0]);
	fp2_zero(a[1]);
	fp2_zero(a[2]);
}

int fp6_is_zero(const fp6_t a) {
	return fp2_is_zero(a[0]) && fp2_is_zero(a[1]) && fp2_is_zero(a[2]);
}

void fp6_rand(fp6_t a) {
	fp2_rand(a[0]);
	fp2_rand(a[1]);
	fp2_rand(a[2]);
}

void fp6_print(const fp6_t a) {
	fp2_print(a[0]);
	fp2_print(a[1]);
	fp2_print(a[2]);
}

int fp6_size_bin(fp6_t a) {
	return 6 * RLC_FP_BYTES;
}

void fp6_read_bin(fp6_t a, const uint8_t *bin, size_t len) {
	if (len != 6 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp2_read_bin(a[0], bin, 2 * RLC_FP_BYTES);
	fp2_read_bin(a[1], bin + 2 * RLC_FP_BYTES, 2 * RLC_FP_BYTES);
	fp2_read_bin(a[2], bin + 4 * RLC_FP_BYTES, 2 * RLC_FP_BYTES);
}

void fp6_write_bin(uint8_t *bin, size_t len, const fp6_t a) {
	if (len != 6 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp2_write_bin(bin, 2 * RLC_FP_BYTES, a[0], 0);
	fp2_write_bin(bin + 2 * RLC_FP_BYTES, 2 * RLC_FP_BYTES, a[1], 0);
	fp2_write_bin(bin + 4 * RLC_FP_BYTES, 2 * RLC_FP_BYTES, a[2], 0);
}

void fp6_set_dig(fp6_t a, const dig_t b) {
	fp2_set_dig(a[0], b);
	fp2_zero(a[1]);
	fp2_zero(a[2]);
}


void fp7_copy(fp7_t c, const fp7_t a) {
	fp_copy(c[0], a[0]);
	fp_copy(c[1], a[1]);
	fp_copy(c[2], a[2]);
	fp_copy(c[3], a[3]);
	fp_copy(c[4], a[4]);
	fp_copy(c[5], a[5]);
	fp_copy(c[6], a[6]);
}

void fp7_zero(fp7_t a) {
	fp_zero(a[0]);
	fp_zero(a[1]);
	fp_zero(a[2]);
	fp_zero(a[3]);
	fp_zero(a[4]);
	fp_zero(a[5]);
	fp_zero(a[6]);
}

int fp7_is_zero(const fp7_t a) {
	return fp_is_zero(a[0]) && fp_is_zero(a[1]) && fp_is_zero(a[2]) && fp_is_zero(a[3]) && fp_is_zero(a[4]) && fp_is_zero(a[5]) && fp_is_zero(a[6]);
}

void fp7_print(const fp7_t a) {
	fp_print(a[0]);
	fp_print(a[1]);
	fp_print(a[2]);
	fp_print(a[3]);
	fp_print(a[4]);
	fp_print(a[5]);
	fp_print(a[6]);	
}

void fp7_rand(fp7_t a) {
	fp_rand(a[0]);
	fp_rand(a[1]);
	fp_rand(a[2]);
	fp_rand(a[3]);
	fp_rand(a[4]);
	fp_rand(a[5]);
	fp_rand(a[6]);	
}


void fp7_set_dig(fp7_t a, const dig_t b) {
	fp_set_dig(a[0], b);
	fp_zero(a[1]);
	fp_zero(a[2]);
	fp_zero(a[3]);
	fp_zero(a[4]);
	fp_zero(a[5]);
	fp_zero(a[6]);
}




int fp7_is_square(const fp7_t a) {
	int r = -1;
	fp_t u;
	fp7_t t0;
	fp7_t t1;
 
    fp_null(u);
	fp7_null(t0);
	fp7_null(t1);

	if (fp7_is_zero(a)) {
		return 1;
	}

	RLC_TRY {
		fp7_new(t0);
		fp7_new(t1);
    		fp7_frb(t0, a, 1);//a^p
		fp7_frb(t1, a, 2);//a^(p^2)
		fp7_mul(t0, t0, t1);
		fp7_frb(t1, a, 3);//a^(p^3)
		fp7_mul(t0, t0, t1);//a^p*a^(p^2)*a^(p^3)
		fp7_frb(t1, t0, 3);//a^(p^4)*a^(p^5)*a^(p^6)

		fp7_mul(t0, t0, t1);
		fp7_mul(t0, t0, a);
		fp_srt(u, t0[0]);

		fp_sqr(u,u);
		 if(fp_cmp(u, t0[0]) == RLC_EQ)
		 {
			 r = 1;
		 } 
		
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp7_free(t0);
		fp7_free(t1);
		fp_free(u);
	}
	return r;
}




void fp8_copy(fp8_t c, const fp8_t a) {
	fp4_copy(c[0], a[0]);
	fp4_copy(c[1], a[1]);
}

void fp8_zero(fp8_t a) {
	fp4_zero(a[0]);
	fp4_zero(a[1]);
}

int fp8_is_zero(const fp8_t a) {
	return fp4_is_zero(a[0]) && fp4_is_zero(a[1]);
}

void fp8_rand(fp8_t a) {
	fp4_rand(a[0]);
	fp4_rand(a[1]);
}

void fp8_print(const fp8_t a) {
	fp4_print(a[0]);
	fp4_print(a[1]);
}

int fp8_size_bin(fp8_t a, int pack) {
	if (pack) {
		if (fp8_test_cyc(a)) {
			return 4 * RLC_FP_BYTES;
		} else {
			return 8 * RLC_FP_BYTES;
		}
	} else {
		return 8 * RLC_FP_BYTES;
	}
}

void fp8_read_bin(fp8_t a, const uint8_t *bin, size_t len) {
	if (len != 8 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp4_read_bin(a[0], bin, 4 * RLC_FP_BYTES);
	fp4_read_bin(a[1], bin + 4 * RLC_FP_BYTES, 4 * RLC_FP_BYTES);
}

void fp8_write_bin(uint8_t *bin, size_t len, const fp8_t a) {
	if (len != 8 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp4_write_bin(bin, 4 * RLC_FP_BYTES, a[0]);
	fp4_write_bin(bin + 4 * RLC_FP_BYTES, 4 * RLC_FP_BYTES, a[1]);
}

void fp8_set_dig(fp8_t a, const dig_t b) {
	fp4_set_dig(a[0], b);
	fp4_zero(a[1]);
}

void fp9_copy(fp9_t c, const fp9_t a) {
	fp3_copy(c[0], a[0]);
	fp3_copy(c[1], a[1]);
	fp3_copy(c[2], a[2]);
}

void fp9_zero(fp9_t a) {
	fp3_zero(a[0]);
	fp3_zero(a[1]);
	fp3_zero(a[2]);
}

int fp9_is_zero(const fp9_t a) {
	return fp3_is_zero(a[0]) && fp3_is_zero(a[1]) && fp3_is_zero(a[2]);
}

void fp9_rand(fp9_t a) {
	fp3_rand(a[0]);
	fp3_rand(a[1]);
	fp3_rand(a[2]);
}

void fp9_print(const fp9_t a) {
	fp3_print(a[0]);
	fp3_print(a[1]);
	fp3_print(a[2]);
}

int fp9_size_bin(fp9_t a) {
	return 9 * RLC_FP_BYTES;
}

void fp9_read_bin(fp9_t a, const uint8_t *bin, size_t len) {
	if (len != 9 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp3_read_bin(a[0], bin, 3 * RLC_FP_BYTES);
	fp3_read_bin(a[1], bin + 3 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
	fp3_read_bin(a[2], bin + 6 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
}

void fp9_write_bin(uint8_t *bin, size_t len, const fp9_t a) {
	if (len != 9 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp3_write_bin(bin, 3 * RLC_FP_BYTES, a[0]);
	fp3_write_bin(bin + 3 * RLC_FP_BYTES, 3 * RLC_FP_BYTES, a[1]);
	fp3_write_bin(bin + 6 * RLC_FP_BYTES, 3 * RLC_FP_BYTES, a[2]);
}

void fp9_set_dig(fp9_t a, const dig_t b) {
	fp3_set_dig(a[0], b);
	fp3_zero(a[1]);
	fp3_zero(a[2]);
}

void fp12_copy(fp12_t c, const fp12_t a) {
	fp6_copy(c[0], a[0]);
	fp6_copy(c[1], a[1]);
}

void fp12_zero(fp12_t a) {
	fp6_zero(a[0]);
	fp6_zero(a[1]);
}

int fp12_is_zero(const fp12_t a) {
	return (fp6_is_zero(a[0]) && fp6_is_zero(a[1]));
}

void fp12_rand(fp12_t a) {
	fp6_rand(a[0]);
	fp6_rand(a[1]);
}

void fp12_print(const fp12_t a) {
	fp6_print(a[0]);
	fp6_print(a[1]);
}

int fp12_size_bin(fp12_t a, int pack) {
	if (pack) {
		if (fp12_test_cyc(a)) {
			return 8 * RLC_FP_BYTES;
		} else {
			return 12 * RLC_FP_BYTES;
		}
	} else {
		return 12 * RLC_FP_BYTES;
	}
}

void fp12_read_bin(fp12_t a, const uint8_t *bin, size_t len) {
	if (len != 8 * RLC_FP_BYTES && len != 12 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	if (len == 8 * RLC_FP_BYTES) {
		fp2_zero(a[0][0]);
		fp2_read_bin(a[0][1], bin, 2 * RLC_FP_BYTES);
		fp2_read_bin(a[0][2], bin + 2 * RLC_FP_BYTES, 2 * RLC_FP_BYTES);
		fp2_read_bin(a[1][0], bin + 4 * RLC_FP_BYTES, 2 * RLC_FP_BYTES);
		fp2_zero(a[1][1]);
		fp2_read_bin(a[1][2], bin + 6 * RLC_FP_BYTES, 2 * RLC_FP_BYTES);
		fp12_back_cyc(a, a);
	}
	if (len == 12 * RLC_FP_BYTES) {
		fp6_read_bin(a[0], bin, 6 * RLC_FP_BYTES);
		fp6_read_bin(a[1], bin + 6 * RLC_FP_BYTES, 6 * RLC_FP_BYTES);
	}
}

void fp12_write_bin(uint8_t *bin, size_t len, const fp12_t a, int pack) {
	fp12_t t;

	fp12_null(t);

	RLC_TRY {
		fp12_new(t);

		if (pack) {
			if (len != 8 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp12_pck(t, a);
			fp2_write_bin(bin, 2 * RLC_FP_BYTES, a[0][1], 0);
			fp2_write_bin(bin + 2 * RLC_FP_BYTES, 2 * RLC_FP_BYTES, a[0][2], 0);
			fp2_write_bin(bin + 4 * RLC_FP_BYTES, 2 * RLC_FP_BYTES, a[1][0], 0);
			fp2_write_bin(bin + 6 * RLC_FP_BYTES, 2 * RLC_FP_BYTES, a[1][2], 0);
		} else {
			if (len != 12 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp6_write_bin(bin, 6 * RLC_FP_BYTES, a[0]);
			fp6_write_bin(bin + 6 * RLC_FP_BYTES, 6 * RLC_FP_BYTES, a[1]);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp12_free(t);
	}
}

void fp12_set_dig(fp12_t a, const dig_t b) {
	fp6_set_dig(a[0], b);
	fp6_zero(a[1]);
}

void fp13_copy(fp13_t c, const fp13_t a)
{
	fp13_do_2(fp_copy, c, a);
}

void fp13_zero(fp13_t a)
{
	fp13_do_1(fp_zero, a);
}

int fp13_is_zero(const fp13_t a)
{
	return fp_is_zero(a[0]) && fp_is_zero(a[1]) && fp_is_zero(a[2]) && fp_is_zero(a[3]) && fp_is_zero(a[4]) && fp_is_zero(a[5]) && fp_is_zero(a[6]) && fp_is_zero(a[7]) && fp_is_zero(a[8]) && fp_is_zero(a[9]) && fp_is_zero(a[10]) && fp_is_zero(a[11]) && fp_is_zero(a[12]);
}

void fp13_rand(fp13_t a)
{
	fp13_do_1(fp_rand, a);
}

void fp13_print(const fp13_t a)
{
	fp13_do_1(fp_print, a);
}


void fp13_read_bin(fp13_t a, uint8_t* bin, int len)
{
	if (len != 13 * RLC_FP_BYTES)
		RLC_THROW(ERR_NO_BUFFER);
	fp_read_bin(a[0], bin, RLC_FP_BYTES);
	fp_read_bin(a[1], bin + RLC_FP_BYTES, RLC_FP_BYTES);
	fp_read_bin(a[2], bin + 2 * RLC_FP_BYTES, RLC_FP_BYTES);
	fp_read_bin(a[3], bin + 3 * RLC_FP_BYTES, RLC_FP_BYTES);
	fp_read_bin(a[4], bin + 4 * RLC_FP_BYTES, RLC_FP_BYTES);
	fp_read_bin(a[5], bin + 5 * RLC_FP_BYTES, RLC_FP_BYTES);
	fp_read_bin(a[6], bin + 6 * RLC_FP_BYTES, RLC_FP_BYTES);
	fp_read_bin(a[7], bin + 7 * RLC_FP_BYTES, RLC_FP_BYTES);
	fp_read_bin(a[8], bin + 8 * RLC_FP_BYTES, RLC_FP_BYTES);
	fp_read_bin(a[9], bin + 9 * RLC_FP_BYTES, RLC_FP_BYTES);
	fp_read_bin(a[10], bin + 10 * RLC_FP_BYTES, RLC_FP_BYTES);
	fp_read_bin(a[11], bin + 11 * RLC_FP_BYTES, RLC_FP_BYTES);
	fp_read_bin(a[12], bin + 12 * RLC_FP_BYTES, RLC_FP_BYTES);
}

void fp13_set_dig(fp13_t a,const dig_t b){
	fp_set_dig(a[0],b);
	for(int i=1;i<13;i++)fp_zero(a[i]);
}


int fp13_is_square(const fp13_t a) {
	int r = -1;
	fp_t u;
	fp13_t t0;
	fp13_t t1;
 
    fp_null(u);
	fp13_null(t0);
	fp13_null(t1);

	if (fp13_is_zero(a)) {
		return 1;
	}

	RLC_TRY {
		fp13_new(t0);
		fp13_new(t1);
    	fp13_frb(t0, a, 1);//a^p
		fp13_frb(t1, a, 2);//a^(p^2)
		fp13_mul(t0, t0, t1);
		fp13_frb(t1, a, 3);//a^(p^3)
		fp13_mul(t0, t0, t1);//a^p*a^(p^2)*a^(p^3)
		fp13_frb(t1, t0, 3);//a^(p^4)*a^(p^5)*a^(p^6)
		fp13_mul(t0, t0, t1);//a^p*a^(p^2)*...*a^(p^6)
		fp13_frb(t1, t0, 6);//a^(p^7)*...*a^(p^12)
		fp13_mul(t0, t0, t1);
		fp13_mul(t0, t0, a);
		fp_srt(u, t0[0]);

		fp_sqr(u,u);
		 if(fp_cmp(u, t0[0]) == RLC_EQ)
		 {
			 r = 1;
		 } 
		
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp13_free(t0);
		fp13_free(t1);
		fp_free(u);
	}
	return r;
}

void fp18_copy(fp18_t c, const fp18_t a) {
	fp9_copy(c[0], a[0]);
	fp9_copy(c[1], a[1]);
}

void fp18_zero(fp18_t a) {
	fp9_zero(a[0]);
	fp9_zero(a[1]);
}

int fp18_is_zero(const fp18_t a) {
	return (fp9_is_zero(a[0]) && fp9_is_zero(a[1]));
}

void fp18_rand(fp18_t a) {
	fp9_rand(a[0]);
	fp9_rand(a[1]);
}

void fp18_print(const fp18_t a) {
	fp9_print(a[0]);
	fp9_print(a[1]);
}

int fp18_size_bin(fp18_t a, int pack) {
	if (pack) {
		if (fp18_test_cyc(a)) {
			return 12 * RLC_FP_BYTES;
		} else {
			return 18 * RLC_FP_BYTES;
		}
	} else {
		return 18 * RLC_FP_BYTES;
	}
}

void fp18_read_bin(fp18_t a, const uint8_t *bin, size_t len) {
	if (len != 12 * RLC_FP_BYTES && len != 18 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	if (len == 12 * RLC_FP_BYTES) {
		fp3_zero(a[0][0]);
		fp3_read_bin(a[0][1], bin, 3 * RLC_FP_BYTES);
		fp3_read_bin(a[0][2], bin + 3 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
		fp3_read_bin(a[1][0], bin + 6 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
		fp3_zero(a[1][1]);
		fp3_read_bin(a[1][2], bin + 9 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
		fp18_back_cyc(a, a);
	}
	if (len == 18 * RLC_FP_BYTES) {
		fp9_read_bin(a[0], bin, 9 * RLC_FP_BYTES);
		fp9_read_bin(a[1], bin + 9 * RLC_FP_BYTES, 9 * RLC_FP_BYTES);
	}
}

void fp18_write_bin(uint8_t *bin, size_t len, const fp18_t a, int pack) {
	fp18_t t;

	fp18_null(t);

	RLC_TRY {
		fp18_new(t);

		if (pack) {
			if (len != 12 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp18_pck(t, a);
			fp3_write_bin(bin, 3 * RLC_FP_BYTES, a[0][1]);
			fp3_write_bin(bin + 3 * RLC_FP_BYTES, 3 * RLC_FP_BYTES, a[0][2]);
			fp3_write_bin(bin + 6 * RLC_FP_BYTES, 3 * RLC_FP_BYTES, a[1][0]);
			fp3_write_bin(bin + 9 * RLC_FP_BYTES, 3 * RLC_FP_BYTES, a[1][2]);
		} else {
			if (len != 18 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp9_write_bin(bin, 9 * RLC_FP_BYTES, a[0]);
			fp9_write_bin(bin + 9 * RLC_FP_BYTES, 9 * RLC_FP_BYTES, a[1]);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp18_free(t);
	}
}

void fp18_set_dig(fp18_t a, const dig_t b) {
	fp9_set_dig(a[0], b);
	fp9_zero(a[1]);
}

void fp24_copy(fp24_t c, const fp24_t a) {
	fp8_copy(c[0], a[0]);
	fp8_copy(c[1], a[1]);
	fp8_copy(c[2], a[2]);
}

void fp24_zero(fp24_t a) {
	fp8_zero(a[0]);
	fp8_zero(a[1]);
	fp8_zero(a[2]);
}

int fp24_is_zero(const fp24_t a) {
	return fp8_is_zero(a[0]) && fp8_is_zero(a[1]) && fp8_is_zero(a[2]);
}

void fp24_rand(fp24_t a) {
	fp8_rand(a[0]);
	fp8_rand(a[1]);
	fp8_rand(a[2]);
}

void fp24_print(const fp24_t a) {
	fp8_print(a[0]);
	fp8_print(a[1]);
	fp8_print(a[2]);
}

int fp24_size_bin(fp24_t a, int pack) {
	if (pack) {
		if (fp24_test_cyc(a)) {
			return 16 * RLC_FP_BYTES;
		} else {
			return 24 * RLC_FP_BYTES;
		}
	} else {
		return 24 * RLC_FP_BYTES;
	}
}

void fp24_read_bin(fp24_t a, const uint8_t *bin, size_t len) {
	if (len != 16 * RLC_FP_BYTES && len != 24 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	if (len == 16 * RLC_FP_BYTES) {
		fp4_zero(a[0][0]);
		fp4_zero(a[0][1]);
		fp4_read_bin(a[1][0], bin, 4 * RLC_FP_BYTES);
		fp4_read_bin(a[1][1], bin + 4 * RLC_FP_BYTES, 4 * RLC_FP_BYTES);
		fp4_read_bin(a[2][0], bin + 8 * RLC_FP_BYTES, 4 * RLC_FP_BYTES);
		fp4_read_bin(a[2][1], bin + 12 * RLC_FP_BYTES, 4 * RLC_FP_BYTES);
		fp24_back_cyc(a, a);
	}
	if (len == 24 * RLC_FP_BYTES) {
		fp8_read_bin(a[0], bin, 8 * RLC_FP_BYTES);
		fp8_read_bin(a[1], bin + 8 * RLC_FP_BYTES, 8 * RLC_FP_BYTES);
		fp8_read_bin(a[2], bin + 16 * RLC_FP_BYTES, 8 * RLC_FP_BYTES);
	}
}

void fp24_write_bin(uint8_t *bin, size_t len, const fp24_t a, int pack) {
	fp24_t t;

	fp24_null(t);

	RLC_TRY {
		fp24_new(t);

		if (pack) {
			if (len != 16 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp24_pck(t, a);
			fp4_write_bin(bin, 4 * RLC_FP_BYTES, a[1][0]);
			fp4_write_bin(bin + 4 * RLC_FP_BYTES, 4 * RLC_FP_BYTES, a[1][1]);
			fp4_write_bin(bin + 8 * RLC_FP_BYTES, 4 * RLC_FP_BYTES, a[2][0]);
			fp4_write_bin(bin + 12 * RLC_FP_BYTES, 4 * RLC_FP_BYTES, a[2][1]);
		} else {
			if (len != 24 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp8_write_bin(bin, 8 * RLC_FP_BYTES, a[0]);
			fp8_write_bin(bin + 8 * RLC_FP_BYTES, 8 * RLC_FP_BYTES, a[1]);
			fp8_write_bin(bin + 16 * RLC_FP_BYTES, 8 * RLC_FP_BYTES, a[2]);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp24_free(t);
	}
}

void fp24_set_dig(fp24_t a, const dig_t b) {
	fp8_set_dig(a[0], b);
	fp8_zero(a[1]);
	fp8_zero(a[2]);
}

void fp48_copy(fp48_t c, const fp48_t a) {
	fp24_copy(c[0], a[0]);
	fp24_copy(c[1], a[1]);
}

void fp48_zero(fp48_t a) {
	fp24_zero(a[0]);
	fp24_zero(a[1]);
}

int fp48_is_zero(const fp48_t a) {
	return (fp24_is_zero(a[0]) && fp24_is_zero(a[1]));
}

void fp48_rand(fp48_t a) {
	fp24_rand(a[0]);
	fp24_rand(a[1]);
}

void fp48_print(const fp48_t a) {
	fp24_print(a[0]);
	fp24_print(a[1]);
}

int fp48_size_bin(fp48_t a, int pack) {
	if (pack) {
		if (fp48_test_cyc(a)) {
			return 32 * RLC_FP_BYTES;
		} else {
			return 48 * RLC_FP_BYTES;
		}
	} else {
		return 48 * RLC_FP_BYTES;
	}
}

void fp48_read_bin(fp48_t a, const uint8_t *bin, size_t len) {
	if (len != 32 * RLC_FP_BYTES && len != 48 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	if (len == 32 * RLC_FP_BYTES) {
		fp8_zero(a[0][0]);
		fp8_read_bin(a[0][1], bin, 8 * RLC_FP_BYTES);
		fp8_read_bin(a[0][2], bin + 8 * RLC_FP_BYTES, 8 * RLC_FP_BYTES);
		fp8_read_bin(a[1][0], bin + 16 * RLC_FP_BYTES, 8 * RLC_FP_BYTES);
		fp8_zero(a[1][1]);
		fp8_read_bin(a[1][2], bin + 24 * RLC_FP_BYTES, 8 * RLC_FP_BYTES);
		fp48_back_cyc(a, a);
	}
	if (len == 48 * RLC_FP_BYTES) {
		fp24_read_bin(a[0], bin, 24 * RLC_FP_BYTES);
		fp24_read_bin(a[1], bin + 24 * RLC_FP_BYTES, 24 * RLC_FP_BYTES);
	}
}

void fp48_write_bin(uint8_t *bin, size_t len, const fp48_t a, int pack) {
	fp48_t t;

	fp48_null(t);

	RLC_TRY {
		fp48_new(t);

		if (pack) {
			if (len != 32 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp48_pck(t, a);
			fp8_write_bin(bin, 8 * RLC_FP_BYTES, a[0][1]);
			fp8_write_bin(bin + 8 * RLC_FP_BYTES, 8 * RLC_FP_BYTES, a[0][2]);
			fp8_write_bin(bin + 16 * RLC_FP_BYTES, 8 * RLC_FP_BYTES, a[1][0]);
			fp8_write_bin(bin + 24 * RLC_FP_BYTES, 8 * RLC_FP_BYTES, a[1][2]);
		} else {
			if (len != 48 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp24_write_bin(bin, 24 * RLC_FP_BYTES, a[0], 0);
			fp24_write_bin(bin + 24 * RLC_FP_BYTES, 24 * RLC_FP_BYTES, a[1], 0);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp48_free(t);
	}
}

void fp48_set_dig(fp48_t a, const dig_t b) {
	fp24_set_dig(a[0], b);
	fp24_zero(a[1]);
}

void fp54_copy(fp54_t c, const fp54_t a) {
	fp18_copy(c[0], a[0]);
	fp18_copy(c[1], a[1]);
	fp18_copy(c[2], a[2]);
}

void fp54_zero(fp54_t a) {
	fp18_zero(a[0]);
	fp18_zero(a[1]);
	fp18_zero(a[2]);
}

int fp54_is_zero(const fp54_t a) {
	return (fp18_is_zero(a[0]) && fp18_is_zero(a[1]) && fp18_is_zero(a[2]));
}

void fp54_rand(fp54_t a) {
	fp18_rand(a[0]);
	fp18_rand(a[1]);
	fp18_rand(a[2]);
}

void fp54_print(const fp54_t a) {
	fp18_print(a[0]);
	fp18_print(a[1]);
	fp18_print(a[2]);
}

int fp54_size_bin(fp54_t a, int pack) {
	if (pack) {
		if (fp54_test_cyc(a)) {
			return 36 * RLC_FP_BYTES;
		} else {
			return 54 * RLC_FP_BYTES;
		}
	} else {
		return 54 * RLC_FP_BYTES;
	}
}

void fp54_read_bin(fp54_t a, const uint8_t *bin, size_t len) {
	if (len != 36 * RLC_FP_BYTES && len != 54 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	if (len == 36 * RLC_FP_BYTES) {
		fp9_zero(a[0][0]);
		fp9_zero(a[0][1]);
		fp9_read_bin(a[1][0], bin, 9 * RLC_FP_BYTES);
		fp9_read_bin(a[1][1], bin + 9 * RLC_FP_BYTES, 9 * RLC_FP_BYTES);
		fp9_read_bin(a[2][0], bin + 18 * RLC_FP_BYTES, 9 * RLC_FP_BYTES);
		fp9_read_bin(a[2][1], bin + 27 * RLC_FP_BYTES, 9 * RLC_FP_BYTES);
		fp54_back_cyc(a, a);
	}
	if (len == 54 * RLC_FP_BYTES) {
		fp18_read_bin(a[0], bin, 18 * RLC_FP_BYTES);
		fp18_read_bin(a[1], bin + 18 * RLC_FP_BYTES, 18 * RLC_FP_BYTES);
		fp18_read_bin(a[2], bin + 36 * RLC_FP_BYTES, 18 * RLC_FP_BYTES);
	}
}

void fp54_write_bin(uint8_t *bin, size_t len, const fp54_t a, int pack) {
	fp54_t t;

	fp54_null(t);

	RLC_TRY {
		fp54_new(t);

		if (pack) {
			if (len != 36 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp54_pck(t, a);
			fp9_write_bin(bin, 9 * RLC_FP_BYTES, a[1][0]);
			fp9_write_bin(bin + 9 * RLC_FP_BYTES, 9 * RLC_FP_BYTES, a[1][1]);
			fp9_write_bin(bin + 18 * RLC_FP_BYTES, 9 * RLC_FP_BYTES, a[2][0]);
			fp9_write_bin(bin + 27 * RLC_FP_BYTES, 9 * RLC_FP_BYTES, a[2][1]);
		} else {
			if (len != 54 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp18_write_bin(bin, 18 * RLC_FP_BYTES, a[0], 0);
			fp18_write_bin(bin + 18 * RLC_FP_BYTES, 18 * RLC_FP_BYTES, a[1], 0);
			fp18_write_bin(bin + 36 * RLC_FP_BYTES, 18 * RLC_FP_BYTES, a[2], 0);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp54_free(t);
	}
}

void fp54_set_dig(fp54_t a, dig_t b) {
	fp18_set_dig(a[0], b);
	fp18_zero(a[1]);
	fp18_zero(a[2]);
}


void fp14_copy(fp14_t c, const fp14_t a) {
	fp7_copy(c[0], a[0]);
	fp7_copy(c[1], a[1]);
	
}

void fp14_zero(fp14_t a) {
	fp7_zero(a[0]);
	fp7_zero(a[1]);
}

int fp14_is_zero(const fp14_t a) {
	return fp7_is_zero(a[0]) && fp7_is_zero(a[1]);
}

void fp14_print(const fp14_t a) {
	fp7_print(a[0]);
	fp7_print(a[1]);
}

void fp14_rand(fp14_t a) {
	fp7_rand(a[0]);
	fp7_rand(a[1]);
}


void fp14_set_dig(fp14_t a, const dig_t b) {
	fp7_set_dig(a[0], b);
	fp7_zero(a[1]);
}

