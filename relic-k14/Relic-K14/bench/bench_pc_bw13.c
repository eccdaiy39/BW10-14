/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2010 RELIC Authors
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
 * Benchmarks for Pairing-Based Cryptography.
 *
 * @ingroup bench
 */

#include <stdio.h>

#include "relic.h"
#include "relic_pc.h"
#include "relic_pp.h"
#include "relic_ep.h"
#include "relic_epx.h"
#include "relic_bench.h"



static void G1(void) {
	ep_t p, q;
	bn_t k;
	ep_null(p);
	ep_new(p);
	ep_null(q);
	ep_new(q);
	bn_null(k);
        bn_new(k);

	BENCH_RUN("g1_map") {
		uint8_t msg[5];
		rand_bytes(msg, 5);
		BENCH_ADD(ep_map(p, msg, 5));
	} BENCH_END;

	BENCH_RUN("g1_is_valid") {
		ep_rand(p);
		BENCH_ADD(g1_is_valid_bw13(p));
	} BENCH_END;

	BENCH_RUN("g1_mul") {
		bn_rand(k, RLC_POS, 256);
		ep_rand(p);
		BENCH_ADD(ep_mul(q, p, k));
	}BENCH_END;

	bn_free(k);
	ep_free(p);
}

static void G2(void) {
	ep13_t p, q;
	bn_t k;
	ep13_null(p);
	ep13_new(p);
	ep13_null(q);
	ep13_new(q);
	bn_null(k);
        bn_new(k);
	BENCH_RUN("g2_map") {
		uint8_t msg[5];
		rand_bytes(msg, 5);
		BENCH_ADD(ep13_map(p, msg, 5));
	} BENCH_END;

	BENCH_RUN("g2_is_valid") {
		ep13_rand(p);
		BENCH_ADD(g2_is_valid_bw13(p));
	} BENCH_END;

	BENCH_RUN("g2_mul") {
		bn_rand(k, RLC_POS, 256);
		ep13_rand(p);
		BENCH_ADD(ep13_mul(q, p, k));
	}BENCH_END;

	ep13_free(p);
	ep13_free(q);
	bn_free(k);
}

static void Gt(void) {
	fp13_t h0, h1;
	fp13_null(h0);
	fp13_null(h1);
	fp13_new(h0);
	fp13_new(h1);
	bn_t  k;
	bn_null(k);
    bn_new(k);
	
	BENCH_RUN("gt_is_valid") {
		fp13_rand(h0);
		fp13_rand(h1);
		pp_exp_bwk13(h0, h0, h1); 
		BENCH_ADD(gt_is_valid_bw13(h0));
	} BENCH_END;

	BENCH_RUN("gt_exp") {
		fp13_rand(h0);
		fp13_rand(h1);
		pp_exp_bwk13(h0, h0, h1);
		bn_rand(k, RLC_POS, 256);
		BENCH_ADD(fp13_exp_gt(h1, h0, k));
	} BENCH_END;

	fp13_free(h0);
	fp13_free(h1);
	bn_free(k);
}

static void pairing(void) {
	int i;
	ep_t p[8];
	ep13_t q[8];
	fp13_t h0, h1;

	for(i=0; i<8; i++){
		ep_new(p[i]);
		ep13_new(q[i]);
	}

	fp13_new(h0);
	fp13_new(h1);

	BENCH_RUN("pp_exp_bwk13") {
		fp13_rand(h0);
		fp13_rand(h1);
		BENCH_ADD(pp_exp_bwk13(h0, h0, h1));
	} BENCH_END;


	BENCH_RUN("pp_map_sup_oatep_k13") {
		ep_rand(p[0]);
		ep13_rand(q[0]);
		BENCH_ADD(pp_map_sup_oatep_k13(h0, p[0], q[0]));
	} BENCH_END;

	BENCH_RUN("pp_map_sim_sup_oatep_k13(2)") {
		for(i=0; i<2; i++){
			ep_rand(p[i]);
			ep13_rand(q[i]);
		}
		BENCH_ADD(pp_map_sim_sup_oatep_k13(h0, p, q, 2));
	} BENCH_END;

	BENCH_RUN("pp_map_sim_sup_oatep_k13(5)") {
		for(i=0; i<5; i++){
			ep_rand(p[i]);
			ep13_rand(q[i]);
		}
		BENCH_ADD(pp_map_sim_sup_oatep_k13(h0, p, q, 5));
	} BENCH_END;	

	BENCH_RUN("pp_map_sim_sup_oatep_k13(8)") {
		for(i=0; i<8; i++){
			ep_rand(p[i]);
			ep13_rand(q[i]);
		}
		BENCH_ADD(pp_map_sim_sup_oatep_k13(h0, p, q, 8));
	} BENCH_END;	

for(i=0; i<8; i++){
		ep_free(p[i]);
		ep13_free(q[i]);
	}
	fp13_free(h0);
	fp13_free(h1);

}

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	conf_print();



	if (ep_param_set_any_pairf() != RLC_OK) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}
	util_banner("G1:", 0);
	G1();
	util_banner("G2:", 0);
	G2();
	util_banner("Gt:", 0);
	Gt();
	util_banner("pairing:", 0);
	pairing();
	core_clean();
	return 0;
}
