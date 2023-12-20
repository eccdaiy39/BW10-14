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
		BENCH_ADD(g1_is_valid(p));
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
	ep7_t p, q;
	bn_t k;
	ep7_null(p);
	ep7_new(p);
	ep7_null(q);
	ep7_new(q);
	bn_null(k);
        bn_new(k);
	BENCH_RUN("g2_map") {
		uint8_t msg[5];
		rand_bytes(msg, 5);
		BENCH_ADD(ep7_map(p, msg, 5));
	} BENCH_END;

	BENCH_RUN("g2_is_valid") {
		ep7_rand(p);
		BENCH_ADD(g2_is_valid_bw14(p));
	} BENCH_END;

	BENCH_RUN("g2_mul") {
		bn_rand(k, RLC_POS, 256);
		ep7_rand(p);
		BENCH_ADD(ep7_mul(q, p, k));
	}BENCH_END;

	ep7_free(p);
	ep7_free(q);
	bn_free(k);
}

static void Gt(void) {
	fp14_t h;
	fp14_null(h);
	fp14_new(h);
	bn_t  k;
	bn_null(k);
    bn_new(k);
	
	BENCH_RUN("gt_is_valid") {
		fp14_rand(h);
		pp_exp_bwk14(h, h); 
		BENCH_ADD(gt_is_valid_bw14(h));
	} BENCH_END;

	BENCH_RUN("gt_exp") {
		fp14_rand(h);
		pp_exp_bwk14(h, h);
		bn_rand(k, RLC_POS, 256);
		BENCH_ADD(fp14_exp_cyc(h, h, k));
	} BENCH_END;

	fp14_free(h);
	bn_free(k);
}

static void pairing(void) {
	int i;
	ep_t p[8];
	ep7_t q[8];
	fp14_t h;

	for(i=0; i<8; i++){
		ep_new(p[i]);
		ep7_new(q[i]);
	}

	fp14_new(h);

	BENCH_RUN("pp_exp_bwk14") {
		fp14_rand(h);
		BENCH_ADD(pp_exp_bwk14(h, h));
	} BENCH_END;


	BENCH_RUN("pp_map_sup_oatep_k14") {
		ep_rand(p[0]);
		ep7_rand(q[0]);
		BENCH_ADD(pp_map_sup_oatep_k14(h, p[0], q[0]));
	} BENCH_END;

	BENCH_RUN("pp_map_sim_sup_oatep_k14(2)") {
		for(i=0; i<2; i++){
			ep_rand(p[i]);
			ep7_rand(q[i]);
		}
		BENCH_ADD(pp_map_sim_sup_oatep_k14(h, p, q, 2));
	} BENCH_END;

	BENCH_RUN("pp_map_sim_sup_oatep_k14(5)") {
		for(i=0; i<5; i++){
			ep_rand(p[i]);
			ep7_rand(q[i]);
		}
		BENCH_ADD(pp_map_sim_sup_oatep_k14(h, p, q, 5));
	} BENCH_END;	

	BENCH_RUN("pp_map_sim_sup_oatep_k14(8)") {
		for(i=0; i<8; i++){
			ep_rand(p[i]);
			ep7_rand(q[i]);
		}
		BENCH_ADD(pp_map_sim_sup_oatep_k14(h, p, q, 8));
	} BENCH_END;	

for(i=0; i<8; i++){
		ep_free(p[i]);
		ep7_free(q[i]);
	}
	fp14_free(h);


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
