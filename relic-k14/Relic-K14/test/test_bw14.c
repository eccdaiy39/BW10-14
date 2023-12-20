#include <stdio.h>
#include "relic.h"
#include "relic_test.h"
#include "relic_pp.h"
int test1(void){
		
	int code = RLC_ERR;
	g1_t a;
	uint8_t msg[5];

	g1_null(a);

	RLC_TRY {
		g1_new(a);

		TEST_CASE("validity test is correct") {
			g1_set_infty(a);
			TEST_ASSERT(!g1_is_valid(a), end);
			g1_rand(a);
			TEST_ASSERT(g1_is_valid(a), end);
		}
		TEST_END;

	TEST_CASE("point hashing is correct") {
			rand_bytes(msg, sizeof(msg));
			g1_map(a, msg, sizeof(msg));
			TEST_ASSERT(g1_is_valid(a), end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	g1_free(a);
	return code;

}

int test2(void){
	int code = RLC_ERR;
        ep7_t q1, q2, q3;
	uint8_t msg[5];
	ep7_null(q1);
	ep7_null(q2);
	ep7_null(q3);
	bn_t k, n;
	bn_null(n);
	bn_null(k);
	RLC_TRY {
		ep7_new(q1);
		ep7_new(q2);
		ep7_new(q3);
		bn_new(n);
		bn_new(k);
		pc_get_ord(n);

		TEST_CASE("validity test is correct") {
			ep7_set_infty(q1);
			TEST_ASSERT(!g2_is_valid_bw14(q1), end);
			ep7_rand(q2);
			TEST_ASSERT(g2_is_valid_bw14(q2), end);
		}
		TEST_END;
		TEST_CASE("point hashing is correct") {
			rand_bytes(msg, sizeof(msg));
			ep7_map(q1, msg, sizeof(msg));
			TEST_ASSERT(g2_is_valid_bw14(q1), end);
		}
		TEST_END;
		TEST_CASE("scalar multiplication in correct") {
			/* given q3 in G_2,  and k in Z_r,we first compute
                             q2=[n]q3 by using classic double-add algorithm.
			   Then we compute q1=[n]q3 by using our algorithm.
                           Finally, we check that q1=q2.*/
			ep7_rand(q3);
			bn_rand_mod(k, n);
			ep7_mul(q1, q3, k);
			ep7_mul_basic(q2, q3, k);
			TEST_ASSERT(ep7_cmp(q1, q2) == RLC_EQ, end);
			
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep7_free(q1);
	ep7_free(q2);
	ep7_free(q3);
	bn_free(n);
	bn_free(k);
	return code;	

}

int test3(void){
	int code = RLC_ERR;
	ep_t p[2];
	ep7_t q[2];
        fp14_t e1, e2, e3;
	bn_t k, n;
	ep_null(p[0]);
	ep_null(p[1]);
	ep7_null(q[0]);
	ep7_null(q[1]);
	fp14_null(e1);
	fp14_null(e2);
	fp14_null(e3);

	bn_null(n);
	bn_null(k);
	RLC_TRY {
		ep_new(p[0]);
		ep_new(p[1]);
		ep7_new(q[0]);
		ep7_new(q[1]);
		fp14_new(e1);
		fp14_new(e2);
		bn_new(n);
		bn_new(k);

		pc_get_ord(n);
		TEST_CASE("validity test is correct") {
			fp14_set_dig(e1,1);
			TEST_ASSERT(!gt_is_valid_bw14(e1), end);
			fp14_rand(e2);
			pp_exp_bwk14(e3,e2);
			TEST_ASSERT(gt_is_valid_bw14(e3), end);
		}
		TEST_END;


		TEST_CASE("exponentiation is correct") {
			/* given e3 in G_T,  and k in Z_r,we first compute
                             e2=e3^n by using classic square-mulplication algorithm.
			   Then we comapyte e1=e3^n by using our algorithm.
                           Finally, we check that e1=e2.
		
                           
			*/ 
			fp14_rand(e2);
			pp_exp_bwk14(e3, e2);

			bn_rand_mod(k, n);
			fp14_exp_cyc(e1, e3, k);
			fp14_exp(e2, e3, k);
			TEST_ASSERT(fp14_cmp(e1, e2) == RLC_EQ, end);
	
		} TEST_END;

		TEST_CASE("pairing is bilinear") {
			/* given p[0] in G1, q[0] in G2 and k in Z_r, checking that 
				e(p[0], k*q[0])=e(k*p[0], q[0])=e(p[0], q[0])^k
			*/ 	
			ep_rand(p[0]);
			ep7_rand(q[0]);
			bn_rand_mod(k, n);
			ep_mul(p[1], p[0], k);
			ep7_mul(q[1], q[0], k);
			pp_map_sup_oatep_k14(e1, p[1], q[0]);
			pp_map_sup_oatep_k14(e2, p[0], q[1]);
			pp_map_sup_oatep_k14(e3, p[0], q[0]);
			fp14_exp_cyc(e3, e3, k);
			TEST_ASSERT(fp14_cmp(e1, e2) == RLC_EQ, end);
			TEST_ASSERT(fp14_cmp(e1, e3) == RLC_EQ, end);
		} TEST_END;


		TEST_CASE("multi-pairing is bilinear") {
			/* given p[0], p[1] in G1, q[0], q[1] in G2  checking that 
				e(p[0], q[0])*(p[0], q[0])=e_sim (p, q, 2), where e_sim 
				is the multi-pairing function
			*/ 	
			ep_rand(p[0]);
			ep_rand(p[1]);
			ep7_rand(q[0]);
			ep7_rand(q[1]);
			pp_map_sup_oatep_k14(e1, p[0], q[0]);
			pp_map_sup_oatep_k14(e2, p[1], q[1]);
			pp_map_sim_sup_oatep_k14(e3, p, q, 2);
			fp14_mul(e1, e1, e2);			
		TEST_ASSERT(fp14_cmp(e1, e3) == RLC_EQ, end);
		} TEST_END;

	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep_free(p1);
	ep_free(p2);
	ep7_free(q1);
	ep7_free(q2);
	fp14_free(f1);
	fp14_free(f2);
	bn_free(n);
	bn_free(k);
	return code;
}


int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Tests for the PC module:", 0);

	if (pc_param_set_any() != RLC_OK) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}

	pc_param_print();

	util_banner("Group G_1:", 0);
	if (test1() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Group G_2:", 0);
	if (test2() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Group G_T:", 0);
	if (test3() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("All tests have passed.\n", 0);

	core_clean();
	return 0;
}

