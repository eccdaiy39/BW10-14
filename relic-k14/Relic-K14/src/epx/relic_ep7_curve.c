
#include <stdio.h>
#include "relic.h"
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
 * Implementation of the pairings over prime curves.
 *
 * @ingroup pp
 */
#define BW14_P340_A0		"0"
#define BW14_P340_A1		"0"
#define BW14_P340_A2		"0"
#define BW14_P340_A3		"0"
#define BW14_P340_A4		"0"
#define BW14_P340_A5		"0"
#define BW14_P340_A6		"0"
#define BW14_P340_B0		"0"
#define BW14_P340_B1		"0"
#define BW14_P340_B2		"0"
#define BW14_P340_B3		"0"
#define BW14_P340_B4		"5A77AE120FBF671689DFC2B57FB70967C361618E01D4F44EE303C5A1B72BE55346DAFF62C30F4BD49E281"
#define BW14_P340_B5		"0"
#define BW14_P340_B6		"0"
#define BW14_P340_X0		"745B7CA40DE496059D735254F38944398E9744CC41200B81149551F49B71AB435570F0D8192A1285148C"
#define BW14_P340_X1        "9802387418771A732F34F29CF6DB9613AA60E131E30870EEDCC175E6F264672E46A65153F629AA67BBC9B"
#define BW14_P340_X2		"3EED7F1734AF487204C624F481CDA9BA19A48476593686C245D5FD693A92B420365E8483F492B74C27E65"
#define BW14_P340_X3		"916F20AAEDF6A8211ADA9FC90AB9F40D61481DBA03151258A54715665DE5F1E7BC4A3DE0CE04BAF312567"
#define BW14_P340_X4		"7E7C46609F8E0684C320749898DE57A7EE54143ACD28ED5A8AA2098F420D53B9BA39A797B0B5CEA176A5C"
#define BW14_P340_X5		"827194CBA2918EC512768691A2FA7AEE9DD7A367A3556772625EA0D4F6C66210F4D5A2B7762E30A3A21B3"
#define BW14_P340_X6		"131563CCBEA39B01B0D5B98AAB0A7D3E9E36A8DDADCDBF0EB3426DF31D688AF17431A1883F6793955279A"
#define BW14_P340_Y0		"14FEDA7D5302E6D1BDAD04CC55500478C8FA117174E943B97D35F0807E0484A46F658820CCE33AFF6428E"
#define BW14_P340_Y1		"63AE342F74BC1D3925508CC16CD44C7590A8270B390F3B3DEF3B92765AAA97A50B011D946D5221745D28"
#define BW14_P340_Y2		"7D287878B31B85EB00405A53AC387F5C2C1C98EE2B18A03E743D3849953E4725F09141CA2E99DDEDABE42"
#define BW14_P340_Y3		"63F5BC9560F448E50ADBBED11C57A318E914AF3A473EF877ECF10241C406EA54581CF13A6A04110F04569"
#define BW14_P340_Y4		"21B790C30A59255446324DD86C6D9897621272EC43659F1FD2D24148276D09FADBA29555703E77D50A32A"
#define BW14_P340_Y5		"16E01D760A1B058EF1B25AFDECA3DB4B4A15E9F674223A317CD58522197202B4FB9E2BF5B8D27B394E8BC"
#define BW14_P340_Y6		"85E11FB0B813D23331C07D1F46EF86CFE9535D73ABD3C70835BE79F417A2DCDEC384A63E94DEB6974CC11"
#define BW14_P340_R		    "E0E982A238DC854CD2D85442A895261C02C5E651E9E90DC5AFD0784DE8BEF945"
#define BW14_P340_H		     "1"

#define BW14_P351_A0		"0"
#define BW14_P351_A1		"0"
#define BW14_P351_A2		"0"
#define BW14_P351_A3		"0"
#define BW14_P351_A4		"0"
#define BW14_P351_A5		"0"
#define BW14_P351_A6		"0"
#define BW14_P351_B0		"0"
#define BW14_P351_B1		"0"
#define BW14_P351_B2		"0"
#define BW14_P351_B3		"0"
#define BW14_P351_B4		"2E1D1A2C456CB7F688DEF57C8CEEE2BF184A22BFBFDF653C0FA159D3C3203C1887C75E3CE0C62CB154397297"
#define BW14_P351_B5		"0"
#define BW14_P351_B6		"0"
#define BW14_P351_X0		"10FC1FE77E3EEF7A1AA07AFA2D954F6837C7F437792D2990C7920BE097DADC5ACB4E8DC3218150C8550A4C8F"
#define BW14_P351_X1            "229E53EBE87D0D1482C6C89EE5D549AD308C1DF6206E6AC80B8C2CDB6D9DC6E50BA2198B445D25B03D775001"
#define BW14_P351_X2		"171CAFC304667077DACF28B8E986A93F571E243FE604387C892A43792B1F3771AC0B5E8B690F3154907C97E0"
#define BW14_P351_X3		"13727E994B02288FFA77777C553641C2A7C792BA2739BAE306DCB93C8FA8EA38D742AEB0122D9E835997737D"
#define BW14_P351_X4		"4D5C4442EC74B347044F54F59260520D9EB3D67FF80017503E4D243FD290D08F495D0AB487A3D0072176449C"
#define BW14_P351_X5		"52D96EB4E2DC8B97415C3A9B534C2A65036598C7F92AD2E7D3D9D868851C04F6EF12445E12E2E50DFFD427E3"
#define BW14_P351_X6		"42F89C175B061465D0047AA6FAB3C277D6770ABA93BC978569858918A602BCC5A0B18252D43C60CDDA5A5506"
#define BW14_P351_Y0		"976472DFA968922B4ACFC2C27A9B91FF1BF669B2D120E6E02FE00A705EED1F42B27F88D5171E29F50D48626"
#define BW14_P351_Y1		"2B69E0976DB0EE5FA34F88EA4182C0E67BB2C1D9744C3FDB46F1ABE061CBB71B720ECFD5944EA5E962A005C4"
#define BW14_P351_Y2		"3BC0123D001E604D36936A3AC36BA10A5876CF9E0C401F0C302D9604016954ED102D4C7803B53B1C3D29D3FD"
#define BW14_P351_Y3		"51D20D71B2D6B3BEF68D6ADC2ECB6624411D4BDBA9C58495B73908F44B488639503ACC335D8E2F69A153A9D9"
#define BW14_P351_Y4		"4072067EC75CA6CE10A2CF2A2C1E17B69ECAF97A0F99CD0A85F811CF2B00EF6401AECA417D2BE550D2F9058B"
#define BW14_P351_Y5		"54A6C1414D1A320AA243DF4CE2EA7EFF820CB5DC94FE0E470F6649E36C7E40F3288B75523ED2684A09F34166"
#define BW14_P351_Y6		"17ABCA10B366CAE95567D2F962EC7491748DF7FEEDED4E5FD8F0C89D9A8944B16DD3164F6DC85A6343CA5260"
#define BW14_P351_R		    "10F5C2568986E859098113999F6D23DBCD80C79E0682DD4E2843B23FC7E4DBBB041"
#define BW14_P351_H		     "1"

#define ASSIGN(CURVE)   													\
	RLC_GET(str, CURVE##_A0, sizeof(CURVE##_A0));							\
	fp_read_str(a[0], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_A1, sizeof(CURVE##_A1));							\
	fp_read_str(a[1], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_A2, sizeof(CURVE##_A2));							\
	fp_read_str(a[2], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_A3, sizeof(CURVE##_A3));							\
	fp_read_str(a[3], str, strlen(str), 16);		                        \
	RLC_GET(str, CURVE##_A4, sizeof(CURVE##_A4));							\
	fp_read_str(a[4], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_A5, sizeof(CURVE##_A5));							\
	fp_read_str(a[5], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_A6, sizeof(CURVE##_A6));							\
	fp_read_str(a[6], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_B0, sizeof(CURVE##_B0));							\
	fp_read_str(b[0], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_B1, sizeof(CURVE##_B1));							\
	fp_read_str(b[1], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_B2, sizeof(CURVE##_B2));							\
	fp_read_str(b[2], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_B3, sizeof(CURVE##_B3));							\
	fp_read_str(b[3], str, strlen(str), 16);	                         	\
	RLC_GET(str, CURVE##_B4, sizeof(CURVE##_B4));							\
	fp_read_str(b[4], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_B5, sizeof(CURVE##_B5));							\
	fp_read_str(b[5], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_B6, sizeof(CURVE##_B6));                           \
	fp_read_str(b[6], str, strlen(str), 16);	                            \
    RLC_GET(str, CURVE##_X0, sizeof(CURVE##_X0));                          \		
    fp_read_str(g->x[0], str, strlen(str), 16); 							\
	RLC_GET(str, CURVE##_X1, sizeof(CURVE##_X1));  						  \          
	fp_read_str(g->x[1], str, strlen(str), 16);	    \
	RLC_GET(str, CURVE##_X2, sizeof(CURVE##_X2));	           			    \
	fp_read_str(g->x[2], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_X3, sizeof(CURVE##_X3));							\
	fp_read_str(g->x[3], str, strlen(str), 16);							    \
    RLC_GET(str, CURVE##_X4, sizeof(CURVE##_X4));							\
    fp_read_str(g->x[4], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_X5, sizeof(CURVE##_X5));    						\
    fp_read_str(g->x[5], str, strlen(str), 16);								\
    RLC_GET(str, CURVE##_X6, sizeof(CURVE##_X6));							\
	fp_read_str(g->x[6], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_Y0, sizeof(CURVE##_Y0));							\
	fp_read_str(g->y[0], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_Y1, sizeof(CURVE##_Y1));							\
	fp_read_str(g->y[1], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_Y2, sizeof(CURVE##_Y2));							\
	fp_read_str(g->y[2], str, strlen(str), 16);			   					\
    RLC_GET(str, CURVE##_Y3, sizeof(CURVE##_Y3));							\
	fp_read_str(g->y[3], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_Y4, sizeof(CURVE##_Y4));							\
	fp_read_str(g->y[4], str, strlen(str), 16);			           			\
	RLC_GET(str, CURVE##_Y5, sizeof(CURVE##_Y5));							\
	fp_read_str(g->y[5], str, strlen(str), 16);                             \
	RLC_GET(str, CURVE##_Y6, sizeof(CURVE##_Y6));					        \
	fp_read_str(g->y[6], str, strlen(str), 16);								\
                            					 	
/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep7_curve_set_twist(int type){
    char str[2 * RLC_FP_BYTES + 1];
	ctx_t *ctx = core_get();
	fp_t  sr3;
	fp7_t a,b;
	ep7_t g;
	fp7_null(a);
	fp7_null(b);

	ep7_null(g);
	ctx->ep7_is_twist = 0;	
	if (type == RLC_EP_MTYPE || type == RLC_EP_DTYPE) {
		ctx->ep7_is_twist = type;
	} else {
		return;
	}		

	RLC_TRY {
		fp7_new(a);
		fp7_new(b);
		ep7_new(g);
		#if FP_PRIME == 340
			ASSIGN(BW14_P340);
		#elif FP_PRIME == 351
			ASSIGN(BW14_P351);
		#endif

		fp7_field_init();
		fp7_zero(g->z);
		fp_set_dig(g->z[0], 1);
		g->coord = BASIC;
		ep7_copy(&(ctx->ep7_g), g);
		fp7_copy(ctx->ep7_a, a);
		fp7_copy(ctx->ep7_b, b);
		
		
		fp_set_dig(sr3, 3);
		fp_neg(sr3, sr3);
		fp_srt(sr3, sr3);
		fp_copy(ctx->sr3, sr3);	
		
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep7_free(g);
		fp7_free(a);
		fp7_free(b);

	}
}				



void ep7_curve_get_a(fp7_t a) {
	fp7_copy(a, core_get()->ep7_a);
}

void ep7_curve_get_b(fp7_t b) {
	fp7_copy(b, core_get()->ep7_b);
}
				
void ep7_curve_get_gen(ep7_t g) {
	ep7_copy(g, &(core_get()->ep7_g));
}




int ep7_curve_is_twist(void) {
	return core_get()->ep7_is_twist;
}

