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
 * Implementation of multiplication in a quadratic extension of a prime field.
 *
 * @ingroup fpx
 */
#include"relic_core.h"
#include"relic_fp.h"
#include"relic_fp_low.h"
#include"relic_fpx_low.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/
/**
 * Given a=a[0]+a[1]x and compute a^2
 *
 * @param[out] c			- the result.
 * @param[in] a			- the first element.
 * @param[in] b			- the second element.
 */

static void fp_sqr_level2(dv_t* c, const fp_t* a){
      fp_addn_low(c[0],a[0],a[1]);
      fp_sqrn_low(c[1],c[0]);
      fp_sqrn_low(c[0],a[0]);
      fp_sqrn_low(c[2],a[1]);
      fp_subd_low(c[1],c[1],c[0]);
      fp_subd_low(c[1],c[1],c[2]);
}
/**
 * Given a=a[0]+a[1]x+a[2]x^2 and compute a^2
 *
 * @param[out] c			- the result.
 * @param[in] a			- the first element.
 * @param[in] b			- the second element.
 */
static void fp_sqr_level3(dv_t* c, const fp_t* a) {
      dig_t k0[2 * RLC_FP_DIGS], k1[2 * RLC_FP_DIGS];
      for(int i = 0; i<3;i++)fp_sqrn_low(c[2*i],a[i]);

      fp_addn_low(k0,a[0],a[1]);
      fp_sqrn_low(c[1],k0);
      fp_subd_low(c[1],c[1],c[0]);
      fp_subd_low(c[1],c[1],c[2]);

      fp_addn_low(k0,a[1],a[2]);
      fp_sqrn_low(c[3],k0);
      fp_subd_low(c[3],c[3],c[2]);
      fp_subd_low(c[3],c[3],c[4]);

      fp_addn_low(k0,a[0],a[2]);
      fp_sqrn_low(k1,k0);       //
      fp_addd_low(c[2],c[2],k1);
      fp_subd_low(c[2],c[2],c[0]);
      fp_subd_low(c[2],c[2],c[4]);

}
/**
 * Given a=a[0]+a[1]x+a[2]x^2+a[3]x^3 and compute a^2
 *
 * @param[out] c			- the result.
 * @param[in] a			- the first element.
 * @param[in] b			- the second element.
 */
static void fp_sqr_level4(dv_t* c, const fp_t* a) {
      fp2_t u;
      dv_t m[3],mm[3], mmm[3];  
  
      fp_sqr_level2(m, a);
      fp_sqr_level2(mm, a+2); 

      fp_addn_low(u[0],a[0],a[2]);
      fp_addn_low(u[1],a[1],a[3]); 
      fp_sqr_level2(mmm, u); 

      for(int i = 0; i <3; i++){
	fp_subd_low(mmm[i],mmm[i],m[i]); 
	fp_subd_low(mmm[i],mmm[i],mm[i]);   
      }
 
      dv_copy(c[0],m[0],10);
      dv_copy(c[1],m[1],10);
      dv_copy(c[3],mmm[1],10);
      dv_copy(c[5],mm[1],10);
      dv_copy(c[6],mm[2],10);

      fp_addd_low(c[2],m[2],mmm[0]);
      fp_addd_low(c[4],mm[0],mmm[2]);
      fp2_free(u);
      for(int i = 0; i <3; i++){
	 dv_free(m[i]);
	 dv_free(mm[i]);	
	 dv_free(mmm[i]);	
      }
}
/**
 * Given a=a[0]+a[1]x+...+a[5]x^5 and compute a^2
 *
 * @param[out] c			- the result.
 * @param[in] a			- the first element.
 * @param[in] b			- the second element.
 */
static void fp_sqr_level6(dv_t* c, const fp_t* a) {

      fp_t u[3];

      dv_t m[5],mm[5],mmm[5];  
      for(int i = 0;i<3; i++)fp_addn_low(u[i],a[i],a[i+3]);
     
      fp_sqr_level3(m,a);
      fp_sqr_level3(mm,a+3);
      fp_sqr_level3(mmm,u);

      for(int i = 0;i<5; i++){
         fp_subd_low(mmm[i],mmm[i],m[i]);
         fp_subd_low(mmm[i],mmm[i],mm[i]);
      }

      for(int i = 0;i<3; i++){ 
       dv_copy(c[i], m[i],10);
      }
      dv_copy(c[5],mmm[2],10);
      for(int i = 0;i<3; i++){ 
       dv_copy(c[i+8], mm[i+2],10);
      }

      fp_addd_low(c[3],m[3],mmm[0]);
      fp_addd_low(c[4],m[4],mmm[1]);

      fp_addd_low(c[7],mm[1],mmm[4]);
      fp_addd_low(c[6],mm[0],mmm[3]);
      for(int i = 0; i < 3; i++)fp_free(u[i]);
      for(int i = 0; i < 5; i++){
	 dv_free(m[i]);
	 dv_free(mm[i]);	
	 dv_free(mmm[i]);	
      }
}
/**
 * Compute a^2, where a=a[0]+a[1]x+...+a[6]x^6
 *
 * @param[out] c			- the result.
 * @param[in] a			- the first element.
 * @param[in] b			- the second element.
 */
static void fp_sqr_level7(dv_t* c, const fp_t* a) {

      fp_t u[4];
      dv_t m[5],mm[7],mmm[7];  
      for(int i = 0;i<3; i++)fp_addn_low(u[i],a[i],a[i+3]);
      
      fp_copy(u[3],a[6]);
      fp_sqr_level3(m,a);
      fp_sqr_level4(mm,a+3);
      fp_sqr_level4(mmm,u);
      for(int i = 0;i<5; i++){
         fp_subd_low(mmm[i],mmm[i],m[i]);
         fp_subd_low(mmm[i],mmm[i],mm[i]);
      }
     fp_subd_low(mmm[5],mmm[5],mm[5]);
     fp_subd_low(mmm[6],mmm[6],mm[6]);
     for(int i = 0;i<3; i++){
        dv_copy(c[i],m[i],10);
      }
     fp_addd_low(c[3],m[3],mmm[0]);
     fp_addd_low(c[4],m[4],mmm[1]);
     dv_copy(c[5],mmm[2],10);
     fp_addd_low(c[6],mm[0],mmm[3]);
     fp_addd_low(c[7],mm[1],mmm[4]);
     fp_addd_low(c[8],mm[2],mmm[5]);
     fp_addd_low(c[9],mm[3],mmm[6]);
     for(int i = 0;i<3; i++){
        dv_copy(c[10+i],mm[i+4],10);
      }   
     for(int i = 0; i < 4; i++)fp_free(u[i]);
     for(int i = 0; i < 5; i++)dv_free(m[i]);
     for(int i = 0; i < 7; i++){
	 dv_free(mm[i]);	
	 dv_free(mmm[i]);	
     }
}



/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/
void fp13_sqrn_low(dv13_t c, const fp13_t a){
     fp_t u[7];
     dv_t m[11],mm[13],mmm[13];	
     fp_sqr_level6(m,a);
     fp_sqr_level7(mm,a+6);
     for(int i = 0;i<6; i++)fp_addn_low(u[i],a[i],a[i+6]);
   
     fp_copy(u[6],a[12]);
     fp_sqr_level7(mmm,u);
     for(int i = 0;i<11; i++){
         fp_subd_low(mmm[i],mmm[i],m[i]);
         fp_subd_low(mmm[i],mmm[i],mm[i]);
      }
     fp_subd_low(mmm[11],mmm[11],mm[11]);
     fp_subd_low(mmm[12],mmm[12],mm[12]);


      for(int i = 0;i<6; i++){   
        fp_addd_low(c[i],mm[i+1],mmm[i+7]);
        fp_addd_low(c[i],c[i],c[i]);
	fp_subc_low(c[i],m[i],c[i]);
     }
     for(int i = 0;i<5; i++){ 
        fp_addd_low(c[i+6], mm[i+7], mm[i+7]);
	fp_addd_low(m[0], m[i+6], mmm[i]);
        fp_subc_low(c[i+6], m[0], c[i+6]);
     }
     
    fp_addd_low(c[11],mm[12],mm[12]);
    fp_subc_low(c[11],mmm[5],c[11]);
    fp_addd_low(c[12],mm[0],mmm[6]);
   for(int i = 0; i <7; i++)fp_free(u[i]);
   for(int i = 0; i <11; i++)dv_free(m[i]);
   for(int i = 0; i <13; i++){
	dv_free(mm[i]);	
	dv_free(mmm[i]);	
      }
}

void fp13_sqr_lazyr(fp13_t d, const fp13_t a){
     dv13_t c;
     for(int i = 0; i<13; i++)dv_null(c[i]);
     for(int i = 0; i<13; i++)dv_new(c[i]);
     fp13_sqrn_low(c,a);
     fp13_rdc(d,c);
     dv13_free(c);
}





















