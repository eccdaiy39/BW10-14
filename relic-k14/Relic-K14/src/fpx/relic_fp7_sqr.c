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
 
      dv_copy(c[0],m[0],12);
      dv_copy(c[1],m[1],12);
      dv_copy(c[3],mmm[1],12);
      dv_copy(c[5],mm[1],12);
      dv_copy(c[6],mm[2],12);

      fp_addd_low(c[2],m[2],mmm[0]);
      fp_addd_low(c[4],mm[0],mmm[2]);
      fp2_free(u);
      for(int i = 0; i <3; i++){
	 dv_free(m[i]);
	 dv_free(mm[i]);	
	 dv_free(mmm[i]);	
      }
}



/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/
 void fp7_sqrn_low(dv7_t c, const fp7_t a) {

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
      #if FP_PRIME == 340 
            fp_addd_low(mm[1],mm[1],mmm[4]);
            fp_addd_low(mm[1],mm[1],mm[1]);
            fp_addd_low(mm[1],mm[1],mm[1]);
            fp_subc_low(c[0],m[0],mm[1]);

            fp_addd_low(mm[2],mm[2],mmm[5]);
            fp_addd_low(mm[2],mm[2],mm[2]);
            fp_addd_low(mm[2],mm[2],mm[2]);
            fp_subc_low(c[1],m[1],mm[2]);   

            fp_addd_low(mm[3],mm[3],mmm[6]);
            fp_addd_low(mm[3],mm[3],mm[3]);
            fp_addd_low(mm[3],mm[3],mm[3]);
            fp_subc_low(c[2],m[2],mm[3]);    
         
            fp_addd_low(mm[4],mm[4],mm[4]);
            fp_addd_low(mm [4],mm[4],mm[4]);
            fp_addd_low(c[3],m[3],mmm[0]);    
            fp_subc_low(c[3],c[3],mm[4]); 
     
            fp_addd_low(mm[5],mm[5],mm[5]);
            fp_addd_low(mm[5],mm[5],mm[5]);
            fp_addd_low(c[4],m[4],mmm[1]);    
            fp_subc_low(c[4],c[4],mm[5]); 

            fp_addd_low(mm[6],mm[6],mm[6]);
            fp_addd_low(mm[6],mm[6],mm[6]);
            fp_subc_low(c[5],mmm[2],mm[6]); 
     
            fp_addd_low(c[6],mm[0],mmm[3]);   
 
      #elif FP_PRIME == 351

            fp_addd_low(mm[1],mm[1],mmm[4]);
            fp_addd_low(mm[1],mm[1],mm[1]);
            fp_addd_low(c[0],m[0],mm[1]);

            fp_addd_low(mm[2],mm[2],mmm[5]);
            fp_addd_low(mm[2],mm[2],mm[2]);
            fp_addd_low(c[1],m[1],mm[2]);   

            fp_addd_low(mm[3],mm[3],mmm[6]);
            fp_addd_low(mm[3],mm[3],mm[3]);
            fp_addd_low(c[2],m[2],mm[3]);    
         
            fp_addd_low(mm[4],mm[4],mm[4]);
            fp_addd_low(c[3],m[3],mmm[0]);    
            fp_addd_low(c[3],c[3],mm[4]); 
     
            fp_addd_low(mm[5],mm[5],mm[5]);
            fp_addd_low(c[4],m[4],mmm[1]);    
            fp_addd_low(c[4],c[4],mm[5]); 

            fp_addd_low(mm[6],mm[6],mm[6]);
            fp_addd_low(c[5],mmm[2],mm[6]); 
     
            fp_addd_low(c[6],mm[0],mmm[3]);   
      #endif

   for(int i = 0; i <5; i++)dv_free(m[i]);

   for(int i = 0; i <7; i++){
	dv_free(mm[i]);	
	dv_free(mmm[i]);	
      }
   for(int i = 0; i < 4; i++){
	fp_free(u[i]);
	fp_free(uu[i]);	
      }
}



void fp7_sqr_lazyr(fp7_t d, const fp7_t a){
     dv7_t c;
     for(int i = 0; i<7; i++)dv_null(c[i]);
     for(int i = 0; i<7; i++)dv_new(c[i]);
     fp7_sqrn_low(c,a);
     fp7_rdc(d,c);
     dv7_free(c);
}

