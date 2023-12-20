#include"relic_core.h"
#include"relic_fp.h"
#include"relic_fp_low.h"
#include"relic_fpx_low.h"
/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Given a=a[0]+a[1]x and  b=b[0]+ b[1]x. compute a*b
 *
 * @param[out] c			- the result.
 * @param[in] a			- the first element.
 * @param[in] b			- the second element.
 */
static void fp_mul_level2(dv_t* c, const fp_t* a, const fp_t* b) {
      dig_t k0[2 * RLC_FP_DIGS], k1[2 * RLC_FP_DIGS];

      fp_muln_low(c[0], a[0], b[0]);

      fp_muln_low(c[2], a[1], b[1]);

      fp_addn_low(k0, a[0], a[1]);
      fp_addn_low(k1, b[0], b[1]);
      fp_muln_low(c[1], k0, k1);
      fp_subd_low(c[1], c[1], c[0]);
      fp_subd_low(c[1], c[1], c[2]);



}
/**
 * Given a=a[0]+a[1]x+a[2]x^2 and  b=b[0]+ b[1]x+b[2]x^2. compute a*b
 *
 * @param[out] c			- the result.
 * @param[in] a			- the first element.
 * @param[in] b			- the second element.
 */
static void fp_mul_level3(dv_t* c, const fp_t* a, const fp_t* b) {
      dig_t k0[2 * RLC_FP_DIGS], k1[2 * RLC_FP_DIGS], k2[2 * RLC_FP_DIGS];
     // for(int i = 0; i<3; i++)dv_null(k[i]);
     // for(int i = 0; i<3; i++)dv_new(k[i]);
      for(int i = 0; i<3;i++)fp_muln_low(c[2*i],a[i],b[i]);

      fp_addn_low(k0, a[0], a[1]);
      fp_addn_low(k1, b[0], b[1]);
      fp_muln_low(c[1], k0, k1);
      fp_subd_low(c[1], c[1], c[0]);
      fp_subd_low(c[1], c[1], c[2]);

      fp_addn_low(k0, a[1], a[2]);
      fp_addn_low(k1, b[1], b[2]);
      fp_muln_low(c[3], k0, k1);
      fp_subd_low(c[3], c[3], c[2]);
      fp_subd_low(c[3], c[3], c[4]);

      fp_addn_low(k0, a[0], a[2]);
      fp_addn_low(k1, b[0], b[2]);
      fp_muln_low(k2, k0, k1);
      fp_addd_low(c[2], c[2], k2);
      fp_subd_low(c[2], c[2], c[0]);
      fp_subd_low(c[2], c[2], c[4]);
}
/**
 * Given a=a[0]+a[1]x+a[2]x^2+a[3]x^3 and  b=b[0]+ b[1]x+b[2]x^2+b[3]x^3.
 *  compute a*b
 *
 * @param[out] c			- the result.
 * @param[in] a			- the first element.
 * @param[in] b			- the second element.
 */
static void fp_mul_level4(dv_t* c, const fp_t* a, const fp_t* b) {
      fp2_t u,uu;
      dv_t m[3],mm[3], mmm[3];  
  
      fp_mul_level2(m, a, b);

      fp_mul_level2(mm, a+2, b+2); 

      fp_addn_low(u[0],a[0],a[2]);
      fp_addn_low(u[1],a[1],a[3]); 
      fp_addn_low(uu[0],b[0],b[2]);
      fp_addn_low(uu[1],b[1],b[3]); 
      fp_mul_level2(mmm, u, uu); 

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
      for(int i = 0; i <3; i++){
	dv_free(m[i]);
	dv_free(mm[i]);	
	dv_free(mmm[i]);	
      }
     fp2_free(u);
     fp2_free(uu);
     
}


void fp7_muln_low(dv7_t c, const fp7_t a, const fp7_t b) {
      fp_t u[4];
      fp_t  uu[4];
      dv_t m[5],mm[7],mmm[7];  
      for(int i = 0;i<3; i++){
        fp_addn_low(u[i],a[i],a[i+3]);
        fp_addn_low(uu[i],b[i],b[i+3]);
      }
      fp_copy(u[3],a[6]);
      fp_copy(uu[3],b[6]);

      fp_mul_level3(m,a,b);
      fp_mul_level4(mm,a+3,b+3);
      fp_mul_level4(mmm,u,uu);
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

void fp7_mul_lazyr(fp7_t d, const fp7_t a, const fp7_t b){
     dv7_t c;
     for(int i = 0; i<7; i++)dv_null(c[i]);
     for(int i = 0; i<7; i++)dv_new(c[i]);
     fp7_muln_low(c,a, b);
     fp7_rdc(d,c);
     dv7_free(c);
}

void fp7_mul_frb(fp7_t c, const fp7_t a,int i){
	ctx_t *ctx = core_get();
	switch(i%7){
		case 0:
			fp7_copy(c,a);
			break;
		case 1:
			fp_copy(c[0],a[0]);
			for(int i=1;i<7;i++)
				fp_mul(c[i],a[i],ctx->frb7_1[i]);
			break;
		case 2:
			fp_copy(c[0],a[0]);
			for(int i=1;i<7;i++)
				fp_mul(c[i],a[i],ctx->frb7_2[i]);
			break;
		case 3:
			fp_copy(c[0],a[0]);
			for(int i=1;i<7;i++)
				fp_mul(c[i],a[i],ctx->frb7_3[i]);
			break;
		case 4:
			fp_copy(c[0],a[0]);
			for(int i=1;i<7;i++)
				fp_mul(c[i],a[i],ctx->frb7_4[i]);
			break;
		case 5:
			fp_copy(c[0],a[0]);
			for(int i=1;i<7;i++)
				fp_mul(c[i],a[i],ctx->frb7_5[i]);
			break;
		case 6:
			fp_copy(c[0],a[0]);
			for(int i=1;i<7;i++)
				fp_mul(c[i],a[i],ctx->frb7_6[i]);
			break;
	}
	
}


void fp7_mul_frb2(fp7_t c, const fp7_t a,int i){
	ctx_t *ctx = core_get();
	switch(i%14){
		case 0:
			fp7_copy(c,a);
			break;
		case 1:
			for(int i=0;i<7;i++)
				fp_mul(c[i],a[i],ctx->frb7_1b[i]);
			break;
		case 2:
			for(int i=0;i<7;i++)
				fp_mul(c[i],a[i],ctx->frb7_2b[i]);
			break;
		case 3:
			for(int i=0;i<7;i++)
				fp_mul(c[i],a[i],ctx->frb7_3b[i]);
			break;
		case 4:
			for(int i=0;i<7;i++)
				fp_mul(c[i],a[i],ctx->frb7_4b[i]);
			break;
		case 5:
			for(int i=0;i<7;i++)
				fp_mul(c[i],a[i],ctx->frb7_5b[i]);
			break;
		case 6:
			for(int i=0;i<7;i++)
				fp_mul(c[i],a[i],ctx->frb7_6b[i]);
			break;
            case 7:     
                  fp7_neg(c,a); 
 			break;                  
            case 8:
			for(int i=0;i<7;i++)
                        fp_mul(c[i],a[i],ctx->frb7_1b[i]);
                  fp7_neg(c,c);  
             	break;                  
      
		case 9:
			for(int i=0;i<7;i++)
				fp_mul(c[i],a[i],ctx->frb7_2b[i]);
                  fp7_neg(c,c); 
            	break;
            case 10:
			for(int i=0;i<7;i++)
				fp_mul(c[i],a[i],ctx->frb7_3b[i]);
                  fp7_neg(c,c); 
			break; 
		case 11:
			for(int i=0;i<7;i++)
				fp_mul(c[i],a[i],ctx->frb7_4b[i]);
                  fp7_neg(c,c); 
 			break;                  
		case 12:
			for(int i=0;i<7;i++)
				fp_mul(c[i],a[i],ctx->frb7_5b[i]);
                  fp7_neg(c,c); 
			break;
		case 13:
			for(int i=0;i<7;i++)
				fp_mul(c[i],a[i],ctx->frb7_6b[i]);
                  fp7_neg(c,c); 
			break;
	}
	
}

void fp7_mul_nor_low(dv7_t c, dv7_t a) {
	for(int i = 1; i < 7; i++)dv_copy(c[i], a[i-1], 12);
      #if FP_PRIME ==340 
	      fp_addd_low(c[0], a[6], a[6]);
	      fp_addd_low(c[0], c[0], c[0]);
      #elif FP_PRIME ==351 
      	fp_addd_low(c[0], a[6], a[6]);
      #endif
}
void fp7_mul_art(fp7_t c, const fp7_t a) {
      fp7_t d;
      fp7_null(d);
      fp7_new(d);
	for(int i = 1; i < 7; i++)fp_copy(d[i], a[i-1]);

      #if FP_PRIME ==340 
	      fp_dbl(d[0], a[6]);
	      fp_dbl(d[0], d[0]);
            fp_neg(d[0], d[0]);
      #elif FP_PRIME ==351 
            fp_dbl(d[0], a[6]);
      #endif
      fp7_copy(c,d);
      fp7_free(d);

}
