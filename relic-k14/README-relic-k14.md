# BW14-351
### Notice
When downloding this folder, please make sure that the name of the  downloaded file does not contain "()", eg.<***(1)>.
Otherwise, the compiler will produce an error at the "cmake" step. 

### Algorithms

We implemented the following building blocks related to pairing-based protocols on "BW14-351" using the famous [RELIC cryptographic toolkit](https://github.com/relic-toolkit/relic):
* pairing computation.
*  hashing to  $\mathbb{G}_1$ and $\mathbb{G}_2$.
*  group expontiations in  $\mathbb{G}_1$, $\mathbb{G}_2$ and  $\mathbb{G}_T$.
*  membership testings for $\mathbb{G}_1$, $\mathbb{G}_2$ and  $\mathbb{G}_T$.
### Requirements

The build process requires the [CMake](https://cmake.org/) cross-platform build system. The [GMP](https://gmplib.org/) library is also needed in our benchmarks.

### Build instructions

Instructions for building the library can be found in the [Wiki](https://github.com/relic-toolkit/relic/wiki/Building).


### main functions
  
The main source code of our algorithms are distributed in different folders.  The main functions are:
* pp_map_sup_oatep_k14(fp14_t r, ep_t p, ep7_t q): given $p\in  \mathbb{G}_1$ and $q\in \mathbb{G}_2$,  computing a single pairing.
* pp_map_sim_sup_oatep_k14(fp14_t r,  ep_t *p,   ep7_t *q, int m): computing a m-pairing products
* ep_map(ep_t p, const uint8_t *msg, int len) : hashing to $\mathbb{G}_1$
* ep7_map(ep7_t p, const uint8_t *msg, int len) : hashing to $\mathbb{G}_2$
* ep_mul(ep_t q, ep_t p, bn_t k) : given a random point $p\in \mathbb{G}_1$ and a random scalar $k$, computing $q=[k]p$. This function is given by the Relic library itself.
* ep7_mul(ep7_t q, ep7_t p, bn_t k) : given a random point $p\in \mathbb{G}_2$ and a random scalar $k$, computing $q=[k]p$
* fp14_exp_cyc(fp14_t $h_1$, fp14_t $h_0$,  bn_t k) : given a random point $h_0\in \mathbb{G}_T$ and a random exp $k$, computing $h_1={h_0}^k$
* g1_is_valid(ep_t p): Checking whether $p$ is a point of $\mathbb{G}_1$ or not.
* g2_is_valid_bw14(ep7_t q): Checking whether $q$ is a point of $\mathbb{G}_2$ or not.
* gt_is_valid_bw14(fp14_t $h_0$): Checking whether $h_0$ is a element of $\mathbb{G}_T$ or not.

### finite field arithmitcs
     multiplications in $F_{p^7}$ : /src/fpx/relic_fp7_mul.c
     squairing in $F_{p^7}$:        /src/fpx/relic_fp7_sqr.c
     inversion in $F_{p^7}$:        line 972 in /src/fpx/relic_fpx_inv.c 
    
     multiplications in $F_{p^{14}$ : /src/fpx/relic_fp14_mul.c
     squairing in $F_{p^7}$:        /src/fpx/relic_fp14_sqr.c
     inversion in $F_{p^7}$:        line 739 in /src/fpx/relic_fpx_inv.c 



### Testings, benckmarks and comparisons
* Testings and benckmarks: Function testings and benckmarking can be done by performing the following commands：

    1. mkdir build && cd build 
    2. ../preset/x64-pbc-bw351.sh ./
    3. make
    4. cd bin 
    5. ./test_bw14 (This is to check that our implementation is corrret)
    6. ./bench_pc_bw14 (This is to obtain clock cycles of pairing group operations on BW14-P351)
  
 * Likewsie, if you want to obatin the benchmarking results on BW13-310, you can perform the following commands:
     1. mkdir build && cd build 
    2. ../preset/x64-pbc-bw310.sh ./
    3. make
    4. cd bin 
    5. ./test_bw13 
    6. ./bench_pc_bw13
 
 *  For BN-446 and BLS12-446, you can perform the following commands:
   1. mkdir build && cd build 
   2. ../preset/ < preset >.sh ./
   3. make
   4. cd bin 
   5. ./bench_pc

### Operation count for n-pairings products computation:
Notations:

m1, s1, a1 : Multiplication squaring and addition in $\mathbb{F}_{p}$.

m7, m7_u, s7, s7_u, r7, m7_xi, a7, : Multiplication, multiplication without reduction, squaring, squaring without reduction, modular reduction, multiplication by $xi$ and addition in $\mathbb{F}_{p^{7}}$.


    1.pp_add_k14_projc_lazyr():\src\pp\relic_pp_add_k14.c
    
        Line62-Line81, point additon, 6m7+2m7_u+3s7+r7+8a7;
       
        Line84-Line94 line function computation, 2m7_u+21m1+m7_xi+r7+4a7
        
        total cost: 6m7+4m7_u+3s7+21m1+m7_xi+2r7+12a7.
    
    2.pp_dbl_k14():\src\pp\relic_pp_dbl_k14.c
    
        Line 67- Line 84, point doubling,  3m7+m7_u+3s7+s7_u+r7+10a7,
        Line 86-Line 97,  line function computation, 2m7+21m1+m7_xi+3a7+a1
        
        total cost 5m7+m7_u+3s7+s7_u+21m1+m7_xi+r7+13a7+a

   3. pp_map_sim_sup_oatep_k14(): line 515 in \src\pp\relic_pp_map_k14.c
   
  
   4. pp_exp_bwk14(r, l1): /src/pp/relic_pp_exp_k14.c

 
