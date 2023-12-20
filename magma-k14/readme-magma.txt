In this folder we provide MAGMA codes to verify our proposed  algorithms are correct.

1. The folder "pairing" contains files for pairing computations on our target curves. The file is name by "pp_map_curvename".
 In the "pp_map_curvename" file:
     1)the "pp_dbl" function is used for computing the Miller doubling evaluation;
     2)the "pp_add" function is used for computing the Miller addition evaluation;     
     3)the "Millerk"function is to perfom the Miller's algorithm, where "k" is the embedding degree of the curve;
     4)the "expk"function is to perfom the final expontiation,  where "k" is the embedding degree of the curve;
     5) the "pp_map" function is the optimal pairing function.
 
  Testing: 
  In the testing step,we first generate two random points p1 in G1 and q1 in G2, and a random integer s in [1, r-1], 
  where r is the prime order. The function is correct if it passes the following two testings:
    1)pp_map(p1,q1) is not equal to 1;
    2)pp_map([s]p1, q1)=pp_map(p1, [s]q1).

2. The folder "cof-mul" contains conctains two subfolders: "G1" and "G2". In detai:
   - the subfolder "G1" contains cofactor multiplication for G1 on different pairing-friendly curves:
     1)the file "VectorG1" aims to search for short vectors that used for cofactor multiplication for G1.
     2)the file "cm-curvename" file is to peform our proposed algorthm for cofactor multiplication for G1.

   - the subfolder "G2" contains cofactor multiplication for G2 on different pairing-friendly curves:
     1)the file "VectorG2" aims to search for short vectors that used for cofactor multiplication for G2.
     2)the file "cm-curvename" file is to peform our proposed algorthm for cofactor multiplication for G2

3. The folder "smt" contains files for subgroup membership testings on our target curves. In detai:
     1)the file "vectorG1" aims to search for short vectors that used for  G1 membership testing.
     2)the file "vectorG2" aims to search for short vectors that used for  G1 membership testing.
     3)the file "vectorGT" aims to search for short vectors that used for  G1 membership testing.
     4)the file "curvename" file is to peform our proposed algorthm for subgroup membership testing.

4. the flie "pairing_cost" is to analysis the opertion counts of pairing computation.



