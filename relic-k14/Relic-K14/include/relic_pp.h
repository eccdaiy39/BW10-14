/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
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
 * @defgroup pp Bilinear pairings over prime elliptic curves.
 */

/**
 * @file
 *
 * Interface of the module for computing bilinear pairings over prime elliptic
 * curves.
 *
 * @ingroup pp
 */

#ifndef RLC_PP_H
#define RLC_PP_H

#include "relic_fpx.h"
#include "relic_epx.h"
#include "relic_types.h"

/*============================================================================*/
/* Macro definitions                                                          */
/*============================================================================*/

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 2 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] P				- the second point to add.
 * @param[in] Q				- the affine point to evaluate the line function.
 */
#if PP_EXT == BASIC
#define pp_add_k2_projc(L, R, P, Q)		pp_add_k2_projc_basic(L, R, P, Q)
#else
#define pp_add_k2_projc(L, R, P, Q)		pp_add_k2_projc_lazyr(L, R, P, Q)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 2.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] P				- the second point to add.
 * @param[in] Q				- the affine point to evaluate the line function.
 */
#if EP_ADD == BASIC
#define pp_add_k2(L, R, P, Q)		pp_add_k2_basic(L, R, P, Q)
#else
#define pp_add_k2(L, R, P, Q)		pp_add_k2_projc(L, R, P, Q)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 8 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == BASIC
#define pp_add_k8_projc(L, R, Q, P)	pp_add_k8_projc_basic(L, R, Q, P)
#elif PP_EXT == LAZYR
#define pp_add_k8_projc(L, R, Q, P)	pp_add_k8_projc_lazyr(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 8.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == BASIC
#define pp_add_k8(L, R, Q, P)		pp_add_k8_basic(L, R, Q, P)
#else
#define pp_add_k8(L, R, Q, P)		pp_add_k8_projc(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == BASIC
#define pp_add_k12_projc(L, R, Q, P)	pp_add_k12_projc_basic(L, R, Q, P)
#elif PP_EXT == LAZYR
#define pp_add_k12_projc(L, R, Q, P)	pp_add_k12_projc_lazyr(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == BASIC
#define pp_add_k12(L, R, Q, P)		pp_add_k12_basic(L, R, Q, P)
#else
#define pp_add_k12(L, R, Q, P)		pp_add_k12_projc(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == BASIC
#define pp_add_k18_projc(L, R, Q, P)	pp_add_k18_projc_basic(L, R, Q, P)
#elif PP_EXT == LAZYR
#define pp_add_k18_projc(L, R, Q, P)	pp_add_k18_projc_lazyr(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == BASIC
#define pp_add_k18(L, R, Q, P)		pp_add_k18_basic(L, R, Q, P)
#else
#define pp_add_k18(L, R, Q, P)		pp_add_k18_projc(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 24.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == BASIC
#define pp_add_k24(L, R, Q, P)		pp_add_k24_basic(L, R, Q, P)
#else
#define pp_add_k24(L, R, Q, P)		pp_add_k24_projc(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 48.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == BASIC
#define pp_add_k48(L, RX, RY, RZ, QX, QY, P)	pp_add_k48_basic(L, RX, RY, QX, QY, P)
#else
#define pp_add_k48(L, RX, RY, RZ, QX, QY, P)	pp_add_k48_projc(L, RX, RY, RZ, QX, QY, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 54.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == BASIC
#define pp_add_k54(L, RX, RY, RZ, QX, QY, P)	pp_add_k54_basic(L, RX, RY, QX, QY, P)
#else
#define pp_add_k54(L, RX, RY, RZ, QX, QY, P)	pp_add_k54_projc(L, RX, RY, RZ, QX, QY, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 2 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == BASIC
#define pp_dbl_k2_projc(L, R, P, Q)		pp_dbl_k2_projc_basic(L, R, P, Q)
#elif PP_EXT == LAZYR
#define pp_dbl_k2_projc(L, R, P, Q)		pp_dbl_k2_projc_lazyr(L, R, P, Q)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 2.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[out] R			- the resulting point.
 * @param[in] P				- the point to double.
 * @param[in] Q				- the affine point to evaluate the line function.
 */
#if EP_ADD == BASIC
#define pp_dbl_k2(L, R, P, Q)			pp_dbl_k2_basic(L, R, P, Q)
#else
#define pp_dbl_k2(L, R, P, Q)			pp_dbl_k2_projc(L, R, P, Q)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == BASIC
#define pp_dbl_k8_projc(L, R, Q, P)		pp_dbl_k8_projc_basic(L, R, Q, P)
#elif PP_EXT == LAZYR
#define pp_dbl_k8_projc(L, R, Q, P)		pp_dbl_k8_projc_lazyr(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 8.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[out] R			- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == BASIC
#define pp_dbl_k8(L, R, Q, P)			pp_dbl_k8_basic(L, R, Q, P)
#else
#define pp_dbl_k8(L, R, Q, P)			pp_dbl_k8_projc(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == BASIC
#define pp_dbl_k12_projc(L, R, Q, P)	pp_dbl_k12_projc_basic(L, R, Q, P)
#elif PP_EXT == LAZYR
#define pp_dbl_k12_projc(L, R, Q, P)	pp_dbl_k12_projc_lazyr(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[out] R			- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == BASIC
#define pp_dbl_k12(L, R, Q, P)			pp_dbl_k12_basic(L, R, Q, P)
#else
#define pp_dbl_k12(L, R, Q, P)			pp_dbl_k12_projc(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == BASIC
#define pp_dbl_k18_projc(L, R, Q, P)	pp_dbl_k18_projc_basic(L, R, Q, P)
#elif PP_EXT == LAZYR
#define pp_dbl_k18_projc(L, R, Q, P)	pp_dbl_k18_projc_lazyr(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[out] R			- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == BASIC
#define pp_dbl_k18(L, R, Q, P)			pp_dbl_k18_basic(L, R, Q, P)
#else
#define pp_dbl_k18(L, R, Q, P)			pp_dbl_k18_projc(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 24.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[out] R			- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == BASIC
#define pp_dbl_k24(L, R, Q, P)			pp_dbl_k24_basic(L, R, Q, P)
#else
#define pp_dbl_k24(L, R, Q, P)			pp_dbl_k24_projc(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 48.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[out] R			- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == BASIC
#define pp_dbl_k48(L, RX, RY, RZ, P)	pp_dbl_k48_basic(L, RX, RY, P)
#else
#define pp_dbl_k48(L, RX, RY, RZ, P)	pp_dbl_k48_projc(L, RX, RY, RZ, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 54.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[out] R			- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == BASIC
#define pp_dbl_k54(L, RX, RY, RZ, P)	pp_dbl_k54_basic(L, RX, RY, P)
#else
#define pp_dbl_k54(L, RX, RY, RZ, P)	pp_dbl_k54_projc(L, RX, RY, RZ, P)
#endif

/**
 * Computes a pairing of two prime elliptic curve points defined on an elliptic
 * curves of embedding degree 2. Computes e(P, Q).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first elliptic curve point.
 * @param[in] Q				- the second elliptic curve point.
 */
#if PP_MAP == TATEP
#define pp_map_k2(R, P, Q)				pp_map_tatep_k2(R, P, Q)
#elif PP_MAP == WEILP
#define pp_map_k2(R, P, Q)				pp_map_weilp_k2(R, P, Q)
#elif PP_MAP == OATEP
#define pp_map_k2(R, P, Q)				pp_map_tatep_k2(R, P, Q)
#endif

/**
 * Computes a pairing of two prime elliptic curve points defined on an elliptic
 * curve of embedding degree 12. Computes e(P, Q).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first elliptic curve point.
 * @param[in] Q				- the second elliptic curve point.
 */
#if PP_MAP == TATEP
#define pp_map_k12(R, P, Q)				pp_map_tatep_k12(R, P, Q)
#elif PP_MAP == WEILP
#define pp_map_k12(R, P, Q)				pp_map_weilp_k12(R, P, Q)
#elif PP_MAP == OATEP
#define pp_map_k12(R, P, Q)				pp_map_oatep_k12(R, P, Q)
#endif

/**
 * Computes a pairing of two prime elliptic curve points defined on an elliptic
 * curve of embedding degree 18. Computes e(P, Q).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first elliptic curve point.
 * @param[in] Q				- the second elliptic curve point.
 */
#if PP_MAP == TATEP
#define pp_map_k18(R, P, Q)				pp_map_tatep_k18(R, P, Q)
#elif PP_MAP == WEILP
#define pp_map_k18(R, P, Q)				pp_map_weilp_k18(R, P, Q)
#elif PP_MAP == OATEP
#define pp_map_k18(R, P, Q)				pp_map_oatep_k18(R, P, Q)
#endif

/**
 * Computes a multi-pairing of elliptic curve points defined on an elliptic
 * curve of embedding degree 2. Computes \prod e(P_i, Q_i).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first pairing arguments.
 * @param[in] Q				- the second pairing arguments.
 * @param[in] M 			- the number of pairings to evaluate.
 */
#if PP_MAP == WEILP
#define pp_map_sim_k2(R, P, Q, M)		pp_map_sim_weilp_k2(R, P, Q, M)
#elif PP_MAP == TATEP || PP_MAP == OATEP
#define pp_map_sim_k2(R, P, Q, M)		pp_map_sim_tatep_k2(R, P, Q, M)
#endif


/**
 * Computes a multi-pairing of elliptic curve points defined on an elliptic
 * curve of embedding degree 12. Computes \prod e(P_i, Q_i).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first pairing arguments.
 * @param[in] Q				- the second pairing arguments.
 * @param[in] M 			- the number of pairings to evaluate.
 */
#if PP_MAP == TATEP
#define pp_map_sim_k12(R, P, Q, M)		pp_map_sim_tatep_k12(R, P, Q, M)
#elif PP_MAP == WEILP
#define pp_map_sim_k12(R, P, Q, M)		pp_map_sim_weilp_k12(R, P, Q, M)
#elif PP_MAP == OATEP
#define pp_map_sim_k12(R, P, Q, M)		pp_map_sim_oatep_k12(R, P, Q, M)
#endif

/**
 * Computes a multi-pairing of elliptic curve points defined on an elliptic
 * curve of embedding degree 18. Computes \prod e(P_i, Q_i).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first pairing arguments.
 * @param[in] Q				- the second pairing arguments.
 * @param[in] M 			- the number of pairings to evaluate.
 */
#if PP_MAP == TATEP
#define pp_map_sim_k18(R, P, Q, M)		pp_map_sim_tatep_k18(R, P, Q, M)
#elif PP_MAP == WEILP
#define pp_map_sim_k18(R, P, Q, M)		pp_map_sim_weilp_k18(R, P, Q, M)
#elif PP_MAP == OATEP
#define pp_map_sim_k18(R, P, Q, M)		pp_map_sim_oatep_k18(R, P, Q, M)
#endif



#define pp_map_k14(R, P, Q)			pp_map_sim_sup_oatep_k14(R, P, Q)
#define pp_map_sim_k14(R, P, Q, M)		pp_map_sim_sup_oatep_k14(R, P, Q, M)



/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Initializes the pairing over prime fields.
 */
void pp_map_init(void);

/**
 * Finalizes the pairing over prime fields.
 */
void pp_map_clean(void);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 2 using affine coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] p				- the second point to add.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_add_k2_basic(fp2_t l, ep_t r, const ep_t p, const ep_t q);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] p				- the second point to add.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_add_k2_projc_basic(fp2_t l, ep_t r, const ep_t p, const ep_t q);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] p				- the second point to add.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_add_k2_projc_lazyr(fp2_t l, ep_t r, const ep_t p, const ep_t q);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 8 using affine coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k8_basic(fp8_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 8 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k8_projc_basic(fp8_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 8 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k8_projc_lazyr(fp8_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using affine coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k12_basic(fp12_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k12_projc_basic(fp12_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k12_projc_lazyr(fp12_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve twist with embedding degree 12 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] p				- the second point to add.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_add_lit_k12(fp12_t l, ep_t r, const ep_t p, const ep2_t q);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18 using affine coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k18_basic(fp18_t l, ep3_t r, const ep3_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k18_projc_basic(fp18_t l, ep3_t r, const ep3_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k18_projc_lazyr(fp18_t l, ep3_t r, const ep3_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve twist with embedding degree 18 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] p				- the second point to add.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_add_lit_k18(fp18_t l, ep_t r, const ep_t p, const ep3_t q);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 24 using affine coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k24_basic(fp24_t l, ep4_t r, const ep4_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 24 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k24_projc(fp24_t l, ep4_t r, const ep4_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 48 using affine coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k48_basic(fp48_t l, fp8_t rx, fp8_t ry, fp8_t qx, fp8_t qy,
        const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 48 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k48_projc(fp48_t l, fp8_t rx, fp8_t ry, fp8_t rz, const fp8_t qx,
        const fp8_t qy, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 54 using affine coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k54_basic(fp54_t l, fp9_t rx, fp9_t ry, const fp9_t qx,
        const fp9_t qy, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 54 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k54_projc(fp54_t l, fp9_t rx, fp9_t ry, fp9_t rz, const fp9_t qx,
        const fp9_t qy, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 2 using affine
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] p				- the point to double.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_dbl_k2_basic(fp2_t l, ep_t r, const ep_t p, const ep_t q);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] p				- the point to double.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_dbl_k2_projc_basic(fp2_t l, ep_t r, const ep_t p, const ep_t q);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] p				- the point to double.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_dbl_k2_projc_lazyr(fp2_t l, ep_t r, const ep_t p, const ep_t q);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 8 using affine
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k8_basic(fp8_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 8 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k8_projc_basic(fp8_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 8 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k8_projc_lazyr(fp8_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using affine
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k12_basic(fp12_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Doubles a point and evaluates the correspodblnding line function at another
 * point on an elliptic curve with embedding degree 12 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k12_projc_basic(fp12_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k12_projc_lazyr(fp12_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18 using affine
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k18_basic(fp18_t l, ep3_t r, const ep3_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k18_projc_basic(fp18_t l, ep3_t r, const ep3_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k18_projc_lazyr(fp18_t l, ep3_t r, const ep3_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 24 using affine
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k24_basic(fp24_t l, ep4_t r, const ep4_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 24 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k24_projc(fp24_t l, ep4_t r, const ep4_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 48 using affine
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k48_basic(fp48_t l, fp8_t rx, fp8_t ry, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 48 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k48_projc(fp48_t l, fp8_t rx, fp8_t ry, fp8_t rz, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 54 using affine
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k54_basic(fp54_t l, fp9_t rx, fp9_t ry, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 54 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k54_projc(fp54_t l, fp9_t rx, fp9_t ry, fp9_t rz, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve twist with embedding degree 12 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] p				- the point to double.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_dbl_lit_k12(fp12_t l, ep_t r, const ep_t p, const ep2_t q);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve twist with embedding degree 18 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] p				- the point to double.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_dbl_lit_k18(fp18_t l, ep_t r, const ep_t p, const ep3_t q);

/**
 * Computes the final exponentiation for a pairing defined over curves of
 * embedding degree 2. Computes c = a^(p^2 - 1)/r.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
void pp_exp_k2(fp2_t c, fp2_t a);

/**
 * Computes the final exponentiation for a pairing defined over curves of
 * embedding degree 8. Computes c = a^(p^8 - 1)/r.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
void pp_exp_k8(fp8_t c, fp8_t a);

/**
 * Computes the final exponentiation for a pairing defined over curves of
 * embedding degree 12. Computes c = a^(p^12 - 1)/r.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
void pp_exp_k12(fp12_t c, fp12_t a);

/**
 * Computes the final exponentiation for a pairing defined over curves of
 * embedding degree 18. Computes c = a^(p^18 - 1)/r.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
void pp_exp_k18(fp18_t c, fp18_t a);

/**
 * Computes the final exponentiation for a pairing defined over curves of
 * embedding degree 24. Computes c = a^(p^24 - 1)/r.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
void pp_exp_k24(fp24_t c, fp24_t a);

/**
 * Computes the final exponentiation for a pairing defined over curves of
 * embedding degree 48. Computes c = a^(p^48 - 1)/r.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
void pp_exp_k48(fp48_t c, fp48_t a);

/**
 * Computes the final exponentiation for a pairing defined over curves of
 * embedding degree 54. Computes c = a^(p^54 - 1)/r.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
void pp_exp_k54(fp54_t c, fp54_t a);

/**
 * Normalizes the accumulator point used inside pairing computation defined
 * over curves of embedding degree 2.
 *
 * @param[out] r			- the resulting point.
 * @param[in] p				- the point to normalize.
 */
void pp_norm_k2(ep_t c, const ep_t a);

/**
 * Normalizes the accumulator point used inside pairing computation defined
 * over curves of embedding degree 8.
 *
 * @param[out] r			- the resulting point.
 * @param[in] p				- the point to normalize.
 */
void pp_norm_k8(ep2_t c, const ep2_t a);

/**
 * Normalizes the accumulator point used inside pairing computation defined
 * over curves of embedding degree 12.
 *
 * @param[out] r			- the resulting point.
 * @param[in] p				- the point to normalize.
 */
void pp_norm_k12(ep2_t c, const ep2_t a);

/**
 * Normalizes the accumulator point used inside pairing computation defined
 * over curves of embedding degree 18.
 *
 * @param[out] r			- the resulting point.
 * @param[in] p				- the point to normalize.
 */
void pp_norm_k18(ep3_t c, const ep3_t a);

/**
 * Normalizes the accumulator point used inside pairing computation defined
 * over curves of embedding degree 24.
 *
 * @param[out] r			- the resulting point.
 * @param[in] p				- the point to normalize.
 */
void pp_norm_k24(ep4_t c, const ep4_t a);

/**
 * Computes the Tate pairing of two points in a parameterized elliptic curve
 * with embedding degree 12.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_tatep_k2(fp2_t r, const ep_t p, const ep_t q);

/**
 * Computes the Tate multi-pairing of in a parameterized elliptic curve with
 * embedding degree 2.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_tatep_k2(fp2_t r, const ep_t *p, const ep_t *q, int m);

/**
 * Computes the Weil pairing of two points in a parameterized elliptic curve
 * with embedding degree 2.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_weilp_k2(fp2_t r, const ep_t p, const ep_t q);

/**
 * Computes the optimal ate pairing of two points in a parameterized elliptic
 * curve with embedding degree 8.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_oatep_k8(fp8_t r, const ep_t p, const ep2_t q);

/**
 * Computes the Weil multi-pairing of in a parameterized elliptic curve with
 * embedding degree 2.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_weilp_k2(fp2_t r, const ep_t *p, const ep_t *q, int m);

/**
 * Computes the Tate pairing of two points in a parameterized elliptic curve
 * with embedding degree 12.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_tatep_k12(fp12_t r, const ep_t p, const ep2_t q);

/**
 * Computes the Tate multi-pairing of in a parameterized elliptic curve with
 * embedding degree 12.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_tatep_k12(fp12_t r, const ep_t *p, const ep2_t *q, int m);

/**
 * Computes the Weil pairing of two points in a parameterized elliptic curve
 * with embedding degree 12.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_weilp_k12(fp12_t r, const ep_t p, const ep2_t q);

/**
 * Computes the Weil multi-pairing of in a parameterized elliptic curve with
 * embedding degree 12.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_weilp_k12(fp12_t r, const ep_t *p, const ep2_t *q, int m);

/**
 * Computes the optimal ate pairing of two points in a parameterized elliptic
 * curve with embedding degree 12.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_oatep_k12(fp12_t r, const ep_t p, const ep2_t q);

/**
 * Computes the optimal ate multi-pairing of in a parameterized elliptic
 * curve with embedding degree 12.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_oatep_k12(fp12_t r, const ep_t *p, const ep2_t *q, int m);

/**
 * Computes the Tate pairing of two points in a parameterized elliptic curve
 * with embedding degree 18.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_tatep_k18(fp18_t r, const ep_t p, const ep3_t q);

/**
 * Computes the Tate multi-pairing of in a parameterized elliptic curve with
 * embedding degree 18.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_tatep_k18(fp18_t r, const ep_t *p, const ep3_t *q, int m);

/**
 * Computes the Weil pairing of two points in a parameterized elliptic curve
 * with embedding degree 18.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_weilp_k18(fp18_t r, const ep_t p, const ep3_t q);

/**
 * Computes the Weil multi-pairing of in a parameterized elliptic curve with
 * embedding degree 18.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_weilp_k18(fp18_t r, const ep_t *p, const ep3_t *q, int m);

/**
 * Computes the optimal ate pairing of two points in a parameterized elliptic
 * curve with embedding degree 18.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_oatep_k18(fp18_t r, const ep_t p, const ep3_t q);

/**
 * Computes the optimal ate multi-pairing of in a parameterized elliptic
 * curve with embedding degree 18.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_oatep_k18(fp18_t r, const ep_t *p, const ep3_t *q, int m);

/**
 * Computes the Optimal Ate pairing of two points in a parameterized elliptic
 * curve with embedding degree 24.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_k24(fp24_t r, const ep_t p, const ep4_t q);

/**
 * Computes the optimal ate multi-pairing of in a parameterized elliptic
 * curve with embedding degree 24.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_k24(fp24_t r, const ep_t *p, const ep4_t *q, int m);

/**
 * Computes the Optimal Ate pairing of two points in a parameterized elliptic
 * curve with embedding degree 48.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_k48(fp48_t r, const ep_t p, const fp8_t qx, const fp8_t qy);

/**
 * Computes the Optimal Ate pairing of two points in a parameterized elliptic
 * curve with embedding degree 54.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_k54(fp54_t r, const ep_t p, const fp9_t qx, const fp9_t qy);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 13 using projective
 * coordinates and lazy reduction.
 *
 * @param[in, out] r		- the resulting point and the first  point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the first affine point to evaluate the function.
 * @param[in] p2			-the second affine point to evaluate the function.
 * @param[out] f1			- numerator of function l_{r,q}(p)/v_{r}(p).
 * @param[out] g1			- denominator of function l_{r,q}(p)/v_{r}(p).
 * @param[out] f2			- numerator of function l_{r,q}(p2)/v_{r}(p2).
 * @param[out] g2			- denominator of function l_{2r,q}(p2)/v_{r}(p2).
 */

void pp_add_k13_projc_lazyr(fp13_t f1, fp13_t g1, fp13_t f2, fp13_t g2, ep13_t r, ep13_t q, ep_t p, ep_t p2);

/**
 * Double one point and adds the reult with another point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 13 using projective
 * coordinates and lazy reduction.
 * @param[in, out] r		- the resulting point and first point to double and add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the first affine point to evaluate the line function.
 * @param[in] p2			-the second affine point to evaluate the line function.
 * @param[out] f1			- numerator of  function l_{2r,q}(p)/l_{-r,-r}(p).
 * @param[out] g1			- denominator of function l_{2r,q}(p)/l_{-r,-r}(p).
 * @param[out] f2			- numerator of function l_{2r,q}(p2)/l_{-r,-r}(p2).
 * @param[out] g2			- numerator of function l_{2r,q}(p2)/l_{-r,-r}(p2).
 */
void pp_dba_k13_projc_lazyr(fp13_t f1, fp13_t g1, fp13_t f2, fp13_t g2,  ep13_t r, ep13_t q, ep_t p, ep_t p2);

/**
 * quadruple a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 13 using projective
 * coordinates and lazy reduction.
 *
 * @param[in, out] r			- the the resulting  point .
 * @param[in] q				- the point to quadruple.
 * @param[in] p				- the affine point to evaluate the line function.
 * @param[in] p2			- the image of p under a 2-dimensional glv endomorphism.
 * @param[out] f1			- numerator of  function l_{2q,2q}(p)/l_{-q,-q}(p).
 * @param[out] g1			- denominator of of function l_{2q,2q}(p)/l_{-q,-q}(p).
 * @param[out] f2			- numerator of  function l_{2q,2q}(p2)/l_{-q,-q}(p2).
 * @param[out] g2			- numerator of  function l_{2q,2q}(p)/l_{-q,-q}(p2).
 */

void pp_qpl_k13_projc_lazyr(fp13_t f1, fp13_t g1, fp13_t f2, fp13_t g2, ep13_t q, ep_t p, ep_t p2);

/**
 * Computes the final exponentiation for a pairing defined over curves of
 * embedding degree 13. Computes c = (l1/l2)^(p^13 - 1)/r.
 *
 * @param[out] c			- the result.
 * @param[in] l1, l2			- the extension field element to exponentiate.
 */
void pp_exp_bwk13(fp13_t c, fp13_t l1, fp13_t l2);

/**
 * Computes the super optimal ate pairing of two points in a parameterized elliptic
 * curve with embedding degree 13 with quadruple miller loop
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_sup_oatep_k13(fp13_t r, ep_t p, ep13_t q);

/**
 * Computes the super  optimal ate multi-pairing of in a parameterized elliptic
 * curve with embedding 13 13 with quadruple miller loop
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_sup_oatep_k13(fp13_t r,  ep_t *p,   ep13_t *q, int m);



/**
 * Doubles a point and evaluates the correspodblnding line function at another
 * point on an elliptic curve with embedding degree 14 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l1			- the first result of the evaluation.
 * @param[out] l2			- the second result of the evaluation. * @param[in, out] r		        - the resulting point.
 * @param[in, out] r				- the point to double.
 * @param[in] p1			- the first affine point to evaluate the line function.
 * @param[in] p2			- the second affine point to evaluate the line function.
 */
void pp_dbl_k14(fp14_t l1, fp14_t l2,  ep7_t r,  const ep_t p1, const ep_t p2);
void pp_dbl_k14_first(fp14_t l1, fp14_t l2, ep7_t r, const ep_t p1,const ep_t p2);
void pp_dbl_k14_last(fp14_t l1, fp14_t l2, ep7_t r, const ep_t p1,const ep_t p2);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 14 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l1			- the first result of the evaluation.
 * @param[out] l2			- the second result of the evaluation.
 * @param[in, out] r		        - the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p1			- the first affine point to evaluate the line function.
 * @param[in] p2			- the second affine point to evaluate the line function.

 */
void pp_add_k14(fp14_t l1,fp14_t l2, ep7_t r, const ep7_t q, const ep_t p1, const ep_t p2);


/**
 * Computes the final exponentiation for a pairing defined over curves of
 * embedding degree 14. 
 *
 * @param[out] c			- the result.
 * @param[in]  a		- the extension field element to exponentiate.
 */
void pp_exp_bwk14(fp14_t c, fp14_t a);
void pp_map_sup_oatep_k14_basic(fp14_t r,  ep_t p,   ep7_t q);
void pp_map_sim_sup_oatep_k14_basic(fp14_t r,  ep_t *p,   ep7_t *q, int m);
void pp_map_sup_oatep_k14(fp14_t r,  ep_t p,   ep7_t q);
void pp_map_sim_sup_oatep_k14(fp14_t r,  ep_t *p,   ep7_t *q, int m);
#endif /* !RLC_PP_H */
