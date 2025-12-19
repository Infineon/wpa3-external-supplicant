/*
 * (c) 2025, Infineon Technologies AG, or an affiliate of Infineon
 * Technologies AG. All rights reserved.
 * This software, associated documentation and materials ("Software") is
 * owned by Infineon Technologies AG or one of its affiliates ("Infineon")
 * and is protected by and subject to worldwide patent protection, worldwide
 * copyright laws, and international treaty provisions. Therefore, you may use
 * this Software only as provided in the license agreement accompanying the
 * software package from which you obtained this Software. If no license
 * agreement applies, then any use, reproduction, modification, translation, or
 * compilation of this Software is prohibited without the express written
 * permission of Infineon.
 *
 * Disclaimer: UNLESS OTHERWISE EXPRESSLY AGREED WITH INFINEON, THIS SOFTWARE
 * IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING, BUT NOT LIMITED TO, ALL WARRANTIES OF NON-INFRINGEMENT OF
 * THIRD-PARTY RIGHTS AND IMPLIED WARRANTIES SUCH AS WARRANTIES OF FITNESS FOR A
 * SPECIFIC USE/PURPOSE OR MERCHANTABILITY.
 * Infineon reserves the right to make changes to the Software without notice.
 * You are responsible for properly designing, programming, and testing the
 * functionality and safety of your intended application of the Software, as
 * well as complying with any legal requirements related to its use. Infineon
 * does not guarantee that the Software will be free from intrusion, data theft
 * or loss, or other breaches ("Security Breaches"), and Infineon shall have
 * no liability arising out of any Security Breaches. Unless otherwise
 * explicitly approved by Infineon, the Software may not be used in any
 * application where a failure of the Product or any consequences of the use
 * thereof can reasonably be expected to result in personal injury.
 */
/*
 * wpa3_ext_crypto.h
 *
 */

#ifndef WPA3_EXT_CRYPTO_H_
#define WPA3_EXT_CRYPTO_H_

#if defined (COMPONENT_MBEDTLS)

#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/hkdf.h"

#ifndef MBEDTLS_PRIVATE
#define MBEDTLS_PRIVATE(member) member
#endif

/** struct wpa3_sae_context_info_t for handling SAE context information */
typedef struct
{
    mbedtls_mpi peer_commit_scalar;             /**< peer Commit scalar    */
    mbedtls_ecp_point peer_commit_element;      /**< peer commit element   */
    uint16_t peer_group_id;                     /**< peer Group ID         */
    uint16_t sndconfirm;                        /**< STA send confirm      */
    uint16_t sc;                                /**< sync variable         */
    uint16_t rc;                                /**< received send confirm */
    uint8_t pmk[WPA3_SAE_PMK_LEN];              /**< Pairwise Master Key   */
    uint8_t kck[WPA3_SAE_KCK_LEN];              /**< Key confirmation Key  */
    uint8_t pmkid[WPA3_SAE_PMKID_LEN];          /**< Pairwise Master KeyID */
    uint8_t peer_confirm[WPA3_SAE_CONFIRM_LEN]; /**< peer confirm          */
} wpa3_sae_context_info_t;

/** struct wpa3_crypto_context_info_t for handling WPA EXT Supplicant crypto information */
typedef struct
{
    mbedtls_ecp_group  group;                 /**< ECP group                          */
    mbedtls_ecp_point  pwe;                   /**< xy point(pwe)of the ECP Curve      */
    mbedtls_entropy_context entropy;          /**< Entropy context                    */
    mbedtls_ctr_drbg_context ctr_drbg;        /**< CTR DBG context                    */
    bool pwe_found;                           /**< PWE Element found                  */
    uint16_t group_id;                        /**< ECP group ID                       */
    uint8_t x_buf[WPA3_SAE_KEYSEED_KEY_LEN];  /**< x_buf in uint8_t*                  */
    uint8_t y_buf[WPA3_SAE_KEYSEED_KEY_LEN];  /**< y_buf in uint8_t*                  */
    uint8_t py_buf[WPA3_SAE_KEYSEED_KEY_LEN]; /**< py_buf in uint8_t*                 */
    uint8_t confirm[WPA3_SAE_CONFIRM_LEN];    /**< confirm msg in uint8_t*            */
    mbedtls_mpi sta_scalar;                   /**< STA scalar                         */
    mbedtls_mpi sta_private;                  /**< STA private                        */
    mbedtls_ecp_point sta_commit_element;     /**< STA commit element                 */
    mbedtls_mpi sta_sae_rand;                 /**< STA SAE Random buffer              */
    mbedtls_ecp_point sta_pt_element;         /**< STA PT Element                     */
} wpa3_crypto_context_info_t;

#elif defined (COMPONENT_NETXSECURE)

#include "nx_crypto_drbg.h"
#include "nx_crypto_hmac.h"
#include "nx_crypto_hkdf.h"
#include "nx_api.h"
#include "nx_crypto_ec.h"
#include "nx_crypto_huge_number.h"


/** struct wpa3_sae_context_info_t for handling SAE context information */
typedef struct
{
    NX_CRYPTO_HUGE_NUMBER  peer_commit_scalar;              /**< peer Commit scalar                */
    NX_CRYPTO_EC_POINT     peer_commit_element;             /**< peer commit element               */
    UCHAR                 *scratch_buffer;                  /**< Scratch buffer for scalar/element */
    uint16_t peer_group_id;                                 /**< peer Group ID                     */
    uint16_t sndconfirm;                                    /**< STA send confirm                  */
    uint16_t sc;                                            /**< sync variable                     */
    uint16_t rc;                                            /**< received send confirm             */
    uint8_t pmk[WPA3_SAE_PMK_LEN];                          /**< Pairwise Master Key               */
    uint8_t kck[WPA3_SAE_KCK_LEN];                          /**< Key confirmation Key              */
    uint8_t pmkid[WPA3_SAE_PMKID_LEN];                      /**< Pairwise Master KeyID             */
    uint8_t peer_confirm[WPA3_SAE_CONFIRM_LEN];             /**< peer confirm                      */
} wpa3_sae_context_info_t;

/** struct wpa3_crypto_context_info_t for handling WPA EXT Supplicant crypto information */
typedef struct
{
    NX_CRYPTO_EC          *curve;                           /**< ECP curve pointer                  */
    NX_CRYPTO_EC_POINT    pwe;                              /**< xy point(pwe)of the ECP Curve      */
    bool                  pwe_found;                        /**< PWE Element found                  */
    uint16_t              group_id;                         /**< ECP group ID                       */
    uint8_t               x_buf[WPA3_SAE_KEYSEED_KEY_LEN];  /**< x_buf in uint8_t*                  */
    uint8_t               y_buf[WPA3_SAE_KEYSEED_KEY_LEN];  /**< y_buf in uint8_t*                  */
    uint8_t               py_buf[WPA3_SAE_KEYSEED_KEY_LEN]; /**< py_buf in uint8_t*                 */
    uint8_t               confirm[WPA3_SAE_CONFIRM_LEN];    /**< confirm msg in uint8_t*            */
    NX_CRYPTO_HUGE_NUMBER sta_scalar;                       /**< STA scalar                         */
    NX_CRYPTO_HUGE_NUMBER sta_private;                      /**< STA private                        */
    NX_CRYPTO_EC_POINT    sta_commit_element;               /**< STA commit element                 */
    NX_CRYPTO_EC_POINT    sta_pt_element;                   /**< STA PT Element                     */
    UCHAR                 *scratch_buffer;                  /**< Scratch buffer for the HUGE NUMBER */
} wpa3_crypto_context_info_t;

#else
#error "WPA3-EXT-SUPP: Unsupported crypto stack"
#endif

struct wpa3_supplicant_workspace;

/** This function start PWE generation for HnP
 * @param   workspace : The pointer extended WPA3 workspace context
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 *******************************************************************************/
cy_rslt_t wpa3_crypto_start_pwe_generation(struct wpa3_supplicant_workspace *workspace);

/** This function checks valid point on ECP curve
 * @param   wksp       : The pointer extended WPA3 workspace context
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 *******************************************************************************/
cy_rslt_t wpa3_crypto_check_valid_point_on_ecp_curve(struct wpa3_supplicant_workspace *wksp );

/** This function start PWE generation from PT for H2E
 * @param   wksp       : The pointer extended WPA3 workspace context
 * @param   ssid       : The pointer ssid
 * @param   passphrase : The pointer passphrase
 * @param   output     : The pointer to the output buffer
 * @param   output_len : The pointer to the output length
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 *******************************************************************************/
cy_rslt_t wpa3_crypto_derive_pt( struct wpa3_supplicant_workspace *wksp, uint8_t *ssid, uint8_t *passphrase,
                                 uint8_t *output, uint8_t output_len);

/** This function start PWE generation from PT for H2E
 * @param   wksp       : The pointer extended WPA3 workspace context
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 *******************************************************************************/
cy_rslt_t wpa3_crypto_derive_pwe_from_pt( struct wpa3_supplicant_workspace *wksp);

/** This function gets own group id, scalar and element into a buffer
 * @param   workspace  : The pointer to WPA3 supplicant workspace
 * @param   buf        : The pointer to the buffer
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_crypto_get_grp_id_scalar_element(struct wpa3_supplicant_workspace* workspace, uint8_t * buf);

/** This function gets own group id into a buffer
 * @param   workspace  : The pointer to WPA3 supplicant workspace
 * @param   buf        : The pointer to the buffer
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_crypto_get_grp_id(struct wpa3_supplicant_workspace* workspace, uint8_t * buf);

/** This function gets own scalar and element into a buffer
 * @param   workspace  : The pointer to WPA3 supplicant workspace
 * @param   buf        : The pointer to the buffer
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_crypto_get_scalar_element(struct wpa3_supplicant_workspace* workspace, uint8_t * buf);


/** This function computes shared secret
 * @param   workspace  : The pointer to WPA3 supplicant workspace
 * @param   ss         : The pointer to shared secret
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_crypto_compute_shared_secret( struct wpa3_supplicant_workspace *workspace, uint8_t *ss);

/** This function computes KCK, PMK and PMKID
 * @param   workspace  : The pointer to WPA3 supplicant workspace
 * @param   ss         : The pointer to shared secret
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_crypto_derive_kck_pmk( struct wpa3_supplicant_workspace *workspace, uint8_t *ss);

/** This function gets peer group id, scalar and element from buffer
 * @param   workspace  : The pointer to WPA3 supplicant workspace
 * @param   buf        : The pointer to the buffer
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_crypto_get_peer_grp_id_scalar_element(struct wpa3_supplicant_workspace* workspace, uint8_t * buf);

/** This function gets confirm handshake to buffer
 * @param   workspace  : The pointer to WPA3 supplicant workspace
 * @param   buf        : The pointer to the buffer
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_crypto_get_send_confirm_handshake(struct wpa3_supplicant_workspace* workspace, uint8_t * buf);

/** This function gets confirm handshake from buffer
 * @param   workspace  : The pointer to WPA3 supplicant workspace
 * @param   buf        : The pointer to the buffer
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_crypto_get_send_confirm(struct wpa3_supplicant_workspace* workspace, uint8_t *buf);

/** This function builds confirm handshake to buffer
 * @param   wksp       : The pointer to WPA3 supplicant workspace
 * @param   buffer     : The pointer to the buffer
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_crypto_build_send_confirm_handshake(struct wpa3_supplicant_workspace * wksp, uint8_t *buffer);

/** This function initializes wpa3 cyrpto context
 * @param   wksp       : The pointer to WPA3 supplicant workspace
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 * *******************************************************************************/
cy_rslt_t wpa3_crypto_init(struct wpa3_supplicant_workspace *wksp);

/** This function de-initializes wpa3 cyrpto context
 * @param   wksp       : The pointer to WPA3 supplicant workspace
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 * *******************************************************************************/
cy_rslt_t wpa3_crypto_deinit(struct wpa3_supplicant_workspace *wksp);

#endif /* WPA3_EXT_CRYPTO_H_ */
