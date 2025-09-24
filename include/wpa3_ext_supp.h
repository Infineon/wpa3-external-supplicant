/*
 * Copyright 2025, Cypress Semiconductor Corporation (an Infineon company) or
 * an affiliate of Cypress Semiconductor Corporation.  All rights reserved.
 *
 * This software, including source code, documentation and related
 * materials ("Software") is owned by Cypress Semiconductor Corporation
 * or one of its affiliates ("Cypress") and is protected by and subject to
 * worldwide patent protection (United States and foreign),
 * United States copyright laws and international treaty provisions.
 * Therefore, you may use this Software only as provided in the license
 * agreement accompanying the software package from which you
 * obtained this Software ("EULA").
 * If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
 * non-transferable license to copy, modify, and compile the Software
 * source code solely for use in connection with Cypress's
 * integrated circuit products.  Any reproduction, modification, translation,
 * compilation, or representation of this Software except as specified
 * above is prohibited without the express written permission of Cypress.
 *
 * Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
 * reserves the right to make changes to the Software without notice. Cypress
 * does not assume any liability arising out of the application or use of the
 * Software or any product or circuit described in the Software. Cypress does
 * not authorize its products for use in any products where a malfunction or
 * failure of the Cypress product may reasonably be expected to result in
 * significant property damage, injury or death ("High Risk Product"). By
 * including Cypress's product in a High Risk Product, the manufacturer
 * of such system or application assumes all risk of such use and in doing
 * so agrees to indemnify Cypress against all liability.
 */

#include "cy_result.h"
#ifndef WPA3_EXT_NO_HARDWARE
#include "cyabs_rtos_impl.h"
#include "cyabs_rtos.h"
#include "whd.h"
#include "whd_version.h"
#include "whd_int.h"
#include "whd_types.h"
#include "whd_wlioctl.h"
#include "whd_endian.h"
#include "whd_buffer_api.h"
#include "cy_wcm.h"
#else
#include "wpa3_ext_supp_stubs.h"
#include "wpa3_ext_crypto_stubs.h"
#include "wpa3_ext_rtos_stubs.h"
#include <string.h>
#endif
#include "wpa3_ext_supp_utils.h"
#include <stdlib.h>
#include "wpa3_wcm_intf.h"

#ifdef WPA3_UNIT_TEST_ENABLED
#define WHD_WIFI_STUB_IMPL(x,_stub) x ## _stub
#include "wpa3_ext_whd_stub.h"
#else
#ifdef WPA3_EXT_NO_HARDWARE
#define WHD_WIFI_STUB_IMPL(x,_stub) x ## _stub
#else /* WPA3_EXT_NO_HARDWARE */
#define WHD_WIFI_STUB_IMPL(x,_stub) x
#endif
#endif /* WPA3_UNIT_TEST_ENABLED */


#define WLAN_AUTH_FT             2
#define WLAN_AUTH_SAE            3
#define ETH_ADDR_LEN             6

/* AUTH Status fields */
#define WPA3_SAE_AUTH_STATUS_SUCCESS              0       /**< Success                      */
#define WPA3_SAE_AUTH_FAILURE                     1       /**< Unspecified failure          */
#define WPA3_SAE_AUTH_MISMATCH                    13      /**< Responding station does not support
                                                           * the specified authentication
                                                           * algorithm
                                                           */
#define WPA3_SAE_AUTH_SC_MISMATCH                 14      /**< Received an Authentication frame
                                                           * with authentication transaction
                                                           * sequence number out of expected
                                                           * sequence
                                                           */

#define WPA3_SAE_AUTH_AUTH_TIMEOUT                16      /**< Authentication rejected due to timeout */
#define WPA3_SAE_AUTH_ANTICLOG_TOKEN_REQUIRED     76      /**< Anti-clogging token required */
#define WPA3_SAE_AUTH_INVALID_FINITE_CYCLIC_GRP   77      /**< Invalid contents of RSNIE    */
#define WPA3_SAE_AUTH_HASH_TO_ELEMENT             126     /**< SAE hash-to-element          */

#define WLAN_FC_TYPE_MGMT        0
#define WLAN_FC_TYPE_CTRL        1
#define WLAN_FC_TYPE_DATA        2

#define WPA3_SAE_KCK_LEN                32
#define WPA3_SAE_PMK_LEN                32
#define WPA3_SAE_PMKID_LEN              16
#define WPA3_SAE_KEYSEED_KEY_LEN        32
#define WPA3_PWE_SEED_BUF_LEN           64
#define WPA3_SAE_SCALAR_LEN             32
#define WPA3_SAE_ELEMENT_LEN            64
#define WPA3_KCK_PMK_LEN                64
#define WPA3_KCK_PMK_LEN_BITS           512
#define WPA3_SAE_CONFIRM_LEN            32
#define WPA3_ECP_GROUP_P256R1_PRIME_LEN 32
#define WPA3_SAE_ANTICLOG_TOKEN_MIN_LEN 32
#define WPA3_SAE_ANTICLOG_TOKEN_MAX_LEN 64
#define WPA3_SAE_CONFIRM_MSG_BUFLEN     64
#define WPA3_KDF_EXPAND_LEN             (WPA3_SAE_KEYSEED_KEY_LEN + ( WPA3_SAE_KEYSEED_KEY_LEN + 1)/2)
#define WPA3_H2E_PT_XY_SIZE             65

#define WPA3_SAE_DOT11_MNG_ID_EXT_ID 255
#define WPA3_SAE_EXT_MNG_SAE_ANTI_CLOGGING_TOKEN_ID  93u  /**< WPA3 SAE anticlogging token container */
#define WAP3_SAE_DOT11_MNG_SAE_ANTI_CLOGGING_TOKEN_ID \
    (WPA3_SAE_DOT11_MNG_ID_EXT_ID + WPA3_SAE_EXT_MNG_SAE_ANTI_CLOGGING_TOKEN_ID)


#define WPA3_SAE_H2E_SUPPORTED    1


#define WPA3_SAE_COMMIT_MSG       1
#define WPA3_SAE_CONFIRM_MSG      2
#define WPA3_SAE_SEND_CONFIRM_LEN 2

#define WPA3_SAE_CONFIRM_DATA_MSG_LEN  (WPA3_SAE_SEND_CONFIRM_LEN + WPA3_SAE_SCALAR_LEN *2 + WPA3_SAE_ELEMENT_LEN *2 )


#define WPA3_SAE_ECP_GROUP_ID       19
#define WPA3_SAE_ECP_GROUP_ID_LEN   2
#define WPA3_SAE_ECP_CURVE_PARAM    10

#define WPA3_SSID_LEN               32
#define WPA3_MAX_PASSPHRASE_LEN     128

#define WPA3_PWE_SEED_MAX_LEN       80

#define WPA3_MAX_PWE_LOOP           40

#define WPA3_STA_INTERFACE          0

#define WPA3_SAE_HANDSHAKE_TIMEOUT_MS 7000
#define WPA3_SAE_HANDSHAKE_DELETE_MS 1

#define WPA3_SAE_MAX_RETRANS_ATTEMTPS 4

#define WPA3_SAE_RX_FRAME_MIN_LENGTH 30 /* 24 bytes 802.11 header + 6 bytes of Authentication header */

#define WPA3_MAX_SEMA_COUNT          1
#define WPA3_SCAN_SEMAPHORE_TIMEOUT  5000

/* management */
#define WLAN_FC_STYPE_AUTH      11
#define WPA3_SAE_EXIT_THREAD_DELAY  100

#ifndef OFFSETOF
#ifdef __ARMCC_VERSION
/*
 * The ARM RVCT compiler complains when using OFFSETOF where a constant
 * expression is expected, such as an initializer for a static object.
 * offsetof from the runtime library doesn't have that problem.
 */
#include <stddef.h>
#define OFFSETOF(type, member)  offsetof(type, member)
#else
#  if ((__GNUC__ >= 4) && (__GNUC_MINOR__ >= 8))
/* GCC 4.8+ complains when using our OFFSETOF macro in array length declarations. */
#    define OFFSETOF(type, member)  __builtin_offsetof(type, member)
#  else
#include <stdint.h>
#    define OFFSETOF(type, member)  ((uint)(uintptr_t)&((type *)0)->member)
#  endif /* GCC 4.8 or newer */
#endif /* __ARMCC_VERSION */
#endif /* OFFSETOF */

#include "wpa3_ext_crypto.h"

#define WPA3_AUTH_DATA_BUF_LEN  (1024)
#define WPA3_THREAD_STACK_SIZE  (1024 * 6)

#define WPA3_SUPPLICANT_QUEUE_SZ         10
#define WPA3_SUPPLICANT_WAIT_FOREVER    (0xFFFFFFFF)

/** WPA3 EXT supplicant states */
typedef enum
{
    WPA3_SUPPLICANT_NOTHING_STATE,      /**< WPA3 Supplicant Nothing state    */
    WPA3_SUPPLICANT_COMMITTED_STATE,    /**< WPA3 Supplicant Commit state     */
    WPA3_SUPPLICANT_CONFIRMED_STATE,    /**< WPA3 Supplicant confirmed state  */
    WPA3_SUPPLICANT_ACCEPTED_STATE      /**< WPA3 Supplicant connected state  */
} wpa3_supplicant_state_t;

/** struct wpa3_sae_sta_info_t (date) for password id and token */
typedef struct
{
    uint8_t *password_id;               /**< Password Identifier              */
    uint8_t *anticlog_token;            /**< Anticlogging token               */
} wpa3_sae_sta_info_t;

/** struct wpa3_sae_anticlog_container_t (date) for setting anticlog token with container */
typedef CYPRESS_PACKED(struct)
{
   uint8_t  id;                         /**< IE ID                           */
   uint8_t  len;                        /**< IE length                       */
   uint8_t  id_ext;                     /**< IE extension                    */
   uint8_t data[1];                     /**< WPA3 SAE Anticlogging token     */
} wpa3_sae_anticlog_container_t;

/** WPA3 EXT supplicant events */
typedef enum
{
    WPA3_SUPPLICANT_EVENT_NO_EVENT,     /**< WPA3 Supplicant No event        */
    WPA3_SAE_CONNECT_START,             /**< WPA3 Supplicant connect start   */
    WPA3_SUPPLICANT_EVENT_AUTH_REQ,     /**< WPA3 Supplicant auth request    */
    WPA3_SUPPLICANT_EVENT_AUTH_RX_FRAME,/**< WPA3 Supplicant auth rx frame   */
    WPA3_SUPPLICANT_EVENT_TIMEOUT,      /**< WPA3 Supplicant timeout event   */
    WPA3_SUPPLICANT_EVENT_COMPLETE,     /**< WPA3 Supplicant complete        */
    WPA3_SUPPLICANT_EVENT_DELETE        /**< WPA3 Supplicant delete event    */
} wpa3_supplicant_event_t;

/** struct wpa3_supplicant_event_message_t for handling supplicant message   */
typedef struct
{
    wpa3_supplicant_event_t event_type;  /**< WPA3 Supplicant event type     */
    void* data;                          /**< WPA3 Supplicant data           */
    uint16_t length;                     /**< WPA3 Supplicant data length    */
} wpa3_supplicant_event_message_t;

/** struct wpa3_supplicant_rtos_info_t for handling WPA EXT Supplicant thread information */
typedef struct
{
    cy_thread_t thread_handle;           /**< WPA3 Supplicant Thread         */
    void* thread_stack;                  /**< WPA3 Supplicant Thread Stack   */
    cy_queue_t event_queue;              /**< WPA3 Supplicant event queue    */
    cy_time_t timer_timeout;             /**< WPA3 Supplicant timer          */
} wpa3_supplicant_rtos_info_t;

/** struct wpa3_sae_auth_info_t for handling WPA EXT Supplicant authentication information */
typedef struct
{
  uint8_t ssid[WPA3_SSID_LEN];                    /**< SSID of the AP            */
  uint8_t ssid_len;                               /**< Length of SSID            */
  uint8_t passhphrase[WPA3_MAX_PASSPHRASE_LEN+1]; /**< Passphrase  + 1 byte counter  */
  uint8_t passphrase_len;                         /**< Length of Passphrase      */
  uint8_t ap_bssid[ETH_ADDR_LEN];                 /**< AP BSSID                  */
  uint8_t sta_mac[ETH_ADDR_LEN];                  /**< STA MAC Address           */
  void (*whd_auth_result_callback_t)( void *result_ptr, uint32_t*, whd_auth_status_t); /**< Auth Cbk function  */
} wpa3_sae_auth_info_t;

void wpa3_auth_req_callbackfunc ( void *result_ptr, uint32_t len, whd_auth_status_t status, uint8_t *flag,  void *user_data);
void wpa3_auth_join_callback (cy_wcm_event_t event, cy_wcm_event_data_t *event_data);


/** struct wpa3_supplicant_workspace_t for handling WPA EXT Supplicant context information */
typedef struct wpa3_supplicant_workspace
{
    void*                         wpa3_supp_workspace;                    /**< WPA3 Supplicant workspace      */
    whd_interface_t               interface;                              /**< WHD interface                  */
    cy_rslt_t                     supplicant_result;                      /**< WPA3 supplicant result         */
    wpa3_supplicant_rtos_info_t*  wpa3_rtos_info;                         /**< WPA3 supplicant RTOS info      */
    cy_timer_t                    wpa3_sae_timer;                         /**< WPA3 supplicant timer          */
    wpa3_supplicant_state_t       wpa3_state;                             /**< WPA3 State machine states      */
    wpa3_sae_context_info_t       wpa3_sae_context_info;                  /**< WPA3 SAE Context info          */
    wpa3_sae_auth_info_t          wpa3_sae_auth_info;                     /**< WPA3 SAE Auth info             */
    bool                          wpa3_h2e_capable;                       /**< WPA3 H2E capable AP            */
    bool                          wpa3_pwe_generation_done;               /**< WPA3 PWE generation done       */
    bool                          wpa3_h2e_method;                        /**< WPA3 H2E method                */
    bool                          wpa3_sae_rx_handshake_fail;             /**< WPA3 SAE Handshake failure     */
    bool                          wpa3_sae_handshake_success;             /**< WPA3 SAE Handshake success     */
    bool                          wpa3_sae_statemachine_exit;             /**< WPA3 SAE state machine exit    */
    bool                          wpa3_anticlog_token_present;            /**< WPA3 Anti clog token           */
    uint8_t wpa3_sae_anticlog_token[WPA3_SAE_ANTICLOG_TOKEN_MAX_LEN + 1]; /**< Anticlog token                 */
    uint16_t                      wpa3_sae_anticlog_token_len;            /**< Anticlog token length          */
    wpa3_crypto_context_info_t*   wpa3_crypto_ctxt;                       /**< WPA3 Crypto context            */
    uint32_t                      wpa3_sae_sync;                          /**< WPA3 SAE sync                  */
    cy_time_t                     start_time;                             /**< Start time                     */
    cy_time_t                     wpa3_handshake_start_time;              /**< WPA3 Handshake start time      */
    cy_time_t                     wpa3_handshake_current_time;            /**< WPA3 Handshake current time    */
} wpa3_supplicant_workspace_t;

/** struct dot11_mgmt_auth_t for handling WPA EXT Supplicant 802.11 HDR and Auth Frame with Body */
typedef CYPRESS_PACKED(struct)
{
    uint16_t frame_control;         /**< 802.11 HDR frame control       */
    uint16_t duration;              /**< 802.11 HDR duration            */
    uint8_t dst_addr[6];            /**< 802.11 HDR destination address */
    uint8_t src_addr[6];            /**< 802.11 HDR source address      */
    uint8_t bssid[6];               /**< 802.11 HDR BSSID               */
    uint16_t seq_ctrl;              /**< AUTH HDR  sequence             */
    uint16_t auth_alg;              /**< AUTH HDR algorithm             */
    uint16_t auth_transaction;      /**< AUTH transaction ID            */
    uint16_t status_code;           /**< AUTH Status code               */
    uint8_t data[1];                /**< AUTH Frame body                */
} dot11_mgmt_auth_t;

/** This function Initializes the WPA3 supplicant workspace
 * @param   wksp       : The double pointer the WPA3 supplicant workspace
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 *******************************************************************************/
cy_rslt_t wpa3_supplicant_init_workspace ( wpa3_supplicant_workspace_t ** wksp);

/** This function Initializes the WPA3 supplicant workspace for PT derivation.
 * @param   wksp       : The double pointer the WPA3 supplicant workspace
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 *******************************************************************************/
cy_rslt_t wpa3_supplicant_init_pt_workspace ( wpa3_supplicant_workspace_t ** wksp);

/** This function de-initializes the WPA3 supplicant workspace
 * @param   wksp       : The pointer the WPA3 supplicant workspace
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 *******************************************************************************/
cy_rslt_t wpa3_supplicant_deinit_sae_context_info(wpa3_supplicant_workspace_t *wksp);

/** This function de-initializes the WPA3 supplicant workspace
 * @param   wksp       : The double pointer the WPA3 supplicant workspace
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 *******************************************************************************/
cy_rslt_t wpa3_supplicant_deinit_workspace(wpa3_supplicant_workspace_t *wksp);

/** This function de-initializes the WPA3 supplicant workspace for PT derivation.
 * @param   wksp       : The double pointer the WPA3 supplicant workspace
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 *******************************************************************************/
cy_rslt_t wpa3_supplicant_deinit_pt_workspace(wpa3_supplicant_workspace_t *wksp);

/** This function sends event WPA3 supplicant thread
 * @param   workspace  : The pointer to WPA3 supplicant workspace
 * @param   msg        : The pointer to supplicant message
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 *******************************************************************************/
cy_rslt_t wpa3_supplicant_send_event( wpa3_supplicant_workspace_t* workspace, wpa3_supplicant_event_message_t* msg );

/** This function implements WPA3 SAE state machine main thread
 * @param   arg        : The pointer value Thread argument
 *
 *******************************************************************************/
void wpa3_sae_statemachine ( cy_thread_arg_t arg );


/** This function builds AUTH frame to be sent to WHD
 * @param   params     : The pointer value to be params
 * @param   len        : The length of the data
 * @param   srcaddr    : The pointer to the source MAC address
 * @param   dstaddr    : The point to the destination MAC address
 * @param   auth_transaction: The AUTH Transaction
 * @param   seq_num    : The sequence number
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 *******************************************************************************/
cy_rslt_t wpa3_build_sae_auth_frame(uint8_t *params, uint16_t len, uint8_t *srcaddr, uint8_t *dstaddr,
                                    uint16_t auth_transaction, uint16_t seq_num);


/** This function computes concatenates STA MAC and AP MAC into output buffer
 * @param   sta_mac    : The pointer to the STA mac address
 * @param   ap_bssid   : The pointer to the BSSID of AP
 * @param   output     : The pointer to the output data
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_sta_mac_ap_bssid_buf(uint8_t *sta_mac, uint8_t *ap_bssid, uint8_t *output);

/** This function computes scalar and element
 * @param   workspace  : The pointer to WPA3 supplicant workspace
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_crypto_gen_scalar_and_element(wpa3_supplicant_workspace_t* workspace);

/** This function builds commit frame
 * @param   workspace  : The pointer to WPA3 supplicant workspace
 * @param   buffer     : The pointer to the buffer
 * @param   auth_status: The value of Auth Status
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_sae_build_commit_message ( wpa3_supplicant_workspace_t *workspace, whd_buffer_t *buffer, uint8_t auth_status);

/** This function builds confirm frame
 * @param   workspace  : The pointer to WPA3 supplicant workspace
 * @param   buffer     : The pointer to the buffer
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_sae_build_confirm_message( wpa3_supplicant_workspace_t *workspace, whd_buffer_t *buffer );

/** This function sends commit frame or confirm frame
 * @param   workspace  : The pointer to WPA3 supplicant workspace
 * @param   buffer     : The pointer to the buffer
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_sae_send_message ( wpa3_supplicant_workspace_t *workspace, whd_buffer_t buffer);

/** This function verifies confirm message
 * @param   workspace  : The pointer to WPA3 supplicant workspace
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_sae_verify_confirm_message(wpa3_supplicant_workspace_t *workspace);

/** This function processes the RX frame received from WHD
 * @param   workspace        : The pointer to WPA3 supplicant workspace
 * @param   buffer           : The pointer to the buffer
 * @param   len              : The length of the buffer
 * @param   auth_transaction : The pointer to auth transaction
 * @return  cy_rslt_t        : CY_RSLT_SUCCESS
 *                           : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_sae_process_rx_frame ( wpa3_supplicant_workspace_t *workspace, whd_buffer_t *buffer,
		                              uint16_t len, uint16_t *auth_transaction);

/** This function verifies the confirm message
 * @param   workspace  : The pointer to WPA3 supplicant workspace
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_crypto_verify_confirm_message(wpa3_supplicant_workspace_t *workspace);

/** This function sets auth status, pmk , pmkid and starts a timer t1
 * @param   workspace  : The pointer to WPA3 supplicant workspace
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_sae_handshake_complete( wpa3_supplicant_workspace_t * workspace);

/** This function sends event WPA3_SUPPLICANT_EVENT_DELETE to delete wpa3 supplicant workspace
 * @param   workspace       : The pointer to WPA3 supplicant workspace
 * @param   auth_transaction: The authentication message type
 * @param   status          : The authentication status
 * @return  cy_rslt_t       : CY_RSLT_SUCCESS
 *                          : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_sae_handshake_failure( wpa3_supplicant_workspace_t* workspace, uint16_t auth_transaction, uint16_t status);

/** This function builds auth reject frame
 * @param   workspace       : The pointer to WPA3 supplicant workspace
 * @param   buffer          : The pointer to the buffer
 * @param   auth_status     : The authentication status
 * @param   auth_transaction: The authentication transaction
 * @return  cy_rslt_t       : CY_RSLT_SUCCESS
 *                          : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_sae_build_auth_rej_message( wpa3_supplicant_workspace_t *workspace, whd_buffer_t *buffer, uint16_t auth_status, uint16_t auth_transaction );

/** This function initializes WPA3 SAE context information
 * @param   wksp       : The pointer to WPA3 supplicant workspace
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_supplicant_init_sae_context_info(wpa3_supplicant_workspace_t *wksp);

/** This function checks peer scalar and element not same as own scalar and element
 * @param   workspace  : The pointer to WPA3 supplicant workspace
 * @return  cy_rslt_t  : CY_RSLT_SUCCESS
 *                     : CY_RSLT_TYPE_ERROR
 *
 * *******************************************************************************/
cy_rslt_t wpa3_crypto_chk_own_peer_scalar_element(wpa3_supplicant_workspace_t* workspace);

/** This function handles WPA3 SAE timer expiry
 * @param   arg       : The pointer to WPA3 supplicant workspace
 *
 * *******************************************************************************/
void wpa3_sae_timer_expiry(cy_timer_callback_arg_t arg);

/** This function parse tlvs of extension id
 * @param    tlv_buf    : The pointer to TLV buffer
 * @param    buflen     : The length of the buffer
 * @param    key        : The key to match
 * @return   uint8_t*   : The pointer to matched key buffer or null
 * *******************************************************************************/
uint8_t* wpa3_sae_parse_tlvs(uint8_t *tlv_buf, int buflen, uint key);

/** This function gets the anticlogging container IE pointer
 * @param    parse                            : The pointer to buffer to parsed
 * @param    len                              : The length of the buffer
 * @return   wpa3_sae_anticlog_container_t*   : The pointer to container ie structure
 * *******************************************************************************/
wpa3_sae_anticlog_container_t *wpa3_sae_find_anticlog_ie(uint8_t *parse, int len);

/** This function prints WPA3 Supplicant State
 * @param    state                            : The WPA3 State
 * *********************************************************************************/
void wpa3_print_state(uint8_t state);

/** This function prints WPA3 Supplicant event
 * @param    event                            : The WPA3 event
 * *********************************************************************************/
void wpa3_print_event(uint8_t event);

/** This function gets WPA3 Supplicant workspace
 * @return wpa3_supplicant_workspace_t*       : The pointer to the WPA3 supplicant workspace
 * *********************************************************************************/
wpa3_supplicant_workspace_t* wpa3_sae_get_workspace (void );

/** This function sets WPA3 Supplicant workspace
 * @param wksp   : The pointer to the WPA3 supplicant workspace
 * *********************************************************************************/
void wpa3_sae_set_workspace( wpa3_supplicant_workspace_t *wksp);

/** This function cleans the WPA3 supplicant workspace and deletes WPA3 Supplicant
 *  State machine thread and its stack memory
 * **********************************************************************************/
void wpa3_sae_cleanup_workspace(void);

/** This function starts scan
 * @param   iface          : The interface to whd
 * @param   sae_auth_info  : The pointer to WPA3 supplicant authentication info
 * @return  cy_rslt_t      : CY_RSLT_SUCCESS
 *                         : CY_RSLT_TYPE_ERROR
 * *******************************************************************************/
cy_rslt_t wpa3_sae_start_scan_hdl ( whd_interface_t iface, wpa3_sae_auth_info_t * sae_auth_info);
