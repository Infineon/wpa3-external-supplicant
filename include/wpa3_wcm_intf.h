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

/** Application interface header file */
#include "cy_result.h"

/**
 * \defgroup group_wpa3_ext_supplicant_wcm_interface_function Functions
 */

/**
 * \addtogroup group_wpa3_ext_supplicant_wcm_interface_function
 * \{
 * * The WPA3 External Supplicant SAE Start API
 * * The below API is a non-blocking call
 */


/** This function initializes the WPA3 External Supplicant middleware library by initializing following
 *   * i.   Initializes the WPA3 External Supplicant
 *   * ii.  Initializes the WPA3 Crypto Context information
 *
 * @return cy_rslt_t : CY_RSLT_SUCCESS
 *                   : WPA3_EXT_SUPP_ERROR
  *******************************************************************************/
cy_rslt_t wpa3_supplicant_sae_start (uint8_t *ssid, uint8_t ssid_len, uint8_t *passphrase, uint8_t passphrase_len);

/** This function waits for the SAE handshake completion and performs the cleanup (Success/Fail/Timeout)
 *
 * @return
  *******************************************************************************/
void wpa3_supplicant_sae_cleanup(void);

/** \} group_wpa3_ext_supplicant_wcm_interface_function */
