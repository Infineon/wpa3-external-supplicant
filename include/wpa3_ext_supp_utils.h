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

#include "cy_result.h"
#ifndef WPA3_EXT_NO_HARDWARE
#include "whd_endian.h"
#else
#include <stdbool.h>
#endif

#ifndef CYPRESS_WEAK
#if defined(__ICCARM__)
#define CYPRESS_WEAK            __WEAK
#define CYPRESS_PACKED(struct)  __packed struct
#elif defined(__GNUC__) || defined(__clang__) || defined(__CC_ARM)
#define CYPRESS_WEAK            __attribute__((weak))
#define CYPRESS_PACKED(struct)  struct __attribute__((packed))
#else
#define CYPRESS_WEAK           __attribute__((weak))
#define CYPRESS_PACKED(struct) struct __attribute__((packed))
#endif  /* defined(__ICCARM__) */
#endif /* CYPRESS_WEAK */

#define WPA3_EXT_SUPP_RSLT_SUCCESS                    0
#define WPA3_EXT_SUPP_RSLT_NO_MEM                     1
#define WPA3_EXT_SUPP_RSLT_AUTH_EXCHG_FAIL            2
#define WPA3_EXT_SUPP_RSLT_AUTH_BAD_ALGO              3
#define WPA3_EXT_SUPP_RSLT_SCALAR_ELEMENT_RANGE_ERROR 4
#define WPA3_EXT_SUPP_ERROR                           5
#define WPA3_EXT_CRYPTO_ERROR                         6
#define WPA3_EXT_PWE_GEN_FAILED                       7
#define WPA3_EXT_SUPP_CONFIRM_VERIFY_FAILURE          9
#define WPA3_EXT_SUPP_SILENTLY_DISCARD                10

#define WPA3_DEFINE_PLUS                              1      /**< positive sign bit */
#define WPA3_DEFINE_MINUS                            -1      /**< negative sign bit */

//#define WPA3_EXT_LOG_ENABLE
//#define WPA3_EXT_SUPPLICANT_DEBUG

#ifdef WPA3_EXT_LOG_ENABLE
#define WPA3_EXT_LOG_MSG(args) { printf args;}
#else
#define WPA3_EXT_LOG_MSG(args)
#endif

//#define WPA3_EXT_HEX_LOG_ENABLE

#ifdef WPA3_EXT_HEX_LOG_ENABLE
#define WPA3_EXT_HEX_BIGNUM_DUMP(args)      {wpa3_print_big_number args; }
#define WPA3_EXT_HEX_BUF_DUMP(args)         {wpa3_print_buf args; }
#else
#define WPA3_EXT_HEX_BIGNUM_DUMP(args)
#define WPA3_EXT_HEX_BUF_DUMP(args)
#endif


#define WPA3_EXT_HEX_BUF_DUMP_WITH_LABEL(label, arr, arr_len)   \
do                                                              \
{                                                               \
    WPA3_EXT_LOG_MSG(("%s:\n", label));                         \
    WPA3_EXT_HEX_BUF_DUMP((arr, arr_len));	                    \
}while(0)

#define WPA3_EXT_BIGNUM_DUMP_WITH_LABEL(label, bignum)          \
do                                                              \
{                                                               \
    WPA3_EXT_LOG_MSG(("%s:\n", label));                         \
    WPA3_EXT_HEX_BIGNUM_DUMP((bignum));                         \
}while(0)


/** This function allocates buffer
 * @param   buf               : The pointer to the whd buffer
 * @param   size              : The size of the buffer
 * @return  cy_rslt_t         : CY_RSLT_SUCESS
 *                            : CY_RSLT_MW_ERROR
 *
 *******************************************************************************/
cy_rslt_t wpa3_buffer_alloc( whd_buffer_t *buf, uint16_t size);

/** This function frees buffer
 * @param   buf               : The pointer to the whd buffer
 * @return  cy_rslt_t         : CY_RSLT_SUCESS
 *                            : CY_RSLT_MW_ERROR
 *
 *******************************************************************************/
cy_rslt_t wpa3_buffer_free( whd_buffer_t buf);

/** This function implements constant time memcmp
 * @param   a       : The pointer to a
 * @param   b       : The pointer to b
 * @param  len      : The length of the data to compare
 * @return  int     : The result is 0 if a == b else non-zero
 *
 *******************************************************************************/
int wpa3_constant_time_memcmp( uint8_t *a, uint8_t *b, uint16_t len );

/** This function checks if the buffer is odd
 * @param   buf     : The pointer to buffer
 * @param   len     : The length of the buffer
 * @return  bool    : The result is true if odd else false
 *
 *******************************************************************************/
bool wpa3_is_buf_val_odd(uint8_t * buf, uint16_t len);

/** This function prints the buffer
 * @param   buf     : The pointer to buffer
 * @param   len     : The length of the buffer
 *
 *******************************************************************************/
void wpa3_print_buf(uint8_t *buf, int len);

/** This function prints the big number
 * @param   bignum  : The pointer to big number
 *
 *******************************************************************************/
void wpa3_print_big_number(void *bignum);

/** This function compares values in constant time.
 * @param  a        : The value of a
 * @param  b        : The value of b
 * @return          : returns 0 if both are same else 1
 *
 *******************************************************************************/
int wpa3_const_time_int_cmp(uint8_t a, uint8_t b);
