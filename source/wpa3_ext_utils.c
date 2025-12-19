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

/* DATA buffer implementation */

#include "wpa3_ext_supp.h"

static whd_buffer_t   packet = NULL;

cy_rslt_t wpa3_buffer_alloc( whd_buffer_t *buf, uint16_t size)
{
   /* Create the buffer */
   packet = (whd_buffer_t *)malloc(size);

   if ( packet == NULL)
   {
       WPA3_EXT_LOG_MSG(("\n WPA3-EXT-SUPP: ALLOC buffer failed\n"));
       return WPA3_EXT_SUPP_RSLT_NO_MEM;
   }
   *buf = packet;
   WPA3_EXT_LOG_MSG(("\n WPA3-EXT-SUPP: ALLOC buffer ptr=%p\n", *buf));
   return CY_RSLT_SUCCESS;
}

cy_rslt_t wpa3_buffer_free(whd_buffer_t buffer)
{
    if (( buffer != NULL ) && ( packet != NULL))
    {
        free(buffer);
        packet = NULL;
        buffer = NULL;
    }
    return CY_RSLT_SUCCESS;
}

int wpa3_constant_time_memcmp( uint8_t *a, uint8_t *b, uint16_t len )
{
    volatile uint8_t *cmp1 = (volatile uint8_t*) a;
    volatile uint8_t *cmp2 = (volatile uint8_t*) b;
    int i, xor = 0;

    for( i = 0; i < len; i++ )
    {
        /* xor bit result will return > 0 if a and b value differ else 0
         * bitwise xor
         *  a b xor
         *  0 0 0
         *  0 1 1
         *  1 0 1
         *  1 1 0
         */
        xor |= cmp1[i] ^ cmp2[i];
    }
    return( (int)xor );
}

int wpa3_const_time_int_cmp(uint8_t a, uint8_t b)
{
    int xor;
    xor  = a ^ b;
    return ( (int)xor);
}

wpa3_sae_anticlog_container_t *wpa3_sae_find_anticlog_ie(uint8_t *parse, int len)
{
    wpa3_sae_anticlog_container_t *ie = NULL;
    while ((ie = (wpa3_sae_anticlog_container_t *)wpa3_sae_parse_tlvs(parse, (int)len, WPA3_SAE_DOT11_MNG_ID_EXT_ID)))
    {
       if ( ie->id_ext == WPA3_SAE_EXT_MNG_SAE_ANTI_CLOGGING_TOKEN_ID)
       {
          WPA3_EXT_LOG_MSG(("\n WPA3-EXT-SUPP:WPA3_SAE_EXT_MNG_SAE_ANTI_CLOGGING_TOKEN_ID found!\n"));
          return ie;
       }
    }
    return NULL;
}

uint8_t* wpa3_sae_parse_tlvs(uint8_t *tlv_buf, int buflen, uint key)
{
    uint8_t *cp;
    int totlen;
    cp = tlv_buf;
    totlen = buflen;

    /* find tagged parameter */
    while (totlen >= 3) {
        uint8_t tag;
        uint8_t len;

        tag = *cp;
        len = *(cp +1);

        /* validate remaining totlen  = bodylen + tag + len */
        if ((tag == key) && (totlen >= (len + 2)))
        {
            WPA3_EXT_LOG_MSG(("\n WPA3-EXT-SUPP:wpa3_sae_parse_tlvs found tag=%d key=%d\n", tag, key));
            return (cp);
        }
        else
        {
            WPA3_EXT_LOG_MSG(("\n WPA3-EXT-SUPP:wpa3_sae_parse_tlvs not found tag=%d key=%d totlen=%d len=%d\n", tag, key, totlen, len));
        }

        cp += (len + 3);
        totlen -= (len + 3);
    }
    return NULL;
}

bool wpa3_is_buf_val_odd(uint8_t * buf, uint16_t len)
{
    bool ret = false;
    ret = ((buf [len-1] & 1 ) != 0 );
    return ret;
}


void wpa3_print_buf(uint8_t *buf, int len)
{
    int i;
    if ( ( len == 0 ) || ( buf == NULL ))
        return;
    for ( i = 0; i < len ; i++ )
    {
        if (( i % 16 == 0 ) && (i != 0))
        {
            WPA3_EXT_LOG_MSG(("\n"));
        }
        WPA3_EXT_LOG_MSG(("%02x ", buf[i]));
    }
    WPA3_EXT_LOG_MSG(("\n WPA3-EXT-SUPP:buf data end >>>\n"));
}

void wpa3_print_state(uint8_t state)
{
   switch(state)
   {
   case WPA3_SUPPLICANT_NOTHING_STATE:
       WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:wpa3_state:%s\n", "WPA3_SUPPLICANT_NOTHING_STATE"));
       break;
   case WPA3_SUPPLICANT_COMMITTED_STATE:
       WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:wpa3_state:%s\n", "WPA3_SUPPLICANT_COMMITTED_STATE"));
       break;
   case WPA3_SUPPLICANT_CONFIRMED_STATE:
       WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:wpa3_state:%s\n", "WPA3_SUPPLICANT_CONFIRMED_STATE"));
       break;
   case WPA3_SUPPLICANT_ACCEPTED_STATE:
       WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPPwpa3_state:%s\n",  "WPA3_SUPPLICANT_ACCEPTED_STATE"));
       break;
   default:
       WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:wpa3_state:%s\n", "WPA3_SUPPLICANT_UNKNOWN_STATE"));
       break;
   }/* end of switch */
}

void wpa3_print_event(uint8_t event)
{
    switch(event)
    {
       case WPA3_SUPPLICANT_EVENT_NO_EVENT:
           WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:wpa3 event:%s\n", "WPA3_SUPPLICANT_EVENT_NO_EVENT"));
           break;
       case WPA3_SAE_CONNECT_START:
           WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:wpa3 event:%s\n", "WPA3_SAE_CONNECT_START"));
           break;
       case WPA3_SUPPLICANT_EVENT_AUTH_REQ:
           WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:wpa3 event:%s\n", "WPA3_SUPPLICANT_EVENT_AUTH_REQ"));
           break;
       case WPA3_SUPPLICANT_EVENT_AUTH_RX_FRAME:
           WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:wpa3 event:%s\n", "WPA3_SUPPLICANT_EVENT_AUTH_RX_FRAME"));
           break;
       case WPA3_SUPPLICANT_EVENT_TIMEOUT:
           WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:wpa3 event:%s\n", "WPA3_SUPPLICANT_EVENT_TIMEOUT"));
           break;
       case WPA3_SUPPLICANT_EVENT_COMPLETE:
           WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:wpa3 event:%s\n", "WPA3_SUPPLICANT_EVENT_COMPLETE"));
           break;
       case WPA3_SUPPLICANT_EVENT_DELETE:
           WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:wpa3 event:%s\n", "WPA3_SUPPLICANT_EVENT_DELETE"));
           break;
       default:
           WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:wpa3 event:%s\n", "WPA3_SUPPLICANT_EVENT_UNKNOWN"));
           break;
    }/* end of switch */
}

/* TODO : Move to crypto.c */
#if defined (COMPONENT_MBEDTLS)

void wpa3_print_big_number(void *bignum)
{
    int i;
    mbedtls_mpi *n = (mbedtls_mpi*)bignum;

    if (n != NULL)
    {
        if (n->MBEDTLS_PRIVATE(s) == WPA3_DEFINE_MINUS)
        {
            WPA3_EXT_LOG_MSG(("- "));
        }
        for (i=(n->MBEDTLS_PRIVATE(n))-1 ; i>=0; i--)
        {
            if (( (i+1) % 8 == 0) && ( i > 0 ))
            {
                WPA3_EXT_LOG_MSG(("\n"));
            }
            WPA3_EXT_LOG_MSG(("%02lx ",n->MBEDTLS_PRIVATE(p)[i]));
        }
        WPA3_EXT_LOG_MSG(("\n"));
    }
}
#elif defined (COMPONENT_NETXSECURE)

void wpa3_print_big_number(void *bignum)
{
    UCHAR buffer[128];
    UINT size = 0;
    UINT status;
    NX_CRYPTO_HUGE_NUMBER *num = (NX_CRYPTO_HUGE_NUMBER *)bignum;

    if (num == NULL)
    {
        return;
    }

    status = _nx_crypto_huge_number_extract(num, buffer, sizeof(buffer), &size);
    if (status != 0)
    {
        WPA3_EXT_LOG_MSG(("%s: Extraction failed (status=%u)\n", __func__, status));
        return;
    }

    for (UINT i = 0; i < size; i++)
    {
        if ((i != 0) && (i % 4 == 0))
        {
            WPA3_EXT_LOG_MSG((" "));
            if (i % 32 == 0)
            {
                WPA3_EXT_LOG_MSG(("\n"));
            }
        }
        WPA3_EXT_LOG_MSG(("%02x", buffer[i]));
    }
    WPA3_EXT_LOG_MSG(("\n"));
}

#else
void wpa3_print_big_number(void *bignum)
{
    WPA3_EXT_LOG_MSG(("Logging not supported\n"));
}
#endif
