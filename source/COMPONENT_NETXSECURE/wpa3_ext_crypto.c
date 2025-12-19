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

#include "wpa3_ext_supp.h"
#include <inttypes.h>

extern NX_CRYPTO_METHOD crypto_method_sha256;
extern NX_CRYPTO_METHOD crypto_method_hkdf;
extern NX_CRYPTO_METHOD crypto_method_hmac;

extern cy_rslt_t cy_wpa3_get_pfn_network( uint8_t * ssid, uint8_t *passphrase, uint8_t *pt );

/* Wrapper macro to check Function return */
#define NX_CRYPTO_CHECK_RET(f)                    \
    do                                            \
    {                                             \
        if( ( ret = (f) ) != NX_CRYPTO_SUCCESS )  \
            goto cleanup;                         \
    } while( 0 )

#define WPA3_EXT_CRYPTO_ALLOC_AND_VALIDATE_SCRATCH_BUFF(scratch_buffer, size, fail_ret)                     \
do {                                                                                                        \
    scratch_buffer = (HN_UBASE*)malloc(size);                                                               \
    if (scratch_buffer == NULL)                                                                             \
    {                                                                                                       \
        WPA3_EXT_LOG_MSG(("%s: WPA3-EXT-SUPP: Memory allocation failed for scratch buffer\n", __func__));   \
        return fail_ret;                                                                                    \
    }                                                                                                       \
} while(0)

#define NX_CRYPTO_UNCOMPRESSED_POINT 0x04

/**
 * @brief HKDF-Extract: create PRK from IKM and salt.
 *
 * @param hkdf_metadata HKDF context buffer.
 * @param hkdf_metadata_size Size of context buffer.
 * @param salt Salt input.
 * @param salt_len Length of salt.
 * @param ikm Input key material.
 * @param ikm_len Length of IKM.
 * @param prk Output buffer for PRK.
 * @param prk_len Length of PRK buffer.
 *
 * @return NX_CRYPTO_SUCCESS on success, error code otherwise.
 */
static UINT wpa3_crypto_hkdf_extract(UCHAR *hkdf_metadata, size_t hkdf_metadata_size,
                                     const UCHAR *salt, size_t salt_len,
                                     const UCHAR *ikm, size_t ikm_len,
                                     UCHAR *prk, size_t prk_len)
{
    UINT ret;
    NX_CRYPTO_METHOD *method_hkdf = &crypto_method_hkdf;
    NX_CRYPTO_METHOD *method_hmac = &crypto_method_hmac;
    NX_CRYPTO_METHOD *method_hash = &crypto_method_sha256;

    /* Initialize the HKDF context with the IKM. */
    NX_CRYPTO_CHECK_RET( method_hkdf->nx_crypto_init(method_hkdf, (UCHAR*)ikm, ikm_len << 3,
                        NX_NULL, hkdf_metadata, hkdf_metadata_size) );

    /* Set the HMAC method. */
    NX_CRYPTO_CHECK_RET( method_hkdf->nx_crypto_operation(NX_CRYPTO_HKDF_SET_HMAC, NX_NULL, method_hmac,
                                    NX_NULL, 0, NX_NULL, 0, NX_NULL, NX_NULL, 0,
                                    hkdf_metadata, hkdf_metadata_size, NX_NULL, NX_NULL) );

    /* Set the hash method (e.g., SHA-256). */
    NX_CRYPTO_CHECK_RET( method_hkdf->nx_crypto_operation(NX_CRYPTO_HKDF_SET_HASH, NX_NULL, method_hash,
                                    NX_NULL, 0, NX_NULL, 0, NX_NULL, NX_NULL, 0,
                                    hkdf_metadata, hkdf_metadata_size, NX_NULL, NX_NULL) );

    /* Perform HKDF Extract to derive the PRK. */
    NX_CRYPTO_CHECK_RET( method_hkdf->nx_crypto_operation(NX_CRYPTO_HKDF_EXTRACT, NX_NULL, method_hkdf,
                                    (UCHAR*) salt, salt_len << 3, (UCHAR*)ikm, ikm_len,
                                    NX_NULL, prk, prk_len, hkdf_metadata, hkdf_metadata_size,
                                    NX_NULL, NX_NULL) );
cleanup:
    if (ret != NX_CRYPTO_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP: Crypto HKDF Extract failed ret = %u\n", ret));
    }
    return ret;
}

/**
 * @brief HKDF-Expand: derive OKM using PRK.
 *
 * @param hkdf_metadata HKDF context buffer.
 * @param hkdf_metadata_size Size of context buffer.
 * @param prk Pseudorandom key.
 * @param prk_len Length of PRK.
 * @param info Optional context and application specific information.
 * @param info_len Length of info.
 * @param okm Output keying material.
 * @param okm_len Length of OKM.
 *
 * @return NX_CRYPTO_SUCCESS on success, error code otherwise.
 */
static UINT wpa3_crypto_hkdf_expand(UCHAR *hkdf_metadata, size_t hkdf_metadata_size,
                                    const UCHAR *prk, size_t prk_len,
                                    const UCHAR *info, size_t info_len,
                                    UCHAR *okm, size_t okm_len)
{
    UINT ret;
    NX_CRYPTO_METHOD *method_hkdf = &crypto_method_hkdf;

    /* Perform the key expansion using the PRK we just generated which is stored in the HKDF context. */
    ret = method_hkdf->nx_crypto_operation(NX_CRYPTO_HKDF_EXPAND,
                                            NX_NULL,
                                            method_hkdf,
                                            (UCHAR*)(info),
                                            info_len << 3,
                                            NX_NULL,
                                            0,
                                            NX_NULL,
                                            (UCHAR *)okm,
                                            okm_len,
                                            hkdf_metadata,
                                            hkdf_metadata_size,
                                            NX_NULL, NX_NULL);

    if (ret != NX_CRYPTO_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP: Crypto HKDF Expand failed ret = %u\n", ret));
    }
    return ret;
}

/**
 * @brief HMAC-SHA256 over multiple buffers.
 *
 * @param key HMAC key.
 * @param key_len Key length.
 * @param num_elem Number of input buffers.
 * @param addr Array of input buffers.
 * @param len Array of input buffer lengths.
 * @param mac Output MAC.
 *
 * @return NX_CRYPTO_SUCCESS on success, error code otherwise.
 */
static cy_rslt_t wpa3_crypto_hmac_sha256(uint8_t *key, size_t key_len, size_t num_elem,
        uint8_t *addr[], size_t *len, uint8_t *mac)
{
    NX_CRYPTO_METHOD *method = &crypto_method_hmac_sha256;
    UINT metadata_sz = method->nx_crypto_metadata_area_size;
    UCHAR *meta_ptr;
    VOID *handler = NX_NULL;
    UINT ret;
    size_t i;

    meta_ptr = (UCHAR*)malloc(metadata_sz);
    if (meta_ptr == NULL)
    {
        return WPA3_EXT_CRYPTO_ERROR;
    }

    /* Initialize HMAC-SHA256 */
    NX_CRYPTO_CHECK_RET(method->nx_crypto_init(method, (UCHAR *)key, key_len << 3,
            &handler, meta_ptr, metadata_sz));

    /* Initialize HMAC-SHA256 context */
    NX_CRYPTO_CHECK_RET(method->nx_crypto_operation(NX_CRYPTO_HASH_INITIALIZE, handler,
                                        method,
                                        (UCHAR *)key, key_len << 3,
                                        NX_CRYPTO_NULL, 0,
                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0,
                                        meta_ptr, metadata_sz,
                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL));

    for (i = 0; i < num_elem; i++)
    {
        NX_CRYPTO_CHECK_RET(method->nx_crypto_operation(NX_CRYPTO_HASH_UPDATE, handler,
                                        method,
                                        NX_CRYPTO_NULL, 0,
                                        (UCHAR *)addr[i], len[i],
                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0,
                                        meta_ptr, metadata_sz,
                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL));
    }


    /* Finalize and get the HMAC result */
    NX_CRYPTO_CHECK_RET(method->nx_crypto_operation(NX_CRYPTO_HASH_CALCULATE, handler,
                                        method,
                                        NX_CRYPTO_NULL, 0,
                                        NX_CRYPTO_NULL, 0,
                                        NX_CRYPTO_NULL, mac, (method -> nx_crypto_ICV_size_in_bits) >> 3,
                                        meta_ptr, metadata_sz,
                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL));

cleanup:
    if (meta_ptr)
    {
        method->nx_crypto_cleanup(meta_ptr);
        free(meta_ptr);
    }
    if (ret != NX_CRYPTO_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP: Crypto HMAC SHA256 failed ret = %u\n", ret));
    }
    return ret;
}

/**
 * @brief HMAC-SHA256 KDF with bit-length output (KDF-n as per RFC 7664)
 *
 * @param key HMAC key.
 * @param key_len Key length.
 * @param label Label string.
 * @param data Input data.
 * @param data_len Data length.
 * @param buf Output buffer.
 * @param buf_len_bits Output length in bits.
 *
 * @return 0 on success, error code otherwise.
 */
static int wpa3_crypto_hmac_sha256_kdf_bits(uint8_t *key, size_t key_len,
        const char *label, uint8_t *data, size_t data_len, uint8_t *buf,
        size_t buf_len_bits)
{
    uint16_t counter = 1;
    size_t pos, plen;
    uint8_t hash[WPA3_ECP_GROUP_P256R1_PRIME_LEN];
    uint8_t *addr[4];
    size_t len[4];
    uint8_t counter_le[2], length_le[2];
    size_t buf_len = (buf_len_bits + 7) / 8;

    addr[0] = counter_le;
    len[0] = 2;
    addr[1] = (uint8_t *) label;
    len[1] = strlen(label);
    addr[2] = data;
    len[2] = data_len;
    addr[3] = length_le;
    len[3] = sizeof(length_le);

    length_le[1] = buf_len_bits >> 8;
    length_le[0] = buf_len_bits & 0xff;

    pos = 0;
    while (pos < buf_len)
    {
        plen = buf_len - pos;
        counter_le[1] = counter >> 8;
        counter_le[0] = counter & 0xff;
        if (plen >= WPA3_ECP_GROUP_P256R1_PRIME_LEN)
        {
            if (wpa3_crypto_hmac_sha256(key, key_len, 4, addr, len,
                    &buf[pos]) != CY_RSLT_SUCCESS)
            {
                return WPA3_EXT_CRYPTO_ERROR;
            }
            pos += WPA3_ECP_GROUP_P256R1_PRIME_LEN;
        }
        else
        {
            if (wpa3_crypto_hmac_sha256(key, key_len, 4, addr, len,
                    hash) != CY_RSLT_SUCCESS)
            {
                return WPA3_EXT_CRYPTO_ERROR;
            }
            memcpy(&buf[pos], hash, plen);
            pos += plen;
            break;
        }
        counter++;
    }

    /*
     * Mask out unused bits in the last octet if it does not use all the
     * bits.
     */
    if (buf_len_bits % 8)
    {
        uint8_t mask = 0xff << (8 - buf_len_bits % 8);
        buf[pos - 1] &= mask;
    }
    memset(hash, 0, sizeof(hash));
    return 0;
}

/**
 * @brief Compare a huge number with an integer.
 *
 * @param X Huge number.
 * @param num Integer.
 *
 * @return Comparison result (EQUAL, LESS, GREATER).
 */
static UINT _nx_crypto_huge_number_compare_int(NX_CRYPTO_HUGE_NUMBER *X, HN_UBASE num)
{
    NX_CRYPTO_HUGE_NUMBER temp;
    HN_UBASE temp_data[2];
    UINT result;

    temp.nx_crypto_huge_number_data = temp_data;
    temp.nx_crypto_huge_number_size = 1;
    temp.nx_crypto_huge_number_is_negative = NX_CRYPTO_FALSE;
    temp.nx_crypto_huge_buffer_size = sizeof(temp_data);
    temp_data[0] = num;

    /* Use the existing compare function */
    result = _nx_crypto_huge_number_compare(X, &temp);

    return result;
}

/**
 * @brief Divide a huge number by a digit.
 *
 * @param dividend Input huge number.
 * @param divisor Digit divisor.
 * @param quotient Output quotient.
 * @param remainder Output remainder.
 *
 * @return NX_CRYPTO_SUCCESS on success, error code otherwise.
 */
static UINT _nx_crypto_huge_number_divide_digit(NX_CRYPTO_HUGE_NUMBER *dividend,
                                                HN_UBASE divisor,
                                                NX_CRYPTO_HUGE_NUMBER *quotient,
                                                HN_UBASE *remainder)
{
    UINT i;
    HN_UBASE2 temp = 0;
    HN_UBASE *dividend_buf = dividend->nx_crypto_huge_number_data;
    HN_UBASE *quotient_buf = quotient->nx_crypto_huge_number_data;
    UINT dividend_size = dividend->nx_crypto_huge_number_size;

    if (divisor == 0)
    {
        /* Division by zero */
        return NX_CRYPTO_NOT_SUCCESSFUL;
    }

    /* Initialize quotient */
    quotient->nx_crypto_huge_number_size = dividend_size;
    quotient->nx_crypto_huge_number_is_negative = dividend->nx_crypto_huge_number_is_negative;

    /* Perform division from most significant digit to least */
    for (i = dividend_size; i > 0; i--)
    {
        temp = (temp << HN_SHIFT) | dividend_buf[i - 1];
        quotient_buf[i - 1] = (HN_UBASE)(temp / divisor);
        temp = temp % divisor;
    }

    /* Remove leading zeros in quotient */
    while (quotient->nx_crypto_huge_number_size > 1 &&
        quotient_buf[quotient->nx_crypto_huge_number_size - 1] == 0)
    {
        quotient->nx_crypto_huge_number_size--;
    }

    if (remainder)
    {
        *remainder = (HN_UBASE)temp;
    }
    return NX_CRYPTO_SUCCESS;
}

/**
 * @brief Constant-time selection between two huge numbers.
 * @param cond 1 to select a, 0 to select b.
 * @param a First input (selected if cond == 1).
 * @param b Second input (selected if cond == 0).
 * @param out Output huge number.
 *
 *  cond: 1 = select a, 0 = select b
 */
static void wpa3_const_time_select(int cond,
                                   const NX_CRYPTO_HUGE_NUMBER *a,
                                   const NX_CRYPTO_HUGE_NUMBER *b,
                                   NX_CRYPTO_HUGE_NUMBER *out)
{

    /* 0xFFFFFFFF... if cond, 0x0 if not */
    HN_UBASE mask = (HN_UBASE)(0 - (cond != 0));
    UINT i;
    UINT size = a->nx_crypto_huge_number_size;

    if (b->nx_crypto_huge_number_size > size)
    {
        size = b->nx_crypto_huge_number_size;
    }

    out->nx_crypto_huge_number_size = size;
    out->nx_crypto_huge_number_is_negative = (a->nx_crypto_huge_number_is_negative & mask) |
                                             (b->nx_crypto_huge_number_is_negative & ~mask);
    for (i = 0; i < size; i++)
    {
        HN_UBASE va = (i < a->nx_crypto_huge_number_size) ? a->nx_crypto_huge_number_data[i] : 0;
        HN_UBASE vb = (i < b->nx_crypto_huge_number_size) ? b->nx_crypto_huge_number_data[i] : 0;
        out->nx_crypto_huge_number_data[i] = (va & mask) | (vb & ~mask);
    }
}

/**
 * @brief Copy an EC point.
 *
 * @param dest Destination point.
 * @param src Source point.
 */
static void _nx_crypto_ec_point_copy(NX_CRYPTO_EC_POINT *dest, NX_CRYPTO_EC_POINT *src)
{
    if (dest != NULL &&  src != NULL)
    {
        NX_CRYPTO_HUGE_NUMBER_COPY(&dest->nx_crypto_ec_point_x, &src->nx_crypto_ec_point_x);
        NX_CRYPTO_HUGE_NUMBER_COPY(&dest->nx_crypto_ec_point_y, &src->nx_crypto_ec_point_y);
        if (src->nx_crypto_ec_point_type == NX_CRYPTO_EC_POINT_PROJECTIVE)
        {
            NX_CRYPTO_HUGE_NUMBER_COPY(&dest->nx_crypto_ec_point_z, &src->nx_crypto_ec_point_z);
        }
        dest->nx_crypto_ec_point_type = src->nx_crypto_ec_point_type;
    }
}

/**
 * @brief Compare two EC points.
 *
 * @param p1 First point.
 * @param p2 Second point.
 *
 * @return Comparison result.
 */
static UINT nx_crypto_ec_point_compare(NX_CRYPTO_EC_POINT *p1, NX_CRYPTO_EC_POINT *p2)
{
    UINT comp_ret;

    /* compare X then Y */
    comp_ret = _nx_crypto_huge_number_compare(&p1->nx_crypto_ec_point_x, &p2->nx_crypto_ec_point_x);
    if (comp_ret != NX_CRYPTO_HUGE_NUMBER_EQUAL)
    {
        return comp_ret;
    }
    comp_ret = _nx_crypto_huge_number_compare(&p1->nx_crypto_ec_point_y, &p2->nx_crypto_ec_point_y);
    if (comp_ret != NX_CRYPTO_HUGE_NUMBER_EQUAL)
    {
        return comp_ret;
    }
    /* Optionally compare z if using projective coordinates */
    if (p1->nx_crypto_ec_point_type == NX_CRYPTO_EC_POINT_PROJECTIVE ||
        p2->nx_crypto_ec_point_type == NX_CRYPTO_EC_POINT_PROJECTIVE)
    {
        comp_ret = _nx_crypto_huge_number_compare(&p1->nx_crypto_ec_point_z, &p2->nx_crypto_ec_point_z);
    }
    return comp_ret;
}

/**
 * @brief Compute Legendre symbol (a/p).
 *
 * @param a Input number.
 * @param p Prime modulus.
 *
 * @return 1 if quadratic residue, -1 if non-residue, 0 if zero.
 */
static int wpa3_crypto_bignum_legendre(NX_CRYPTO_HUGE_NUMBER *a, NX_CRYPTO_HUGE_NUMBER *p)
{
    NX_CRYPTO_HUGE_NUMBER exp, tmp;
    int res = -2;
    HN_UBASE *scratch_buff = NULL;
    HN_UBASE *scratch_ptr = NULL;

    /* 2 Huge num and 2 for _nx_crypto_huge_number_power_modulus */
    WPA3_EXT_CRYPTO_ALLOC_AND_VALIDATE_SCRATCH_BUFF(
        scratch_buff, p->nx_crypto_huge_buffer_size * 4, res);

    scratch_ptr = scratch_buff;

    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&exp, scratch_ptr, p->nx_crypto_huge_buffer_size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&tmp, scratch_ptr, p->nx_crypto_huge_buffer_size);

    /* exp = (p-1) / 2 */
    NX_CRYPTO_HUGE_NUMBER_COPY(&exp, p);
    _nx_crypto_huge_number_subtract_digit_unsigned(&exp, 1u);
    _nx_crypto_huge_number_shift_right(&exp, 1);
    _nx_crypto_huge_number_power_modulus(a, &exp, p, &tmp, scratch_ptr);


    if (_nx_crypto_huge_number_compare_int(&tmp, 1) == NX_CRYPTO_HUGE_NUMBER_EQUAL)
    {
        res = 1;
    }
    else if (_nx_crypto_huge_number_compare_int(&tmp, 0) == NX_CRYPTO_HUGE_NUMBER_EQUAL
            || _nx_crypto_huge_number_compare(&tmp, p) == NX_CRYPTO_HUGE_NUMBER_EQUAL)
    {
        res = 0;
    }
    else
    {
        res = -1;
    }

    free(scratch_buff);
    return res;
}

/**
 * @brief Create an EC point from x and y coordinate buffers in uncompressed format.
 *
 * This function constructs an uncompressed EC point buffer (0x04 | X | Y),
 * sets up the EC point structure from the buffer, and returns the result.
 *
 * @param pt       Output EC point structure.
 * @param buf      Buffer to hold the uncompressed point
 *                  (size should be x_buf_len + y_buf_len + 1).
 * @param x_buf    Input buffer for the x coordinate.
 * @param x_buf_len Length of the x coordinate buffer.
 * @param y_buf    Input buffer for the y coordinate.
 * @param y_buf_len Length of the y coordinate buffer.
 *
 * @return NX_CRYPTO_SUCCESS on success, error code otherwise.
 */
static UINT wpa3_crypto_create_ec_point(NX_CRYPTO_EC_POINT *pt,
    uint8_t *buf, uint8_t *x_buf, uint8_t x_buf_len,
    uint8_t *y_buf, uint8_t y_buf_len)
{
    uint8_t buf_len = 0;

    if (pt == NULL || buf == NULL || x_buf == NULL || y_buf == NULL)
    {
        return (NX_CRYPTO_PTR_ERROR);
    }

    /* Uncompressed point format: 0x04 | X | Y */
    buf[0] = NX_CRYPTO_UNCOMPRESSED_POINT;
    buf_len = 1;
    memcpy(&buf[buf_len], x_buf, x_buf_len);
    buf_len += x_buf_len;
    memcpy(&buf[buf_len], y_buf, y_buf_len);
    buf_len += y_buf_len;

    /* Setup EC point from buffer */
    return (_nx_crypto_ec_point_setup(pt, buf, buf_len));
}

/**
 * @brief Read EC point from x/y buffers.
 *
 * @param wksp WPA3 supplicant workspace.
 * @param x_buf X coordinate buffer.
 * @param y_buf Y coordinate buffer.
 * @param pt Output EC point.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
static cy_rslt_t wpa3_crypto_read_point_from_buffer(wpa3_supplicant_workspace_t *wksp,
                uint8_t *x_buf, uint8_t *y_buf, NX_CRYPTO_EC_POINT *pt)
{
    cy_rslt_t ret = CY_RSLT_SUCCESS;
    uint8_t pwe_buf[WPA3_SAE_KEYSEED_KEY_LEN * 2 + 1] = { 0 };

    ret = wpa3_crypto_create_ec_point(pt, pwe_buf,
                x_buf, WPA3_SAE_KEYSEED_KEY_LEN,
                y_buf, WPA3_SAE_KEYSEED_KEY_LEN);
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(
                ("WPA3-EXT-SUPP:wpa3_crypto_read_point_from_buffer failed ret=%ld\n", ret));
    }
    return ret;
}

/**
 * @brief Write EC point to output buffer (uncompressed format).
 *
 * @param wksp WPA3 supplicant workspace.
 * @param pt EC point.
 * @param output Output buffer.
 * @param outlen Output buffer length.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
static cy_rslt_t wpa3_crypto_write_point_to_buffer(wpa3_supplicant_workspace_t *wksp,
                                    NX_CRYPTO_EC_POINT *pt, uint8_t *output, uint8_t outlen)
{
    UINT len = 0;

    (void)len;

    if (pt == NULL || output == NULL || outlen == 0)
    {
        return WPA3_EXT_CRYPTO_ERROR;
    }
    _nx_crypto_ec_point_extract_uncompressed(wksp->wpa3_crypto_ctxt->curve, pt, output, outlen, &len);
    return CY_RSLT_SUCCESS;
}

/**
 * @brief Compute y^2 from x for the curve equation.
 *
 * @param x X coordinate buffer.
 * @param x_len Length of x.
 * @param ysqr Output y^2 as huge number.
 * @param curve EC curve.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
cy_rslt_t wpa3_crypto_derive_ysqr_from_x(uint8_t *x, uint16_t x_len,
                                        NX_CRYPTO_HUGE_NUMBER *ysqr,
                                        NX_CRYPTO_EC *curve)
{
    NX_CRYPTO_HUGE_NUMBER tmp;
    NX_CRYPTO_HUGE_NUMBER tmp3;
    NX_CRYPTO_HUGE_NUMBER x_num;
    cy_rslt_t ret = CY_RSLT_SUCCESS;
    HN_UBASE *scratch_ptr = NULL;
    HN_UBASE *scratch_buff = NULL;
    UINT size = x_len * 6;

    WPA3_EXT_CRYPTO_ALLOC_AND_VALIDATE_SCRATCH_BUFF(
        scratch_buff, size, WPA3_EXT_CRYPTO_ERROR);

    scratch_ptr = scratch_buff;

    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&x_num, scratch_ptr, x_len);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&tmp, scratch_ptr, x_len*2);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&tmp3, scratch_ptr, x_len*2);

    /* Derive y^2 = x^3 - 3 * x + b */

    /*x_num = x */
    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_setup(&x_num, x, x_len));

    /* x^2 = tmp =  x * x */
    _nx_crypto_huge_number_square(&x_num, &tmp);

    /* x^3 = tmp3 = tmp * x */
    _nx_crypto_huge_number_multiply(&tmp, &x_num, &tmp3);

    /* ax = tmp  = 3 * x */
    _nx_crypto_huge_number_multiply_digit(&x_num, 3, &tmp);

    /* tmp3 =  tmp3 - 3x */;
    _nx_crypto_huge_number_subtract(&tmp3, &tmp);

    /* tmp3 = tmp3 + b */
    _nx_crypto_huge_number_add(&tmp3, &curve->nx_crypto_ec_b);
    _nx_crypto_huge_number_modulus(&tmp3, &curve->nx_crypto_ec_field.fp);

    /* ysqr = tmp3 */
    NX_CRYPTO_HUGE_NUMBER_COPY(ysqr, &tmp3);

cleanup:
    if (ret != NX_CRYPTO_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP: Derive Y^2 from X failed ret=%ld\n", ret));
    }
    if (scratch_buff)
    {
        memset(scratch_buff, 0, size);
        free(scratch_buff);
    }
    return ret;
}

/**
 * @brief Compute y from y^2 for the curve.
 *
 * @param curve EC curve.
 * @param ysqr Input y^2.
 * @param y Output y.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
static cy_rslt_t wpa3_crypto_derive_y_from_ysqr(NX_CRYPTO_EC *curve,
                                                NX_CRYPTO_HUGE_NUMBER *ysqr,
                                                NX_CRYPTO_HUGE_NUMBER *y)
{
    cy_rslt_t ret = CY_RSLT_SUCCESS;
    NX_CRYPTO_HUGE_NUMBER zexp, tmp, y_tmp;
    HN_UBASE *scratch_buffer = NULL;
    HN_UBASE *ptr = NULL;
    UINT size = curve->nx_crypto_ec_field.fp.nx_crypto_huge_buffer_size * 8;

    WPA3_EXT_CRYPTO_ALLOC_AND_VALIDATE_SCRATCH_BUFF(
        scratch_buffer, size,
        WPA3_EXT_CRYPTO_ERROR);

    ptr = scratch_buffer;

    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&zexp, ptr, curve->nx_crypto_ec_field.fp.nx_crypto_huge_buffer_size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&tmp, ptr, curve->nx_crypto_ec_field.fp.nx_crypto_huge_buffer_size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&y_tmp, ptr, curve->nx_crypto_ec_field.fp.nx_crypto_huge_buffer_size * 2);

    /* zexp = p + 1 */
    NX_CRYPTO_HUGE_NUMBER_COPY(&zexp, &curve->nx_crypto_ec_field.fp);
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&tmp, 1);
    _nx_crypto_huge_number_add(&zexp, &tmp);

    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: zexp", &zexp);

    /* zexp = (p + 1) /4  */
    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_divide_digit(&zexp, 4, &tmp, NULL));
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: (p+1)/4", &tmp);

    NX_CRYPTO_HUGE_NUMBER_COPY(&zexp, &curve->nx_crypto_ec_field.fp);

    /* y =  (y2 ^ ((p+1)/4)) mod p */
    _nx_crypto_huge_number_mont_power_modulus(ysqr, &tmp, &zexp, &y_tmp, ptr);

    /* y = Y2^zexp mod p */
    NX_CRYPTO_HUGE_NUMBER_COPY(y, &y_tmp);

cleanup:
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP: Derive Y from Y2 failed ret=%ld\n", ret));
    }
    memset(scratch_buffer, 0, size);
    free(scratch_buffer);
    return ret;
}

/**
 * @brief Generate random number less than field or order.
 *
 * @param curve EC curve.
 * @param r Output huge number.
 * @param order True for order, false for field.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
static cy_rslt_t wpa3_crypto_get_rand(NX_CRYPTO_EC *curve,
                                      NX_CRYPTO_HUGE_NUMBER *r,
                                      bool order)
{
    NX_CRYPTO_HUGE_NUMBER private_key;
    NX_CRYPTO_EC_POINT    public_key;
    int cmp_val = 0, rand_tries = 5;
    unsigned char buf[WPA3_SAE_KEYSEED_KEY_LEN] = { 0 };
    HN_UBASE *scratch_buffer = NULL;
    HN_UBASE *scratch = NULL;
    UINT scratch_size = curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size * 48;
    UINT buffer_size = curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size;

    WPA3_EXT_CRYPTO_ALLOC_AND_VALIDATE_SCRATCH_BUFF(
        scratch_buffer, scratch_size,
        WPA3_EXT_CRYPTO_ERROR);

    do
    {
        memset(scratch_buffer, 0, scratch_size);
        scratch = scratch_buffer;
        NX_CRYPTO_EC_POINT_INITIALIZE(&public_key, NX_CRYPTO_EC_POINT_AFFINE, scratch, buffer_size);
        NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&private_key, scratch, buffer_size + 8);

        do
        {
            _nx_crypto_ec_key_pair_generation_extra(curve, &curve -> nx_crypto_ec_g, &private_key,
                                                    &public_key, scratch);
        } while (_nx_crypto_huge_number_is_zero(&private_key));

        _nx_crypto_huge_number_extract_fixed_size(&private_key, buf, sizeof(buf));

        if (order == true)
        {
            cmp_val = _nx_crypto_huge_number_compare(&private_key, &curve->nx_crypto_ec_n);
        }
        else
        {
            cmp_val = _nx_crypto_huge_number_compare(&private_key, &curve->nx_crypto_ec_field.fp);
        }

        if (cmp_val == NX_CRYPTO_HUGE_NUMBER_LESS)
        {
            /* r = buf */
            NX_CRYPTO_HUGE_NUMBER_COPY(r, &private_key);
        }

        rand_tries--;
    } while ((cmp_val != NX_CRYPTO_HUGE_NUMBER_LESS) && (rand_tries > 0));

    if (scratch_buffer)
    {
        memset(scratch_buffer, 0, scratch_size);
        free(scratch_buffer);
    }

    if (cmp_val != NX_CRYPTO_HUGE_NUMBER_LESS)
    {
        return WPA3_EXT_CRYPTO_ERROR;
    }
    return WPA3_EXT_SUPP_RSLT_SUCCESS;
}

/**
 * @brief Get random quadratic residue and non-residue.
 *
 * @param curve EC curve.
 * @param qr Output buffer for quadratic residue.
 * @param qnr Output buffer for quadratic non-residue.
 * @param buflen Buffer length.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
static cy_rslt_t wpa3_crypto_get_rand_qr_qnr(NX_CRYPTO_EC *curve, uint8_t* qr,
                                             uint8_t* qnr,uint16_t buflen)
{
    NX_CRYPTO_HUGE_NUMBER private_key;
    NX_CRYPTO_EC_POINT    public_key;
    int ret = 0;
    bool qnr_found = false;
    bool qr_found = false;
    HN_UBASE *scratch_buffer = NULL;
    HN_UBASE *scratch = NULL;
    UINT scratch_size = curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size * 48;
    UINT buffer_size = curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size;

    WPA3_EXT_CRYPTO_ALLOC_AND_VALIDATE_SCRATCH_BUFF(
        scratch_buffer, scratch_size,
        WPA3_EXT_CRYPTO_ERROR);

    while ((qnr_found == false) || (qr_found == false))
    {
        memset(scratch_buffer, 0, scratch_size);
        buffer_size = curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size;
        scratch = (HN_UBASE*)(&scratch_buffer[0]);
        NX_CRYPTO_EC_POINT_INITIALIZE(&public_key, NX_CRYPTO_EC_POINT_AFFINE, scratch, buffer_size);
        NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&private_key, scratch, buffer_size + 8);

        /* Generate the key pair. */
        do
        {
            _nx_crypto_ec_key_pair_generation_extra(curve, &curve -> nx_crypto_ec_g, &private_key,
                                                    &public_key, scratch);
        } while (_nx_crypto_huge_number_is_zero(&private_key));


        ret = wpa3_crypto_bignum_legendre(&private_key, &curve->nx_crypto_ec_field.fp);

        if ((ret == 1) && (qr_found == false))
        {
            qr_found = true;
            _nx_crypto_huge_number_extract_fixed_size(&private_key, qr, buflen);
        }
        else if ((ret == -1) && (qnr_found == false))
        {
            qnr_found = true;
            _nx_crypto_huge_number_extract_fixed_size(&private_key, qnr, buflen);
        }

        if ((qr_found == true) && (qnr_found == true))
        {
            break;
        }
    }
    memset(scratch_buffer, 0, scratch_size);
    free(scratch_buffer);
    return CY_RSLT_SUCCESS;
}

/**
 * @brief Blind quadratic residue check.
 *
 * @param qr_buf Quadratic residue buffer.
 * @param qnr_buf Quadratic non-residue buffer.
 * @param ysqr_buf Input value buffer.
 * @param ysqr_buflen Buffer length.
 * @param curve EC curve.
 *
 * @return true if quadratic residue, false otherwise.
 */
static bool wpa3_cyrpto_is_quadratic_residue_blind(uint8_t *qr_buf, uint8_t *qnr_buf,
                                                   uint8_t *ysqr_buf, uint16_t ysqr_buflen,
                                                   NX_CRYPTO_EC *curve)
{
    NX_CRYPTO_HUGE_NUMBER num, qr, qnr, unity, r_tmp, exp, p;
    NX_CRYPTO_HUGE_NUMBER ysqr;
    cy_rslt_t ret = CY_RSLT_SUCCESS;
    bool ret_val = false;
    uint8_t tmp[WPA3_SAE_KEYSEED_KEY_LEN] = { 0 };
    HN_UBASE *scratch_buff = NULL;
    HN_UBASE *scratch_ptr = NULL;
    UINT buffer_size = curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size;

    WPA3_EXT_CRYPTO_ALLOC_AND_VALIDATE_SCRATCH_BUFF(
        scratch_buff, (WPA3_SAE_KEYSEED_KEY_LEN * 5) + (buffer_size * 8), false);

    scratch_ptr = scratch_buff;

    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&ysqr, scratch_ptr, (WPA3_SAE_KEYSEED_KEY_LEN * 3));
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&num, scratch_ptr, buffer_size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&qr, scratch_ptr, WPA3_SAE_KEYSEED_KEY_LEN);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&qnr, scratch_ptr, WPA3_SAE_KEYSEED_KEY_LEN);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&unity, scratch_ptr, 2);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&r_tmp, scratch_ptr, buffer_size*2);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&p, scratch_ptr, buffer_size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&exp, scratch_ptr, 2);

    ret = wpa3_crypto_get_rand(curve, &r_tmp, false);
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(
                ("WPA3-EXT-SUPP:wpa3_cyrpto_is_quadratic_residue_blind : get_rand failed!!\n"));
        ret_val = false;
        goto cleanup;
    }

    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&exp, 2);
    NX_CRYPTO_HUGE_NUMBER_COPY(&p, &curve->nx_crypto_ec_field.fp);
    _nx_crypto_huge_number_mont_power_modulus(&r_tmp, &exp, &p, &num, scratch_ptr);

    /* read ysqr from buffer */
    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_setup(&ysqr, ysqr_buf, (WPA3_SAE_KEYSEED_KEY_LEN * 3)));
    _nx_crypto_huge_number_modulus(&ysqr, &curve->nx_crypto_ec_field.fp);

    /* r_tmp = ysrq * num */
    _nx_crypto_huge_number_multiply(&ysqr, &num, &r_tmp);

    /* num = (r_tmp) mod p */
    _nx_crypto_huge_number_modulus(&r_tmp, &curve->nx_crypto_ec_field.fp);

    _nx_crypto_huge_number_extract_fixed_size(&r_tmp, tmp, sizeof(tmp));

    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_setup(&qr, qr_buf, WPA3_SAE_KEYSEED_KEY_LEN));
    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_setup(&qnr, qnr_buf, WPA3_SAE_KEYSEED_KEY_LEN));

    /* set unity = 1 */
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&unity, 1);

    if (wpa3_is_buf_val_odd(tmp, sizeof(tmp)) == true)
    {
        /*  num = num * qr  */
        _nx_crypto_huge_number_multiply(&num, &qr, &r_tmp);

        /*  num = num ^1 mod p */
        _nx_crypto_huge_number_mont_power_modulus(&r_tmp, &unity, &p, &num, scratch_ptr);

        if (wpa3_crypto_bignum_legendre(&num, &curve->nx_crypto_ec_field.fp) == 1)
        {
            ret_val = true;
            goto cleanup;
        }
    }
    else
    {
        /*  num = num * qnr  */
        _nx_crypto_huge_number_multiply(&num, &qnr,&r_tmp);

        /*  num = num ^1 mod p */
        _nx_crypto_huge_number_mont_power_modulus(&r_tmp, &unity, &p, &num, scratch_ptr);

        if (wpa3_crypto_bignum_legendre(&num, &curve->nx_crypto_ec_field.fp) == -1)
        {
            ret_val = true;
            goto cleanup;
        }
    }

cleanup:
    free(scratch_buff);
    return ret_val;
}

/**
 * @brief Compute inverse of EC point.
 *
 * @param curve EC curve.
 * @param R Output (or in-place) point.
 * @param P Input point.
 *
 * @return 0 on success.
 */
static int wpa3_crypto_point_inverse(NX_CRYPTO_EC *curve,
                                    NX_CRYPTO_EC_POINT *R,
                                    NX_CRYPTO_EC_POINT *P)
{
    int ret = 0;
    NX_CRYPTO_HUGE_NUMBER tmp;
    HN_UBASE *scratch_buffer = NULL;
    HN_UBASE *scratch_ptr = NULL;

    WPA3_EXT_CRYPTO_ALLOC_AND_VALIDATE_SCRATCH_BUFF(
        scratch_buffer, curve->nx_crypto_ec_field.fp.nx_crypto_huge_buffer_size * 2,
        WPA3_EXT_CRYPTO_ERROR);

    scratch_ptr = scratch_buffer;
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&tmp, scratch_ptr,
        curve->nx_crypto_ec_field.fp.nx_crypto_huge_buffer_size);

    /* Copy */
    if (R != P)
    {
        _nx_crypto_ec_point_copy(R, P);
    }
    /* In-place opposite */
    if(!_nx_crypto_huge_number_is_zero(&R->nx_crypto_ec_point_y))
    {
        NX_CRYPTO_HUGE_NUMBER_COPY(&tmp, &curve->nx_crypto_ec_field.fp);
        _nx_crypto_huge_number_subtract(&tmp, &R->nx_crypto_ec_point_y);
        NX_CRYPTO_HUGE_NUMBER_COPY(&R->nx_crypto_ec_point_y, &tmp);
    }
    free(scratch_buffer);
    return (ret);
}
/**
 * @brief Simplified SWU hash-to-curve mapping.
 *
 * @param wksp WPA3 supplicant workspace.
 * @param u Input field element.
 * @param xpt Output buffer for x coordinate.
 * @param ypt Output buffer for y coordinate.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
static cy_rslt_t wpa3_cyrpto_sswu_algo(wpa3_supplicant_workspace_t *wksp,
                NX_CRYPTO_HUGE_NUMBER *u, uint8_t *xpt, uint8_t *ypt)
{
    int m_is_zero, is_qr, lsbu, lsby, is_eq;
    cy_rslt_t ret = CY_RSLT_SUCCESS;
    NX_CRYPTO_HUGE_NUMBER z, u2, zu2, z2u4, tmp,  m, za, tmp1, tmp2;
    NX_CRYPTO_HUGE_NUMBER exp, t, t2, modulus, negb, negba, bza, negbat;
    NX_CRYPTO_HUGE_NUMBER x1,gx1, x2, gx2, v, x, y;
    HN_UBASE *scratch_buffer = NULL;
    HN_UBASE *scratch = NULL;
    UINT size = wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size;

    WPA3_EXT_CRYPTO_ALLOC_AND_VALIDATE_SCRATCH_BUFF(
        scratch_buffer, size * 50, WPA3_EXT_CRYPTO_ERROR);

    scratch = scratch_buffer;

    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&tmp, scratch, size*4);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&tmp1, scratch, size*2);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&tmp2, scratch, size*2);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&z, scratch, size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&u2, scratch, size*2);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&z2u4, scratch, size*2);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&zu2, scratch, size*2);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&m, scratch, size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&exp, scratch, size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&t, scratch, size*2);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&t2, scratch, size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&modulus, scratch, size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&za, scratch, size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&bza, scratch, size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&negb, scratch, size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&negba, scratch, size*2);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&negbat, scratch, size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&x1, scratch, size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&gx1, scratch, size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&x2, scratch, size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&gx2, scratch, size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&v, scratch, size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&x, scratch, size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&y, scratch, size);


    /* set z = -WPA3_SAE_ECP_CURVE_PARAM, 10 = curve param for group 19 */
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&tmp, WPA3_SAE_ECP_CURVE_PARAM);
    NX_CRYPTO_HUGE_NUMBER_COPY(&z, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    _nx_crypto_huge_number_subtract(&z, &tmp);

    /* set negb = P-B */
     NX_CRYPTO_HUGE_NUMBER_COPY(&negb, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    _nx_crypto_huge_number_subtract(&negb, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_b);

    /* u2 = ( u * u) */
    _nx_crypto_huge_number_square(u, &u2);
    _nx_crypto_huge_number_modulus(&u2, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("U2 = U * U", &u2);

    /*zu2 = z * u2 */
    _nx_crypto_huge_number_multiply(&z, &u2, &zu2);
    _nx_crypto_huge_number_modulus(&zu2, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("ZU2", &zu2);

    /*z2u4 = (z * u2)^2 */
    _nx_crypto_huge_number_square(&zu2, &z2u4);
    _nx_crypto_huge_number_modulus(&z2u4, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("Z2U4", &zu2);

    /*  m = (z2 * u4 + z * u2) modulo p */
    NX_CRYPTO_HUGE_NUMBER_COPY(&tmp, &z2u4);
    _nx_crypto_huge_number_add(&tmp, &zu2);
    _nx_crypto_huge_number_modulus(&tmp, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    NX_CRYPTO_HUGE_NUMBER_COPY(&m, &tmp);

    /*  l = CEQ(m, 0) */
    m_is_zero = _nx_crypto_huge_number_is_zero(&m);

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP: m_is_zero=%d\n", m_is_zero));
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("M", &m);

    /* t = inverse(m) */
    /* t=  m^(p-2) modulo p */
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&tmp, 2);
    NX_CRYPTO_HUGE_NUMBER_COPY(&exp, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    _nx_crypto_huge_number_subtract(&exp, &tmp);
    NX_CRYPTO_HUGE_NUMBER_COPY(&modulus, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    _nx_crypto_huge_number_mont_power_modulus(&m, &exp, &modulus, &t, scratch);

    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP:t", &t);

    /*  x1 = CSEL(l, (b / (z * a) modulo p), ((-b/a) * (1 + t)) modulo p) */
    /*  za = z * a */
    _nx_crypto_huge_number_multiply(&z, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_a, &za);
    _nx_crypto_huge_number_modulus(&za, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);

    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP:ECP A", &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_a);
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP:ECP Z", &z);
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP:ECP ZA", &za);
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP:ECP negb", &negb);

    /* bza = (b /za) mod p */
    /* 1/za mod P */
    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_inverse_modulus(&za,
            &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp, &bza, scratch));

    /* b/za mod p */
    _nx_crypto_huge_number_multiply(&bza, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_b, &tmp);
    _nx_crypto_huge_number_modulus(&tmp, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    NX_CRYPTO_HUGE_NUMBER_COPY(&bza, &tmp);

    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: bza", &bza);

    /* 1/a mod P */
    NX_CRYPTO_HUGE_NUMBER_COPY(&tmp, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_a);
    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_inverse_modulus_prime(&tmp,
            &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp, &negba, scratch));

    /* -b * 1/a mod P */
    _nx_crypto_huge_number_multiply(&negb, &negba, &tmp);
    _nx_crypto_huge_number_modulus(&tmp, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    NX_CRYPTO_HUGE_NUMBER_COPY(&negba, &tmp);

    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: negba", &negba);

    /* t + 1 */
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&tmp, 1);
    _nx_crypto_huge_number_add(&t, &tmp);

    /* (-b/a * (t + 1)) */
    _nx_crypto_huge_number_multiply(&negba, &t, &negbat);

    /* (-b/a * (t + 1)) mod p */
    _nx_crypto_huge_number_modulus(&negbat, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);

    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: negbat", &negbat);

    /* x1 = CSEL (l, bza, negbat) */
    /* CSEL(x,y,z) operates in constant-time and returns y if x is true and z otherwise.*/
    wpa3_const_time_select(m_is_zero, &bza, &negbat, &x1);
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: x1", &x1);

    /*  gx1 = (x1^3 + a * x1 + b) modulo p */
    _nx_crypto_huge_number_square(&x1, &tmp1);
    _nx_crypto_huge_number_multiply(&x1, &tmp1, &tmp);
    _nx_crypto_huge_number_modulus(&tmp, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    /* tmp1 =  x1^3; */
    NX_CRYPTO_HUGE_NUMBER_COPY(&tmp1, &tmp);

    /* a * x1 + b */
    _nx_crypto_huge_number_multiply(&x1, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_a, &tmp);
    _nx_crypto_huge_number_modulus(&tmp, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    _nx_crypto_huge_number_add(&tmp, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_b);

    /* gx1 = x1^3 + ax1 */
    _nx_crypto_huge_number_add(&tmp, &tmp1);
    _nx_crypto_huge_number_modulus(&tmp, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    NX_CRYPTO_HUGE_NUMBER_COPY(&gx1, &tmp);

    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: gx1", &gx1);

    /*  x2 = (z * u2 * x1) modulo p */
    /* zu2 = ( z * u2 ) */
    /* x2 =  (zu2 * x1_tmp) */
    _nx_crypto_huge_number_multiply(&x1, &zu2, &tmp);
    _nx_crypto_huge_number_modulus(&tmp, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    NX_CRYPTO_HUGE_NUMBER_COPY(&x2, &tmp);

    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: x2", &x2);

    /* tmp1 = x2 ^ 3 */
    _nx_crypto_huge_number_square(&x2, &tmp1);
    _nx_crypto_huge_number_multiply(&x2, &tmp1, &tmp);
    _nx_crypto_huge_number_modulus(&tmp, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    NX_CRYPTO_HUGE_NUMBER_COPY(&tmp1, &tmp);

    /* a * x2 + b */
    _nx_crypto_huge_number_multiply(&x2, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_a, &tmp);
    _nx_crypto_huge_number_modulus(&tmp, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    _nx_crypto_huge_number_add(&tmp, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_b);

    /*  gx2 = (x2^3 + a * x2 + b) modulo p */
    /* gx2 = x3 + ax1 */
    _nx_crypto_huge_number_add(&tmp, &tmp1);
    _nx_crypto_huge_number_modulus(&tmp, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    NX_CRYPTO_HUGE_NUMBER_COPY(&gx2, &tmp);

    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: gx2", &gx2);

    /*  t = gx1 is a quadratic residue modulo p */
    /* --> gx1^((p-1)/2) modulo p is zero or one */
    NX_CRYPTO_HUGE_NUMBER_COPY(&tmp1, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    NX_CRYPTO_HUGE_NUMBER_COPY(&tmp2, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    _nx_crypto_huge_number_subtract_digit_unsigned(&tmp1, 1u);
    _nx_crypto_huge_number_shift_right(&tmp1, 1);
    _nx_crypto_huge_number_mont_power_modulus(&gx1, &tmp1, &tmp2, &tmp, scratch);
    NX_CRYPTO_HUGE_NUMBER_COPY(&t2, &tmp);

    is_qr = (_nx_crypto_huge_number_compare_int(&t2, 1) == NX_CRYPTO_HUGE_NUMBER_EQUAL || _nx_crypto_huge_number_is_zero(&t2));

    WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP:gx1^((p-1)/2) modulo p is_qr=%d\n", is_qr));
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: t2", &t2);

    /*  v = CSEL(l, gx1, gx2) */
    /* CSEL(l,gx1,gx2) operates in constant-time and returns gx1 if l is true and gx2 otherwise.*/
    wpa3_const_time_select(is_qr, &gx1, &gx2, &v);
    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:v is_qr=%d\n", is_qr));
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: v", &v);

    /*  x = CSEL(l, x1, x2) */
    /* CSEL(l,x1,x2) operates in constant-time and returns x1 if l is true and x2 otherwise.*/
    wpa3_const_time_select(is_qr, &x1, &x2, &x);

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:x is_qr=%d\n", is_qr));
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: x", &x);

    /*  y = sqrt(v) */
    wpa3_crypto_derive_y_from_ysqr(wksp->wpa3_crypto_ctxt->curve, &v, &y);

    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: y", &y);

    lsbu = u->nx_crypto_huge_number_data[0] & 0x01;
    lsby = y.nx_crypto_huge_number_data[0] & 0x01;

    WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP:lsbu =%d lsby =%d\n", lsbu , lsby));

    /* l = CEQ(lsbu, lsby) */
    is_eq = wpa3_const_time_int_cmp(lsbu, lsby);

    WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP:is_eq=%d\n", is_eq));

    /* P = CSEL(l, (x,y), (x, p-y)) */
    /* py = p-y */
    NX_CRYPTO_HUGE_NUMBER_COPY(&tmp, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    _nx_crypto_huge_number_subtract(&tmp, &y);

    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: py", &tmp);

    if(is_eq)
    {
        /* if is_eq, then y = p-y */
        NX_CRYPTO_HUGE_NUMBER_COPY(&y, &tmp);
    }

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:x is_eq=%d\n", is_eq));
    WPA3_EXT_HEX_BIGNUM_DUMP((&x));

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:y is_eq=%d\n", is_eq));
    WPA3_EXT_HEX_BIGNUM_DUMP((&y));

    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(&x, xpt, WPA3_SAE_KEYSEED_KEY_LEN));
    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(&y, ypt, WPA3_SAE_KEYSEED_KEY_LEN));

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP: (x, y)\n"));
    WPA3_EXT_HEX_BUF_DUMP((xpt, WPA3_SAE_KEYSEED_KEY_LEN));
    WPA3_EXT_HEX_BUF_DUMP((ypt, WPA3_SAE_KEYSEED_KEY_LEN));

cleanup:
    if (scratch_buffer != NULL)
    {
        free(scratch_buffer);
    }
    return ret;
}

/**
 * @brief Generate Password Element (PWE) using Hunting and Pecking (HnP).
 *
 * @param wksp WPA3 supplicant workspace.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
cy_rslt_t wpa3_crypto_start_pwe_generation(wpa3_supplicant_workspace_t *wksp)
{
    uint8_t counter = 1;
    bool found = false;
    NX_CRYPTO_HUGE_NUMBER y, ysqr, seed, save, randpass, ycomp, pycomp, py;
    UINT ret;
    int cmp_val_y2 = 0, cmp_val_py2 = 0;
    uint8_t mac_buf[ETH_ADDR_LEN * 2] = { 0 };
    uint8_t base_val[WPA3_SAE_KEYSEED_KEY_LEN] = { 0 };
    uint8_t pwd_seed[WPA3_PWE_SEED_MAX_LEN] = { 0 };
    uint8_t rand_passwd[WPA3_MAX_PASSPHRASE_LEN] = { 0 };
    uint8_t pointx[WPA3_SAE_KEYSEED_KEY_LEN] = { 0 };
    uint8_t qr[WPA3_SAE_KEYSEED_KEY_LEN];
    uint8_t qnr[WPA3_SAE_KEYSEED_KEY_LEN];
    uint8_t y2_calc[WPA3_SAE_KEYSEED_KEY_LEN];
    uint8_t y2_buf[WPA3_SAE_KEYSEED_KEY_LEN];
    uint8_t save_buf[WPA3_SAE_KEYSEED_KEY_LEN];
    uint8_t py2_calc[WPA3_SAE_KEYSEED_KEY_LEN];
    uint8_t ysqr_buf[WPA3_SAE_KEYSEED_KEY_LEN * 3] = { 0 };
    uint8_t primebuf[WPA3_SAE_KEYSEED_KEY_LEN] = { 0 };
    uint32_t start_time = 0;
    uint32_t end_time = 0;
    uint8_t *addr[3];
    size_t len[3];
    size_t num_elem = 0;
    NX_CRYPTO_EC  *curve;
    HN_UBASE *scratch_buffer = NULL;
    HN_UBASE *scratch_ptr = NULL;

    WPA3_EXT_CRYPTO_ALLOC_AND_VALIDATE_SCRATCH_BUFF(
        scratch_buffer, (WPA3_SAE_KEYSEED_KEY_LEN * 12),
        WPA3_EXT_CRYPTO_ERROR);
    scratch_ptr = scratch_buffer;

    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&y, scratch_ptr, WPA3_SAE_KEYSEED_KEY_LEN);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&ysqr, scratch_ptr, WPA3_SAE_KEYSEED_KEY_LEN*2);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&seed, scratch_ptr, WPA3_SAE_KEYSEED_KEY_LEN);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&save, scratch_ptr, WPA3_SAE_KEYSEED_KEY_LEN);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&ycomp, scratch_ptr, WPA3_SAE_KEYSEED_KEY_LEN*2);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&pycomp, scratch_ptr, WPA3_SAE_KEYSEED_KEY_LEN*2);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&py, scratch_ptr, WPA3_SAE_KEYSEED_KEY_LEN);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&randpass, scratch_ptr, WPA3_SAE_KEYSEED_KEY_LEN);

    curve = (NX_CRYPTO_EC *)wksp->wpa3_crypto_ctxt->curve;

    ret = wpa3_crypto_get_rand_qr_qnr(curve, qr, qnr, WPA3_SAE_KEYSEED_KEY_LEN);
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP:wpa3_crypto_get_rand_qr_qnr failed ret = %u\n", ret));
        return ret;
    }

    ret = wpa3_crypto_get_rand(curve, &randpass, false);
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP:wpa3_crypto_get_rand failed ret = %u\n", ret));
        return ret;
    }

    NX_CRYPTO_CHECK_RET(
            _nx_crypto_huge_number_extract_fixed_size(&randpass, rand_passwd, WPA3_SAE_KEYSEED_KEY_LEN));

    ret = wpa3_sta_mac_ap_bssid_buf(
            (uint8_t *) wksp->wpa3_sae_auth_info.sta_mac,
            (uint8_t *) wksp->wpa3_sae_auth_info.ap_bssid, (uint8_t *) mac_buf);
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP:wpa3_sta_mac_ap_bssid_buf failed ret = %u\n", ret));
        goto cleanup;
    }
    WPA3_EXT_HEX_BUF_DUMP_WITH_LABEL("WPA3-EXT-SUPP:mac_buf", mac_buf, sizeof(mac_buf));

    cy_rtos_get_time(&start_time);

    addr[0]        = wksp->wpa3_sae_auth_info.passhphrase;
    len[0]         = strlen((const char *) wksp->wpa3_sae_auth_info.passhphrase);
    num_elem++;
    addr[num_elem] = (uint8_t *) &counter;
    len[num_elem]  = sizeof(uint8_t);
    num_elem++;

    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(&curve->nx_crypto_ec_field.fp,
            primebuf, WPA3_SAE_KEYSEED_KEY_LEN));

    do
    {
        memset(base_val, 0, sizeof(base_val));
        memset(pwd_seed, 0, sizeof(pwd_seed));

        ret = wpa3_crypto_hmac_sha256(mac_buf, (ETH_ADDR_LEN * 2), num_elem,
                                    addr, len, base_val);
        if (ret != CY_RSLT_SUCCESS)
        {
            WPA3_EXT_LOG_MSG(
                    ("WPA3-EXT-SUPP:wpa3_supplicant_hmac_sha256 failed ret = %u\n", ret));
            goto cleanup;
        }

        ret = wpa3_crypto_hmac_sha256_kdf_bits(base_val,
                WPA3_SAE_KEYSEED_KEY_LEN, "SAE Hunting and Pecking", primebuf,
                (size_t) WPA3_SAE_KEYSEED_KEY_LEN, pwd_seed,
                (8 * WPA3_SAE_KEYSEED_KEY_LEN));
        if (ret != CY_RSLT_SUCCESS)
        {
            WPA3_EXT_LOG_MSG(
                    ("WPA3-EXT-SUPP:wpa3_supplicant_hmac_sha256_kdf failed ret = %u\n", ret));
            goto cleanup;
        }

        NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_setup(&seed, (const unsigned char *)pwd_seed, WPA3_SAE_KEYSEED_KEY_LEN));

        /*
        * Export X into unsigned binary data, big endian
        */
        NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(&seed, pointx, sizeof(pointx)));

        /* compared seed to be less than prime */
        ret = _nx_crypto_huge_number_compare(&seed, &curve->nx_crypto_ec_field.fp);
        if (ret == NX_CRYPTO_HUGE_NUMBER_LESS)
        {
            /* ysqr = seed ^ 3 + a * seed + b; */
            ret = wpa3_crypto_derive_ysqr_from_x(pointx, sizeof(pointx), &ysqr, curve);
            if (ret != CY_RSLT_SUCCESS)
            {
                WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP: Unable to derive Y2 from X (ret = %u)\n", ret));
            }

            NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(&ysqr, ysqr_buf, sizeof(ysqr_buf)));

            wpa3_cyrpto_is_quadratic_residue_blind(qr, qnr, ysqr_buf, sizeof(ysqr_buf), curve);

            if (found == false)
            {
                /* Save Seed to X Buf */
                NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(&seed, wksp->wpa3_crypto_ctxt->x_buf,
                        sizeof(wksp->wpa3_crypto_ctxt->x_buf)));

                NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_setup(&save, (const UCHAR *)base_val, sizeof(base_val)));

                NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(&save, save_buf, sizeof(save_buf)));

                /* Perform modulo operation */
                _nx_crypto_huge_number_modulus(&ysqr, &curve->nx_crypto_ec_field.fp);

                /* derive y from ysqr */
                ret = wpa3_crypto_derive_y_from_ysqr(curve, &ysqr, &y);
                if (ret == CY_RSLT_SUCCESS)
                {
                    /* Save Y to Y Buf */
                    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(&y,
                            wksp->wpa3_crypto_ctxt->y_buf, sizeof(wksp->wpa3_crypto_ctxt->y_buf)));

                    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("Y from Y^2", &y);

                    /* Check  (X,Y) point is valid on EC curve */
                    ret = wpa3_crypto_check_valid_point_on_ecp_curve(wksp);
                    if (ret == CY_RSLT_SUCCESS)
                    {
                        found = true;
                        wksp->wpa3_crypto_ctxt->pwe_found = true;
                        WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP:counter=%d\n", counter));

                        /* change password for the remaining iterations */
                        addr[0] = rand_passwd;

                        /* Ensure the y2 match by computing again */
                        NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(&ysqr, y2_buf, sizeof(y2_buf)));

                        /* compute y^2 */
                        _nx_crypto_huge_number_square(&y, &ycomp);
                        _nx_crypto_huge_number_modulus(&ycomp, &curve->nx_crypto_ec_field.fp);

                        NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(&ycomp, y2_calc, sizeof(y2_calc)));


                        NX_CRYPTO_HUGE_NUMBER_COPY(&py, &curve->nx_crypto_ec_field.fp);
                        _nx_crypto_huge_number_subtract(&py, &y);

                        /* compute py and py ^2 */
                        NX_CRYPTO_CHECK_RET(
                                _nx_crypto_huge_number_extract_fixed_size(&py,
                                        wksp->wpa3_crypto_ctxt->py_buf, sizeof(wksp->wpa3_crypto_ctxt->py_buf)));

                        _nx_crypto_huge_number_square(&py, &pycomp);
                        _nx_crypto_huge_number_modulus(&pycomp, &curve->nx_crypto_ec_field.fp);


                        NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(&pycomp, py2_calc, sizeof(py2_calc)));

                        cmp_val_y2  = memcmp(y2_calc, y2_buf, sizeof(y2_buf));
                        cmp_val_py2 = memcmp(py2_calc, y2_buf, sizeof(y2_buf));

                        if ((cmp_val_y2 == 0) || (cmp_val_py2 == 0))
                        {
                            WPA3_EXT_LOG_MSG(
                                    ("WPA3-EXT-SUPP:y2 calculated matches with y2 buf\n"));
#ifdef WPA3_EXT_SUPPLICANT_DEBUG
                            WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:x point counter=%d...\n", counter));
                            WPA3_EXT_HEX_BUF_DUMP((wksp->wpa3_crypto_ctxt->x_buf, sizeof(wksp->wpa3_crypto_ctxt->x_buf)));

                            WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:ysqr point counter=%d...\n", counter));
                            WPA3_EXT_HEX_BUF_DUMP((y2_buf, sizeof(y2_buf)));

                            WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:y point counter=%d...\n", counter));
                            WPA3_EXT_HEX_BUF_DUMP((wksp->wpa3_crypto_ctxt->y_buf, sizeof(wksp->wpa3_crypto_ctxt->y_buf)));

                            WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:py point counter=%d...\n", counter));
                            WPA3_EXT_HEX_BUF_DUMP((wksp->wpa3_crypto_ctxt->py_buf, sizeof(wksp->wpa3_crypto_ctxt->py_buf)));

                            WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:computed y2\n"));
                            WPA3_EXT_HEX_BUF_DUMP((y2_calc, sizeof(y2_calc)));

                            WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:computed py2\n"));
                            WPA3_EXT_HEX_BUF_DUMP((py2_calc, sizeof(py2_calc)));
#endif
                        }
                    }
                }
            }

        }
        counter = counter + 1;
        if (counter > WPA3_MAX_PWE_LOOP)
        {
            WPA3_EXT_LOG_MSG(
                    ("\n***WPA3-EXT-SUPP:(counter > WPA3_MAX_PWE_LOOP)****\n"));
            break;
        }
    } while (counter <= WPA3_MAX_PWE_LOOP);

    cy_rtos_get_time(&end_time);

    WPA3_EXT_LOG_MSG(
            ("WPA3-EXT-SUPP:PWE loop time for 40 iterations computing ysqr, start_time:%ld end_time:%ld  computation time = %ld ms\n",
                    start_time, end_time, (end_time - start_time)));
#ifdef WPA3_EXT_SUPPLICANT_DEBUG
    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:Found ysqr as perfect square\n"));
    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:x point counter=%d...\n", counter));
    WPA3_EXT_HEX_BUF_DUMP((wksp->wpa3_crypto_ctxt->x_buf, sizeof(wksp->wpa3_crypto_ctxt->x_buf)));

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:ysqr point counter=%d...\n", counter));
    WPA3_EXT_HEX_BUF_DUMP((y2_buf, sizeof(y2_buf)));

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:y point counter=%d...\n", counter));
    WPA3_EXT_HEX_BUF_DUMP((wksp->wpa3_crypto_ctxt->y_buf, sizeof(wksp->wpa3_crypto_ctxt->y_buf)));

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:computed y2\n"));
    WPA3_EXT_HEX_BIGNUM_DUMP((&ycomp));

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:computed py2\n"));
    WPA3_EXT_HEX_BIGNUM_DUMP((&pycomp));

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:base \n"));
    WPA3_EXT_HEX_BIGNUM_DUMP((&save));
#endif

    if (wksp->wpa3_crypto_ctxt->pwe_found == false)
    {
        WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP:PWE generation for HnP failed\n"));
        /* post WPA3_SUPPLICANT_EVENT_DELETE to supplicant */
        /* do cleanup */
        ret = WPA3_EXT_PWE_GEN_FAILED;
        goto cleanup;
    }

    /*
    if (lsb(y) == lsb(save))
    {
        PE = (x, y);
    }
    else
    {
        PE = (x, p - y);
    }
    */
    if ((save_buf[WPA3_SAE_KEYSEED_KEY_LEN - 1] & 1)
            != (wksp->wpa3_crypto_ctxt->y_buf[WPA3_SAE_KEYSEED_KEY_LEN - 1] & 1))
    {
        /* py = p - y */
        NX_CRYPTO_HUGE_NUMBER_COPY(&py, &curve->nx_crypto_ec_field.fp);
        _nx_crypto_huge_number_subtract(&py, &y);

        /* y = py */
        ret = _nx_crypto_huge_number_extract_fixed_size(&py,wksp->wpa3_crypto_ctxt->y_buf,
                        sizeof(wksp->wpa3_crypto_ctxt->y_buf));
    }

    WPA3_EXT_HEX_BUF_DUMP_WITH_LABEL("WPA3-EXT-SUPP:X point",
            wksp->wpa3_crypto_ctxt->x_buf, sizeof(wksp->wpa3_crypto_ctxt->x_buf));
    WPA3_EXT_HEX_BUF_DUMP_WITH_LABEL("WPA3-EXT-SUPP:Y point",
            wksp->wpa3_crypto_ctxt->y_buf, sizeof(wksp->wpa3_crypto_ctxt->y_buf));


    /* Check (X,Y) point is valid */
    ret = wpa3_crypto_check_valid_point_on_ecp_curve(wksp);
    if (ret != CY_RSLT_SUCCESS) {
        WPA3_EXT_LOG_MSG(
                ("WPA3-EXT-SUPP:xyz point not valid on curve ret=%u\n", ret));
    }

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:xy point\n"));
    WPA3_EXT_HEX_BIGNUM_DUMP((&wksp->wpa3_crypto_ctxt->pwe.nx_crypto_ec_point_x));
    WPA3_EXT_HEX_BIGNUM_DUMP((&wksp->wpa3_crypto_ctxt->pwe.nx_crypto_ec_point_y));

    /* PWE generation done */
    wksp->wpa3_pwe_generation_done = true;

cleanup:
    if (scratch_buffer != NULL)
    {
        free(scratch_buffer);
    }
    return ret;
}

/**
 * @brief Derive PWE from PT using H2E method.
 *
 * @param wksp WPA3 supplicant workspace.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
cy_rslt_t wpa3_crypto_derive_pwe_from_pt(wpa3_supplicant_workspace_t *wksp)
{
    cy_rslt_t ret = CY_RSLT_SUCCESS;
    uint8_t pt[WPA3_H2E_PT_XY_SIZE] = {0};
    uint8_t len = 1;
    uint8_t mac_buf[ETH_ADDR_LEN * 2] = { 0 };
    uint8_t pwd_seed[WPA3_SAE_KEYSEED_KEY_LEN] = { 0 };
    NX_CRYPTO_HUGE_NUMBER pwdval, q1, tmp;
    uint8_t salt[WPA3_SAE_KEYSEED_KEY_LEN];
    HN_UBASE *scratch_buffer = NULL;
    HN_UBASE *scratch = NULL;
    UCHAR hkdf_metadata[sizeof(NX_CRYPTO_HKDF) + sizeof(NX_CRYPTO_HMAC)];

    /* check if the PT is stored */
    ret = cy_wpa3_get_pfn_network( wksp->wpa3_sae_auth_info.ssid, wksp->wpa3_sae_auth_info.passhphrase, pt);
    if ( ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:  PT not found \n"));

        /* derive PT */
        ret = wpa3_crypto_derive_pt(wksp, wksp->wpa3_sae_auth_info.ssid, wksp->wpa3_sae_auth_info.passhphrase, pt, sizeof(pt));

        WPA3_EXT_HEX_BUF_DUMP_WITH_LABEL("WPA3-EXT-SUPP:  PT", pt, sizeof(pt));
    }
    else
    {
        WPA3_EXT_HEX_BUF_DUMP_WITH_LABEL("WPA3-EXT-SUPP:  PT Found", pt, sizeof(pt));
    }

    /* read point from buffer */
    wpa3_crypto_read_point_from_buffer(wksp, &pt[len], &pt[len + WPA3_SAE_SCALAR_LEN],
            &wksp->wpa3_crypto_ctxt->sta_pt_element);

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:PT xy point\n"));
    WPA3_EXT_HEX_BIGNUM_DUMP((&wksp->wpa3_crypto_ctxt->sta_pt_element.nx_crypto_ec_point_x));
    WPA3_EXT_HEX_BIGNUM_DUMP((&wksp->wpa3_crypto_ctxt->sta_pt_element.nx_crypto_ec_point_y));


    /* val = H(0n, MAX(STA-MAC, AP-MAC) || MIN(STA-MAC, AP-MAC)) */
    ret = wpa3_sta_mac_ap_bssid_buf((uint8_t *) wksp->wpa3_sae_auth_info.sta_mac,
                                    (uint8_t *) wksp->wpa3_sae_auth_info.ap_bssid, (uint8_t *) mac_buf);
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP:wpa3_sta_mac_ap_bssid_buf failed ret = %ld\n", ret));
        return ret;
    }
    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:mac_buf\n"));
    WPA3_EXT_HEX_BUF_DUMP((mac_buf, sizeof(mac_buf)));

    memset(salt, 0, sizeof(salt));

    ret = wpa3_crypto_hkdf_extract(hkdf_metadata, sizeof(hkdf_metadata),
            (const UCHAR *) salt, sizeof(salt),
            (const UCHAR *) mac_buf, (size_t) sizeof(mac_buf),
            pwd_seed, sizeof(pwd_seed));
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP:wpa3_crypto_hkdf_extract failed ret=%ld \n", ret));
        return WPA3_EXT_CRYPTO_ERROR;
    }
    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:  pwd_seed\n"));
    WPA3_EXT_HEX_BUF_DUMP((pwd_seed, sizeof(pwd_seed)));


    WPA3_EXT_CRYPTO_ALLOC_AND_VALIDATE_SCRATCH_BUFF(
        scratch_buffer,
        (wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size * 32),
        WPA3_EXT_CRYPTO_ERROR);
    scratch = scratch_buffer;

    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&pwdval, scratch, WPA3_SAE_KEYSEED_KEY_LEN);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&q1, scratch, WPA3_SAE_KEYSEED_KEY_LEN);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&tmp, scratch, 2);

    /* pwdval = pwdval modulo (q - 1) + 1 */

    /* q - 1 */
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&tmp, 1);
    NX_CRYPTO_HUGE_NUMBER_COPY(&q1, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_n);
    _nx_crypto_huge_number_subtract(&q1, &tmp);

    _nx_crypto_huge_number_setup(&pwdval, pwd_seed, sizeof(pwd_seed));

    /* pwdval = pwdval mod (q - 1) */
    _nx_crypto_huge_number_modulus(&pwdval, &q1);

    /* pwdval = pwdval + 1 */
    _nx_crypto_huge_number_add(&pwdval, &tmp);

    /* PWE = scalar-op(pwdval, PT) */
    wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_multiple(wksp->wpa3_crypto_ctxt->curve,
            &wksp->wpa3_crypto_ctxt->sta_pt_element,
            &pwdval, &wksp->wpa3_crypto_ctxt->pwe, scratch);

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:H2E pwe before inverse\n"));
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("PWE.X", &wksp->wpa3_crypto_ctxt->pwe.nx_crypto_ec_point_x);
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("PWE.Y", &wksp->wpa3_crypto_ctxt->pwe.nx_crypto_ec_point_y);

    /* sta_commit_element = inverse(sta_commit_element) */
    ret = wpa3_crypto_point_inverse(wksp->wpa3_crypto_ctxt->curve,
            &wksp->wpa3_crypto_ctxt->sta_pt_element,
            &wksp->wpa3_crypto_ctxt->sta_pt_element);
    if (ret != 0)
    {
        WPA3_EXT_LOG_MSG(( "WPA3-EXT-SUPP:wpa3_crypto_point_inverse failed: ret=%ld\n", ret ));
        goto cleanup;
    }

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:H2E STA PWE\n"));
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("PWE.X", &wksp->wpa3_crypto_ctxt->pwe.nx_crypto_ec_point_x);
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("PWE.Y", &wksp->wpa3_crypto_ctxt->pwe.nx_crypto_ec_point_y);

    /* check if the point is valid on the ECP curve */
    ret = _nx_crypto_ec_validate_public_key(&wksp->wpa3_crypto_ctxt->pwe,
            wksp->wpa3_crypto_ctxt->curve, NX_CRYPTO_FALSE, scratch);
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(("\n WPA3-EXT-SUPP:H2E PWE  not valid point on curve ret=%ld\n", ret));
    }
    else
    {
        WPA3_EXT_LOG_MSG(("\n*** WPA3-EXT-SUPP:H2E PWE is a VALID point on ECP CURVE ret=%ld ***\n", ret));
    }

cleanup:
    if (scratch_buffer != NULL)
    {
        free(scratch_buffer);
    }
    return ret;
}

/**
 * @brief Derive Password Element (PT) using SSWU mapping.
 *
 * @param wksp WPA3 supplicant workspace.
 * @param ssid SSID.
 * @param passphrase Passphrase.
 * @param output Output buffer for PT.
 * @param outlen Output buffer length.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
cy_rslt_t wpa3_crypto_derive_pt(wpa3_supplicant_workspace_t *wksp,
        uint8_t *ssid, uint8_t *passphrase, uint8_t *output, uint8_t outlen)
{
    uint8_t pwd_seed[WPA3_SAE_KEYSEED_KEY_LEN] = { 0 };
    uint8_t pwd_value[WPA3_KDF_EXPAND_LEN] = { 0 };
    uint8_t xp1[WPA3_SAE_KEYSEED_KEY_LEN] = { 0 };
    uint8_t yp1[WPA3_SAE_KEYSEED_KEY_LEN] = { 0 };
    uint8_t xp2[WPA3_SAE_KEYSEED_KEY_LEN] = { 0 };
    uint8_t yp2[WPA3_SAE_KEYSEED_KEY_LEN] = { 0 };
    cy_rslt_t ret = CY_RSLT_SUCCESS;
    NX_CRYPTO_HUGE_NUMBER u1, u2;
    NX_CRYPTO_EC_POINT P1, P2;
    NX_CRYPTO_HUGE_NUMBER pwdval;
    NX_CRYPTO_HUGE_NUMBER m;
    UCHAR hkdf_metadata[sizeof(NX_CRYPTO_HKDF) + sizeof(NX_CRYPTO_HMAC)];
    HN_UBASE *scratch_buffer = NULL;
    HN_UBASE *scratch = NULL;

    WPA3_EXT_CRYPTO_ALLOC_AND_VALIDATE_SCRATCH_BUFF(
        scratch_buffer,
        (wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size * 32),
        WPA3_EXT_CRYPTO_ERROR);
    scratch = scratch_buffer;

    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&pwdval, scratch, WPA3_KDF_EXPAND_LEN);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&u1, scratch, WPA3_SAE_KEYSEED_KEY_LEN);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&u2, scratch, WPA3_SAE_KEYSEED_KEY_LEN);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&m, scratch, 2);

    NX_CRYPTO_EC_POINT_INITIALIZE(&P1, NX_CRYPTO_EC_POINT_AFFINE, scratch,
        wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size);
    NX_CRYPTO_EC_POINT_INITIALIZE(&P2, NX_CRYPTO_EC_POINT_AFFINE, scratch,
        wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size);

    /* set m = 1 */
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&m, 1);

    /* pwd-seed = HKDF-Extract(ssid, password [|| identifier]) */
    ret = wpa3_crypto_hkdf_extract(hkdf_metadata, sizeof(hkdf_metadata),
            (const UCHAR *) ssid, (size_t) strlen((const char *) ssid),
            (const UCHAR *) passphrase,
            (size_t) strlen((const char *) passphrase),
            (UCHAR *) pwd_seed, sizeof(pwd_seed));
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(
                ("WPA3-EXT-SUPP:mbedtls_hkdf_extract failed ret=%ld \n", ret));
        ret = WPA3_EXT_CRYPTO_ERROR;
        goto cleanup;
    }

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:  pwd_seed\n"));
    WPA3_EXT_HEX_BUF_DUMP((pwd_seed, sizeof(pwd_seed)));

    /* pwd-value = HKDF-Expand(pwd-seed, SAE Hash to Element u1 P1, len) */
    ret = wpa3_crypto_hkdf_expand(hkdf_metadata, sizeof(hkdf_metadata),
            (const UCHAR *) pwd_seed, (size_t) sizeof(pwd_seed),
            (const UCHAR *) ("SAE Hash to Element u1 P1"),
            (size_t) strlen("SAE Hash to Element u1 P1"),
            (UCHAR *) pwd_value, (size_t) sizeof(pwd_value));
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(
                ("WPA3-EXT-SUPP:mbedtls_hkdf_expand u1p1 failed ret=%ld \n", ret));
        ret = WPA3_EXT_CRYPTO_ERROR;
        goto cleanup;
    }

    /* Perform a modular reduction. R = pwd-value mod p*/
    /* u1 = pwd_value modulo p */
    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_setup(&pwdval, pwd_value, sizeof(pwd_value)));
    _nx_crypto_huge_number_modulus(&pwdval, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    NX_CRYPTO_HUGE_NUMBER_COPY(&u1, &pwdval);

    WPA3_EXT_HEX_BUF_DUMP_WITH_LABEL("WPA3-EXT-SUPP:  pwd_value", pwd_value, sizeof(pwd_value));
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: u1 pwdval point", &pwdval);
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: u1", &u1);

    /* P1 = SSWU(u1) */
    ret = wpa3_cyrpto_sswu_algo(wksp, &u1, xp1, yp1);
    if (ret != CY_RSLT_SUCCESS) {
        WPA3_EXT_LOG_MSG(
                ("WPA3-EXT-SUPP:wpa3_cyrpto_sswu_algo pt1 failed ret=%ld \n", ret));
        ret = WPA3_EXT_CRYPTO_ERROR;
        goto cleanup;
    }
    wpa3_crypto_read_point_from_buffer(wksp, xp1, yp1, &P1);

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:xp1 dump\n"));
    WPA3_EXT_HEX_BUF_DUMP((xp1, sizeof(xp1)));
    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:yp1 dump\n"));
    WPA3_EXT_HEX_BUF_DUMP((yp1, sizeof(yp2)));

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:P1 (X,Y) point\n"));
    WPA3_EXT_HEX_BIGNUM_DUMP((&P1.nx_crypto_ec_point_x));
    WPA3_EXT_HEX_BIGNUM_DUMP((&P1.nx_crypto_ec_point_y));

    /* check if the point is valid on the ECP curve */
    ret = _nx_crypto_ec_validate_public_key(&P1,
            wksp->wpa3_crypto_ctxt->curve, NX_CRYPTO_FALSE, scratch);
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(("\n** WPA3-EXT-SUPP:P1 point not valid on curve ret=%ld\n", ret));
    }
    else
    {
        WPA3_EXT_LOG_MSG(("\n** WPA3-EXT-SUPP:P1 point VALID on ECP CURVE ret=%ld **\n", ret));
    }

    /* pwd-value = HKDF-Expand(pwd-seed, SAE Hash to Element u2 P2, len) */
    ret = wpa3_crypto_hkdf_expand(hkdf_metadata, sizeof(hkdf_metadata),
            (const UCHAR *) pwd_seed, (size_t) sizeof(pwd_seed),
            (const UCHAR *) ("SAE Hash to Element u2 P2"),
            (size_t) strlen("SAE Hash to Element u2 P2"),
            (UCHAR *) pwd_value, (size_t) sizeof(pwd_value));
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(
                ("WPA3-EXT-SUPP:mbedtls_hkdf_expand u2p2 failed ret=%ld \n", ret));
        ret = WPA3_EXT_CRYPTO_ERROR;
        goto cleanup;
    }

    /* u2 = pwd-value modulo p */
    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_setup(&pwdval, pwd_value, sizeof(pwd_value)));
    _nx_crypto_huge_number_modulus(&pwdval, &wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_field.fp);
    NX_CRYPTO_HUGE_NUMBER_COPY(&u2, &pwdval);

    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: u2 pwdval point", &pwdval);
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: u2", &u2);

    ret = wpa3_cyrpto_sswu_algo(wksp, &u2, xp2, yp2);
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(
                ("WPA3-EXT-SUPP:wpa3_cyrpto_sswu_algo pt2 failed ret=%ld \n", ret));
        ret = WPA3_EXT_CRYPTO_ERROR;
        goto cleanup;
    }

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:xp2 dump\n"));
    WPA3_EXT_HEX_BUF_DUMP((xp2, sizeof(xp2)));
    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:yp2 dump\n"));
    WPA3_EXT_HEX_BUF_DUMP((yp2, sizeof(yp2)));

    /*  PT = elem-op(P1, P2); */
    wpa3_crypto_read_point_from_buffer(wksp, xp2, yp2, &P2);

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:P2 (X,Y) point\n"));
    WPA3_EXT_HEX_BIGNUM_DUMP((&P2.nx_crypto_ec_point_x));
    WPA3_EXT_HEX_BIGNUM_DUMP((&P2.nx_crypto_ec_point_y));

    /* check if the point is valid on the ECP curve */
    ret = _nx_crypto_ec_validate_public_key(&P2,
            wksp->wpa3_crypto_ctxt->curve, NX_CRYPTO_FALSE, scratch);
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(("\n** WPA3-EXT-SUPP:P2 point not valid on curve ret=%ld\n", ret));
    }
    else
    {
        WPA3_EXT_LOG_MSG(("\n** WPA3-EXT-SUPP:P2 point VALID on ECP CURVE ret=%ld **\n", ret));
    }

    /* P1 =  P1 + P2 */
    wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_add(
            wksp->wpa3_crypto_ctxt->curve,
            &P1,
            &P2,
            scratch);

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:PT (X,Y) point\n"));
    WPA3_EXT_HEX_BIGNUM_DUMP((&P1.nx_crypto_ec_point_x));
    WPA3_EXT_HEX_BIGNUM_DUMP((&P1.nx_crypto_ec_point_y));

    /* Write to output buffer */
    ret = wpa3_crypto_write_point_to_buffer(wksp, &P1, output, outlen);

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:output dump\n"));
    WPA3_EXT_HEX_BUF_DUMP((output, outlen));

    if (ret != CY_RSLT_SUCCESS)
    {
        ret = WPA3_EXT_CRYPTO_ERROR;
    }

cleanup:
    if (scratch_buffer != NULL)
    {
        free(scratch_buffer);
    }
    return ret;
}

/**
 * @brief Check if (x, y) point is valid on the EC curve.
 *
 * @param wksp WPA3 supplicant workspace.
 *
 * @return CY_RSLT_SUCCESS if valid, error code otherwise.
 */
cy_rslt_t wpa3_crypto_check_valid_point_on_ecp_curve( wpa3_supplicant_workspace_t *wksp )
{
    HN_UBASE *scratch = NULL;
    HN_UBASE *scratch_buffer = NULL;
    UINT status;
    uint8_t pwe_buf[WPA3_SAE_KEYSEED_KEY_LEN * 2 + 1] = { 0 };
    cy_rslt_t ret = CY_RSLT_SUCCESS;

    WPA3_EXT_CRYPTO_ALLOC_AND_VALIDATE_SCRATCH_BUFF(
        scratch_buffer,
        (wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size * 16),
        WPA3_EXT_CRYPTO_ERROR);
    scratch = scratch_buffer;

    /* read x and y into EC point pwe */
    status = wpa3_crypto_create_ec_point(&wksp->wpa3_crypto_ctxt->pwe, pwe_buf,
        wksp->wpa3_crypto_ctxt->x_buf, sizeof(wksp->wpa3_crypto_ctxt->x_buf),
        wksp->wpa3_crypto_ctxt->y_buf, sizeof(wksp->wpa3_crypto_ctxt->y_buf));
    if(status == NX_CRYPTO_SUCCESS)
    {
        status = _nx_crypto_ec_validate_public_key(&wksp->wpa3_crypto_ctxt->pwe,
                wksp->wpa3_crypto_ctxt->curve, NX_CRYPTO_FALSE, scratch);
        if (status != NX_CRYPTO_SUCCESS)
        {
            WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP:EC point is not valid on the curve (status=%u)\n", status));
        }
        else
        {
            WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP:EC point is valid on the curve\n"));
        }
    }
    else
    {
        WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP:EC point setup failed (status=%u)\n", status));
    }

    if (scratch_buffer != NULL)
    {
        free(scratch_buffer);
    }

    ret = (status == NX_CRYPTO_SUCCESS) ? WPA3_EXT_SUPP_RSLT_SUCCESS : WPA3_EXT_CRYPTO_ERROR;
    return ret;
}

/**
 * @brief Generate scalar and element for SAE commit.
 *
 * @param workspace WPA3 supplicant workspace.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
cy_rslt_t wpa3_crypto_gen_scalar_and_element(wpa3_supplicant_workspace_t* workspace)
{
    NX_CRYPTO_HUGE_NUMBER private;
    NX_CRYPTO_HUGE_NUMBER mask;
    NX_CRYPTO_HUGE_NUMBER tmp;
    HN_UBASE *scratch_buffer = NULL;
    HN_UBASE *scratch = NULL;
    wpa3_crypto_context_info_t *crypto_ctxt = workspace->wpa3_crypto_ctxt;
    NX_CRYPTO_EC *curve = crypto_ctxt->curve;
    cy_rslt_t ret = CY_RSLT_SUCCESS;
    UINT size = curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size * 32;

    WPA3_EXT_CRYPTO_ALLOC_AND_VALIDATE_SCRATCH_BUFF(
        scratch_buffer,
        size,
        WPA3_EXT_CRYPTO_ERROR);
    scratch = scratch_buffer;

    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&private, scratch, curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&mask, scratch, curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&tmp, scratch, curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size * 2);

    /* generate private and mask */
    /* 1 < private < q   */
    wpa3_crypto_get_rand(curve, &private, true);

    /* 1 < mask    < q  */
    wpa3_crypto_get_rand(curve, &mask, true);

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:private\n"));
    WPA3_EXT_HEX_BIGNUM_DUMP((&private));

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:mask\n"));
    WPA3_EXT_HEX_BIGNUM_DUMP((&mask));

    /* scalar = (private + mask ) mod q */

    /* tmp = private + mask */
    NX_CRYPTO_HUGE_NUMBER_COPY(&tmp, &private);
    _nx_crypto_huge_number_add(&tmp, &mask);

    /* scalar = tmp mod q */
    _nx_crypto_huge_number_modulus(&tmp, &curve->nx_crypto_ec_n);

    /* sta_scalar = scalar */
    NX_CRYPTO_HUGE_NUMBER_COPY(&crypto_ctxt->sta_scalar, &tmp);

    /* sta_private = private */
    NX_CRYPTO_HUGE_NUMBER_COPY(&crypto_ctxt->sta_private, &private);

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:STA SCALAR\n"));
    WPA3_EXT_HEX_BIGNUM_DUMP((&crypto_ctxt->sta_scalar));

    /* sta_commit_element = scalar-op(mask, pwe) */
    curve->nx_crypto_ec_multiple(curve,
            &crypto_ctxt->pwe,
            &mask,
            &crypto_ctxt->sta_commit_element,
            scratch);

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:commit element before inverse\n"));
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("COMMIT Element X", &crypto_ctxt->sta_commit_element.nx_crypto_ec_point_x);
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("COMMIT Element Y", &crypto_ctxt->sta_commit_element.nx_crypto_ec_point_y);

    /* sta_commit_element = inverse(sta_commit_element) */
    ret = wpa3_crypto_point_inverse(curve,
            &crypto_ctxt->sta_commit_element,
            &crypto_ctxt->sta_commit_element);
    if (ret != 0)
    {
        WPA3_EXT_LOG_MSG(
                ( "WPA3-EXT-SUPP:wpa3_crypto_point_inverse failed: ret=%ld\n", ret ));
        goto cleanup;
    }

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:commit element\n"));
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("COMMIT Element X", &crypto_ctxt->sta_commit_element.nx_crypto_ec_point_x);
    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("COMMIT Element Y", &crypto_ctxt->sta_commit_element.nx_crypto_ec_point_y);

    /* check if the point is valid on the ECP curve */
    ret = _nx_crypto_ec_validate_public_key(&crypto_ctxt->sta_commit_element,
            curve, NX_CRYPTO_FALSE, scratch);
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(
                ("\n WPA3-EXT-SUPP:Commit Element  not valid point on curve ret=%ld\n", ret));
    }
    else
    {
        WPA3_EXT_LOG_MSG(
                ("\n*** WPA3-EXT-SUPP:Commit Element is a VALID point on ECP CURVE ret=%ld ***\n", ret));
    }

cleanup:
    if (scratch_buffer != NULL)
    {
        memset(scratch_buffer, 0, size);
        free(scratch_buffer);
    }
    return ret;
}

/**
 * @brief Serialize group ID, scalar, and element to buffer.
 *
 * @param workspace WPA3 supplicant workspace.
 * @param buf Output buffer.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
cy_rslt_t wpa3_crypto_get_grp_id_scalar_element(wpa3_supplicant_workspace_t* workspace, uint8_t * buf)
{
    cy_rslt_t ret = CY_RSLT_SUCCESS;
    int len = 0;

    if (workspace != NULL)
    {
        memcpy(buf, &(workspace->wpa3_crypto_ctxt->group_id),
                sizeof(workspace->wpa3_crypto_ctxt->group_id));
        len += sizeof(workspace->wpa3_crypto_ctxt->group_id);

        NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
                &workspace->wpa3_crypto_ctxt->sta_scalar,
                &buf[len], WPA3_SAE_SCALAR_LEN));

        WPA3_EXT_LOG_MSG(
                ("\nWPA3-EXT-SUPP:WPA3_EXT_HEX_BUF_DUMP .. own Scalar scalar dump\n"));
        WPA3_EXT_HEX_BUF_DUMP((&buf[len], WPA3_SAE_SCALAR_LEN));
        len += WPA3_SAE_SCALAR_LEN;

        NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
                &workspace->wpa3_crypto_ctxt->sta_commit_element.nx_crypto_ec_point_x,
                &buf[len], WPA3_SAE_SCALAR_LEN));

        WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:STA Element dump\n"));
        WPA3_EXT_HEX_BUF_DUMP((&buf[len], WPA3_SAE_SCALAR_LEN));
        len += WPA3_SAE_SCALAR_LEN;

        NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
                &workspace->wpa3_crypto_ctxt->sta_commit_element.nx_crypto_ec_point_y,
                &buf[len], WPA3_SAE_SCALAR_LEN));

        WPA3_EXT_HEX_BUF_DUMP((&buf[len], WPA3_SAE_SCALAR_LEN));
        len += WPA3_SAE_SCALAR_LEN;
        WPA3_EXT_LOG_MSG(
                ("\nWPA3-EXT-SUPP:WPA3_EXT_HEX_BUF_DUMP .. own Element len=%d\n", len));
    }
cleanup:
    return ret;
}

/**
 * @brief Serialize group ID to buffer.
 *
 * @param workspace WPA3 supplicant workspace.
 * @param buf Output buffer.
 *
 * @return CY_RSLT_SUCCESS on success.
 */
cy_rslt_t wpa3_crypto_get_grp_id(wpa3_supplicant_workspace_t* workspace, uint8_t * buf)
{
    if (workspace != NULL && buf != NULL)
    {
        memcpy(buf, &(workspace->wpa3_crypto_ctxt->group_id),
                sizeof(workspace->wpa3_crypto_ctxt->group_id));
    }
    return CY_RSLT_SUCCESS;
}

/**
 * @brief Serialize scalar and element to buffer.
 *
 * @param workspace WPA3 supplicant workspace.
 * @param buf Output buffer.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
cy_rslt_t wpa3_crypto_get_scalar_element(wpa3_supplicant_workspace_t* workspace, uint8_t * buf)
{
    cy_rslt_t ret = CY_RSLT_SUCCESS;
    int len = 0;

    if (workspace != NULL && buf != NULL)
    {
        NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
                &workspace->wpa3_crypto_ctxt->sta_scalar,
                buf, WPA3_SAE_SCALAR_LEN));

        WPA3_EXT_LOG_MSG(
                ("\nWPA3-EXT-SUPP:WPA3_EXT_HEX_BUF_DUMP .. own Scalar scalar dump\n"));
        WPA3_EXT_HEX_BUF_DUMP((&buf[len], WPA3_SAE_SCALAR_LEN));
        len += WPA3_SAE_SCALAR_LEN;

        NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
                &workspace->wpa3_crypto_ctxt->sta_commit_element.nx_crypto_ec_point_x,
                &buf[len], WPA3_SAE_SCALAR_LEN));

        WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:STA Element dump\n"));
        WPA3_EXT_HEX_BUF_DUMP((&buf[len], WPA3_SAE_SCALAR_LEN));
        len += WPA3_SAE_SCALAR_LEN;

        NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
                &workspace->wpa3_crypto_ctxt->sta_commit_element.nx_crypto_ec_point_y,
                &buf[len], WPA3_SAE_SCALAR_LEN));

        WPA3_EXT_HEX_BUF_DUMP((&buf[len], WPA3_SAE_SCALAR_LEN));
        len += WPA3_SAE_SCALAR_LEN;
        WPA3_EXT_LOG_MSG(
                ("\nWPA3-EXT-SUPP:WPA3_EXT_HEX_BUF_DUMP .. own Element len=%d\n", len));
    }
cleanup:
    return ret;
}

/**
 * @brief Check own and peer scalar/element for validity and uniqueness.
 *
 * @param workspace WPA3 supplicant workspace.
 *
 * @return CY_RSLT_SUCCESS if valid, error code otherwise.
 */
cy_rslt_t wpa3_crypto_chk_own_peer_scalar_element(wpa3_supplicant_workspace_t* workspace)
{
    NX_CRYPTO_HUGE_NUMBER scalar_one;
    int ret = 0;
    cy_rslt_t result = CY_RSLT_SUCCESS;
    HN_UBASE buff[2];
    HN_UBASE *scratch = (HN_UBASE*)buff;

    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&scalar_one, scratch, 2);
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&scalar_one, 1);

    /* Scalar range check 1 < scalar < q */
    ret = _nx_crypto_huge_number_compare(&(workspace->wpa3_sae_context_info.peer_commit_scalar),
            &scalar_one);
    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:Scalar COMP ret %d\n", ret));

    /* scalar greater than 1*/
    if (ret == NX_CRYPTO_HUGE_NUMBER_GREATER)
    {
        ret = _nx_crypto_huge_number_compare(&(workspace->wpa3_sae_context_info.peer_commit_scalar),
                                            &workspace->wpa3_crypto_ctxt->curve->nx_crypto_ec_n);
        /* scalar less than order */
        if (ret == NX_CRYPTO_HUGE_NUMBER_LESS)
        {
            ret = _nx_crypto_huge_number_compare(&workspace->wpa3_crypto_ctxt->sta_scalar,
                                                &workspace->wpa3_sae_context_info.peer_commit_scalar);

            WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("STA SCALAR", &workspace->wpa3_crypto_ctxt->sta_scalar);
            WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("PEER SCALAR", &workspace->wpa3_sae_context_info.peer_commit_scalar);

            /* if scalar is different check element */
            if (ret != NX_CRYPTO_HUGE_NUMBER_EQUAL)
            {
                ret = nx_crypto_ec_point_compare(&workspace->wpa3_crypto_ctxt->sta_commit_element,
                                &(workspace->wpa3_sae_context_info.peer_commit_element));

                WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP:STA COMMIT X",
                        &workspace->wpa3_crypto_ctxt->sta_commit_element.nx_crypto_ec_point_x);
                WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP:STA COMMIT Y",
                        &workspace->wpa3_crypto_ctxt->sta_commit_element.nx_crypto_ec_point_y);
                WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP:PEER COMMIT X",
                        &workspace->wpa3_sae_context_info.peer_commit_element.nx_crypto_ec_point_x);
                WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP:PEER COMMIT Y",
                        &workspace->wpa3_sae_context_info.peer_commit_element.nx_crypto_ec_point_y);
            }
            else
            {
                /* scalar is same as peer scalar  */
                result = WPA3_EXT_SUPP_RSLT_SCALAR_ELEMENT_RANGE_ERROR;
            }

            if (ret == NX_CRYPTO_HUGE_NUMBER_EQUAL)
            {
                /* element is same as peer element */
                result = WPA3_EXT_SUPP_RSLT_SCALAR_ELEMENT_RANGE_ERROR;
            }
        }
        else
        {
            /* scalar greater than or equal to order of the curve */
            result = WPA3_EXT_SUPP_RSLT_SCALAR_ELEMENT_RANGE_ERROR;
        }
    }
    else
    {
        /* scalar less than 1 */
        result = WPA3_EXT_SUPP_RSLT_SCALAR_ELEMENT_RANGE_ERROR;
    }

    if (result != WPA3_EXT_SUPP_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:Check own peer scalar returned %d\n", ret));
    }
    return result;
}

/**
 * @brief Compute shared secret for SAE.
 *
 * @param workspace WPA3 supplicant workspace.
 * @param k Output buffer for shared secret.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
cy_rslt_t wpa3_crypto_compute_shared_secret(wpa3_supplicant_workspace_t *workspace, uint8_t *k)
{
    cy_rslt_t ret = CY_RSLT_SUCCESS;
    NX_CRYPTO_EC_POINT ecp_point;
    wpa3_crypto_context_info_t *crypto_ctxt;
    NX_CRYPTO_HUGE_NUMBER m;
    HN_UBASE *scratch_buffer = NULL;
    HN_UBASE *scratch = NULL;
    NX_CRYPTO_EC_POINT tmp_1, tmp_2;
    NX_CRYPTO_EC *curve;

    if (workspace == NULL)
    {
        return WPA3_EXT_SUPP_ERROR;
    }
    crypto_ctxt = workspace->wpa3_crypto_ctxt;
    curve = workspace->wpa3_crypto_ctxt->curve;

    WPA3_EXT_CRYPTO_ALLOC_AND_VALIDATE_SCRATCH_BUFF(
        scratch_buffer,
        (curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size * 32),
        WPA3_EXT_CRYPTO_ERROR);
    scratch = scratch_buffer;

    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&m, scratch, 2);
    NX_CRYPTO_EC_POINT_INITIALIZE(&ecp_point, NX_CRYPTO_EC_POINT_AFFINE, scratch,
        curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size);
    NX_CRYPTO_EC_POINT_INITIALIZE(&tmp_1, NX_CRYPTO_EC_POINT_AFFINE, scratch,
        curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size);
    NX_CRYPTO_EC_POINT_INITIALIZE(&tmp_2, NX_CRYPTO_EC_POINT_AFFINE, scratch,
        curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size);

    /* set m = 1 */
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&m, 1);

    /*  K = F(scalar-op(private, element-op(peer-Element, scalar-op(peer-scalar, PE)))) */
    /*  If K is identity element (point-at-infinity) then reject */
    /*  k = F(K) (= x coordinate) */

    /* ecp_point = scalar-op(peer-scalar, PE) */
    curve->nx_crypto_ec_multiple(curve,
            &crypto_ctxt->pwe,
            &(workspace->wpa3_sae_context_info.peer_commit_scalar),
            &ecp_point,
            scratch);

    /* temp_point =  m * (peer-Element) +  m * (ecp_point) */
    curve->nx_crypto_ec_multiple(curve,
            &(workspace->wpa3_sae_context_info.peer_commit_element),
            &m,
            &tmp_1,
            scratch);

    curve->nx_crypto_ec_multiple(curve,
            &ecp_point,
            &m,
            &tmp_2,
            scratch);

    curve->nx_crypto_ec_add(curve,
            &tmp_1,
            &tmp_2,
            scratch);

    /* ecp_point = scalar-op(private, temp_point) */
    curve->nx_crypto_ec_multiple(curve,
            &tmp_1,
            &(workspace->wpa3_crypto_ctxt->sta_private),
            &ecp_point,
            scratch);

    if(_nx_crypto_ec_point_is_infinite(&ecp_point))
    {
        /* point is at infinity */
        WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:computed K is at infinity \n"));
        ret = WPA3_EXT_CRYPTO_ERROR;
        goto cleanup;
    }

    /* copy the ecp_point to buffer */
    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
            &ecp_point.nx_crypto_ec_point_x,
            (uint8_t *)k, WPA3_SAE_SCALAR_LEN));

    WPA3_EXT_BIGNUM_DUMP_WITH_LABEL("WPA3-EXT-SUPP: ECP POINT.X", &ecp_point.nx_crypto_ec_point_x);
    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:Dump of K \n"));
    WPA3_EXT_HEX_BUF_DUMP((k, WPA3_SAE_KEYSEED_KEY_LEN));

    /*  kck | mk = KDF-n(k, "SAE KCK and PMK") */
    /*  confirm = H(kck | scalar | peer-scalar | Element | Peer-Element | <sender-id>) */

cleanup:
    if (scratch_buffer != NULL)
    {
        free(scratch_buffer);
    }
    return ret;
}

/**
 * @brief Derive KCK and PMK from shared secret.
 *
 * @param workspace WPA3 supplicant workspace.
 * @param k Shared secret.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
cy_rslt_t wpa3_crypto_derive_kck_pmk(wpa3_supplicant_workspace_t *workspace, uint8_t *k)
{
    cy_rslt_t result = CY_RSLT_SUCCESS;
    uint8_t zero_key[WPA3_SAE_KEYSEED_KEY_LEN];
    uint8_t keyseed[WPA3_SAE_KEYSEED_KEY_LEN] = { 0 };
    uint8_t value[WPA3_SAE_KEYSEED_KEY_LEN] = { 0 };
    uint8_t kckpmk[WPA3_KCK_PMK_LEN] = { 0 };
    NX_CRYPTO_HUGE_NUMBER temp;
    int ret = 0;
    size_t key_len = WPA3_SAE_KEYSEED_KEY_LEN;
    uint8_t num_elem = 1;
    UCHAR buff[64];
    HN_UBASE *scratch = (HN_UBASE*)buff;

    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&temp, scratch, sizeof(buff));

    WPA3_EXT_LOG_MSG(
            ("\nWPA3-EXT-SUPP:wpa3_crypto_derive_kck_pmk() Dump of K \n"));
    WPA3_EXT_HEX_BUF_DUMP((k, WPA3_SAE_KEYSEED_KEY_LEN));

    /* keyseed = H(<0>32, k)
    * KCK + PMK = KDF-512(keyseed, "SAE KCK and PMK", (commit-scalar + peer-commit-scalar) mod r)
    * PMKID = L(( commit-scalar + peer-commit-scalar) mod r, 0, 128)
    */
    memset(zero_key, 0, sizeof(zero_key));
    ret = wpa3_crypto_hmac_sha256(zero_key, WPA3_SAE_KEYSEED_KEY_LEN,
                                num_elem, &k, &key_len, keyseed);
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(
                ("WPA3-EXT-SUPP:wpa3_crypto_derive_kck_pmk -->wpa3_supplicant_hmac_sha256 failed ret = %d\n", ret));
        goto cleanup;
    }

    WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP:keyseed dump\n "));
    WPA3_EXT_HEX_BUF_DUMP((keyseed, WPA3_SAE_KEYSEED_KEY_LEN));

    /* tmp = commit-scalar + peer-commit-scalar */
    NX_CRYPTO_HUGE_NUMBER_COPY(&temp, &(workspace->wpa3_crypto_ctxt->sta_scalar));
    _nx_crypto_huge_number_add(&temp, &(workspace->wpa3_sae_context_info.peer_commit_scalar));

    /* tmp = tmp mod q */
    _nx_crypto_huge_number_modulus(&temp, &workspace->wpa3_crypto_ctxt->curve->nx_crypto_ec_n);

    _nx_crypto_huge_number_extract_fixed_size(&temp, value, sizeof(value));

    WPA3_EXT_LOG_MSG((" WPA3-EXT-SUPP:SAE: PMKID dump\n"));
    WPA3_EXT_HEX_BUF_DUMP((value, WPA3_SAE_KEYSEED_KEY_LEN));

    WPA3_EXT_LOG_MSG(
            (" WPA3-EXT-SUPP:SAE: calling wpa3_crypto_hmac_sha256_kdf KCK!!!\n"));

    ret = wpa3_crypto_hmac_sha256_kdf_bits(keyseed, sizeof(keyseed),
            "SAE KCK and PMK", value, WPA3_SAE_KEYSEED_KEY_LEN, kckpmk,
            WPA3_KCK_PMK_LEN_BITS);
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(
                ("WPA3-EXT-SUPP:wpa3_supplicant_hmac_sha256_kdf failed ret = %d\n", ret));
        result = WPA3_EXT_CRYPTO_ERROR;
        goto cleanup;
    }
    memset(keyseed, 0, sizeof(keyseed));

    memcpy(workspace->wpa3_sae_context_info.kck, kckpmk, WPA3_SAE_KCK_LEN);
    memcpy(workspace->wpa3_sae_context_info.pmk, &kckpmk[WPA3_SAE_KCK_LEN], WPA3_SAE_PMK_LEN);
    memcpy(workspace->wpa3_sae_context_info.pmkid, value, WPA3_SAE_PMKID_LEN);

    WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP: SAE: PMKID 0-128 dump\n"));
    WPA3_EXT_HEX_BUF_DUMP((workspace->wpa3_sae_context_info.pmkid, WPA3_SAE_PMKID_LEN));

    memset(kckpmk, 0, sizeof(kckpmk));
    memset(value, 0, sizeof(value));

    WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP:SAE: KCK dump\n"));
    WPA3_EXT_HEX_BUF_DUMP((workspace->wpa3_sae_context_info.kck, WPA3_SAE_KCK_LEN));

    WPA3_EXT_LOG_MSG(("WPA3-EXT-SUPP:SAE: PMK dump\n"));
    WPA3_EXT_HEX_BUF_DUMP((workspace->wpa3_sae_context_info.pmk, WPA3_SAE_PMK_LEN));

cleanup:
    memset(buff, 0, sizeof(buff));
    return result;
}

/**
 * @brief Parse peer's group ID, scalar, and element from buffer.
 *
 * @param workspace WPA3 supplicant workspace.
 * @param buf Input buffer.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
cy_rslt_t wpa3_crypto_get_peer_grp_id_scalar_element(wpa3_supplicant_workspace_t* workspace, uint8_t *buf)
{
    int ret;
    int len = 0;
    uint8_t ap_scalar_element_buf[WPA3_SAE_KEYSEED_KEY_LEN * 2 + 1] = { 0 };
    HN_UBASE scratch[32];

    if (workspace != NULL)
    {
        memcpy(&(workspace->wpa3_sae_context_info.peer_group_id), buf,
                sizeof(workspace->wpa3_sae_context_info.peer_group_id));
        len += sizeof(workspace->wpa3_sae_context_info.peer_group_id);
        WPA3_EXT_LOG_MSG(
                ("\nWPA3-EXT-SUPP:wpa3_crypto_get_peer_grp_id_scalar_element() length of group id len=%d\n", len));

        _nx_crypto_huge_number_setup(&workspace->wpa3_sae_context_info.peer_commit_scalar,
                (unsigned char *)&buf[len], WPA3_SAE_SCALAR_LEN);

        WPA3_EXT_LOG_MSG(
                ("\nWPA3-EXT-SUPP:WPA3_EXT_HEX_BUF_DUMP .. peer scalar scalar dump\n"));
        WPA3_EXT_HEX_BUF_DUMP((&buf[len], WPA3_SAE_SCALAR_LEN));
        len += WPA3_SAE_SCALAR_LEN;

        /* read x and y into ecp point ap_scalar_element_buf */
        ret = wpa3_crypto_create_ec_point(
                &workspace->wpa3_sae_context_info.peer_commit_element,
                ap_scalar_element_buf,
                &buf[len],
                WPA3_SAE_SCALAR_LEN,
                &buf[len+WPA3_SAE_SCALAR_LEN],
                WPA3_SAE_SCALAR_LEN);
        if (ret != CY_RSLT_SUCCESS)
        {
            WPA3_EXT_LOG_MSG(
                    ("WPA3-EXT-SUPP:my_ecp_point_read_binary of AP element failed ret=%d\n", ret));
            return WPA3_EXT_CRYPTO_ERROR;
        }

        WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:xy point of peer element\n"));
        WPA3_EXT_HEX_BIGNUM_DUMP((&workspace->wpa3_sae_context_info.peer_commit_element.nx_crypto_ec_point_x));
        WPA3_EXT_HEX_BIGNUM_DUMP((&workspace->wpa3_sae_context_info.peer_commit_element.nx_crypto_ec_point_y));

        /* check if the point is valid on the ECP curve */
        ret = _nx_crypto_ec_validate_public_key(&workspace->wpa3_sae_context_info.peer_commit_element,
                workspace->wpa3_crypto_ctxt->curve, NX_CRYPTO_FALSE, scratch);
        if (ret != CY_RSLT_SUCCESS)
        {
            WPA3_EXT_LOG_MSG(
                    ("\n** WPA3-EXT-SUPP:peer Element xyz point not valid on curve ret=%d\n", ret));
            return WPA3_EXT_CRYPTO_ERROR;
        }
        else
        {
            WPA3_EXT_LOG_MSG(
                    ("\n** WPA3-EXT-SUPP:peer Element xyz point VALID on ECP CURVE ret=%d **\n", ret));
        }
    }
    return CY_RSLT_SUCCESS;
}

/**
 * @brief Parse peer's send-confirm from buffer.
 *
 * @param workspace WPA3 supplicant workspace.
 * @param buf Input buffer.
 *
 * @return CY_RSLT_SUCCESS on success.
 */
cy_rslt_t wpa3_crypto_get_send_confirm(wpa3_supplicant_workspace_t* workspace, uint8_t *buf)
{
    uint16_t len = 0;

    if (workspace != NULL && buf != NULL)
    {
        memcpy(&(workspace->wpa3_sae_context_info.rc), buf,
                sizeof(workspace->wpa3_sae_context_info.rc));
        len += sizeof(workspace->wpa3_sae_context_info.rc);
        WPA3_EXT_LOG_MSG(
                ("\nWPA3-EXT-SUPP:wpa3_crypto_get_send_confirm() length of receive confirm id len=%u peer-send-confirm=%d\n", len, workspace->wpa3_sae_context_info.rc));

        memcpy(workspace->wpa3_sae_context_info.peer_confirm,
                (unsigned char *) &buf[len], WPA3_SAE_CONFIRM_LEN);
        WPA3_EXT_LOG_MSG(
                ("\nWPA3-EXT-SUPP:WPA3_EXT_HEX_BUF_DUMP .. peer confirm dump\n"));
        WPA3_EXT_HEX_BUF_DUMP((&buf[len], WPA3_SAE_CONFIRM_LEN));
        len += WPA3_SAE_CONFIRM_LEN;
    }
    return CY_RSLT_SUCCESS;
}

/**
 * @brief Build and output send-confirm handshake message.
 *
 * @param wksp WPA3 supplicant workspace.
 * @param buffer Output buffer.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
cy_rslt_t wpa3_crypto_build_send_confirm_handshake(wpa3_supplicant_workspace_t * wksp, uint8_t *buffer)
{
    /* confirm = HMAC-SHA256(KCK, send-confirm, commit-scalar, COMMIT-ELEMENT,
     *              peer-commit-scalar, PEER-COMMIT-ELEMENT)
     * verifier = HMAC-SHA256(KCK, peer-send-confirm, peer-commit-scalar,
     *               PEER-COMMIT-ELEMENT, commit-scalar, COMMIT-ELEMENT)
     */

    int ret = 0;
    uint8_t confirm_data[WPA3_SAE_CONFIRM_DATA_MSG_LEN] = { 0 };
    uint8_t confirm[WPA3_SAE_KEYSEED_KEY_LEN] = { 0 };
    uint8_t *addr[5];
    size_t len[5];
    uint8_t scalar_b1[WPA3_SAE_SCALAR_LEN];
    uint8_t scalar_b2[WPA3_SAE_SCALAR_LEN];
    uint8_t element1[WPA3_SAE_ELEMENT_LEN];
    uint8_t element2[WPA3_SAE_ELEMENT_LEN];

    /* confirm = HMAC-SHA256(KCK, send-confirm, commit-scalar, COMMIT-ELEMENT, */
    /*                      peer-commit-scalar, PEER-COMMIT-ELEMENT) */

    WPA3_EXT_LOG_MSG(("\n** WPA3-EXT-SUPP:wpa3_crypto_build_send_confirm_handshake **\n"));

    /* Confirm
    * CN(key, X, Y, Z, ...) =
    *    HMAC-SHA256(key, D2OS(X) || D2OS(Y) || D2OS(Z) | ...)
    * confirm = CN(KCK, send-confirm, commit-scalar, COMMIT-ELEMENT,
    *              peer-commit-scalar, PEER-COMMIT-ELEMENT)
    * verifier = CN(KCK, peer-send-confirm, peer-commit-scalar,
    *               PEER-COMMIT-ELEMENT, commit-scalar, COMMIT-ELEMENT)
    */
    addr[0] = (uint8_t *) &(wksp->wpa3_sae_context_info.sc);
    len[0] = 2;

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP: send confirm =%d\n", wksp->wpa3_sae_context_info.sc));
    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
            &wksp->wpa3_crypto_ctxt->sta_scalar,
            scalar_b1, WPA3_SAE_SCALAR_LEN));

    addr[1] = scalar_b1;
    len[1] = WPA3_SAE_SCALAR_LEN;

    /* commit-element */
    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
            &wksp->wpa3_crypto_ctxt->sta_commit_element.nx_crypto_ec_point_x,
            element1, WPA3_SAE_SCALAR_LEN));

    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
            &wksp->wpa3_crypto_ctxt->sta_commit_element.nx_crypto_ec_point_y,
            &element1[WPA3_SAE_SCALAR_LEN], WPA3_SAE_SCALAR_LEN));

    addr[2] = element1;
    len[2] = WPA3_SAE_ELEMENT_LEN;

    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
            &wksp->wpa3_sae_context_info.peer_commit_scalar,
            scalar_b2, WPA3_SAE_SCALAR_LEN));

    addr[3] = scalar_b2;
    len[3] = WPA3_SAE_SCALAR_LEN;

    /* commit-element */
    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
            &wksp->wpa3_sae_context_info.peer_commit_element.nx_crypto_ec_point_x,
            element2, WPA3_SAE_SCALAR_LEN));

    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
            &wksp->wpa3_sae_context_info.peer_commit_element.nx_crypto_ec_point_y,
            &element2[WPA3_SAE_SCALAR_LEN], WPA3_SAE_SCALAR_LEN));

    addr[4] = element2;
    len[4] = WPA3_SAE_ELEMENT_LEN;

    ret = wpa3_crypto_hmac_sha256(wksp->wpa3_sae_context_info.kck, WPA3_SAE_KCK_LEN,
                                5, addr, len, confirm);
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(
                ("WPA3-EXT-SUPP:wpa3_crypto_build_send_confirm_handshake failed ret = %d\n", ret));
    }

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:confirm MSG dump\n"));
    WPA3_EXT_HEX_BUF_DUMP((confirm, WPA3_SAE_CONFIRM_LEN));

    memcpy(buffer, confirm, WPA3_SAE_CONFIRM_LEN);
    memcpy(wksp->wpa3_crypto_ctxt->confirm, confirm, WPA3_SAE_CONFIRM_LEN);

    memset(confirm, 0, sizeof(confirm));
    memset(confirm_data, 0, sizeof(confirm_data));

cleanup:
    return ret;
}

/**
 * @brief Verify received confirm message.
 *
 * @param wksp WPA3 supplicant workspace.
 *
 * @return CY_RSLT_SUCCESS if valid, error code otherwise.
 */
cy_rslt_t wpa3_crypto_verify_confirm_message(wpa3_supplicant_workspace_t *wksp)
{
    cy_rslt_t ret = CY_RSLT_SUCCESS;
    uint8_t verify[WPA3_SAE_KEYSEED_KEY_LEN] = { 0 };
    uint8_t temp[WPA3_SAE_CONFIRM_DATA_MSG_LEN] = { 0 };
    uint8_t *addr[5];
    size_t len[5];
    uint8_t scalar_b1[WPA3_SAE_SCALAR_LEN], scalar_b2[WPA3_SAE_SCALAR_LEN];
    uint8_t element1[WPA3_SAE_ELEMENT_LEN];
    uint8_t element2[WPA3_SAE_ELEMENT_LEN];

    /* verifier = CN(KCK, peer-send-confirm, peer-commit-scalar,
    *      PEER-COMMIT-ELEMENT, commit-scalar, COMMIT-ELEMENT)
    */

    /* Copy the peer-send-confirm */
    addr[0] = (uint8_t *) &(wksp->wpa3_sae_context_info.rc);
    len[0] = 2;

    WPA3_EXT_LOG_MSG(
            ("\nWPA3-EXT-SUPP:peer send confirm =%d\n", wksp->wpa3_sae_context_info.rc));
    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
            &(wksp->wpa3_sae_context_info.peer_commit_scalar),
            scalar_b1, WPA3_SAE_SCALAR_LEN));

    addr[1] = scalar_b1;
    len[1] = WPA3_SAE_SCALAR_LEN;

    /* commit-element */
    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
            &wksp->wpa3_sae_context_info.peer_commit_element.nx_crypto_ec_point_x,
            element1, WPA3_SAE_SCALAR_LEN));

    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
            &wksp->wpa3_sae_context_info.peer_commit_element.nx_crypto_ec_point_y,
            &element1[WPA3_SAE_SCALAR_LEN], WPA3_SAE_SCALAR_LEN));

    addr[2] = element1;
    len[2] = WPA3_SAE_ELEMENT_LEN;

    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
            &(wksp->wpa3_crypto_ctxt->sta_scalar),
            scalar_b2, WPA3_SAE_SCALAR_LEN));

    addr[3] = scalar_b2;
    len[3] = WPA3_SAE_SCALAR_LEN;

    /* commit-element */
    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
            &wksp->wpa3_crypto_ctxt->sta_commit_element.nx_crypto_ec_point_x,
            element2, WPA3_SAE_SCALAR_LEN));

    NX_CRYPTO_CHECK_RET(_nx_crypto_huge_number_extract_fixed_size(
            &wksp->wpa3_crypto_ctxt->sta_commit_element.nx_crypto_ec_point_y,
            &element2[WPA3_SAE_SCALAR_LEN], WPA3_SAE_SCALAR_LEN));

    addr[4] = element2;
    len[4] = WPA3_SAE_ELEMENT_LEN;

    ret = wpa3_crypto_hmac_sha256(wksp->wpa3_sae_context_info.kck, WPA3_SAE_KCK_LEN,
                                5, addr, len, verify);
    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(
                ("WPA3-EXT-SUPP:wpa3_crypto_build_send_confirm_handshake failed ret = %ld\n", ret));
        goto cleanup;
    }

    WPA3_EXT_LOG_MSG(("\nWPA3-EXT-SUPP:verify dump\n"));
    WPA3_EXT_HEX_BUF_DUMP((verify, WPA3_SAE_CONFIRM_LEN));

    ret = memcmp(wksp->wpa3_sae_context_info.peer_confirm, verify, WPA3_SAE_CONFIRM_LEN);

    memset(verify, 0, sizeof(verify));
    memset(temp, 0, sizeof(temp));

    if (ret != CY_RSLT_SUCCESS)
    {
        WPA3_EXT_LOG_MSG(
                ("WPA3-EXT-SUPP:confirm verify failed result = %ld\n", ret));
        return WPA3_EXT_SUPP_CONFIRM_VERIFY_FAILURE;
    }

cleanup:
    return ret;
}

/**
 * @brief Get send-confirm handshake message.
 *
 * @param workspace WPA3 supplicant workspace.
 * @param buf Output buffer.
 *
 * @return CY_RSLT_SUCCESS on success.
 */
cy_rslt_t wpa3_crypto_get_send_confirm_handshake(wpa3_supplicant_workspace_t* workspace, uint8_t * buf)
{
    cy_rslt_t result = CY_RSLT_SUCCESS;
    uint16_t len = 0;

    if (workspace != NULL && buf != NULL)
    {
        memcpy(buf, &(workspace->wpa3_sae_context_info.sc),
                sizeof(workspace->wpa3_sae_context_info.sc));
        len += sizeof(workspace->wpa3_sae_context_info.sc);

        result = wpa3_crypto_build_send_confirm_handshake(workspace, &buf[len]);
        if (result != CY_RSLT_SUCCESS)
        {
            WPA3_EXT_LOG_MSG(
                    ("\nWPA3-EXT-SUPP:wpa3_crypto_build_send_confirm_handshake failed result=%ld\n", result));
            return result;
        }
    }
    return CY_RSLT_SUCCESS;
}

/**
 * @brief Initialize SAE context info.
 *
 * @param wksp WPA3 supplicant workspace.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
cy_rslt_t wpa3_supplicant_init_sae_context_info(wpa3_supplicant_workspace_t *wksp)
{
    UINT size;
    HN_UBASE *scratch;

    if ( wksp == NULL || wksp->wpa3_crypto_ctxt == NULL || wksp->wpa3_crypto_ctxt->curve == NULL)
    {
        return WPA3_EXT_SUPP_ERROR;
    }

    size = wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size;

    wksp->wpa3_sae_context_info.scratch_buffer = malloc(size * 4);
    if (wksp->wpa3_sae_context_info.scratch_buffer == NULL)
    {
        return WPA3_EXT_SUPP_ERROR;
    }
    scratch = (HN_UBASE*)wksp->wpa3_sae_context_info.scratch_buffer;
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&wksp->wpa3_sae_context_info.peer_commit_scalar,
                                        scratch, size);
    NX_CRYPTO_EC_POINT_INITIALIZE(&wksp->wpa3_sae_context_info.peer_commit_element,
                                    NX_CRYPTO_EC_POINT_AFFINE, scratch, size);
    return CY_RSLT_SUCCESS;
}

/**
 * @brief Deinitialize SAE context info.
 *
 * @param wksp WPA3 supplicant workspace.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
cy_rslt_t wpa3_supplicant_deinit_sae_context_info(wpa3_supplicant_workspace_t *wksp)
{
    if ( wksp == NULL )
    {
        return WPA3_EXT_SUPP_ERROR;
    }
    if (wksp->wpa3_sae_context_info.scratch_buffer)
    {
        free(wksp->wpa3_sae_context_info.scratch_buffer);
        wksp->wpa3_sae_context_info.scratch_buffer = NULL;
    }
    return CY_RSLT_SUCCESS;
}

/**
 * @brief Initialize WPA3 crypto context.
 *
 * @param wksp WPA3 supplicant workspace.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
cy_rslt_t wpa3_crypto_init(wpa3_supplicant_workspace_t *wksp)
{
    cy_rslt_t ret = CY_RSLT_SUCCESS;
    HN_UBASE *scratch;
    UINT size;

    wksp->wpa3_crypto_ctxt = malloc(sizeof(wpa3_crypto_context_info_t));
    if (wksp->wpa3_crypto_ctxt == NULL)
    {
        return WPA3_EXT_SUPP_RSLT_NO_MEM;
    }

    memset(wksp->wpa3_crypto_ctxt, 0, sizeof(wpa3_crypto_context_info_t));

    NX_CRYPTO_EC_GET_SECP256R1(wksp->wpa3_crypto_ctxt->curve);

    size  = wksp->wpa3_crypto_ctxt->curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size;

    /* Initialize scratch element; 3 EC point (64*3) + 2 huge number (32*2) = 256 */
    wksp->wpa3_crypto_ctxt->scratch_buffer = malloc((size * 3 * 2) + (size * 2));
    if (wksp->wpa3_crypto_ctxt->scratch_buffer == NULL)
    {
        free(wksp->wpa3_crypto_ctxt);
        wksp->wpa3_crypto_ctxt = NULL;
        return WPA3_EXT_SUPP_RSLT_NO_MEM;
    }

    scratch = (HN_UBASE*)wksp->wpa3_crypto_ctxt->scratch_buffer;

    /* Initialize EC points */
    NX_CRYPTO_EC_POINT_INITIALIZE(&wksp->wpa3_crypto_ctxt->sta_commit_element,
            NX_CRYPTO_EC_POINT_AFFINE, scratch, size);
    NX_CRYPTO_EC_POINT_INITIALIZE(&wksp->wpa3_crypto_ctxt->sta_pt_element,
                NX_CRYPTO_EC_POINT_AFFINE, scratch, size);
    NX_CRYPTO_EC_POINT_INITIALIZE(&wksp->wpa3_crypto_ctxt->pwe,
                NX_CRYPTO_EC_POINT_AFFINE, scratch, size);

    /* Initialize Scalar and private */
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&wksp->wpa3_crypto_ctxt->sta_scalar, scratch, size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&wksp->wpa3_crypto_ctxt->sta_private, scratch, size);

    wksp->wpa3_crypto_ctxt->group_id = WPA3_SAE_ECP_GROUP_ID;

    return ret;
}

/**
 * @brief Deinitialize WPA3 crypto context.
 *
 * @param wksp WPA3 supplicant workspace.
 *
 * @return CY_RSLT_SUCCESS on success, error code otherwise.
 */
cy_rslt_t wpa3_crypto_deinit(wpa3_supplicant_workspace_t *wksp)
{
    cy_rslt_t ret = CY_RSLT_SUCCESS;

    if (wksp->wpa3_crypto_ctxt == NULL)
    {
        return WPA3_EXT_SUPP_RSLT_NO_MEM;
    }

    if (wksp->wpa3_crypto_ctxt->scratch_buffer != NULL)
    {
        free(wksp->wpa3_crypto_ctxt->scratch_buffer);
        wksp->wpa3_crypto_ctxt->scratch_buffer = NULL;
    }

    memset(wksp->wpa3_crypto_ctxt, 0, sizeof(wpa3_crypto_context_info_t));

    if (wksp->wpa3_crypto_ctxt != NULL)
    {
        free(wksp->wpa3_crypto_ctxt);
        wksp->wpa3_crypto_ctxt = NULL;
    }
    return ret;
}

/**
 * @brief Platform-specific function to retrieve PT (weak stub).
 *
 * @param ssid SSID.
 * @param passphrase Passphrase.
 * @param pt Output buffer for PT.
 */
CYPRESS_WEAK cy_rslt_t cy_wpa3_get_pfn_network( uint8_t * ssid, uint8_t *passphrase, uint8_t *pt )
{
    return WPA3_EXT_CRYPTO_ERROR;
}
