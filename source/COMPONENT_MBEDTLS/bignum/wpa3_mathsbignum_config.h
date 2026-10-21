/*
 * WPA3-SAE big-number / ECP arithmetic for TF-M non-secure (PSA client) builds.
 *
 * Enable with COMPONENTS+=mathsbignum in TF-M NS projects only.
 *
 * In PSA client mode TF-PSA-Crypto does not build the legacy bignum/ECP modules,
 * but wpa3_ext_crypto.c calls mbedtls_mpi_* and mbedtls_ecp_* directly. The .c
 * files in this folder are unmodified copies from ifx-tf-psa-crypto release-v1.2.100
 * (drivers/builtin/src), except for the include of this header. Their private
 * headers are used from ifx-tf-psa-crypto itself. The options below apply to these
 * files only, not to the application's crypto configuration. Structure layouts do
 * not depend on them.
 */

#if defined(CY_TFM_PSA_SUPPORTED)

#ifndef WPA3_MATHSBIGNUM_CONFIG_H
#define WPA3_MATHSBIGNUM_CONFIG_H

#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_LIGHT
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED    /* SAE group 19, the only group WPA3 uses */

#endif /* WPA3_MATHSBIGNUM_CONFIG_H */

#endif /* CY_TFM_PSA_SUPPORTED */
