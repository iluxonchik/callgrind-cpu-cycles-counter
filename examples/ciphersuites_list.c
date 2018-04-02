#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#endif


#include "mbedtls/net_sockets.h"

int main( void )
{
    /*
     * Output format:
     * NAME ID FLAGS
     */

    const int *enabled_ciphersuites;
    int index = 0;
    const char* cipher_name;
    unsigned char flags_raw;
    char* flags_str;
    const mbedtls_ssl_ciphersuite_t *ciphersuite;

    enabled_ciphersuites = mbedtls_ssl_list_ciphersuites();

    while (*enabled_ciphersuites != 0) {
        ciphersuite = mbedtls_ssl_ciphersuite_from_id(*enabled_ciphersuites);
        cipher_name = ciphersuite->name;
        flags_raw = ciphersuite->flags;

        if (flags_raw == MBEDTLS_CIPHERSUITE_WEAK)
            flags_str = "WEAK";
        else if (flags_raw == MBEDTLS_CIPHERSUITE_NODTLS)
            flags_str = "NO_DTLS";
        else if (flags_raw == MBEDTLS_CIPHERSUITE_SHORT_TAG)
            flags_str = "SHORT_TAG";
        else if (flags_raw == 0)
            flags_str = "NONE";
        else
            flags_str = "UNKNOWN";

        mbedtls_printf("%d %s %s\n", *enabled_ciphersuites, cipher_name, flags_str);
        enabled_ciphersuites++;
    }

    return( 0 );
}

