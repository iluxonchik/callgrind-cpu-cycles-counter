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

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_CERTS_C) ||    \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_SSL_TLS_C) || \
    !defined(MBEDTLS_SSL_SRV_C) || !defined(MBEDTLS_NET_C) ||     \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_CTR_DRBG_C) ||    \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_PEM_PARSE_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_CERTS_C and/or MBEDTLS_ENTROPY_C "
           "and/or MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_SRV_C and/or "
           "MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
           "MBEDTLS_CTR_DRBG_C and/or MBEDTLS_X509_CRT_PARSE_C "
           "and/or MBEDTLS_PEM_PARSE_C not defined.\n");
    return( 0 );
}
#else

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#define SERVER_MSG "pong"

#define DEBUG_LEVEL 0

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

int main( int argc, char** argv )
{


    char *ciphersuite_str_id;
    int ciphersuite_id;
    int custom_cipher_suite[2];
    char *ciphersuite_name;

    int ret, len;
    mbedtls_net_context listen_fd, client_fd;
    unsigned char buf[1024];
    const char *pers = "ssl_server";
    char *chosen_cipher;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif

    mbedtls_net_init( &listen_fd );
    mbedtls_net_init( &client_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init( &cache );
#endif
    mbedtls_x509_crt_init( &srvcert );
    mbedtls_pk_init( &pkey );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( DEBUG_LEVEL );
#endif


  // parse arg
    if (argc < 2) {
        mbedtls_printf("[!!!] No ciphersuite argument provided\n");
        return ( -1 );
    }

    ciphersuite_str_id = argv[1];

    ciphersuite_id = strtol(ciphersuite_str_id, NULL, 10);
    custom_cipher_suite[0] = ciphersuite_id;
    custom_cipher_suite[1] = 0;
    mbedtls_printf("Chosen ciphersuite id: %d\n", custom_cipher_suite[0]);

    /*
     * 1. Load the certificates and private RSA key
     */
    mbedtls_printf( "\n  . Loading the server cert. and key..." );
    fflush( stdout );

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
     */
    ciphersuite_name = mbedtls_ssl_get_ciphersuite_name(ciphersuite_id);

    unsigned char* srv_crt;
    size_t srv_crt_len;
    unsigned char *srv_key;
    size_t srv_key_len;

    // Now let's decide on which certificate to use
    const char* use_cert_with_ecdh_params = "DH-";

    // load the default server cert and key values
    srv_crt = mbedtls_test_srv_crt_rsa;
    srv_crt_len = mbedtls_test_srv_crt_rsa_len;
    srv_key = mbedtls_test_srv_key_rsa;
    srv_key_len = mbedtls_test_srv_key_rsa_len;
    mbedtls_printf("Ciphersuite Name: %s\n", ciphersuite_name);

    if (strstr(ciphersuite_name, use_cert_with_ecdh_params) != NULL){
        mbedtls_printf("[INFO] Using ECDH certificate\n");
        srv_crt = mbedtls_test_srv_crt_ec;
        srv_crt_len = mbedtls_test_srv_crt_ec_len;

        srv_key = mbedtls_test_srv_key_ec;
        srv_key_len = mbedtls_test_srv_key_ec_len;
    }


    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) srv_crt,
                                  srv_crt_len );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse #1 returned %d\n\n", ret );
        goto exit;
    }

    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_cas_pem,
                                  mbedtls_test_cas_pem_len );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse #2 returned %d\n\n", ret );
        goto exit;
    }

    // INFO: mbedtls_test_srv_key is defined in certs.c. It's literally a defined string
    ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) srv_key,
                                 srv_key_len, NULL, 0 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 2. Setup the listening TCP socket
     */
    mbedtls_printf( "  . Bind on https://localhost:4433/ ..." );
    fflush( stdout );

    if( ( ret = mbedtls_net_bind( &listen_fd, NULL, "4433", MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 3. Seed the RNG
     */
    mbedtls_printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 4. Setup stuff
     */
    mbedtls_printf( "  . Setting up the SSL data...." );
    fflush( stdout );

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                                             MBEDTLS_SSL_IS_SERVER,
                                             MBEDTLS_SSL_TRANSPORT_STREAM,
                                             MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf( "  . Setting up custom ciphersuite..." );
    fflush( stdout );

    mbedtls_ssl_conf_ciphersuites(&conf, custom_cipher_suite);

    mbedtls_printf(" ok\n");

    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache( &conf, &cache,
                                    mbedtls_ssl_cache_get,
                                    mbedtls_ssl_cache_set );
#endif

    mbedtls_ssl_conf_ca_chain( &conf, srvcert.next, NULL );
    if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert, &pkey ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    reset:
#ifdef MBEDTLS_ERROR_C
    if( ret != 0 ) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
        mbedtls_printf("The error might be caused by the fact that you're using incompatible certificate/ciphersuite types. For example, you might be trying to use a DSA ciphersuite when using an RSA certificate.");
        goto exit_no_msg; // let's end on err here
    }
#endif

    mbedtls_net_free( &client_fd );

    mbedtls_ssl_session_reset( &ssl );

    /*
     * 3. Wait until a client connects
     */
    mbedtls_printf( "  . Waiting for a remote connection ..." );
    fflush( stdout );

    if( ( ret = mbedtls_net_accept( &listen_fd, &client_fd,
                                    NULL, 0, NULL ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_accept returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_set_bio( &ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    mbedtls_printf( " ok\n" );

    /*
     * 5. Handshake
     */
    mbedtls_printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret );
            goto reset;
        }
    }

    mbedtls_printf( " ok\n" );
    chosen_cipher = mbedtls_ssl_get_ciphersuite( &ssl );
    mbedtls_printf("   Negotiated Ciphersuite: %s\n", chosen_cipher);

    /*
     * 6. Read the HTTP Request
     */
    mbedtls_printf( "  < Read from client:" );
    fflush( stdout );

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = mbedtls_ssl_read( &ssl, buf, len );

        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
            continue;

        if( ret <= 0 )
        {
            switch( ret )
            {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf( " connection was closed gracefully\n" );
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    mbedtls_printf( " connection was reset by peer\n" );
                    break;

                default:
                    mbedtls_printf( " mbedtls_ssl_read returned -0x%x\n", -ret );
                    break;
            }

            break;
        }

        len = ret;
        mbedtls_printf( " %d bytes read:\n%s\n", len, (char *) buf );

        if( ret > 0 )
            break;
    }
    while( 1 );

    /*
     * 7. Write the 200 Response
     */
    mbedtls_printf( "  > Write to client:" );
    fflush( stdout );

    len = sprintf( (char *) buf, SERVER_MSG);

    while( ( ret = mbedtls_ssl_write( &ssl, buf, len ) ) <= 0 )
    {
        if( ret == MBEDTLS_ERR_NET_CONN_RESET )
        {
            mbedtls_printf( " failed\n  ! peer closed the connection\n\n" );
            goto reset;
        }

        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf( " %d bytes written\n%s\n", len, (char *) buf );

    mbedtls_printf( "  . Closing the connection..." );

    while( ( ret = mbedtls_ssl_close_notify( &ssl ) ) < 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret );
            goto reset;
        }
    }

    mbedtls_printf( " ok\n" );

    ret = 0;
    mbedtls_printf("Terminating server...\n");
    goto exit;

    exit:

#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    exit_no_msg:

    mbedtls_net_free( &client_fd );
    mbedtls_net_free( &listen_fd );

    mbedtls_x509_crt_free( &srvcert );
    mbedtls_pk_free( &pkey );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free( &cache );
#endif
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(_WIN32)
    mbedtls_printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_CERTS_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_SSL_TLS_C && MBEDTLS_SSL_SRV_C && MBEDTLS_NET_C &&
          MBEDTLS_RSA_C && MBEDTLS_CTR_DRBG_C && MBEDTLS_X509_CRT_PARSE_C
          && MBEDTLS_FS_IO && MBEDTLS_PEM_PARSE_C */
