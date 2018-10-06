#!/bin/bash

python jointpenccol.py rsa_$1_rsa/server mbedtls_pk_sign:ssl_write_server_key_exchange jsons/rsa_$1_rsa_server.json

python jointpenccol.py rsa_$1_ecdsa/server mbedtls_pk_sign:ssl_write_server_key_exchange jsons/rsa_$1_ecdsa_server.json

python jointpenccol.py rsa_$1_rsa/client mbedtls_pk_verify:ssl_parse_server_key_exchange jsons/rsa_$1_rsa_cli.json

python jointpenccol.py rsa_$1_ecdsa/client mbedtls_pk_verify:ssl_parse_server_key_exchange jsons/rsa_$1_ecdsa_cli.json
