#!/usr/bin/env python3
import os
import time
import argparse
from pathlib import Path
from multiprocessing.pool import ThreadPool

from ccc.ccc import (parse_ciphersuite_list_from_file, run_server, run_client,
                     get_cc_from_callgrind_file, show_plot)

def get_next_or_default(iterator, default):
    try:
        return next(iterator)
    except StopIteration:
        return default

def build_key(sc_id, name, flags):
    flag_to_use = ''
    if flags.lower() != 'none':
        flag_to_use = f'[{flags}] '
    key = f'{flag_to_use}{sc_id}'
    return key

def create_output_directory_if_needed(out_dir):
    p = Path(out_dir)
    if not p.exists():
        print(f'\t[!] Creating {out_dir} since it did not exit.\n')
        p.mkdir(parents=True)


def run(client_path, server_path, ciphersuite_list_file_path,
        cli_bytes_start, cli_bytes_end, cli_bytes_step,
        srv_bytes_start, srv_bytes_end, srv_bytes_step,
        out_dir, timeout, verbose=False):
    SERVER_CALLGRIND_OUT_FILE = '{}/server.callgrind.out.{}.{}.{}'
    CLIENT_CALLGRIND_OUT_FILE = '{}/client.callgrind.out.{}.{}.{}'
    PROFILE_RESULTS_SRV = {}
    PROFILE_RESULTS_CLI = {}

    DEFAULT_BYTES_TO_SEND = 0

    print('Running with configurations: ')
    print(f'\tClient Path: {client_path}')
    print(f'\tSever Path: {server_path}')
    print(f'\tCiphesuite List Path: {ciphersuite_list_file_path}')
    print(f'\tclient bytes to send start, end, step: '
          f'{cli_bytes_start} {cli_bytes_end} {cli_bytes_step}')
    print(f'\tserver bytes to send start, end, step: '
          f'{srv_bytes_start} {srv_bytes_end} {srv_bytes_step}')
    print(f'\tOutput directory: {out_dir}')
    print(f'\tTimeout: {timeout}')
    print(f'\tVerbose: {verbose}')

    print('\n')

    create_output_directory_if_needed(out_dir)

    print('Parsing ciphersuties...',end='')
    ciphersuites = parse_ciphersuite_list_from_file(ciphersuite_list_file_path)
    num_cipheruites = len(ciphersuites)
    num_skipped_ciphersuites = 0
    completed_iterations = 0
    num_sigttou = 0
    ciphersuite_names = []  # display names in graph
    print('ok')

    if 0 in (srv_bytes_step, srv_bytes_end):
        print('\t[!] Setting server send bytes to zero')
        srv_bytes_start = 0
        srv_bytes_end = 1
        srv_bytes_step = 1

    if 0 in (cli_bytes_step, cli_bytes_end):
        print('\t[!] Setting client send bytes to zero')
        cli_bytes_start = 0
        cli_bytes_end = 1
        cli_bytes_step = 1

    srv_bytes_to_send_list = list(range(srv_bytes_start, srv_bytes_end, srv_bytes_step))
    cli_bytes_to_send_list = list(range(cli_bytes_start, cli_bytes_end, cli_bytes_step))

    max_iter = max(srv_bytes_to_send_list, cli_bytes_to_send_list)
    total_iterations = len(max_iter) * num_cipheruites

    produced_callgrind_out_files = [] # we don't want to delete any callgrind files from previous runs

    for sc_id, name, flags in ciphersuites:
        """
        1. Start server in thread 1
        2. Start client in thread 2
        3. Make sure that server ret code == 0
            else - continue
        4. Make sure that server ret coce == 0
            else - continue
        """
        srv_bytes_to_send_iter = iter(srv_bytes_to_send_list)
        cli_bytes_to_send_iter = iter(cli_bytes_to_send_list)

        for _ in max_iter:
            cli_bytes_to_send = get_next_or_default(cli_bytes_to_send_iter,
                                                    DEFAULT_BYTES_TO_SEND)
            srv_bytes_to_send = get_next_or_default(srv_bytes_to_send_iter,
                                                    DEFAULT_BYTES_TO_SEND)

            pool = ThreadPool(processes=2)
            completed_iterations += 1
            callgrind_out_srv = SERVER_CALLGRIND_OUT_FILE.format(out_dir,
                                                                sc_id,
                                                                srv_bytes_to_send,
                                                                cli_bytes_to_send)
            callgrind_out_cli = CLIENT_CALLGRIND_OUT_FILE.format(out_dir,
                                                                 sc_id,
                                                                 cli_bytes_to_send,
                                                                 srv_bytes_to_send)

            print(f'--- Begin profiling for {sc_id} : {name} : {flags} [{completed_iterations}/{total_iterations}] ---')

            print(f'\tStarting server... (Out file: {callgrind_out_srv})')

            async_result_srv = pool.apply_async(run_server,
                                                (server_path,
                                                 sc_id,
                                                 callgrind_out_srv,
                                                 verbose,
                                                 srv_bytes_to_send
                                                 )
                                                )

            print(f'\t\tWaiting {timeout} seconds for server to load...')
            time.sleep(timeout) # give the server time to start

            print(f'\tStarting client... (Out file: {callgrind_out_cli})')
            async_result_cli = pool.apply_async(run_client,
                                                (client_path,
                                                 sc_id,
                                                 callgrind_out_cli,
                                                 verbose,
                                                 cli_bytes_to_send
                                                 )
                                                )

            srv_res = async_result_srv.get()
            cli_res = async_result_cli.get()
            pool.close()

            if srv_res != 0 or cli_res != 0:
                print(f'\n\t[!!!] Non-zero return code from ciphersuite {sc_id} {name} {flags}')
                print(f'\t\tServer: {srv_res} Client: {cli_res}')
                print('\t\tSkipping to next ciphersuite...\n')
                num_skipped_ciphersuites += 1

                if -27 in (srv_res, cli_res):
                    # This here is sort of for debugging. If you're getting
                    # -27 return codes, make sure you're not compiling/linking
                    # with the "-pg" option
                    num_sigttou += 1

                continue

            print(f'--- End profiling for {sc_id} : {name} : {flags} [{completed_iterations}/{total_iterations}] ---\n')

    print('--- STATISTICS ---')
    print(f'\tTotal CipherSuites:{num_cipheruites}'
    f'\nMeasured: {num_cipheruites - num_skipped_ciphersuites}\n'
    f'Skipped: {num_skipped_ciphersuites}')
    print(f'Number of SIGTTOU signals: {num_sigttou}')

    if (num_sigttou > 0):
        print('[!!!] SIGTTOU singals detected! Make sure you\'re not compiling'
        '/linking with the "-pg" opiton (for gprof). You cannot use valgrind'
        ' and grpof together.')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description= 'Profile Encryption Metrics\n'
    'The goal of this tool is to profile varoius client and server encryption metric\n'
    'Run mbedTLS client and server'
    ', with different number of bytes to send and collect profiling metrics for'
    ' a list of ciphersuties.\n'
    'The output file naming will be the following:\n'
    '\t[client|server].callgrind.out.<ciphersuite_id>.<num_bytes_sent>.<num_bytes_received>')
    parser.add_argument('client', type=str, help='client program path')
    parser.add_argument('server', type=str, help='server program path')
    parser.add_argument('ciphersuite_list', type=str, help='path to file containing a list of cipherstuies (format per line: ciphersuite_ID ciphersutie_name ciphersuite_flags)')
    parser.add_argument('cli_bytes_start', type=int, help='number of bytes to send start value for client')
    parser.add_argument('cli_bytes_end', type=int, help='number of bytes to send end value for client')
    parser.add_argument('cli_bytes_step', type=int, help='number of bytes to send step value for client')
    parser.add_argument('srv_bytes_start', type=int, help='number of bytes to send start value for server')
    parser.add_argument('srv_bytes_end', type=int, help='number of bytes to send end value for server')
    parser.add_argument('srv_bytes_step', type=int, help='number of bytes to send step value for server')
    parser.add_argument('-o', '--out_dir', type=str, default='./', help='output directory for the callgrind files')
    parser.add_argument('-t', '--timeout', type=int, default=2, help='time to wait after starting the server before starting the client')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Enable verbose output')

    args = parser.parse_args()

    run(args.client,
        args.server,
        args.ciphersuite_list,
        args.cli_bytes_start,
        args.cli_bytes_end,
        args.cli_bytes_step,
        args.srv_bytes_start,
        args.srv_bytes_end,
        args.srv_bytes_step,
        args.out_dir,
        args.timeout,
        args.verbose)
