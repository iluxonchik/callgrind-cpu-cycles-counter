#!/usr/bin/env python3
import os
import time
import argparse
from multiprocessing.pool import ThreadPool

from ccc.ccc import parse_ciphersuite_list_from_file, run_server, run_client, get_cc_from_callgrind_file, show_plot

def build_key(sc_id, name, flags):
    flag_to_use = ''
    if flags.lower() != 'none':
        flag_to_use = f'[{flags}] '
    key = f'{flag_to_use}{sc_id}'
    return key


def run(client_path, server_path, ciphersuite_list_file_path,
        srv_funcs_to_prof, cli_funcs_to_prof, keep_callgrind_out,
        timeout, verbose=False):
    SERVER_CALLGRIND_OUT_FILE = 'callgrind.out.server.{}'
    CLIENT_CALLGRIND_OUT_FILE = 'callgrind.out.client.{}'
    # { 'sc_id': {'function_name', 'number_of_cycles'} }
    PROFILE_RESULTS_SRV = {}
    PROFILE_RESULTS_CLI = {}

    # User-defined args
    CLIENT_PATH = client_path
    SERVER_PATH = server_path
    CIPHERSUITE_LIST_PATH = ciphersuite_list_file_path
    SRV_FUNCTIONS_TO_PROFILE = srv_funcs_to_prof
    CLI_FUNCTIONS_TO_PROFILE = cli_funcs_to_prof
    TIMEOUT = timeout
    VERBOSE = verbose

    print('Running with configurations: ')
    print(f'\tClient Path: {CLIENT_PATH}')
    print(f'\tSever Path: {SERVER_PATH}')
    print(f'\tCiphesuite List Path: {CIPHERSUITE_LIST_PATH}')
    print(f'\tServer Funcs To Prof: {SRV_FUNCTIONS_TO_PROFILE}')
    print(f'\tClient Funcs To Prof: {CLI_FUNCTIONS_TO_PROFILE}')
    print(f'\tKeep Callgrind Output Files: {keep_callgrind_out}')
    print(f'\tTimeout: {TIMEOUT}')
    print(f'\tVerbose: {VERBOSE}')
    print('\n')

    print('Parsing ciphersuties...',end='')
    ciphersuites = parse_ciphersuite_list_from_file(CIPHERSUITE_LIST_PATH)
    num_cipheruites = len(ciphersuites)
    num_skipped_ciphersuites = 0
    num_procecessed_ciphersuites = 0
    num_sigttou = 0
    ciphersuite_names = []  # display names in graph
    print('ok')

    produced_callgrind_out_files = [] # we don't want to delete any callgrind files from previous runs

    for sc_id, name, flags in ciphersuites:
        """
        1. Start server in thread 1
        2. Start client in thread 2
        3. Make sure that server ret code == 0
            else - continue
        4. Make sure that server ret coce == 0
            else - continue
        5. Parse cycles for selected functions
        """
        pool = ThreadPool(processes=2)
        num_procecessed_ciphersuites += 1
        callgrind_out_srv = SERVER_CALLGRIND_OUT_FILE.format(sc_id)
        callgrind_out_cli = CLIENT_CALLGRIND_OUT_FILE.format(sc_id)

        print(f'--- Begin profiling for {sc_id} : {name} : {flags} [{num_procecessed_ciphersuites}/{num_cipheruites}] ---')

        print(f'\tStarting server... (Out file: {callgrind_out_srv})')

        async_result_srv = pool.apply_async(run_server, (SERVER_PATH, sc_id, callgrind_out_srv, verbose))

        print(f'\t\tWaiting {TIMEOUT} seconds for server to load...')
        time.sleep(TIMEOUT) # give the server time to start

        print(f'\tStarting client... (Out file: {callgrind_out_cli})')
        async_result_cli = pool.apply_async(run_client, (CLIENT_PATH, sc_id, callgrind_out_cli, verbose))

        srv_res = async_result_srv.get()
        cli_res = async_result_cli.get()
        produced_callgrind_out_files += [callgrind_out_cli, callgrind_out_srv]
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

        print('\tParsing CPU Cycles...')

        # 5. Parse the cycles for selected functions
        sc_key = build_key(sc_id, name, flags)
        #    5.1 Server
        time.sleep(TIMEOUT)
        print(f'\t\tWaiting {TIMEOUT} seconds for callgrind output to flush...')
        print('\t\tParsing server....')
        PROFILE_RESULTS_SRV[sc_key] = {}
        for function_name in SRV_FUNCTIONS_TO_PROFILE:
            num_cc = get_cc_from_callgrind_file(callgrind_out_srv, function_name)
            print(f'\t\t\t{function_name}: {num_cc}')
            PROFILE_RESULTS_SRV[sc_key][function_name] = num_cc

        #   5.2 Client
        print('\t\tParsing client...')
        PROFILE_RESULTS_CLI[sc_key] = {}
        for function_name in CLI_FUNCTIONS_TO_PROFILE:
            num_cc = get_cc_from_callgrind_file(callgrind_out_cli, function_name)
            print(f'\t\t\t{function_name}: {num_cc}')
            PROFILE_RESULTS_CLI[sc_key][function_name] = num_cc

        ciphersuite_names += [name]

        print(f'--- End profiling for {sc_id} : {name} : {flags} [{num_procecessed_ciphersuites}/{num_cipheruites}] ---\n')

    print('--- STATISTICS ---')
    print(f'\tTotal CipherSuites:{num_cipheruites}'
    f'\nMeasured: {num_cipheruites - num_skipped_ciphersuites}\n'
    f'Skipped: {num_skipped_ciphersuites}')
    print(f'Number of SIGTTOU signals: {num_sigttou}')

    if (num_sigttou > 0):
        print('[!!!] SIGTTOU singals detected! Make sure you\'re not compiling'
        '/linking with the "-pg" opiton (for gprof). You cannot use valgrind'
        ' and grpof together.')

    for func_name in SRV_FUNCTIONS_TO_PROFILE:
        labels = []
        values = []
        for key, value in PROFILE_RESULTS_SRV.items():
            labels.append(key)
            values.append(value[func_name])
        show_plot(values, labels, func_name, ciphersuite_names, 'Server')

    for func_name in CLI_FUNCTIONS_TO_PROFILE:
        labels = []
        values = []
        for key, value in PROFILE_RESULTS_CLI.items():
            labels.append(key)
            values.append(value[func_name])
        show_plot(values, labels, func_name, ciphersuite_names, 'Client')

    if not keep_callgrind_out:
        print('Removing callgrind output files...')
        for file_name in produced_callgrind_out_files:
            try:
                os.remove(file_name)
            except Exception:
                print(f'\t[!!!] Could not delete f{file_name}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run mbedTLS server and client program and collect profiling metrics for a list of ciphersuties.')
    parser.add_argument('client', type=str, help='client program path')
    parser.add_argument('server', type=str, help='server program path')
    parser.add_argument('ciphersuite_list', type=str, help='path to file containing a list of cipherstuies (format per line: ciphersuite_ID ciphersutie_name ciphersuite_flags)')
    parser.add_argument('--sf', nargs='*', help='name of server functions to profile')
    parser.add_argument('--cf', nargs='*', help='name of client functions to profile')
    parser.add_argument('-k', '--keep-callgrind-output', action='store_true', default=False, help='Keep the output callgrind files after the program has finished running')
    parser.add_argument('-t', '--timeout', type=int, default=2, help='time to wait after starting the server before starting the client')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Enable verbose output')

    args = parser.parse_args()

    run(args.client, args.server, args.ciphersuite_list, args.sf, args.cf,
        args.keep_callgrind_output, args.timeout, args.verbose)
