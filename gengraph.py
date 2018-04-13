#!/usr/bin/env python3
import os
from os import listdir
from os.path import isfile, join
import re
import argparse
from collections import OrderedDict, defaultdict
from ccc.ccc import get_cc_from_callgrind_file

def parse_ciphersuite_names_from_file(ciphers_file_path):
    CIPHER_ID_NAME_REGEX = r'(?P<id>\d+) (?P<name>[^ ]*?)( |$|\r?\n)'
    pattern = re.compile(CIPHER_ID_NAME_REGEX)
    ciphersuite_name = OrderedDict()

    with open(ciphers_file_path, 'r') as ciphers_file:
        lines = ciphers_file.readlines()

        print(f'{ciphers_file_path} has {len(lines)} lines')

        for line in lines:
            if line is os.linesep:
                continue
            res = pattern.search(line)
            id, name = int(res.group('id')), res.group('name')
            ciphersuite_name[id] = name

    return ciphersuite_name

def parse_callgrind_cli_srv_file_names(path):
    CLI_FILE_REGEX = r'.*?callgrind\.out\.client\.(?P<cipher_id>\d+)'
    SRV_FILE_REGEX = r'.*?callgrind\.out\.server\.(?P<cipher_id>\d+)'

    cli_pattern = re.compile(CLI_FILE_REGEX)
    srv_pattern = re.compile(SRV_FILE_REGEX)

    cli_files = {}
    srv_files = {}

    all_files = [join(path, f) for f in listdir(path) if isfile(join(path, f))]

    for file_name in all_files:
        res = cli_pattern.search(file_name)

        if res is not None:
            cipher_id = int(res.group('cipher_id'))
            cli_files[cipher_id] = file_name
            continue

        res = srv_pattern.search(file_name)

        if res is not None:
            cipher_id = int(res.group('cipher_id'))
            srv_files[cipher_id] = file_name

    return cli_files, srv_files

def parse_callgrind_cpu_cycles_from_files(funcs, cipher_id_file, entity):
    profiling = defaultdict(dict) # {function_name : {ciphersuite_id : num_cycles}}
    num_funcs = len(funcs)
    funcs_parsed = 0

    for func in funcs:
        funcs_parsed = 1
        print(f'Parsing for {entity} {func} {funcs_parsed}/{num_funcs}]...')

        for cipher_id, file_name in cipher_id_file.items():
            print(f'\tparsing for ciphersuite {cipher_id}...')
            num_cycles = get_cc_from_callgrind_file(file_name, func)
            profiling[func][cipher_id] = num_cycles

            print(f'\t\t num cycles: {num_cycles}')

    return profiling

def run(ciphers_file_path, path, cli_funcs, srv_funcs):
    ciphersuite_name = parse_ciphersuite_names_from_file(ciphers_file_path)
    ciphersuite_order = ciphersuite_name.keys()  # follow the ordre of the file

    cipher_id_file_cli, cipher_id_file_srv = parse_callgrind_cli_srv_file_names(path)

    total_ciphersuites_requested = len(ciphersuite_order)
    cli_ciphersuites_skipped = 0
    cli_ciphersuties_evaluated = 0

    # {function_name : {ciphersuite_id : num_cycles}}
    CLI_FUNCS_PROFILING = parse_callgrind_cpu_cycles_from_files(cli_funcs, cipher_id_file_cli, 'client')
    SRV_FUNCS_PROFILING = parse_callgrind_cpu_cycles_from_files(srv_funcs, cipher_id_file_srv, 'server')

    # TODO: graph results



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate graph from existing callgrind ouput files.'
                                                  'The file name format file must be: callgrind.out.[client||server].<ciphersuite_id>.'
                                                  'If you need to change the output graph, edit the code directly.')
    parser.add_argument('ciphers', type=str, help='file containing a list of ciphersuite ids and their respective names.'
                                                   'Each line of the file must have the format: <ciphersuite_id> <ciphersuite_name> [arbitrary_info, ...]')
    parser.add_argument('-p', '--path', type=str, default='./', help='path of the callgrind output files')
    parser.add_argument('--sf', nargs='*', default=[], help='name of server functions to profile')
    parser.add_argument('--cf', nargs='*', default=[], help='name of client functions to profile')

    args = parser.parse_args()

    if args.path[-1] is not '/':
        args.path += '/'


    run(args.ciphers, args.path, args.cf, args.sf)
