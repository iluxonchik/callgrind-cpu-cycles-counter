#!/usr/bin/env python3
import os
import json
from os import listdir
from os.path import isfile, join
import matplotlib.pyplot as plt; plt.rcdefaults()
import matplotlib
import re
import argparse
from collections import OrderedDict, defaultdict
from ccc.ccc import get_cc_from_callgrind_file
from math import log

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
    CLI_FILE_REGEX = r'.*?client\.callgrind\.out\.(?P<cipher_id>\d+).*?'
    SRV_FILE_REGEX = r'.*?server\.callgrind\.out\.(?P<cipher_id>\d+).*?'

    cli_pattern = re.compile(CLI_FILE_REGEX)
    srv_pattern = re.compile(SRV_FILE_REGEX)

    cli_files = {}
    srv_files = {}

    # checking for membership in sets is O(1) [O(n) worst case]
    cli_included_ciphers = set()
    srv_included_ciphers = set()

    all_files = [join(path, f) for f in listdir(path) if isfile(join(path, f))]
    
    for file_name in all_files:
        res = cli_pattern.search(file_name)

        if res is not None:
            cipher_id = int(res.group('cipher_id'))
            if cipher_id not in cli_included_ciphers:
                cli_files[cipher_id] = file_name
                cli_included_ciphers.add(cipher_id)
                print(f'Using {file_name}')
            continue

        res = srv_pattern.search(file_name)

        if res is not None:
            cipher_id = int(res.group('cipher_id'))
            if cipher_id not in srv_included_ciphers:
                srv_files[cipher_id] = file_name
                srv_included_ciphers.add(cipher_id)
            continue
        print(f'[!!!] Invalid filename found {file_name}. Ignoring...')

    return cli_files, srv_files

def parse_callgrind_cli_srv_file_names_2(path):
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
            cipher_id = int(cipher_id)
            num_cycles = get_cc_from_callgrind_file(file_name, func)
            profiling[func][cipher_id] = num_cycles

            print(f'\t\t num cycles: {num_cycles}')

    return profiling

def dump_json_ids(cli_profiling, srv_profiling, file_name):
    obj = {'client': cli_profiling, 'server': srv_profiling}
    res = json.dumps(obj)
    with open(file_name, 'w') as out_file:
        out_file.write(res)

def print_total_ciphers_profiled_stats(cli_prof, srv_prof, cli_funcs, srv_funcs):
    print('Total client ciphersuites profiled: ', end='')
    num_cli_ciphers = 0
    if len(cli_funcs) > 0:
        first_func = cli_funcs[0]
        num_cli_ciphers = len(cli_prof[first_func])
    print(num_cli_ciphers)

    print('Total server ciphersuites profiled: ', end='')
    num_srv_ciphers = 0
    if len(srv_funcs) > 0:
        first_func = srv_funcs[0]
        num_srv_ciphers = len(cli_prof[first_func])
    print(num_srv_ciphers)

def dump_json_ids_if_needed(json_ids_file, cli_prof, srv_prof):
    if json_ids_file is not None:
            print(f'Dumping profiling resutls to {json_ids_file}...')
            dump_json_ids(cli_prof, srv_prof, json_ids_file)

def plot_from_profiling(func_names, profiling, ciphersuites_ids_to_graph, ciphersuite_id_to_name, entity):
    for func_name in func_names:
        func_profiling = profiling[func_name]

        values = []
        labels = []
        ciphersuite_names = []
        num_ciphersuites_graphed = 0
        for ciphersuite_id in ciphersuites_ids_to_graph:
            profiling_res = func_profiling.get(ciphersuite_id, None)
            if profiling_res is None:
                continue
            values.append(profiling_res)
            labels.append(ciphersuite_id)
            ciphersuite_names.append(ciphersuite_id_to_name[ciphersuite_id])

        total_ciphers = len(values)
        suffix = f'{entity} (Total: {total_ciphers})'
        show_plot(values, labels, func_name, ciphersuite_names, suffix)

def show_plot(values, labels, func_name, ciphersuite_names, suffix):

    font = {'family' : 'normal',
        'size'   : 7}

    matplotlib.rc('font', **font)

    fig, ax = plt.subplots()
    ax.get_yaxis().get_major_formatter().set_scientific(False)
    ax.get_xaxis().set_visible(False)
    y_pos = range(len(labels))
    bar1 = plt.bar(y_pos, values, align='edge', alpha=0.5)
    plt.xticks(y_pos, labels, rotation='vertical')
    plt.yticks()
    plt.ylabel(f'Number Of CPU Instructions')
    plt.title(f'Handshake Cost For {suffix}')
    plt.margins(0)

    max_val = max(values)
    label_pos = max_val/2 + max_val/3

    MAC_REGEX = r'WITH-(?P<mac>.*)'
    pattern = re.compile(MAC_REGEX)

    new_ciphersuite_names = []
    for ciphersuite_name in ciphersuite_names:
        res = pattern.search(ciphersuite_name)
        new_ciphersuite_names.append(res.group('mac'))

    for i, v in enumerate(values):
        if v < 80000000:
            v = 6000000 * log(v)
        else:
            v = v - 9000000
        ax.text(i, v, f'{new_ciphersuite_names[i]}', rotation='vertical')

    plt.show()

def run(ciphers_file_path, path, cli_funcs, srv_funcs, json_ids_file):
    ciphersuite_name = parse_ciphersuite_names_from_file(ciphers_file_path)
    ciphersuite_order = ciphersuite_name.keys()  # follow the ordre of the file

    cipher_id_file_cli, cipher_id_file_srv = parse_callgrind_cli_srv_file_names(path)

    total_ciphersuites_requested = len(ciphersuite_order)
    cli_ciphersuites_skipped = 0
    cli_ciphersuties_evaluated = 0

    # {function_name : {ciphersuite_id : num_cycles}}
    CLI_FUNCS_PROFILING = parse_callgrind_cpu_cycles_from_files(cli_funcs, cipher_id_file_cli, 'client')
    SRV_FUNCS_PROFILING = parse_callgrind_cpu_cycles_from_files(srv_funcs, cipher_id_file_srv, 'server')

    print_total_ciphers_profiled_stats(CLI_FUNCS_PROFILING, SRV_FUNCS_PROFILING, cli_funcs, srv_funcs)
    dump_json_ids_if_needed(json_ids_file, CLI_FUNCS_PROFILING, SRV_FUNCS_PROFILING)

    plot_from_profiling(cli_funcs, CLI_FUNCS_PROFILING, ciphersuite_order, ciphersuite_name, 'Client')
    plot_from_profiling(srv_funcs, SRV_FUNCS_PROFILING, ciphersuite_order, ciphersuite_name, 'Server')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate graph from existing callgrind ouput files.'
                                                  'The file name format file must be: callgrind.out.[client||server].<ciphersuite_id>.'
                                                  'If you need to change the output graph, edit the code directly.')
    parser.add_argument('ciphers', type=str, help='file containing a list of ciphersuite ids and their respective names.'
                                                   'Each line of the file must have the format: <ciphersuite_id> <ciphersuite_name> [arbitrary_info, ...]')
    parser.add_argument('-p', '--path', type=str, default='./', help='path of the callgrind output files')
    parser.add_argument('--sf', nargs='*', default=[], help='name of server functions to profile')
    parser.add_argument('--cf', nargs='*', default=[], help='name of client functions to profile')
    parser.add_argument('--json-ids', type=str, default=None, help='output JSON file with the profiling results. The keys of the ciphersuites are its ids')
    #TODO: json-cipher-names

    args = parser.parse_args()

    if args.path[-1] is not '/':
        args.path += '/'


    run(args.ciphers, args.path, args.cf, args.sf, args.json_ids)
