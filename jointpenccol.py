#!/usr/bin/env python3
import re
import os
import sys
import json
import argparse
import statistics
from utils.colors import print_green, print_red, print_yellow
from os import listdir
from pathlib import Path
from os.path import isfile, join
from ccc.ccc import get_cc_from_callgrind_file
from utils.utils import convert_dict_keys_to_str
from collections import OrderedDict, defaultdict

def verbose_print(msg, verbose, end='\n'):
    if verbose:
        print(msg, end=end)

def parse_filenames_list(path):
    CALLGRIND_FILE_REGEX = (fr'(?P<prefix>(client|server))\.callgrind\.out\.(?P<cipher_id>\d+)\.'
                       '(?P<num_bytes_sent>\d+)\.(?P<num_bytes_received>\d+)')
    pattern = re.compile(CALLGRIND_FILE_REGEX)
    filenames = []

    all_files = [join(path, f) for f in listdir(path) if isfile(join(path, f))]

    for file_name in all_files:
        res = pattern.search(file_name)

        if res is not None:
            filenames.append(file_name)
        else:
            print(f'[!!!] No pattern found for file name {file_name}')

    return filenames


def write_dict_as_json_to_file(raw_dict, file_name):
    json_dict = convert_dict_keys_to_str(raw_dict)
    res = json.dumps(json_dict)
    with open(file_name, 'w') as out_file:
        out_file.write(res)

def parse_profilings(path, funcs, verbose=False):
    minimum = {}
    maximum = {}

    profilings = defaultdict(list)

    files_in_dir = parse_filenames_list(path)

    num_files_in_dir = len(files_in_dir)
    num_files_parsed = 0

    print(f'Begin parsing metrics | Total files: {num_files_in_dir}')

    for funcname in funcs:
        minimum[funcname] = (sys.maxsize, None)
        maximum[funcname] = (0, None)
        for filename in files_in_dir:
            num_files_parsed += 1
            num_instr = get_cc_from_callgrind_file(filename, funcname)
            num_instr = int(num_instr)
            profilings[funcname].append(num_instr)

            if num_instr < minimum[funcname][0]:
                minimum[funcname] = (num_instr, filename)
            if num_instr > maximum[funcname][0]:
                maximum[funcname] = (num_instr, filename)

            if verbose:
                print(f'{funcname} from file {filename} [{num_files_parsed}/{num_files_in_dir}]')
                print_green(f'\t{num_instr}')
            
    return profilings, minimum, maximum

def average_profilings(profilings):
    res = defaultdict(dict)
    for func_name, values in profilings.items():
        avg = statistics.mean(values)
        stdev = statistics.stdev(values)
        res[func_name] = {
            'avg': avg,
            'stdev': stdev,
        }
    return res

def run(path, funcs, out_file_name, verbose=False):
    path = Path(path)

    if not path.is_dir():
        raise Exception('Path argument must point to a directory')

    profilings, minimum, maximum = parse_profilings(path, funcs, verbose)

    averaged_profilings = average_profilings(profilings)

    write_dict_as_json_to_file(averaged_profilings, out_file_name)

    for key, value in minimum.items():
        print_green(f'{key} minimum:\n\t{value[0]} | {value[1]}')
    
    for key, value in maximum.items():
        print_green(f'{key} maximum:\n\t{value[0]} | {value[1]}')



if __name__ == '__main__':

    parser = argparse.ArgumentParser(description= 'Profiled Encryption Metrics Collector: Joint Version\n'
    'Collect the joint profiled encryption metrics and save data as JSON.\n'
    'Here is how the tool works:\n'
    '\t1. Collect the number of CPU cycles from all callgrind outs in path for each function\n'
    '\t2. Compute the average and the standard deviation and output it in JSON\n'

    'The tool assumes that the files have the following naming:\n'
    '\t[client|server].callgrind.out.<ciphersuite_id>.<num_bytes_sent>.<num_bytes_received>')

    
    parser.add_argument('path', type=str, default='./', help='path of the callgrind output files')
    parser.add_argument('functions', nargs='*', default=[], help='name of server functions to profile')
    parser.add_argument('output', type=str, help='output path of the JSON file with results')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='enable verbose output')

    args = parser.parse_args()
    run(args.path, args.functions, args.output, args.verbose)
