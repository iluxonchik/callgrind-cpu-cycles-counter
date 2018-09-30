import argparse
import glob
import shutil
from utils.colors import print_green, print_yellow
from pathlib import Path

def create_output_directory_if_needed(out_dir):
    p = Path(out_dir)
    if not p.exists():
        print_yellow(f'\t[!] Creating {out_dir} since it did not exit.\n')
        p.mkdir(parents=True)

def parse_cipher_ids_for_alg(ciphers_path, algorithm):
    res = []

    with open(ciphers_path, 'r') as ciphers_f:
        all_lines = [line for line in ciphers_f.readlines() if line.strip()]
        
    for line in all_lines:
        line_sep = line.split(' ')
        cipher_id, cipher_name = line_sep[0], line_sep[1]
        spaced_cipher_name = f'{cipher_name} ' # allows to filter for SHA funcs
        if algorithm in spaced_cipher_name:
            res.append(cipher_id)
    
    print_green(f'{len(res)} matching ciphers found!') 

    return res


def run(source, destination, algorithm):
    algorithm = algorithm.upper()
    cipher_ids_for_alg = parse_cipher_ids_for_alg('./ordered_ciphers.txt', algorithm)
    create_output_directory_if_needed(destination)
    num_matching_files = 0

    source_path = Path(source)
    for cipher_id in cipher_ids_for_alg:
        pattern = rf'*.callgrind.out.{cipher_id}.*'
        file_path = source_path.joinpath(pattern)
        file_path = str(file_path)
        for f in glob.glob(file_path):
           shutil.copy(f, destination)
           num_matching_files += 1

    print_green('Done')
    print_green(f'\tTotal files copied: {num_matching_files}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description= 'Copy Callgrind Files With RSA/ECSDA Algorithm\n'
    'The tool expects ordered_ciphers.txt file to exist in its path.\n'
    'The tool expets the following callgrind file naming format:\n'
    '\t[client|server].callgrind.out.<ciphersuite_id>.<num_bytes_sent>.<num_bytes_received>')
    parser.add_argument('source', type=str, help='path containing source callgrind files')
    parser.add_argument('destination', type=str, help='destintaion where to copy the files')
    parser.add_argument('algorithm', type=str, help='algorithm to copy (RSA or ECDSA)')

    args = parser.parse_args()
    run(args.source, args.destination, args.algorithm)