from pathlib import Path
import argparse
import json

def parse_ciphers_joint(res):
    client = res['client']

    print(f'Client:')
    for func_name, func_value in client.items():
        print(f'\t{func_name}:')
        for cipher_name, cipher_value in func_value.items():
            avg = round(cipher_value['avg'])
            stdev = round(cipher_value['stdev'])
            print(f'\t\t{cipher_name}:')
            print(f'\t\t\t{avg} ({stdev})')
    
    server = res['server']

    print(f'\nServer:')
    for func_name, func_value in server.items():
        print(f'\t{func_name}:')
        for cipher_name, cipher_value in func_value.items():
            avg = round(cipher_value['avg'])
            stdev = round(cipher_value['stdev'])
            print(f'\t\t{cipher_name}:')
            print(f'\t\t\t{avg} ({stdev})')



def parse_func_joint(res):
    for func_name, value in res.items():
        avg = round(value['avg'])
        stdev = round(value['stdev'])
        print(f'{func_name}:\n\t{avg} ({stdev})')

def run(path):
    path = Path(path)

    with open(str(path), 'r') as f:
        res = json.load(f)

    if 'client' in res.keys():
        parse_ciphers_joint(res)
    else:
        parse_func_joint(res)




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Convert JSON joint metrics to a oneliner.')
    parser.add_argument('path', type=str, help='Path to JSON results file')

    args = parser.parse_args()

    run(args.path)