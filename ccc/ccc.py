import subprocess
import re

def parse_ciphersuite_list_from_file(file_path):
    """Parses a list of ciphersuites from a file.

    Format of file:
    CIPHERSUITE_ID[:id] CIPHERSUITE_NAME[:str] TAG[:str]
    """
    with open(file_path, 'r') as sc_file:
        ciphersuites = [line for line in sc_file.split(' ')]

    return ciphersuites

def get_cc_from_callgrind_file(callgrind_file, func_name):
    """Gets the number of CPU cycles for a function from a callgrind file."""
    with open(callgrind_file, 'r') as f:
        file_content = f.read()

    REGEX = fr'{func_name}\n.+\n\* (?P<cpu_cycles>\d+)'
    pattern = re.compile(REGEX)
    res = pattern.search(file_content)
    return int(res.group('cpu_cycles'))


def run_server(ciphersuite_id):
    args = ['../../mbed-tls-playground/mbedtls-2.7.0/playground/server_cc', str(ciphersuite_id)]
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

    print(f'\n\nServer OUT:\n{stdout}')
    print(f'\n\nServer ERR:\n{stderr}')
    return p.returncode

def run_client(ciphersuite_id):
    args = ['../../mbed-tls-playground/mbedtls-2.7.0/playground/client_cc', str(ciphersuite_id)]
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

    print(f'\n\nClient OUT:\n{stdout}')
    print(f'\n\nClient ERR:\n{stderr}')
    return p.returncode
