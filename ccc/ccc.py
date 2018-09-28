import matplotlib.pyplot as plt; plt.rcdefaults()
import subprocess
import re
from utils.colors import print_green, print_red, print_yellow

# warning message from cachegrind that L3 cache will be used as LL cache
CACHEGRIND_L3_MSG = 'warning: L3 cache found, using its data for the LL simulation'

def _filter_cachegrind_warnings(return_code, stderr, entity, show_output):
    strerr = stderr.decode('utf-8')
    if strerr.count('\n') > 1:
        return return_code, stderr
    
    if CACHEGRIND_L3_MSG in strerr:
        if(show_output):
            print_yellow(f'\t{entity} ERR out: {stderr}')
            print_yellow('\t\tManually setting return code to 0 and error message to \'\'...')
        return_code = 0
        stderr = b''
    return return_code, stderr

def _get_client_return_code(return_code, stdout, show_output):
    CLIENT_OK_LAST_MSG = 'Last error was: -30848 - SSL - The peer notified us that the connection is going to be closed'
    strout = stdout.decode('utf-8')
    strout = strout.strip('\n')
    last_out = strout.split('\n')[-1]
    if last_out == CLIENT_OK_LAST_MSG:
        return_code = 0
        print_yellow(f'\tClient\'s last message was the expected one. Setting return code to 0...')
    else:
        return_code = -1
        print_red(f'\tClient\'s last message was an unexpected one. Setting return code to -1...')
        print_red(f'\tExpected: {CLIENT_OK_LAST_MSG}')
        print_red(f'\nObtained: {last_out}')
    return return_code

def _get_server_return_code(return_code, stdout, show_output):
    SERVER_OK_LAST_MSG = 'Terminating server...'
    strout = stdout.decode('utf-8')
    strout = strout.strip('\n')
    last_out = strout.split('\n')[-1]
    if last_out == SERVER_OK_LAST_MSG:
        return_code = 0
        print_yellow(f'\tServer\'s last message was the expected one. Setting return code to 0...')
    else:
        return_code = -1
        print_red(f'\tServer\'s last message was an unexpected one. Setting return code to -1...')
        print_red(f'\tExpected: {SERVER_OK_LAST_MSG}')
        print_red(f'\nObtained: {last_out}')
    return return_code

def parse_ciphersuite_list_from_file(file_path):
    """Parses a list of ciphersuites from a file.

    Format of file:
    CIPHERSUITE_ID[:id] CIPHERSUITE_NAME[:str] TAG[:str]
    """
    with open(file_path, 'r') as sc_file:
        ciphersuites = [line.strip().split(' ') for line in sc_file.readlines()]

    ciphersuites = [ciphersuite for ciphersuite in ciphersuites if len(ciphersuite) > 1]

    for i in range(0, len(ciphersuites)):
        ciphersuite = ciphersuites[i]
        if len(ciphersuite) < 3:
            ciphersuite.append('')
        elif len(ciphersuite) > 3:
            ciphersuites[i] = ciphersuite[0:2] + [' '.join(ciphersuite[2:])]
    return ciphersuites

def get_cc_from_callgrind_output(content, func_name):
    FUNC_ID_REGEX = fr'fn=\((?P<func_id>\d+)\) {func_name}\n'
    pattern = re.compile(FUNC_ID_REGEX)
    res = pattern.search(content)

    func_id = res.group('func_id')
    REGEX = fr'cfn=\({func_id}\).*?\ncalls=.+\n.+? (?P<cpu_cycles>\d+)'
    pattern = re.compile(REGEX)
    res = pattern.search(content)
    return int(res.group('cpu_cycles'))

def get_cc_from_callgrind_file(callgrind_file, func_name):
    """Gets the number of CPU cycles for a function from a callgrind file."""
    with open(callgrind_file, 'r') as f:
        file_content = f.read()

    return get_cc_from_callgrind_output(file_content, func_name)

def run_server(server_path, ciphersuite_id, out_file, show_output=True,
               num_bytes_to_send=None):
    srv_args = [server_path, str(ciphersuite_id)]

    if num_bytes_to_send:
        srv_args.append(str(num_bytes_to_send))

    args = ['valgrind', '--tool=callgrind', '--branch-sim=yes', '--cache-sim=yes', f'--callgrind-out-file={out_file}',
            '--quiet'] + srv_args

    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

    return_code = p.returncode
    # hackfix | Do a proper when/if time is not so tight
    # NOTE: this renders the sigttou signal count useless
    return_code = _get_server_return_code(return_code, stdout, show_output)

    if (show_output):
        print(f'\n\nServer OUT:\n{stdout}')
        print(f'\n\nServer ERR:\n{stderr}')
    return return_code

def run_client(client_path, ciphersuite_id, out_file, show_output=True,
                num_bytes_to_send=None):

    cli_args = [client_path, str(ciphersuite_id)]

    if num_bytes_to_send:
        cli_args.append(str(num_bytes_to_send))

    args = ['valgrind', '--tool=callgrind', '--branch-sim=yes', '--cache-sim=yes', f'--callgrind-out-file={out_file}',
            '--quiet'] + cli_args

    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

    return_code = p.returncode
    # hackfix | Do a proper when/if time is not so tight
    # NOTE: this renders the sigttou signal count useless
    return_code = _get_client_return_code(return_code, stdout, show_output)
    
    if (show_output):
        print(f'\n\nClient OUT:\n{stdout}')
        print(f'\n\nClient ERR:\n{stderr}')
    return return_code


def show_plot(values, labels, func_name, ciphersuite_names, suffix):
    fig, ax = plt.subplots()
    ax.get_yaxis().get_major_formatter().set_scientific(False)
    y_pos = range(len(labels))
    plt.bar(y_pos, values, align='center', alpha=0.5)
    plt.xticks(y_pos, labels, rotation='vertical')
    plt.yticks()
    plt.ylabel(f'CPU Cycles For {func_name}')
    plt.title(f'Ciphersuite Comparison For {suffix}')

    max_val = max(values)
    label_pos = max_val/2 + max_val/3


    for i, v in enumerate(values):
        ax.text(i - 0.25, label_pos, f'{v} | {ciphersuite_names[i]}', rotation='vertical')

    #plt.tight_layout()

    plt.show()
