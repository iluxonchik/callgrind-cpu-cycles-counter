import matplotlib.pyplot as plt; plt.rcdefaults()
import subprocess
import re

def parse_ciphersuite_list_from_file(file_path):
    """Parses a list of ciphersuites from a file.

    Format of file:
    CIPHERSUITE_ID[:id] CIPHERSUITE_NAME[:str] TAG[:str]
    """
    with open(file_path, 'r') as sc_file:
        ciphersuites = [line.strip().split(' ') for line in sc_file.readlines()]

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

def run_server(server_path, ciphersuite_id, out_file, show_output=True):
    args = ['valgrind', '--tool=callgrind', f'--callgrind-out-file={out_file}',
            '--quiet', server_path, str(ciphersuite_id)]

    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

    return_code = p.returncode

    if (show_output):
        print(f'\n\nServer OUT:\n{stdout}')
        print(f'\n\nServer ERR:\n{stderr}')
    return return_code

def run_client(client_path, ciphersuite_id, out_file, show_output=True):
    args = ['valgrind', '--tool=callgrind', f'--callgrind-out-file={out_file}',
            '--quiet', client_path, str(ciphersuite_id)]

    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

    return_code = p.returncode

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
