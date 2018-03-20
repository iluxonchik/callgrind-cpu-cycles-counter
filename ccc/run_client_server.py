from multiprocessing.pool import ThreadPool
from .ccc import parse_ciphersuite_list_from_file, run_server, run_client
from multiprocessing.pool import ThreadPool
import time

def run():
    TIMEOUT = 2
    CLIENT_PATH = None
    SERVER_PATH = None
    CIPHERSUITE_LIST_PATH = None
    FUNCTIONS_TO_PROFILE = []

    # { 'sc_id': [{'function_name', 'number_of_cycles'}] }
    PROFILE_RESULTS = {}

    ciphersuites = parse_ciphersuite_list_from_file(CIPHERSUITE_LIST_PATH)
    num_cipheruites = ciphersuites
    num_skipped_ciphersuites = 0

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
        
        print('Starting server...')
        async_result_srv = pool.apply_async(run_server, (sc_id,))
        print(f'\t,Waiting {TIMEOUT} seconds for server to load...')
        time.sleep(TIMEOUT) # give the server time to start
        print('Starting client...')
        async_result_cli = pool.apply_async(run_client, (sc_id,))

        srv_res = async_result_srv.get()
        cli_res = async_result_cli.get()

        if srv_res != 0 or cli_res != 0:
            print(f'[!!!] Non-zero return code from ciphersuite {sc_id} {name} {flags}')
            print('\tSkipping to next ciphersuite...')
            num_skipped_ciphersuites += 1
            continue

        pass

        print('--- STATISTICS ---')
        print(f'\tTotal CipherSuites:{num_cipheruites}'
        '\nMeasured: {num_cipheruites - num_skipped_ciphersuites}\n'
        'Skipped: {num_skipped_ciphersuites}')

if __name__ == '__main__':
    run()
