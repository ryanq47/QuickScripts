import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, wait
import time

error_block = "[!]"
operation_block = "[*]"


'''
Little decorator note (still a newer concept to me), instead of running the function that the @ is above, it 
tells python to run the @function instead, and calls the function under the decorator in the process

'''
def execution_time(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"Execution time: {execution_time:.4f} seconds")
        return result
    return wrapper

class CLASS:
    def __init__(self, ARGS):
        if not self._valuecheck(ARGS):
            exit()
        pass

    def __str__(self):
        return f"=== Details ==="


    def _valuecheck(self):
        '''
        This method is a double check that items are the right types/values. if running as a one off, argparse checks as well.
        This is mainly for bulletproofing/making it apparent where you screwed up.
        '''
        #self.VAR = str


        if not isinstance(VAR, str):
            print("{} target parameter is the incorrect type: {}, {}. Expected a string.".format(error_block, VAR, type(VAR)))
            return False
        
        return True



    


if __name__ == "__main__":
    '''Parser is down here for one-off runs, as this script can be imported & used in other pyprojects'''
    parser = argparse.ArgumentParser(
                        prog='qs-portscan',
                        description='The QuickScripts portscanner. No non-standard dependencies required',
                        epilog='-- Designed by ryanq.47 --')

    parser.add_argument('-t', '--target', help="The target you wish to scan. Can be an IP, FQDN, or hostname. Example: 'qs-portscan -t 192.168.0.1'", required=True) 
    args = parser.parse_args()

    # display -h/help if no flags are supplied
    if not any(vars(args).values()):
        parser.print_help()
        # the exit makes sure the class instances don't get created/cause any errors with no values
        exit()

    scanner = CLASS(
    )

    # Logic tree
    if args.debug:
        print(scanner)


    if args.method == "telnet":
        if not args.singleprocess:
            scanner.telnet_multiprocess_scan()
        else:
            scanner.telnet_scan()

    elif args.method == "socket":
        if not args.singleprocess:
            scanner.socket_multiprocess_scan()
        else:
            scanner.socket_scan()
