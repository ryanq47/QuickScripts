#!/usr/bin/python
import argparse
import time
import re
import random
import string


error_block = "[!]" # presents option to contiue
operation_block = "[*]" # standard operation
unrecov_error_block = "[X]" # unrecoverable, no option to continue
input_block = "[>]" # for getting  user input


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

class PsObs:
    def __init__(self):
        #if not self._valuecheck(ARGS):
        #    exit()
        pass

    def __str__(self):
        return "=== Details ==="


    def _valuecheck(self):
        '''
        This method is a double check that items are the right types/values. if running as a one off, argparse checks as well.
        This is mainly for bulletproofing/making it apparent where you screwed up.
        '''
        #self.VAR = str


        if not isinstance(VAR, str):
            print("{} target parameter is the incorrect type: {}, {}. Expected a string.".format(error_block, VAR, type(VAR)))
            if not QsUtils.continue_anyways():
                return False
        
        return True


    def variable_name_scramble(self):
        '''
        takes  current txt from  file, finds all items that start with '$'. Creates a set of them so there's only one of  each.
        for i in list_of_vars:
            new_name = random_name(alphabet)
            replace(i, new_name)
        
        
        '''

        text = "$var"

        letters = string.ascii_letters

        #list_of_regex_vars = ["$WinProc","$DllLoader"]
        # regex_vars_match = regexresults #find all that start with $, an d end with a = OR a space, use regex :(
            #[$]\w+\b -- starts with $, any valid word characters, stops when those characters end (word boundary)
            # use  findall  to return a list
        pattern = r'[$]\w+\b'
        list_of_regex_vars = results = re.findall(pattern=pattern, string=text)
        print(list_of_regex_vars)
        
        list_of_clean_vars = set(list_of_regex_vars)

        for variable in list_of_clean_vars:
            obs_variable_name = ''.join(random.choice(letters) for i in range(10))
            print("{} is now {}".format(variable, obs_variable_name))

            ##need to make sure that this does't reset textfile each loop
            #textfile.replace(variable, obs_variable_name)

    def base_64_encode():
        pass # put me in an encoding class?

class QsUtils:
    '''
    A static class used for tools accross the QS scripts
    '''

    @staticmethod
    def send_to(dest):
        '''
        Send data to a server/other PC. Handy for getting data out
        '''
        try:
            ip, port = dest.split(':')
        
        except Exception as e:
            print("{} Error occured when getting IP & Port for sending data: {}".format(error_block, e))

        # the algorithms send func

    @staticmethod
    def continue_anyways():
        '''
        A little function that propmts the user to continue anyway. Returns true/false. 
        '''
        if input("Enter 'y' to continue execution (high chance of failure), or any other key to exit: ") == "y":
            return True
        else:
            return False
    @staticmethod
    def calculate_host_ips(subnet):
        try:
            import ipaddress
        except Exception as e:
            print("{} 'ipaddress' module could not be imported, python 3.3 or higher is needed: {}".format(error_block, e))
            return ""
            #exit? not sure
        
        network = ipaddress.ip_network(subnet, strict=False)
        host_ips = [str(ip) for ip in network.hosts()]
        return host_ips


if __name__ == "__main__":
    '''
    parser = argparse.ArgumentParser(
                        prog='qs-portscan',
                        description='The QuickScripts portscanner. No non-standard dependencies required',
                        epilog='-- Designed by ryanq.47 --')

    parser.add_argument('-t', '--target', help="The target you wish to scan. Can be an IP, FQDN, or hostname. Example: 'qs-portscan -t 192.168.0.1'", required=True) 
    parser.add_argument('-d', '--debug', help="Print debug information", action="store_true") 

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
            scanner.socket_scan()'''
        
    z = PsObs()

    z.variable_name_scramble()
