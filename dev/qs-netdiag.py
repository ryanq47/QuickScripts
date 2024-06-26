#!/usr/bin/python
import socket
import argparse
#from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, wait
import time
from scapy.all import *
## makes the warnings quiet
logging.getLogger("scapy").setLevel(logging.CRITICAL)

error_block = "[!]" # presents option to contiue
operation_block = "[*]" # standard operation
unrecov_error_block = "[X]" # unrecoverable, no option to continue
input_block = "[>]" # for getting  user input

#bandaid fix for decorator debug print
qs_debug = False
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
        ## wasn't sure how to pass a var here yet, just using a glbal debug var
        print(f"\t{execution_time:.4f} seconds") if qs_debug else None
        return result
    return wrapper

class NetDiag:
    def __init__(self, debug):
        '''if not self._valuecheck(ARGS):
            exit()'''
        
        self.debug = debug
        
        self.local_ip = "EMPTY"
        self.hostname = "EMPTY"
        self.gateway = "EMPTY"
        
        #IP's to ping. Usually gateway, loopback, and any others
        self.icmp_ip = ["192.168.0.1", "127.0.0.1", self.gateway, self.local_ip]
        
        ## domains to look up
        # 3 seperate domains, note, netflix may be blocked
        self.dns_domain = ["google.com","netflix.com","microsoft.com"]
        ## servers to perform the lookups
        #google, quaddns, clouflare
        self.dns_servers = ["8.8.8.8","9.9.9.9","1.1.1.1"]

    def __str__(self):
        return "=== Details ==="


    def _valuecheck(self):
        '''
        This method is a double check that items are the right types/values. if running as a one off, argparse checks as well.
        This is mainly for bulletproofing/making it apparent where you screwed up.
        '''
        #self.VAR = str


        if not isinstance("VAR", str):
            print("{} target parameter is the incorrect type: {}, {}. Expected a string.".format(error_block, VAR, type(VAR)))
            if not QsUtils.continue_anyways():
                return False
        
        return True


    def main(self):
        print("{} Starting qs-netdiag".format(operation_block)) if self.debug else print("{} Starting qs-netdiag, run with -d for detailed output. This may take a sec...".format(operation_block))

        #mockup
        dns_passed = 0
        dns_total = 0
        icmp_passed = 0 
        icmp_total = 0

        #dns
        for dns_server in self.dns_servers:
            for dns_domain in self.dns_domain:
                dns_total = dns_total + 1
                if self._dns_lookup(domain = dns_domain, dns_server=dns_server, debug = self.debug):
                    dns_passed = dns_passed + 1
        print("{} DNS: {}/{} ({:.2f}%) tests passed.".format(operation_block, dns_passed, dns_total, (dns_passed/dns_total) * 100))

        self._dns_lookup_reverse()

        ## ICMP
        for icmp_ip in self.icmp_ip:
            icmp_total = icmp_total + 1
            if self._icmp_gateway(ip=icmp_ip, debug = self.debug):
                icmp_passed = icmp_passed + 1

        print("{} ICMP: {}/{} ({:.2f}%) tests passed.".format(operation_block, icmp_passed, icmp_total, (icmp_passed/icmp_total) * 100))


        self._system_net_info()

        ## DHCP 
        self._dhcp_renew()

        #print("DNS: OK | GATEWAY: reachable | Other: OK | Other: FAIL")

    @execution_time
    def _dns_lookup(self, dns_server, domain, debug=False, timeout=5):
        ## chatgpt modified mockup - NEED to format these into correct tabs n stuff
        # Craft a DNS query packet
        try:
            dns_query = IP(dst=dns_server) / UDP() / DNS(rd=1, qd=DNSQR(qname=domain))

            # Send the packet and capture the response
            response = sr1(dns_query, verbose=False, timeout=timeout)

            # Check if a response was received
            if response:
                # Extract the resolved IP address(es) from the response
                answers = response[DNS].an
                if answers:
                    for answer in answers:
                        if answer.type == 1:  # Only consider A records
                            print("{} DNS Query {}\t -> \t{}: {}\t".format(operation_block, domain, dns_server, answer.rdata), end="") if debug else None
                            return True
                            ## do a normal lookup as well if this is successful
                else:
                    print("{} DNS Query {}\t -> \t{}: No Answers receieved".format(error_block, domain, dns_server), end="") if debug else None

            else:
                print("{} DNS Query {}\t -> \t{}: No Response receieved".format(error_block, domain, dns_server), end="") if debug else None

        except Exception as e:
            print("{} DNS error: {}".format(unrecov_error_block, e))

        #print("{} DNS Query 8.8.8.8 -> google.com Successful".format(operation_block))
        #pass

    def _dns_lookup_reverse(self):
        #print("{} DNS Query google.com -> 8.8.8.8 Successful".format(operation_block))

        pass

    def _icmp_gateway(self, ip, debug=False):
        ## being a pain with responsese. need to tesetk
        try:
            icmp_request = IP(dst=ip)/ICMP()

            # Send the packet and capture the response
            # using sr1 as we are only getting one response from each I think.
            result = sr1(icmp_request, timeout=1, verbose=False)
            
            if result is not None:
                #print(f"ICMP response received from {result[IP].src}")
                #print("IP: {}\tPKT: {}".format(result[IP].src, result.summary())) if debug else None
                print("{} ICMP \t -> \t{}: Success!".format(operation_block, result[IP].src)) if debug else None
                return True

            else:
                print("{} ICMP \t -> \t{}: No Response".format(error_block, ip)) if debug else None
                return False

        except Exception as e:
            print("{} ICMP err (ip: {}) \t -> : {}".format(unrecov_error_block, ip ,e)) if debug else None
            return False

        #print("{} ICMP Message -> 192.168.0.1 [GATEWAY] successful".format(operation_block))

        #pass

    def _system_net_info(self):
        self.local_ip = socket.gethostbyname(socket.gethostname())
        self.hostname = socket.gethostname()

        #print("{} IP: {} HOST: {} MAC: {} Interface: {}".format(operation_block, self.local_ip, self.hostname, "__", "__"))

    def _dhcp_renew(self):
        print("NOT IMPLEMENTED> IS TEST")
        print("{} DHCP Renewal \t -> \t{}: Success!".format(operation_block, "DATA")) if debug else None


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
    '''Parser is down here for one-off runs, as this script can be imported & used in other pyprojects'''
    parser = argparse.ArgumentParser(
                        prog='qs-portscan',
                        description='The QuickScripts netdiag tool. Meant to help you quickly find where your connection is fucked up. Performs a series of common DNS lookups, ICMP messages, and ___',
                        epilog='-- Designed by ryanq.47 --')

    #target prolly not needed
    #parser.add_argument('-t', '--target', help="The target you wish to scan. Can be an IP, FQDN, or hostname. Example: 'qs-portscan -t 192.168.0.1'", required=True) 
    parser.add_argument('-d', '--debug', help="Print debug information", action="store_true") 
    parser.add_argument('-z', help="Print debug information", action="store_true") 

    #interface arg, to choose which interface to use

    args = parser.parse_args()

    # display -h/help if no flags are supplied
    '''if not any(vars(args).values()):
        parser.print_help()
        # the exit makes sure the class instances don't get created/cause any errors with no values
        exit()'''

    netdiag = NetDiag(
        debug = args.debug
    )

    # Logic tree
    if args.debug:
        qs_debug = True
        print(netdiag)

    netdiag.main()


    '''
    Notes/todo

    add timeout option & implement.

    re learn DHCP and see how it can be added here

    on keyboard interupt, need to kill everything
    
    
    '''
