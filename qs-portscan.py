import socket
import argparse
from telnetlib import Telnet
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, wait
import time

error_block = "[!]"
operation_block = "[*]"


'''
Little decorator note (still a newer concept to me), instead of running the function that the @ is above, it 
tells python to run the @function instead, and calls the function under the decorator in the process

'''
#thank you chatGPT for this one
def execution_time(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"Execution time: {execution_time:.4f} seconds")
        return result
    return wrapper

class PortScan:
    def __init__(self, ports=[1,1024], timeout=0.5, target="127.0.0.1", method=""):
        self.target = target
        self.timeout = float(timeout)
        self.ports = self._port_sort(ports)
        self.method = method

    def __str__(self):
        return f"=== Scan Details: target: {self.target} timeout= {self.timeout} ports= {self.ports[0]}-{self.ports[-1]} method= {self.method} ==="

    def socket_scan(self):
        '''
        Standard socket portsan - single thread/process
        '''
        pass

    def socket_multiprocess_scan(self):
        '''
        Threadexecutor'd socket multiprocess scan
        '''
        pass

    def telnet_scan(self):
        '''
        standard telnet scan
        '''

        for port_to_scan in self.ports:
            self._telnet_scan_implementation(ip=self.target, port=port_to_scan)
            '''if self._telnet_scan_implementation(ip=self.target, port=port_to_scan):
                print(f"{self.target}:{port_to_scan} is open")
                ## append to a list somewhere?'''

    @execution_time
    def telnet_multiprocess_scan(self):
        '''
        Threadexecutor'd telnet multiprocess scan
        '''
        ##ThreadPoolExecutor: - is faster, uses one core, but multiple processes
        #ThreadPoolExecutor()#, literally a drop in replacement. Multicore, a (fair, about 2/3rds) bit slower due to overhead for IO tasks
        with ProcessPoolExecutor() as executor:
            futures = [executor.submit(self._telnet_scan_implementation, self.target, port) for port in self.ports]
            #wait(futures, timeout=2)

        print("Done!")


    def _telnet_scan_implementation(self, ip="", port=1):
        '''
        The actual logic behind the telnet scan. Gets called for each port. This allows for
        additional handling/cleanliness/flexibility
        '''

        try:
            #with Telnet(ip, port, timeout_time) as tn:
            tn = Telnet(host=ip, port=port, timeout=self.timeout)
            tn.close()
            print(f"{self.target}:{port} is open")
            return True
        # it's okay to ignore these, they just catch a bad/refused connection
        except (ConnectionRefusedError, TimeoutError) as cre:
            return False

        except Exception as e:
            print(f"{error_block} Telnet error occured: {e}")
            #exit()

        return False
        
        #delay
        #time.sleep(random.uniform(delay[0], delay[1]))

    def _port_sort(self, ports=""):
        '''
        Sorts the ports into an acceptable format
        '''

        port_list = []

        if "-" in ports:
            try:
                p = ports.split("-")
                # +1 as range ends one short
                port_range = range(int(p[0]), int(p[1]) + 1)
                for i in port_range:
                    port_list.append(int(i))
            except Exception as e:
                print(f"{error_block} Error occured while parsing port range: {e}")
                exit()
        
        elif "," in ports:
            try:
                p = ports.split(",")
                for i in p:
                    port_list.append(int(i))

            except Exception as e:
                print(f"{error_block} Error occured while parsing ports: {e}")
                exit()

        else:
            print(f"{error_block} Unrecognized format for ports: {ports}")
            exit()

        return port_list
    


if __name__ == "__main__":
    '''Parser is down here for one-off runs, as this script can be imported & used in other pyprojects'''
    parser = argparse.ArgumentParser(
                        prog='qs-portscan',
                        description='The QuickScripts portscanner. No non-standard dependencies required',
                        epilog='-- Designed by ryanq.47 --')

    parser.add_argument('-t', '--target', help="The target you wish to scan. Can be an IP, FQDN, or hostname. Example: 'qs-portscan -t 192.168.0.1'", required=True) 
    parser.add_argument('-p', '--ports', help="The port(s) to scan. For a port range, enter as such: '1-1024', or for select ports: '22,23,80,443'", default="1-1024") 
    parser.add_argument('-m', '--method', help="The method used to portscan, current options are telnet and socket. Defaults to the fastest implementation available.", default="telnet") 
    parser.add_argument('-sp', '--singleprocess', action="store_true",
                        help="Reduces scanning to a single process. Each port has to wait for the previous scan to complete, so this takes much longer. Included for compatability reasons.")
    parser.add_argument('-to', '--timeout', help="The time the protocol will wait for a repsonse from the port. '.5' (seconds) is the default. I would not reccomend going any lower unless you are LAN scanning", default=.5)  
    parser.add_argument('-d', '--debug', help="Prints debug information", action="store_true")  
    args = parser.parse_args()

    # display -h/help if no flags are supplied
    if not any(vars(args).values()):
        parser.print_help()
        # the exit makes sure the class instances don't get created/cause any errors with no values
        exit()

    scanner = PortScan(
        target = args.target,
        ports = args.ports,
        timeout = args.timeout,
        method = args.method
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
