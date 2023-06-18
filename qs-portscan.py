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
    def __init__(self, ports=[1,1024], timeout=0.5, target="127.0.0.1", method="", process_allocation="threadpool"):
        self.target = target
        self.timeout = float(timeout)
        self.ports = self._port_sort(ports)
        self.method = method
        self.process_allocation = process_allocation

    def __str__(self):
        return f"=== Scan Details: target: {self.target} timeout: {self.timeout} ports: {self.ports[0]}-{self.ports[-1]} method: {self.method} process allocation: {self.process_allocation} ==="
    
    @execution_time
    def socket_scan(self):
        '''
        Standard socket portsan - single thread/process
        '''
        print(f"{error_block} Warning! Using single process mode. This will take longer than usual, and is included only for compatability reasons")
        for port_to_scan in self.ports:
            self._socket_scan_implementation(ip=self.target, port=port_to_scan, timeout=self.timeout)

    @execution_time
    def socket_multiprocess_scan(self):
        '''
        Threadexecutor'd socket multiprocess scan
        '''
        #sock.setblocking(False)

        #sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #sock.setblocking(False)

        '''
        Cool idea: Could make 4 socket objects, and rotate which gets used. would eliminate overhead
        of creating a new sock each time
        
        '''
        if self.process_allocation == "processpool":
            with ProcessPoolExecutor() as executor:
                futures = [executor.submit(self._socket_scan_implementation, self.target, port, self.timeout) for port in self.ports]
                #wait(futures, timeout=2)
        elif self.process_allocation == "threadpool":
            with ThreadPoolExecutor() as executor:
                futures = [executor.submit(self._socket_scan_implementation, self.target, port, self.timeout) for port in self.ports]
                #wait(futures, timeout=2)   
        elif self.process_allocation == "singleprocess" or self.process_allocation == "single":
            print(f"{error_block} Warning! Using single process mode. This will take longer than usual, and is included only for compatability reasons")
            for port_to_scan in self.ports:
                self._socket_scan_implementation(ip=self.target, port=port_to_scan, timeout=self.timeout)
        else:
            print(f"Invalid process_allocation option: {self.process_allocation}")

        print("Done!")

    def _socket_scan_implementation(self, ip="127.0.0.1", port=1, timeout=.5):
        try:
            # have to create a socket object each time as otherwise the sockets error out.
            # fix here: https://stackoverflow.com/questions/54437148/python-socket-connect-an-invalid-argument-was-supplied-oserror-winerror
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(("127.0.0.1", port))
            print(f"{self.target}:{port} is open")
        
        except (ConnectionError, ConnectionRefusedError, TimeoutError) as e:
            pass

        except ConnectionResetError as re:
            print(f"{self.target}:{port} reset. Test Manually")
        
        except Exception as e:
            print(e)

    def telnet_scan(self):
        '''
        standard telnet scan
        '''
        print(f"{error_block} Warning! Using single process mode. This will take longer than usual, and is included only for compatability reasons")

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
        #ProcessPoolExecutor()#, literally a drop in replacement. Multicore, a (fair, about 2/3rds) bit slower due to overhead for IO tasks

        if self.process_allocation == "processpool":
            with ProcessPoolExecutor() as executor:
                futures = [executor.submit(self._telnet_scan_implementation, self.target, port) for port in self.ports]
                #wait(futures, timeout=2)
        elif self.process_allocation == "threadpool":
            with ThreadPoolExecutor() as executor:
                futures = [executor.submit(self._telnet_scan_implementation, self.target, port) for port in self.ports]
                #wait(futures, timeout=2)   
        elif self.process_allocation == "singleprocess" or self.process_allocation == "single":
            print(f"{error_block} Warning! Using single process mode. This will take longer than usual, and is included only for compatability reasons")
            for port_to_scan in self.ports:
                self._telnet_scan_implementation(ip=self.target, port=port_to_scan)
        else:
            print(f"Invalid process_allocation option: {self.process_allocation}")

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
    parser.add_argument('-pa', '--processallocation', default = "threadpool",
                        help="Which method of concurrency to use, 'threadpool' (multiprocess, subject to GIL), 'processpool' (multicore, better for CPU intensive items.) or 'singleprocess' for no concurrency. YMMV, included for compatibility")
    parser.add_argument('-to', '--timeout', help="The time the protocol will wait for a repsonse from the port. '.5' (seconds) is the default. I would not reccomend going any lower unless you are LAN scanning", default=.25)  
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
        method = args.method,
        process_allocation = args.processallocation
    )

    # Logic tree
    if args.debug:
        print(scanner)


    if args.method == "telnet":
        scanner.telnet_multiprocess_scan()


    elif args.method == "socket":
        scanner.socket_multiprocess_scan()

