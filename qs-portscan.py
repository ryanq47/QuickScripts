import socket
import argparse
from telnetlib import Telnet
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, wait
import time

error_block = "[!]"
operation_block = "[*]"


'''
Notes:
using .format for strings for compatability with python versions prior to 3.6


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
        print("Execution time: {:.4f} seconds".format(execution_time))
        return result
    return wrapper

class PortScan:
    def __init__(self, ports=[1,1024], timeout=0.5, target="127.0.0.1", method="", process_allocation="threadpool"):
        if not self._valuecheck(target=target, ports=ports,timeout=timeout, method=method, process_allocation=process_allocation):
            exit()
        
        self.target = target
        self.timeout = timeout = 0.0000001 if timeout == 0 else timeout #0 causes issues, turning it into practically 0
        self.ports = self._port_sort(ports)
        self.method = method
        self.process_allocation = process_allocation


    def __str__(self):
        return "=== Scan Details: target: {} timeout: {} ports: {}-{} method: {} process allocation: {} ===".format(
    self.target, self.timeout, self.ports[0], self.ports[-1], self.method, self.process_allocation)

    
    def _valuecheck(self, target, ports, timeout, method, process_allocation):
        '''
        This method is a double check that items are the right types/values. if running as a one off, argparse checks as well.
        This is mainly for bulletproofing/making it apparent where you screwed up.
        '''
        #self.target = str
        #self.timeout = float, also if 0, self.target = 0.0000001 (can't do 0, causes issue with socket)
        #self.ports?
        #sel.method = str & equal to one of 2 values (telnet, socket)
        #self.process_allovation str & equal to one of 3 values (singlethread, professpool, threadpool)

        if not isinstance(target, str):
            print("{} target parameter is the incorrect type: {}, {}. Expected a string.".format(error_block, target, type(target)))
            return False
        
        if not isinstance(timeout, float):
            print("{} timeout parameter is the incorrect type: {}, {}. Expected a float.".format(error_block, timeout, type(timeout)))
            return False
        
        if not isinstance(method, str) or method not in ["telnet", "socket"]:
            print("{} method parameter is the incorrect type: {}, {}. Expected a str, with a value of 'telnet' or 'socket'.".format(error_block, method, type(method)))
            return False
        
        if not isinstance(process_allocation, str) or process_allocation not in ["processpool", "threadpool", "singleprocess", "single"]:
            print("{} process_allocation parameter is the incorrect type or value: {}, {}. Expected a str, with a value of 'processpool', 'threadpool', or 'singleprocess'.".format(error_block, process_allocation, type(process_allocation)))
            return False


        return True
        pass

    @execution_time
    def socket_scan(self):
        '''
        Standard socket portsan - single thread/process
        '''
        print("{} Warning! Using single process mode. This will take longer than usual, and is included only for compatibility reasons".format(error_block))
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
            print("{} Warning! Using single process mode. This will take longer than usual, and is included only for compatibility reasons".format(error_block))
            for port_to_scan in self.ports:
                self._socket_scan_implementation(ip=self.target, port=port_to_scan, timeout=self.timeout)
        else:
            print("Invalid process_allocation option: {}".format(self.process_allocation))
            exit()

        print("Done!")

    def _socket_scan_implementation(self, ip="127.0.0.1", port=1, timeout=.5):
        try:
            # have to create a socket object each time as otherwise the sockets error out.
            # fix here: https://stackoverflow.com/questions/54437148/python-socket-connect-an-invalid-argument-was-supplied-oserror-winerror
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(("127.0.0.1", port))
            print("{}:{} is open".format(self.target, port))
        
        except (ConnectionError, ConnectionRefusedError, TimeoutError) as e:
            pass

        except ConnectionResetError as re:
            print("{}:{} reset. Test Manually".format(self.target, port))
        
        except Exception as e:
            print(e)

    def telnet_scan(self):
        '''
        standard telnet scan
        '''
        print("{} Warning! Using single process mode. This will take longer than usual, and is included only for compatibility reasons".format(error_block))

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
            print("{} Warning! Using single process mode. This will take longer than usual, and is included only for compatability reasons".format(error_block))
            for port_to_scan in self.ports:
                self._telnet_scan_implementation(ip=self.target, port=port_to_scan)
        else:
            print("Invalid process_allocation option: {}".format(self.process_allocation))

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
            print("{}:{} is open".format(self.target, port))
            return True
        # it's okay to ignore these, they just catch a bad/refused connection
        except (ConnectionRefusedError, TimeoutError) as cre:
            return False

        except Exception as e:
            print("{} Telnet error occurred: {}".format(error_block, e))
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
                print("{} Error occurred while parsing port range: {}".format(error_block, e))
                exit()
        
        elif "," in ports:
            try:
                p = ports.split(",")
                for i in p:
                    port_list.append(int(i))

            except Exception as e:
                print("{} Error occurred while parsing ports: {}".format(error_block, e))
                exit()

        else:
            print("{} Unrecognized format for ports: {}".format(error_block, ports))
            exit()

        return port_list
    


if __name__ == "__main__":
    '''Parser is down here for one-off runs, as this script can be imported & used in other pyprojects'''
    parser = argparse.ArgumentParser(
                        prog='qs-portscan',
                        description='The QuickScripts portscanner. No non-standard dependencies required',
                        epilog='-- Designed by ryanq.47 --')

    parser.add_argument('-t', '--target', help="The target you wish to scan. Can be an IP, FQDN, or hostname. Example: 'qs-portscan -t 192.168.0.1'", required=True, type=str) 
    parser.add_argument('-p', '--ports', help="The port(s) to scan. For a port range, enter as such: '1-1024', or for select ports: '22,23,80,443'", default="1-1024") 
    parser.add_argument('-m', '--method', help="The method used to portscan, current options are telnet and socket. Defaults to the fastest implementation available.", default="telnet", type=str) 
    parser.add_argument('-pa', '--processallocation', default = "threadpool",
                        help="Which method of concurrency to use, 'threadpool' (multiprocess, subject to GIL), 'processpool' (multicore, better for CPU intensive items.) or 'singleprocess' for no concurrency. YMMV, included for compatibility", type=str)
    parser.add_argument('-to', '--timeout', help="The time the protocol will wait for a repsonse from the port. '.5' (seconds) is the default. I would not reccomend going any lower unless you are LAN scanning", default=.25, type=float)  
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

