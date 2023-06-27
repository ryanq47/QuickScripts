import socket
import argparse
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, wait
import urllib.request

error_block = "[!]"
operation_block = "[*]"

## init this here
json_out_dict = {}
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

class ScapyScanner:
    ## one excception to stdlib rule, optional scapy scans.
    ## mainlyso I can  POC beforedoing raw socket stuff, and leaving it in
    def __init__(self, targetsubnet, protocol, interface="eth0", lookups=True):
        if not self._valuecheck(targetsubnet, protocol, interface):
            #print("TypeFailure")
            exit()

        self.target_subnet = targetsubnet
        self.protocol = protocol#["arp", "icmp"] #protocol # list of protocols, delim by ,
        self.interface = interface
        self.lookups  = lookups # internet based lookups, true: do lookups, false: don't

    def __str__(self):
        return "=== Details: Target Subnet: {}, Library: Scapy, Protocol: {}, interface: {} ===".format(self.target_subnet,self.protocol, self.interface)

    def _valuecheck(self, targetsubnet, protocol, interface):
        '''
        This method is a double check that items are the right types/values. if running as a one off, argparse checks as well.
        This is mainly for bulletproofing/making it apparent where you screwed up.

        When possble, provide the user the chance to override the errors with the continue_anyways function
        '''
        #self.VAR = str

        #protocol check
        if not isinstance(protocol, list): #or protocol not in ["arp", "icmp"]:
            print("{} protocol parameter is the incorrect type or value: {}, {}. Expected a str, with a value of 'arp' or 'icmp'.".format(error_block, protocol, type(protocol)))
            return False
        
        #interface check
        if not isinstance(interface, str) or interface in ["None"]:
            #skipping scans that do NOT need an interface
            if protocol in ["icmp"]:
                pass
            #checking for an interface arg in scans that require an interface. Note, None is not a str
            elif interface == None and protocol == "arp":
                print("{} Interface is 'None'. An interface is required for ARP scans.".format(error_block))
                if not continue_anyways():
                    return False
            else:
                print("{} interface parameter is the incorrect type: {}, {}. Expected a str".format(error_block, interface, type(interface)))
                return False
            
        #subnet/IP check
        if not isinstance(targetsubnet, str):
            '''
            Maybe do a regex or similar check to make sure the IP is valid? otherwise this check is useless lol
            '''
            print("{} target subnet/IP parameter is the incorrect type: {}, {}. Expected a str".format(error_block, targetsubnet, type(targetsubnet)))
            return False

        return True
    
    #callable function
    @execution_time
    def scan(self):
        # generate IP list

        ip_list = calculate_host_ips(self.target_subnet)

        with ProcessPoolExecutor() as executor:
            for ip in ip_list:
                if "arp" in self.protocol:
                    #pass
                    executor.submit(self._scapy_arp_scan, target_subnet=ip)
                    #do arp
                    #executor.submit
                
                if "icmp" in self.protocol:
                    #pass
                    executor.submit(self._scapy_icmp_scan, ip)
                    #do icmp
                    #executor.submit

            

        ''' old method
        ## start scans
        if self.protocol == "arp":
            self._scapy_arp_scan(target_subnet=self.target_subnet, interface=self.interface)
        elif self.protocol == "icmp":
            host_ips=calculate_host_ips(self.target_subnet)

            with ProcessPoolExecutor() as executor:
                #futures = [executor.submit(self._scapy_icmp_scan, ip) for ip in host_ips]
                for ip in host_ips:
                    executor.submit(self._scapy_icmp_scan, ip)

                #for i in futures:
                    #print(i)'''


    ## protocol implementation
    #passing variables instead of using self, just incase this can be multithreaded later
    def _scapy_arp_scan(self, target_subnet="127.0.0.1/24", interface=""):
        try:
            # Craft the ARP request packet
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_subnet)

            # Send the packet and capture the response
            result = srp(arp_request, timeout=5, iface=interface, verbose=False)[0]

            # Process the response
            devices = []
            for sent, received in result:
                devices.append({'IP': received.psrc, 'MAC': received.hwsrc})

            # Print the discovered devices
            for device in devices:
                ## doing this as these values a re used a few times & I don't wanna call  mac_lookup more than once
                temp_ip, temp_mac, temp_vendor = device['IP'], device['MAC'], mac_lookup(device['MAC']) if self.lookups else 'Disabled'

                ## change to .format str
                #print(f"IP: {temp_ip}\tMAC: {temp_mac} \tVENDOR: {mac_lookup(temp_vendor) if self.lookups else 'Disabled'}")
                print("IP: {}\tMAC: {}\tVENDOR {}".format(temp_ip, temp_mac, temp_vendor))
                json_build(ip=temp_ip,mac=temp_mac,vendor=temp_vendor)

        except Exception as e:
            print("{} Arp error occured: {}".format(error_block, e))

    ##This could benefit from multithread/process.Need to understand what is hapening under the 
    #hood first
    def _scapy_icmp_scan(self, ip="127.0.0.1"):
        #print(ip)
        #print("ICMP")
        try:
            icmp_request = IP(dst=ip)/ICMP()

            # Send the packet and capture the response
            # using sr1 as we are only getting one response from each I think.
            result = sr1(icmp_request, timeout=1, verbose=False)
            
            if result is not None:
                #print(f"ICMP response received from {result[IP].src}")
                print("IP: {}\tPKT: {}".format(result[IP].src, result.summary()))

            else:
                pass
                #print("No ICMP response received")

        except Exception as e:
            print("{} ICMP error occured: {}".format(error_block, e))



class RawSocketOps:
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


def continue_anyways():
    '''
    A little function that propmts the user to continue anyway. Returns true/false. 
    '''
    if input("Enter 'y' to continue execution (high chance of failure), or any other key to exit: ") == "y":
        return True
    else:
        return False

def calculate_host_ips(subnet):
    network = ipaddress.ip_network(subnet, strict=False)
    host_ips = [str(ip) for ip in network.hosts()]
    return host_ips

# Note, No performance hit with lookups, as the lookups take longer than the url requests lol
#idea: dict lookup for already found MACs to save requests - was being picky when tried
def mac_lookup(mac):
    try:
        url = "http://api.macvendors.com/" + str(mac).replace(" ","")
        response = urllib.request.urlopen(url)
        mac_vendor = response.read().decode('utf-8')
        return mac_vendor

    except Exception as e:
        print("{} Error with MAC Vendor lookup: {}".format(error_block, e))
        return "Error"
    

def json_build(ip="", mac="",vendor=""):
    json_out_dict[mac] = {
        'ip':ip,
        'vendor':vendor
    }

def json_write_to_file(item_to_write="No Contents", filename="qs-netscan-results.json"):
    try:
        import json
        with open(filename, 'w') as file:
            json.dump(item_to_write, file)

    except ImportError as je:
        print("{} Error with importing JSON module: {}".format(error_block, je))
    except Exception as e:
        print("{} Error with JSON write: {}".format(error_block, e))



if __name__ == "__main__":
    '''Parser is down here for one-off runs, as this script can be imported & used in other pyprojects'''
    parser = argparse.ArgumentParser(
                        prog='qs-portscan',
                        description='''The QuickScripts netscanner. 
                        Discovers other devices in your subnet. No non-standard dependencies required, however scanning via scapy is optional if you wish. 
                        Minimum PyVersion is 3.3, as the ipaddress module is required. Last, you  may need sudo/elevated permissions to perform network operations''',
                        epilog='-- Designed by ryanq.47 --')
    parser.add_argument('-d', '--debug', help="Prints debug information", action="store_true") 
    parser.add_argument('-t', '--targetsubnet', help="The target you wish to scan. Can be an IP, FQDN, or hostname. Example: 'qs-portscan -t 192.168.0.1'", required=True, default="127.0.0.1/24") 
    parser.add_argument('-p', '--protocol', help="The method/protocol(s) to use to scan. Enter one, or multiple, i.e.: '-p arp', -p arp icmp", type=str, nargs='+') 
    parser.add_argument('-l', '--library', help="The library you want to use to conduct network operations", default="scapy") 
    parser.add_argument('-i', '--interface', help="The interface you want to scan on.", required=False) 
    parser.add_argument('-o', '--output', help="Output data in JSON. Add a name after for a filename", required=False, default="qs-netscan-output.json") 
    parser.add_argument('--nolookups', help="Don't do any internet based lookups (i.e. MAC vendor lookups)", required=False,action="store_false") 
    parser.add_argument('--sendto', help="Send the results (in JSON) to a listener/server/host. Ex: --sendto 127.0.0.1:8080", required=False) 


    args = parser.parse_args()

    # display -h/help if no flags are supplied
    if not any(vars(args).values()):
        parser.print_help()
        # the exit makes sure the class instances don't get created/cause any errors with no values
        exit()


    if args.library == "scapy":
        try:
            from scapy.all import *
            logging.getLogger("scapy").setLevel(logging.CRITICAL)
        
        except ImportError as ie:
            print("{} Warning, scapy import error.\n{} Error Message: {}".format(error_block, error_block, ie))
            if continue_anyways():
                pass
            else:
                exit()

        scanner = ScapyScanner(
            targetsubnet=args.targetsubnet,
            protocol=args.protocol,
            interface = args.interface,
            lookups = args.nolookups
        )


    elif args.library == "socket":
        print("Socket not yet implemented")
        exit()
        scanner = SocketScanner(
        )
        #socketclass()

    # Debug
    if args.debug:
            print(scanner)
            ##scapyclass()
    
    try:
        '''
        json_build(ip="123.254.11.35", mac="00:11:22:33:44:55",vendor="RQ Industrial")
        json_build(ip="123.254.11.31", mac="00:11:22:33:44:56",vendor="RQ Industrial")
        json_write_to_file(item_to_write=json_out_dict)'''
        scanner.scan()

        if args.output:
            json_write_to_file(item_to_write=json_out_dict, filename=args.output)

        if args.sendto:
            QsUtils.send_to(args.sendto)

    except PermissionError as pe:
        print("{} Permission error, may need elevated priveleges. \n{} Error Message: {}".format(error_block,error_block,pe))

    except KeyboardInterrupt as ke:
        print("Keyboard Interupt... Exiting")

    except Exception as e:
        print("{} Error Occured: {}".format(error_block, e))


'''
Left off::

Doing error handling & checking for the inputs. Trying to break the current logic and account for it.
(i.e. defualt arguments, interface=eth0, etc)

need to re-learn threadool options & get farmilisar with scapy too

Ideally, would  like to move away from scapy
but that may take some time to get the raw socket stuff done



!! Latest: Fix the error handling.value checking stopping the '-p arp' from working. it just got moved to a list,
need to adjust it as so

'''