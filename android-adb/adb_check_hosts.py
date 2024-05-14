import sys
import argparse
import time
import os
try:
    from ppadb.client import Client as AdbClient
except Exception as e:
    print(e)
    print("Error: Cannot load ppadb. Please ensure 'pure-python-adb' is installed.")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Check if a device can be connected to via ADB")
    parser.add_argument('--file', '-f', required=True, help='File of IPs to check')
    return parser.parse_args()

class CheckHosts:
    def __init__(self, ip_file):
        self.ip_file = ip_file
        self.adb_client = AdbClient(host="127.0.0.1", port=5037)

    def restart_adb(self):
        """
        Restarts ADB server to ensure fresh connections.
        """
        print("[+] Restarting ADB Server...")
        os.system("adb kill-server")
        os.system("adb start-server")
        time.sleep(3)

    def enumerate_device(self):
        """
        Attempts to connect to devices listed by IP in the specified file.
        """
        with open(self.ip_file, 'r') as file:
            ip_addresses = file.readlines()

        for ip in ip_addresses:
            ip = ip.strip()
            
            if ip:
                print(f"Trying to connect to {ip}...")
                try:
                    ip = ip.strip()
                    ip_and_port = f"{ip}:5555"
                    device = self.adb_client.remote_connect(ip, 5555)
                    #device = self.adb_client.device(ip_and_port)
                    if device:
                        print(f"[+] Successfully connected to {ip}")
                    else:
                        print(f"[-] Failed to connect to {ip}")


                except Exception as e:
                    print(f"[-] Error connecting to {ip}: {e}\n")

                finally:
                    print(f"[*] Removing & Disconnecting device {ip}\n")
                    self.adb_client.remote_disconnect(ip)


        #print(f"[+] Disconnecting all devices...")

        #self.adb_client.remote_disconnect()

def main():
    args = parse_arguments()
    enumerator = CheckHosts(args.file)
    enumerator.restart_adb()
    enumerator.enumerate_device()

if __name__ == "__main__":
    main()
