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
    parser = argparse.ArgumentParser(description="Enumerate detailed information about an Android device over ADB, including network, hardware, and software details.")
    return parser.parse_args()

class AndroidEnumerator:
    def __init__(self, host="127.0.0.1", port=5037):
        print("[*] Connecting to the ADB server...")
        self.client = AdbClient(host=host, port=port)
        self.device = self.connect_to_device()
        if self.device:
            print(f"[+] Successfully connected to {host}:{port}")
            self.device_id = self.device.get_serial_no()
            print(f"[+] Device serial number: {self.device_id}")
            self.setup_directory()
        else:
            print("[!] Failed to connect to the ADB server. Please check if it is running and accessible.")
            sys.exit(1)  # Exit if connection is not successful

    def setup_directory(self):
        """Setup directory structure for saving device data."""
        self.base_dir = f"data/adb_enum/{self.device_id}/"
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir)
        print("[+] Data directory setup complete.")

    def connect_to_device(self):
        """Establish a connection with the first available ADB device."""
        try:
            devices = self.client.devices()
            if not devices:
                print("[!] No devices connected.")
                return None
            return devices[0]
        except Exception as e:
            print(f"[!] Error connecting to ADB server: {e}")
            return None

    def restart_adb_as_root(self):
        print("[*] Attempting to restart ADB as root")
        if self.device is None:
            print("[(┛◉Д◉)┛┻━┻] No device is connected.")
            return False
        try:
            self.device.root()
            self.wait_for_device_to_be_up()
        except Exception as e:
            if str(e) == "adbd is already running as root":
                print("[•_•] ADB is already root!")
                return True
            else:    
                print("[(┛◉Д◉)┛┻━┻] Failed to restart ADB with root permissions:", str(e))
                return False
        return True

    def wait_for_device_to_be_up(self):
        for _ in range(30):
            try:
                if self.device.get_state() == 'device':
                    print("[*] Device reconnected and ready.")
                    return True
            except Exception as e:
                print(f"Waiting for device to reconnect... {e}")

            time.sleep(1)
        print("[(┛◉Д◉)┛┻━┻] Timeout: Device did not reconnect in the expected time.")
        return False

    def enumerate_device(self):
        """Run all enumeration functions to gather comprehensive device information and save to files."""
        print("[*] Starting device enumeration...")
        summary = self.get_device_summary()
        self.save_data_to_file("device_summary.txt", summary)
        #print(summary)

    def get_device_summary(self):
        """Generate a summary of the device properties, network, and hardware info."""
        print("[*] Retrieving device properties...")
        properties = self.device.shell("getprop")
        print(properties)

        print("[*] Retrieving network information...")
        ip_info = self.device.shell("ip addr")
        print(ip_info)

        print("[*] Retrieving CPU information...")
        cpu_info = self.device.shell("cat /proc/cpuinfo")
        print(cpu_info)

        print("[*] Retrieving memory information...")
        mem_info = self.device.shell("cat /proc/meminfo")
        print(mem_info)
        
        print("[*] Retrieving Misc information...")

        device_model = self.device.shell("getprop ro.product.model").strip()
        android_version = self.device.shell("getprop ro.build.version.release").strip()
        
        print(f"Model: {device_model}")
        print(f"Android Version: {android_version}")

        summary = (
            f"Device Properties:\n{properties}\n\n"
            f"Network Interfaces:\n{ip_info}\n\n"
            f"CPU Information:\n{cpu_info}\n\n"
            f"Memory Information:\n{mem_info}\n"
            f"Model Information: {device_model}\n"
            f"Android Version: {android_version}\n"


        )
        return summary

    def save_data_to_file(self, filename, data):
        """Save the collected data to a file in the device-specific directory."""
        file_path = os.path.join(self.base_dir, filename)
        with open(file_path, 'w') as file:
            file.write(data)
        print(f"\n[+] Data saved to {file_path}")

    def print_device_properties(self):
        print("[*] Retrieving device properties...")
        self.properties = self.device.shell("getprop")
        print("\n[+] Device Properties:\n", self.properties)

    def print_network_info(self):
        print("[*] Retrieving network information...")
        self.ip_info = self.device.shell("ip addr")
        print("\n[+] Network Interfaces:\n", self.ip_info)

    def print_hardware_info(self):
        print("[*] Retrieving hardware information...")
        self.cpu_info = self.device.shell("cat /proc/cpuinfo")
        print("\n[+] CPU Information:\n", self.cpu_info)
        self.mem_info = self.device.shell("cat /proc/meminfo")
        print("\n[+] Memory Information:\n", self.mem_info)

    def print_installed_packages(self):
        print("[*] Listing installed packages...")
        self.packages = self.device.shell("pm list packages")
        print("\n[+] Installed Packages:")
        for package in self.packages.strip().split('\n'):
            print(f" - {package.replace('package:', '')}")


    def get_last_known_location(self):
        """Attempt to retrieve the last known location from the device."""
        try:
            # This command assumes you have root access and the device has tools to dump location info
            location_data = self.device.shell("dumpsys location")
            # Look for a line containing a valid latitude and longitude
            for line in location_data.splitlines():
                if 'Last Known Locations:' in line:
                    # This is pseudo-code and may need adjustment based on actual output
                    lat_lng = line.split(' ')[-1]  # Adjust this based on actual output format
                    latitude, longitude = lat_lng.split(',')
                    return latitude, longitude
        except Exception as e:
            print(f"Failed to retrieve location data: {e}")
        return "Unknown", "Unknown"

    def extract_ip_address(self):
        """Extract the first found IP address from the ip_info property."""
        for line in self.ip_info.split('\n'):
            if 'inet ' in line and 'scope global' in line:
                return line.split()[1].split('/')[0]
        return "Not found"

def main():
    args = parse_arguments()
    enumerator = AndroidEnumerator()
    enumerator.enumerate_device()

if __name__ == "__main__":
    main()
