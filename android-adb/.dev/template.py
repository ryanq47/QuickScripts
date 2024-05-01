try:
    from ppadb.client import Client as AdbClient
except Exception as e:
    print(e)
    print("[(┛◉Д◉)┛┻━┻] Cannot load ppadb.client, try running: 'pip install pure-python-adb'")
import os
import sys
import time

class ADBDatabasePuller:
    def __init__(self, host="127.0.0.1", port=5037):
        print(f"[*] Attempting to connect to local ADB server.")
        self.client = AdbClient(host=host, port=port)
        self.device = self.connect_to_device()
        if self.device:
            print(f"[*] Successful connection to server: {host}:{port}")
            self.device_name = self.device.get_serial_no()
            print(f"[•_•] Connected to device with serial: {self.device_name}")
        else:
            print(f"[(┛◉Д◉)┛┻━┻] Failed to connect to server, run 'adb start-server': {host}:{port}")
            sys.exit(1)  # Exit if connection is not successful

    def connect_to_device(self):
        """Connect to the first available ADB device."""
        try:
            devices = self.client.devices()
            if len(devices) == 0:
                print("[(┛◉Д◉)┛┻━┻] No devices connected.")
                return None
            return devices[0]
        except Exception as e:
            print(f"[(┛◉Д◉)┛┻━┻] Error connecting to ADB server: {e}")
            return None

    def restart_adb_as_root(self):
        """Attempt to restart adb with root permissions."""
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
        for _ in range(30):  # Retry for 30 seconds
            try:
                if self.device.get_state() == 'device':
                    print("[*] Device reconnected and ready.")
                    return True
            except Exception as e:
                print(f"Waiting for device to reconnect... {e}")

            time.sleep(1)  # Wait for 1 second before trying again

        print("[(┛◉Д◉)┛┻━┻] Timeout: Device did not reconnect in the expected time.")
        return False

    ## Custom functions for actions here
    #def myfunc(self):
        #result = self.device.shell("find /data/data/ -type f -name '*.db'")


def main():
    adb_puller = ADBDatabasePuller()
    #adb_puller.myfunc()

if __name__ == "__main__":
    main()
