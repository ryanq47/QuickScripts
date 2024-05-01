# Ascii: https://gist.github.com/ww9/a26ca38836a62fbf3b8b85a190d5b2f0
try:
	from ppadb.client import Client as AdbClient
except Exception as e:
	print(e)
	print("[(┛◉Д◉)┛┻━┻] Cannot load ppadb.client, try running: 'pip install pure-python-adb'")
	

import os

class ADBDatabasePuller:
    def __init__(self, host="127.0.0.1", port=5037):
        print(f"[*] Attempting to connect to local ADB server.")
        self.client = AdbClient(host=host, port=port)
        self.device = self.connect_to_device()
        if self.device:
            print(f"[*] Successful connection to server: {host}:{port}")
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
        except Exception as e:
            if str(e) == "adbd is already running as root":
                    print("[•_•] ADB is already root!")
                    return True
            else:    
                    print("[(┛◉Д◉)┛┻━┻] Failed to restart ADB with root permissions:", str(e))
                    return False
        return True

    def find_database_files(self):
        """Find all .db files on the device and return a list."""
        if self.device is None:
            print("[(┛◉Д◉)┛┻━┻] No device is connected.")
            return []
        result = self.device.shell("find /data/data/ -type f -name '*.db'")
        return result.splitlines()

    def setup_directories(self, base_dir):
        """Ensure the base directory for database storage exists."""
        os.makedirs(base_dir, exist_ok=True)

    def pull_databases(self, storagedir="data/adb_pull_databases/"):
        """Pull database files from the device."""
        if not self.restart_adb_as_root():
            return

        self.setup_directories(storagedir)
        db_files = self.find_database_files()
        if not db_files:
            print("[(┛◉Д◉)┛┻━┻] No database files found.")
            return

        print(f"{len(db_files)} DB files found!")
        num = 0

        for db_file in db_files:
            num += 1
            db_file = db_file.strip()
            if db_file:
                # Prepare the local file path by appending the filename to local_path
                local_dir = os.path.join(storagedir, os.path.dirname(db_file[1:]))
                local_file_path = os.path.join(local_dir, os.path.basename(db_file))
                #print(local_file_path)
                os.makedirs(local_dir, exist_ok=True)
            
                print(f"[( ͡° ͜ʖ ͡°)] ({num}/{len(db_files)}) Pulling: {db_file}")
                try:
                    self.device.pull(db_file, local_file_path)  # Now using local_file_path
                except Exception as e:
                    print(f"[(┛◉Д◉)┛┻━┻] Failed to pull {db_file}: {str(e)}")


def main():
    adb_puller = ADBDatabasePuller()
    adb_puller.pull_databases()

if __name__ == "__main__":
    main()
