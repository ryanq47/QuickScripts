try:
    from ppadb.client import Client as AdbClient
except Exception as e:
    print(e)
    print("[(┛◉Д◉)┛┻━┻] Cannot load ppadb.client, try running: 'pip install pure-python-adb'")
import os
import sys
import time
import argparse
import subprocess
import threading

def parse_args():
    parser = argparse.ArgumentParser(description='Take and optionally display screenshots from an ADB-connected device.')
    parser.add_argument('--display', action='store_true', help='Display each screenshot using the default image viewer.')
    return parser.parse_args()

class ADBScreenshotTaker:
    def __init__(self, host="127.0.0.1", port=5037, display=False):
        self.display = display
        print(f"[*] Attempting to connect to local ADB server.")
        self.client = AdbClient(host=host, port=port)
        self.device = self.connect_to_device()
        if self.device:
            print(f"[*] Successful connection to server: {host}:{port}")
            self.device_name = self.device.get_serial_no()  # Using serial no. for directory naming
            print(f"[(⌐■_■)] Connected to device with serial: {self.device_name}")
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

    def take_screenshots(self, interval=5):
        """Take screenshots at specified intervals and save them to a specific directory based on device name."""
        screenshot_dir = f"data/adb_take_screenshot_loop/{self.device_name}/"
        os.makedirs(screenshot_dir, exist_ok=True)
        
        try:
            counter = 1
            while True:
                print(f"[*] Taking SS #{counter}... This might be ridiculously slow based on the connection.")
                screenshot_data = self.device.screencap()
                file_path = os.path.join(screenshot_dir, f'screenshot_{counter}.png')
                with open(file_path, 'wb') as f:
                    f.write(screenshot_data)
                print(f"[*] Screenshot taken and saved as {file_path}")
                
                if self.display:
                    print("[*] Displaying image onscreen")
                    self.display_image(file_path)

                counter += 1
                time.sleep(interval)  # Wait for the specified interval before taking the next screenshot
        except KeyboardInterrupt:
            print("Screenshot capture stopped by user.")
        except Exception as e:
            print(f"Error during screenshot capture: {e}")

    def display_image(self, image_path):
        """Display an image in the default viewer with an automatic close after a specified timeout."""
        if sys.platform == 'win32':
            # For Windows, using startfile doesn't provide an easy way to kill it, so we use a different viewer that can be killed
            viewer = subprocess.Popen(['mspaint', image_path])
        elif sys.platform == 'darwin':
            # For macOS, open and then kill the viewer after a timeout
            viewer = subprocess.Popen(['open', image_path])
        else:
            # For Linux, using xdg-open with a viewer that can be tracked and killed
            viewer = subprocess.Popen(['xdg-open', image_path])

        # Set a timer to automatically close the viewer
        def kill_viewer():
            try:
                viewer.kill()
                print(f"Closed viewer for {image_path}")
            except Exception as e:
                print(f"Failed to close viewer for {image_path}: {e}")

        # Start the timer to close the viewer after 5 seconds
        # halts the time for next SS tho, so its time image is up + next SS, sequentially
        #Does not kill it on WSL tho, so that's fun
        timer = threading.Timer(5, kill_viewer)
        timer.start()

def main():
    args = parse_args()

    screenshot_taker = ADBScreenshotTaker(display=args.display)
    screenshot_taker.take_screenshots()

if __name__ == "__main__":
    main()
