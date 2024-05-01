import argparse
import time
import os
from ppadb.client import Client as AdbClient

def parse_arguments():
    parser = argparse.ArgumentParser(description="ADB Speed Test Tool")
    parser.add_argument('--filesize', type=int, help='Size of the file to transfer in megabytes (MB)')
    return parser.parse_args()

def create_large_file(size_in_mb, filename="testfile.tmp"):
    with open(filename, 'wb') as f:
        f.write(os.urandom(size_in_mb * 1024 * 1024))  # Write random data

def measure_transfer_speed(device, local_path, device_path, direction='push'):
    start_time = time.time()
    if direction == 'push':
        device.push(local_path, device_path)
    else:
        device.pull(device_path, local_path)
    elapsed_time = time.time() - start_time
    file_size = os.path.getsize(local_path)  # Get the file size from the local file
    speed_mbps = (file_size / (1024 * 1024)) / elapsed_time  # Convert bytes to megabytes
    return speed_mbps, elapsed_time

def main():
    args = parse_arguments()
    client = AdbClient(host="127.0.0.1", port=5037)
    devices = client.devices()
    if len(devices) == 0:
        print("No devices connected.")
        return
    device = devices[0]

    print(f"[*] Started speedtest with a file size of {args.filesize} MB, this will take a minute or so...")

    # Create a large file for testing
    filename = "testfile.tmp"
    create_large_file(args.filesize, filename)

    # Test upload speed
    print("[*] Testing upload speed...")
    upload_speed, upload_time = measure_transfer_speed(device, filename, "/sdcard/" + filename, 'push')
    print(f"[*] Upload Speed: {upload_speed:.2f} MB/s over {upload_time:.2f} seconds.")

    # Test download speed
    print("[*] Testing download speed...")
    download_speed, download_time = measure_transfer_speed(device, filename, "/sdcard/" + filename, 'pull')
    print(f"[*] Download Speed: {download_speed:.2f} MB/s over {download_time:.2f} seconds.")

    # Clean up
    print("[*] Cleaning up temp file")
    os.remove(filename)
    device.shell(f"rm /sdcard/{filename}")

if __name__ == "__main__":
    main()
