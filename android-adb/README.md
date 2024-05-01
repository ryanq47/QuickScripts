## About

This is a set of tools used to make ADB stuff easier, basically macro commands. They are meant to be quick and dirty. 

A few things are assumed before running these tools:
 - 1. You only have one device connected to ADB. Multiple are not supported. use `adb connect IP` to connect a device.


#### Files
All useful files are stored in the 'data' directory under the Device IP & Tool name. Each tool has its own folder. 

Ex: data/adb_pull_device/1.2.3.4:5555/

## Installation

```
python3 -m pip install -r requirements.txt

```

## Typical Usage:

```
./adb_restart.sh (or manaully do this)

adb connect ip_of_target

python/bash tool_of_choice

```

## Tools:

## adb_pull_databases.py
Pulls all the databases in /data/data/ on the Device. Saves in: data/adb_pull_device/dev_ip:dev_port/. use with `extract_data_from_db.py` for quick parsing of resulting data

## extract_data_from_db.py
Pulls sensitive data from the extracted databases. Operates off the following keywords:

```
    'username', 'user', 'password', 'pass', 'login', 'credential', 'passwd',
    'cookie', 'cookies', 'history', 'session', 'autofill', 'formdata',
    'bookmark', 'bookmarks', 'email', 'address', 'phone', 'number', 'contact', 'contacts',
    'profile', 'account', 'token', 'tokens', 'apikey', 'api_key', 'secret', 'secrets',
    'auth', 'authentication', 'credit', 'card', 'payment', 'billing', 'transaction', 'transactions',
    'wallet', 'account_number', 'account_info', 'location', 'longitude', 'latitude'
```

## adb_restart.sh - Linux Only
Restart the local adb server. 

## adb_speedtest.py

Runs a speedtest on the target. Defaults to 10 MB random file upload/download.

Arguments:
 - `--Filesize`: Size (in MB) of file to upload/download

## adb_take_screenshot_loop.py
Takes a screenshot every ~5 seconds on the device, and opens in the default application. Saves the images in  data/adb_take_screenshot_loop/dev_ip:dev_port/

Arguments:
 - `--display`: Display images on screen after a successful screenshot

## adb_elevate_privs.py
Tries to elevate the current ADB shell session into a root one. Most android devices don't have a password for root access.

## adb_enum.py
Runs basic Enum on the device, outputs on screen and saves to data/adb_enum/dev_ip:dev_port. Automatically tries to elevate to root.