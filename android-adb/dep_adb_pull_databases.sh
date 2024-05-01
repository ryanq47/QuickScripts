#!/bin/bash

echo "Bash Implemetation of an ADB Database puller. Pulls data from /data/data/*/*.db"
echo "Depending on connection speed, this may take a minute."
echo "ONLY USE WHEN YOU HAVE PERMISSION!"


# Temporary file to store the list of database files
mkdir -p "tmp"
touch "tmp/db_files.txt"
tempfile="db_files.txt"
storagedir="data/adb_pull_databases/"

# Use adb to find all .db files in /data/data/ and save them to a tempfile
adb shell "find /data/data/ -type f -name '*.db'" > $tempfile

# Iterate over the list of files and pull each one
while IFS= read -r dbfile; do

    # Trim carriage return if running on Cygwin/MSYS on Windows
    dbfile=$(echo $dbfile | tr -d '\r')
    echo "[*] Pulling: "  $dbfile

    # Create a local path, mirroring the device's directory structure
    localpath="./${storagedir}$(dirname "$dbfile")"
    mkdir -p "$localpath"
    
    # Pull the file using adb pull
    adb pull "$dbfile" "$localpath/"

# Loops back & tells it to read from tempfile
done < "$tempfile"

# Clean up the temporary file
rm "$tempfile"
