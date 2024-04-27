#!/bin/bash

echo "Bash Implemetation of an ADB file/directory puller. Pulls data from whatever directory you input"
echo "Depending on connection speed, this may take a minute."
echo "ONLY USE WHEN YOU HAVE PERMISSION!"

echo "Enter directory to pull: "
read dir_to_pull

# Create a directory to store the temporary list of database files
mkdir -p "tmp"
touch "tmp/dir_pull_files.txt"
tempfile="tmp/dir_pull_files.txt"

# Create the storage directory
storagedir="data/adb_pull_directory_and_subdirectories/"
mkdir -p "$storagedir"

# Use adb to find all files in the specified directory and save them to a tempfile
adb shell "find $dir_to_pull" > "$tempfile"

#cat $tempfile

# Iterate over the list of files and pull each one
while IFS= read -r dbfile; do
    dbfile=$(echo "$dbfile" | tr -d '\r') # Trim carriage return if running on Windows bash or something
    echo "[*] Pulling: $dbfile"

    localpath="./${storagedir}$(dirname "$dbfile")"
    mkdir -p "$localpath"
    
    # pull file & store in local dir
    adb pull "$dbfile" "$localpath/"

done < "$tempfile"