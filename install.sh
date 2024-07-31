#!/bin/bash

# -----------------------------------
# CTF Tools Setup Script
# Author: Ryan Kleffman W outline from chatgpt
# Date: Current Date
# -----------------------------------

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to display messages
function echo_green {
    echo -e "[+] ${GREEN}$1${NC}"
}

function echo_yellow {
    echo -e "[!] ${YELLOW}$1${NC}"
}

function echo_hashtags {
    echo "########################################"
}

function echo_red {
    echo -e "[-] ${RED}$1${NC}"
}

# Function to check and install a package
function install_package {
    if ! dpkg -l | grep -q $1; then
        echo_yellow "Installing $1..."
        sudo apt-get install -y $1
    else
        echo_green "$1 is already installed."
    fi
}

# Function to download and unzip files
function download_file {
    local url=$1
    local output_dir=$2
    local output_file=$3

    if [ ! -f ${output_dir}/${output_file} ]; then
        echo_yellow "Downloading $output_file from $url"
        wget $url -O ${output_dir}/${output_file} # took off quiet flag
        echo_green "Downloaded ${output_dir}/${output_file}."

        if [[ $output_file == *.zip ]]; then
            echo_yellow "Unzipping $output_file..."
            unzip -o ${output_dir}/${output_file} -d ${output_dir} 1>/dev/null
            echo_green "Unzipped ${output_dir}/${output_file}."
        fi
    else
        echo_green "${output_dir}/${output_file} already exists."
    fi
}

# Function to add a directory to PATH if it is not already in PATH
function add_to_path {
    local dir=$1

    if [[ ":$PATH:" != *":$dir:"* ]]; then
        echo "Adding $dir to PATH..."
        export PATH="$dir:$PATH"
        echo "Added $dir to PATH."
    else
        echo "$dir is already in PATH."
    fi
}


# Function to create directories
function create_directory {
    if [ ! -d $1 ]; then
        echo_yellow "Creating directory $1..."
        mkdir -p $1
        echo_green "Created directory $1."
    else
        echo_green "Directory $1 already exists."
    fi
}

function install_requirements {
    local requirements_file=$1

    if [ -f $requirements_file ]; then
        echo_yellow "Installing Python packages from $requirements_file..."
        pip3 install -r $requirements_file > /dev/null 1>/dev/null
        if [ $? -eq 0 ]; then
            echo_green "Successfully installed packages from $requirements_file."
        else
            echo_red "Failed to install packages from $requirements_file."
        fi
    else
        echo_red "$requirements_file does not exist."
    fi
}

function clone_repo {
    local repo_url=$1
    local dest_dir=$2

    if [ ! -d $dest_dir ]; then
        echo_yellow "Cloning repository $repo_url..."
        git clone $repo_url $dest_dir
        if [ $? -eq 0 ]; then
            echo_green "Successfully cloned $repo_url into $dest_dir."
        else
            echo_red "Failed to clone $repo_url."
        fi
    else
        echo_green "Directory $dest_dir already exists."
    fi
}

# Function to add Kali Linux repositories
add_kali_repos() {
    echo_yellow "Adding Kali Linux repositories..."
    
    # Add Kali Linux repositories to sources list
    cat <<EOF | sudo tee /etc/apt/sources.list.d/kali.list
deb http://http.kali.org/kali kali-rolling main non-free contrib
deb-src http://http.kali.org/kali kali-rolling main non-free contrib
EOF

    # Import the Kali Linux GPG key
    echo_yellow "Importing Kali Linux GPG key..."
    wget -q -O - https://archive.kali.org/archive-key.asc | sudo apt-key add -
    
    if [ $? -eq 0 ]; then
        echo_green "Successfully added Kali Linux repositories and imported GPG key."
    else
        echo_red "Failed to add Kali Linux repositories or import GPG key."
    fi

    # Update package list
    echo_yellow "Updating package list..."
    sudo apt-get update -y

    if [ $? -eq 0 ]; then
        echo_green "Package list updated successfully."
    else
        echo_red "Failed to update package list."
    fi
}

add_kali_repos

# Update and upgrade system
echo_yellow "Updating package list..."
sudo apt-get update -y
echo_yellow "Upgrading installed packages..."
sudo apt-get upgrade -y

# Install essential tools
echo_hashtags
echo_yellow "Installing essential tools..."
echo_hashtags
install_package git
install_package python3
install_package python3-pip
install_package wget
install_package curl
install_package vim
install_package unzip
install_package wine

# Set up directory structure
echo_hashtags
echo_yellow "Setting up directory structure..."
echo_hashtags

create_directory "./CTF"
create_directory "./CTF/tools"
create_directory "./CTF/challenges"
create_directory "./CTF/wordlists"
create_directory "./CTF/tools/forensics"
create_directory "./CTF/tools/web"
create_directory "./CTF/tools/pwn"
create_directory "./CTF/tools/rev"


# Download necessary files
#echo_yellow "Downloading necessary files..."
#download_file "https://github.com/danielmiessler/SecLists/archive/master.zip" "./CTF/wordlists" "SecLists.zip"


echo_hashtags
echo_yellow "Installing Web Tools"
echo_hashtags

echo_hashtags
echo_yellow "Installing Pentest Tools"
echo_hashtags

pip3 install impacket

echo_hashtags
echo_yellow "Installing Pwn Tools"
echo_hashtags

pip3 install pwntools


echo_hashtags
echo_yellow "Installing Rev Tools"
echo_hashtags

install_package ghidra
install_package radare2

# Install GDB and GEF
install_package gdb
if [ ! -d ~/.gdbinit-gef ]; then
    echo_yellow "Installing GEF for GDB..."
    bash -c "$(wget -q -O- https://gef.blah.cat/sh)"
else
    echo_green "GEF is already installed."
fi


## NOTES, when installing like this, put the .zip file or whatever in the category folder, it will auto unzip to a folder then in that dir
#create_directory "./CTF/tools/rev/binja"
download_file "https://cdn.binary.ninja/installers/binaryninja_free_linux.zip" "./CTF/tools/rev/" "binja.zip"
#NOT WORKING add_to_path "./CTF/tools/rev/binaryninja/binaryninja"


echo_hashtags
echo_yellow "Installing Forensics Tools"
echo_hashtags

install_package wireshark
install_package tshark
install_package binwalk
#install_package findaes

clone_repo "https://github.com/volatilityfoundation/volatility3.git" "./CTF/tools/forensics/volatility3"
install_requirements "./CTF/tools/forensics/volatility3/requirements.txt"

# Final message
echo_green "CTF setup completed successfully!"



## To Add:
# Forensics stuff