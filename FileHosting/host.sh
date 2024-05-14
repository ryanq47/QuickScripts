#!/bin/bash

# Create a virtual environment if it does not exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "Virtual environment created."
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install flask markdown

# Run the server
python server.py

# Deactivate the virtual environment
deactivate
