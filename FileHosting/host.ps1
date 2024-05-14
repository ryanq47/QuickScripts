# Create a virtual environment if it does not exist
if (-Not (Test-Path "venv")) {
    python -m venv venv
    Write-Host "Virtual environment created."
}

# Activate virtual environment
. .\venv\Scripts\Activate.ps1

# Install dependencies
pip install flask markdown

# Run the server
python server.py

# Deactivate the virtual environment
deactivate
